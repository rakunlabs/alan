# TLA+ model of alan's distributed lock

This directory contains PlusCal models of `lock.go`. The original goal
was to make the README's existing safety claims mechanically checkable;
along the way the model uncovered an unintended **reorder bug** in the
"safe" configuration (quorum + no partitions). The bug and the fix are
described below.

## Models and outcomes

| Spec | Models | Config | Outcome |
|---|---|---|---|
| `LockSpec.tla` | Original lock.go: each lock message gets its own QUIC stream; releases are anonymous (no requestID match) | `LockSpec_StartupRace.cfg` (2 peers, no quorum) | Mutual exclusion **violated** (3-step trace; reproduces the documented startup race) |
| `LockSpec.tla` | (same) | `LockSpec_Safe.cfg` (3 peers, quorum, no partitions) | Mutual exclusion **violated** (16-step trace; **reorder bug**, see below) |
| `LockSpec.tla` | (same) | `LockSpec_Partition.cfg` (3 peers, quorum, partitions enabled) | Violated (expected; partition split-brain is a documented "best-effort" limit) |
| `LockSpecFIFO.tla` | Fix: persistent per-(sender, receiver) FIFO stream + requestID-tagged Release frames | `LockSpecFIFO_Safe.cfg` (3 peers, quorum, no partitions) | **Holds.** TLC explored 3.2M states, 21s, no counter-example |
| `LockSpecFIFO.tla` | (same) | `LockSpecFIFO_Partition.cfg` (3 peers, quorum, partitions enabled) | Violated (expected; partition split-brain is unrelated to ordering) |
| `LockSpecFIFO_PartialVisibility.tla` | Same FIFO protocol; one peer starts already SelfHeld | `LockSpecFIFO_PartialVisibility.cfg` (3 peers, quorum, no partitions, p1 pre-held) | **Violated** in 5 steps. A second peer reaching the third (without handshaking with the holder yet) satisfies HasQuorum on `\|visible\|+1 = majority` and acquires alone. |
| `LockSpecFIFO_PartialVisibility_Fixed.tla` | Same scenario + warm-start guard: each peer has a `settled` flag that flips only on full local visibility, and AcquireStart / AcquireNoPeers gate on it | `LockSpecFIFO_PartialVisibility_Fixed.cfg` (3 peers, quorum, no partitions, p1 pre-held) | **Holds.** TLC explored 9 491 states; no counter-example. This is the model of `Config.LockAcquireMembershipWait` — see "Lock acquisition: warm-start guard" in the main README. |

## The reorder bug found by `LockSpec_Safe.cfg`

Each lock message in the original code path opened its own QUIC stream
(`alan.go: sendLockMsg → openStream → OpenStreamSync`). QUIC streams
are independently flow-controlled and reorder freely relative to each
other; the receiver also dispatched each accepted stream on its own
goroutine, so dispatch order was not the send order. With anonymous
`LockRelease` frames (the original `broadcastLockRelease` filled the
requestID with 16 zero bytes), a release from an earlier aborted
acquisition could arrive *after* a fresh grant for a later acquisition
and clobber the recorded `HeldBy` entry — leaving two peers in
`SelfHeld` simultaneously even with quorum and no partitions.

TLC's counter-example for `LockSpec_Safe.cfg` materialises exactly
this scenario in 16 steps:

1. p3's first acquisition is preempted; abort broadcasts an anonymous
   Release (state 9).
2. p3 starts a second acquisition; p2 grants it; p2 records
   `HeldBy(p3)` (states 11–12).
3. p2 receives the stale Release from step 1 — anonymous, so it
   matches anything from p3 — and clears its `HeldBy(p3)` entry
   (state 13).
4. p2 then grants p1's still-in-flight request, recording
   `HeldBy(p1)`. p1 collects its grants and enters `SelfHeld`.
5. p3 collects its grants and also enters `SelfHeld`. **Mutual
   exclusion violated.**

## The fix (verified by `LockSpecFIFO.tla`)

Two changes, both implemented in alan and shipped as part of the
`alan/2` → `alan/3` ALPN bump:

1. **Per-peer FIFO stream.** Each ordered pair of peers now shares a
   single persistent QUIC stream (`MsgTypeLockMux = 0x50`) for all lock
   frames in that direction. Within one stream QUIC guarantees FIFO;
   the receiver reads frames serially in a single goroutine. This
   removes the per-message reorder window.
2. **Tagged Releases.** `LockRelease` frames now carry the requestID
   that established the corresponding `HeldBy` entry on the receiver
   (`broadcastLockRelease(ctx, requestID, key)` in `lock.go`).
   `handleLockRelease` compares the incoming id against the
   locally-stored `holderID` and drops mismatches. This is defence in
   depth — even if ordering is ever weaker than expected (e.g. a
   stream torn down and re-opened across a brief connectivity blip),
   stale releases cannot clobber the current holder.

`LockSpecFIFO.tla` models both. With 3 peers and quorum enabled TLC
explores 3.2M states (43-step deepest path) and reports no
`MutualExclusion` violation.

## Files

- `LockSpec.tla` — original protocol (per-message stream, anonymous
  releases). One lock key, N peers, Connect / AcquireNoPeers /
  AcquireStart / Receive{Request,Grant,Deny,Release} / Disconnect.
  Tie-break is the same `bytes.Compare(requestID, state.pending)`
  used in `lock.go`.
- `LockSpecFIFO.tla` — fixed protocol. Mesages travel through
  per-(sender, receiver) FIFO sequences (`inbox[from][to]`) and
  Releases carry an `id`. `heldByID[p]` tracks the requestID that
  established the local `HeldBy` entry; a Release whose id does not
  match is dropped.
- `LockSpec_StartupRace.cfg` — 2 peers, `RequireQuorum = FALSE`.
- `LockSpec_Safe.cfg` — 3 peers, quorum on, no partitions.
- `LockSpec_Partition.cfg` — 3 peers, quorum on, partitions allowed.
- `LockSpecFIFO_Safe.cfg` — same as `LockSpec_Safe.cfg` but for the
  FIFO model.
- `LockSpecFIFO_Partition.cfg` — same as `LockSpec_Partition.cfg`
  but for the FIFO model.
- `LockSpecFIFO_PartialVisibility.tla` / `.cfg` — variant of the FIFO
  model with an asymmetric Init: peer p1 starts in SelfHeld with
  attempts[p1]=1 (i.e. it acquired the lock before p2/p3 booted).
  Reproduces the partial-visibility startup race: p2 and p3
  handshake with each other before either reaches p1, satisfy
  HasQuorum on `|visible|+1 = majority`, and one of them enters
  SelfHeld concurrently with p1.
- `LockSpecFIFO_PartialVisibility_Fixed.tla` / `.cfg` — same Init,
  same actions, plus a per-peer `settled` flag that gates AcquireStart
  and AcquireNoPeers. The flag flips only when the peer's visible set
  equals the full cluster (`Peers \ {self}`). This models the
  `LockAcquireMembershipWait` guard in its strict form (long enough
  for full membership to be reached). TLC verifies the partial-vis
  counter-example is no longer reachable: 9 491 states explored, no
  invariant violation.

## Install TLC

The simplest path is the standalone `tla2tools.jar`:

```bash
# Java 11+ is required.
sudo apt install -y default-jre   # or any JRE >= 11

# Grab the toolbox jar (single ~5 MB file).
curl -L -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
```

Alternatively, install the
[VS Code TLA+ extension](https://marketplace.visualstudio.com/items?itemName=alygin.vscode-tlaplus)
which bundles the toolbox.

## Run the model checker

The PlusCal translator runs in-place; modern `tla2tools.jar` builds
do it automatically when TLC starts. To force a re-translate:

```bash
java -cp tla2tools.jar pcal.trans LockSpec.tla
java -cp tla2tools.jar pcal.trans LockSpecFIFO.tla
```

### Reproduce the bug (original protocol, "safe" config)

```bash
java -jar tla2tools.jar -config LockSpec_Safe.cfg LockSpec.tla
```

Expected: `Invariant MutualExclusion is violated.` with the 16-step
trace described above.

### Verify the fix (FIFO protocol, "safe" config)

```bash
java -jar tla2tools.jar -config LockSpecFIFO_Safe.cfg LockSpecFIFO.tla
```

Expected: `Model checking completed. No error has been found.` after
~3.2M states and ~20 seconds.

### Other configurations

```bash
# Documented startup race — invariant violated in 3 steps.
java -jar tla2tools.jar -config LockSpec_StartupRace.cfg LockSpec.tla

# Documented partition split-brain — invariant violated.
java -jar tla2tools.jar -config LockSpec_Partition.cfg LockSpec.tla
java -jar tla2tools.jar -config LockSpecFIFO_Partition.cfg LockSpecFIFO.tla
```

## What these models do NOT cover

- Voluntary `Unlock` (omitted from the protocol model; the hard case
  for mutual exclusion is concurrent acquisition, and Unlock is a
  trivial transition that does not interact with it).
- The `waiters` queue and `Lock`'s outer retry loop (modelled
  implicitly by re-firing `AcquireStart` after `Free`).
- QUIC backpressure / message-queue overflow.
- Per-message timeouts.
- Liveness — the models check only safety (mutual exclusion).

If you want to extend the models, natural next steps:

1. Add `LeaderLoop`-style re-acquire on top of the FIFO model and
   prove only one leader per partition.
2. Multi-key variant to check independence of distinct lock keys.
3. Add explicit `Unlock` action and a liveness invariant (waiters
   eventually get the lock under fairness assumptions).
