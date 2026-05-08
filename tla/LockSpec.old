------------------------------- MODULE LockSpec -------------------------------
(***************************************************************************)
(* TLA+ / PlusCal model of alan's distributed lock protocol (lock.go).     *)
(*                                                                         *)
(* Models exactly ONE lock key with N peers. Each peer can attempt to      *)
(* acquire the lock at most MaxAttempts times (state-space bound).         *)
(*                                                                         *)
(* The model captures:                                                     *)
(*   - Local lock state machine (Free / Pending / SelfHeld / HeldBy)       *)
(*   - LockRequest broadcast to every visible peer                         *)
(*   - Symmetric tie-break by requestID (lower wins)                       *)
(*   - LockGrant / LockDeny / LockRelease delivery                         *)
(*   - Speculative HeldBy(peer) state on the responder side                *)
(*   - abort() broadcasting LockRelease to clear speculative holders       *)
(*   - Optional peer disconnect (releaseLocksHeldBy + peerLeft pending)    *)
(*   - Optional quorum gate (Replicas-style)                               *)
(*                                                                         *)
(* What it deliberately abstracts:                                         *)
(*   - The 16-byte random requestIDs are replaced by (peer, attempt)       *)
(*     pairs, totally ordered by ReqLT.                                    *)
(*   - QUIC stream ordering: messages travel through an unordered set so   *)
(*     any reordering across peers is allowed.                             *)
(*   - Voluntary Unlock is omitted for state-space size; it does not       *)
(*     affect the safety properties checked here.                          *)
(*                                                                         *)
(* Run                                                                     *)
(*   tlc -config LockSpec_StartupRace.cfg LockSpec.tla                     *)
(* to see MutualExclusion violated when RequireQuorum = FALSE              *)
(* (the README's "startup race" admission, mechanically demonstrated).     *)
(*                                                                         *)
(* Run                                                                     *)
(*   tlc -config LockSpec_Safe.cfg LockSpec.tla                            *)
(* to see MutualExclusion HOLD when quorum is enforced and partitions      *)
(* are disabled.                                                           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Peers,             \* finite set of peer IDs (e.g. {1, 2})
    MaxAttempts,       \* per-peer cap on acquisition attempts
    RequireQuorum,     \* TRUE  => peer needs majority of |Peers| visible+self
                       \* FALSE => quorum disabled (Replicas = 0 in alan)
    EnableDisconnect   \* TRUE  => peers may partition mid-flight

ASSUME RequireQuorum    \in BOOLEAN
ASSUME EnableDisconnect \in BOOLEAN
ASSUME MaxAttempts \in Nat /\ MaxAttempts >= 1

\* Majority of |Peers|; self counts toward this in HasQuorum.
QuorumSize == (Cardinality(Peers) \div 2) + 1

\* Tagged-record state values --------------------------------------------------
StateFree      == [tag |-> "Free"]
StatePending   == [tag |-> "Pending"]
StateSelfHeld  == [tag |-> "SelfHeld"]
StateHeldBy(q) == [tag |-> "HeldBy", who |-> q]

\* Request ID: a (peer, attempt) pair. Total order via lex compare.
ReqID(p, n) == [peer |-> p, num |-> n]
NoReq       == [peer |-> 0, num |-> 0]   \* sentinel "absent"

\* Total order on Peers. TLC model values (p1, p2, ...) cannot be
\* compared with <, so we pick any bijection Peers -> 1..|Peers|.
\* CHOOSE is deterministic, so this is a fixed order across the run.
PeerIdx == CHOOSE f \in [Peers -> 1..Cardinality(Peers)] :
              \A p, q \in Peers : p # q => f[p] # f[q]

\* Lex compare on (PeerIdx[peer], num). Only called on valid ReqIDs
\* (i.e. a.peer, b.peer \in Peers), never on NoReq.
ReqLT(a, b) == \/ PeerIdx[a.peer] < PeerIdx[b.peer]
               \/ /\ a.peer = b.peer
                  /\ a.num  < b.num

\* Wire messages ---------------------------------------------------------------
MsgRequest(f, t, id) == [type |-> "Req",   from |-> f, to |-> t, id |-> id]
MsgGrant(f, t, id)   == [type |-> "Grant", from |-> f, to |-> t, id |-> id]
MsgDeny(f, t, id)    == [type |-> "Deny",  from |-> f, to |-> t, id |-> id]
MsgRelease(f, t)     == [type |-> "Rel",   from |-> f, to |-> t]

(*--algorithm Lock

variables
    \* Per-peer local lock state for the single key.
    state    = [p \in Peers |-> StateFree],

    \* Pending requestID I broadcast (NoReq when not Pending).
    myReq    = [p \in Peers |-> NoReq],

    \* Pending: peers that have granted my request so far.
    grants   = [p \in Peers |-> {}],

    \* Pending: snapshot of visible peers at AcquireStart.
    expected = [p \in Peers |-> {}],

    \* Mutual visibility (live QUIC connections; symmetric).
    visible  = [p \in Peers |-> {}],

    \* Per-peer attempt counter (bounds state space + uniques requestIDs).
    attempts = [p \in Peers |-> 0],

    \* Pairs of peers permanently severed (prevents Connect/Disconnect
    \* oscillation from blowing up the state space).
    severed  = {},

    \* Bag of in-flight messages.
    network  = {};

define
    HasQuorum(p) == (~RequireQuorum)
                  \/ ((Cardinality(visible[p]) + 1) >= QuorumSize)

    Holders         == { p \in Peers : state[p] = StateSelfHeld }
    MutualExclusion == Cardinality(Holders) <= 1

    TypeInv ==
        /\ visible  \in [Peers -> SUBSET Peers]
        /\ attempts \in [Peers -> 0..MaxAttempts]
        /\ \A p \in Peers :
              \/ state[p] = StateFree
              \/ state[p] = StatePending
              \/ state[p] = StateSelfHeld
              \/ /\ state[p].tag = "HeldBy"
                 /\ state[p].who \in Peers
end define;

process Peer \in Peers
begin Loop:
    while TRUE do
        either
            (* ---- Connect: establish a QUIC handshake ---- *)
            await visible[self] # (Peers \ {self});
            with q \in (Peers \ {self}) \ visible[self] do
                await {self, q} \notin severed;
                visible[self] := visible[self] \cup {q} ||
                visible[q]    := visible[q]    \cup {self};
            end with;

        or
            (* ---- AcquireNoPeers: the dangerous self-grant path ----
               When visible = {} and quorum is disabled (or |Peers| = 1),
               two peers can fire this concurrently before they have
               discovered each other => MutualExclusion violation
               (the README's documented "startup race").                  *)
            await /\ state[self]   = StateFree
                  /\ visible[self] = {}
                  /\ attempts[self] < MaxAttempts
                  /\ HasQuorum(self);
            attempts[self] := attempts[self] + 1 ||
            state[self]    := StateSelfHeld;

        or
            (* ---- AcquireStart: broadcast LockRequest to visible peers *)
            await /\ state[self]   = StateFree
                  /\ visible[self] # {}
                  /\ attempts[self] < MaxAttempts
                  /\ HasQuorum(self);
            with newAttempt = attempts[self] + 1,
                 rid        = ReqID(self, newAttempt) do
                attempts[self] := newAttempt ||
                state[self]    := StatePending ||
                myReq[self]    := rid ||
                grants[self]   := {} ||
                expected[self] := visible[self] ||
                network        := network
                                \cup { MsgRequest(self, q, rid) :
                                       q \in visible[self] };
            end with;

        or
            (* ---- ReceiveRequest ---- *)
            with m \in { x \in network : x.type = "Req" /\ x.to = self } do
                if state[self] = StateFree then
                    state[self] := StateHeldBy(m.from) ||
                    network     := (network \ {m})
                                 \cup { MsgGrant(self, m.from, m.id) };
                elsif state[self].tag = "HeldBy" \/ state[self] = StateSelfHeld then
                    network := (network \ {m})
                             \cup { MsgDeny(self, m.from, m.id) };
                elsif state[self] = StatePending then
                    if ReqLT(m.id, myReq[self]) then
                        \* Incoming wins: hand over, preempt, broadcast
                        \* Release to clear my own speculative HeldBy(self)
                        \* on visible peers (matches abort()).
                        state[self] := StateHeldBy(m.from) ||
                        myReq[self] := NoReq ||
                        grants[self]   := {} ||
                        expected[self] := {} ||
                        network := (network \ {m})
                                 \cup { MsgGrant(self, m.from, m.id) }
                                 \cup { MsgRelease(self, q) :
                                        q \in visible[self] };
                    else
                        network := (network \ {m})
                                 \cup { MsgDeny(self, m.from, m.id) };
                    end if;
                end if;
            end with;

        or
            (* ---- ReceiveGrant ---- *)
            with m \in { x \in network :
                            /\ x.type = "Grant"
                            /\ x.to   = self
                            /\ state[self] = StatePending
                            /\ x.id   = myReq[self] } do
                if expected[self] \subseteq (grants[self] \cup {m.from}) then
                    state[self]    := StateSelfHeld ||
                    myReq[self]    := NoReq ||
                    grants[self]   := {} ||
                    expected[self] := {} ||
                    network        := network \ {m};
                else
                    grants[self] := grants[self] \cup {m.from} ||
                    network      := network \ {m};
                end if;
            end with;

        or
            (* ---- ReceiveDeny: abort -> Free, broadcast Release ---- *)
            with m \in { x \in network :
                            /\ x.type = "Deny"
                            /\ x.to   = self
                            /\ state[self] = StatePending
                            /\ x.id   = myReq[self] } do
                state[self]    := StateFree ||
                myReq[self]    := NoReq ||
                grants[self]   := {} ||
                expected[self] := {} ||
                network        := (network \ {m})
                                \cup { MsgRelease(self, q) :
                                       q \in visible[self] };
            end with;

        or
            (* ---- ReceiveRelease ---- *)
            with m \in { x \in network : x.type = "Rel" /\ x.to = self } do
                if state[self].tag = "HeldBy" /\ state[self].who = m.from then
                    state[self] := StateFree ||
                    network     := network \ {m};
                else
                    network := network \ {m};
                end if;
            end with;

        or
            (* ---- Disconnect: link torn down -----------------------
               Mirrors releaseLocksHeldBy + peerLeft notification.     *)
            await EnableDisconnect /\ visible[self] # {};
            with q \in visible[self] do
                visible[self] := visible[self] \ {q} ||
                visible[q]    := visible[q]    \ {self} ||
                severed       := severed \cup { {self, q} } ||

                \* Self-side cleanup of HeldBy(q).
                state[self]   := IF state[self].tag = "HeldBy"
                                   /\ state[self].who = q
                                 THEN StateFree
                                 ELSE state[self] ||

                \* Other-side cleanup of HeldBy(self).
                state[q]      := IF state[q].tag = "HeldBy"
                                   /\ state[q].who = self
                                 THEN StateFree
                                 ELSE state[q] ||

                \* Self-side: drop q from expected; promote if done.
                expected[self] := IF state[self] = StatePending
                                  THEN expected[self] \ {q}
                                  ELSE expected[self] ||

                \* Other-side: same for q's pending.
                expected[q]    := IF state[q] = StatePending
                                  THEN expected[q] \ {self}
                                  ELSE expected[q];
            end with;
        end either;
    end while;
end process;

end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "eb3049ca" /\ chksum(tla) = "77b8fbe4")
VARIABLES state, myReq, grants, expected, visible, attempts, severed, network

(* define statement *)
HasQuorum(p) == (~RequireQuorum)
              \/ ((Cardinality(visible[p]) + 1) >= QuorumSize)

Holders         == { p \in Peers : state[p] = StateSelfHeld }
MutualExclusion == Cardinality(Holders) <= 1

TypeInv ==
    /\ visible  \in [Peers -> SUBSET Peers]
    /\ attempts \in [Peers -> 0..MaxAttempts]
    /\ \A p \in Peers :
          \/ state[p] = StateFree
          \/ state[p] = StatePending
          \/ state[p] = StateSelfHeld
          \/ /\ state[p].tag = "HeldBy"
             /\ state[p].who \in Peers


vars == << state, myReq, grants, expected, visible, attempts, severed, 
           network >>

ProcSet == (Peers)

Init == (* Global variables *)
        /\ state = [p \in Peers |-> StateFree]
        /\ myReq = [p \in Peers |-> NoReq]
        /\ grants = [p \in Peers |-> {}]
        /\ expected = [p \in Peers |-> {}]
        /\ visible = [p \in Peers |-> {}]
        /\ attempts = [p \in Peers |-> 0]
        /\ severed = {}
        /\ network = {}

Peer(self) == \/ /\ visible[self] # (Peers \ {self})
                 /\ \E q \in (Peers \ {self}) \ visible[self]:
                      /\ {self, q} \notin severed
                      /\ visible' = [visible EXCEPT ![self] = visible[self] \cup {q},
                                                    ![q] = visible[q]    \cup {self}]
                 /\ UNCHANGED <<state, myReq, grants, expected, attempts, severed, network>>
              \/ /\ /\ state[self]   = StateFree
                    /\ visible[self] = {}
                    /\ attempts[self] < MaxAttempts
                    /\ HasQuorum(self)
                 /\ /\ attempts' = [attempts EXCEPT ![self] = attempts[self] + 1]
                    /\ state' = [state EXCEPT ![self] = StateSelfHeld]
                 /\ UNCHANGED <<myReq, grants, expected, visible, severed, network>>
              \/ /\ /\ state[self]   = StateFree
                    /\ visible[self] # {}
                    /\ attempts[self] < MaxAttempts
                    /\ HasQuorum(self)
                 /\ LET newAttempt == attempts[self] + 1 IN
                      LET rid == ReqID(self, newAttempt) IN
                        /\ attempts' = [attempts EXCEPT ![self] = newAttempt]
                        /\ expected' = [expected EXCEPT ![self] = visible[self]]
                        /\ grants' = [grants EXCEPT ![self] = {}]
                        /\ myReq' = [myReq EXCEPT ![self] = rid]
                        /\ network' =   network
                                      \cup { MsgRequest(self, q, rid) :
                                             q \in visible[self] }
                        /\ state' = [state EXCEPT ![self] = StatePending]
                 /\ UNCHANGED <<visible, severed>>
              \/ /\ \E m \in { x \in network : x.type = "Req" /\ x.to = self }:
                      IF state[self] = StateFree
                         THEN /\ /\ network' =   (network \ {m})
                                               \cup { MsgGrant(self, m.from, m.id) }
                                 /\ state' = [state EXCEPT ![self] = StateHeldBy(m.from)]
                              /\ UNCHANGED << myReq, grants, expected >>
                         ELSE /\ IF state[self].tag = "HeldBy" \/ state[self] = StateSelfHeld
                                    THEN /\ network' =   (network \ {m})
                                                       \cup { MsgDeny(self, m.from, m.id) }
                                         /\ UNCHANGED << state, myReq, 
                                                         grants, expected >>
                                    ELSE /\ IF state[self] = StatePending
                                               THEN /\ IF ReqLT(m.id, myReq[self])
                                                          THEN /\ /\ expected' = [expected EXCEPT ![self] = {}]
                                                                  /\ grants' = [grants EXCEPT ![self] = {}]
                                                                  /\ myReq' = [myReq EXCEPT ![self] = NoReq]
                                                                  /\ network' =   (network \ {m})
                                                                                \cup { MsgGrant(self, m.from, m.id) }
                                                                                \cup { MsgRelease(self, q) :
                                                                                       q \in visible[self] }
                                                                  /\ state' = [state EXCEPT ![self] = StateHeldBy(m.from)]
                                                          ELSE /\ network' =   (network \ {m})
                                                                             \cup { MsgDeny(self, m.from, m.id) }
                                                               /\ UNCHANGED << state, 
                                                                               myReq, 
                                                                               grants, 
                                                                               expected >>
                                               ELSE /\ TRUE
                                                    /\ UNCHANGED << state, 
                                                                    myReq, 
                                                                    grants, 
                                                                    expected, 
                                                                    network >>
                 /\ UNCHANGED <<visible, attempts, severed>>
              \/ /\ \E m \in { x \in network :
                                  /\ x.type = "Grant"
                                  /\ x.to   = self
                                  /\ state[self] = StatePending
                                  /\ x.id   = myReq[self] }:
                      IF expected[self] \subseteq (grants[self] \cup {m.from})
                         THEN /\ /\ expected' = [expected EXCEPT ![self] = {}]
                                 /\ grants' = [grants EXCEPT ![self] = {}]
                                 /\ myReq' = [myReq EXCEPT ![self] = NoReq]
                                 /\ network' = network \ {m}
                                 /\ state' = [state EXCEPT ![self] = StateSelfHeld]
                         ELSE /\ /\ grants' = [grants EXCEPT ![self] = grants[self] \cup {m.from}]
                                 /\ network' = network \ {m}
                              /\ UNCHANGED << state, myReq, expected >>
                 /\ UNCHANGED <<visible, attempts, severed>>
              \/ /\ \E m \in { x \in network :
                                  /\ x.type = "Deny"
                                  /\ x.to   = self
                                  /\ state[self] = StatePending
                                  /\ x.id   = myReq[self] }:
                      /\ expected' = [expected EXCEPT ![self] = {}]
                      /\ grants' = [grants EXCEPT ![self] = {}]
                      /\ myReq' = [myReq EXCEPT ![self] = NoReq]
                      /\ network' =   (network \ {m})
                                    \cup { MsgRelease(self, q) :
                                           q \in visible[self] }
                      /\ state' = [state EXCEPT ![self] = StateFree]
                 /\ UNCHANGED <<visible, attempts, severed>>
              \/ /\ \E m \in { x \in network : x.type = "Rel" /\ x.to = self }:
                      IF state[self].tag = "HeldBy" /\ state[self].who = m.from
                         THEN /\ /\ network' = network \ {m}
                                 /\ state' = [state EXCEPT ![self] = StateFree]
                         ELSE /\ network' = network \ {m}
                              /\ state' = state
                 /\ UNCHANGED <<myReq, grants, expected, visible, attempts, severed>>
              \/ /\ EnableDisconnect /\ visible[self] # {}
                 /\ \E q \in visible[self]:
                      /\ expected' = [expected EXCEPT ![self] = IF state[self] = StatePending
                                                                THEN expected[self] \ {q}
                                                                ELSE expected[self],
                                                      ![q] = IF state[q] = StatePending
                                                             THEN expected[q] \ {self}
                                                             ELSE expected[q]]
                      /\ severed' = (severed \cup { {self, q} })
                      /\ state' = [state EXCEPT ![self] = IF state[self].tag = "HeldBy"
                                                            /\ state[self].who = q
                                                          THEN StateFree
                                                          ELSE state[self],
                                                ![q] = IF state[q].tag = "HeldBy"
                                                         /\ state[q].who = self
                                                       THEN StateFree
                                                       ELSE state[q]]
                      /\ visible' = [visible EXCEPT ![self] = visible[self] \ {q},
                                                    ![q] = visible[q]    \ {self}]
                 /\ UNCHANGED <<myReq, grants, attempts, network>>

Next == (\E self \in Peers: Peer(self))

Spec == Init /\ [][Next]_vars

\* END TRANSLATION 

\* Symmetry: peers are interchangeable. Speeds up TLC ~ N! times.
Symmetry_Peers == Permutations(Peers)

\* ----------- TLA+ TRANSLATION (produced by `pcal LockSpec.tla`) -----------
\*
\* The PlusCal block above is the source of truth. Run the translator
\* once before TLC:
\*
\*    java -cp tla2tools.jar pcal.trans LockSpec.tla
\*
\* The translator overwrites this section in place with the next-state
\* relation and `Spec` definition. Modern tla2tools.jar invocations do
\* the translation automatically, so a plain
\*
\*    java -jar tla2tools.jar -config LockSpec_StartupRace.cfg LockSpec.tla
\*
\* works out of the box.
\*
=============================================================================
