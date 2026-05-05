# alan

[![License](https://img.shields.io/github/license/rakunlabs/alan?color=red&style=flat-square)](https://raw.githubusercontent.com/rakunlabs/alan/main/LICENSE)
[![Coverage](https://img.shields.io/sonar/coverage/rakunlabs_alan?logo=sonarcloud&server=https%3A%2F%2Fsonarcloud.io&style=flat-square)](https://sonarcloud.io/summary/overall?id=rakunlabs_alan)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/rakunlabs/alan/test.yml?branch=main&logo=github&style=flat-square&label=ci)](https://github.com/rakunlabs/alan/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/rakunlabs/alan?style=flat-square)](https://goreportcard.com/report/github.com/rakunlabs/alan)
[![Go PKG](https://raw.githubusercontent.com/rakunlabs/.github/main/assets/badges/gopkg.svg)](https://pkg.go.dev/github.com/rakunlabs/alan)

QUIC-based peer discovery and communication library for Go. All peer-to-peer
traffic is secured by QUIC's built-in TLS 1.3, with optional pre-shared-key
admission control. Supports both bytes-style RPC and zero-copy streaming for
arbitrarily large payloads.

## Features

- **DNS-based peer discovery** — resolve a DNS name to discover cluster members
- **Automatic membership** — JOIN/LEAVE on QUIC connect/disconnect
- **Secure transport by default** — QUIC + TLS 1.3 (mTLS); optional pre-shared
  key restricts which peers may join
- **Byte and streaming I/O** — `Send`/`Handle` for bounded RPC, `SendStream`/
  `HandleStream` for arbitrary-size payloads
- **Request-Reply pattern** — fire-and-collect responses across the cluster
- **Distributed locking** — named locks with automatic release on peer disconnect
- **Quorum support** — configurable quorum requirement for distributed operations
- **Cancellation everywhere** — every blocking method takes `context.Context`
- **Bounded memory by default** — `MaxMessageSize` cap and per-peer byte budget
  protect receivers from runaway senders

## Installation

```sh
go get github.com/rakunlabs/alan
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "net"

    "github.com/rakunlabs/alan"
)

func main() {
    a, err := alan.New(alan.Config{
        DNSAddr: "my-cluster.local",
        Port:    5000,
    })
    if err != nil {
        panic(err)
    }

    a.OnPeerJoin(func(addr *net.UDPAddr) {
        fmt.Printf("peer joined: %s\n", addr)
    })
    a.OnPeerLeave(func(addr *net.UDPAddr) {
        fmt.Printf("peer left: %s\n", addr)
    })

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    a.Handle("", func(ctx context.Context, msg alan.Message) {
        fmt.Printf("received from %s: %s\n", msg.Addr, msg.Data)
    })

    go a.Start(ctx)

    // Broadcast.
    a.Send(ctx, "", []byte("Hello everyone!"))

    // Send to a specific peer.
    target := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 5000}
    a.SendTo(ctx, target, "", []byte("Hello you!"))

    a.Stop()
}
```

## Cluster Admission (Pre-Shared Key)

Traffic is **always** encrypted by QUIC/TLS 1.3 — there is no insecure mode.
To restrict *which* peers may join your cluster, configure a pre-shared key.
Only peers presenting a TLS certificate bound to the same key are accepted
during the handshake.

```go
a, err := alan.New(alan.Config{
    DNSAddr: "my-cluster.local",
    Port:    5000,
    Security: alan.SecurityConfig{
        Key:     []byte("my-secret-key"), // any length, hashed into a 32-byte fingerprint
        Enabled: true,
    },
})
```

When `Enabled` is true, every peer must use the same `Key`. Peers with a
different key (or no key) fail the TLS handshake and never become members.

## Streaming I/O

For payloads that exceed `MaxMessageSize` (default 16 MiB), use the streaming
API. Both sides handle the body as an `io.Reader` / `io.Writer`, so memory
stays bounded regardless of payload size.

### Sender — stream from a file

```go
f, _ := os.Open("big.bin")
defer f.Close()

target := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 5000}
n, err := a.SendToStream(ctx, target, "blob", f)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("sent %d bytes\n", n)
```

For broadcast streaming use `SendStream`. The `io.Reader` is consumed once,
so peers are written serially.

### Receiver — stream to a hash / file / pipeline

```go
a.HandleStream("blob", func(ctx context.Context, msg alan.Message, body io.Reader) error {
    h := sha256.New()
    n, err := io.Copy(h, body)
    if err != nil {
        return err
    }
    log.Printf("got %d bytes from %s, sha256=%x", n, msg.Addr, h.Sum(nil))
    return nil
})
```

A given message-type can have **either** a byte handler (`Handle`) or a
stream handler (`HandleStream`), not both. Registering the second one returns
`ErrDuplicateHandler`.

Stream handlers run on a per-message goroutine; messages from the same peer
may be processed concurrently. Use `Handle` if you need ordered delivery.

## Global Instance

For services that create a single cluster-wide `Alan` instance, register it
as a process-wide default and access it from any package without passing the
handle around. Same pattern as `slog.Default` / `slog.SetDefault`.

```go
func main() {
    a, _ := alan.New(alan.Config{DNSAddr: "my-cluster.local", Port: 5000})

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    a.Handle("", handleMessage)
    go a.Start(ctx)

    alan.SetDefault(a)
    // ... run your service ...
}

// In some other package:
func Notify(ctx context.Context, data []byte) error {
    a, err := alan.Default()
    if err != nil {
        return err
    }
    a.Send(ctx, "", data)
    return nil
}
```

| Function | Description |
|----------|-------------|
| `SetDefault(*Alan)` | Register the global instance (pass `nil` to clear) |
| `Default() (*Alan, error)` | Get the instance; returns `ErrNoDefault` if none set |
| `MustDefault() *Alan` | Get the instance; panics if none set |
| `HasDefault() bool` | Check whether a default is registered |

`Default` / `MustDefault` use `atomic.Pointer[Alan]` and are lock-free on the
hot path. `SetDefault` is safe from any goroutine.

> If a single process needs to join two clusters, prefer passing `*Alan` as
> a dependency. The global is a convenience for the common single-cluster case.

## Request-Reply

```go
// Broadcast a request, collect responses.
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

replies, err := a.SendAndWaitReply(ctx, "", []byte("status-request"))
if err != nil && !errors.Is(err, context.DeadlineExceeded) {
    log.Fatal(err)
}
for _, reply := range replies {
    fmt.Printf("from %s: %s\n", reply.Addr, reply.Data)
}

// Single peer:
target := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 5000}
reply, err := a.SendToAndWaitReply(ctx, target, "", []byte("ping"))
```

### Responder side

```go
a.Handle("", func(ctx context.Context, msg alan.Message) {
    if msg.IsRequest() {
        a.Reply(ctx, msg, processRequest(msg.Data))
    } else {
        handleMessage(msg.Data)
    }
})
```

Notes:

- The library tracks which peers a request is waiting for. If a peer
  disconnects while you are waiting:
  - `SendAndWaitReply` drops it from the expected set and returns when the
    remaining peers have responded.
  - `SendToAndWaitReply` returns `ErrPeerDisconnected` immediately.
- Request/response bodies are bytes-only and capped by `MaxMessageSize`.
  Use `SendStream` / `HandleStream` for one-way streaming workloads.
- Request ID correlation is handled by the library.

## Distributed Locking

```go
ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
defer cancel()

if err := a.Lock(ctx, "my-job"); err != nil {
    log.Fatal(err)
}
doExclusiveWork()
if err := a.Unlock(ctx, "my-job"); err != nil {
    log.Fatal(err)
}
```

Non-blocking variant:

```go
if a.TryLock(ctx, "my-job") {
    defer a.Unlock(ctx, "my-job")
    doWork()
}
```

Features:

- **Named locks** — multiple independent locks identified by key
- **Auto-release** — held locks are released automatically when the holder disconnects
- **Quorum-aware** — `Lock` waits for quorum before acquiring
- **Context-driven** — every lock method respects `ctx`

Limitations: distributed lock is **best-effort coordination**, not strong
consistency.

- During network partitions, multiple peers may believe they hold the lock.
- No fencing tokens — there's no way to prove ownership to an external system.
- Startup race: peers starting simultaneously may all acquire the lock before
  discovering each other. Configure `Replicas` so quorum mitigates this.

### Leader Election Helpers

For "only one instance in the cluster runs this long-running task":

```go
err := a.RunAsLeader(ctx, "scheduler", func(ctx context.Context) error {
    if err := scheduler.Start(ctx); err != nil {
        return err
    }
    defer scheduler.Stop()
    <-ctx.Done()
    return ctx.Err()
})
```

Other instances block in their own `RunAsLeader` until the current leader
releases (via `Unlock`, `fn` returning, or QUIC idle timeout if it crashes).

`LeaderLoop` re-acquires if `fn` returns before `ctx` is cancelled:

```go
err := a.LeaderLoop(ctx, "scheduler", 5*time.Second,
    func(ctx context.Context) error {
        return runCron(ctx)
    })
```

Notes:
- Locks have no TTL / session: the holder keeps them until `Unlock`, graceful
  exit, or QUIC `MaxIdleTimeout`. There is no "lock lost" notification.
- The helpers do not pass a separate "leader context" to `fn`. If you need
  a context scoped to leadership specifically, derive one inside `fn`.

## Quorum

Quorum ensures distributed operations only proceed when enough peers are
present in the cluster.

```go
a, _ := alan.New(alan.Config{
    DNSAddr:  "my-cluster.local",
    Port:     5000,
    Replicas: 3, // expected total cluster size, including self
})
```

`Replicas` is the **total** cluster size; the quorum is a majority of that
total. `QuorumSize()` returns the number of *peers* (excluding self) required:

| Replicas | Required peers (`QuorumSize`) | Effective quorum |
|---------:|-----------------------------:|-----------------:|
| 0        | 0                            | disabled         |
| 1        | 0                            | 1 (just self)    |
| 2        | 1                            | 2 of 2           |
| 3        | 1                            | 2 of 3           |
| 4        | 2                            | 3 of 4           |
| 5        | 2                            | 3 of 5           |
| 6        | 3                            | 4 of 6           |
| 7        | 3                            | 4 of 7           |

Operations:

| Operation | Behaviour |
|-----------|-----------|
| `Lock(ctx, key)` | Waits for quorum, then acquires |
| `TryLock(ctx, key)` | Returns false if quorum not met |
| `HasQuorum()` | Snapshot check |
| `WaitForQuorum(ctx)` | Block until quorum reached |
| `HasAllPeers()` / `WaitAll(ctx)` | Same but for full membership |

## Configuration

```go
type Config struct {
    // DNSAddr is the DNS name to resolve for discovering peers (optional).
    DNSAddr string

    // BindAddr is the local IP to bind to (default: "0.0.0.0").
    BindAddr string

    // Port is the UDP port to use (default: 5000). All peers must use the
    // same port — DNS only provides IPs, the port is taken from this field.
    Port int

    // Timeout is the read/write timeout for short control operations (default: 5s).
    Timeout time.Duration

    // HeartbeatInterval controls QUIC KeepAlivePeriod (default: 5s).
    HeartbeatInterval time.Duration

    // HeartbeatTimeout controls QUIC MaxIdleTimeout (default: 15s).
    // Peers not exchanging traffic within this window are torn down.
    HeartbeatTimeout time.Duration

    // RefreshInterval is how often to re-resolve DNS (default: 30s; -1 disables).
    // Refresh only adds new peers; stale peers are removed via QUIC idle timeout.
    RefreshInterval time.Duration

    // MessageQueueSize is the per-peer queue length for byte handlers
    // (default: 256). Stream handlers bypass the queue.
    MessageQueueSize int

    // MaxMessageSize is the maximum payload size in bytes for the bytes-API
    // (Send / SendTo / SendAndWaitReply / Reply). Larger payloads are
    // rejected with ErrMessageTooLarge before allocation. Default: 16 MiB.
    // Negative disables the cap (not recommended). Use SendStream / HandleStream
    // for arbitrary-size payloads.
    MaxMessageSize int64

    // MessageQueueBytes is the per-peer queue's byte budget. When exceeded,
    // the QUIC accept loop blocks on enqueue (backpressure). Default: 256 MiB.
    // Negative disables the cap.
    MessageQueueBytes int64

    // StreamOpenTimeout is the maximum time the receiver will wait for the
    // first byte of a newly accepted stream before closing it. Defends
    // against half-open streams. Default: 10s.
    StreamOpenTimeout time.Duration

    // Replicas is the expected total cluster size (including self) for
    // quorum-aware operations. 0 disables quorum (default).
    Replicas int

    // Security configures the optional pre-shared key for cluster admission.
    // Transport encryption (QUIC/TLS 1.3) is always enabled regardless.
    Security SecurityConfig
}

type SecurityConfig struct {
    // Key is a pre-shared cluster admission secret. Any length; hashed with
    // SHA-256 into a 32-byte fingerprint embedded in each peer's TLS cert
    // and verified on every handshake.
    Key []byte

    // Enabled turns PSK admission control on. When false, any peer reaching
    // the listener can complete the TLS handshake (transport stays encrypted).
    Enabled bool
}
```

## How It Works

### Peer Discovery

1. On `Start`, the library resolves `DNSAddr` to get initial peer IPs.
2. For each IP it dials a QUIC connection to `<ip>:<Port>`.
3. The successful TLS+QUIC handshake = JOIN. No application-level handshake.
4. When a connection drops or `MaxIdleTimeout` fires, the peer is removed
   and `OnPeerLeave` fires. Locks held by that peer are released.

### Wire Protocol

Every QUIC stream carries exactly one logical message. The first byte is the
`MsgType`:

| Hex | Type | Frame |
|----:|------|-------|
| `0x10` | `Data` | `[0x10][TypeLen:2][Type:T] <body until FIN>` |
| `0x20` | `Request` | `[0x20][RequestID:16][TypeLen:2][Type:T][BodyLen:varint][Body]` |
| `0x21` | `Response` | `[0x21][RequestID:16][BodyLen:varint][Body]` |
| `0x30` | `LockRequest` | `[0x30][RequestID:16][KeyLen:2][Key]` |
| `0x31` | `LockGrant` | `[0x31][RequestID:16][KeyLen:2][Key]` |
| `0x32` | `LockDeny` | `[0x32][RequestID:16][KeyLen:2][Key]` |
| `0x33` | `LockRelease` | `[0x33][RequestID:16][KeyLen:2][Key]` |

Notes:
- `Data` bodies are **FIN-delimited** — the sender doesn't need to know the
  full size up-front, and the receiver can deliver the body to a handler as
  an `io.Reader` without buffering. This is what `SendStream` / `HandleStream`
  use.
- `Request` / `Response` bodies are length-prefixed (varint) so the receiver
  can enforce `MaxMessageSize` before allocating.
- The protocol version is negotiated by ALPN (`"alan/2"`). Peers with a
  different ALPN fail the TLS handshake.

### Message Ordering

- **Byte handlers** (`Handle`): messages from the same peer are dispatched in
  order. Each peer has a dedicated channel and worker goroutine.
- **Stream handlers** (`HandleStream`): each accepted stream spawns its own
  goroutine and reads the body directly. Messages from the same peer may be
  processed concurrently. If you need ordered streaming, register a byte
  handler and dispatch internally.

### Message Size Limits

The bytes-API is capped by `Config.MaxMessageSize` (default 16 MiB):

- Sender pre-flight: `Send` / `SendTo` / `Reply` / `*AndWaitReply` return
  `ErrMessageTooLarge` immediately if `len(data) > MaxMessageSize`.
- Receiver enforcement: `Request` / `Response` frames carry a varint length;
  the receiver checks it against `MaxMessageSize` *before* allocating. A
  malicious peer cannot OOM you with a 4 GiB length announcement.
- Byte data messages: the body is read via `io.LimitReader(stream, max+1)`;
  if the receiver reads more than the cap, the message is dropped.
- Streaming (`SendStream` / `HandleStream`) bypasses the cap entirely; the
  handler is responsible for bounding its own reads.

### Per-peer Backpressure

For byte handlers, each peer's queue tracks both:
- `MessageQueueSize` — count of pending messages (default 256)
- `MessageQueueBytes` — total bytes pending (default 256 MiB)

Whichever cap is hit first applies backpressure to the QUIC stream-accept
loop, which propagates back to the sender via QUIC flow control. Stream
handlers bypass the queue entirely.

### Secure Transport (QUIC + TLS 1.3)

Alan does **not** implement its own message encryption. Every peer-to-peer
connection runs over [QUIC](https://datatracker.ietf.org/doc/html/rfc9000),
which carries [TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446) inside
its handshake. This gives the cluster strong, modern security with no
application-level crypto code:

1. **One UDP socket, QUIC on top.** Alan opens a single UDP socket on the
   configured port and hands it to `quic.Transport`. Every peer is reached
   by establishing a QUIC connection to that peer's `udp:host:port`;
   membership/data/lock messages travel over QUIC streams.
2. **TLS 1.3 handshake on first contact.** Before any application bytes
   flow, QUIC runs a TLS 1.3 handshake. This negotiates an AEAD cipher
   suite (AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305 — chosen by the
   TLS stack), performs an ECDHE key exchange, and derives per-direction
   traffic keys with full forward secrecy.
3. **Mutual TLS (mTLS).** Both sides present a certificate (`ClientAuth =
   RequireAnyClientCert`). On startup each peer generates an **ephemeral
   self-signed ECDSA P-256 certificate** in memory — there are no files
   or CAs to manage.
4. **ALPN pins the protocol.** The handshake advertises a single ALPN
   identifier, `alan/2`. A peer speaking a different ALPN is rejected
   before any frames are read; this is also how alan version-bumps the
   wire protocol cleanly.
5. **Optional pre-shared key for cluster admission.** When
   `SecurityConfig.Enabled` is true, the SHA-256 fingerprint of `Key` is
   embedded into the certificate's `Subject.Organization` field. The TLS
   `VerifyPeerCertificate` callback compares it with a constant-time
   compare and fails the handshake on mismatch (`"PSK mismatch: peer not
   in cluster"`).
6. **Encrypted, authenticated, and integrity-protected.** Once the
   handshake completes, *every* QUIC packet — including membership
   protocol, user data, requests/responses, lock RPCs — is encrypted and
   authenticated by the negotiated AEAD. QUIC also encrypts most of its
   own headers, so on-path observers see only opaque UDP datagrams.
7. **Connection-level keep-alive and idle timeout.** QUIC keeps the
   secure session alive with its own keep-alives and tears it down on
   `MaxIdleTimeout`, so a crashed peer's session does not linger.

In short: confidentiality, integrity, peer authentication, and forward
secrecy come from QUIC/TLS 1.3. The optional pre-shared key adds *cluster
membership* authentication on top — it controls *who* may join, not
*whether* traffic is encrypted.

#### How mTLS and self-signed certs are safe here

The classic objection to self-signed certs is "no CA vouches for the
identity, so you don't know who you're talking to." Alan sidesteps this by
**redefining what identity means** for a peer.

Standard web PKI:
- Identity = DNS name
- Trust anchor = a CA in the OS root store

Alan:
- Identity = "member of *this* cluster"
- Trust anchor = the **pre-shared key**, embedded into each cert's
  `Subject.Organization` and verified on every handshake

Threat coverage:

| Threat | Why it fails |
|--------|--------------|
| Random attacker dials your port | No PSK → certificate's `Organization` doesn't match → `VerifyPeerCertificate` rejects |
| Stolen certificate (it's public anyway) | Without the matching private key, the attacker cannot sign the TLS `CertificateVerify` — handshake fails. Private keys live only in the issuing peer's RAM |
| MITM proxies traffic | The MITM has to terminate TLS on both legs and present its own cert. Without the PSK it cannot forge a cert with the right `Organization`; the verifier rejects |
| Insider leaves with cert | Rotate `SecurityConfig.Key` → all peers regenerate certs with a new PSK fingerprint → old cert no longer matches. No CRL needed |
| Cert/key leaked from disk | Keys are never written to disk — `generatePSKCert` keeps them in process memory and they die with the process |
| Algorithm/cipher downgrade | TLS 1.3 only (QUIC requirement) + ALPN `alan/2` so a peer speaking a different protocol is rejected before any frame is read |

Forward secrecy: TLS 1.3 mandates ephemeral ECDHE, so even if
`SecurityConfig.Key` later leaks, previously captured ciphertext cannot be
decrypted — the PSK is only used for *admission*, never for deriving traffic
keys.

When `SecurityConfig.Enabled` is false the channel is still TLS-encrypted,
but any peer can join. That is fine on a closed network (private VPC,
pod-to-pod inside a cluster) but should not be exposed to untrusted networks.

## API Reference

### Package-level

| Function | Description |
|----------|-------------|
| `New(Config)` | Create a new instance |
| `SetDefault(*Alan)` | Register a process-wide default |
| `Default() (*Alan, error)` | Get the default; `ErrNoDefault` if unset |
| `MustDefault() *Alan` | Get the default; panics if unset |
| `HasDefault() bool` | Whether a default is registered |

### Lifecycle / discovery

| Method | Description |
|--------|-------------|
| `Start(ctx)` | Start the discovery system (blocking) |
| `Stop()` | Gracefully stop |
| `Ready() <-chan struct{}` | Closed when ready |
| `Refresh()` | Manually re-resolve DNS |
| `Peers()` | Current peer addresses |
| `PeerCount()` | Peer count |
| `LocalAddr()` | Local listening address |
| `IsSecure()` | PSK admission enabled? |
| `Config()` | Snapshot of the configuration |
| `OnPeerJoin(handler)` | Set the join callback |
| `OnPeerLeave(handler)` | Set the leave callback |

### Messaging

| Method | Description |
|--------|-------------|
| `Handle(type, handler)` | Register a byte handler for `type` |
| `HandleStream(type, handler)` | Register a streaming handler for `type` |
| `Remove(type)` | Remove handler(s) for `type` |
| `Send(ctx, type, data) []SendResult` | Broadcast bytes to all peers |
| `SendTo(ctx, addr, type, data)` | Send bytes to one peer |
| `SendStream(ctx, type, body)` | Broadcast streaming body to all peers (serial) |
| `SendToStream(ctx, addr, type, body)` | Stream body to one peer |
| `SendAndWaitReply(ctx, type, data)` | RPC broadcast — collect responses |
| `SendToAndWaitReply(ctx, addr, type, data)` | RPC to one peer |
| `Reply(ctx, msg, data)` | Respond to a request message |

### Locks / leader election

| Method | Description |
|--------|-------------|
| `Lock(ctx, key)` | Acquire (blocking) |
| `TryLock(ctx, key)` | Acquire (non-blocking) |
| `Unlock(ctx, key)` | Release |
| `RunAsLeader(ctx, key, fn)` | Acquire, run `fn`, release |
| `LeaderLoop(ctx, key, retry, fn)` | Continuously re-acquire and run `fn` |

### Quorum

| Method | Description |
|--------|-------------|
| `HasQuorum()` | Snapshot |
| `WaitForQuorum(ctx)` | Block until reached |
| `QuorumSize()` | Required peer count |
| `HasAllPeers()` / `WaitAll(ctx)` | Full-membership variants |

### Types

```go
type Message struct {
    Type string       // matched handler type
    Data []byte       // body for byte handlers; empty for stream handlers
    Addr *net.UDPAddr // sender
    Size int64        // body length, or -1 if unknown (Data messages on the read path)
}
func (m Message) IsRequest() bool

type Reply struct {
    Data []byte
    Addr *net.UDPAddr
}

type SendResult struct {
    Addr  *net.UDPAddr
    Sent  int64
    Error error
}

type PeerHandler    func(addr *net.UDPAddr)
type MessageHandler func(ctx context.Context, msg Message)
type StreamHandler  func(ctx context.Context, msg Message, body io.Reader) error
```

### Errors

```go
var (
    ErrEmptyKey         // Security.Enabled with empty Key
    ErrAlreadyStarted   // Start called on running instance
    ErrNotStarted       // operation requires Start
    ErrPeerDisconnected // peer left mid-RPC
    ErrNoQuorum         // quorum not currently met
    ErrLockNotHeld      // Unlock called for lock not held here
    ErrNoPeerConnection // no live QUIC conn for target
    ErrMessageTooLarge  // bytes-API exceeds MaxMessageSize
    ErrDuplicateHandler // both Handle and HandleStream for same type
    ErrTypeTooLong      // message type > 65535 bytes
    ErrFrameTooLarge    // wire frame announced > MaxMessageSize
    ErrNoDefault        // global Default() with none set
)
```

## Upgrading from an earlier version

This release breaks both source compatibility and wire compatibility:

- **Wire (ALPN bump):** the protocol identifier moved from `alan/1` to
  `alan/2`. Old peers fail the TLS handshake against new peers — there is
  no silent corruption. Upgrade all peers together.
- **Source:** every `Send` / `SendTo` / `SendStream` / `SendToStream` /
  `SendAndWaitReply` / `SendToAndWaitReply` / `Reply` / `Lock` / `TryLock` /
  `Unlock` call now takes `context.Context` as the first argument. Pass
  `context.Background()` if you need today's behaviour.
- **Frame format:** `Data` messages are now FIN-delimited (no length prefix);
  `Request` / `Response` use varint lengths. Application-level message types
  are unaffected — only the wire encoding changed.
- **Receiver safety:** every length-prefixed frame is bounded by
  `Config.MaxMessageSize` (default 16 MiB). Switch to `SendStream` /
  `HandleStream` to lift the cap for a specific message type.
- **Application encryption removed:** earlier versions documented optional
  ChaCha20-Poly1305 at the application layer. That is gone — encryption now
  comes from QUIC/TLS 1.3 (also AEAD; cipher suite is negotiated by TLS).
  `SecurityConfig.Key` now controls cluster admission, not data encryption.

## UDP Buffer Size (Linux)

QUIC performs best with larger UDP buffers. If you see a warning about
receive buffer size, increase the OS limits:

```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```

To persist across reboots, add to `/etc/sysctl.conf`:

```
net.core.rmem_max=7500000
net.core.wmem_max=7500000
```

This is optional — the application works without it, but may drop packets
under heavy load.

## License

MIT License — see [LICENSE](LICENSE) for details.
