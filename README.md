# alan

[![License](https://img.shields.io/github/license/rakunlabs/alan?color=red&style=flat-square)](https://raw.githubusercontent.com/rakunlabs/alan/main/LICENSE)
[![Coverage](https://img.shields.io/sonar/coverage/rakunlabs_alan?logo=sonarcloud&server=https%3A%2F%2Fsonarcloud.io&style=flat-square)](https://sonarcloud.io/summary/overall?id=rakunlabs_alan)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/rakunlabs/alan/test.yml?branch=main&logo=github&style=flat-square&label=ci)](https://github.com/rakunlabs/alan/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/rakunlabs/alan?style=flat-square)](https://goreportcard.com/report/github.com/rakunlabs/alan)
[![Go PKG](https://raw.githubusercontent.com/rakunlabs/.github/main/assets/badges/gopkg.svg)](https://pkg.go.dev/github.com/rakunlabs/alan)

QUIC-based peer discovery and communication library for Go. All peer-to-peer traffic is secured by QUIC's built-in TLS 1.3.

## Features

- **DNS-based peer discovery** - Resolve a DNS name to discover cluster members
- **Automatic membership** - JOIN/LEAVE/HEARTBEAT protocol for peer tracking
- **Secure transport by default** - All traffic runs over QUIC with TLS 1.3 (mTLS); optional pre-shared key restricts which peers may join the cluster
- **Request-Reply pattern** - Send requests and wait for responses from peers
- **Distributed locking** - Named locks with automatic release on peer disconnect
- **Quorum support** - Configurable quorum requirement for distributed operations
- **Simple API** - `Start()`, `Send()`, `Stop()` - that's it
- **Callbacks** - Get notified when peers join or leave
- **Auto-refresh** - Optionally re-resolve DNS to discover new peers

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
    // Create Alan instance
    a, err := alan.New(alan.Config{
        DNSAddr: "my-cluster.local",  // DNS name for peer discovery
        Port:    5000,
    })
    if err != nil {
        panic(err)
    }

    // Optional: Get notified when peers join/leave
    a.OnPeerJoin(func(addr *net.UDPAddr) {
        fmt.Printf("Peer joined: %s\n", addr)
    })
    a.OnPeerLeave(func(addr *net.UDPAddr) {
        fmt.Printf("Peer left: %s\n", addr)
    })

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Register message handler
    a.Handle("", func(ctx context.Context, msg alan.Message) {
        fmt.Printf("Received from %s: %s\n", msg.Addr, msg.Data)
    })

    // Start in background
    go func() {
        a.Start(ctx)
    }()

    // Send to all peers
    a.Send("", []byte("Hello everyone!"))

    // Send to specific peer
    a.SendTo(specificAddr, "", []byte("Hello you!"))

    // Graceful shutdown
    a.Stop()
}
```

## Global Instance

For services that create a single cluster-wide `Alan` instance, you can register
it as a process-wide default and access it from any package without passing the
handle around. This follows the same pattern as `slog.Default` / `slog.SetDefault`.

### Register at startup

```go
func main() {
    a, err := alan.New(alan.Config{DNSAddr: "my-cluster.local", Port: 5000})
    if err != nil {
        log.Fatal(err)
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    a.Handle("", handleMessage)
    go a.Start(ctx)

    // Register as the process-wide default
    alan.SetDefault(a)

    // ... run your service ...
}
```

### Use from any package

```go
package worker

import "github.com/rakunlabs/alan"

func Notify(data []byte) error {
    a, err := alan.Default()
    if err != nil {
        return err // no default registered yet
    }
    a.Send("", data)
    return nil
}
```

### API

| Function | Description |
|----------|-------------|
| `SetDefault(*Alan)` | Register the global instance (pass `nil` to clear) |
| `Default() (*Alan, error)` | Get the instance; returns `ErrNoDefault` if none set |
| `MustDefault() *Alan` | Get the instance; panics if none set |
| `HasDefault() bool` | Check whether a default is registered |

Internally uses `atomic.Pointer[Alan]`, so `Default()` / `MustDefault()` are
lock-free on the hot path and `SetDefault()` is safe from any goroutine.

> **When not to use this:** if a single process needs to join two clusters
> (two `Alan` instances), prefer passing `*Alan` as a dependency. The global
> is a convenience for the common single-cluster case.

## Cluster Admission (Pre-Shared Key)

Traffic is **always** encrypted by QUIC/TLS 1.3 — there is no insecure mode. To restrict
*which* peers may join your cluster, configure a pre-shared key. Only peers presenting a
TLS certificate bound to the same key are accepted during the handshake.

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

When `Enabled` is true, the same `Key` must be configured on every peer. Peers with a
different key (or no key) will fail the TLS handshake and never become members.

## Request-Reply Pattern

Alan supports a request-reply pattern for scenarios where you need responses from peers:

### Send to All Peers and Collect Responses

```go
// Broadcast request to all peers and wait for their responses
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

replies, err := a.SendAndWaitReply(ctx, "", []byte("status-request"))
if err != nil && !errors.Is(err, context.DeadlineExceeded) {
    log.Fatal(err)
}

for _, reply := range replies {
    fmt.Printf("Response from %s: %s\n", reply.Addr, reply.Data)
}
```

### Send to Specific Peer and Wait for Response

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

reply, err := a.SendToAndWaitReply(ctx, peerAddr, "", []byte("ping"))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Got response: %s\n", reply.Data)
```

### Handling Requests (Responder Side)

```go
a.Handle("", func(ctx context.Context, msg alan.Message) {
    if msg.IsRequest() {
        // This is a request expecting a reply
        response := processRequest(msg.Data)
        a.Reply(msg, response)
    } else {
        // Regular fire-and-forget message
        handleMessage(msg.Data)
    }
})
go a.Start(ctx)
```

### Notes on Request-Reply

- **Smart peer tracking**: The library tracks which peers you're waiting for responses from
- **Early return on disconnect**: If a peer disconnects (gracefully or via heartbeat timeout) while waiting, the library automatically adjusts:
  - `SendAndWaitReply`: Removes the disconnected peer from expected responses and returns when all remaining peers have responded
  - `SendToAndWaitReply`: Returns immediately with `ErrPeerDisconnected` if the target peer disconnects
- **No infinite waits**: Because peer disconnects are detected via the membership protocol, requests won't wait forever for unresponsive peers
- The request ID correlation is handled automatically by the library

## Distributed Locking

Alan provides distributed named locks for coordinating work across peers:

### Basic Lock Usage

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

// Acquire a named lock (blocks until acquired or context cancelled)
err := a.Lock(ctx, "my-job")
if err != nil {
    log.Fatal("failed to acquire lock:", err)
}

// Do protected work...
doExclusiveWork()

// Release the lock
err = a.Unlock("my-job")
if err != nil {
    log.Fatal("failed to release lock:", err)
}
```

### TryLock (Non-blocking)

```go
// Try to acquire lock without blocking
if a.TryLock("my-job") {
    // Got the lock
    defer a.Unlock("my-job")
    doWork()
} else {
    // Lock is held by another peer
    log.Println("could not acquire lock")
}
```

### Lock Features

- **Named locks**: Multiple independent locks identified by key
- **Auto-release**: Locks are automatically released when the holder disconnects
- **Quorum-aware**: When quorum is enabled, `Lock()` waits for quorum before acquiring
- **Context support**: `Lock()` respects context cancellation and deadlines

### Lock Limitations

The distributed lock provides **best-effort coordination**, not strong consistency:

- **Split-brain possible**: During network partitions, multiple peers might acquire the same lock
- **No fencing tokens**: There's no mechanism to prove lock ownership to external systems
- **Startup race**: If peers start simultaneously before discovering each other, both might acquire a lock

Use quorum configuration to mitigate the startup race condition.

### Leader Election Helpers

For the common pattern "only one instance in the cluster should run this
long-running task", Alan provides two wrappers around `Lock`/`Unlock`.

#### RunAsLeader

```go
err := a.RunAsLeader(ctx, "scheduler", func(ctx context.Context) error {
    if err := scheduler.Start(ctx); err != nil {
        return err
    }
    defer scheduler.Stop()
    <-ctx.Done() // hold leadership until shutdown
    return ctx.Err()
})
```

Blocks inside the acquire until this instance becomes leader, runs `fn`,
and releases the lock when `fn` returns or `ctx` is cancelled. Other
instances in the cluster block in their own `RunAsLeader` call until the
current leader releases (via `Unlock`, `fn` returning, or heartbeat timeout
if the leader crashes).

This replaces hand-rolled leader loops like:

```go
// Before: manual retry / hold / release
for {
    if err := a.Lock(ctx, "scheduler"); err != nil {
        if ctx.Err() != nil { return }
        time.Sleep(5 * time.Second)
        continue
    }
    startWork()
    <-ctx.Done()
    stopWork()
    a.Unlock("scheduler")
    return
}

// After:
a.RunAsLeader(ctx, "scheduler", func(ctx context.Context) error {
    startWork()
    defer stopWork()
    <-ctx.Done()
    return ctx.Err()
})
```

#### LeaderLoop

Same as `RunAsLeader` but re-acquires if `fn` exits before `ctx` is cancelled:

```go
err := a.LeaderLoop(ctx, "scheduler", 5*time.Second,
    func(ctx context.Context) error {
        return runCron(ctx) // if this returns, helper retries after 5s
    })
```

Useful when `fn` might exit unexpectedly but you still want the service to
retain leader semantics across the cluster. Errors returned by `fn` are
discarded by the loop — handle them inside `fn` (log, metrics, etc.) if
you need them. `LeaderLoop` itself returns only when `ctx` is cancelled,
and always returns `ctx.Err()`. A `retryDelay` of 0 uses a 1-second default.

#### Notes

- Alan locks have no TTL / session; once held, the holder keeps the lock
  until it calls `Unlock`, exits gracefully (LEAVE), or stops heartbeating
  (detected via `HeartbeatTimeout`). There is no mid-run "lock lost"
  notification — these helpers assume holding the lock == being the leader.
- The helpers do not pass a separate "leader context" to `fn`. If you need
  a context scoped strictly to the leadership window (e.g. to cancel
  dependent workers when leadership ends), derive one inside `fn`.

## Quorum

Quorum ensures operations only proceed when enough peers are present in the cluster:

### Configuration

```go
a, err := alan.New(alan.Config{
    DNSAddr: "my-cluster.local",
    Port:    5000,
    Quorum:  3, // Expected cluster size
})
```

With `Quorum: 3`, operations require `(3/2)+1 = 2` peers to be present.

| Quorum Setting | Required Peers |
|----------------|----------------|
| 0 (default)    | Disabled       |
| 1              | 1              |
| 2              | 2              |
| 3              | 2              |
| 4              | 3              |
| 5              | 3              |

### Quorum-Aware Operations

| Operation | Quorum Behavior |
|-----------|-----------------|
| `Lock(ctx, key)` | Waits for quorum, then acquires lock |
| `TryLock(key)` | Returns `false` if quorum not met |

### Checking Quorum Status

```go
// Check if quorum is currently met
if a.HasQuorum() {
    // Safe to proceed
}

// Get required peer count
required := a.QuorumSize() // Returns (Quorum/2)+1

// Wait for quorum before starting work
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := a.WaitForQuorum(ctx); err != nil {
    log.Fatal("cluster not ready:", err)
}
```

## Configuration

```go
type Config struct {
    // DNSAddr is the DNS name to resolve for discovering peers (required)
    DNSAddr string
    
    // BindAddr is the local IP address to bind to (default: "0.0.0.0" for all interfaces)
    // Useful when running multiple instances on same machine with different IPs
    BindAddr string
    
    // Port is the UDP port to use (default: 5000)
    // IMPORTANT: All peers in the cluster MUST use the same port
    Port int
    
    // Timeout is the read/write timeout (default: 5s)
    Timeout time.Duration
    
    // BufferSize for receiving messages (default: 4096)
    BufferSize int
    
    // HeartbeatInterval - how often to send heartbeats (default: 5s)
    HeartbeatInterval time.Duration
    
    // HeartbeatTimeout - when a peer is considered dead (default: 15s)
    HeartbeatTimeout time.Duration
    
    // RefreshInterval - how often to re-resolve DNS (default: 30s, set to -1 to disable)
    // Note: Refresh only adds new peers; stale peers are removed via heartbeat timeout
    RefreshInterval time.Duration
    
    // MessageQueueSize - per-peer message buffer size (default: 256)
    // Messages from the same peer are processed in order.
    // When the queue is full, the listener blocks until space is available.
    MessageQueueSize int
    
    // Quorum - expected cluster size for distributed operations (default: 0 = disabled)
    // When set, operations like Lock() and SendCtx() wait until (Quorum/2)+1 peers are present
    Quorum int

    // Security configures the optional pre-shared key for cluster admission.
    // Transport encryption (QUIC/TLS 1.3) is always enabled regardless of this field.
    Security SecurityConfig
}

type SecurityConfig struct {
    // Key is a pre-shared cluster admission secret. Any length; hashed with SHA-256
    // into a 32-byte fingerprint that is embedded in each peer's TLS certificate
    // and verified on every handshake. Only peers with the same Key can connect.
    Key []byte

    // Enabled turns PSK admission control on. When false, any peer reaching the
    // listener can complete the TLS handshake (transport is still encrypted).
    Enabled bool
}
```

> **Note:** All peers in the cluster must use the same port. DNS only provides IP addresses,
> so the library assumes all peers listen on the configured port.

## How It Works

### Peer Discovery

1. On `Start()`, the library resolves `DNSAddr` to get initial peer IPs
2. Sends JOIN message to all discovered peers
3. Other peers add the new member to their peer list

### Membership Protocol

The library uses a simple internal protocol:

| Message | Purpose |
|---------|---------|
| JOIN | Announce joining the cluster |
| LEAVE | Announce graceful departure |
| HEARTBEAT | Periodic keepalive |
| DATA | User data message |
| REQUEST | Request message expecting a response |
| RESPONSE | Response to a request message |
| LOCK_REQUEST | Request to acquire a distributed lock |
| LOCK_GRANT | Grant lock to requester |
| LOCK_DENY | Deny lock (already held) |
| LOCK_RELEASE | Notify lock has been released |

- **JOIN**: Sent on startup to all known peers
- **HEARTBEAT**: Sent every `HeartbeatInterval` to all peers
- **LEAVE**: Sent on `Stop()` to notify peers of graceful shutdown
- **Timeout**: Peers not seen within `HeartbeatTimeout` are removed

### Message Ordering

Messages from the same peer are guaranteed to be processed in order:

- Each peer has a dedicated message queue (per-peer channel)
- A worker goroutine processes messages from each queue sequentially
- This ensures DATA and REQUEST messages from the same peer are handled in the order received
- Queue size is configurable via `MessageQueueSize` (default: 256)
- When a queue is full, the listener blocks (backpressure)
- Queues are automatically cleaned up when peers leave or timeout

### Peer Event Ordering

Peer join/leave events are also processed in order:

- A single event queue handles all `OnPeerJoin` and `OnPeerLeave` callbacks
- Events are processed sequentially by a dedicated worker
- When the queue is full, the listener blocks (backpressure)
- This ensures handlers see events in the order they occurred

### Secure Transport (QUIC + TLS 1.3)

Alan does **not** implement its own message encryption. Instead, every peer-to-peer
connection runs over [QUIC](https://datatracker.ietf.org/doc/html/rfc9000), which carries
[TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446) inside its handshake. This gives
the cluster strong, modern security with no application-level crypto code:

1. **One UDP socket, QUIC on top.** Alan opens a single UDP socket on the configured
   port and hands it to `quic.Transport`. Every peer is reached by establishing a QUIC
   connection to that peer's `udp:host:port`; membership/data/lock messages then travel
   over QUIC streams.
2. **TLS 1.3 handshake on first contact.** Before any application bytes flow, QUIC runs
   a TLS 1.3 handshake. This negotiates an AEAD cipher suite (typically AES-128-GCM,
   AES-256-GCM, or ChaCha20-Poly1305 — chosen by the TLS stack), performs an ECDHE key
   exchange, and derives per-direction traffic keys. Both 0-RTT and full handshakes
   produce a forward-secret session.
3. **Mutual TLS (mTLS).** Both sides present a certificate (`ClientAuth =
   RequireAnyClientCert`). On startup each peer generates an **ephemeral self-signed
   ECDSA P-256 certificate** in memory — there are no files or CAs to manage.
4. **ALPN pins the protocol.** The handshake advertises a single ALPN identifier,
   `alan/1`. A peer speaking a different protocol on the same port is rejected before
   any frames are read.
5. **Optional pre-shared key for cluster admission.** When `SecurityConfig.Enabled` is
   true, the SHA-256 fingerprint of `Key` is embedded into the certificate's
   `Subject.Organization` field. The TLS `VerifyPeerCertificate` callback compares the
   fingerprint on the peer's cert to the local one and fails the handshake on mismatch
   (`"PSK mismatch: peer not in cluster"`). Without a matching key, no QUIC connection,
   no streams, no data — the peer simply cannot join.
6. **Encrypted, authenticated, and integrity-protected.** Once the handshake completes,
   *every* QUIC packet — including the membership protocol (JOIN / LEAVE / HEARTBEAT),
   user data, requests/responses, and lock RPCs — is encrypted and authenticated by the
   negotiated AEAD. QUIC also encrypts most of its own headers, so on-path observers
   see only opaque UDP datagrams.
7. **Connection-level keep-alive and idle timeout.** QUIC keeps the secure session alive
   with its own keep-alives and tears it down on `MaxIdleTimeout`, so a crashed peer's
   session does not linger.

In short: confidentiality, integrity, peer authentication, and forward secrecy are all
provided by QUIC/TLS 1.3. The optional pre-shared key adds *cluster membership*
authentication on top — it controls *who* may join, not *whether* traffic is encrypted.

## API Reference

### Package-level

| Function | Description |
|----------|-------------|
| `New(Config)` | Create new Alan instance |
| `SetDefault(*Alan)` | Register process-wide default instance |
| `Default() (*Alan, error)` | Get the default instance |
| `MustDefault() *Alan` | Get the default instance or panic |
| `HasDefault() bool` | Report whether a default has been set |

### Alan

| Method | Description |
|--------|-------------|
| `OnPeerJoin(handler)` | Set callback for peer join events |
| `OnPeerLeave(handler)` | Set callback for peer leave events |
| `Start(ctx, handler)` | Start the peer discovery system (blocking) |
| `Stop()` | Gracefully stop and notify peers |
| `Send(ctx, data)` | Send data to all peers (waits for quorum if enabled) |
| `SendTo(addr, data)` | Send data to a specific peer (no quorum check) |
| `SendAndWaitReply(ctx, data)` | Send request to all peers and wait for responses |
| `SendToAndWaitReply(ctx, addr, data)` | Send request to specific peer and wait for response |
| `Reply(msg, data)` | Send response to a request message |
| `Lock(ctx, key)` | Acquire a distributed lock (blocking) |
| `TryLock(key)` | Try to acquire a lock (non-blocking) |
| `Unlock(key)` | Release a distributed lock |
| `RunAsLeader(ctx, key, fn)` | Acquire lock, run fn while holding it, release on return |
| `LeaderLoop(ctx, key, retry, fn)` | Continuously re-acquire and run fn until ctx cancelled |
| `HasQuorum()` | Check if quorum is currently met |
| `WaitForQuorum(ctx)` | Block until quorum is reached |
| `QuorumSize()` | Get required peer count for quorum |
| `Peers()` | Get list of current peer addresses |
| `PeerCount()` | Get number of connected peers |
| `Refresh()` | Manually re-resolve DNS |
| `Ready()` | Returns channel closed when ready to send/receive |
| `LocalAddr()` | Get local listening address |
| `IsSecure()` | Report whether the pre-shared cluster key is enabled (transport is always encrypted by QUIC) |
| `Config()` | Get current configuration |

### Types

```go
// Message received from a peer
type Message struct {
    Data []byte       // Decrypted payload
    Addr *net.UDPAddr // Sender's address
}

// Check if message is a request expecting a reply
func (m Message) IsRequest() bool

// Reply received from a peer (for request-reply pattern)
type Reply struct {
    Data []byte       // Response payload
    Addr *net.UDPAddr // Responder's address
}

// Result of sending to a peer
type SendResult struct {
    Addr  *net.UDPAddr
    Sent  int
    Error error
}

// Callbacks
type PeerHandler func(addr *net.UDPAddr)
type MessageHandler func(ctx context.Context, msg Message)

// Errors
var ErrPeerDisconnected = errors.New("peer disconnected before responding")
var ErrNoQuorum = errors.New("quorum not reached")
var ErrLockNotHeld = errors.New("lock not held by this instance")
var ErrNoDefault = errors.New("alan: no default instance set")
```

## UDP Buffer Size (Linux)

QUIC performs best with larger UDP buffers. If you see a warning about receive buffer size, increase the OS limits:

```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```

To persist across reboots, add to `/etc/sysctl.conf`:

```
net.core.rmem_max=7500000
net.core.wmem_max=7500000
```

This is optional — the application works without it, but may drop packets under heavy load.


## License

MIT License - see [LICENSE](LICENSE) for details.
