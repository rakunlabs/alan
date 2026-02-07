# alan

[![License](https://img.shields.io/github/license/rakunlabs/alan?color=red&style=flat-square)](https://raw.githubusercontent.com/rakunlabs/alan/main/LICENSE)
[![Coverage](https://img.shields.io/sonar/coverage/rakunlabs_alan?logo=sonarcloud&server=https%3A%2F%2Fsonarcloud.io&style=flat-square)](https://sonarcloud.io/summary/overall?id=rakunlabs_alan)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/rakunlabs/alan/test.yml?branch=main&logo=github&style=flat-square&label=ci)](https://github.com/rakunlabs/alan/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/rakunlabs/alan?style=flat-square)](https://goreportcard.com/report/github.com/rakunlabs/alan)
[![Go PKG](https://raw.githubusercontent.com/rakunlabs/.github/main/assets/badges/gopkg.svg)](https://pkg.go.dev/github.com/rakunlabs/alan)

UDP peer discovery and communication library for Go with optional ChaCha20-Poly1305 encryption.

## Features

- **DNS-based peer discovery** - Resolve a DNS name to discover cluster members
- **Automatic membership** - JOIN/LEAVE/HEARTBEAT protocol for peer tracking
- **Encrypted communication** - Optional ChaCha20-Poly1305 authenticated encryption
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

    // Start in background
    go func() {
        a.Start(ctx, func(ctx context.Context, msg alan.Message) {
            fmt.Printf("Received from %s: %s\n", msg.Addr, msg.Data)
        })
    }()

    // Send to all peers
    a.Send([]byte("Hello everyone!"))

    // Send to specific peer
    a.SendTo(specificAddr, []byte("Hello you!"))

    // Graceful shutdown
    a.Stop()
}
```

## With Encryption

```go
a, err := alan.New(alan.Config{
    DNSAddr: "my-cluster.local",
    Port:    5000,
    Security: &alan.SecurityConfig{
        Key:     []byte("12345678901234567890123456789012"), // 32 bytes
        Enabled: true,
    },
})
```

All messages (including membership protocol) are automatically encrypted.

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
    
    // RefreshInterval - how often to re-resolve DNS (default: 0 = disabled)
    RefreshInterval time.Duration
    
    // Security for encryption (optional)
    Security *SecurityConfig
}

type SecurityConfig struct {
    // Key must be exactly 32 bytes for ChaCha20-Poly1305
    Key     []byte
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

- **JOIN**: Sent on startup to all known peers
- **HEARTBEAT**: Sent every `HeartbeatInterval` to all peers
- **LEAVE**: Sent on `Stop()` to notify peers of graceful shutdown
- **Timeout**: Peers not seen within `HeartbeatTimeout` are removed

### Security

When encryption is enabled:
- All messages (JOIN/LEAVE/HEARTBEAT/DATA) are encrypted
- Uses XChaCha20-Poly1305 (AEAD)
- Random 24-byte nonce per message
- Wire format: `[nonce:24][ciphertext+tag]`

## API Reference

### Alan

| Method | Description |
|--------|-------------|
| `New(Config)` | Create new Alan instance |
| `OnPeerJoin(handler)` | Set callback for peer join events |
| `OnPeerLeave(handler)` | Set callback for peer leave events |
| `Start(ctx, handler)` | Start the peer discovery system (blocking) |
| `Stop()` | Gracefully stop and notify peers |
| `Send(data)` | Send data to all peers |
| `SendTo(addr, data)` | Send data to a specific peer |
| `Peers()` | Get list of current peer addresses |
| `PeerCount()` | Get number of connected peers |
| `Refresh()` | Manually re-resolve DNS |
| `Ready()` | Returns channel closed when ready to send/receive |
| `LocalAddr()` | Get local listening address |
| `IsSecure()` | Check if encryption is enabled |
| `Config()` | Get current configuration |

### Types

```go
// Message received from a peer
type Message struct {
    Data []byte       // Decrypted payload
    Addr *net.UDPAddr // Sender's address
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
```

## License

MIT License - see [LICENSE](LICENSE) for details.
