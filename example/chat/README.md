# Alan TUI Chat Example

A terminal-based peer-to-peer chat application using the Alan library for secure QUIC-based communication.

## Features

- Real-time peer-to-peer messaging
- Encrypted transport via QUIC (TLS 1.3, mTLS) with optional pre-shared cluster key
- Peer list showing connected users
- Message timestamps
- Color-coded messages per peer
- System notifications for peer join/leave events

## Prerequisites

Add the following entries to `/etc/hosts` to enable local peer discovery:

```
127.0.1.1  alan-chat.local
127.0.1.2  alan-chat.local
127.0.1.3  alan-chat.local
```

## Running the Example

Open multiple terminals and run with different bind addresses:

```bash
# Terminal 1
ALAN_BIND_ADDR=127.0.1.1 ALAN_NAME=Ada go run .

# Terminal 2
ALAN_BIND_ADDR=127.0.1.2 ALAN_NAME=Selin go run .

# Terminal 3
ALAN_BIND_ADDR=127.0.1.3 ALAN_NAME=Eray go run .
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ALAN_NAME` | hostname | Your display name in the chat |
| `ALAN_BIND_ADDR` | `0.0.0.0` | Local IP address to bind to |
| `ALAN_DNS_ADDR` | `alan-chat.local` | DNS name for peer discovery |
| `ALAN_PORT` | `5000` | UDP port (must be same for all peers) |
| `ALAN_SECURITY_KEY` | `alan-chat-default-key` | Pre-shared cluster admission key, any length (must be same for all peers) |
| `ALAN_SECURITY_ENABLED` | `true` | Enable/disable PSK admission check (transport stays encrypted via QUIC either way) |

## Controls

| Key | Action |
|-----|--------|
| `Enter` | Send message |
| `↑` / `↓` | Scroll message history |
| `Esc` / `Ctrl+C` | Quit |

## Screenshot

```
┌─────────────────────────────────────────────────────────────────┐
│  Alan Chat - Ada (online | 2 peers)                             │
├──────────────────────────────────────────────┬──────────────────┤
│ [12:34:05] Connected as Ada. Waiting...      │ Peers (2)        │
│ [12:34:08] 127.0.1.2:5000 joined             │──────────────────│
│ [12:34:10] Selin: Hello everyone!            │ ● 127.0.1.2:5000 │
│ [12:34:12] Ada: Hey Selin!                   │ ● 127.0.1.3:5000 │
│ [12:34:15] Eray: Hi all!                     │                  │
│                                              │                  │
├──────────────────────────────────────────────┴──────────────────┤
│ > Type a message...                                             │
├─────────────────────────────────────────────────────────────────┤
│ Enter: send | Esc/Ctrl+C: quit | ↑↓: scroll                     │
└─────────────────────────────────────────────────────────────────┘
```
