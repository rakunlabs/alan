# Sync Example

Simple example demonstrating how to synchronize state across peers using a custom protocol. Each peer maintains a counter that can be incremented locally and synchronized with other peers.

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
ALAN_BIND_ADDR=127.0.1.1 ALAN_NAME=1 ALAN_REPLICAS=3 go run .

# Terminal 2
ALAN_BIND_ADDR=127.0.1.2 ALAN_NAME=2 ALAN_REPLICAS=3 go run .

# Terminal 3
ALAN_BIND_ADDR=127.0.1.3 ALAN_NAME=3 ALAN_REPLICAS=3 go run .
```

```bash
curl -X POST http://alan-chat.local:8080
```
