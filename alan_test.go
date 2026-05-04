package alan

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// Test key for encryption
var testKey = []byte("my-secret-key")

func TestNew(t *testing.T) {
	t.Run("without security", func(t *testing.T) {
		a, err := New(Config{Port: 5000})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if a.IsSecure() {
			t.Error("expected IsSecure() to be false")
		}
	})

	t.Run("with security", func(t *testing.T) {
		a, err := New(Config{
			Port: 5000,
			Security: SecurityConfig{
				Key:     testKey,
				Enabled: true,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !a.IsSecure() {
			t.Error("expected IsSecure() to be true")
		}
	})

	t.Run("empty key", func(t *testing.T) {
		_, err := New(Config{
			Port: 5000,
			Security: SecurityConfig{
				Key:     []byte{},
				Enabled: true,
			},
		})
		if err == nil {
			t.Error("expected error for empty key")
		}
		if !errors.Is(err, ErrEmptyKey) {
			t.Errorf("expected ErrEmptyKey, got %v", err)
		}
	})

	t.Run("defaults", func(t *testing.T) {
		a, err := New(Config{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if a.config.Port != 5000 {
			t.Errorf("expected default port 5000, got %d", a.config.Port)
		}
		if a.config.Timeout != 5*time.Second {
			t.Errorf("expected default timeout 5s, got %v", a.config.Timeout)
		}
		if a.config.HeartbeatInterval != 5*time.Second {
			t.Errorf("expected default heartbeat interval 5s, got %v", a.config.HeartbeatInterval)
		}
		if a.config.HeartbeatTimeout != 15*time.Second {
			t.Errorf("expected default heartbeat timeout 15s, got %v", a.config.HeartbeatTimeout)
		}
		if a.config.RefreshInterval != 30*time.Second {
			t.Errorf("expected default refresh interval 30s, got %v", a.config.RefreshInterval)
		}
		if a.config.MessageQueueSize != 256 {
			t.Errorf("expected default message queue size 256, got %d", a.config.MessageQueueSize)
		}
	})
}

func TestProtocolEncoding(t *testing.T) {
	t.Run("stream framing roundtrip", func(t *testing.T) {
		// Test writeStreamMessage / readStreamMessage via a pipe
		pr, pw := net.Pipe()
		defer pr.Close()
		defer pw.Close()

		payload := []byte("Hello, World!")

		go func() {
			writeStreamMessage(pw, MsgTypeData, payload)
			pw.Close()
		}()

		msgType, got, err := readStreamMessage(pr)
		if err != nil {
			t.Fatalf("readStreamMessage failed: %v", err)
		}
		if msgType != MsgTypeData {
			t.Errorf("expected type %d, got %d", MsgTypeData, msgType)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("payload mismatch: got %q, want %q", got, payload)
		}
	})

	t.Run("lock payload encoding", func(t *testing.T) {
		requestID := make([]byte, RequestIDSize)
		for i := range requestID {
			requestID[i] = byte(i)
		}
		key := "my-lock"

		payload := encodeLockPayload(requestID, key)
		gotID, gotKey, err := decodeLockPayload(payload)
		if err != nil {
			t.Fatalf("decodeLockPayload failed: %v", err)
		}
		if !bytes.Equal(gotID, requestID) {
			t.Errorf("requestID mismatch")
		}
		if gotKey != key {
			t.Errorf("key mismatch: got %q, want %q", gotKey, key)
		}
	})
}

func TestPeerManagement(t *testing.T) {
	p := newPeers()

	addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000}
	addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5000}

	// Add peers
	if !p.add(addr1, nil) {
		t.Error("expected first add to return isNew=true")
	}
	if p.add(addr1, nil) {
		t.Error("expected second add to return isNew=false")
	}
	if !p.add(addr2, nil) {
		t.Error("expected add of different peer to return isNew=true")
	}

	// Count
	if p.count() != 2 {
		t.Errorf("expected 2 peers, got %d", p.count())
	}

	// List
	addrs := p.list()
	if len(addrs) != 2 {
		t.Errorf("expected 2 addresses, got %d", len(addrs))
	}

	// Get
	peer, exists := p.get(addr1)
	if !exists || peer == nil {
		t.Error("expected to find peer")
	}

	// Remove
	existed, _ := p.remove(addr1)
	if !existed {
		t.Error("expected remove to return existed=true")
	}
	if p.count() != 1 {
		t.Errorf("expected 1 peer after removal, got %d", p.count())
	}

	existed, _ = p.remove(addr1)
	if existed {
		t.Error("expected remove of non-existent peer to return existed=false")
	}
}

// startTestPair creates and starts two connected Alan instances for testing.
// It returns both instances and a cleanup function.
func startTestPair(t *testing.T, port1, port2 int) (*Alan, *Alan, context.CancelFunc) {
	t.Helper()

	a1, err := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create a1: %v", err)
	}

	a2, err := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create a2: %v", err)
	}

	return a1, a2, func() {
		a1.Stop()
		a2.Stop()
	}
}

// connectPeers dials a QUIC connection from a2 to a1 (simulating peer discovery).
func connectPeers(t *testing.T, a1, a2 *Alan) {
	t.Helper()

	a1Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: a1.config.Port}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := a2.transport.Dial(ctx, a1Addr, a2.clientTLS, a2.quicConfig)
	if err != nil {
		t.Fatalf("failed to dial from a2 to a1: %v", err)
	}

	// Register in a2's peer list
	a2.peers.add(a1Addr, conn)

	// a1 will pick up the connection via its accept loop
	// Wait a bit for the accept loop to register the peer
	time.Sleep(100 * time.Millisecond)
}

func TestStartStop(t *testing.T) {
	const testPort = 16001

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a.Ready()

	// Verify it's running
	if a.LocalAddr() == nil {
		t.Error("expected non-nil LocalAddr")
	}

	// Stop
	if err := a.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Double stop should be fine
	if err := a.Stop(); err != nil {
		t.Fatalf("Double Stop failed: %v", err)
	}
}

func TestSendTo(t *testing.T) {
	const port1 = 16003
	const port2 = 16004

	a1, a2, cleanup := startTestPair(t, port1, port2)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var received []byte
	var msgWg sync.WaitGroup
	msgWg.Add(1)

	go a1.Start(ctx, func(ctx context.Context, msg Message) {
		received = msg.Data
		msgWg.Done()
	})

	go a2.Start(ctx, func(ctx context.Context, msg Message) {})

	<-a1.Ready()
	<-a2.Ready()

	// Connect a2 -> a1
	connectPeers(t, a1, a2)

	// SendTo specific address
	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	_, err := a2.SendTo(targetAddr, []byte("Direct message"))
	if err != nil {
		t.Fatalf("SendTo failed: %v", err)
	}

	msgWg.Wait()

	if !bytes.Equal(received, []byte("Direct message")) {
		t.Errorf("received wrong data: %q", received)
	}
}

func TestSend(t *testing.T) {
	const port1 = 16005
	const port2 = 16006

	a1, a2, cleanup := startTestPair(t, port1, port2)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var received []byte
	var msgWg sync.WaitGroup
	msgWg.Add(1)

	go a1.Start(ctx, func(ctx context.Context, msg Message) {
		received = msg.Data
		msgWg.Done()
	})

	go a2.Start(ctx, func(ctx context.Context, msg Message) {})

	<-a1.Ready()
	<-a2.Ready()

	// Connect a2 -> a1
	connectPeers(t, a1, a2)

	// Broadcast (only a1 is peer)
	results := a2.Send([]byte("Broadcast message"))
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Fatalf("send error: %v", results[0].Error)
	}

	msgWg.Wait()

	if !bytes.Equal(received, []byte("Broadcast message")) {
		t.Errorf("received wrong data: %q", received)
	}
}

func TestSendToAndWaitReply(t *testing.T) {
	const port1 = 16007
	const port2 = 16008

	a1, a2, cleanup := startTestPair(t, port1, port2)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// a1 echoes requests with a prefix
	go a1.Start(ctx, func(ctx context.Context, msg Message) {
		if msg.IsRequest() {
			a1.Reply(msg, append([]byte("reply:"), msg.Data...))
		}
	})

	go a2.Start(ctx, func(ctx context.Context, msg Message) {})

	<-a1.Ready()
	<-a2.Ready()

	// Connect both ways so a1 can reply to a2
	connectPeers(t, a1, a2)
	// Also connect a1 -> a2 so a1 can send reply stream back
	a2Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port2}
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	conn12, err := a1.transport.Dial(dialCtx, a2Addr, a1.clientTLS, a1.quicConfig)
	if err != nil {
		t.Fatalf("failed to dial a1->a2: %v", err)
	}
	a1.peers.add(a2Addr, conn12)
	go a1.handleConnection(conn12, a2Addr)
	time.Sleep(100 * time.Millisecond)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}

	reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
	defer reqCancel()

	reply, err := a2.SendToAndWaitReply(reqCtx, targetAddr, []byte("hello"))
	if err != nil {
		t.Fatalf("SendToAndWaitReply failed: %v", err)
	}

	if !bytes.Equal(reply.Data, []byte("reply:hello")) {
		t.Errorf("unexpected reply: %q", reply.Data)
	}
}

func TestSendAndWaitReply(t *testing.T) {
	const port1 = 16009
	const port2 = 16010

	a1, a2, cleanup := startTestPair(t, port1, port2)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// a1 echoes requests
	go a1.Start(ctx, func(ctx context.Context, msg Message) {
		if msg.IsRequest() {
			a1.Reply(msg, append([]byte("echo:"), msg.Data...))
		}
	})

	go a2.Start(ctx, func(ctx context.Context, msg Message) {})

	<-a1.Ready()
	<-a2.Ready()

	// Connect both ways
	connectPeers(t, a1, a2)
	a2Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port2}
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	conn12, err := a1.transport.Dial(dialCtx, a2Addr, a1.clientTLS, a1.quicConfig)
	if err != nil {
		t.Fatalf("failed to dial a1->a2: %v", err)
	}
	a1.peers.add(a2Addr, conn12)
	go a1.handleConnection(conn12, a2Addr)
	time.Sleep(100 * time.Millisecond)

	reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
	defer reqCancel()

	replies, err := a2.SendAndWaitReply(reqCtx, []byte("world"))
	if err != nil {
		t.Fatalf("SendAndWaitReply failed: %v", err)
	}

	if len(replies) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(replies))
	}
	if !bytes.Equal(replies[0].Data, []byte("echo:world")) {
		t.Errorf("unexpected reply: %q", replies[0].Data)
	}
}

func TestPeerJoinLeaveCallbacks(t *testing.T) {
	const port1 = 16011
	const port2 = 16012

	a1, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})

	var joinedPeer *net.UDPAddr
	var joinWg sync.WaitGroup
	joinWg.Add(1)

	a1.OnPeerJoin(func(addr *net.UDPAddr) {
		joinedPeer = addr
		joinWg.Done()
	})

	var leftPeer *net.UDPAddr
	var leaveWg sync.WaitGroup
	leaveWg.Add(1)

	a1.OnPeerLeave(func(addr *net.UDPAddr) {
		leftPeer = addr
		leaveWg.Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a1.Ready()

	// Create a2 and connect to a1
	a2, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})

	go a2.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a2.Ready()

	connectPeers(t, a1, a2)

	// Wait for join callback
	joinWg.Wait()
	if joinedPeer == nil {
		t.Fatal("expected join callback to be called")
	}

	// Simulate peer leaving by stopping a2
	a2.Stop()

	// Wait for leave callback
	leaveWg.Wait()
	if leftPeer == nil {
		t.Fatal("expected leave callback to be called")
	}

	a1.Stop()
}

func TestSecurityPSK(t *testing.T) {
	const port1 = 16013
	const port2 = 16014

	// Both peers with same key
	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     port1,
		Security: SecurityConfig{Key: testKey, Enabled: true},
	})
	a2, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     port2,
		Security: SecurityConfig{Key: testKey, Enabled: true},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var received []byte
	var msgWg sync.WaitGroup
	msgWg.Add(1)

	go a1.Start(ctx, func(ctx context.Context, msg Message) {
		received = msg.Data
		msgWg.Done()
	})
	go a2.Start(ctx, func(ctx context.Context, msg Message) {})

	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	_, err := a2.SendTo(targetAddr, []byte("secure msg"))
	if err != nil {
		t.Fatalf("SendTo failed: %v", err)
	}

	msgWg.Wait()
	if !bytes.Equal(received, []byte("secure msg")) {
		t.Errorf("got %q, want %q", received, "secure msg")
	}

	a1.Stop()
	a2.Stop()
}

func TestSecurityPSK_Mismatch(t *testing.T) {
	const port1 = 16015
	const port2 = 16016

	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     port1,
		Security: SecurityConfig{Key: []byte("key-a"), Enabled: true},
	})
	a2, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     port2,
		Security: SecurityConfig{Key: []byte("key-b"), Enabled: true},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx, func(ctx context.Context, msg Message) {})
	go a2.Start(ctx, func(ctx context.Context, msg Message) {})

	<-a1.Ready()
	<-a2.Ready()

	// Try to dial — should fail because PSK mismatch
	a1Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	dialCtx, dialCancel := context.WithTimeout(ctx, 2*time.Second)
	defer dialCancel()

	_, err := a2.transport.Dial(dialCtx, a1Addr, a2.clientTLS, a2.quicConfig)
	if err == nil {
		t.Error("expected dial to fail with PSK mismatch")
	}

	a1.Stop()
	a2.Stop()
}

func TestLockUnlock(t *testing.T) {
	const port1 = 16017

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: port1})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a.Ready()
	defer a.Stop()

	// Lock with no peers should succeed immediately
	lockCtx, lockCancel := context.WithTimeout(ctx, 2*time.Second)
	defer lockCancel()

	if err := a.Lock(lockCtx, "test-lock"); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	// TryLock should succeed (we already hold it)
	if !a.TryLock("test-lock") {
		t.Error("TryLock should succeed when we hold the lock")
	}

	// Unlock
	if err := a.Unlock("test-lock"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Unlock again should fail
	if err := a.Unlock("test-lock"); !errors.Is(err, ErrLockNotHeld) {
		t.Errorf("expected ErrLockNotHeld, got %v", err)
	}
}

func TestQuorumHelpers(t *testing.T) {
	// No replicas configured
	a, _ := New(Config{Port: 5000})
	if a.QuorumSize() != 0 {
		t.Errorf("expected quorum size 0, got %d", a.QuorumSize())
	}
	if !a.HasQuorum() {
		t.Error("expected HasQuorum()=true when Replicas=0")
	}

	// With replicas
	a, _ = New(Config{Port: 5000, Replicas: 3})
	if a.QuorumSize() != 2 {
		t.Errorf("expected quorum size 2, got %d", a.QuorumSize())
	}
	if a.HasQuorum() {
		t.Error("expected HasQuorum()=false with 0 peers and Replicas=3")
	}
}

func TestSendNotStarted(t *testing.T) {
	a, _ := New(Config{Port: 5000})

	// Send before Start should return nil
	results := a.Send([]byte("test"))
	if results != nil {
		t.Error("expected nil results before start")
	}

	// SendTo before Start should return error
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}
	_, err := a.SendTo(addr, []byte("test"))
	if !errors.Is(err, ErrNotStarted) {
		t.Errorf("expected ErrNotStarted, got %v", err)
	}
}

func TestLargeData(t *testing.T) {
	const port1 = 16019
	const port2 = 16020

	a1, a2, cleanup := startTestPair(t, port1, port2)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Send 1MB of data
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	var received []byte
	var msgWg sync.WaitGroup
	msgWg.Add(1)

	go a1.Start(ctx, func(ctx context.Context, msg Message) {
		received = msg.Data
		msgWg.Done()
	})

	go a2.Start(ctx, func(ctx context.Context, msg Message) {})

	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	_, err := a2.SendTo(targetAddr, largeData)
	if err != nil {
		t.Fatalf("SendTo failed: %v", err)
	}

	msgWg.Wait()

	if !bytes.Equal(received, largeData) {
		t.Errorf("large data mismatch: got %d bytes, want %d bytes", len(received), len(largeData))
	}
}

func TestWaitForQuorum(t *testing.T) {
	const port1 = 16021

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: port1, Replicas: 3})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a.Ready()
	defer a.Stop()

	// Quorum should timeout since we have no peers
	quorumCtx, quorumCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer quorumCancel()

	err := a.WaitForQuorum(quorumCtx)
	if err == nil {
		t.Error("expected timeout waiting for quorum")
	}
}

func TestMultipleSends(t *testing.T) {
	const port1 = 16023
	const port2 = 16024

	a1, a2, cleanup := startTestPair(t, port1, port2)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numMessages = 10
	var mu sync.Mutex
	received := make([][]byte, 0, numMessages)
	var msgWg sync.WaitGroup
	msgWg.Add(numMessages)

	go a1.Start(ctx, func(ctx context.Context, msg Message) {
		mu.Lock()
		received = append(received, msg.Data)
		mu.Unlock()
		msgWg.Done()
	})

	go a2.Start(ctx, func(ctx context.Context, msg Message) {})

	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	for i := 0; i < numMessages; i++ {
		_, err := a2.SendTo(targetAddr, []byte("msg"))
		if err != nil {
			t.Fatalf("SendTo %d failed: %v", i, err)
		}
	}

	msgWg.Wait()

	mu.Lock()
	if len(received) != numMessages {
		t.Errorf("expected %d messages, got %d", numMessages, len(received))
	}
	mu.Unlock()
}
