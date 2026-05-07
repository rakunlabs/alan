package alan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test key for cluster admission
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
		if a.config.MaxMessageSize != defaultMaxMessageSize {
			t.Errorf("expected default max message size %d, got %d", defaultMaxMessageSize, a.config.MaxMessageSize)
		}
		if a.config.MessageQueueBytes != defaultMessageQueueBytes {
			t.Errorf("expected default message queue bytes %d, got %d", defaultMessageQueueBytes, a.config.MessageQueueBytes)
		}
		if a.config.StreamOpenTimeout != defaultStreamOpenTimeout {
			t.Errorf("expected default stream open timeout %v, got %v", defaultStreamOpenTimeout, a.config.StreamOpenTimeout)
		}
	})
}

func TestProtocolEncoding(t *testing.T) {
	t.Run("data header roundtrip", func(t *testing.T) {
		// writeDataHeader writes [MsgTypeData][TypeLen][Type]; on the read side
		// the MsgType byte is consumed first by readMsgType.
		var buf bytes.Buffer
		if err := writeDataHeader(&buf, "my.type"); err != nil {
			t.Fatalf("writeDataHeader: %v", err)
		}
		if _, err := buf.WriteString("payload"); err != nil {
			t.Fatalf("write payload: %v", err)
		}

		got, err := readMsgType(&buf)
		if err != nil {
			t.Fatalf("readMsgType: %v", err)
		}
		if got != MsgTypeData {
			t.Errorf("type byte = %x, want %x", got, MsgTypeData)
		}
		mt, err := readDataHeader(&buf)
		if err != nil {
			t.Fatalf("readDataHeader: %v", err)
		}
		if mt != "my.type" {
			t.Errorf("type = %q, want %q", mt, "my.type")
		}
		body, err := io.ReadAll(&buf)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != "payload" {
			t.Errorf("body = %q, want %q", body, "payload")
		}
	})

	t.Run("request frame roundtrip", func(t *testing.T) {
		var buf bytes.Buffer
		reqID := bytes.Repeat([]byte{0xAB}, RequestIDSize)
		if err := writeRequestFrame(&buf, reqID, "rpc.echo", []byte("hello")); err != nil {
			t.Fatalf("writeRequestFrame: %v", err)
		}
		mt, err := readMsgType(&buf)
		if err != nil {
			t.Fatalf("readMsgType: %v", err)
		}
		if mt != MsgTypeRequest {
			t.Errorf("msgType = %x, want %x", mt, MsgTypeRequest)
		}
		gotID, gotType, gotBody, err := readRequestFrame(&buf, 1024)
		if err != nil {
			t.Fatalf("readRequestFrame: %v", err)
		}
		if !bytes.Equal(gotID, reqID) {
			t.Errorf("reqID mismatch")
		}
		if gotType != "rpc.echo" {
			t.Errorf("type = %q", gotType)
		}
		if string(gotBody) != "hello" {
			t.Errorf("body = %q", gotBody)
		}
	})

	t.Run("request frame oversize rejected", func(t *testing.T) {
		var buf bytes.Buffer
		reqID := bytes.Repeat([]byte{0xCD}, RequestIDSize)
		if err := writeRequestFrame(&buf, reqID, "t", make([]byte, 1024)); err != nil {
			t.Fatalf("writeRequestFrame: %v", err)
		}
		_, _ = readMsgType(&buf) // consume type byte
		_, _, _, err := readRequestFrame(&buf, 100)
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Errorf("expected ErrFrameTooLarge, got %v", err)
		}
	})

	t.Run("response frame roundtrip", func(t *testing.T) {
		var buf bytes.Buffer
		reqID := bytes.Repeat([]byte{0xEF}, RequestIDSize)
		if err := writeResponseFrame(&buf, reqID, []byte("response")); err != nil {
			t.Fatalf("writeResponseFrame: %v", err)
		}
		mt, _ := readMsgType(&buf)
		if mt != MsgTypeResponse {
			t.Errorf("msgType = %x", mt)
		}
		gotID, gotBody, err := readResponseFrame(&buf, 1024)
		if err != nil {
			t.Fatalf("readResponseFrame: %v", err)
		}
		if !bytes.Equal(gotID, reqID) {
			t.Errorf("reqID mismatch")
		}
		if string(gotBody) != "response" {
			t.Errorf("body = %q", gotBody)
		}
	})

	t.Run("lock frame roundtrip", func(t *testing.T) {
		var buf bytes.Buffer
		reqID := bytes.Repeat([]byte{0x12}, RequestIDSize)
		if err := writeLockFrame(&buf, MsgTypeLockRequest, reqID, "my-lock"); err != nil {
			t.Fatalf("writeLockFrame: %v", err)
		}
		mt, _ := readMsgType(&buf)
		if mt != MsgTypeLockRequest {
			t.Errorf("msgType = %x", mt)
		}
		gotID, gotKey, err := readLockFrame(&buf)
		if err != nil {
			t.Fatalf("readLockFrame: %v", err)
		}
		if !bytes.Equal(gotID, reqID) {
			t.Errorf("reqID mismatch")
		}
		if gotKey != "my-lock" {
			t.Errorf("key = %q", gotKey)
		}
	})
}

func TestPeerManagement(t *testing.T) {
	p := newPeers()

	addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000}
	addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5000}

	if !p.add(addr1, nil) {
		t.Error("expected first add to return isNew=true")
	}
	if p.add(addr1, nil) {
		t.Error("expected second add to return isNew=false")
	}
	if !p.add(addr2, nil) {
		t.Error("expected add of different peer to return isNew=true")
	}

	if p.count() != 2 {
		t.Errorf("expected 2 peers, got %d", p.count())
	}

	addrs := p.list()
	if len(addrs) != 2 {
		t.Errorf("expected 2 addresses, got %d", len(addrs))
	}

	peer, exists := p.get(addr1)
	if !exists || peer == nil {
		t.Error("expected to find peer")
	}

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

	a2.peers.add(a1Addr, conn)
	go a2.handleConnection(conn, a1Addr)

	time.Sleep(100 * time.Millisecond)
}

func TestStartStop(t *testing.T) {
	const testPort = 16001

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a.Start(ctx)
	<-a.Ready()

	if a.LocalAddr() == nil {
		t.Error("expected non-nil LocalAddr")
	}

	if err := a.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

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

	a1.Handle("", func(ctx context.Context, msg Message) {
		received = msg.Data
		msgWg.Done()
	})
	go a1.Start(ctx)
	go a2.Start(ctx)

	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	_, err := a2.SendTo(ctx, targetAddr, "", []byte("Direct message"))
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

	a1.Handle("", func(ctx context.Context, msg Message) {
		received = msg.Data
		msgWg.Done()
	})
	go a1.Start(ctx)
	go a2.Start(ctx)

	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	results := a2.Send(ctx, "", []byte("Broadcast message"))
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

	a1.Handle("", func(ctx context.Context, msg Message) {
		if msg.IsRequest() {
			a1.Reply(ctx, msg, append([]byte("reply:"), msg.Data...))
		}
	})
	go a1.Start(ctx)
	go a2.Start(ctx)

	<-a1.Ready()
	<-a2.Ready()

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

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}

	reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
	defer reqCancel()

	reply, err := a2.SendToAndWaitReply(reqCtx, targetAddr, "", []byte("hello"))
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

	a1.Handle("", func(ctx context.Context, msg Message) {
		if msg.IsRequest() {
			a1.Reply(ctx, msg, append([]byte("echo:"), msg.Data...))
		}
	})
	go a1.Start(ctx)
	go a2.Start(ctx)

	<-a1.Ready()
	<-a2.Ready()

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

	replies, err := a2.SendAndWaitReply(reqCtx, "", []byte("world"))
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

// waitWithTimeout returns true if wg completed before the timeout elapsed.
func waitWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
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

	var joinedPeer atomic.Pointer[net.UDPAddr]
	var joinWg sync.WaitGroup
	joinWg.Add(1)

	a1.OnPeerJoin(func(addr *net.UDPAddr) {
		if joinedPeer.CompareAndSwap(nil, addr) {
			joinWg.Done()
		}
	})

	var leftPeer atomic.Pointer[net.UDPAddr]
	var leaveWg sync.WaitGroup
	leaveWg.Add(1)

	a1.OnPeerLeave(func(addr *net.UDPAddr) {
		if leftPeer.CompareAndSwap(nil, addr) {
			leaveWg.Done()
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx)
	<-a1.Ready()

	a2, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})

	go a2.Start(ctx)
	<-a2.Ready()

	connectPeers(t, a1, a2)

	if !waitWithTimeout(&joinWg, 5*time.Second) {
		t.Fatal("expected join callback to be called within 5s")
	}
	if joinedPeer.Load() == nil {
		t.Fatal("expected join callback to be called")
	}

	a2.Stop()

	if !waitWithTimeout(&leaveWg, 3*time.Second) {
		t.Fatal("expected leave callback to be called within 3s of Stop")
	}
	if leftPeer.Load() == nil {
		t.Fatal("expected leave callback to be called")
	}

	a1.Stop()
}

// TestPeerLeaveIsFast verifies the graceful-leave protocol message kicks
// in: with a long HeartbeatTimeout, OnPeerLeave should still fire promptly
// after the peer calls Stop, instead of waiting for the QUIC idle timer.
func TestPeerLeaveIsFast(t *testing.T) {
	const port1 = 16031
	const port2 = 16032

	// Long idle timeout: if the leave-announcement protocol is missing,
	// OnPeerLeave can only fire after this elapses.
	a1, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		HeartbeatInterval: 5 * time.Second,
		HeartbeatTimeout:  30 * time.Second,
	})
	a2, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		HeartbeatInterval: 5 * time.Second,
		HeartbeatTimeout:  30 * time.Second,
	})

	var leaveWg sync.WaitGroup
	leaveWg.Add(1)
	var fired atomic.Bool
	a1.OnPeerLeave(func(addr *net.UDPAddr) {
		if fired.CompareAndSwap(false, true) {
			leaveWg.Done()
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	start := time.Now()
	a2.Stop()

	if !waitWithTimeout(&leaveWg, 3*time.Second) {
		t.Fatalf("OnPeerLeave did not fire within 3s of Stop (elapsed=%v); leave protocol may be broken", time.Since(start))
	}
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Errorf("OnPeerLeave fired but took too long: %v", elapsed)
	}

	a1.Stop()
}

// TestPeerLeaveOnContextCancel verifies that cancelling the parent ctx
// passed to Start (instead of calling Stop explicitly) still triggers the
// graceful leave announcement on remote peers. This is the typical
// pattern for applications driven by signal-handling frameworks.
func TestPeerLeaveOnContextCancel(t *testing.T) {
	const port1 = 16051
	const port2 = 16052

	// Long idle timeout: leave must come from the announcement, not from
	// QUIC's own idle timer.
	a1, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		HeartbeatInterval: 5 * time.Second,
		HeartbeatTimeout:  30 * time.Second,
	})
	a2, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		HeartbeatInterval: 5 * time.Second,
		HeartbeatTimeout:  30 * time.Second,
	})

	var leaveWg sync.WaitGroup
	leaveWg.Add(1)
	var fired atomic.Bool
	a1.OnPeerLeave(func(addr *net.UDPAddr) {
		if fired.CompareAndSwap(false, true) {
			leaveWg.Done()
		}
	})

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())

	go a1.Start(ctx1)
	go a2.Start(ctx2)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	// Cancel a2's parent ctx — Start should run the same graceful
	// shutdown as Stop, including the leave broadcast.
	start := time.Now()
	cancel2()

	if !waitWithTimeout(&leaveWg, 3*time.Second) {
		t.Fatalf("OnPeerLeave did not fire within 3s of parent ctx cancel (elapsed=%v)", time.Since(start))
	}

	a1.Stop()
}

// TestPeerLeaveOnAbruptClose codifies the idle-timeout fallback: when a
// peer is torn down without sending a graceful leave, the remote should
// still eventually fire OnPeerLeave once the QUIC idle timer expires.
func TestPeerLeaveOnAbruptClose(t *testing.T) {
	const port1 = 16041
	const port2 = 16042

	// Short idle timeout so the test finishes quickly.
	a1, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		HeartbeatInterval: 200 * time.Millisecond,
		HeartbeatTimeout:  1500 * time.Millisecond,
	})
	a2, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		HeartbeatInterval: 200 * time.Millisecond,
		HeartbeatTimeout:  1500 * time.Millisecond,
	})

	var leaveWg sync.WaitGroup
	leaveWg.Add(1)
	var fired atomic.Bool
	a1.OnPeerLeave(func(addr *net.UDPAddr) {
		if fired.CompareAndSwap(false, true) {
			leaveWg.Done()
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	// Simulate abrupt teardown (e.g. SIGKILL / OS reclaim): close the
	// underlying UDP socket without going through Stop(), so no leave
	// announcement is sent. The remote should still detect the loss via
	// the QUIC idle timer.
	a2.mu.RLock()
	udpConn := a2.udpConn
	a2.mu.RUnlock()
	if udpConn != nil {
		_ = udpConn.Close()
	}

	if !waitWithTimeout(&leaveWg, 5*time.Second) {
		t.Fatal("OnPeerLeave did not fire within 5s after abrupt close")
	}

	a1.Stop()
}

func TestSecurityPSK(t *testing.T) {
	const port1 = 16013
	const port2 = 16014

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

	a1.Handle("", func(ctx context.Context, msg Message) {
		received = msg.Data
		msgWg.Done()
	})
	go a1.Start(ctx)
	go a2.Start(ctx)

	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	_, err := a2.SendTo(ctx, targetAddr, "", []byte("secure msg"))
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

	go a1.Start(ctx)
	go a2.Start(ctx)

	<-a1.Ready()
	<-a2.Ready()

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

	go a.Start(ctx)
	<-a.Ready()
	defer a.Stop()

	lockCtx, lockCancel := context.WithTimeout(ctx, 2*time.Second)
	defer lockCancel()

	if err := a.Lock(lockCtx, "test-lock"); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	if !a.TryLock(ctx, "test-lock") {
		t.Error("TryLock should succeed when we hold the lock")
	}

	if err := a.Unlock(ctx, "test-lock"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	if err := a.Unlock(ctx, "test-lock"); !errors.Is(err, ErrLockNotHeld) {
		t.Errorf("expected ErrLockNotHeld, got %v", err)
	}
}

func TestQuorumHelpers(t *testing.T) {
	a, _ := New(Config{Port: 5000})
	if a.QuorumSize() != 0 {
		t.Errorf("expected quorum size 0, got %d", a.QuorumSize())
	}
	if !a.HasQuorum() {
		t.Error("expected HasQuorum()=true when Replicas=0")
	}

	a, _ = New(Config{Port: 5000, Replicas: 3})
	if a.QuorumSize() != 1 {
		t.Errorf("expected quorum size 1, got %d", a.QuorumSize())
	}
	if a.HasQuorum() {
		t.Error("expected HasQuorum()=false with 0 peers and Replicas=3")
	}
}

func TestSendNotStarted(t *testing.T) {
	a, _ := New(Config{Port: 5000})

	results := a.Send(context.Background(), "", []byte("test"))
	if results != nil {
		t.Error("expected nil results before start")
	}

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}
	_, err := a.SendTo(context.Background(), addr, "", []byte("test"))
	if !errors.Is(err, ErrNotStarted) {
		t.Errorf("expected ErrNotStarted, got %v", err)
	}
}

func TestLargeData(t *testing.T) {
	const port1 = 16019
	const port2 = 16020

	// Bump cap so 1 MiB fits.
	a1, err := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new a1: %v", err)
	}
	a2, err := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new a2: %v", err)
	}
	defer a1.Stop()
	defer a2.Stop()

	ctx := t.Context()

	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	var received []byte
	var msgWg sync.WaitGroup
	msgWg.Add(1)

	a1.Handle("", func(ctx context.Context, msg Message) {
		received = msg.Data
		msgWg.Done()
	})
	go a1.Start(ctx)
	go a2.Start(ctx)

	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	_, err = a2.SendTo(ctx, targetAddr, "", largeData)
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

	go a.Start(ctx)
	<-a.Ready()
	defer a.Stop()

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

	a1.Handle("", func(ctx context.Context, msg Message) {
		mu.Lock()
		received = append(received, msg.Data)
		mu.Unlock()
		msgWg.Done()
	})
	go a1.Start(ctx)
	go a2.Start(ctx)

	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	for i := 0; i < numMessages; i++ {
		_, err := a2.SendTo(ctx, targetAddr, "", []byte("msg"))
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

// ─────────────────────────────────────────────────────────────────────────────
// New robustness tests
// ─────────────────────────────────────────────────────────────────────────────

func TestSendBytesOversizeRejected(t *testing.T) {
	const port1 = 16201
	const port2 = 16202

	a1, err := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		MaxMessageSize:    1024, // 1 KiB
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new a1: %v", err)
	}
	a2, err := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		MaxMessageSize:    1024,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new a2: %v", err)
	}
	defer a1.Stop()
	defer a2.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	big := make([]byte, 2048) // 2 KiB > 1 KiB cap
	_, err = a2.SendTo(ctx, targetAddr, "", big)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}

	// Same for Send broadcast: each peer result should carry the error.
	results := a2.Send(ctx, "", big)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !errors.Is(results[0].Error, ErrMessageTooLarge) {
		t.Errorf("expected ErrMessageTooLarge in result, got %v", results[0].Error)
	}

	// Reply oversize.
	_, err = a2.Reply(ctx, Message{requestID: make([]byte, RequestIDSize), Addr: targetAddr}, big)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Errorf("Reply: expected ErrMessageTooLarge, got %v", err)
	}
}

func TestStreamHandlerRoundTrip(t *testing.T) {
	const port1 = 16203
	const port2 = 16204

	a1, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	a2, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	defer a1.Stop()
	defer a2.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const payloadSize = 4 * 1024 * 1024 // 4 MiB
	want := sha256.Sum256(repeatedBytes(payloadSize))

	var got [32]byte
	var rxSize int64
	var rxWg sync.WaitGroup
	rxWg.Add(1)

	a1.HandleStream("blob", func(ctx context.Context, msg Message, body io.Reader) error {
		defer rxWg.Done()
		h := sha256.New()
		n, err := io.Copy(h, body)
		if err != nil {
			return err
		}
		atomic.StoreInt64(&rxSize, n)
		copy(got[:], h.Sum(nil))
		return nil
	})

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
	src := bytes.NewReader(repeatedBytes(payloadSize))
	n, err := a2.SendToStream(ctx, targetAddr, "blob", src)
	if err != nil {
		t.Fatalf("SendToStream: %v", err)
	}
	if n != int64(payloadSize) {
		t.Errorf("sent %d bytes, want %d", n, payloadSize)
	}

	rxWg.Wait()

	if atomic.LoadInt64(&rxSize) != int64(payloadSize) {
		t.Errorf("received %d bytes, want %d", rxSize, payloadSize)
	}
	if got != want {
		t.Errorf("hash mismatch: got %x, want %x", got, want)
	}
}

func TestSendCtxCancelOnIdlePeer(t *testing.T) {
	// Verify SendTo respects ctx deadline when the peer connection is alive
	// but unwilling to accept (we simulate by cancelling immediately).
	const port1 = 16205
	const port2 = 16206

	a1, a2, cleanup := startTestPair(t, port1, port2)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}

	cancelledCtx, cancelImmediate := context.WithCancel(ctx)
	cancelImmediate()

	start := time.Now()
	_, err := a2.SendTo(cancelledCtx, targetAddr, "", []byte("nope"))
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected error from cancelled ctx")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected fast return, took %v", elapsed)
	}
}

func TestHandlerOverwrite(t *testing.T) {
	a, _ := New(Config{Port: 5000})

	// Register a byte handler, then a stream handler for the same type.
	// The stream handler should replace the byte handler.
	a.Handle("foo", func(ctx context.Context, msg Message) {})
	a.handlersMu.RLock()
	_, hasByte := a.byteHandlers["foo"]
	a.handlersMu.RUnlock()
	if !hasByte {
		t.Fatalf("expected byte handler registered")
	}

	a.HandleStream("foo", func(ctx context.Context, msg Message, body io.Reader) error { return nil })
	a.handlersMu.RLock()
	_, hasByte = a.byteHandlers["foo"]
	_, hasStream := a.streamHandlers["foo"]
	a.handlersMu.RUnlock()
	if hasByte {
		t.Errorf("expected byte handler evicted by HandleStream")
	}
	if !hasStream {
		t.Errorf("expected stream handler registered")
	}

	// Reverse: Handle should evict the stream handler.
	a.Handle("foo", func(ctx context.Context, msg Message) {})
	a.handlersMu.RLock()
	_, hasByte = a.byteHandlers["foo"]
	_, hasStream = a.streamHandlers["foo"]
	a.handlersMu.RUnlock()
	if !hasByte {
		t.Errorf("expected byte handler registered")
	}
	if hasStream {
		t.Errorf("expected stream handler evicted by Handle")
	}
}

func TestPerPeerByteBudgetBackpressure(t *testing.T) {
	// Configure a tight byte budget and a slow handler. enqueueMessage should
	// block (applying backpressure) until the handler drains.
	const port1 = 16207
	const port2 = 16208

	const budget = 8 * 1024
	a1, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		MessageQueueBytes: budget,
		MessageQueueSize:  16,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	a2, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	defer a1.Stop()
	defer a2.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const handlerDelay = 50 * time.Millisecond
	var processed int32

	a1.Handle("", func(ctx context.Context, msg Message) {
		time.Sleep(handlerDelay)
		atomic.AddInt32(&processed, 1)
	})

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}

	// Send 8 messages of 4 KiB each = 32 KiB. With an 8 KiB budget and
	// handlerDelay of 50ms, total wall time should be at least ~150ms
	// (4 batches of 2 messages drained sequentially).
	const each = 4 * 1024
	const count = 8
	payload := make([]byte, each)

	start := time.Now()
	for i := 0; i < count; i++ {
		if _, err := a2.SendTo(ctx, targetAddr, "", payload); err != nil {
			t.Fatalf("SendTo %d: %v", i, err)
		}
	}

	// Wait for all to be processed.
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&processed) < count && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	elapsed := time.Since(start)

	if atomic.LoadInt32(&processed) != count {
		t.Fatalf("processed %d/%d", atomic.LoadInt32(&processed), count)
	}
	// Expect at least handlerDelay * (count / (budget/each)) = 50ms * 4 = 200ms
	// (with some slack for setup).
	minElapsed := 100 * time.Millisecond
	if elapsed < minElapsed {
		t.Errorf("backpressure not applied: only %v elapsed, expected ≥ %v", elapsed, minElapsed)
	}
}

// repeatedBytes returns a slice of n bytes with a deterministic pattern.
func repeatedBytes(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i % 251)
	}
	return buf
}

// Verify Replicas+QuorumSize math matches doc table.
func TestQuorumSizeTable(t *testing.T) {
	cases := []struct {
		replicas int
		want     int
	}{
		{0, 0},
		{1, 0},
		{2, 1},
		{3, 1},
		{4, 2},
		{5, 2},
		{6, 3},
		{7, 3},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("replicas=%d", c.replicas), func(t *testing.T) {
			a, _ := New(Config{Replicas: c.replicas})
			if got := a.QuorumSize(); got != c.want {
				t.Errorf("QuorumSize() = %d, want %d", got, c.want)
			}
		})
	}
}
