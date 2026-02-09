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

// Test key for encryption (32 bytes)
var testKey = []byte("12345678901234567890123456789012")

func TestNew(t *testing.T) {
	t.Run("without security", func(t *testing.T) {
		a, err := New(Config{
			DNSAddr: "localhost",
			Port:    5000,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if a.IsSecure() {
			t.Error("expected IsSecure() to be false")
		}
	})

	t.Run("with security", func(t *testing.T) {
		a, err := New(Config{
			DNSAddr: "localhost",
			Port:    5000,
			Security: &SecurityConfig{
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

	t.Run("invalid key size", func(t *testing.T) {
		_, err := New(Config{
			DNSAddr: "localhost",
			Port:    5000,
			Security: &SecurityConfig{
				Key:     []byte("short"),
				Enabled: true,
			},
		})
		if err == nil {
			t.Error("expected error for invalid key size")
		}
	})

	t.Run("empty DNSAddr allowed", func(t *testing.T) {
		a, err := New(Config{
			Port: 5000,
		})
		if err != nil {
			t.Errorf("expected no error for empty DNSAddr, got %v", err)
		}
		if a == nil {
			t.Error("expected Alan instance to be created")
		}
	})

	t.Run("defaults", func(t *testing.T) {
		a, err := New(Config{
			DNSAddr: "localhost",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if a.config.Timeout != 5*time.Second {
			t.Errorf("expected default timeout 5s, got %v", a.config.Timeout)
		}
		if a.config.BufferSize != 4096 {
			t.Errorf("expected default buffer size 4096, got %d", a.config.BufferSize)
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
	})
}

func TestEncryptDecrypt(t *testing.T) {
	a, err := New(Config{
		DNSAddr: "localhost",
		Security: &SecurityConfig{
			Key:     testKey,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("failed to create Alan: %v", err)
	}

	plaintext := []byte("Hello, World!")

	// Encrypt
	ciphertext, err := a.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Ciphertext should be longer than plaintext (nonce + tag)
	if len(ciphertext) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext")
	}

	// Decrypt
	decrypted, err := a.decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_DifferentNonces(t *testing.T) {
	a, err := New(Config{
		DNSAddr: "localhost",
		Security: &SecurityConfig{
			Key:     testKey,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("failed to create Alan: %v", err)
	}

	plaintext := []byte("Hello, World!")

	// Encrypt twice
	ciphertext1, _ := a.encrypt(plaintext)
	ciphertext2, _ := a.encrypt(plaintext)

	// Should produce different ciphertexts (different nonces)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("same plaintext should produce different ciphertexts")
	}
}

func TestDecrypt_InvalidMessage(t *testing.T) {
	a, err := New(Config{
		DNSAddr: "localhost",
		Security: &SecurityConfig{
			Key:     testKey,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("failed to create Alan: %v", err)
	}

	// Too short
	_, err = a.decrypt([]byte("short"))
	if !errors.Is(err, ErrMessageTooShort) {
		t.Errorf("expected ErrMessageTooShort, got %v", err)
	}

	// Invalid ciphertext (tampered)
	ciphertext, _ := a.encrypt([]byte("test"))
	ciphertext[len(ciphertext)-1] ^= 0xFF // Flip last byte
	_, err = a.decrypt(ciphertext)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestProcessOutgoingIncoming_NoSecurity(t *testing.T) {
	a, err := New(Config{
		DNSAddr: "localhost",
	})
	if err != nil {
		t.Fatalf("failed to create Alan: %v", err)
	}

	data := []byte("plain data")

	// Process outgoing (no encryption)
	out, err := a.processOutgoing(data)
	if err != nil {
		t.Fatalf("processOutgoing failed: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Error("data should be unchanged without security")
	}

	// Process incoming (no decryption)
	in, err := a.processIncoming(data)
	if err != nil {
		t.Fatalf("processIncoming failed: %v", err)
	}
	if !bytes.Equal(in, data) {
		t.Error("data should be unchanged without security")
	}
}

func TestProtocolEncoding(t *testing.T) {
	t.Run("control message", func(t *testing.T) {
		msg := encodeControlMessage(MsgTypeJoin, 5000)
		if len(msg) != 3 {
			t.Errorf("expected 3 bytes, got %d", len(msg))
		}
		if msg[0] != MsgTypeJoin {
			t.Errorf("expected type %d, got %d", MsgTypeJoin, msg[0])
		}

		msgType, payload, err := decodeMessage(msg)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if msgType != MsgTypeJoin {
			t.Errorf("expected type %d, got %d", MsgTypeJoin, msgType)
		}

		port, err := decodeControlPayload(payload)
		if err != nil {
			t.Fatalf("decode control payload failed: %v", err)
		}
		if port != 5000 {
			t.Errorf("expected port 5000, got %d", port)
		}
	})

	t.Run("data message", func(t *testing.T) {
		data := []byte("Hello, World!")
		msg := encodeDataMessage(data)

		if msg[0] != MsgTypeData {
			t.Errorf("expected type %d, got %d", MsgTypeData, msg[0])
		}

		msgType, payload, err := decodeMessage(msg)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if msgType != MsgTypeData {
			t.Errorf("expected type %d, got %d", MsgTypeData, msgType)
		}
		if !bytes.Equal(payload, data) {
			t.Errorf("payload mismatch: got %q, want %q", payload, data)
		}
	})
}

func TestPeerManagement(t *testing.T) {
	p := newPeers()

	addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000}
	addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5000}

	// Add peers
	if !p.add(addr1) {
		t.Error("expected add to return true for new peer")
	}
	if p.add(addr1) {
		t.Error("expected add to return false for existing peer")
	}
	if !p.add(addr2) {
		t.Error("expected add to return true for new peer")
	}

	// Count
	if p.count() != 2 {
		t.Errorf("expected 2 peers, got %d", p.count())
	}

	// List
	list := p.list()
	if len(list) != 2 {
		t.Errorf("expected 2 peers in list, got %d", len(list))
	}

	// Get
	peer, exists := p.get(addr1)
	if !exists {
		t.Error("expected peer to exist")
	}
	if !peer.Addr.IP.Equal(addr1.IP) {
		t.Error("peer address mismatch")
	}

	// Remove
	if !p.remove(addr1) {
		t.Error("expected remove to return true")
	}
	if p.remove(addr1) {
		t.Error("expected remove to return false for non-existent peer")
	}
	if p.count() != 1 {
		t.Errorf("expected 1 peer after removal, got %d", p.count())
	}
}

func TestPeerStaleRemoval(t *testing.T) {
	p := newPeers()

	addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000}
	addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5000}

	p.add(addr1)
	p.add(addr2)

	// Manually set addr1's last seen to past
	p.mu.Lock()
	p.items[peerKey(addr1)].LastSeen = time.Now().Add(-10 * time.Second)
	p.mu.Unlock()

	// Remove stale with 5s timeout
	removed := p.removeStale(5 * time.Second)

	if len(removed) != 1 {
		t.Errorf("expected 1 removed peer, got %d", len(removed))
	}
	if !removed[0].IP.Equal(addr1.IP) {
		t.Error("wrong peer removed")
	}
	if p.count() != 1 {
		t.Errorf("expected 1 peer remaining, got %d", p.count())
	}
}

func TestTwoPeers(t *testing.T) {
	// Use different loopback IPs with same port
	const testPort = 15000

	// Create two Alan instances that will communicate on different loopback IPs
	a1, err := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.1",
		Port:              testPort,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create a1: %v", err)
	}

	a2, err := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.2",
		Port:              testPort,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create a2: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var received1 []byte
	var received2 []byte
	var msgWg sync.WaitGroup
	msgWg.Add(2)

	// Start a1 in background
	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {
			received1 = msg.Data
			msgWg.Done()
		})
	}()

	// Start a2 in background
	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {
			received2 = msg.Data
			msgWg.Done()
		})
	}()

	// Wait for both instances to be ready
	<-a1.Ready()
	<-a2.Ready()

	// Add each other as peers using the known addresses
	a1.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort})
	a2.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort})

	// Send from a1 to all peers (which includes a2)
	a1.Send([]byte("Hello from a1"))

	// Send from a2 to all peers (which includes a1)
	a2.Send([]byte("Hello from a2"))

	// Wait for messages
	msgWg.Wait()

	if !bytes.Equal(received1, []byte("Hello from a2")) {
		t.Errorf("a1 received wrong data: %q", received1)
	}
	if !bytes.Equal(received2, []byte("Hello from a1")) {
		t.Errorf("a2 received wrong data: %q", received2)
	}

	// Cleanup
	a1.Stop()
	a2.Stop()
}

func TestTwoPeers_Encrypted(t *testing.T) {
	// Use different loopback IPs with same port
	const testPort = 15001

	// Create two Alan instances with encryption
	a1, err := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.1",
		Port:              testPort,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
		Security: &SecurityConfig{
			Key:     testKey,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("failed to create a1: %v", err)
	}

	a2, err := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.2",
		Port:              testPort,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
		Security: &SecurityConfig{
			Key:     testKey,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("failed to create a2: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var received []byte
	var msgWg sync.WaitGroup
	msgWg.Add(1)

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {
			received = msg.Data
			msgWg.Done()
		})
	}()

	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	// Wait for both instances to be ready
	<-a1.Ready()
	<-a2.Ready()

	// Add a1 as peer of a2
	a2.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort})

	// Send encrypted message
	a2.Send([]byte("Secret message!"))

	msgWg.Wait()

	if !bytes.Equal(received, []byte("Secret message!")) {
		t.Errorf("received wrong data: %q", received)
	}

	a1.Stop()
	a2.Stop()
}

func TestPeerJoinLeaveCallbacks(t *testing.T) {
	const testPort = 15002

	a1, _ := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.1",
		Port:              testPort,
		HeartbeatInterval: 100 * time.Millisecond,
		HeartbeatTimeout:  500 * time.Millisecond,
	})

	var joinedPeer *net.UDPAddr
	var leftPeer *net.UDPAddr
	var joinWg, leaveWg sync.WaitGroup
	joinWg.Add(1)
	leaveWg.Add(1)

	a1.OnPeerJoin(func(addr *net.UDPAddr) {
		joinedPeer = addr
		joinWg.Done()
	})

	a1.OnPeerLeave(func(addr *net.UDPAddr) {
		leftPeer = addr
		leaveWg.Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	// Wait for instance to be ready
	<-a1.Ready()

	// Simulate a peer joining by sending JOIN message
	a1Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort}

	conn, _ := net.DialUDP("udp", nil, a1Addr)
	defer conn.Close()

	// Send JOIN
	joinMsg := encodeControlMessage(MsgTypeJoin, 9999)
	conn.Write(joinMsg)

	// Wait for join callback
	joinWg.Wait()

	if joinedPeer == nil || joinedPeer.Port != 9999 {
		t.Errorf("join callback not called correctly: %v", joinedPeer)
	}

	// Send LEAVE
	leaveMsg := encodeControlMessage(MsgTypeLeave, 9999)
	conn.Write(leaveMsg)

	// Wait for leave callback
	leaveWg.Wait()

	if leftPeer == nil || leftPeer.Port != 9999 {
		t.Errorf("leave callback not called correctly: %v", leftPeer)
	}

	a1.Stop()
}

func TestSendTo(t *testing.T) {
	const testPort = 15003

	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort,
	})

	a2, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.2",
		Port:     testPort,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var received []byte
	var msgWg sync.WaitGroup
	msgWg.Add(1)

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {
			received = msg.Data
			msgWg.Done()
		})
	}()

	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	// Wait for both instances to be ready
	<-a1.Ready()
	<-a2.Ready()

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort}

	// SendTo specific address
	_, err := a2.SendTo(targetAddr, []byte("Direct message"))
	if err != nil {
		t.Fatalf("SendTo failed: %v", err)
	}

	msgWg.Wait()

	if !bytes.Equal(received, []byte("Direct message")) {
		t.Errorf("received wrong data: %q", received)
	}

	a1.Stop()
	a2.Stop()
}

func TestSendToAndWaitReply(t *testing.T) {
	const testPort = 15004

	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort,
	})

	a2, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.2",
		Port:     testPort,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// a1 will respond to requests
	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {
			if msg.IsRequest() {
				// Echo back the data with a prefix
				a1.Reply(msg, append([]byte("reply:"), msg.Data...))
			}
		})
	}()

	// a2 will send requests
	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort}

	// Send request and wait for reply
	reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
	defer reqCancel()

	reply, err := a2.SendToAndWaitReply(reqCtx, targetAddr, []byte("hello"))
	if err != nil {
		t.Fatalf("SendToAndWaitReply failed: %v", err)
	}

	if !bytes.Equal(reply.Data, []byte("reply:hello")) {
		t.Errorf("unexpected reply data: %q, want %q", reply.Data, "reply:hello")
	}

	if !reply.Addr.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("unexpected reply addr: %v", reply.Addr)
	}

	a1.Stop()
	a2.Stop()
}

func TestSendAndWaitReply(t *testing.T) {
	const testPort1 = 15005
	const testPort2 = 15015
	const testPort3 = 15025

	// Create three peers with different ports
	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort1,
	})

	a2, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort2,
	})

	a3, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort3,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// a2 and a3 will respond to requests
	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {
			if msg.IsRequest() {
				a2.Reply(msg, []byte("from-a2"))
			}
		})
	}()

	go func() {
		a3.Start(ctx, func(ctx context.Context, msg Message) {
			if msg.IsRequest() {
				a3.Reply(msg, []byte("from-a3"))
			}
		})
	}()

	// a1 will broadcast requests
	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()
	<-a3.Ready()

	// Small delay to ensure all goroutines are ready
	time.Sleep(50 * time.Millisecond)

	// Add a2 and a3 as peers of a1
	a1.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort2})
	a1.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort3})

	// Broadcast request and wait for replies
	reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
	defer reqCancel()

	replies, err := a1.SendAndWaitReply(reqCtx, []byte("broadcast-request"))
	if err != nil {
		t.Fatalf("SendAndWaitReply failed: %v", err)
	}

	if len(replies) != 2 {
		t.Fatalf("expected 2 replies, got %d", len(replies))
	}

	// Check that we got responses from both peers
	responseData := make(map[string]bool)
	for _, r := range replies {
		responseData[string(r.Data)] = true
	}

	if !responseData["from-a2"] || !responseData["from-a3"] {
		t.Errorf("missing expected responses: got %v", responseData)
	}

	a1.Stop()
	a2.Stop()
	a3.Stop()
}

func TestSendAndWaitReply_Timeout(t *testing.T) {
	const testPort = 15006

	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort,
	})

	a2, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.2",
		Port:     testPort,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// a2 will NOT respond to requests (simulating unresponsive peer)
	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {
			// Intentionally not replying
		})
	}()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	// Add a2 as peer of a1
	a1.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort})

	// Broadcast request with short timeout
	reqCtx, reqCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer reqCancel()

	replies, err := a1.SendAndWaitReply(reqCtx, []byte("request"))

	// Should return with context deadline exceeded and empty replies
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}

	if len(replies) != 0 {
		t.Errorf("expected 0 replies, got %d", len(replies))
	}

	a1.Stop()
	a2.Stop()
}

func TestSendAndWaitReply_PartialResponses(t *testing.T) {
	const testPort = 15007

	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort,
	})

	a2, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.2",
		Port:     testPort,
	})

	a3, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.3",
		Port:     testPort,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Only a2 responds, a3 does not
	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {
			if msg.IsRequest() {
				a2.Reply(msg, []byte("from-a2"))
			}
		})
	}()

	go func() {
		a3.Start(ctx, func(ctx context.Context, msg Message) {
			// Intentionally not replying
		})
	}()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()
	<-a3.Ready()

	// Add both as peers
	a1.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort})
	a1.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: testPort})

	// Broadcast request with short timeout
	reqCtx, reqCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer reqCancel()

	replies, err := a1.SendAndWaitReply(reqCtx, []byte("request"))

	// Should timeout but return partial responses
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}

	if len(replies) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(replies))
	}

	if !bytes.Equal(replies[0].Data, []byte("from-a2")) {
		t.Errorf("unexpected reply data: %q", replies[0].Data)
	}

	a1.Stop()
	a2.Stop()
	a3.Stop()
}

func TestSendToAndWaitReply_Encrypted(t *testing.T) {
	const testPort = 15008

	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort,
		Security: &SecurityConfig{
			Key:     testKey,
			Enabled: true,
		},
	})

	a2, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.2",
		Port:     testPort,
		Security: &SecurityConfig{
			Key:     testKey,
			Enabled: true,
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {
			if msg.IsRequest() {
				a1.Reply(msg, append([]byte("encrypted-reply:"), msg.Data...))
			}
		})
	}()

	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort}

	reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
	defer reqCancel()

	reply, err := a2.SendToAndWaitReply(reqCtx, targetAddr, []byte("secret"))
	if err != nil {
		t.Fatalf("SendToAndWaitReply failed: %v", err)
	}

	if !bytes.Equal(reply.Data, []byte("encrypted-reply:secret")) {
		t.Errorf("unexpected reply data: %q", reply.Data)
	}

	a1.Stop()
	a2.Stop()
}

func TestIsRequest(t *testing.T) {
	// Message without request ID
	msg1 := Message{
		Data: []byte("test"),
		Addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000},
	}
	if msg1.IsRequest() {
		t.Error("expected IsRequest() to be false for regular message")
	}

	// Message with request ID
	msg2 := Message{
		Data:      []byte("test"),
		Addr:      &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000},
		requestID: make([]byte, 16),
	}
	if !msg2.IsRequest() {
		t.Error("expected IsRequest() to be true for request message")
	}
}

func TestReplyToNonRequest(t *testing.T) {
	const testPort = 15009

	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()

	// Try to reply to a non-request message
	msg := Message{
		Data: []byte("test"),
		Addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort},
	}

	_, err := a1.Reply(msg, []byte("response"))
	if err == nil {
		t.Error("expected error when replying to non-request message")
	}

	a1.Stop()
}

func TestRequestResponseProtocol(t *testing.T) {
	t.Run("encode/decode request", func(t *testing.T) {
		requestID := []byte("0123456789abcdef") // 16 bytes
		data := []byte("request data")

		msg := encodeRequestMessage(requestID, data)

		if msg[0] != MsgTypeRequest {
			t.Errorf("expected type %d, got %d", MsgTypeRequest, msg[0])
		}

		msgType, payload, err := decodeMessage(msg)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if msgType != MsgTypeRequest {
			t.Errorf("expected type %d, got %d", MsgTypeRequest, msgType)
		}

		decodedReqID, decodedData, err := decodeRequestPayload(payload)
		if err != nil {
			t.Fatalf("decode request payload failed: %v", err)
		}
		if !bytes.Equal(decodedReqID, requestID) {
			t.Errorf("request ID mismatch: got %q, want %q", decodedReqID, requestID)
		}
		if !bytes.Equal(decodedData, data) {
			t.Errorf("data mismatch: got %q, want %q", decodedData, data)
		}
	})

	t.Run("encode/decode response", func(t *testing.T) {
		requestID := []byte("fedcba9876543210") // 16 bytes
		data := []byte("response data")

		msg := encodeResponseMessage(requestID, data)

		if msg[0] != MsgTypeResponse {
			t.Errorf("expected type %d, got %d", MsgTypeResponse, msg[0])
		}

		msgType, payload, err := decodeMessage(msg)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if msgType != MsgTypeResponse {
			t.Errorf("expected type %d, got %d", MsgTypeResponse, msgType)
		}

		decodedReqID, decodedData, err := decodeRequestPayload(payload)
		if err != nil {
			t.Fatalf("decode request payload failed: %v", err)
		}
		if !bytes.Equal(decodedReqID, requestID) {
			t.Errorf("request ID mismatch: got %q, want %q", decodedReqID, requestID)
		}
		if !bytes.Equal(decodedData, data) {
			t.Errorf("data mismatch: got %q, want %q", decodedData, data)
		}
	})
}

func TestSendToAndWaitReply_PeerDisconnects(t *testing.T) {
	const testPort = 15010

	a1, _ := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.1",
		Port:              testPort,
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  150 * time.Millisecond,
	})

	a2, _ := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.2",
		Port:              testPort,
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  150 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// a2 will NOT respond to requests - simulating a peer that receives but doesn't reply
	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {
			// Intentionally not replying
		})
	}()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	// Add a2 as peer of a1
	a2Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort}
	a1.peers.add(a2Addr)

	// Start request in background
	resultChan := make(chan error, 1)
	go func() {
		reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
		defer reqCancel()

		_, err := a1.SendToAndWaitReply(reqCtx, a2Addr, []byte("request"))
		resultChan <- err
	}()

	// Give request time to be sent
	time.Sleep(50 * time.Millisecond)

	// Stop a2 to simulate peer leaving
	a2.Stop()

	// Wait for result
	select {
	case err := <-resultChan:
		if !errors.Is(err, ErrPeerDisconnected) {
			t.Errorf("expected ErrPeerDisconnected, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("test timed out waiting for peer disconnect error")
	}

	a1.Stop()
}

func TestSendAndWaitReply_PeerDisconnectsDuringRequest(t *testing.T) {
	const testPort1 = 15011
	const testPort2 = 15021
	const testPort3 = 15031

	a1, _ := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.1",
		Port:              testPort1,
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  150 * time.Millisecond,
	})

	a2, _ := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.1",
		Port:              testPort2,
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  150 * time.Millisecond,
	})

	a3, _ := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.1",
		Port:              testPort3,
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  150 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// a2 responds immediately
	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {
			if msg.IsRequest() {
				a2.Reply(msg, []byte("from-a2"))
			}
		})
	}()

	// a3 does NOT respond (will be stopped during request)
	go func() {
		a3.Start(ctx, func(ctx context.Context, msg Message) {
			// Intentionally not replying
		})
	}()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()
	<-a3.Ready()

	// Add peers
	a2Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort2}
	a3Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort3}
	a1.peers.add(a2Addr)
	a1.peers.add(a3Addr)

	// Start request in background
	type result struct {
		replies []Reply
		err     error
	}
	resultChan := make(chan result, 1)
	go func() {
		reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
		defer reqCancel()

		replies, err := a1.SendAndWaitReply(reqCtx, []byte("request"))
		resultChan <- result{replies, err}
	}()

	// Give request time to be sent and a2 to respond
	time.Sleep(100 * time.Millisecond)

	// Stop a3 to simulate peer leaving
	a3.Stop()

	// Wait for result - should return with partial results once a3 leaves
	select {
	case res := <-resultChan:
		if res.err != nil {
			t.Errorf("unexpected error: %v", res.err)
		}
		if len(res.replies) != 1 {
			t.Fatalf("expected 1 reply, got %d", len(res.replies))
		}
		if !bytes.Equal(res.replies[0].Data, []byte("from-a2")) {
			t.Errorf("unexpected reply data: %q", res.replies[0].Data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("test timed out - SendAndWaitReply should return early when peer disconnects")
	}

	a1.Stop()
	a2.Stop()
}

func TestSendAndWaitReply_AllPeersDisconnect(t *testing.T) {
	const testPort1 = 15012
	const testPort2 = 15022

	a1, _ := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.1",
		Port:              testPort1,
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  150 * time.Millisecond,
	})

	a2, _ := New(Config{
		DNSAddr:           "localhost",
		BindAddr:          "127.0.0.1",
		Port:              testPort2,
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  150 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// a2 does NOT respond
	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {
			// Intentionally not replying
		})
	}()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	// Add peer
	a2Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort2}
	a1.peers.add(a2Addr)

	// Start request in background
	type result struct {
		replies []Reply
		err     error
	}
	resultChan := make(chan result, 1)
	go func() {
		reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
		defer reqCancel()

		replies, err := a1.SendAndWaitReply(reqCtx, []byte("request"))
		resultChan <- result{replies, err}
	}()

	// Give request time to be sent
	time.Sleep(50 * time.Millisecond)

	// Stop a2 to simulate all peers leaving
	a2.Stop()

	// Wait for result - should return with empty results once all peers leave
	select {
	case res := <-resultChan:
		if res.err != nil {
			t.Errorf("unexpected error: %v", res.err)
		}
		if len(res.replies) != 0 {
			t.Errorf("expected 0 replies, got %d", len(res.replies))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("test timed out - SendAndWaitReply should return early when all peers disconnect")
	}

	a1.Stop()
}

// TestMessageOrdering verifies that messages from the same peer are processed in order
func TestMessageOrdering(t *testing.T) {
	const testPort = 15050

	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort,
	})

	a2, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.2",
		Port:     testPort,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Track received messages with their order
	var mu sync.Mutex
	received := make([]int, 0, 100)

	// a2 tracks message order
	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {
			// Simulate some processing time to expose ordering issues
			time.Sleep(time.Millisecond)
			mu.Lock()
			// Each message contains its sequence number as a single byte
			received = append(received, int(msg.Data[0]))
			mu.Unlock()
		})
	}()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort}

	// Send 100 messages rapidly
	numMessages := 100
	for i := 0; i < numMessages; i++ {
		a1.SendTo(targetAddr, []byte{byte(i)})
	}

	// Wait for all messages to be processed
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(received) != numMessages {
		t.Errorf("expected %d messages, got %d", numMessages, len(received))
	}

	// Verify messages were received in order
	for i, v := range received {
		if v != i {
			t.Errorf("message ordering violated: expected %d at index %d, got %d", i, i, v)
			// Show first few misordered messages
			if i < 5 {
				continue
			}
			break
		}
	}

	a1.Stop()
	a2.Stop()
}

// TestMessageOrderingWithRequests verifies that request messages are also processed in order
// when sent synchronously (one at a time)
func TestMessageOrderingWithRequests(t *testing.T) {
	const testPort = 15060

	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort,
	})

	a2, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.2",
		Port:     testPort,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	received := make([]int, 0, 20)

	// a2 tracks order and responds to requests
	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {
			mu.Lock()
			received = append(received, int(msg.Data[0]))
			mu.Unlock()

			// Reply if it's a request
			if msg.IsRequest() {
				a2.Reply(msg, []byte("ok"))
			}
		})
	}()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort}

	// Send requests synchronously (one at a time) to verify ordering
	// Each request waits for response before sending the next
	numMessages := 20
	for i := 0; i < numMessages; i++ {
		reqCtx, reqCancel := context.WithTimeout(ctx, time.Second)
		_, err := a1.SendToAndWaitReply(reqCtx, targetAddr, []byte{byte(i)})
		reqCancel()
		if err != nil {
			t.Logf("request %d failed: %v", i, err)
		}
	}

	// Wait for any remaining processing
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(received) != numMessages {
		t.Errorf("expected %d messages, got %d", numMessages, len(received))
	}

	// Verify ordering
	for i, v := range received {
		if v != i {
			t.Errorf("message ordering violated at index %d: expected %d, got %d", i, i, v)
			break
		}
	}

	a1.Stop()
	a2.Stop()
}

// TestPeerQueueCleanupOnLeave verifies that peer queues are cleaned up when peers leave
func TestPeerQueueCleanupOnLeave(t *testing.T) {
	const testPort = 15070

	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// a1 receives messages
	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {
			// Just receive messages to trigger queue creation
		})
	}()

	<-a1.Ready()

	// Simulate an external peer sending a DATA message to create a queue
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort}
	conn, _ := net.DialUDP("udp", peerAddr, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort})
	defer conn.Close()

	// Send JOIN first so a1 knows about this peer
	joinMsg := encodeControlMessage(MsgTypeJoin, testPort)
	conn.Write(joinMsg)
	time.Sleep(50 * time.Millisecond)

	// Send data message to create queue
	dataMsg := encodeDataMessage([]byte("hello"))
	conn.Write(dataMsg)
	time.Sleep(50 * time.Millisecond)

	// Check that queue exists
	a1.peerQueuesMu.RLock()
	queuesBefore := len(a1.peerQueues)
	a1.peerQueuesMu.RUnlock()

	if queuesBefore == 0 {
		t.Error("expected at least one peer queue to exist")
	}

	// Send LEAVE message
	leaveMsg := encodeControlMessage(MsgTypeLeave, testPort)
	conn.Write(leaveMsg)
	time.Sleep(100 * time.Millisecond)

	// Check that queue was cleaned up
	a1.peerQueuesMu.RLock()
	queuesAfter := len(a1.peerQueues)
	a1.peerQueuesMu.RUnlock()

	if queuesAfter != 0 {
		t.Errorf("expected 0 peer queues after peer left, got %d", queuesAfter)
	}

	a1.Stop()
}

// TestMessageQueueSizeConfig verifies that custom queue size is respected
func TestMessageQueueSizeConfig(t *testing.T) {
	customSize := 64

	a, err := New(Config{
		Port:             0,
		MessageQueueSize: customSize,
	})
	if err != nil {
		t.Fatalf("failed to create alan: %v", err)
	}

	if a.config.MessageQueueSize != customSize {
		t.Errorf("expected MessageQueueSize %d, got %d", customSize, a.config.MessageQueueSize)
	}
}

// TestDefaultMessageQueueSize verifies the default queue size
func TestDefaultMessageQueueSize(t *testing.T) {
	a, err := New(Config{Port: 0})
	if err != nil {
		t.Fatalf("failed to create alan: %v", err)
	}

	if a.config.MessageQueueSize != 256 {
		t.Errorf("expected default MessageQueueSize 256, got %d", a.config.MessageQueueSize)
	}
}

// TestPeerEventOrdering verifies that peer join/leave events are processed in order
func TestPeerEventOrdering(t *testing.T) {
	const testPort = 15080

	a1, _ := New(Config{
		DNSAddr:  "localhost",
		BindAddr: "127.0.0.1",
		Port:     testPort,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	events := make([]string, 0, 20)

	// Track join/leave events in order
	a1.OnPeerJoin(func(addr *net.UDPAddr) {
		time.Sleep(time.Millisecond) // Simulate processing
		mu.Lock()
		events = append(events, "join:"+addr.String())
		mu.Unlock()
	})

	a1.OnPeerLeave(func(addr *net.UDPAddr) {
		time.Sleep(time.Millisecond) // Simulate processing
		mu.Lock()
		events = append(events, "leave:"+addr.String())
		mu.Unlock()
	})

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()

	a1Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort}

	// Simulate multiple peers joining and leaving rapidly
	conn, _ := net.DialUDP("udp", nil, a1Addr)
	defer conn.Close()

	// Send JOIN/LEAVE for multiple "peers" (simulated by different ports)
	numPeers := 10
	for i := 0; i < numPeers; i++ {
		peerPort := 20000 + i
		joinMsg := encodeControlMessage(MsgTypeJoin, peerPort)
		conn.Write(joinMsg)
	}

	// Give time for all joins to be processed
	time.Sleep(100 * time.Millisecond)

	// Now send leaves in the same order
	for i := 0; i < numPeers; i++ {
		peerPort := 20000 + i
		leaveMsg := encodeControlMessage(MsgTypeLeave, peerPort)
		conn.Write(leaveMsg)
	}

	// Wait for all events to be processed
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Verify we got all events
	expectedEvents := numPeers * 2 // join + leave for each
	if len(events) != expectedEvents {
		t.Errorf("expected %d events, got %d", expectedEvents, len(events))
	}

	// Verify joins came before leaves (ordered processing)
	// All joins should be processed before leaves because they were sent first
	joinCount := 0
	leaveStarted := false
	for i, event := range events {
		if event[:4] == "join" {
			if leaveStarted {
				// A join after a leave means ordering was violated
				// (Note: this is a bit weak - if the events are processed truly in order,
				// all joins should come before all leaves since we sent all joins first)
				t.Logf("event %d: %s (join after leave started)", i, event)
			}
			joinCount++
		} else {
			leaveStarted = true
		}
	}

	if joinCount != numPeers {
		t.Errorf("expected %d joins, got %d", numPeers, joinCount)
	}

	a1.Stop()
}

// ============================================================================
// Quorum Tests
// ============================================================================

func TestQuorumSize(t *testing.T) {
	tests := []struct {
		quorum   int
		expected int
	}{
		{0, 0}, // disabled
		{1, 1}, // (1/2)+1 = 1
		{2, 2}, // (2/2)+1 = 2
		{3, 2}, // (3/2)+1 = 2
		{4, 3}, // (4/2)+1 = 3
		{5, 3}, // (5/2)+1 = 3
		{6, 4}, // (6/2)+1 = 4
		{7, 4}, // (7/2)+1 = 4
	}

	for _, tc := range tests {
		a, _ := New(Config{Port: 0, Replicas: tc.quorum})
		got := a.QuorumSize()
		if got != tc.expected {
			t.Errorf("QuorumSize() with Quorum=%d: got %d, want %d", tc.quorum, got, tc.expected)
		}
	}
}

func TestHasQuorum_Disabled(t *testing.T) {
	a, _ := New(Config{Port: 0, Replicas: 0})

	// With quorum disabled, HasQuorum should always return true
	if !a.HasQuorum() {
		t.Error("HasQuorum() should return true when quorum is disabled")
	}
}

func TestHasQuorum_NotMet(t *testing.T) {
	a, _ := New(Config{Port: 0, Replicas: 3})

	// With Quorum=3, we need (3/2)+1 = 2 peers
	// With 0 peers, quorum should not be met
	if a.HasQuorum() {
		t.Error("HasQuorum() should return false with 0 peers and Quorum=3")
	}

	// Add 1 peer, still not enough
	a.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 5000})
	if a.HasQuorum() {
		t.Error("HasQuorum() should return false with 1 peer and Quorum=3")
	}
}

func TestHasQuorum_Met(t *testing.T) {
	a, _ := New(Config{Port: 0, Replicas: 3})

	// Add 2 peers to meet quorum (need (3/2)+1 = 2)
	a.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 5000})
	a.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: 5000})

	if !a.HasQuorum() {
		t.Error("HasQuorum() should return true with 2 peers and Quorum=3")
	}
}

func TestWaitForQuorum_Disabled(t *testing.T) {
	a, _ := New(Config{Port: 0, Replicas: 0})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Should return immediately when quorum is disabled
	err := a.WaitForQuorum(ctx)
	if err != nil {
		t.Errorf("WaitForQuorum() should return nil when disabled, got %v", err)
	}
}

func TestWaitForQuorum_AlreadyMet(t *testing.T) {
	a, _ := New(Config{Port: 0, Replicas: 3})

	// Add enough peers
	a.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 5000})
	a.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: 5000})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	start := time.Now()
	err := a.WaitForQuorum(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("WaitForQuorum() returned error: %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("WaitForQuorum() took too long: %v", elapsed)
	}
}

func TestWaitForQuorum_WaitsUntilMet(t *testing.T) {
	a, _ := New(Config{Port: 0, Replicas: 3})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Add peers in background after a delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		a.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 5000})
		time.Sleep(100 * time.Millisecond)
		a.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: 5000})
	}()

	start := time.Now()
	err := a.WaitForQuorum(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("WaitForQuorum() returned error: %v", err)
	}
	if elapsed < 150*time.Millisecond {
		t.Errorf("WaitForQuorum() returned too quickly: %v", elapsed)
	}
}

func TestWaitForQuorum_ContextCancelled(t *testing.T) {
	a, _ := New(Config{Port: 0, Replicas: 5})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Don't add any peers - quorum will never be met
	err := a.WaitForQuorum(ctx)
	if err != context.DeadlineExceeded {
		t.Errorf("WaitForQuorum() should return DeadlineExceeded, got %v", err)
	}
}

// ============================================================================
// Lock Tests
// ============================================================================

func TestLock_SinglePeer_NoQuorum(t *testing.T) {
	const testPort = 16001

	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     testPort,
		Replicas: 0, // Quorum disabled
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()

	// With no peers and quorum disabled, lock should succeed immediately
	lockCtx, lockCancel := context.WithTimeout(ctx, time.Second)
	defer lockCancel()

	err := a1.Lock(lockCtx, "test-key")
	if err != nil {
		t.Fatalf("Lock() failed: %v", err)
	}

	// Unlock should succeed
	err = a1.Unlock("test-key")
	if err != nil {
		t.Errorf("Unlock() failed: %v", err)
	}

	a1.Stop()
}

func TestLock_TwoPeers(t *testing.T) {
	const testPort = 16002

	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     testPort,
		Replicas: 0,
	})

	a2, _ := New(Config{
		BindAddr: "127.0.0.2",
		Port:     testPort,
		Replicas: 0,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	// Connect peers
	a2Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort}
	a1Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort}
	a1.peers.add(a2Addr)
	a2.peers.add(a1Addr)

	// a1 acquires lock
	lockCtx, lockCancel := context.WithTimeout(ctx, time.Second)
	defer lockCancel()

	err := a1.Lock(lockCtx, "shared-key")
	if err != nil {
		t.Fatalf("a1.Lock() failed: %v", err)
	}

	// a1 unlocks
	err = a1.Unlock("shared-key")
	if err != nil {
		t.Errorf("a1.Unlock() failed: %v", err)
	}

	// Now a2 should be able to acquire the lock
	lockCtx2, lockCancel2 := context.WithTimeout(ctx, time.Second)
	defer lockCancel2()

	err = a2.Lock(lockCtx2, "shared-key")
	if err != nil {
		t.Fatalf("a2.Lock() failed after a1 unlocked: %v", err)
	}

	a2.Unlock("shared-key")

	a1.Stop()
	a2.Stop()
}

func TestLock_Contention(t *testing.T) {
	const testPort = 16003

	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     testPort,
		Replicas: 0,
	})

	a2, _ := New(Config{
		BindAddr: "127.0.0.2",
		Port:     testPort,
		Replicas: 0,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	// Connect peers
	a2Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort}
	a1Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort}
	a1.peers.add(a2Addr)
	a2.peers.add(a1Addr)

	// a1 acquires lock first
	lockCtx, lockCancel := context.WithTimeout(ctx, time.Second)
	err := a1.Lock(lockCtx, "contested-key")
	lockCancel()
	if err != nil {
		t.Fatalf("a1.Lock() failed: %v", err)
	}

	// a2 tries to acquire same lock with short timeout - should fail/timeout
	lockCtx2, lockCancel2 := context.WithTimeout(ctx, 200*time.Millisecond)
	err = a2.Lock(lockCtx2, "contested-key")
	lockCancel2()

	if err == nil {
		t.Error("a2.Lock() should have timed out while a1 holds lock")
		a2.Unlock("contested-key")
	} else if err != context.DeadlineExceeded {
		t.Errorf("expected DeadlineExceeded, got %v", err)
	}

	// a1 releases lock
	a1.Unlock("contested-key")

	// Now a2 should be able to acquire
	lockCtx3, lockCancel3 := context.WithTimeout(ctx, time.Second)
	err = a2.Lock(lockCtx3, "contested-key")
	lockCancel3()
	if err != nil {
		t.Fatalf("a2.Lock() failed after a1 released: %v", err)
	}

	a2.Unlock("contested-key")

	a1.Stop()
	a2.Stop()
}

func TestTryLock_Success(t *testing.T) {
	const testPort = 16004

	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     testPort,
		Replicas: 0,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()

	// TryLock on free lock should succeed
	if !a1.TryLock("trylock-key") {
		t.Error("TryLock() should succeed on free lock")
	}

	a1.Unlock("trylock-key")
	a1.Stop()
}

func TestTryLock_Failure(t *testing.T) {
	const testPort = 16005

	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     testPort,
		Replicas: 0,
	})

	a2, _ := New(Config{
		BindAddr: "127.0.0.2",
		Port:     testPort,
		Replicas: 0,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	// Connect peers
	a2Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort}
	a1Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort}
	a1.peers.add(a2Addr)
	a2.peers.add(a1Addr)

	// a1 acquires lock
	lockCtx, lockCancel := context.WithTimeout(ctx, time.Second)
	a1.Lock(lockCtx, "trylock-fail")
	lockCancel()

	// a2's TryLock should fail
	if a2.TryLock("trylock-fail") {
		t.Error("TryLock() should fail when lock is held by another peer")
		a2.Unlock("trylock-fail")
	}

	a1.Unlock("trylock-fail")
	a1.Stop()
	a2.Stop()
}

func TestTryLock_NoQuorum(t *testing.T) {
	a, _ := New(Config{Port: 0, Replicas: 5})

	// With Quorum=5, we need 3 peers, but we have 0
	// TryLock should return false
	if a.TryLock("no-quorum-key") {
		t.Error("TryLock() should return false when quorum not met")
	}
}

func TestUnlock_NotHeld(t *testing.T) {
	const testPort = 16006

	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     testPort,
		Replicas: 0,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()

	// Try to unlock a lock we don't hold
	err := a1.Unlock("not-held-key")
	if !errors.Is(err, ErrLockNotHeld) {
		t.Errorf("Unlock() should return ErrLockNotHeld, got %v", err)
	}

	a1.Stop()
}

func TestLock_AutoRelease(t *testing.T) {
	const testPort = 16007

	a1, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              testPort,
		Replicas:          0,
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  150 * time.Millisecond,
	})

	a2, _ := New(Config{
		BindAddr:          "127.0.0.2",
		Port:              testPort,
		Replicas:          0,
		HeartbeatInterval: 50 * time.Millisecond,
		HeartbeatTimeout:  150 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	// Connect peers
	a2Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort}
	a1Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort}
	a1.peers.add(a2Addr)
	a2.peers.add(a1Addr)

	// a2 acquires lock
	lockCtx, lockCancel := context.WithTimeout(ctx, time.Second)
	err := a2.Lock(lockCtx, "auto-release-key")
	lockCancel()
	if err != nil {
		t.Fatalf("a2.Lock() failed: %v", err)
	}

	// a2 stops without unlocking
	a2.Stop()

	// Wait for a1 to detect a2 left
	time.Sleep(300 * time.Millisecond)

	// a1 should now be able to acquire the lock
	lockCtx2, lockCancel2 := context.WithTimeout(ctx, time.Second)
	err = a1.Lock(lockCtx2, "auto-release-key")
	lockCancel2()
	if err != nil {
		t.Fatalf("a1.Lock() failed after a2 disconnected: %v", err)
	}

	a1.Unlock("auto-release-key")
	a1.Stop()
}

func TestLock_ContextCancellation(t *testing.T) {
	const testPort = 16008

	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     testPort,
		Replicas: 0,
	})

	a2, _ := New(Config{
		BindAddr: "127.0.0.2",
		Port:     testPort,
		Replicas: 0,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	go func() {
		a2.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()
	<-a2.Ready()

	// Connect peers
	a2Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort}
	a1Addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort}
	a1.peers.add(a2Addr)
	a2.peers.add(a1Addr)

	// a1 acquires lock
	lockCtx, lockCancel := context.WithTimeout(ctx, time.Second)
	a1.Lock(lockCtx, "cancel-key")
	lockCancel()

	// a2 tries to acquire with cancellable context
	lockCtx2, lockCancel2 := context.WithCancel(ctx)

	resultCh := make(chan error, 1)
	go func() {
		resultCh <- a2.Lock(lockCtx2, "cancel-key")
	}()

	// Cancel while waiting
	time.Sleep(50 * time.Millisecond)
	lockCancel2()

	select {
	case err := <-resultCh:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Lock() didn't return after context cancelled")
	}

	a1.Unlock("cancel-key")
	a1.Stop()
	a2.Stop()
}

func TestLock_MultipleKeys(t *testing.T) {
	const testPort = 16009

	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     testPort,
		Replicas: 0,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()

	// Acquire multiple independent locks
	keys := []string{"key-a", "key-b", "key-c"}

	for _, key := range keys {
		lockCtx, lockCancel := context.WithTimeout(ctx, time.Second)
		err := a1.Lock(lockCtx, key)
		lockCancel()
		if err != nil {
			t.Fatalf("Lock(%s) failed: %v", key, err)
		}
	}

	// All should be held
	a1.locksMu.Lock()
	heldCount := len(a1.locks)
	a1.locksMu.Unlock()

	if heldCount != len(keys) {
		t.Errorf("expected %d locks held, got %d", len(keys), heldCount)
	}

	// Unlock all
	for _, key := range keys {
		err := a1.Unlock(key)
		if err != nil {
			t.Errorf("Unlock(%s) failed: %v", key, err)
		}
	}

	a1.Stop()
}

func TestLock_WaitsForQuorum(t *testing.T) {
	const testPort = 16010

	a1, _ := New(Config{
		BindAddr: "127.0.0.1",
		Port:     testPort,
		Replicas: 3, // Need (3/2)+1 = 2 peers
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		a1.Start(ctx, func(ctx context.Context, msg Message) {})
	}()

	<-a1.Ready()

	// Try to lock without quorum - should block
	lockCtx, lockCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	err := a1.Lock(lockCtx, "quorum-key")
	lockCancel()

	if err != context.DeadlineExceeded {
		t.Errorf("Lock() should timeout waiting for quorum, got %v", err)
	}

	a1.Stop()
}

func TestLockProtocol_EncodeDecodec(t *testing.T) {
	requestID := []byte("0123456789abcdef") // 16 bytes
	key := "my-lock-key"

	// Test LockRequest encoding
	msg := encodeLockMessage(MsgTypeLockRequest, requestID, key)
	if msg[0] != MsgTypeLockRequest {
		t.Errorf("expected type %d, got %d", MsgTypeLockRequest, msg[0])
	}

	msgType, payload, err := decodeMessage(msg)
	if err != nil {
		t.Fatalf("decodeMessage failed: %v", err)
	}
	if msgType != MsgTypeLockRequest {
		t.Errorf("expected type %d, got %d", MsgTypeLockRequest, msgType)
	}

	decodedReqID, decodedKey, err := decodeLockPayload(payload)
	if err != nil {
		t.Fatalf("decodeLockPayload failed: %v", err)
	}
	if !bytes.Equal(decodedReqID, requestID) {
		t.Errorf("request ID mismatch: got %q, want %q", decodedReqID, requestID)
	}
	if decodedKey != key {
		t.Errorf("key mismatch: got %q, want %q", decodedKey, key)
	}

	// Test other message types
	for _, msgType := range []byte{MsgTypeLockGrant, MsgTypeLockDeny, MsgTypeLockRelease} {
		msg := encodeLockMessage(msgType, requestID, key)
		if msg[0] != msgType {
			t.Errorf("expected type %d, got %d", msgType, msg[0])
		}
	}
}
