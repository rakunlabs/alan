package alan

import (
	"bytes"
	"context"
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
	if err != ErrMessageTooShort {
		t.Errorf("expected ErrMessageTooShort, got %v", err)
	}

	// Invalid ciphertext (tampered)
	ciphertext, _ := a.encrypt([]byte("test"))
	ciphertext[len(ciphertext)-1] ^= 0xFF // Flip last byte
	_, err = a.decrypt(ciphertext)
	if err != ErrDecryptionFailed {
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
