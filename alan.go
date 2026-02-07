package alan

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrInvalidKeySize is returned when the key is not exactly 32 bytes
	ErrInvalidKeySize = errors.New("key must be exactly 32 bytes")
	// ErrSecurityNotEnabled is returned when trying to use encryption without enabling it
	ErrSecurityNotEnabled = errors.New("security is not enabled")
	// ErrMessageTooShort is returned when encrypted message is shorter than nonce size
	ErrMessageTooShort = errors.New("encrypted message too short")
	// ErrDecryptionFailed is returned when message authentication fails
	ErrDecryptionFailed = errors.New("decryption failed: message authentication failed")

	// ErrAlreadyStarted is returned when Start is called on an already running instance
	ErrAlreadyStarted = errors.New("alan is already started")
	// ErrNotStarted is returned when operations are attempted before Start
	ErrNotStarted = errors.New("alan is not started")
)

// Config holds all configuration for Alan
type Config struct {
	// DNSAddr is the DNS name to resolve for discovering peers (optional).
	// If empty or DNS resolution fails, the library will still start and
	// can discover peers through incoming messages or later DNS resolution.
	DNSAddr string `cfg:"dns_addr" json:"dns_addr"`
	// BindAddr is the local address to bind to (default: "0.0.0.0" for all interfaces)
	BindAddr string `cfg:"bind_addr" json:"bind_addr"`
	// Port is the UDP port to use (default: 5000)
	// IMPORTANT: All peers in the cluster MUST use the same port
	Port int `cfg:"port" json:"port"`
	// Timeout is the read/write timeout duration (default: 5s)
	Timeout time.Duration `cfg:"timeout" json:"timeout"`
	// BufferSize is the buffer size for receiving messages (default: 4096)
	BufferSize int `cfg:"buffer_size" json:"buffer_size"`
	// Security holds optional encryption configuration
	Security *SecurityConfig `cfg:"security" json:"security"`
	// HeartbeatInterval is how often to send heartbeats (default: 5s)
	HeartbeatInterval time.Duration `cfg:"heartbeat_interval" json:"heartbeat_interval"`
	// HeartbeatTimeout is when a peer is considered dead (default: 15s)
	HeartbeatTimeout time.Duration `cfg:"heartbeat_timeout" json:"heartbeat_timeout"`
	// RefreshInterval is how often to re-resolve DNS (default: 30s, set to -1 to disable)
	RefreshInterval time.Duration `cfg:"refresh_interval" json:"refresh_interval"`
}

// SecurityConfig holds encryption settings
type SecurityConfig struct {
	// Key is the pre-shared key for ChaCha20-Poly1305 encryption.
	// Must be exactly 32 bytes.
	Key []byte `cfg:"key" json:"key"`
	// Enabled determines whether encryption is active
	Enabled bool `cfg:"enabled" json:"enabled"`
}

// PeerHandler is a callback for peer membership events
type PeerHandler func(addr *net.UDPAddr)

// MessageHandler is a callback for receiving data messages
type MessageHandler func(ctx context.Context, msg Message)

// Message represents an incoming data message from a peer
type Message struct {
	// Data contains the decrypted message payload
	Data []byte
	// Addr is the sender's address
	Addr *net.UDPAddr
	// requestID is set for request messages (internal use)
	requestID []byte
}

// IsRequest returns true if this message is a request expecting a reply
func (m Message) IsRequest() bool {
	return len(m.requestID) > 0
}

// Reply represents a response from a peer to a request
type Reply struct {
	// Data contains the response payload
	Data []byte
	// Addr is the responder's address
	Addr *net.UDPAddr
}

// pendingRequest tracks an in-flight request waiting for responses
type pendingRequest struct {
	responseChan  chan Reply
	expectedCount int
}

// SendResult contains the result of sending to a single peer
type SendResult struct {
	// Addr is the peer address
	Addr *net.UDPAddr
	// Sent is the number of bytes sent
	Sent int
	// Error is any error that occurred
	Error error
}

// Alan is the main entry point for the UDP peer discovery library.
type Alan struct {
	config Config
	aead   cipher.AEAD

	// Peer management
	peers *peers

	// Network
	conn *net.UDPConn

	// State
	running   bool
	mu        sync.RWMutex
	stopChan  chan struct{}
	readyChan chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc

	// Pending requests for request-reply pattern
	pendingRequests   map[string]*pendingRequest
	pendingRequestsMu sync.RWMutex

	// Callbacks
	onPeerJoin  PeerHandler
	onPeerLeave PeerHandler
	onMessage   MessageHandler
}

// New creates a new Alan instance with the given configuration.
func New(config Config) (*Alan, error) {
	// Set defaults
	if config.Port == 0 {
		config.Port = 5000
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.BufferSize == 0 {
		config.BufferSize = 4096
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 5 * time.Second
	}
	if config.HeartbeatTimeout == 0 {
		config.HeartbeatTimeout = 15 * time.Second
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = 30 * time.Second
	}

	a := &Alan{
		config:          config,
		peers:           newPeers(),
		readyChan:       make(chan struct{}),
		pendingRequests: make(map[string]*pendingRequest),
	}

	// Initialize encryption if security is enabled
	if config.Security != nil && config.Security.Enabled {
		if len(config.Security.Key) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("%w: got %d bytes, want %d bytes",
				ErrInvalidKeySize, len(config.Security.Key), chacha20poly1305.KeySize)
		}

		aead, err := chacha20poly1305.NewX(config.Security.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher: %w", err)
		}
		a.aead = aead
	}

	return a, nil
}

// OnPeerJoin sets the callback for when a peer joins the cluster
func (a *Alan) OnPeerJoin(handler PeerHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onPeerJoin = handler
}

// OnPeerLeave sets the callback for when a peer leaves the cluster
func (a *Alan) OnPeerLeave(handler PeerHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onPeerLeave = handler
}

// Start initializes the peer discovery system:
// - Resolves DNSAddr to discover initial peers (if configured and resolvable)
// - Starts UDP server
// - Sends JOIN to all peers
// - Starts heartbeat goroutine
// This method blocks until the context is cancelled or Stop() is called.
func (a *Alan) Start(ctx context.Context, handler MessageHandler) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return ErrAlreadyStarted
	}
	a.running = true
	a.onMessage = handler
	a.stopChan = make(chan struct{})
	a.ctx, a.cancel = context.WithCancel(ctx)
	a.mu.Unlock()

	// Create UDP socket
	bindIP := net.IPv4zero
	if a.config.BindAddr != "" {
		bindIP = net.ParseIP(a.config.BindAddr)
		if bindIP == nil {
			a.mu.Lock()
			a.running = false
			a.mu.Unlock()
			return fmt.Errorf("invalid BindAddr: %s", a.config.BindAddr)
		}
	}
	addr := &net.UDPAddr{
		IP:   bindIP,
		Port: a.config.Port,
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		return fmt.Errorf("failed to listen on port %d: %w", a.config.Port, err)
	}

	a.mu.Lock()
	a.conn = conn
	a.mu.Unlock()

	// Resolve DNS and discover initial peers
	if err := a.discoverPeers(); err != nil {
		a.conn.Close()
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		return fmt.Errorf("failed to discover peers: %w", err)
	}

	// Send JOIN to all peers
	a.broadcastControl(MsgTypeJoin)

	// Start heartbeat goroutine
	go a.heartbeatLoop()

	// Start DNS refresh goroutine if configured
	if a.config.RefreshInterval > 0 {
		go a.refreshLoop()
	}

	// Signal that we're ready to send/receive
	close(a.readyChan)

	// Start listening for messages (blocking)
	return a.listen()
}

// Stop gracefully stops the peer discovery system
func (a *Alan) Stop() error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = false
	a.mu.Unlock()

	// Send LEAVE to all peers
	a.broadcastControl(MsgTypeLeave)

	// Cancel context and close stop channel
	if a.cancel != nil {
		a.cancel()
	}
	close(a.stopChan)

	// Close connection
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Send broadcasts data to all peers
func (a *Alan) Send(data []byte) []SendResult {
	a.mu.RLock()
	if !a.running {
		a.mu.RUnlock()
		return nil
	}
	conn := a.conn
	a.mu.RUnlock()

	// Encode as DATA message
	msg := encodeDataMessage(data)

	// Encrypt if needed
	processed, err := a.processOutgoing(msg)
	if err != nil {
		peers := a.peers.list()
		results := make([]SendResult, len(peers))
		for i, peer := range peers {
			results[i] = SendResult{Addr: peer, Error: err}
		}
		return results
	}

	// Send to all peers
	peers := a.peers.list()
	results := make([]SendResult, len(peers))

	var wg sync.WaitGroup
	for i, peer := range peers {
		wg.Add(1)
		go func(idx int, addr *net.UDPAddr) {
			defer wg.Done()
			n, err := conn.WriteToUDP(processed, addr)
			results[idx] = SendResult{
				Addr:  addr,
				Sent:  n,
				Error: err,
			}
		}(i, peer)
	}
	wg.Wait()

	return results
}

// SendTo sends data to a specific peer
func (a *Alan) SendTo(addr *net.UDPAddr, data []byte) (int, error) {
	a.mu.RLock()
	if !a.running {
		a.mu.RUnlock()
		return 0, ErrNotStarted
	}
	conn := a.conn
	a.mu.RUnlock()

	// Encode as DATA message
	msg := encodeDataMessage(data)

	// Encrypt if needed
	processed, err := a.processOutgoing(msg)
	if err != nil {
		return 0, err
	}

	return conn.WriteToUDP(processed, addr)
}

// SendAndWaitReply broadcasts a request to all peers and waits for their responses.
// It returns all replies received before the context is cancelled or deadline exceeded.
// The context should have a deadline/timeout set to control how long to wait.
func (a *Alan) SendAndWaitReply(ctx context.Context, data []byte) ([]Reply, error) {
	a.mu.RLock()
	if !a.running {
		a.mu.RUnlock()
		return nil, ErrNotStarted
	}
	conn := a.conn
	a.mu.RUnlock()

	// Get current peers
	peers := a.peers.list()
	if len(peers) == 0 {
		return []Reply{}, nil
	}

	// Generate random request ID
	requestID := make([]byte, RequestIDSize)
	if _, err := rand.Read(requestID); err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	// Encode as REQUEST message
	msg := encodeRequestMessage(requestID, data)

	// Encrypt if needed
	processed, err := a.processOutgoing(msg)
	if err != nil {
		return nil, err
	}

	// Register pending request
	reqKey := hex.EncodeToString(requestID)
	pending := &pendingRequest{
		responseChan:  make(chan Reply, len(peers)+10), // Buffer for all expected responses + safety margin
		expectedCount: len(peers),
	}
	a.pendingRequestsMu.Lock()
	a.pendingRequests[reqKey] = pending
	a.pendingRequestsMu.Unlock()

	// Cleanup when done
	defer func() {
		a.pendingRequestsMu.Lock()
		delete(a.pendingRequests, reqKey)
		a.pendingRequestsMu.Unlock()
	}()

	// Send to all peers
	var wg sync.WaitGroup
	for _, peer := range peers {
		wg.Add(1)
		go func(addr *net.UDPAddr) {
			defer wg.Done()
			conn.WriteToUDP(processed, addr)
		}(peer)
	}
	wg.Wait()

	// Collect responses
	replies := make([]Reply, 0, len(peers))
	for {
		select {
		case <-ctx.Done():
			return replies, ctx.Err()
		case reply := <-pending.responseChan:
			replies = append(replies, reply)
			if len(replies) >= pending.expectedCount {
				return replies, nil
			}
		}
	}
}

// SendToAndWaitReply sends a request to a specific peer and waits for its response.
// The context should have a deadline/timeout set to control how long to wait.
func (a *Alan) SendToAndWaitReply(ctx context.Context, addr *net.UDPAddr, data []byte) (*Reply, error) {
	a.mu.RLock()
	if !a.running {
		a.mu.RUnlock()
		return nil, ErrNotStarted
	}
	conn := a.conn
	a.mu.RUnlock()

	// Generate random request ID
	requestID := make([]byte, RequestIDSize)
	if _, err := rand.Read(requestID); err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	// Encode as REQUEST message
	msg := encodeRequestMessage(requestID, data)

	// Encrypt if needed
	processed, err := a.processOutgoing(msg)
	if err != nil {
		return nil, err
	}

	// Register pending request
	reqKey := hex.EncodeToString(requestID)
	pending := &pendingRequest{
		responseChan:  make(chan Reply, 1),
		expectedCount: 1,
	}
	a.pendingRequestsMu.Lock()
	a.pendingRequests[reqKey] = pending
	a.pendingRequestsMu.Unlock()

	// Cleanup when done
	defer func() {
		a.pendingRequestsMu.Lock()
		delete(a.pendingRequests, reqKey)
		a.pendingRequestsMu.Unlock()
	}()

	// Send to peer
	if _, err := conn.WriteToUDP(processed, addr); err != nil {
		return nil, err
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case reply := <-pending.responseChan:
		return &reply, nil
	}
}

// Reply sends a response to a request message.
// This should be called from the message handler when processing a request.
// Returns an error if the message is not a request.
func (a *Alan) Reply(msg Message, data []byte) (int, error) {
	if !msg.IsRequest() {
		return 0, errors.New("cannot reply to a non-request message")
	}

	a.mu.RLock()
	if !a.running {
		a.mu.RUnlock()
		return 0, ErrNotStarted
	}
	conn := a.conn
	a.mu.RUnlock()

	// Encode as RESPONSE message with the same request ID
	respMsg := encodeResponseMessage(msg.requestID, data)

	// Encrypt if needed
	processed, err := a.processOutgoing(respMsg)
	if err != nil {
		return 0, err
	}

	return conn.WriteToUDP(processed, msg.Addr)
}

// Peers returns the list of current peer addresses
func (a *Alan) Peers() []*net.UDPAddr {
	return a.peers.list()
}

// PeerCount returns the number of connected peers
func (a *Alan) PeerCount() int {
	return a.peers.count()
}

// IsSecure returns true if encryption is enabled
func (a *Alan) IsSecure() bool {
	return a.aead != nil
}

// Config returns a copy of the current configuration
func (a *Alan) Config() Config {
	return a.config
}

// LocalAddr returns the local address the server is listening on
func (a *Alan) LocalAddr() net.Addr {
	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()
	if conn == nil {
		return nil
	}
	return conn.LocalAddr()
}

// Ready returns a channel that is closed when the instance is ready to send/receive.
// Use this to wait for Start() to complete initialization before calling Send/SendTo.
func (a *Alan) Ready() <-chan struct{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.readyChan
}

// discoverPeers resolves DNS and adds initial peers.
// If DNSAddr is empty or DNS resolution fails, it silently returns without error.
// Peers may be discovered later via DNS refresh or incoming messages.
func (a *Alan) discoverPeers() error {
	if a.config.DNSAddr == "" {
		return nil
	}

	ips, err := lookupIP(a.config.DNSAddr)
	if err != nil {
		// DNS resolution failed, but we don't fail startup
		// Peers may resolve later via refresh
		return nil
	}

	localAddr := a.conn.LocalAddr().(*net.UDPAddr)

	for _, ip := range ips {
		peerAddr := &net.UDPAddr{
			IP:   ip,
			Port: a.config.Port,
		}

		// Skip self
		if peerAddr.IP.Equal(localAddr.IP) && peerAddr.Port == localAddr.Port {
			continue
		}

		// Also skip if it's our own IP (different check for localhost)
		if isOwnIP(ip) && peerAddr.Port == localAddr.Port {
			continue
		}

		a.peers.add(peerAddr)
	}

	return nil
}

// isOwnIP checks if an IP belongs to this machine
func isOwnIP(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// listen handles incoming messages
func (a *Alan) listen() error {
	buffer := make([]byte, a.config.BufferSize)

	for {
		select {
		case <-a.ctx.Done():
			return a.ctx.Err()
		case <-a.stopChan:
			return nil
		default:
			a.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := a.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				a.mu.RLock()
				if !a.running {
					a.mu.RUnlock()
					return nil
				}
				a.mu.RUnlock()
				continue
			}

			// Decrypt if needed
			data, err := a.processIncoming(buffer[:n])
			if err != nil {
				// Skip messages that fail decryption
				continue
			}

			// Decode protocol message
			msgType, payload, err := decodeMessage(data)
			if err != nil {
				continue
			}

			// Handle message based on type
			a.handleMessage(msgType, payload, addr)
		}
	}
}

// handleMessage processes a decoded protocol message
func (a *Alan) handleMessage(msgType byte, payload []byte, sourceAddr *net.UDPAddr) {
	switch msgType {
	case MsgTypeJoin:
		port, err := decodeControlPayload(payload)
		if err != nil {
			return
		}
		peerAddr := buildPeerAddr(sourceAddr, port)
		if isNew := a.peers.add(peerAddr); isNew {
			a.mu.RLock()
			handler := a.onPeerJoin
			a.mu.RUnlock()
			if handler != nil {
				go handler(peerAddr)
			}
		}

	case MsgTypeLeave:
		port, err := decodeControlPayload(payload)
		if err != nil {
			return
		}
		peerAddr := buildPeerAddr(sourceAddr, port)
		if existed := a.peers.remove(peerAddr); existed {
			a.mu.RLock()
			handler := a.onPeerLeave
			a.mu.RUnlock()
			if handler != nil {
				go handler(peerAddr)
			}
		}

	case MsgTypeHeartbeat:
		port, err := decodeControlPayload(payload)
		if err != nil {
			return
		}
		peerAddr := buildPeerAddr(sourceAddr, port)
		// Add peer if new (in case we missed the JOIN)
		if isNew := a.peers.add(peerAddr); isNew {
			a.mu.RLock()
			handler := a.onPeerJoin
			a.mu.RUnlock()
			if handler != nil {
				go handler(peerAddr)
			}
		}

	case MsgTypeData:
		// Update last seen time for the peer (keeps peer alive even without heartbeats)
		a.peers.updateLastSeen(sourceAddr)

		a.mu.RLock()
		handler := a.onMessage
		a.mu.RUnlock()
		if handler != nil {
			// Copy payload to avoid buffer reuse issues when handler runs in goroutine
			payloadCopy := make([]byte, len(payload))
			copy(payloadCopy, payload)

			msg := Message{
				Data: payloadCopy,
				Addr: sourceAddr,
			}
			go handler(a.ctx, msg)
		}

	case MsgTypeRequest:
		// Update last seen time for the peer
		a.peers.updateLastSeen(sourceAddr)

		requestID, data, err := decodeRequestPayload(payload)
		if err != nil {
			return
		}

		a.mu.RLock()
		handler := a.onMessage
		a.mu.RUnlock()
		if handler != nil {
			// Copy data to avoid buffer reuse issues when handler runs in goroutine
			dataCopy := make([]byte, len(data))
			copy(dataCopy, data)
			requestIDCopy := make([]byte, len(requestID))
			copy(requestIDCopy, requestID)

			msg := Message{
				Data:      dataCopy,
				Addr:      sourceAddr,
				requestID: requestIDCopy,
			}
			go handler(a.ctx, msg)
		}

	case MsgTypeResponse:
		// Update last seen time for the peer
		a.peers.updateLastSeen(sourceAddr)

		requestID, data, err := decodeRequestPayload(payload)
		if err != nil {
			return
		}

		// Route response to the waiting request
		reqKey := hex.EncodeToString(requestID)
		a.pendingRequestsMu.RLock()
		pending, ok := a.pendingRequests[reqKey]
		a.pendingRequestsMu.RUnlock()

		if ok {
			// Copy data to avoid buffer reuse issues
			dataCopy := make([]byte, len(data))
			copy(dataCopy, data)

			reply := Reply{
				Data: dataCopy,
				Addr: sourceAddr,
			}
			// Non-blocking send to avoid deadlock if channel is full
			select {
			case pending.responseChan <- reply:
			default:
			}
		}
	}
}

// broadcastControl sends a control message to all peers
func (a *Alan) broadcastControl(msgType byte) {
	localAddr := a.conn.LocalAddr().(*net.UDPAddr)
	msg := encodeControlMessage(msgType, localAddr.Port)

	processed, err := a.processOutgoing(msg)
	if err != nil {
		return
	}

	for _, peer := range a.peers.list() {
		a.conn.WriteToUDP(processed, peer)
	}
}

// heartbeatLoop periodically sends heartbeats and removes stale peers
func (a *Alan) heartbeatLoop() {
	ticker := time.NewTicker(a.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.stopChan:
			return
		case <-ticker.C:
			// Send heartbeat to all peers
			a.broadcastControl(MsgTypeHeartbeat)

			// Remove stale peers
			removed := a.peers.removeStale(a.config.HeartbeatTimeout)
			a.mu.RLock()
			handler := a.onPeerLeave
			a.mu.RUnlock()
			if handler != nil {
				for _, addr := range removed {
					go handler(addr)
				}
			}
		}
	}
}

// refreshLoop periodically re-resolves DNS to discover new peers
func (a *Alan) refreshLoop() {
	ticker := time.NewTicker(a.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.stopChan:
			return
		case <-ticker.C:
			a.Refresh()
		}
	}
}

// Refresh re-resolves DNS and discovers new peers.
// If DNSAddr is empty or DNS resolution fails, it returns nil without error.
func (a *Alan) Refresh() error {
	if a.config.DNSAddr == "" {
		return nil
	}

	ips, err := lookupIP(a.config.DNSAddr)
	if err != nil {
		// DNS resolution failed, but we don't fail
		// It may resolve later
		return nil
	}

	localAddr := a.conn.LocalAddr().(*net.UDPAddr)

	for _, ip := range ips {
		peerAddr := &net.UDPAddr{
			IP:   ip,
			Port: a.config.Port,
		}

		// Skip self
		if isOwnIP(ip) && peerAddr.Port == localAddr.Port {
			continue
		}

		// Add peer if new
		if isNew := a.peers.add(peerAddr); isNew {
			// Send JOIN to new peer
			msg := encodeControlMessage(MsgTypeJoin, localAddr.Port)
			processed, _ := a.processOutgoing(msg)
			a.conn.WriteToUDP(processed, peerAddr)

			a.mu.RLock()
			handler := a.onPeerJoin
			a.mu.RUnlock()
			if handler != nil {
				go handler(peerAddr)
			}
		}
	}

	return nil
}
