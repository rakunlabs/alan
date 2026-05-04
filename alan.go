package alan

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

var (
	// ErrEmptyKey is returned when the security key is empty
	ErrEmptyKey = errors.New("security key must not be empty")

	// ErrAlreadyStarted is returned when Start is called on an already running instance
	ErrAlreadyStarted = errors.New("alan is already started")
	// ErrNotStarted is returned when operations are attempted before Start
	ErrNotStarted = errors.New("alan is not started")
	// ErrPeerDisconnected is returned when the target peer disconnects before responding
	ErrPeerDisconnected = errors.New("peer disconnected before responding")
	// ErrNoQuorum is returned when quorum is not reached
	ErrNoQuorum = errors.New("quorum not reached")
	// ErrLockNotHeld is returned when trying to unlock a lock not held by this instance
	ErrLockNotHeld = errors.New("lock not held by this instance")
	// ErrNoPeerConnection is returned when no QUIC connection exists for a peer
	ErrNoPeerConnection = errors.New("no QUIC connection to peer")
)

// Config holds all configuration for Alan
type Config struct {
	// DNSAddr is the DNS name to resolve for discovering peers (optional).
	DNSAddr string `cfg:"dns_addr" json:"dns_addr"`
	// BindAddr is the local address to bind to (default: "0.0.0.0" for all interfaces)
	BindAddr string `cfg:"bind_addr" json:"bind_addr"`
	// Port is the UDP port to use (default: 5000)
	// IMPORTANT: All peers in the cluster MUST use the same port
	Port int `cfg:"port" json:"port"`
	// Timeout is the read/write timeout duration (default: 5s)
	Timeout time.Duration `cfg:"timeout" json:"timeout"`
	// Security holds optional encryption configuration
	Security SecurityConfig `cfg:"security" json:"security"`
	// HeartbeatInterval controls QUIC KeepAlivePeriod (default: 5s)
	HeartbeatInterval time.Duration `cfg:"heartbeat_interval" json:"heartbeat_interval"`
	// HeartbeatTimeout controls QUIC MaxIdleTimeout (default: 15s)
	HeartbeatTimeout time.Duration `cfg:"heartbeat_timeout" json:"heartbeat_timeout"`
	// RefreshInterval is how often to re-resolve DNS (default: 30s, set to -1 to disable)
	RefreshInterval time.Duration `cfg:"refresh_interval" json:"refresh_interval"`
	// MessageQueueSize is the per-peer message buffer size (default: 256)
	MessageQueueSize int `cfg:"message_queue_size" json:"message_queue_size"`
	// Replicas is the expected cluster size for distributed operations.
	Replicas int `cfg:"replicas" json:"replicas"`
}

// SecurityConfig holds encryption settings
type SecurityConfig struct {
	// Key is the pre-shared key for cluster membership.
	// Only peers with the same key can connect.
	Key []byte `cfg:"key" json:"key" log:"-"`
	// Enabled determines whether PSK verification is active
	Enabled bool `cfg:"enabled" json:"enabled"`
}

// PeerHandler is a callback for peer membership events
type PeerHandler func(addr *net.UDPAddr)

// MessageHandler is a callback for receiving data messages
type MessageHandler func(ctx context.Context, msg Message)

// Message represents an incoming data message from a peer
type Message struct {
	// Type is the matched handler prefix (set by the internal mux).
	// Empty if no prefix matched or if a catch-all handler processed it.
	Type string
	// Data contains the message payload (with the Type prefix stripped)
	Data []byte
	// Addr is the sender's address
	Addr *net.UDPAddr
	// requestID is set for request messages (internal use)
	requestID []byte
	// replyStream is the QUIC stream to reply on (for request/reply pattern)
	replyStream *quic.Stream
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
	responseChan chan Reply
	// waitingFor tracks which peers we're still waiting for responses from
	waitingFor   map[string]struct{}
	waitingForMu sync.Mutex
	// peerLeftChan receives notifications when a peer we're waiting for disconnects
	peerLeftChan chan *net.UDPAddr
}

// peerQueue manages ordered message processing for a single peer
type peerQueue struct {
	ch     chan Message
	cancel context.CancelFunc
}

// peerEventType indicates whether a peer joined or left
type peerEventType int

const (
	peerEventJoin peerEventType = iota
	peerEventLeave
)

// peerEvent represents a peer join or leave event
type peerEvent struct {
	eventType peerEventType
	addr      *net.UDPAddr
}

// lockState tracks the state of a distributed lock
type lockState struct {
	holder  *net.UDPAddr
	waiters []chan struct{}
}

// pendingLock tracks an in-flight lock request
type pendingLock struct {
	grantCh chan *net.UDPAddr
	denyCh  chan *net.UDPAddr
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

// Alan is the main entry point for the QUIC peer discovery library.
type Alan struct {
	config Config

	// Peer management
	peers *peers

	// QUIC networking
	transport  *quic.Transport
	listener   *quic.Listener
	serverTLS  *tls.Config
	clientTLS  *tls.Config
	quicConfig *quic.Config
	udpConn    *net.UDPConn // underlying UDP conn for Transport

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

	// Per-peer message queues for ordered processing
	peerQueues   map[string]*peerQueue
	peerQueuesMu sync.RWMutex

	// Peer event queue for ordered join/leave processing
	peerEventCh     chan peerEvent
	peerEventCancel context.CancelFunc

	// Distributed locks
	locks          map[string]*lockState
	locksMu        sync.Mutex
	pendingLocks   map[string]*pendingLock
	pendingLocksMu sync.Mutex

	// Callbacks
	onPeerJoin  PeerHandler
	onPeerLeave PeerHandler

	// Message routing: prefix -> handler
	handlers   map[string]MessageHandler
	handlersMu sync.RWMutex
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
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 5 * time.Second
	}
	if config.HeartbeatTimeout == 0 {
		config.HeartbeatTimeout = 15 * time.Second
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = 30 * time.Second
	}
	if config.MessageQueueSize == 0 {
		config.MessageQueueSize = 256
	}

	if config.Security.Enabled && len(config.Security.Key) == 0 {
		return nil, ErrEmptyKey
	}

	a := &Alan{
		config:          config,
		peers:           newPeers(),
		readyChan:       make(chan struct{}),
		pendingRequests: make(map[string]*pendingRequest),
		peerQueues:      make(map[string]*peerQueue),
		peerEventCh:     make(chan peerEvent, config.MessageQueueSize),
		locks:           make(map[string]*lockState),
		pendingLocks:    make(map[string]*pendingLock),
		handlers:        make(map[string]MessageHandler),
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

// MaxTypeLen is the maximum length of a message type string (limited by uint16 wire encoding).
const MaxTypeLen = 65535

// ErrTypeTooLong is returned when a message type exceeds [MaxTypeLen] bytes.
var ErrTypeTooLong = errors.New("alan: message type exceeds maximum length (65535 bytes)")

// Handle registers a message handler for the given message type. When a message
// arrives with a matching type, the handler is called with Type set and the
// type already stripped from Data.
//
// Use an empty string "" to register a catch-all handler for messages that
// don't match any registered type.
//
// This is safe to call before or after Start, and concurrently from multiple
// goroutines.
func (a *Alan) Handle(msgType string, handler MessageHandler) error {
	if len(msgType) > MaxTypeLen {
		return ErrTypeTooLong
	}
	a.handlersMu.Lock()
	a.handlers[msgType] = handler
	a.handlersMu.Unlock()
	return nil
}

// Remove unregisters the handler for the given type prefix.
func (a *Alan) Remove(msgType string) {
	a.handlersMu.Lock()
	delete(a.handlers, msgType)
	a.handlersMu.Unlock()
}

// Start initializes the QUIC-based peer discovery system.
// This method blocks until the context is cancelled or Stop() is called.
//
// Register message handlers with [Handle] before or after calling Start.
func (a *Alan) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return ErrAlreadyStarted
	}
	a.running = true
	a.stopChan = make(chan struct{})
	a.ctx, a.cancel = context.WithCancel(ctx)
	a.mu.Unlock()

	// Generate TLS certificates
	var sharedKey []byte
	if a.config.Security.Enabled {
		sharedKey = a.config.Security.Key
	}

	cert, err := generatePSKCert(sharedKey)
	if err != nil {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		return fmt.Errorf("failed to generate TLS cert: %w", err)
	}

	a.serverTLS = newServerTLSConfig(cert, sharedKey)
	a.clientTLS = newClientTLSConfig(cert, sharedKey)
	a.quicConfig = newQUICConfig(a.config.HeartbeatInterval, a.config.HeartbeatTimeout)

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
	udpAddr := &net.UDPAddr{IP: bindIP, Port: a.config.Port}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		return fmt.Errorf("failed to listen on port %d: %w", a.config.Port, err)
	}

	a.mu.Lock()
	a.udpConn = udpConn
	a.mu.Unlock()

	// Create QUIC transport
	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.Listen(a.serverTLS, a.quicConfig)
	if err != nil {
		udpConn.Close()
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		return fmt.Errorf("failed to start QUIC listener: %w", err)
	}

	a.mu.Lock()
	a.transport = tr
	a.listener = ln
	a.mu.Unlock()

	// Resolve DNS and dial initial peers
	if err := a.discoverAndDialPeers(); err != nil {
		ln.Close()
		tr.Close()
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		return fmt.Errorf("failed to discover peers: %w", err)
	}

	// Start DNS refresh goroutine if configured
	if a.config.RefreshInterval > 0 {
		go a.refreshLoop()
	}

	// Start peer event worker for ordered join/leave processing
	peerEventCtx, peerEventCancel := context.WithCancel(a.ctx)
	a.peerEventCancel = peerEventCancel
	go a.peerEventWorker(peerEventCtx)

	// Signal that we're ready to send/receive
	close(a.readyChan)

	// Accept incoming QUIC connections (blocking)
	return a.acceptLoop()
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

	// Close all QUIC connections to peers (this signals LEAVE via connection close)
	for _, ca := range a.peers.connAddrs() {
		if ca.Conn != nil {
			(*ca.Conn).CloseWithError(0, "shutdown")
		}
	}

	// Close all peer message queues
	a.closeAllPeerQueues()

	// Close peer event queue
	if a.peerEventCancel != nil {
		a.peerEventCancel()
	}

	// Cancel context and close stop channel
	if a.cancel != nil {
		a.cancel()
	}
	close(a.stopChan)

	// Close QUIC listener and transport
	if a.listener != nil {
		a.listener.Close()
	}
	if a.transport != nil {
		a.transport.Close()
	}

	return nil
}

// sendOnStream opens a stream, writes a framed message, and closes it.
func (a *Alan) sendOnStream(conn *quic.Conn, msgType byte, payload []byte) error {
	stream, err := (*conn).OpenStreamSync(a.ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	if err := writeStreamMessage(stream, msgType, payload); err != nil {
		return fmt.Errorf("write stream: %w", err)
	}

	return nil
}

// Send broadcasts data to all peers under the given message type.
// The msgType is used for routing on the receiver via [Handle].
func (a *Alan) Send(msgType string, data []byte) []SendResult {
	a.mu.RLock()
	if !a.running {
		a.mu.RUnlock()
		return nil
	}
	a.mu.RUnlock()

	payload := encodeTypedPayload(msgType, data)
	peerConns := a.peers.connAddrs()
	results := make([]SendResult, len(peerConns))

	var wg sync.WaitGroup
	for i, pc := range peerConns {
		wg.Add(1)
		go func(idx int, addr *net.UDPAddr, conn *quic.Conn) {
			defer wg.Done()
			err := a.sendOnStream(conn, MsgTypeData, payload)
			sent := 0
			if err == nil {
				sent = len(data)
			}
			results[idx] = SendResult{Addr: addr, Sent: sent, Error: err}
		}(i, pc.Addr, pc.Conn)
	}
	wg.Wait()

	return results
}

// SendTo sends data to a specific peer under the given message type.
func (a *Alan) SendTo(addr *net.UDPAddr, msgType string, data []byte) (int, error) {
	a.mu.RLock()
	if !a.running {
		a.mu.RUnlock()
		return 0, ErrNotStarted
	}
	a.mu.RUnlock()

	conn, ok := a.peers.getConn(addr)
	if !ok {
		return 0, ErrNoPeerConnection
	}

	payload := encodeTypedPayload(msgType, data)
	if err := a.sendOnStream(conn, MsgTypeData, payload); err != nil {
		return 0, err
	}
	return len(data), nil
}

// SendAndWaitReply broadcasts a request to all peers and waits for their responses.
// The msgType is used for routing on the receiver via [Handle].
func (a *Alan) SendAndWaitReply(ctx context.Context, msgType string, data []byte) ([]Reply, error) {
	a.mu.RLock()
	if !a.running {
		a.mu.RUnlock()
		return nil, ErrNotStarted
	}
	a.mu.RUnlock()

	peerConns := a.peers.connAddrs()
	if len(peerConns) == 0 {
		return []Reply{}, nil
	}

	// Generate random request ID
	requestID := make([]byte, RequestIDSize)
	if _, err := rand.Read(requestID); err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	// Build waitingFor set
	waitingFor := make(map[string]struct{}, len(peerConns))
	for _, pc := range peerConns {
		waitingFor[pc.Addr.String()] = struct{}{}
	}

	// Register pending request
	reqKey := hex.EncodeToString(requestID)
	pending := &pendingRequest{
		responseChan: make(chan Reply, len(peerConns)+10),
		waitingFor:   waitingFor,
		peerLeftChan: make(chan *net.UDPAddr, len(peerConns)+10),
	}
	a.pendingRequestsMu.Lock()
	a.pendingRequests[reqKey] = pending
	a.pendingRequestsMu.Unlock()

	defer func() {
		a.pendingRequestsMu.Lock()
		delete(a.pendingRequests, reqKey)
		a.pendingRequestsMu.Unlock()
	}()

	// Send request to all peers via bidirectional streams.
	// Each stream carries: REQUEST with requestID, then we read RESPONSE back.
	// The response is routed through pending.responseChan.
	typedData := encodeTypedPayload(msgType, data)
	payload := make([]byte, RequestIDSize+len(typedData))
	copy(payload[:RequestIDSize], requestID)
	copy(payload[RequestIDSize:], typedData)

	var wg sync.WaitGroup
	for _, pc := range peerConns {
		wg.Add(1)
		go func(addr *net.UDPAddr, conn *quic.Conn) {
			defer wg.Done()
			a.sendOnStream(conn, MsgTypeRequest, payload)
		}(pc.Addr, pc.Conn)
	}
	wg.Wait()

	// Collect responses
	replies := make([]Reply, 0, len(peerConns))
	for {
		pending.waitingForMu.Lock()
		remaining := len(pending.waitingFor)
		pending.waitingForMu.Unlock()
		if remaining == 0 {
			return replies, nil
		}

		select {
		case <-ctx.Done():
			return replies, ctx.Err()
		case reply := <-pending.responseChan:
			replies = append(replies, reply)
			pending.waitingForMu.Lock()
			delete(pending.waitingFor, reply.Addr.String())
			remaining := len(pending.waitingFor)
			pending.waitingForMu.Unlock()
			if remaining == 0 {
				return replies, nil
			}
		case leftAddr := <-pending.peerLeftChan:
			pending.waitingForMu.Lock()
			delete(pending.waitingFor, leftAddr.String())
			remaining := len(pending.waitingFor)
			pending.waitingForMu.Unlock()
			if remaining == 0 {
				return replies, nil
			}
		}
	}
}

// SendToAndWaitReply sends a request to a specific peer and waits for its response.
// The msgType is used for routing on the receiver via [Handle].
func (a *Alan) SendToAndWaitReply(ctx context.Context, addr *net.UDPAddr, msgType string, data []byte) (*Reply, error) {
	a.mu.RLock()
	if !a.running {
		a.mu.RUnlock()
		return nil, ErrNotStarted
	}
	a.mu.RUnlock()

	conn, ok := a.peers.getConn(addr)
	if !ok {
		return nil, ErrNoPeerConnection
	}

	// Generate random request ID
	requestID := make([]byte, RequestIDSize)
	if _, err := rand.Read(requestID); err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	// Build waitingFor
	waitingFor := make(map[string]struct{}, 1)
	waitingFor[addr.String()] = struct{}{}

	// Register pending request
	reqKey := hex.EncodeToString(requestID)
	pending := &pendingRequest{
		responseChan: make(chan Reply, 1),
		waitingFor:   waitingFor,
		peerLeftChan: make(chan *net.UDPAddr, 1),
	}
	a.pendingRequestsMu.Lock()
	a.pendingRequests[reqKey] = pending
	a.pendingRequestsMu.Unlock()

	defer func() {
		a.pendingRequestsMu.Lock()
		delete(a.pendingRequests, reqKey)
		a.pendingRequestsMu.Unlock()
	}()

	// Send request
	typedData := encodeTypedPayload(msgType, data)
	payload := make([]byte, RequestIDSize+len(typedData))
	copy(payload[:RequestIDSize], requestID)
	copy(payload[RequestIDSize:], typedData)

	if err := a.sendOnStream(conn, MsgTypeRequest, payload); err != nil {
		return nil, err
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case reply := <-pending.responseChan:
		return &reply, nil
	case <-pending.peerLeftChan:
		return nil, ErrPeerDisconnected
	}
}

// Reply sends a response to a request message.
func (a *Alan) Reply(msg Message, data []byte) (int, error) {
	if !msg.IsRequest() {
		return 0, errors.New("cannot reply to a non-request message")
	}

	a.mu.RLock()
	if !a.running {
		a.mu.RUnlock()
		return 0, ErrNotStarted
	}
	a.mu.RUnlock()

	// Send response via a new stream to the peer
	conn, ok := a.peers.getConn(msg.Addr)
	if !ok {
		return 0, ErrNoPeerConnection
	}

	payload := make([]byte, RequestIDSize+len(data))
	copy(payload[:RequestIDSize], msg.requestID)
	copy(payload[RequestIDSize:], data)

	if err := a.sendOnStream(conn, MsgTypeResponse, payload); err != nil {
		return 0, err
	}
	return len(data), nil
}

// notifyPeerLeft notifies all pending requests that a peer has left.
func (a *Alan) notifyPeerLeft(addr *net.UDPAddr) {
	a.pendingRequestsMu.RLock()
	defer a.pendingRequestsMu.RUnlock()

	peerKey := addr.String()
	for _, pending := range a.pendingRequests {
		pending.waitingForMu.Lock()
		if _, waiting := pending.waitingFor[peerKey]; waiting {
			select {
			case pending.peerLeftChan <- addr:
			default:
			}
		}
		pending.waitingForMu.Unlock()
	}
}

// Peers returns the list of current peer addresses
func (a *Alan) Peers() []*net.UDPAddr {
	return a.peers.list()
}

// PeerCount returns the number of connected peers
func (a *Alan) PeerCount() int {
	return a.peers.count()
}

// IsSecure returns true if PSK verification is enabled
func (a *Alan) IsSecure() bool {
	return a.config.Security.Enabled
}

// Config returns a copy of the current configuration
func (a *Alan) Config() Config {
	return a.config
}

// LocalAddr returns the local address the server is listening on
func (a *Alan) LocalAddr() net.Addr {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.listener != nil {
		return a.listener.Addr()
	}
	return nil
}

// Ready returns a channel that is closed when the instance is ready to send/receive.
func (a *Alan) Ready() <-chan struct{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.readyChan
}

// QuorumSize returns the number of peers (excluding self) required for quorum.
// Replicas represents the total cluster size including self.
// Quorum = majority of cluster = (Replicas/2)+1, but since PeerCount excludes
// self, we subtract 1: need (Replicas/2+1)-1 = Replicas/2 peers.
func (a *Alan) QuorumSize() int {
	if a.config.Replicas == 0 {
		return 0
	}
	return a.config.Replicas / 2
}

// HasQuorum returns true if the current number of peers meets the quorum requirement.
func (a *Alan) HasQuorum() bool {
	required := a.QuorumSize()
	if required == 0 {
		return true
	}
	return a.PeerCount() >= required
}

// HasAllPeers returns true if the current number of peers meets the full cluster membership.
func (a *Alan) HasAllPeers() bool {
	if a.config.Replicas == 0 {
		return true
	}
	return a.PeerCount() >= a.config.Replicas
}

// WaitAll blocks until all peers are online or the context is cancelled.
func (a *Alan) WaitAll(ctx context.Context) error {
	if a.config.Replicas == 0 {
		return nil
	}
	return a.waitTicker(ctx, a.config.Replicas)
}

// WaitForQuorum blocks until quorum is reached or the context is cancelled.
func (a *Alan) WaitForQuorum(ctx context.Context) error {
	if a.config.Replicas == 0 {
		return nil
	}
	return a.waitTicker(ctx, a.QuorumSize())
}

func (a *Alan) waitTicker(ctx context.Context, required int) error {
	if a.PeerCount() >= required {
		return nil
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if a.PeerCount() >= required {
				return nil
			}
		}
	}
}

func (a *Alan) waitForQuorum(ctx context.Context) error {
	return a.WaitForQuorum(ctx)
}

// acceptLoop accepts incoming QUIC connections.
func (a *Alan) acceptLoop() error {
	for {
		select {
		case <-a.ctx.Done():
			return a.ctx.Err()
		case <-a.stopChan:
			return nil
		default:
		}

		conn, err := a.listener.Accept(a.ctx)
		if err != nil {
			a.mu.RLock()
			running := a.running
			a.mu.RUnlock()
			if !running {
				return nil
			}
			// Context cancelled
			if a.ctx.Err() != nil {
				return a.ctx.Err()
			}
			continue
		}

		// Determine peer address from the connection's remote address.
		// Since QUIC transport reuses the listener's UDP socket for outgoing
		// dials, the remote address port IS the peer's listening port.
		remoteAddr := conn.RemoteAddr()
		rawAddr, ok := remoteAddr.(*net.UDPAddr)
		if !ok {
			conn.CloseWithError(1, "unsupported address type")
			continue
		}
		udpAddr := &net.UDPAddr{IP: rawAddr.IP, Port: rawAddr.Port, Zone: rawAddr.Zone}

		// Skip self — a self-connection occurs when our own transport
		// dials our own listener (same IP and same port).
		localAddr := a.listener.Addr().(*net.UDPAddr)
		if udpAddr.Port == localAddr.Port && (udpAddr.IP.Equal(localAddr.IP) || isOwnIP(udpAddr.IP)) {
			conn.CloseWithError(0, "self-connection")
			continue
		}

		// Register peer (connection = JOIN)
		if isNew := a.peers.add(udpAddr, conn); isNew {
			a.enqueuePeerEvent(peerEventJoin, udpAddr)
		}

		// Handle streams from this connection
		go a.handleConnection(conn, udpAddr)
	}
}

// handleConnection processes all incoming streams from a QUIC connection.
// When the connection closes (peer leaves), the peer is removed.
func (a *Alan) handleConnection(conn *quic.Conn, addr *net.UDPAddr) {
	defer func() {
		// Connection closed = peer left
		if existed, _ := a.peers.remove(addr); existed {
			a.notifyPeerLeft(addr)
			a.removePeerQueue(addr)
			a.enqueuePeerEvent(peerEventLeave, addr)
		}
	}()

	for {
		stream, err := conn.AcceptStream(a.ctx)
		if err != nil {
			return // connection closed or context cancelled
		}

		go a.handleStream(stream, addr)
	}
}

// handleStream processes a single incoming QUIC stream.
func (a *Alan) handleStream(stream *quic.Stream, addr *net.UDPAddr) {
	defer (*stream).Close()

	msgType, payload, err := readStreamMessage(stream)
	if err != nil {
		return
	}

	a.handleMessage(msgType, payload, addr)
}

// handleMessage processes a decoded protocol message
func (a *Alan) handleMessage(msgType byte, payload []byte, sourceAddr *net.UDPAddr) {
	switch msgType {
	case MsgTypeData:
		typeName, data := decodeTypedPayload(payload)
		msg := Message{
			Type: typeName,
			Data: data,
			Addr: sourceAddr,
		}
		a.enqueueMessage(sourceAddr, msg)

	case MsgTypeRequest:
		if len(payload) < RequestIDSize {
			return
		}
		requestID := payload[:RequestIDSize]
		typeName, data := decodeTypedPayload(payload[RequestIDSize:])

		msg := Message{
			Type:      typeName,
			Data:      data,
			Addr:      sourceAddr,
			requestID: requestID,
		}
		a.enqueueMessage(sourceAddr, msg)

	case MsgTypeResponse:
		if len(payload) < RequestIDSize {
			return
		}
		requestID := payload[:RequestIDSize]
		data := payload[RequestIDSize:]

		reqKey := hex.EncodeToString(requestID)
		a.pendingRequestsMu.RLock()
		pending, ok := a.pendingRequests[reqKey]
		a.pendingRequestsMu.RUnlock()

		if ok {
			reply := Reply{
				Data: data,
				Addr: sourceAddr,
			}
			select {
			case pending.responseChan <- reply:
			default:
			}
		}

	case MsgTypeLockRequest:
		requestID, key, err := decodeLockPayload(payload)
		if err != nil {
			return
		}
		a.handleLockRequest(requestID, key, sourceAddr)

	case MsgTypeLockGrant:
		requestID, key, err := decodeLockPayload(payload)
		if err != nil {
			return
		}
		a.handleLockGrant(requestID, key, sourceAddr)

	case MsgTypeLockDeny:
		requestID, key, err := decodeLockPayload(payload)
		if err != nil {
			return
		}
		a.handleLockDeny(requestID, key, sourceAddr)

	case MsgTypeLockRelease:
		_, key, err := decodeLockPayload(payload)
		if err != nil {
			return
		}
		a.handleLockRelease(key, sourceAddr)
	}
}

// discoverAndDialPeers resolves DNS and dials QUIC connections to discovered peers.
func (a *Alan) discoverAndDialPeers() error {
	if a.config.DNSAddr == "" {
		return nil
	}

	ips, err := lookupIP(a.config.DNSAddr)
	if err != nil {
		return nil
	}

	localAddr := a.listener.Addr().(*net.UDPAddr)

	for _, ip := range ips {
		peerAddr := &net.UDPAddr{IP: ip, Port: a.config.Port}

		// Skip self
		if peerAddr.IP.Equal(localAddr.IP) && peerAddr.Port == localAddr.Port {
			continue
		}
		if isOwnIP(ip) && peerAddr.Port == localAddr.Port {
			continue
		}

		go a.dialPeer(peerAddr)
	}

	return nil
}

// dialPeer establishes a QUIC connection to a peer.
func (a *Alan) dialPeer(addr *net.UDPAddr) {
	ctx, cancel := context.WithTimeout(a.ctx, a.config.Timeout)
	defer cancel()

	conn, err := a.transport.Dial(ctx, addr, a.clientTLS, a.quicConfig)
	if err != nil {
		return
	}

	if isNew := a.peers.add(addr, conn); isNew {
		a.enqueuePeerEvent(peerEventJoin, addr)
	}

	// Handle incoming streams from this peer
	go a.handleConnection(conn, addr)
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
func (a *Alan) Refresh() error {
	if a.config.DNSAddr == "" {
		return nil
	}

	ips, err := lookupIP(a.config.DNSAddr)
	if err != nil {
		return nil
	}

	localAddr := a.listener.Addr().(*net.UDPAddr)

	for _, ip := range ips {
		peerAddr := &net.UDPAddr{IP: ip, Port: a.config.Port}

		// Skip self
		if peerAddr.IP.Equal(localAddr.IP) && peerAddr.Port == localAddr.Port {
			continue
		}
		if isOwnIP(ip) && peerAddr.Port == localAddr.Port {
			continue
		}

		// Check if we already have this peer
		if _, exists := a.peers.get(peerAddr); exists {
			continue
		}

		go a.dialPeer(peerAddr)
	}

	return nil
}

// getOrCreatePeerQueue returns the message queue for a peer, creating one if it doesn't exist.
func (a *Alan) getOrCreatePeerQueue(addr *net.UDPAddr) *peerQueue {
	key := addr.String()

	a.peerQueuesMu.RLock()
	pq, exists := a.peerQueues[key]
	a.peerQueuesMu.RUnlock()
	if exists {
		return pq
	}

	a.peerQueuesMu.Lock()
	defer a.peerQueuesMu.Unlock()

	if pq, exists = a.peerQueues[key]; exists {
		return pq
	}

	ctx, cancel := context.WithCancel(a.ctx)
	pq = &peerQueue{
		ch:     make(chan Message, a.config.MessageQueueSize),
		cancel: cancel,
	}
	a.peerQueues[key] = pq

	go a.peerWorker(ctx, pq)

	return pq
}

// removePeerQueue closes and removes the message queue for a peer.
func (a *Alan) removePeerQueue(addr *net.UDPAddr) {
	key := addr.String()

	a.peerQueuesMu.Lock()
	pq, exists := a.peerQueues[key]
	if exists {
		delete(a.peerQueues, key)
	}
	a.peerQueuesMu.Unlock()

	if exists && pq != nil {
		pq.cancel()
	}
}

// closeAllPeerQueues closes all peer message queues.
func (a *Alan) closeAllPeerQueues() {
	a.peerQueuesMu.Lock()
	defer a.peerQueuesMu.Unlock()

	for _, pq := range a.peerQueues {
		pq.cancel()
	}
	a.peerQueues = make(map[string]*peerQueue)
}

// enqueueMessage adds a message to the peer's queue for ordered processing.
func (a *Alan) enqueueMessage(addr *net.UDPAddr, msg Message) {
	pq := a.getOrCreatePeerQueue(addr)

	select {
	case pq.ch <- msg:
	case <-a.ctx.Done():
	}
}

// peerWorker processes messages from a peer's queue in order.
func (a *Alan) peerWorker(ctx context.Context, pq *peerQueue) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-pq.ch:
			if !ok {
				return
			}
			a.dispatch(ctx, msg)
		}
	}
}

// dispatch routes a message to the matching handler by msg.Type.
func (a *Alan) dispatch(ctx context.Context, msg Message) {
	a.handlersMu.RLock()
	handler, ok := a.handlers[msg.Type]
	if !ok {
		// Try catch-all handler.
		handler, ok = a.handlers[""]
	}
	a.handlersMu.RUnlock()

	if ok && handler != nil {
		handler(ctx, msg)
	}
}

// enqueuePeerEvent adds a peer join/leave event to the queue.
func (a *Alan) enqueuePeerEvent(eventType peerEventType, addr *net.UDPAddr) {
	select {
	case a.peerEventCh <- peerEvent{eventType: eventType, addr: addr}:
	case <-a.ctx.Done():
	}
}

// peerEventWorker processes peer join/leave events in order.
func (a *Alan) peerEventWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-a.peerEventCh:
			if !ok {
				return
			}

			if event.eventType == peerEventLeave {
				a.releaseLocksHeldBy(event.addr)
			}

			a.mu.RLock()
			var handler PeerHandler
			if event.eventType == peerEventJoin {
				handler = a.onPeerJoin
			} else {
				handler = a.onPeerLeave
			}
			a.mu.RUnlock()

			if handler != nil {
				handler(event.addr)
			}
		}
	}
}
