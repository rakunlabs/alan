package alan

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Default sizes / timeouts. See Config field docs for semantics.
const (
	defaultMaxMessageSize    = int64(16 * 1024 * 1024)  // 16 MiB
	defaultMessageQueueBytes = int64(256 * 1024 * 1024) // 256 MiB
	defaultStreamOpenTimeout = 10 * time.Second
)

// Sentinel errors.
var (
	// ErrEmptyKey is returned by New when Security.Enabled is true but Key is empty.
	ErrEmptyKey = errors.New("alan: security key must not be empty")
	// ErrAlreadyStarted is returned when Start is called on a running instance.
	ErrAlreadyStarted = errors.New("alan: already started")
	// ErrNotStarted is returned when an operation requires Start to have been called.
	ErrNotStarted = errors.New("alan: not started")
	// ErrPeerDisconnected is returned when a target peer disconnects before
	// completing a request/response or send.
	ErrPeerDisconnected = errors.New("alan: peer disconnected before responding")
	// ErrNoQuorum is returned when quorum is required but not currently met.
	ErrNoQuorum = errors.New("alan: quorum not reached")
	// ErrLockNotHeld is returned when Unlock is called for a lock not held here.
	ErrLockNotHeld = errors.New("alan: lock not held by this instance")
	// ErrNoPeerConnection is returned when a target peer has no live QUIC connection.
	ErrNoPeerConnection = errors.New("alan: no QUIC connection to peer")
	// ErrMessageTooLarge is returned when a bytes-API message exceeds Config.MaxMessageSize.
	ErrMessageTooLarge = errors.New("alan: message exceeds MaxMessageSize")
	// ErrTypeTooLong is returned when a message type exceeds 65535 bytes.
	ErrTypeTooLong = errors.New("alan: message type exceeds maximum length (65535 bytes)")
)

// MaxTypeLen is the maximum length of a message type string (limited by uint16
// wire encoding).
const MaxTypeLen = MaxTypeBytes

// Config holds all configuration for an Alan instance.
type Config struct {
	// DNSAddr is the DNS name to resolve for discovering peers (optional).
	DNSAddr string `cfg:"dns_addr" json:"dns_addr"`
	// BindAddr is the local address to bind to (default: "0.0.0.0").
	BindAddr string `cfg:"bind_addr" json:"bind_addr"`
	// Port is the UDP port (default: 5000). All peers in the cluster must
	// listen on the same port.
	Port int `cfg:"port" json:"port"`
	// Timeout is the read/write timeout for short control operations (default: 5s).
	Timeout time.Duration `cfg:"timeout" json:"timeout"`
	// Security configures the optional pre-shared key for cluster admission.
	// Transport encryption (QUIC/TLS 1.3) is always enabled regardless of this field.
	Security SecurityConfig `cfg:"security" json:"security"`
	// HeartbeatInterval controls QUIC KeepAlivePeriod (default: 5s).
	HeartbeatInterval time.Duration `cfg:"heartbeat_interval" json:"heartbeat_interval"`
	// HeartbeatTimeout controls QUIC MaxIdleTimeout (default: 15s).
	HeartbeatTimeout time.Duration `cfg:"heartbeat_timeout" json:"heartbeat_timeout"`
	// RefreshInterval is how often to re-resolve DNS (default: 30s; -1 disables).
	RefreshInterval time.Duration `cfg:"refresh_interval" json:"refresh_interval"`
	// MessageQueueSize is the per-peer message buffer count for byte handlers
	// (default: 256). Stream handlers bypass the queue.
	MessageQueueSize int `cfg:"message_queue_size" json:"message_queue_size"`

	// MaxMessageSize is the maximum payload size in bytes for the bytes-API
	// (Send / SendTo / Request / Response). Larger payloads are rejected
	// with ErrMessageTooLarge before any allocation. Default: 16 MiB.
	// Set to a negative value to disable the cap (not recommended).
	// Use SendStream / HandleStream for arbitrary-size payloads.
	MaxMessageSize int64 `cfg:"max_message_size" json:"max_message_size"`

	// MessageQueueBytes is the per-peer queue's byte budget for buffered
	// byte-handler messages. When the budget is exceeded the QUIC accept
	// loop blocks on enqueue, applying backpressure to the sender.
	// Default: 256 MiB. Negative disables the cap.
	MessageQueueBytes int64 `cfg:"message_queue_bytes" json:"message_queue_bytes"`

	// StreamOpenTimeout is the maximum time the receiver will wait for the
	// first byte of a newly accepted stream before closing it. Protects
	// against half-open streams pinning resources. Default: 10s.
	// Set to a negative value to disable the timeout.
	StreamOpenTimeout time.Duration `cfg:"stream_open_timeout" json:"stream_open_timeout"`

	// Replicas is the expected total cluster size (including self) for
	// distributed operations such as quorum and locks. 0 disables.
	Replicas int `cfg:"replicas" json:"replicas"`
}

// SecurityConfig holds the optional pre-shared cluster admission key.
type SecurityConfig struct {
	// Key is a pre-shared cluster admission secret. Any length; hashed with
	// SHA-256 into a 32-byte fingerprint that is embedded in each peer's
	// TLS certificate and verified on every handshake. Only peers with the
	// same Key can connect.
	Key []byte `cfg:"key" json:"key" log:"-"`
	// Enabled turns PSK admission control on. When false, any peer reaching
	// the listener can complete the TLS handshake (transport stays encrypted).
	Enabled bool `cfg:"enabled" json:"enabled"`
}

// PeerHandler is a callback for peer membership events.
type PeerHandler func(addr *net.UDPAddr)

// MessageHandler is the byte-style handler. The full message body has been
// read and is in msg.Data, capped by Config.MaxMessageSize.
type MessageHandler func(ctx context.Context, msg Message)

// StreamHandler is the streaming-style handler. body reads the message body
// directly from the QUIC stream. The handler must drain or return a non-nil
// error; returning before draining causes the stream to be reset and the
// sender to observe an error. The body is closed automatically when the
// handler returns.
//
// Stream handlers run on a per-message goroutine and do not share the
// per-peer ordered queue used by byte handlers.
type StreamHandler func(ctx context.Context, msg Message, body io.Reader) error

// Message represents an incoming message.
type Message struct {
	// Type is the matched handler key.
	Type string
	// Data carries the body for byte handlers. Empty when delivered via
	// a StreamHandler (use the body io.Reader instead).
	Data []byte
	// Addr is the sender's address.
	Addr *net.UDPAddr
	// Size is the body length in bytes if known, or -1 if streaming with
	// no length declared. Always -1 for Data messages (which are FIN-delimited)
	// and len(Data) for byte deliveries of Request / Data messages.
	Size int64

	// internal:
	requestID   []byte
	replyStream *quic.Stream
}

// IsRequest reports whether this message is an RPC request expecting a reply.
func (m Message) IsRequest() bool { return len(m.requestID) > 0 }

// Reply represents a response from a peer to a request.
type Reply struct {
	// Data carries the response body.
	Data []byte
	// Addr is the responder's address.
	Addr *net.UDPAddr
}

// SendResult is the outcome of a send to a single peer.
type SendResult struct {
	Addr  *net.UDPAddr
	Sent  int64
	Error error
}

// pendingRequest tracks an in-flight RPC request waiting for responses.
type pendingRequest struct {
	responseChan chan Reply
	waitingFor   map[string]struct{}
	waitingForMu sync.Mutex
	peerLeftChan chan *net.UDPAddr
}

// peerEventType indicates whether a peer joined or left.
type peerEventType int

const (
	peerEventJoin peerEventType = iota
	peerEventLeave
)

// peerEvent represents a peer join/leave event.
type peerEvent struct {
	eventType peerEventType
	addr      *net.UDPAddr
}

// peerQueue manages ordered message processing for a single peer's byte
// handlers. The byte budget enforces backpressure when a peer floods the
// instance with large messages.
type peerQueue struct {
	ch     chan queuedMessage
	cancel context.CancelFunc

	mu       sync.Mutex
	cond     *sync.Cond
	bytes    int64
	capBytes int64
}

// queuedMessage carries a message plus its accounted size through the queue.
type queuedMessage struct {
	msg  Message
	size int64
}

// lockState tracks the state of a distributed lock.
//
// Encoding of "who holds it":
//   - holder == nil && pending == nil: we hold the lock locally.
//   - holder == nil && pending != nil: we have an in-flight acquisition;
//     pending is the local requestID used for tie-breaking.
//   - holder != nil: a remote peer holds the lock at that address.
type lockState struct {
	holder  *net.UDPAddr
	pending []byte
	waiters []chan struct{}
}

// pendingLock tracks an in-flight lock request.
type pendingLock struct {
	// requestID is the random 16-byte identifier used to correlate
	// grants/denies and to break ties when multiple peers race for the
	// same key (lower-valued requestID wins).
	requestID []byte
	// key is the lock name; used so per-peer cleanup (e.g. on peer
	// disconnect) can find the right pending acquisition.
	key string
	// peerLeft is signalled when a peer the request is waiting on
	// disconnects, so the acquisition loop can drop that peer from its
	// "needed grants" counter rather than blocking forever.
	peerLeft chan *net.UDPAddr
	grantCh  chan *net.UDPAddr
	denyCh   chan *net.UDPAddr
	// preempted is signalled when a competing request with a smaller
	// requestID wins the tie-break; the local acquisition aborts and
	// retries.
	preempted chan struct{}
}

// Alan is the QUIC peer-discovery and messaging instance.
type Alan struct {
	config Config

	// Peer registry
	peers *peers

	// QUIC networking
	transport  *quic.Transport
	listener   *quic.Listener
	serverTLS  *tls.Config
	clientTLS  *tls.Config
	quicConfig *quic.Config
	udpConn    *net.UDPConn

	// State
	running   bool
	mu        sync.RWMutex
	stopChan  chan struct{}
	readyChan chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc

	// Pending RPC requests
	pendingRequests   map[string]*pendingRequest
	pendingRequestsMu sync.RWMutex

	// Per-peer ordered queues for byte handlers
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

	// Message routing — exactly one of byte or stream handler per type.
	byteHandlers   map[string]MessageHandler
	streamHandlers map[string]StreamHandler
	handlersMu     sync.RWMutex

	// leader
	leaderMu sync.RWMutex
	leaders  map[string]struct{}
}

// New creates a new Alan instance with the given configuration.
func New(config Config) (*Alan, error) {
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
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = defaultMaxMessageSize
	}
	if config.MessageQueueBytes == 0 {
		config.MessageQueueBytes = defaultMessageQueueBytes
	}
	if config.StreamOpenTimeout == 0 {
		config.StreamOpenTimeout = defaultStreamOpenTimeout
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
		byteHandlers:    make(map[string]MessageHandler),
		streamHandlers:  make(map[string]StreamHandler),
		leaders:         make(map[string]struct{}),
	}

	return a, nil
}

// OnPeerJoin sets the callback invoked when a peer joins the cluster.
func (a *Alan) OnPeerJoin(handler PeerHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onPeerJoin = handler
}

// OnPeerLeave sets the callback invoked when a peer leaves the cluster.
func (a *Alan) OnPeerLeave(handler PeerHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onPeerLeave = handler
}

// Handle registers a byte-style handler for the given message type. The full
// message body is read (capped by Config.MaxMessageSize) before the handler
// is invoked. Use "" for a catch-all handler.
//
// Panics with ErrTypeTooLong if msgType exceeds MaxTypeLen; this is treated as
// a programmer error since type strings are typically static.
//
// If a handler (byte or stream) is already registered for msgType, it is
// replaced. A type maps to exactly one handler at any time.
func (a *Alan) Handle(msgType string, handler MessageHandler) {
	if len(msgType) > MaxTypeLen {
		panic(ErrTypeTooLong)
	}
	a.handlersMu.Lock()
	defer a.handlersMu.Unlock()
	delete(a.streamHandlers, msgType)
	a.byteHandlers[msgType] = handler
}

// HandleStream registers a streaming handler for the given message type. The
// handler receives the message body as an io.Reader and is responsible for
// bounding its own reads. The body is read directly from the underlying QUIC
// stream; returning without draining (or returning a non-nil error) resets
// the stream and surfaces an error to the sender.
//
// Stream handlers run on per-message goroutines; messages from the same peer
// may be processed concurrently. Use Handle if you need ordered delivery.
//
// Panics with ErrTypeTooLong if msgType exceeds MaxTypeLen; this is treated as
// a programmer error since type strings are typically static.
//
// If a handler (byte or stream) is already registered for msgType, it is
// replaced. A type maps to exactly one handler at any time.
func (a *Alan) HandleStream(msgType string, handler StreamHandler) {
	if len(msgType) > MaxTypeLen {
		panic(ErrTypeTooLong)
	}
	a.handlersMu.Lock()
	defer a.handlersMu.Unlock()
	delete(a.byteHandlers, msgType)
	a.streamHandlers[msgType] = handler
}

// Remove unregisters any handler (byte or stream) for the given type.
func (a *Alan) Remove(msgType string) {
	a.handlersMu.Lock()
	defer a.handlersMu.Unlock()
	delete(a.byteHandlers, msgType)
	delete(a.streamHandlers, msgType)
}

// Start initialises the QUIC peer-discovery system. Blocks until ctx is
// cancelled or Stop is called.
//
// When ctx is cancelled, Start runs the same graceful shutdown as Stop —
// including the leave-announcement broadcast — before returning. This
// means callers that drive lifecycle via context cancellation alone (no
// explicit Stop call) still get prompt OnPeerLeave notifications on
// remote peers.
func (a *Alan) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return ErrAlreadyStarted
	}
	a.running = true
	a.stopChan = make(chan struct{})
	// a.ctx is independent of the parent ctx so that an external
	// cancellation does not race ahead of the graceful-shutdown sequence
	// (announceLeave needs the peers map to still be populated; if a.ctx
	// were a child of ctx, handleConnection's defer would wipe peers as
	// soon as the parent cancels).
	a.ctx, a.cancel = context.WithCancel(context.Background())
	a.mu.Unlock()

	// Watch the parent ctx and trigger an orderly Stop when it cancels.
	// Stop is idempotent so this is safe even if the user also calls it
	// explicitly.
	go func() {
		select {
		case <-ctx.Done():
			_ = a.Stop()
		case <-a.stopChan:
		}
	}()

	var sharedKey []byte
	if a.config.Security.Enabled {
		sharedKey = a.config.Security.Key
	}

	cert, err := generatePSKCert(sharedKey)
	if err != nil {
		a.markStopped()
		return fmt.Errorf("failed to generate TLS cert: %w", err)
	}

	a.serverTLS = newServerTLSConfig(cert, sharedKey)
	a.clientTLS = newClientTLSConfig(cert, sharedKey)
	a.quicConfig = newQUICConfig(a.config.HeartbeatInterval, a.config.HeartbeatTimeout, a.config.MaxMessageSize)

	bindIP := net.IPv4zero
	if a.config.BindAddr != "" {
		bindIP = net.ParseIP(a.config.BindAddr)
		if bindIP == nil {
			a.markStopped()
			return fmt.Errorf("invalid BindAddr: %s", a.config.BindAddr)
		}
	}
	udpAddr := &net.UDPAddr{IP: bindIP, Port: a.config.Port}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		a.markStopped()
		return fmt.Errorf("failed to listen on port %d: %w", a.config.Port, err)
	}

	a.mu.Lock()
	a.udpConn = udpConn
	a.mu.Unlock()

	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.Listen(a.serverTLS, a.quicConfig)
	if err != nil {
		udpConn.Close()
		a.markStopped()
		return fmt.Errorf("failed to start QUIC listener: %w", err)
	}

	a.mu.Lock()
	a.transport = tr
	a.listener = ln
	a.mu.Unlock()

	if err := a.discoverAndDialPeers(); err != nil {
		ln.Close()
		tr.Close()
		a.markStopped()
		return fmt.Errorf("failed to discover peers: %w", err)
	}

	if a.config.RefreshInterval > 0 {
		go a.refreshLoop()
	}

	peerEventCtx, peerEventCancel := context.WithCancel(a.ctx)
	a.peerEventCancel = peerEventCancel
	go a.peerEventWorker(peerEventCtx)

	close(a.readyChan)

	return a.acceptLoop()
}

func (a *Alan) markStopped() {
	a.mu.Lock()
	a.running = false
	a.mu.Unlock()
}

// Stop gracefully shuts down the instance.
func (a *Alan) Stop() error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = false
	a.mu.Unlock()

	// Best-effort: announce leave to all connected peers so they fire
	// OnPeerLeave immediately rather than waiting for the QUIC idle
	// timeout. Bounded by Config.Timeout so a slow/dead peer cannot stall
	// shutdown indefinitely.
	a.announceLeave()

	for _, ca := range a.peers.connAddrs() {
		if ca.Conn != nil {
			ca.Conn.CloseWithError(0, "shutdown")
		}
	}

	a.closeAllPeerQueues()

	if a.peerEventCancel != nil {
		a.peerEventCancel()
	}

	if a.cancel != nil {
		a.cancel()
	}
	close(a.stopChan)

	if a.listener != nil {
		a.listener.Close()
	}
	if a.transport != nil {
		a.transport.Close()
	}

	return nil
}

// announceLeave broadcasts a graceful leave message to every peer with a
// live connection and waits (bounded) for the writes to flush. This is a
// best-effort operation; failures are silently ignored because the QUIC
// idle-timeout fallback still applies on the receiver side.
func (a *Alan) announceLeave() {
	conns := a.peers.connAddrs()
	if len(conns) == 0 {
		return
	}

	timeout := a.config.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, ca := range conns {
		if ca.Conn == nil {
			continue
		}
		wg.Add(1)
		go func(conn *quic.Conn) {
			defer wg.Done()
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				return
			}
			if dl, ok := ctx.Deadline(); ok {
				_ = stream.SetWriteDeadline(dl)
			}
			_ = writeLeaveFrame(stream)
			// Close FINs the stream so the receiver's readMsgType returns
			// promptly with the leave byte.
			_ = stream.Close()
		}(ca.Conn)
	}
	wg.Wait()
}

// ─────────────────────────────────────────────────────────────────────────────
// Send paths
// ─────────────────────────────────────────────────────────────────────────────

// Send broadcasts a fire-and-forget bytes message to all peers in parallel.
// data is capped by Config.MaxMessageSize.
func (a *Alan) Send(ctx context.Context, msgType string, data []byte) []SendResult {
	if !a.isRunning() {
		return nil
	}
	if a.config.MaxMessageSize >= 0 && int64(len(data)) > a.config.MaxMessageSize {
		// Surface the error per peer to keep the result shape predictable.
		peerConns := a.peers.connAddrs()
		results := make([]SendResult, len(peerConns))
		for i, pc := range peerConns {
			results[i] = SendResult{Addr: pc.Addr, Error: ErrMessageTooLarge}
		}
		return results
	}

	peerConns := a.peers.connAddrs()
	results := make([]SendResult, len(peerConns))

	var wg sync.WaitGroup
	for i, pc := range peerConns {
		wg.Add(1)
		go func(idx int, addr *net.UDPAddr, conn *quic.Conn) {
			defer wg.Done()
			n, err := a.sendDataBytes(ctx, conn, msgType, data)
			results[idx] = SendResult{Addr: addr, Sent: n, Error: err}
		}(i, pc.Addr, pc.Conn)
	}
	wg.Wait()
	return results
}

// SendTo sends a fire-and-forget bytes message to a specific peer.
// data is capped by Config.MaxMessageSize.
func (a *Alan) SendTo(ctx context.Context, addr *net.UDPAddr, msgType string, data []byte) (int, error) {
	if !a.isRunning() {
		return 0, ErrNotStarted
	}
	if a.config.MaxMessageSize >= 0 && int64(len(data)) > a.config.MaxMessageSize {
		return 0, ErrMessageTooLarge
	}
	conn, ok := a.peers.getConn(addr)
	if !ok {
		return 0, ErrNoPeerConnection
	}
	n, err := a.sendDataBytes(ctx, conn, msgType, data)
	return int(n), err
}

// SendStream broadcasts a streaming fire-and-forget message to all peers,
// serially (the io.Reader can only be read once). Use this for payloads
// larger than MaxMessageSize.
func (a *Alan) SendStream(ctx context.Context, msgType string, body io.Reader) []SendResult {
	if !a.isRunning() {
		return nil
	}
	peerConns := a.peers.connAddrs()
	results := make([]SendResult, len(peerConns))
	for i, pc := range peerConns {
		n, err := a.sendDataStream(ctx, pc.Conn, msgType, body)
		results[i] = SendResult{Addr: pc.Addr, Sent: n, Error: err}
		if err != nil {
			// Reader state is undefined after a partial write; abort the rest.
			for j := i + 1; j < len(peerConns); j++ {
				results[j] = SendResult{Addr: peerConns[j].Addr, Error: fmt.Errorf("aborted: prior peer failed: %w", err)}
			}
			break
		}
	}
	return results
}

// SendToStream sends a streaming fire-and-forget message to a specific peer.
// Returns the number of body bytes written.
func (a *Alan) SendToStream(ctx context.Context, addr *net.UDPAddr, msgType string, body io.Reader) (int64, error) {
	if !a.isRunning() {
		return 0, ErrNotStarted
	}
	conn, ok := a.peers.getConn(addr)
	if !ok {
		return 0, ErrNoPeerConnection
	}
	return a.sendDataStream(ctx, conn, msgType, body)
}

// SendAndWaitReply broadcasts a request to all peers and waits for their
// responses. RPC bodies are bytes-only and capped by Config.MaxMessageSize.
func (a *Alan) SendAndWaitReply(ctx context.Context, msgType string, data []byte) ([]Reply, error) {
	if !a.isRunning() {
		return nil, ErrNotStarted
	}
	if a.config.MaxMessageSize >= 0 && int64(len(data)) > a.config.MaxMessageSize {
		return nil, ErrMessageTooLarge
	}

	peerConns := a.peers.connAddrs()
	if len(peerConns) == 0 {
		return []Reply{}, nil
	}

	requestID := make([]byte, RequestIDSize)
	if _, err := rand.Read(requestID); err != nil {
		return nil, fmt.Errorf("generate request id: %w", err)
	}

	waitingFor := make(map[string]struct{}, len(peerConns))
	for _, pc := range peerConns {
		waitingFor[pc.Addr.String()] = struct{}{}
	}

	reqKey := hex.EncodeToString(requestID)
	pending := &pendingRequest{
		responseChan: make(chan Reply, len(peerConns)),
		waitingFor:   waitingFor,
		peerLeftChan: make(chan *net.UDPAddr, len(peerConns)),
	}
	a.pendingRequestsMu.Lock()
	a.pendingRequests[reqKey] = pending
	a.pendingRequestsMu.Unlock()
	defer func() {
		a.pendingRequestsMu.Lock()
		delete(a.pendingRequests, reqKey)
		a.pendingRequestsMu.Unlock()
	}()

	var wg sync.WaitGroup
	for _, pc := range peerConns {
		wg.Add(1)
		go func(conn *quic.Conn) {
			defer wg.Done()
			_ = a.sendRequest(ctx, conn, requestID, msgType, data)
		}(pc.Conn)
	}
	wg.Wait()

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
			pending.waitingForMu.Unlock()
		case leftAddr := <-pending.peerLeftChan:
			pending.waitingForMu.Lock()
			delete(pending.waitingFor, leftAddr.String())
			pending.waitingForMu.Unlock()
		}
	}
}

// SendToAndWaitReply sends a request to a specific peer and waits for its
// response. RPC bodies are bytes-only and capped by Config.MaxMessageSize.
func (a *Alan) SendToAndWaitReply(ctx context.Context, addr *net.UDPAddr, msgType string, data []byte) (*Reply, error) {
	if !a.isRunning() {
		return nil, ErrNotStarted
	}
	if a.config.MaxMessageSize >= 0 && int64(len(data)) > a.config.MaxMessageSize {
		return nil, ErrMessageTooLarge
	}

	conn, ok := a.peers.getConn(addr)
	if !ok {
		return nil, ErrNoPeerConnection
	}

	requestID := make([]byte, RequestIDSize)
	if _, err := rand.Read(requestID); err != nil {
		return nil, fmt.Errorf("generate request id: %w", err)
	}

	waitingFor := map[string]struct{}{addr.String(): {}}
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

	if err := a.sendRequest(ctx, conn, requestID, msgType, data); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case reply := <-pending.responseChan:
		return &reply, nil
	case <-pending.peerLeftChan:
		return nil, ErrPeerDisconnected
	}
}

// Reply sends a response to an RPC request.
func (a *Alan) Reply(ctx context.Context, msg Message, data []byte) (int, error) {
	if !msg.IsRequest() {
		return 0, errors.New("alan: cannot reply to a non-request message")
	}
	if !a.isRunning() {
		return 0, ErrNotStarted
	}
	if a.config.MaxMessageSize >= 0 && int64(len(data)) > a.config.MaxMessageSize {
		return 0, ErrMessageTooLarge
	}
	conn, ok := a.peers.getConn(msg.Addr)
	if !ok {
		return 0, ErrNoPeerConnection
	}
	if err := a.sendResponse(ctx, conn, msg.requestID, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Underlying stream-write helpers
// ─────────────────────────────────────────────────────────────────────────────

// openStream opens a new bidirectional QUIC stream with ctx-driven cancellation
// and propagates ctx deadlines onto the stream's write deadline.
func (a *Alan) openStream(ctx context.Context, conn *quic.Conn) (*quic.Stream, error) {
	stream, err := (*conn).OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = stream.SetWriteDeadline(dl)
	}
	return stream, nil
}

// sendDataBytes opens a stream and writes a complete data frame.
func (a *Alan) sendDataBytes(ctx context.Context, conn *quic.Conn, msgType string, data []byte) (int64, error) {
	stream, err := a.openStream(ctx, conn)
	if err != nil {
		return 0, err
	}
	defer stream.Close()

	if err := writeDataHeader(stream, msgType); err != nil {
		return 0, fmt.Errorf("write header: %w", err)
	}
	if len(data) == 0 {
		return 0, nil
	}
	n, err := stream.Write(data)
	if err != nil {
		return int64(n), fmt.Errorf("write body: %w", err)
	}
	return int64(n), nil
}

// sendDataStream opens a stream, writes the data header, then copies body to
// the stream. The body is read once.
func (a *Alan) sendDataStream(ctx context.Context, conn *quic.Conn, msgType string, body io.Reader) (int64, error) {
	stream, err := a.openStream(ctx, conn)
	if err != nil {
		return 0, err
	}
	defer stream.Close()

	if err := writeDataHeader(stream, msgType); err != nil {
		return 0, fmt.Errorf("write header: %w", err)
	}

	// Drive cancellation: if ctx is cancelled mid-copy, close the stream
	// to abort the in-flight Write.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.SetWriteDeadline(time.Now())
		case <-done:
		}
	}()

	n, err := io.Copy(stream, body)
	if err != nil {
		return n, fmt.Errorf("write body: %w", err)
	}
	return n, nil
}

// sendRequest opens a stream and writes a complete request frame.
func (a *Alan) sendRequest(ctx context.Context, conn *quic.Conn, reqID []byte, msgType string, data []byte) error {
	stream, err := a.openStream(ctx, conn)
	if err != nil {
		return err
	}
	defer stream.Close()
	return writeRequestFrame(stream, reqID, msgType, data)
}

// sendResponse opens a stream and writes a complete response frame.
func (a *Alan) sendResponse(ctx context.Context, conn *quic.Conn, reqID []byte, data []byte) error {
	stream, err := a.openStream(ctx, conn)
	if err != nil {
		return err
	}
	defer stream.Close()
	return writeResponseFrame(stream, reqID, data)
}

// sendLockMsg opens a stream and writes a complete lock frame.
func (a *Alan) sendLockMsg(ctx context.Context, conn *quic.Conn, msgType byte, reqID []byte, key string) error {
	stream, err := a.openStream(ctx, conn)
	if err != nil {
		return err
	}
	defer stream.Close()
	return writeLockFrame(stream, msgType, reqID, key)
}

// ─────────────────────────────────────────────────────────────────────────────
// Notify pending requests on peer leave
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Read-side observers
// ─────────────────────────────────────────────────────────────────────────────

// Peers returns the list of current peer addresses.
func (a *Alan) Peers() []*net.UDPAddr { return a.peers.list() }

// PeerCount returns the number of connected peers.
func (a *Alan) PeerCount() int { return a.peers.count() }

// IsSecure reports whether the pre-shared cluster key is enabled (transport
// is always encrypted by QUIC regardless).
func (a *Alan) IsSecure() bool { return a.config.Security.Enabled }

// Config returns a copy of the current configuration.
func (a *Alan) Config() Config { return a.config }

// LocalAddr returns the local address the listener is bound to.
func (a *Alan) LocalAddr() net.Addr {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.listener != nil {
		return a.listener.Addr()
	}
	return nil
}

// Ready returns a channel closed once Start has finished initialisation.
func (a *Alan) Ready() <-chan struct{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.readyChan
}

// QuorumSize returns the number of peers (excluding self) required for quorum.
// Replicas represents the total cluster size including self; quorum requires
// majority = (Replicas/2)+1; PeerCount excludes self, so we need Replicas/2 peers.
func (a *Alan) QuorumSize() int {
	if a.config.Replicas == 0 {
		return 0
	}
	return a.config.Replicas / 2
}

// HasQuorum returns true if the current peer count meets the quorum requirement.
func (a *Alan) HasQuorum() bool {
	required := a.QuorumSize()
	if required == 0 {
		return true
	}
	return a.PeerCount() >= required
}

// HasAllPeers returns true if all replicas are currently online.
func (a *Alan) HasAllPeers() bool {
	if a.config.Replicas == 0 {
		return true
	}
	return a.PeerCount() >= a.config.Replicas
}

// WaitAll blocks until all replicas are online or ctx is cancelled.
func (a *Alan) WaitAll(ctx context.Context) error {
	if a.config.Replicas == 0 {
		return nil
	}
	return a.waitTicker(ctx, a.config.Replicas)
}

// WaitForQuorum blocks until quorum is reached or ctx is cancelled.
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

func (a *Alan) waitForQuorum(ctx context.Context) error { return a.WaitForQuorum(ctx) }

// ─────────────────────────────────────────────────────────────────────────────
// Accept loop, connection handling, dispatch
// ─────────────────────────────────────────────────────────────────────────────

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
			if !a.isRunning() {
				return nil
			}
			if a.ctx.Err() != nil {
				return a.ctx.Err()
			}
			continue
		}

		remoteAddr := conn.RemoteAddr()
		rawAddr, ok := remoteAddr.(*net.UDPAddr)
		if !ok {
			conn.CloseWithError(1, "unsupported address type")
			continue
		}
		udpAddr := &net.UDPAddr{IP: rawAddr.IP, Port: rawAddr.Port, Zone: rawAddr.Zone}

		localAddr := a.listener.Addr().(*net.UDPAddr)
		if udpAddr.Port == localAddr.Port && (udpAddr.IP.Equal(localAddr.IP) || isOwnIP(udpAddr.IP)) {
			conn.CloseWithError(0, "self-connection")
			continue
		}

		if isNew := a.peers.add(udpAddr, conn); isNew {
			a.enqueuePeerEvent(peerEventJoin, udpAddr)
		}

		go a.handleConnection(conn, udpAddr)
	}
}

func (a *Alan) handleConnection(conn *quic.Conn, addr *net.UDPAddr) {
	defer func() {
		if existed, _ := a.peers.remove(addr); existed {
			// Synchronously release locks held by the departing peer
			// (and notify pending acquisitions) before the
			// peer-event worker would do it asynchronously. This
			// closes the window in which another survivor could
			// process a LockRequest while the dead peer still
			// appears as a holder locally.
			a.releaseLocksHeldBy(addr)
			a.notifyPeerLeft(addr)
			a.removePeerQueue(addr)
			a.enqueuePeerEvent(peerEventLeave, addr)
		}
	}()

	for {
		stream, err := conn.AcceptStream(a.ctx)
		if err != nil {
			return
		}
		go a.handleStream(stream, addr)
	}
}

// handleStream reads the first byte (MsgType) and dispatches based on type.
// For Data messages, the body is delivered as a stream to a StreamHandler if
// one is registered, or read fully (capped) and enqueued for a byte handler.
// For Request/Response/Lock messages, the full frame is read up-front (capped).
func (a *Alan) handleStream(stream *quic.Stream, addr *net.UDPAddr) {
	defer stream.Close()

	// Apply StreamOpenTimeout for the first byte to defend against half-open streams.
	if a.config.StreamOpenTimeout > 0 {
		_ = stream.SetReadDeadline(time.Now().Add(a.config.StreamOpenTimeout))
	}
	msgType, err := readMsgType(stream)
	if err != nil {
		return
	}
	// Clear the open-timeout for the rest of the stream.
	_ = stream.SetReadDeadline(time.Time{})

	switch msgType {
	case MsgTypeData:
		a.handleDataStream(stream, addr)
	case MsgTypeRequest:
		a.handleRequestStream(stream, addr)
	case MsgTypeResponse:
		a.handleResponseStream(stream, addr)
	case MsgTypeLockRequest, MsgTypeLockGrant, MsgTypeLockDeny, MsgTypeLockRelease:
		a.handleLockStream(msgType, stream, addr)
	case MsgTypeLeave:
		a.handleLeaveStream(addr)
	default:
		// Unknown message type — close the stream silently.
	}
}

// handleLeaveStream processes a graceful leave announcement from a peer.
// It removes the peer from the registry, releases any locks the peer
// held, notifies pending requests/acquisitions, fires the OnPeerLeave
// callback (via the ordered peer-event worker), and closes the
// underlying QUIC connection so the dial/accept goroutine for this peer
// exits promptly.
//
// Lock release happens synchronously here (not just via the
// peer-event worker) so a subsequent LockRequest from another survivor
// observes consistent state — without this, a freshly-dead leader could
// still appear as the holder in the local lock map at the moment a
// competing peer's LockRequest is processed, causing spurious denies.
//
// Idempotent with the deferred cleanup in handleConnection: whichever
// path runs second sees existed=false and becomes a no-op.
func (a *Alan) handleLeaveStream(addr *net.UDPAddr) {
	existed, conn := a.peers.remove(addr)
	if !existed {
		return
	}
	a.releaseLocksHeldBy(addr)
	a.notifyPeerLeft(addr)
	a.removePeerQueue(addr)
	a.enqueuePeerEvent(peerEventLeave, addr)
	if conn != nil {
		conn.CloseWithError(0, "peer-left")
	}
}

func (a *Alan) handleDataStream(stream *quic.Stream, addr *net.UDPAddr) {
	msgType, err := readDataHeader(stream)
	if err != nil {
		return
	}

	a.handlersMu.RLock()
	streamHandler, hasStream := a.streamHandlers[msgType]
	if !hasStream {
		streamHandler, hasStream = a.streamHandlers[""]
	}
	byteHandler, hasByte := a.byteHandlers[msgType]
	if !hasByte {
		byteHandler, hasByte = a.byteHandlers[""]
	}
	a.handlersMu.RUnlock()

	msg := Message{
		Type: msgType,
		Addr: addr,
		Size: -1,
	}

	if hasStream {
		// Stream handler: deliver remaining stream as io.Reader.
		_ = streamHandler(a.ctx, msg, stream)
		return
	}

	if !hasByte {
		// No handler — drain (bounded) and discard.
		_, _ = io.Copy(io.Discard, io.LimitReader(stream, a.maxOrUnbounded()))
		return
	}

	// Byte handler: read full body capped by MaxMessageSize.
	body, err := readBoundedAll(stream, a.config.MaxMessageSize)
	if err != nil {
		// Either the body exceeded the cap or the stream errored. Drop.
		return
	}
	msg.Data = body
	msg.Size = int64(len(body))
	a.enqueueMessage(addr, msg, byteHandler)
}

func (a *Alan) handleRequestStream(stream *quic.Stream, addr *net.UDPAddr) {
	reqID, msgType, body, err := readRequestFrame(stream, a.config.MaxMessageSize)
	if err != nil {
		return
	}

	a.handlersMu.RLock()
	byteHandler, hasByte := a.byteHandlers[msgType]
	if !hasByte {
		byteHandler, hasByte = a.byteHandlers[""]
	}
	a.handlersMu.RUnlock()

	if !hasByte {
		// Stream handlers are not supported for RPC requests.
		return
	}

	msg := Message{
		Type:      msgType,
		Data:      body,
		Addr:      addr,
		Size:      int64(len(body)),
		requestID: reqID,
	}
	a.enqueueMessage(addr, msg, byteHandler)
}

func (a *Alan) handleResponseStream(stream *quic.Stream, addr *net.UDPAddr) {
	reqID, body, err := readResponseFrame(stream, a.config.MaxMessageSize)
	if err != nil {
		return
	}
	reqKey := hex.EncodeToString(reqID)
	a.pendingRequestsMu.RLock()
	pending, ok := a.pendingRequests[reqKey]
	a.pendingRequestsMu.RUnlock()
	if !ok {
		return
	}
	select {
	case pending.responseChan <- Reply{Data: body, Addr: addr}:
	default:
	}
}

func (a *Alan) handleLockStream(msgType byte, stream *quic.Stream, addr *net.UDPAddr) {
	reqID, key, err := readLockFrame(stream)
	if err != nil {
		return
	}
	switch msgType {
	case MsgTypeLockRequest:
		a.handleLockRequest(reqID, key, addr)
	case MsgTypeLockGrant:
		a.handleLockGrant(reqID, key, addr)
	case MsgTypeLockDeny:
		a.handleLockDeny(reqID, key, addr)
	case MsgTypeLockRelease:
		a.handleLockRelease(key, addr)
	}
}

// readBoundedAll reads up to max+1 bytes and returns ErrFrameTooLarge if more
// is available. max < 0 disables the cap.
func readBoundedAll(r io.Reader, max int64) ([]byte, error) {
	if max < 0 {
		return io.ReadAll(r)
	}
	// Read max+1 to detect overflow without a second syscall.
	buf, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > max {
		return nil, ErrFrameTooLarge
	}
	return buf, nil
}

func (a *Alan) maxOrUnbounded() int64 {
	if a.config.MaxMessageSize < 0 {
		return 1 << 62
	}
	return a.config.MaxMessageSize
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-peer queue (byte handlers) with byte-budget backpressure
// ─────────────────────────────────────────────────────────────────────────────

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
		ch:       make(chan queuedMessage, a.config.MessageQueueSize),
		cancel:   cancel,
		capBytes: a.config.MessageQueueBytes,
	}
	pq.cond = sync.NewCond(&pq.mu)
	a.peerQueues[key] = pq

	go a.peerWorker(ctx, pq)
	return pq
}

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
		// Wake any goroutines blocked on the byte budget so they exit.
		pq.mu.Lock()
		pq.cond.Broadcast()
		pq.mu.Unlock()
	}
}

func (a *Alan) closeAllPeerQueues() {
	a.peerQueuesMu.Lock()
	defer a.peerQueuesMu.Unlock()
	for _, pq := range a.peerQueues {
		pq.cancel()
		pq.mu.Lock()
		pq.cond.Broadcast()
		pq.mu.Unlock()
	}
	a.peerQueues = make(map[string]*peerQueue)
}

// enqueueMessage pushes a byte-handled message onto the per-peer queue,
// applying byte-budget backpressure. The handler is captured into the queued
// item so dispatch doesn't need another lookup.
func (a *Alan) enqueueMessage(addr *net.UDPAddr, msg Message, handler MessageHandler) {
	pq := a.getOrCreatePeerQueue(addr)
	size := int64(len(msg.Data))

	// Wait for byte budget if needed.
	if pq.capBytes >= 0 {
		pq.mu.Lock()
		for pq.bytes+size > pq.capBytes && pq.capBytes >= 0 {
			// Allow oversize messages to enqueue alone if the queue is empty,
			// otherwise we'd deadlock when a single message is larger than the budget.
			if pq.bytes == 0 {
				break
			}
			select {
			case <-a.ctx.Done():
				pq.mu.Unlock()
				return
			default:
			}
			pq.cond.Wait()
		}
		pq.bytes += size
		pq.mu.Unlock()
	}

	// The handler argument is kept for symmetry with the dispatcher's lookup
	// path (and to avoid races where a handler is replaced between enqueue
	// and dispatch — re-resolution in the worker uses the latest registration).
	_ = handler
	qm := queuedMessage{msg: msg, size: size}
	select {
	case pq.ch <- qm:
	case <-a.ctx.Done():
		// Queue going down — release the byte budget we reserved.
		if pq.capBytes >= 0 {
			pq.mu.Lock()
			pq.bytes -= size
			pq.cond.Broadcast()
			pq.mu.Unlock()
		}
	}
}

func (a *Alan) peerWorker(ctx context.Context, pq *peerQueue) {
	for {
		select {
		case <-ctx.Done():
			return
		case qm, ok := <-pq.ch:
			if !ok {
				return
			}
			a.dispatchByteMessage(ctx, qm.msg)
			if pq.capBytes >= 0 {
				pq.mu.Lock()
				pq.bytes -= qm.size
				pq.cond.Broadcast()
				pq.mu.Unlock()
			}
		}
	}
}

func (a *Alan) dispatchByteMessage(ctx context.Context, msg Message) {
	a.handlersMu.RLock()
	handler, ok := a.byteHandlers[msg.Type]
	if !ok {
		handler, ok = a.byteHandlers[""]
	}
	a.handlersMu.RUnlock()

	if ok && handler != nil {
		handler(ctx, msg)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer event ordering
// ─────────────────────────────────────────────────────────────────────────────

func (a *Alan) enqueuePeerEvent(eventType peerEventType, addr *net.UDPAddr) {
	select {
	case a.peerEventCh <- peerEvent{eventType: eventType, addr: addr}:
	case <-a.ctx.Done():
	}
}

func (a *Alan) peerEventWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-a.peerEventCh:
			if !ok {
				return
			}
			// Lock release on peer-leave happens synchronously at
			// the point of removal (handleLeaveStream /
			// handleConnection's defer); no need to repeat it here.
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

// ─────────────────────────────────────────────────────────────────────────────
// Discovery
// ─────────────────────────────────────────────────────────────────────────────

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
	go a.handleConnection(conn, addr)
}

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

// Refresh re-resolves DNS and dials any newly discovered peers.
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
		if peerAddr.IP.Equal(localAddr.IP) && peerAddr.Port == localAddr.Port {
			continue
		}
		if isOwnIP(ip) && peerAddr.Port == localAddr.Port {
			continue
		}
		if _, exists := a.peers.get(peerAddr); exists {
			continue
		}
		go a.dialPeer(peerAddr)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func (a *Alan) isRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}
