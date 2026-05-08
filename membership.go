package alan

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// Peer represents a remote peer in the cluster
type Peer struct {
	Addr     *net.UDPAddr
	LastSeen time.Time
	// conn is the QUIC connection to this peer (may be nil if not yet established)
	conn *quic.Conn

	// lockSendMu serialises writes to lockSendStream so concurrent
	// goroutines (e.g. competing tryAcquireLock + an Unlock) cannot
	// interleave bytes on the wire.
	lockSendMu sync.Mutex
	// lockSendStream is the persistent per-peer QUIC stream used for ALL
	// outgoing lock frames (Request / Grant / Deny / Release) to this
	// peer. Lazily opened on first lock send. Reusing a single stream
	// is what gives lock messages their FIFO ordering guarantee — see
	// protocol.go MsgTypeLockMux. The stream is bidirectional only
	// because that lets the receiver use the existing AcceptStream loop;
	// alan never reads from this stream's read side.
	lockSendStream *quic.Stream
	// lockSendErr is the sticky error from the first failed open or
	// write. Once set, subsequent send attempts return it immediately
	// (the stream is no longer usable; the peer will be torn down by
	// QUIC idle timeout).
	lockSendErr error

	// outboundSeq is the per-peer monotonic sequence counter stamped on
	// outgoing Data and Request frames. The receiver uses it to dispatch
	// byte handlers in send order even when multiple QUIC streams race
	// body completion. Sequence numbers are 1-based; 0 is a reserved
	// "skip ordering" sentinel that the receiver delivers immediately.
	// The counter is per-(local, remote) and lives only as long as this
	// Peer record (i.e. as long as the QUIC connection is up); a
	// reconnect resets it together with outboundEpoch.
	outboundSeq atomic.Uint64

	// outboundEpoch identifies this connection era. It is set when the
	// Peer record is created (i.e. on every fresh peers.add — typically
	// after a reconnect) and is constant for that record's lifetime.
	// Stamped on every byte-frame alongside outboundSeq so the receiver
	// can detect a reconnect and reset its in-order dispatch state.
	//
	// Receiver semantics on incoming (epoch, seq) — both fields use
	// modular comparison to tolerate the natural uint64 wrap:
	//   - epoch "after" curEpoch: new era. Reset nextSeq=1, drop
	//     pending, accept this frame. (Also used as the bootstrap
	//     path when curEpoch == 0.)
	//   - epoch "before" curEpoch: stale. Drop. The frame is from a
	//     previous era still in flight on a slower QUIC stream from
	//     before the reconnect.
	//   - epoch == curEpoch: normal modular seq comparison.
	//
	// "after" / "before" are signed-difference tests on the unsigned
	// value (see seqAfter in protocol.go); they remain well-defined as
	// long as no two epochs from the same Peer record live more than
	// 2^63 reconnects apart, which is unreachable in any real workload.
	//
	// Initial value is 1 (0 is reserved as "uninitialised" so a
	// missing field is detectable). Bumped only by peers.add when a
	// fresh Peer record replaces a torn-down one (i.e. on reconnect).
	outboundEpoch atomic.Uint64
}

// peerKey generates a unique key for a peer based on IP and Port
func peerKey(addr *net.UDPAddr) string {
	return addr.String()
}

// peers manages the peer list with thread-safe operations
type peers struct {
	mu    sync.RWMutex
	items map[string]*Peer
}

// newPeers creates a new peer manager
func newPeers() *peers {
	return &peers{
		items: make(map[string]*Peer),
	}
}

// add adds or updates a peer. If conn is non-nil, it updates the connection too.
//
// New peer records start at outboundEpoch=1, outboundSeq=0. An update
// to an existing record preserves both fields so a transient peers.add
// (e.g. dial losing the race with accept) does not reset in-flight
// ordering.
func (p *peers) add(addr *net.UDPAddr, conn *quic.Conn) (isNew bool) {
	key := peerKey(addr)
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, exists := p.items[key]; !exists {
		peer := &Peer{
			Addr:     addr,
			LastSeen: time.Now(),
			conn:     conn,
		}
		peer.outboundEpoch.Store(1)
		p.items[key] = peer
		return true
	} else {
		existing.LastSeen = time.Now()
		if conn != nil {
			existing.conn = conn
		}
		return false
	}
}

// remove removes a peer and returns the QUIC connection (if any) for cleanup.
func (p *peers) remove(addr *net.UDPAddr) (existed bool, conn *quic.Conn) {
	key := peerKey(addr)
	p.mu.Lock()
	defer p.mu.Unlock()

	if peer, exists := p.items[key]; exists {
		conn = peer.conn
		delete(p.items, key)
		return true, conn
	}
	return false, nil
}

// removeByKey removes a peer by key and returns its info.
func (p *peers) removeByKey(key string) (addr *net.UDPAddr, conn *quic.Conn, existed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if peer, exists := p.items[key]; exists {
		addr = peer.Addr
		conn = peer.conn
		delete(p.items, key)
		return addr, conn, true
	}
	return nil, nil, false
}

// get returns a peer by address
func (p *peers) get(addr *net.UDPAddr) (*Peer, bool) {
	key := peerKey(addr)
	p.mu.RLock()
	defer p.mu.RUnlock()

	peer, exists := p.items[key]
	return peer, exists
}

// getConn returns the QUIC connection for a peer, if it exists.
func (p *peers) getConn(addr *net.UDPAddr) (*quic.Conn, bool) {
	key := peerKey(addr)
	p.mu.RLock()
	defer p.mu.RUnlock()

	peer, exists := p.items[key]
	if !exists || peer.conn == nil {
		return nil, false
	}
	return peer.conn, true
}

// setConn sets the QUIC connection for an existing peer.
func (p *peers) setConn(addr *net.UDPAddr, conn *quic.Conn) {
	key := peerKey(addr)
	p.mu.Lock()
	defer p.mu.Unlock()

	if peer, exists := p.items[key]; exists {
		peer.conn = conn
	}
}

// list returns all peer addresses
func (p *peers) list() []*net.UDPAddr {
	p.mu.RLock()
	defer p.mu.RUnlock()

	addrs := make([]*net.UDPAddr, 0, len(p.items))
	for _, peer := range p.items {
		addrs = append(addrs, peer.Addr)
	}
	return addrs
}

// count returns the number of peers
func (p *peers) count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.items)
}

// allConns returns all QUIC connections (for broadcasting).
func (p *peers) allConns() []*quic.Conn {
	p.mu.RLock()
	defer p.mu.RUnlock()

	conns := make([]*quic.Conn, 0, len(p.items))
	for _, peer := range p.items {
		if peer.conn != nil {
			conns = append(conns, peer.conn)
		}
	}
	return conns
}

// nextOutboundFrame atomically advances and returns the (epoch, seq)
// pair to stamp on the next outgoing byte-frame to addr. epoch is the
// current outboundEpoch (constant for the lifetime of this Peer record);
// seq is the post-increment outboundSeq.
//
// Both fields are uint64 and use modular comparison on the receiver
// side, so the seq counter is allowed to wrap from 2^64-1 back to 0
// without any application-visible event. In practice no real-world
// workload reaches 2^64 frames on a single connection (1 ns/frame for
// 584 years), but the wrap is well-defined either way.
//
// Returns ok=false only when the peer is not registered (treated by
// callers as ErrNoPeerConnection).
func (p *peers) nextOutboundFrame(addr *net.UDPAddr) (epoch, seq uint64, ok bool) {
	p.mu.RLock()
	peer, exists := p.items[peerKey(addr)]
	p.mu.RUnlock()
	if !exists {
		return 0, 0, false
	}
	// outboundSeq.Add(1) wraps naturally on overflow; receivers handle
	// the wrap via modular comparison.
	return peer.outboundEpoch.Load(), peer.outboundSeq.Add(1), true
}

// withLockSendStream looks up the peer for addr and invokes fn while
// holding the peer's lockSendMu. fn is called with the peer's persistent
// uni-stream; if it has not yet been opened, fn receives a nil stream
// and is responsible for opening one and storing it via setLockSendStream.
//
// Returns ErrNoPeerConnection if the peer is gone, or the sticky
// lockSendErr if a previous send permanently broke the stream.
//
// Callers MUST NOT call this from a context where the peer's
// outer registry mutex (p.mu) is already held.
func (p *peers) withLockSendStream(addr *net.UDPAddr, fn func(*Peer) error) error {
	p.mu.RLock()
	peer, exists := p.items[peerKey(addr)]
	p.mu.RUnlock()
	if !exists {
		return ErrNoPeerConnection
	}
	peer.lockSendMu.Lock()
	defer peer.lockSendMu.Unlock()
	if peer.lockSendErr != nil {
		return peer.lockSendErr
	}
	return fn(peer)
}

// closeLockSendStream tears down the persistent lock-mux stream for the
// given peer. Safe to call multiple times.
func (p *peers) closeLockSendStream(addr *net.UDPAddr) {
	p.mu.RLock()
	peer, exists := p.items[peerKey(addr)]
	p.mu.RUnlock()
	if !exists {
		return
	}
	peer.lockSendMu.Lock()
	defer peer.lockSendMu.Unlock()
	if peer.lockSendStream != nil {
		_ = peer.lockSendStream.Close()
		peer.lockSendStream = nil
	}
}

// connAddrs returns all peers with their connections.
func (p *peers) connAddrs() []struct {
	Addr *net.UDPAddr
	Conn *quic.Conn
} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]struct {
		Addr *net.UDPAddr
		Conn *quic.Conn
	}, 0, len(p.items))
	for _, peer := range p.items {
		if peer.conn != nil {
			result = append(result, struct {
				Addr *net.UDPAddr
				Conn *quic.Conn
			}{Addr: peer.Addr, Conn: peer.conn})
		}
	}
	return result
}
