package alan

import (
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Peer represents a remote peer in the cluster
type Peer struct {
	Addr     *net.UDPAddr
	LastSeen time.Time
	// conn is the QUIC connection to this peer (may be nil if not yet established)
	conn *quic.Conn
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
func (p *peers) add(addr *net.UDPAddr, conn *quic.Conn) (isNew bool) {
	key := peerKey(addr)
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, exists := p.items[key]; !exists {
		p.items[key] = &Peer{
			Addr:     addr,
			LastSeen: time.Now(),
			conn:     conn,
		}
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
