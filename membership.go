package alan

import (
	"net"
	"sync"
	"time"
)

// Peer represents a remote peer in the cluster
type Peer struct {
	Addr     *net.UDPAddr
	LastSeen time.Time
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

// add adds or updates a peer
func (p *peers) add(addr *net.UDPAddr) (isNew bool) {
	key := peerKey(addr)
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.items[key]; !exists {
		p.items[key] = &Peer{
			Addr:     addr,
			LastSeen: time.Now(),
		}
		return true
	}

	p.items[key].LastSeen = time.Now()
	return false
}

// remove removes a peer
func (p *peers) remove(addr *net.UDPAddr) (existed bool) {
	key := peerKey(addr)
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.items[key]; exists {
		delete(p.items, key)
		return true
	}
	return false
}

// updateLastSeen updates the last seen time for a peer
func (p *peers) updateLastSeen(addr *net.UDPAddr) {
	key := peerKey(addr)
	p.mu.Lock()
	defer p.mu.Unlock()

	if peer, exists := p.items[key]; exists {
		peer.LastSeen = time.Now()
	}
}

// get returns a peer by address
func (p *peers) get(addr *net.UDPAddr) (*Peer, bool) {
	key := peerKey(addr)
	p.mu.RLock()
	defer p.mu.RUnlock()

	peer, exists := p.items[key]
	return peer, exists
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

// removeStale removes peers that haven't been seen within the timeout
// and returns the list of removed peer addresses
func (p *peers) removeStale(timeout time.Duration) []*net.UDPAddr {
	p.mu.Lock()
	defer p.mu.Unlock()

	var removed []*net.UDPAddr
	now := time.Now()

	for key, peer := range p.items {
		if now.Sub(peer.LastSeen) > timeout {
			removed = append(removed, peer.Addr)
			delete(p.items, key)
		}
	}

	return removed
}
