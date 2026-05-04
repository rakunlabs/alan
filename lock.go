package alan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Lock acquires a named distributed lock, blocking until acquired or context cancelled.
func (a *Alan) Lock(ctx context.Context, key string) error {
	if err := a.waitForQuorum(ctx); err != nil {
		return err
	}

	for {
		acquired, waitCh := a.tryAcquireLock(ctx, key)
		if acquired {
			return nil
		}

		if waitCh != nil {
			select {
			case <-ctx.Done():
				a.removeWaiter(key, waitCh)
				return ctx.Err()
			case <-waitCh:
				continue
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// TryLock attempts to acquire a named distributed lock without blocking.
func (a *Alan) TryLock(key string) bool {
	if !a.HasQuorum() {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
	defer cancel()

	acquired, _ := a.tryAcquireLock(ctx, key)
	return acquired
}

// Unlock releases a named distributed lock.
func (a *Alan) Unlock(key string) error {
	a.locksMu.Lock()
	state, exists := a.locks[key]
	if !exists || state.holder != nil {
		a.locksMu.Unlock()
		return ErrLockNotHeld
	}

	waiters := state.waiters
	delete(a.locks, key)
	a.locksMu.Unlock()

	for _, ch := range waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}

	a.broadcastLockRelease(key)

	return nil
}

// tryAcquireLock attempts to acquire a lock.
func (a *Alan) tryAcquireLock(ctx context.Context, key string) (bool, chan struct{}) {
	a.locksMu.Lock()

	state, exists := a.locks[key]
	if exists {
		if state.holder == nil {
			a.locksMu.Unlock()
			return true, nil
		}
		waitCh := make(chan struct{}, 1)
		state.waiters = append(state.waiters, waitCh)
		a.locksMu.Unlock()
		return false, waitCh
	}

	a.locksMu.Unlock()

	peerConns := a.peers.connAddrs()
	if len(peerConns) == 0 {
		a.locksMu.Lock()
		if state, exists := a.locks[key]; exists {
			if state.holder == nil {
				a.locksMu.Unlock()
				return true, nil
			}
			waitCh := make(chan struct{}, 1)
			state.waiters = append(state.waiters, waitCh)
			a.locksMu.Unlock()
			return false, waitCh
		}
		a.locks[key] = &lockState{holder: nil, waiters: nil}
		a.locksMu.Unlock()
		return true, nil
	}

	// Generate request ID
	requestID := make([]byte, RequestIDSize)
	if _, err := rand.Read(requestID); err != nil {
		return false, nil
	}

	reqKey := hex.EncodeToString(requestID)
	pending := &pendingLock{
		grantCh: make(chan *net.UDPAddr, len(peerConns)),
		denyCh:  make(chan *net.UDPAddr, len(peerConns)),
	}
	a.pendingLocksMu.Lock()
	a.pendingLocks[reqKey] = pending
	a.pendingLocksMu.Unlock()

	defer func() {
		a.pendingLocksMu.Lock()
		delete(a.pendingLocks, reqKey)
		a.pendingLocksMu.Unlock()
	}()

	// Broadcast lock request over QUIC streams
	a.broadcastLockRequest(requestID, key)

	grants := 0
	needed := len(peerConns)

	for grants < needed {
		select {
		case <-ctx.Done():
			return false, nil
		case <-pending.grantCh:
			grants++
		case <-pending.denyCh:
			a.locksMu.Lock()
			state, exists := a.locks[key]
			if !exists {
				state = &lockState{holder: nil, waiters: nil}
				a.locks[key] = state
			}
			waitCh := make(chan struct{}, 1)
			state.waiters = append(state.waiters, waitCh)
			a.locksMu.Unlock()
			return false, waitCh
		}
	}

	a.locksMu.Lock()
	if state, exists := a.locks[key]; exists && state.holder == nil {
		a.locksMu.Unlock()
		return true, nil
	}
	a.locks[key] = &lockState{holder: nil, waiters: nil}
	a.locksMu.Unlock()

	return true, nil
}

// removeWaiter removes a wait channel from a lock's waiters list
func (a *Alan) removeWaiter(key string, waitCh chan struct{}) {
	a.locksMu.Lock()
	defer a.locksMu.Unlock()

	state, exists := a.locks[key]
	if !exists {
		return
	}

	for i, ch := range state.waiters {
		if ch == waitCh {
			state.waiters = append(state.waiters[:i], state.waiters[i+1:]...)
			break
		}
	}
}

// broadcastLockRequest sends a lock request to all peers via QUIC streams.
func (a *Alan) broadcastLockRequest(requestID []byte, key string) {
	payload := encodeLockPayload(requestID, key)

	peerConns := a.peers.connAddrs()
	var wg sync.WaitGroup
	for _, pc := range peerConns {
		wg.Add(1)
		go func(pc struct {
			Addr *net.UDPAddr
			Conn *quic.Conn
		}) {
			defer wg.Done()
			a.sendOnStream(pc.Conn, MsgTypeLockRequest, payload)
		}(pc)
	}
	wg.Wait()
}

// broadcastLockRelease sends a lock release notification to all peers via QUIC streams.
func (a *Alan) broadcastLockRelease(key string) {
	requestID := make([]byte, RequestIDSize)
	payload := encodeLockPayload(requestID, key)

	peerConns := a.peers.connAddrs()
	var wg sync.WaitGroup
	for _, pc := range peerConns {
		wg.Add(1)
		go func(pc struct {
			Addr *net.UDPAddr
			Conn *quic.Conn
		}) {
			defer wg.Done()
			a.sendOnStream(pc.Conn, MsgTypeLockRelease, payload)
		}(pc)
	}
	wg.Wait()
}

// sendLockResponse sends a lock grant or deny response to a peer via QUIC stream.
func (a *Alan) sendLockResponse(msgType byte, requestID []byte, key string, addr *net.UDPAddr) {
	conn, ok := a.peers.getConn(addr)
	if !ok {
		return
	}

	payload := encodeLockPayload(requestID, key)
	a.sendOnStream(conn, msgType, payload)
}

// releaseLocksHeldBy releases all locks held by a specific peer (called on peer leave)
func (a *Alan) releaseLocksHeldBy(addr *net.UDPAddr) {
	a.locksMu.Lock()
	defer a.locksMu.Unlock()

	peerKey := addr.String()
	for key, state := range a.locks {
		if state.holder != nil && state.holder.String() == peerKey {
			waiters := state.waiters
			delete(a.locks, key)

			for _, ch := range waiters {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}
}

// handleLockRequest processes an incoming lock request
func (a *Alan) handleLockRequest(requestID []byte, key string, sourceAddr *net.UDPAddr) {
	a.locksMu.Lock()
	defer a.locksMu.Unlock()

	state, exists := a.locks[key]
	if !exists {
		a.locks[key] = &lockState{holder: sourceAddr, waiters: nil}
		a.sendLockResponse(MsgTypeLockGrant, requestID, key, sourceAddr)
		return
	}

	if state.holder == nil {
		a.sendLockResponse(MsgTypeLockDeny, requestID, key, sourceAddr)
		return
	}

	a.sendLockResponse(MsgTypeLockDeny, requestID, key, sourceAddr)
}

// handleLockGrant processes an incoming lock grant response
func (a *Alan) handleLockGrant(requestID []byte, _ string, sourceAddr *net.UDPAddr) {
	reqKey := hex.EncodeToString(requestID)

	a.pendingLocksMu.Lock()
	pending, ok := a.pendingLocks[reqKey]
	a.pendingLocksMu.Unlock()

	if ok {
		select {
		case pending.grantCh <- sourceAddr:
		default:
		}
	}
}

// handleLockDeny processes an incoming lock deny response
func (a *Alan) handleLockDeny(requestID []byte, key string, sourceAddr *net.UDPAddr) {
	reqKey := hex.EncodeToString(requestID)

	a.locksMu.Lock()
	state, exists := a.locks[key]
	if !exists {
		state = &lockState{holder: sourceAddr, waiters: nil}
		a.locks[key] = state
	} else if state.holder == nil {
		state.holder = sourceAddr
	}
	a.locksMu.Unlock()

	a.pendingLocksMu.Lock()
	pending, ok := a.pendingLocks[reqKey]
	a.pendingLocksMu.Unlock()

	if ok {
		select {
		case pending.denyCh <- sourceAddr:
		default:
		}
	}
}

// handleLockRelease processes an incoming lock release notification
func (a *Alan) handleLockRelease(key string, sourceAddr *net.UDPAddr) {
	a.locksMu.Lock()
	state, exists := a.locks[key]
	if !exists {
		a.locksMu.Unlock()
		return
	}

	if state.holder != nil && state.holder.String() == sourceAddr.String() {
		waiters := state.waiters
		delete(a.locks, key)
		a.locksMu.Unlock()

		for _, ch := range waiters {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		return
	}

	a.locksMu.Unlock()
}
