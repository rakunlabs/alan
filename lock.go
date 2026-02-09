package alan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"time"
)

// Lock acquires a named distributed lock, blocking until acquired or context cancelled.
// If quorum is enabled, it waits for quorum before attempting to acquire the lock.
// Returns nil on success, ctx.Err() if context is cancelled.
func (a *Alan) Lock(ctx context.Context, key string) error {
	// Wait for quorum if enabled
	if err := a.waitForQuorum(ctx); err != nil {
		return err
	}

	for {
		// Try to acquire the lock
		acquired, waitCh := a.tryAcquireLock(ctx, key)
		if acquired {
			return nil
		}

		// Wait for lock release or context cancellation
		if waitCh != nil {
			select {
			case <-ctx.Done():
				// Remove ourselves from waiters
				a.removeWaiter(key, waitCh)
				return ctx.Err()
			case <-waitCh:
				// Lock was released, retry
				continue
			}
		}

		// No wait channel means context was cancelled during tryAcquireLock
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Small delay before retry to avoid tight loop
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// TryLock attempts to acquire a named distributed lock without blocking.
// Returns true if the lock was acquired, false otherwise.
// If quorum is enabled and not met, returns false.
func (a *Alan) TryLock(key string) bool {
	// Check quorum if enabled
	if !a.HasQuorum() {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
	defer cancel()

	acquired, _ := a.tryAcquireLock(ctx, key)
	return acquired
}

// Unlock releases a named distributed lock.
// Returns ErrLockNotHeld if this instance does not hold the lock.
func (a *Alan) Unlock(key string) error {
	a.locksMu.Lock()
	state, exists := a.locks[key]
	if !exists || state.holder != nil {
		// Lock doesn't exist or is held by another peer (not us)
		a.locksMu.Unlock()
		return ErrLockNotHeld
	}

	// We hold the lock (holder == nil means local), release it
	waiters := state.waiters
	delete(a.locks, key)
	a.locksMu.Unlock()

	// Notify local waiters
	for _, ch := range waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}

	// Broadcast release to all peers
	a.broadcastLockRelease(key)

	return nil
}

// tryAcquireLock attempts to acquire a lock.
// Returns (true, nil) if acquired.
// Returns (false, waitCh) if denied - caller should wait on waitCh for release notification.
// Returns (false, nil) if context was cancelled.
func (a *Alan) tryAcquireLock(ctx context.Context, key string) (bool, chan struct{}) {
	a.locksMu.Lock()

	// Check if lock already exists locally
	state, exists := a.locks[key]
	if exists {
		if state.holder == nil {
			// We already hold this lock
			a.locksMu.Unlock()
			return true, nil
		}
		// Another peer holds it, add ourselves as waiter
		waitCh := make(chan struct{}, 1)
		state.waiters = append(state.waiters, waitCh)
		a.locksMu.Unlock()
		return false, waitCh
	}

	// Lock doesn't exist locally, need to request from peers
	a.locksMu.Unlock()

	peers := a.peers.list()
	if len(peers) == 0 {
		// No peers, acquire locally
		a.locksMu.Lock()
		// Double-check no one else created it
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

	// Register pending lock request
	reqKey := hex.EncodeToString(requestID)
	pending := &pendingLock{
		grantCh: make(chan *net.UDPAddr, len(peers)),
		denyCh:  make(chan *net.UDPAddr, len(peers)),
	}
	a.pendingLocksMu.Lock()
	a.pendingLocks[reqKey] = pending
	a.pendingLocksMu.Unlock()

	defer func() {
		a.pendingLocksMu.Lock()
		delete(a.pendingLocks, reqKey)
		a.pendingLocksMu.Unlock()
	}()

	// Broadcast lock request
	a.broadcastLockRequest(requestID, key)

	// Wait for responses from all peers
	grants := 0
	needed := len(peers)

	for grants < needed {
		select {
		case <-ctx.Done():
			return false, nil
		case <-pending.grantCh:
			grants++
		case <-pending.denyCh:
			// Someone denied, we need to wait for release
			a.locksMu.Lock()
			state, exists := a.locks[key]
			if !exists {
				// Create state to track the remote holder
				state = &lockState{holder: nil, waiters: nil} // holder will be set when we get the response
				a.locks[key] = state
			}
			waitCh := make(chan struct{}, 1)
			state.waiters = append(state.waiters, waitCh)
			a.locksMu.Unlock()
			return false, waitCh
		}
	}

	// All peers granted, acquire locally
	a.locksMu.Lock()
	// Check if someone else got it while we were waiting
	if state, exists := a.locks[key]; exists && state.holder == nil {
		// We already hold it (shouldn't happen but handle it)
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

// broadcastLockRequest sends a lock request to all peers
func (a *Alan) broadcastLockRequest(requestID []byte, key string) {
	msg := encodeLockMessage(MsgTypeLockRequest, requestID, key)
	processed, err := a.processOutgoing(msg)
	if err != nil {
		return
	}

	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()

	for _, peer := range a.peers.list() {
		conn.WriteToUDP(processed, peer)
	}
}

// broadcastLockRelease sends a lock release notification to all peers
func (a *Alan) broadcastLockRelease(key string) {
	// Use a zero request ID for release notifications
	requestID := make([]byte, RequestIDSize)
	msg := encodeLockMessage(MsgTypeLockRelease, requestID, key)
	processed, err := a.processOutgoing(msg)
	if err != nil {
		return
	}

	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()

	for _, peer := range a.peers.list() {
		conn.WriteToUDP(processed, peer)
	}
}

// sendLockResponse sends a lock grant or deny response to a peer
func (a *Alan) sendLockResponse(msgType byte, requestID []byte, key string, addr *net.UDPAddr) {
	msg := encodeLockResponseMessage(msgType, requestID, key)
	processed, err := a.processOutgoing(msg)
	if err != nil {
		return
	}

	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()

	conn.WriteToUDP(processed, addr)
}

// releaseLocksHeldBy releases all locks held by a specific peer (called on peer leave)
func (a *Alan) releaseLocksHeldBy(addr *net.UDPAddr) {
	a.locksMu.Lock()
	defer a.locksMu.Unlock()

	peerKey := addr.String()
	for key, state := range a.locks {
		if state.holder != nil && state.holder.String() == peerKey {
			// This peer held the lock, release it
			waiters := state.waiters
			delete(a.locks, key)

			// Notify waiters
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
		// Lock is free, grant it and record the holder
		a.locks[key] = &lockState{holder: sourceAddr, waiters: nil}
		a.sendLockResponse(MsgTypeLockGrant, requestID, key, sourceAddr)
		return
	}

	if state.holder == nil {
		// We hold the lock locally, deny
		a.sendLockResponse(MsgTypeLockDeny, requestID, key, sourceAddr)
		return
	}

	// Another peer holds it, deny
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

	// Record that this peer holds the lock
	a.locksMu.Lock()
	state, exists := a.locks[key]
	if !exists {
		state = &lockState{holder: sourceAddr, waiters: nil}
		a.locks[key] = state
	} else if state.holder == nil {
		// We thought we had it but someone else does? Shouldn't happen.
		// Update holder to be safe
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

	// Only release if this peer was the holder
	if state.holder != nil && state.holder.String() == sourceAddr.String() {
		waiters := state.waiters
		delete(a.locks, key)
		a.locksMu.Unlock()

		// Notify waiters
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
