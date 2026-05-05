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

// Lock acquires a named distributed lock, blocking until acquired or ctx is cancelled.
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

// TryLock attempts to acquire a named distributed lock without blocking on
// other holders. ctx caps how long peer-discovery / broadcast may take.
func (a *Alan) TryLock(ctx context.Context, key string) bool {
	if !a.HasQuorum() {
		return false
	}

	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), a.config.Timeout)
		defer cancel()
	}

	acquired, _ := a.tryAcquireLock(ctx, key)
	return acquired
}

// Unlock releases a named distributed lock and broadcasts the release. ctx caps
// how long the broadcast may take.
func (a *Alan) Unlock(ctx context.Context, key string) error {
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

	if ctx == nil {
		ctx = context.Background()
	}
	a.broadcastLockRelease(ctx, key)
	return nil
}

// tryAcquireLock attempts to acquire a lock and returns either acquired=true,
// or a waitCh on which the caller can block until the current holder releases.
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

	a.broadcastLockRequest(ctx, requestID, key)

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

func (a *Alan) broadcastLockRequest(ctx context.Context, requestID []byte, key string) {
	peerConns := a.peers.connAddrs()
	var wg sync.WaitGroup
	for _, pc := range peerConns {
		wg.Add(1)
		go func(addr *net.UDPAddr, conn *quic.Conn) {
			defer wg.Done()
			_ = a.sendLockMsg(ctx, conn, MsgTypeLockRequest, requestID, key)
		}(pc.Addr, pc.Conn)
	}
	wg.Wait()
}

func (a *Alan) broadcastLockRelease(ctx context.Context, key string) {
	requestID := make([]byte, RequestIDSize)
	peerConns := a.peers.connAddrs()
	var wg sync.WaitGroup
	for _, pc := range peerConns {
		wg.Add(1)
		go func(addr *net.UDPAddr, conn *quic.Conn) {
			defer wg.Done()
			_ = a.sendLockMsg(ctx, conn, MsgTypeLockRelease, requestID, key)
		}(pc.Addr, pc.Conn)
	}
	wg.Wait()
}

func (a *Alan) sendLockResponse(ctx context.Context, msgType byte, requestID []byte, key string, addr *net.UDPAddr) {
	conn, ok := a.peers.getConn(addr)
	if !ok {
		return
	}
	_ = a.sendLockMsg(ctx, conn, msgType, requestID, key)
}

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

func (a *Alan) handleLockRequest(requestID []byte, key string, sourceAddr *net.UDPAddr) {
	a.locksMu.Lock()
	defer a.locksMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
	defer cancel()

	state, exists := a.locks[key]
	if !exists {
		a.locks[key] = &lockState{holder: sourceAddr, waiters: nil}
		a.sendLockResponse(ctx, MsgTypeLockGrant, requestID, key, sourceAddr)
		return
	}
	if state.holder == nil {
		a.sendLockResponse(ctx, MsgTypeLockDeny, requestID, key, sourceAddr)
		return
	}
	a.sendLockResponse(ctx, MsgTypeLockDeny, requestID, key, sourceAddr)
}

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
