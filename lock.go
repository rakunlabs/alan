package alan

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Lock acquires a named distributed lock, blocking until acquired or ctx is cancelled.
//
// Quorum is enforced on every retry, not just on entry: if the cluster
// loses quorum (e.g. enough peers leave to drop PeerCount below
// QuorumSize), Lock will block waiting for peers to return rather than
// granting the lock to a partition that lacks majority.
func (a *Alan) Lock(ctx context.Context, key string) error {
	for {
		// Re-check quorum on every iteration. Without this, a survivor
		// that was waiting on a holder which then disconnected would
		// re-enter tryAcquireLock with zero peers and silently grant
		// itself the lock — defeating the Replicas guard.
		if err := a.waitForQuorum(ctx); err != nil {
			return err
		}

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
	// Capture the requestID under which we acquired this lock so the
	// outgoing Release frames can be tagged with it. Receivers compare
	// against state.holderID and ignore any Release whose id does not
	// match — this is what prevents a stale abort-Release from clobbering
	// a freshly-granted HeldBy entry on the receiver. See
	// tla/LockSpecFIFO.tla for the model.
	releaseID := state.holderID
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
	a.broadcastLockRelease(ctx, releaseID, key)
	return nil
}

// tryAcquireLock attempts to acquire a lock and returns either acquired=true,
// or a waitCh on which the caller can block until the current holder releases.
//
// When multiple peers race for the same fresh lock, ties are broken by
// lexicographic comparison of the random requestID: the lower requestID
// wins. This is symmetric and deterministic — both sides of any pair
// reach the same conclusion without further coordination.
//
// To close the race window between "I broadcast my request" and
// "competing request arrives", the local lock state is marked with the
// outgoing requestID *before* the broadcast. Subsequent incoming
// requests on this peer can then tie-break against our pending ID even
// if they arrive faster than we can register grant handlers.
func (a *Alan) tryAcquireLock(ctx context.Context, key string) (bool, chan struct{}) {
	// Best-effort wait for full peer membership before deciding to
	// acquire. Closes the partial-visibility startup race captured by
	// tla/LockSpecFIFO_PartialVisibility: a peer that meets quorum-
	// as-majority via a single fellow survivor (without ever having
	// handshaken with the actual lock holder) could otherwise be
	// granted the lock by the survivor alone, producing two
	// simultaneous holders. Waiting for full membership lets the
	// missing handshake complete; if it never does (a peer is genuinely
	// dead) we fall back to the bounded-quorum behaviour so failover
	// still works.
	a.waitForFullMembership(ctx)

	a.locksMu.Lock()

	if state, exists := a.locks[key]; exists {
		if state.holder == nil && state.pending == nil {
			// We already self-hold this lock locally.
			a.locksMu.Unlock()
			return true, nil
		}
		// Either remotely held, or we have an in-flight acquisition
		// from another caller. Park as a waiter.
		waitCh := make(chan struct{}, 1)
		state.waiters = append(state.waiters, waitCh)
		a.locksMu.Unlock()
		return false, waitCh
	}

	requestID := make([]byte, RequestIDSize)
	if _, err := rand.Read(requestID); err != nil {
		a.locksMu.Unlock()
		return false, nil
	}

	peerConns := a.peers.connAddrs()
	if len(peerConns) == 0 {
		// No peers to ask. Only grant the lock locally if quorum allows
		// it — otherwise we would create a split-brain leader that holds
		// a lock no other replica acknowledges. With Replicas=0 the
		// instance is standalone and HasQuorum is always true.
		if !a.HasQuorum() {
			a.locksMu.Unlock()
			return false, nil
		}
		// Self-grant. Record requestID as the acquireID even though no
		// peer will Release it; if a peer joins later and we Unlock,
		// the outbound Release carries this id.
		a.locks[key] = &lockState{holder: nil, holderID: requestID, waiters: nil}
		a.locksMu.Unlock()
		return true, nil
	}

	// Publish our intent to the local lock state map BEFORE broadcasting,
	// so any concurrent peer request that arrives sees our pending
	// requestID and applies the tie-break correctly.
	a.locks[key] = &lockState{holder: nil, pending: requestID, waiters: nil}
	a.locksMu.Unlock()

	reqKey := hex.EncodeToString(requestID)
	pending := &pendingLock{
		requestID: requestID,
		key:       key,
		peerLeft:  make(chan *net.UDPAddr, len(peerConns)),
		grantCh:   make(chan *net.UDPAddr, len(peerConns)),
		denyCh:    make(chan *net.UDPAddr, len(peerConns)),
		preempted: make(chan struct{}, 1),
	}
	a.pendingLocksMu.Lock()
	a.pendingLocks[reqKey] = pending
	a.pendingLocksMu.Unlock()

	// Cleanup helper: removes our pending state. If acquired, transitions
	// to self-held and stamps holderID with the requestID we won under,
	// so a later Unlock can broadcast a Release tagged with that id.
	// Otherwise, drops the pending marker so other callers or remote
	// requests see a clean slate.
	cleanup := func(acquired bool) {
		a.pendingLocksMu.Lock()
		delete(a.pendingLocks, reqKey)
		a.pendingLocksMu.Unlock()

		a.locksMu.Lock()
		if state, exists := a.locks[key]; exists {
			// If we were preempted, holder may already be set by
			// handleLockRequest; don't clobber it.
			if state.holder == nil && bytes.Equal(state.pending, requestID) {
				if acquired {
					state.pending = nil
					state.holderID = requestID
				} else {
					delete(a.locks, key)
				}
			}
		}
		a.locksMu.Unlock()
	}

	a.broadcastLockRequest(ctx, requestID, key)

	grants := 0
	// Track peers we still expect a response from. A peer disconnect
	// drops the corresponding "needed" slot so the acquisition does
	// not block forever waiting on a dead peer.
	expecting := make(map[string]struct{}, len(peerConns))
	for _, pc := range peerConns {
		expecting[pc.Addr.String()] = struct{}{}
	}
	needed := len(expecting)

	// On abort, we must broadcast a Release to every peer. This is
	// because peers may have set holder = us locally even without
	// sending us an explicit grant — specifically, when their own
	// concurrent acquisition was preempted by ours, they store
	// holder = us speculatively. If we don't tell them we're aborting,
	// they'll be stuck thinking we hold the lock and refuse all
	// subsequent acquisitions.
	abort := func() {
		cleanup(false)
		// Best-effort: release on every peer so any speculative
		// holder = us state is cleared cluster-wide. Tag the Release
		// with our pending requestID — receivers compare against the
		// holderID they recorded on grant; if they have already
		// granted us under this id, the Release matches and clears
		// HeldBy(us). If they have since granted a different
		// acquisition (different requestID), the Release id will not
		// match and they harmlessly drop it.
		releaseCtx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
		defer cancel()
		a.broadcastLockRelease(releaseCtx, requestID, key)
	}

	for grants < needed {
		select {
		case <-ctx.Done():
			abort()
			return false, nil
		case <-pending.preempted:
			abort()
			return false, nil
		case grantor := <-pending.grantCh:
			if grantor != nil {
				delete(expecting, grantor.String())
			}
			grants++
		case <-pending.denyCh:
			abort()
			return false, nil
		case dead := <-pending.peerLeft:
			if dead == nil {
				continue
			}
			if _, ok := expecting[dead.String()]; ok {
				delete(expecting, dead.String())
				needed--
			}
		}
	}

	cleanup(true)
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
			_ = a.sendLockMsg(ctx, addr, conn, MsgTypeLockRequest, requestID, key)
		}(pc.Addr, pc.Conn)
	}
	wg.Wait()
}

// broadcastLockRelease sends a LockRelease tagged with the requestID that
// established the holder entry on receivers. Stale releases (from a
// previous abort, in-flight when the peer re-acquires) carry the old
// requestID and are dropped by handleLockRelease's id check.
func (a *Alan) broadcastLockRelease(ctx context.Context, requestID []byte, key string) {
	if len(requestID) != RequestIDSize {
		// Defensive: an empty requestID would clear any current holder
		// regardless of which acquisition is being released. Refuse.
		return
	}
	peerConns := a.peers.connAddrs()
	var wg sync.WaitGroup
	for _, pc := range peerConns {
		wg.Add(1)
		go func(addr *net.UDPAddr, conn *quic.Conn) {
			defer wg.Done()
			_ = a.sendLockMsg(ctx, addr, conn, MsgTypeLockRelease, requestID, key)
		}(pc.Addr, pc.Conn)
	}
	wg.Wait()
}

func (a *Alan) sendLockResponse(ctx context.Context, msgType byte, requestID []byte, key string, addr *net.UDPAddr) {
	conn, ok := a.peers.getConn(addr)
	if !ok {
		return
	}
	_ = a.sendLockMsg(ctx, addr, conn, msgType, requestID, key)
}

// releaseLocksHeldBy releases any locks the departing peer held and
// notifies any in-flight local acquisitions that the peer disconnected
// so they can drop it from their grant-counting set. Safe to call
// multiple times for the same peer (idempotent).
func (a *Alan) releaseLocksHeldBy(addr *net.UDPAddr) {
	a.locksMu.Lock()
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
	a.locksMu.Unlock()

	// Notify any in-flight pending acquisitions that this peer is gone
	// so they can drop it from their needed-grants tally.
	a.pendingLocksMu.Lock()
	pendings := make([]*pendingLock, 0, len(a.pendingLocks))
	for _, p := range a.pendingLocks {
		pendings = append(pendings, p)
	}
	a.pendingLocksMu.Unlock()
	for _, p := range pendings {
		select {
		case p.peerLeft <- addr:
		default:
		}
	}
}

// handleLockRequest is called when a peer asks us for a lock.
//
// Decision matrix on the local lockState for key:
//
//   - state == nil (no entry): grant; record sourceAddr as holder.
//   - state.holder != nil: held by someone (possibly the requester
//     re-asking). Deny.
//   - state.holder == nil && state.pending == nil: we self-hold the
//     lock. Deny.
//   - state.holder == nil && state.pending != nil: in-flight local
//     acquisition. Tie-break by lexicographic comparison of requestIDs:
//     the lower requestID wins. If incoming wins, grant it and
//     preempt our own acquisition (it will retry). If we win, deny.
//
// Tie-break is symmetric: both peers running the same comparison reach
// the same conclusion, so no split-brain is possible from a concurrent
// fresh-acquire race.
func (a *Alan) handleLockRequest(requestID []byte, key string, sourceAddr *net.UDPAddr) {
	ctx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
	defer cancel()

	a.locksMu.Lock()
	state, exists := a.locks[key]
	if !exists {
		// Unowned, no local pending: grant. Record the requester's
		// requestID as holderID so a later Release tagged with the
		// same id matches and clears the entry; releases tagged with
		// any other id are dropped.
		a.locks[key] = &lockState{holder: sourceAddr, holderID: requestID, waiters: nil}
		a.locksMu.Unlock()
		a.sendLockResponse(ctx, MsgTypeLockGrant, requestID, key, sourceAddr)
		return
	}

	if state.holder != nil {
		// Held by some peer (possibly the requester); deny.
		a.locksMu.Unlock()
		a.sendLockResponse(ctx, MsgTypeLockDeny, requestID, key, sourceAddr)
		return
	}

	// holder == nil. Either we self-hold or we have an in-flight
	// acquisition.
	if state.pending == nil {
		// Self-held. Deny.
		a.locksMu.Unlock()
		a.sendLockResponse(ctx, MsgTypeLockDeny, requestID, key, sourceAddr)
		return
	}

	// In-flight local acquisition. Tie-break: lower requestID wins.
	if bytes.Compare(requestID, state.pending) < 0 {
		// Incoming wins. Hand the lock to the source and preempt our
		// own pending acquisition. The local acquisition goroutine
		// will observe `preempted` and retry; its cleanup will see
		// holder != nil and skip clobbering.
		myPending := state.pending
		a.locks[key] = &lockState{
			holder:   sourceAddr,
			holderID: requestID,
			waiters:  state.waiters,
		}
		a.locksMu.Unlock()

		// Signal preemption to the in-flight pending so it gives up.
		a.signalPreempted(myPending)

		a.sendLockResponse(ctx, MsgTypeLockGrant, requestID, key, sourceAddr)
		return
	}

	// We win; deny the incoming request. The peer will retry once we
	// either acquire (and later release) or are denied ourselves.
	a.locksMu.Unlock()
	a.sendLockResponse(ctx, MsgTypeLockDeny, requestID, key, sourceAddr)
}

// signalPreempted notifies the in-flight pendingLock for the given
// requestID that it has been preempted by a winning competing request.
func (a *Alan) signalPreempted(requestID []byte) {
	if len(requestID) == 0 {
		return
	}
	reqKey := hex.EncodeToString(requestID)
	a.pendingLocksMu.Lock()
	pending, ok := a.pendingLocks[reqKey]
	a.pendingLocksMu.Unlock()
	if !ok {
		return
	}
	select {
	case pending.preempted <- struct{}{}:
	default:
	}
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

func (a *Alan) handleLockDeny(requestID []byte, _ string, sourceAddr *net.UDPAddr) {
	reqKey := hex.EncodeToString(requestID)
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

// handleLockRelease processes an incoming LockRelease. Releases are
// matched by (sourceAddr, holderID): only a Release whose requestID
// equals the id under which the local HeldBy entry was established
// clears it. Releases bearing any other id are dropped. This guards
// against the stale-Release race that motivated tla/LockSpecFIFO.tla:
// a Release sent during an earlier abort can arrive AFTER a fresh
// acquisition grant; without the id check it would clobber the new
// holder.
func (a *Alan) handleLockRelease(requestID []byte, key string, sourceAddr *net.UDPAddr) {
	a.locksMu.Lock()
	state, exists := a.locks[key]
	if !exists {
		a.locksMu.Unlock()
		return
	}
	if state.holder == nil || state.holder.String() != sourceAddr.String() {
		// Not held by this peer — nothing to do.
		a.locksMu.Unlock()
		return
	}
	if !bytes.Equal(state.holderID, requestID) {
		// Stale Release from a previous acquisition by the same peer.
		// Drop it; the current HeldBy entry stays intact.
		a.locksMu.Unlock()
		return
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
}
