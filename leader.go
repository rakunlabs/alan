package alan

import (
	"context"
	"time"
)

// RunAsLeader acquires the named distributed lock, invokes fn while holding it,
// and releases the lock when fn returns or ctx is cancelled.
//
// If the lock cannot be acquired (context cancelled, quorum not met, etc.),
// fn is never called and the acquisition error is returned.
// Otherwise, returns whatever fn returns.
//
// Step-down on quorum loss: while fn is running, RunAsLeader watches the
// cluster for quorum loss (e.g. enough peers leaving that PeerCount drops
// below QuorumSize). If quorum is lost, the ctx passed to fn is cancelled
// so fn can shut down gracefully; the lock is then released. fn observes
// this as a normal ctx cancellation. Combined with LeaderLoop, this gives
// automatic re-election once quorum returns.
//
// This is a convenience wrapper around Lock/Unlock for the common
// "leader-only long-running task" pattern. Typical usage:
//
//	err := a.RunAsLeader(ctx, "scheduler", func(ctx context.Context) error {
//	    if err := scheduler.Start(ctx); err != nil {
//	        return err
//	    }
//	    defer scheduler.Stop()
//	    <-ctx.Done() // hold leadership until shutdown OR quorum loss
//	    return ctx.Err()
//	})
//
// Non-leader instances block inside Lock() until the current leader releases
// (by calling Unlock, exiting fn, or being detected as disconnected via
// heartbeat timeout).
func (a *Alan) RunAsLeader(ctx context.Context, key string,
	fn func(ctx context.Context) error) error {

	if err := a.Lock(ctx, key); err != nil {
		return err
	}

	// fnCtx is cancelled either when ctx is cancelled or when the
	// step-down monitor detects quorum loss. fn observes either as a
	// normal ctx cancellation.
	fnCtx, fnCancel := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	go a.leaderQuorumMonitor(fnCtx, fnCancel, monitorDone)

	defer func() {
		// Stop the monitor and wait for it to finish before tearing
		// down the lock state.
		fnCancel()
		<-monitorDone

		// Use a fresh short-lived context for Unlock so a cancelled ctx
		// (the typical reason fn returned) doesn't abort the release broadcast.
		releaseCtx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
		defer cancel()

		a.setLeader(key, false)
		_ = a.Unlock(releaseCtx, key)
	}()

	a.setLeader(key, true)
	return fn(fnCtx)
}

// leaderQuorumMonitor polls HasQuorum on a tick and cancels the leader's
// ctx if quorum is lost. The monitor exits as soon as fnCtx is done. The
// poll interval is HeartbeatInterval (clamped to a sensible range), since
// quorum can only change as fast as the underlying peer-event stream.
func (a *Alan) leaderQuorumMonitor(fnCtx context.Context, fnCancel context.CancelFunc, done chan struct{}) {
	defer close(done)

	interval := min(max(a.config.HeartbeatInterval, 200*time.Millisecond), 5*time.Second)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-fnCtx.Done():
			return
		case <-ticker.C:
			if !a.HasQuorum() {
				fnCancel()
				return
			}
		}
	}
}

// LeaderLoop repeatedly attempts to become leader for the named lock and runs
// fn while holding it. If fn returns (with or without error) and ctx is not
// cancelled, the lock is released and the loop waits retryDelay before
// attempting to reacquire.
//
// The loop returns only when ctx is cancelled, and always returns ctx.Err().
// Errors from fn itself are discarded by this helper; if you need to observe
// them, use RunAsLeader directly or handle them inside fn (e.g. logging).
//
// If retryDelay is zero or negative, a default of 1 second is used.
//
// Use this when fn may exit unexpectedly (e.g. a cron runner crashing) but
// you still want the service to retain leader semantics across the cluster.
func (a *Alan) LeaderLoop(ctx context.Context, key string,
	retryDelay time.Duration,
	fn func(ctx context.Context) error) error {

	if retryDelay <= 0 {
		retryDelay = time.Second
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = a.RunAsLeader(ctx, key, fn)
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryDelay):
		}
	}
}

func (a *Alan) setLeader(key string, isLeader bool) {
	a.leaderMu.Lock()
	defer a.leaderMu.Unlock()

	if isLeader {
		a.leaders[key] = struct{}{}
	} else {
		delete(a.leaders, key)
	}
}

func (a *Alan) IsLeader(key string) bool {
	a.leaderMu.RLock()
	defer a.leaderMu.RUnlock()

	_, isLeader := a.leaders[key]
	return isLeader
}

// LeaderHealthy reports whether this instance currently holds leadership
// for key AND the cluster still has quorum. Use this in handlers that
// need to refuse work when the leader has been partitioned away from the
// majority — e.g. an HTTP endpoint that should return 503 if the local
// instance is "leader" only because peers became unreachable.
//
// RunAsLeader already cancels fn's ctx on quorum loss, so most users do
// not need to call this directly; it's provided for code paths that
// observe leader status from outside the fn closure (e.g. shared
// handlers registered before RunAsLeader is called).
func (a *Alan) LeaderHealthy(key string) bool {
	return a.IsLeader(key) && a.HasQuorum()
}
