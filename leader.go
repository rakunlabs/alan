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
// This is a convenience wrapper around Lock/Unlock for the common
// "leader-only long-running task" pattern. Typical usage:
//
//	err := a.RunAsLeader(ctx, "scheduler", func(ctx context.Context) error {
//	    if err := scheduler.Start(ctx); err != nil {
//	        return err
//	    }
//	    defer scheduler.Stop()
//	    <-ctx.Done() // hold leadership until shutdown
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
	defer func() {
		// Use a fresh short-lived context for Unlock so a cancelled ctx
		// (the typical reason fn returned) doesn't abort the release broadcast.
		releaseCtx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
		defer cancel()
		_ = a.Unlock(releaseCtx, key)
	}()
	return fn(ctx)
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
