package alan

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestRunAsLeader_HappyPath: single instance, no peers, fn runs once and lock is released.
func TestRunAsLeader_HappyPath(t *testing.T) {
	const testPort = 16101

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a.Ready()
	defer a.Stop()

	var called atomic.Int32
	runCtx, runCancel := context.WithTimeout(ctx, 2*time.Second)
	defer runCancel()

	err := a.RunAsLeader(runCtx, "job", func(ctx context.Context) error {
		called.Add(1)
		return nil
	})
	if err != nil {
		t.Fatalf("RunAsLeader returned error: %v", err)
	}
	if got := called.Load(); got != 1 {
		t.Fatalf("fn called %d times, want 1", got)
	}

	// Lock should have been released; we can acquire again immediately.
	lockCtx, lockCancel := context.WithTimeout(ctx, time.Second)
	defer lockCancel()
	if err := a.Lock(lockCtx, "job"); err != nil {
		t.Fatalf("could not reacquire lock after RunAsLeader returned: %v", err)
	}
	_ = a.Unlock("job")
}

// TestRunAsLeader_FnError: fn's error is returned and the lock is still released.
func TestRunAsLeader_FnError(t *testing.T) {
	const testPort = 16102

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a.Ready()
	defer a.Stop()

	sentinel := errors.New("fn failed")
	err := a.RunAsLeader(ctx, "job", func(ctx context.Context) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}

	// Lock must be released despite fn error.
	lockCtx, lockCancel := context.WithTimeout(ctx, time.Second)
	defer lockCancel()
	if err := a.Lock(lockCtx, "job"); err != nil {
		t.Fatalf("lock not released after fn error: %v", err)
	}
	_ = a.Unlock("job")
}

// TestRunAsLeader_CtxCancelBeforeAcquire: when Lock() cannot be acquired
// (quorum not met + ctx cancelled), fn is never called and ctx.Err() is
// returned.
func TestRunAsLeader_CtxCancelBeforeAcquire(t *testing.T) {
	const testPort = 16103

	// Replicas=3 with no peers -> quorum never met -> Lock blocks on ctx.
	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 3})
	startCtx, startCancel := context.WithCancel(context.Background())
	defer startCancel()
	go a.Start(startCtx, func(ctx context.Context, msg Message) {})
	<-a.Ready()
	defer a.Stop()

	ctx, cancel := context.WithTimeout(startCtx, 100*time.Millisecond)
	defer cancel()

	var called atomic.Int32
	err := a.RunAsLeader(ctx, "job", func(ctx context.Context) error {
		called.Add(1)
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if got := called.Load(); got != 0 {
		t.Fatalf("fn called %d times; expected 0", got)
	}
}

// TestRunAsLeader_CtxCancelDuringFn: fn waits on ctx; cancel; verify clean exit and lock released.
func TestRunAsLeader_CtxCancelDuringFn(t *testing.T) {
	const testPort = 16104

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a.Ready()
	defer a.Stop()

	fnCtx, fnCancel := context.WithCancel(ctx)

	done := make(chan error, 1)
	go func() {
		done <- a.RunAsLeader(fnCtx, "job", func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		})
	}()

	// Give the goroutine time to acquire.
	time.Sleep(100 * time.Millisecond)
	fnCancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunAsLeader did not return after ctx cancel")
	}

	// Lock must be released.
	lockCtx, lockCancel := context.WithTimeout(ctx, time.Second)
	defer lockCancel()
	if err := a.Lock(lockCtx, "job"); err != nil {
		t.Fatalf("lock not released after ctx cancel: %v", err)
	}
	_ = a.Unlock("job")
}

// TestRunAsLeader_MutualExclusion: two instances; second waits until first's fn exits.
func TestRunAsLeader_MutualExclusion(t *testing.T) {
	const testPort = 16105

	a1, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	a2, _ := New(Config{BindAddr: "127.0.0.2", Port: testPort, Replicas: 0})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx, func(ctx context.Context, msg Message) {})
	go a2.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a1.Ready()
	<-a2.Ready()
	defer a1.Stop()
	defer a2.Stop()

	// Connect peers.
	a1.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: testPort})
	a2.peers.add(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testPort})

	var (
		a1Entered atomic.Bool
		a1Exited  atomic.Bool
		a2Entered atomic.Bool
	)

	// a1 holds the lock for 300ms.
	a1Done := make(chan struct{})
	go func() {
		defer close(a1Done)
		_ = a1.RunAsLeader(ctx, "leader", func(ctx context.Context) error {
			a1Entered.Store(true)
			time.Sleep(300 * time.Millisecond)
			a1Exited.Store(true)
			return nil
		})
	}()

	// Ensure a1 has entered before a2 starts.
	for i := 0; i < 100 && !a1Entered.Load(); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !a1Entered.Load() {
		t.Fatal("a1 did not enter fn in time")
	}

	// a2 tries to acquire while a1 is running.
	a2Done := make(chan error, 1)
	go func() {
		a2Done <- a2.RunAsLeader(ctx, "leader", func(ctx context.Context) error {
			a2Entered.Store(true)
			// Must only enter after a1 exited.
			if !a1Exited.Load() {
				t.Errorf("a2 entered fn before a1 exited")
			}
			return nil
		})
	}()

	// a2 must not have entered while a1 is running.
	time.Sleep(100 * time.Millisecond)
	if a2Entered.Load() {
		t.Fatal("a2 entered fn while a1 was still holding the lock")
	}

	<-a1Done

	select {
	case err := <-a2Done:
		if err != nil {
			t.Fatalf("a2 RunAsLeader returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a2 did not acquire lock after a1 released")
	}
	if !a2Entered.Load() {
		t.Fatal("a2 did not enter fn")
	}
}

// TestLeaderLoop_RestartsFn: fn exits quickly; loop re-runs it.
func TestLeaderLoop_RestartsFn(t *testing.T) {
	const testPort = 16106

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a.Ready()
	defer a.Stop()

	var calls atomic.Int32
	loopCtx, loopCancel := context.WithCancel(ctx)

	done := make(chan error, 1)
	go func() {
		done <- a.LeaderLoop(loopCtx, "job", 20*time.Millisecond,
			func(ctx context.Context) error {
				calls.Add(1)
				return nil // exit quickly
			})
	}()

	// Allow the loop to run several iterations.
	time.Sleep(200 * time.Millisecond)
	loopCancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LeaderLoop did not exit")
	}

	if got := calls.Load(); got < 2 {
		t.Fatalf("fn called %d times; expected at least 2 restarts", got)
	}
}

// TestLeaderLoop_ExitsOnCtxCancelDuringFn: cancel while fn is blocked on ctx -> single call, ctx.Err().
func TestLeaderLoop_ExitsOnCtxCancelDuringFn(t *testing.T) {
	const testPort = 16107

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a.Ready()
	defer a.Stop()

	var calls atomic.Int32
	loopCtx, loopCancel := context.WithCancel(ctx)

	done := make(chan error, 1)
	go func() {
		done <- a.LeaderLoop(loopCtx, "job", 50*time.Millisecond,
			func(ctx context.Context) error {
				calls.Add(1)
				<-ctx.Done()
				return ctx.Err()
			})
	}()

	time.Sleep(100 * time.Millisecond)
	loopCancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LeaderLoop did not exit")
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("fn called %d times; expected exactly 1", got)
	}
}

// TestLeaderLoop_ExitsOnCtxCancelDuringBackoff: cancel between runs -> loop exits.
func TestLeaderLoop_ExitsOnCtxCancelDuringBackoff(t *testing.T) {
	const testPort = 16108

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a.Ready()
	defer a.Stop()

	loopCtx, loopCancel := context.WithCancel(ctx)

	firstRun := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- a.LeaderLoop(loopCtx, "job", 500*time.Millisecond,
			func(ctx context.Context) error {
				select {
				case firstRun <- struct{}{}:
				default:
				}
				return nil
			})
	}()

	// Wait for first invocation, then cancel during the long backoff.
	select {
	case <-firstRun:
	case <-time.After(2 * time.Second):
		t.Fatal("fn never ran")
	}
	time.Sleep(50 * time.Millisecond) // ensure we're inside the backoff select
	loopCancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LeaderLoop did not exit during backoff")
	}
}

// TestLeaderLoop_DefaultRetryDelay: retryDelay=0 uses default (1s), does not busy-spin.
func TestLeaderLoop_DefaultRetryDelay(t *testing.T) {
	const testPort = 16109

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx, func(ctx context.Context, msg Message) {})
	<-a.Ready()
	defer a.Stop()

	var calls atomic.Int32
	loopCtx, loopCancel := context.WithCancel(ctx)

	done := make(chan error, 1)
	go func() {
		done <- a.LeaderLoop(loopCtx, "job", 0,
			func(ctx context.Context) error {
				calls.Add(1)
				return nil
			})
	}()

	// Within 500ms and a 1s default backoff, we expect at most 2 calls
	// (one immediately, possibly one more if timing is weird). Definitely
	// not a tight spin.
	time.Sleep(500 * time.Millisecond)
	loopCancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("LeaderLoop did not exit")
	}

	if got := calls.Load(); got > 2 {
		t.Fatalf("fn called %d times in 500ms with default retryDelay; expected <= 2 (not busy-spinning)", got)
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("fn called %d times; expected at least 1", got)
	}
}
