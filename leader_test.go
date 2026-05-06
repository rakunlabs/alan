package alan

import (
	"context"
	"errors"
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

	go a.Start(ctx)
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
	_ = a.Unlock(ctx, "job")
}

// TestRunAsLeader_FnError: fn's error is returned and the lock is still released.
func TestRunAsLeader_FnError(t *testing.T) {
	const testPort = 16102

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx)
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
	_ = a.Unlock(ctx, "job")
}

// TestRunAsLeader_CtxCancelBeforeAcquire: quorum never met -> Lock blocks on ctx.
func TestRunAsLeader_CtxCancelBeforeAcquire(t *testing.T) {
	const testPort = 16103

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 3})
	startCtx, startCancel := context.WithCancel(context.Background())
	defer startCancel()
	go a.Start(startCtx)
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
	go a.Start(ctx)
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
	_ = a.Unlock(ctx, "job")
}

// TestLeaderLoop_RestartsFn: fn exits quickly; loop re-runs it.
func TestLeaderLoop_RestartsFn(t *testing.T) {
	const testPort = 16106

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx)
	<-a.Ready()
	defer a.Stop()

	var calls atomic.Int32
	loopCtx, loopCancel := context.WithCancel(ctx)

	done := make(chan error, 1)
	go func() {
		done <- a.LeaderLoop(loopCtx, "job", 20*time.Millisecond,
			func(ctx context.Context) error {
				calls.Add(1)
				return nil
			})
	}()

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

// TestLeaderLoop_ExitsOnCtxCancelDuringFn
func TestLeaderLoop_ExitsOnCtxCancelDuringFn(t *testing.T) {
	const testPort = 16107

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx)
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

// TestLeaderLoop_ExitsOnCtxCancelDuringBackoff
func TestLeaderLoop_ExitsOnCtxCancelDuringBackoff(t *testing.T) {
	const testPort = 16108

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx)
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

	select {
	case <-firstRun:
	case <-time.After(2 * time.Second):
		t.Fatal("fn never ran")
	}
	time.Sleep(50 * time.Millisecond)
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

// TestRunAsLeader_NoQuorumAfterPeerLoss reproduces the case where a
// cluster is configured for 3 replicas but only 2 instances run. With
// Replicas=3, QuorumSize=1, so two instances form quorum and one can
// hold the lock. After the leader is killed, the survivor has 0 peers
// and quorum is no longer met — it must NOT take the lock for itself.
//
// Acquisition is serialised (a1 acquires first, then a2 enters Lock and
// blocks waiting on a1) to isolate the post-failure quorum behaviour
// from any concurrent-acquisition race.
func TestRunAsLeader_NoQuorumAfterPeerLoss(t *testing.T) {
	const port1 = 16110
	const port2 = 16111

	a1, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		Replicas:          3,
		HeartbeatInterval: 200 * time.Millisecond,
		HeartbeatTimeout:  1500 * time.Millisecond,
	})
	a2, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		Replicas:          3,
		HeartbeatInterval: 200 * time.Millisecond,
		HeartbeatTimeout:  1500 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	// a1 acquires the lock first.
	lockCtx, lockCancel := context.WithTimeout(ctx, 3*time.Second)
	defer lockCancel()
	if err := a1.Lock(lockCtx, "job"); err != nil {
		t.Fatalf("a1 failed to acquire lock: %v", err)
	}

	// a2 enters RunAsLeader and blocks waiting for a1.
	a2Ran := make(chan struct{}, 1)
	a2Done := make(chan error, 1)
	leaderCtx, leaderCancel := context.WithCancel(ctx)
	defer leaderCancel()
	go func() {
		a2Done <- a2.RunAsLeader(leaderCtx, "job", func(ctx context.Context) error {
			a2Ran <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		})
	}()

	// Confirm a2 is blocked (didn't acquire while a1 holds).
	select {
	case <-a2Ran:
		t.Fatal("a2 acquired lock while a1 still holds it")
	case <-time.After(300 * time.Millisecond):
	}

	// Kill a1. a2's wait channel fires; on the next Lock iteration it
	// has 0 peers and Replicas=3, so quorum is not met.
	a1.Stop()

	// a2 must NOT promote itself to leader.
	select {
	case <-a2Ran:
		t.Fatal("a2 became leader despite no quorum (0 peers, Replicas=3); lock incorrectly granted")
	case <-time.After(2 * time.Second):
		// Good: a2 is blocked waiting for quorum.
	}

	// Cleanup.
	leaderCancel()
	select {
	case <-a2Done:
	case <-time.After(2 * time.Second):
	}
	a2.Stop()
}

// TestRunAsLeader_3Peers_FailoverElectsNewLeader verifies the typical
// HA scenario: 3 instances, one is leader, the leader is killed, one
// of the survivors must promote itself promptly. Reproduces the
// "neither becomes leader, both waiting" bug where the lock state
// machine deadlocks after a leader failure with concurrent waiters.
func TestRunAsLeader_3Peers_FailoverElectsNewLeader(t *testing.T) {
	const port1 = 16130
	const port2 = 16131
	const port3 = 16132

	mk := func(port int) *Alan {
		a, err := New(Config{
			BindAddr:          "127.0.0.1",
			Port:              port,
			Replicas:          3,
			HeartbeatInterval: 200 * time.Millisecond,
			HeartbeatTimeout:  1500 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		return a
	}
	a1 := mk(port1)
	a2 := mk(port2)
	a3 := mk(port3)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx)
	go a2.Start(ctx)
	go a3.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()
	<-a3.Ready()

	// Wire up a full mesh.
	connectPeers(t, a1, a2)
	connectPeers(t, a1, a3)
	connectPeers(t, a2, a3)

	// Wait for all three to see 2 peers each.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a1.PeerCount() == 2 && a2.PeerCount() == 2 && a3.PeerCount() == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if a1.PeerCount() != 2 || a2.PeerCount() != 2 || a3.PeerCount() != 2 {
		t.Fatalf("mesh not formed: peer counts a1=%d a2=%d a3=%d",
			a1.PeerCount(), a2.PeerCount(), a3.PeerCount())
	}

	// All three race to become leader; one wins.
	leaderCtx, leaderCancel := context.WithCancel(ctx)
	defer leaderCancel()

	type winSig struct {
		who *Alan
	}
	wins := make(chan winSig, 3)
	dones := make(chan error, 3)
	for _, inst := range []*Alan{a1, a2, a3} {
		inst := inst
		go func() {
			dones <- inst.RunAsLeader(leaderCtx, "job", func(fnCtx context.Context) error {
				wins <- winSig{who: inst}
				<-fnCtx.Done()
				return fnCtx.Err()
			})
		}()
	}

	var leader *Alan
	select {
	case w := <-wins:
		leader = w.who
	case <-time.After(5 * time.Second):
		t.Fatal("no leader elected within 5s")
	}

	// Identify survivors.
	var survivors []*Alan
	for _, inst := range []*Alan{a1, a2, a3} {
		if inst != leader {
			survivors = append(survivors, inst)
		}
	}

	// Kill the leader. Quorum (1 peer required for Replicas=3) is still
	// satisfied for the survivors, so one of them must take over.
	leader.Stop()

	select {
	case w := <-wins:
		if w.who == leader {
			t.Fatal("dead leader's fn re-fired")
		}
		// Got new leader.
	case <-time.After(5 * time.Second):
		t.Fatalf("no failover within 5s after killing leader; survivors a=%s b=%s peers=%d,%d",
			survivors[0].LocalAddr(), survivors[1].LocalAddr(),
			survivors[0].PeerCount(), survivors[1].PeerCount())
	}

	leaderCancel()
	// Drain. Best-effort; tests cleanup explicitly via Stop below.
	for i := 0; i < 3; i++ {
		select {
		case <-dones:
		case <-time.After(2 * time.Second):
		}
	}
	a1.Stop()
	a2.Stop()
	a3.Stop()
}

// TestRunAsLeader_StepsDownOnQuorumLoss verifies that when a leader
// loses quorum (peers disconnect), RunAsLeader cancels the fn ctx so
// the leader gracefully steps down instead of continuing to act on a
// minority partition.
func TestRunAsLeader_StepsDownOnQuorumLoss(t *testing.T) {
	const port1 = 16120
	const port2 = 16121

	a1, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port1,
		Replicas:          3,
		HeartbeatInterval: 200 * time.Millisecond,
		HeartbeatTimeout:  1500 * time.Millisecond,
	})
	a2, _ := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2,
		Replicas:          3,
		HeartbeatInterval: 200 * time.Millisecond,
		HeartbeatTimeout:  1500 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	// a1 becomes leader and sits in fn waiting on ctx.
	leaderCtx, leaderCancel := context.WithCancel(ctx)
	defer leaderCancel()

	fnRunning := make(chan struct{}, 1)
	fnExited := make(chan error, 1)
	go func() {
		fnExited <- a1.RunAsLeader(leaderCtx, "job", func(fnCtx context.Context) error {
			fnRunning <- struct{}{}
			<-fnCtx.Done()
			return fnCtx.Err()
		})
	}()

	select {
	case <-fnRunning:
	case <-time.After(3 * time.Second):
		t.Fatal("a1 never became leader")
	}

	if !a1.LeaderHealthy("job") {
		t.Fatal("expected LeaderHealthy=true while quorum is met")
	}

	// Tear down a2 so a1 loses quorum (Replicas=3, PeerCount drops to 0).
	a2.Stop()

	// fn ctx must be cancelled by the step-down monitor and fn must
	// observe ctx.Err(). Allow time for one HeartbeatInterval +
	// graceful-leave latency.
	select {
	case err := <-fnExited:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("fn returned %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunAsLeader did not step down on quorum loss within 3s")
	}

	if a1.LeaderHealthy("job") {
		t.Error("expected LeaderHealthy=false after step-down")
	}

	a1.Stop()
}

// TestLeaderLoop_DefaultRetryDelay: retryDelay=0 uses default (1s), does not busy-spin.
func TestLeaderLoop_DefaultRetryDelay(t *testing.T) {
	const testPort = 16109

	a, _ := New(Config{BindAddr: "127.0.0.1", Port: testPort, Replicas: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Start(ctx)
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

	time.Sleep(500 * time.Millisecond)
	loopCancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("LeaderLoop did not exit")
	}

	if got := calls.Load(); got > 2 {
		t.Fatalf("fn called %d times in 500ms with default retryDelay; expected <= 2", got)
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("fn called %d times; expected at least 1", got)
	}
}
