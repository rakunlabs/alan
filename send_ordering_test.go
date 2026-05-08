package alan

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// TestSendDispatchOrdering_SeqWrap verifies that the per-peer outbound
// sequence counter wraps cleanly from 2^64-1 back to 0 without losing
// any messages. The receiver compares seq numbers modularly, so a wrap
// is a no-op event for the in-order dispatch state.
//
// We cannot realistically emit 2^64 frames in a test (~584 years at
// 1 ns/frame), so we whitebox-poke the per-Peer outboundSeq to a value
// near the wrap point, send a handful of messages straddling the wrap,
// and assert they reach the handler in the correct order with no
// ErrSeqExhausted, no reconnect, and no leadership disruption.
func TestSendDispatchOrdering_SeqWrap(t *testing.T) {
	const port1 = 16210
	const port2 = 16211

	a1, a2, cleanup := startTestPair(t, port1, port2)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const total = 6
	var (
		mu       sync.Mutex
		received []string
	)
	allDone := make(chan struct{})

	a1.Handle("", func(_ context.Context, msg Message) {
		mu.Lock()
		received = append(received, string(msg.Data))
		if len(received) == total {
			close(allDone)
		}
		mu.Unlock()
	})

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}

	// Phase 1: two normal sends so the receiver locks onto the epoch.
	for _, m := range []string{"a", "b"} {
		if _, err := a2.SendTo(ctx, target, "", []byte(m)); err != nil {
			t.Fatalf("phase-1 SendTo %q: %v", m, err)
		}
	}

	// Wait for phase 1 to fully drain so the wrap test starts from a
	// settled receiver state (no in-flight pre-wrap frames lingering).
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		got := len(received)
		mu.Unlock()
		if got >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	if len(received) < 2 {
		mu.Unlock()
		t.Fatalf("phase 1 did not fully arrive: only %d/2", len(received))
	}
	mu.Unlock()

	// Whitebox: nudge BOTH the sender's outboundSeq and the receiver's
	// nextSeq just below the wrap point. In a real workload these two
	// counters track each other tightly (every wire frame increments
	// the sender, every dispatch increments the receiver), so to
	// faithfully simulate the wrap we have to keep them aligned. After
	// the poke the next four sends produce seq numbers
	// 2^64-2, 2^64-1, 0, 1, straddling the wrap.
	peer, ok := a2.peers.get(target)
	if !ok {
		t.Fatalf("a2 has no Peer record for %s", target)
	}
	preEpoch := peer.outboundEpoch.Load()
	// Set sender outboundSeq so the next Add(1) produces 2^64-2.
	peer.outboundSeq.Store(^uint64(0) - 2)

	a1.peers.mu.RLock()
	var pq *peerQueue
	for _, p := range a1.peers.items {
		pq = a1.getOrCreatePeerQueue(p.Addr)
		break
	}
	a1.peers.mu.RUnlock()
	if pq == nil {
		t.Fatalf("a1 has no registered peer for the test sender")
	}
	// Set receiver nextSeq so the first incoming frame (seq=2^64-2)
	// matches as in-order.
	pq.mu.Lock()
	pq.nextSeq = ^uint64(0) - 1
	pq.mu.Unlock()

	// Phase 2: four sends straddling the wrap.
	for _, m := range []string{"c", "d", "e", "f"} {
		if _, err := a2.SendTo(ctx, target, "", []byte(m)); err != nil {
			t.Fatalf("phase-2 SendTo %q: %v", m, err)
		}
	}

	postEpoch := peer.outboundEpoch.Load()
	if postEpoch != preEpoch {
		t.Errorf("outboundEpoch should not change on a seq wrap: pre=%d post=%d", preEpoch, postEpoch)
	}

	// The Peer record / connection must survive intact — wrapping the
	// seq counter is a no-op event, not a reconnect.
	peerAfter, ok := a2.peers.get(target)
	if !ok {
		t.Fatalf("Peer record gone — connection should not be torn down on seq wrap")
	}
	if peer != peerAfter {
		t.Fatalf("Peer record was replaced — implies reconnect, not a clean wrap")
	}

	select {
	case <-allDone:
	case <-time.After(10 * time.Second):
		mu.Lock()
		got := append([]string(nil), received...)
		mu.Unlock()
		t.Fatalf("timeout: only %d/%d received: %v", len(got), total, got)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"a", "b", "c", "d", "e", "f"}
	if len(received) != len(want) {
		t.Fatalf("got %d messages, want %d: %v", len(received), len(want), received)
	}
	for i, m := range received {
		if m != want[i] {
			t.Errorf("position %d: got %q want %q (full: %v)", i, m, want[i], received)
		}
	}
}

// errors imported for ErrNoPeerConnection in other tests.
var _ = errors.New

// TestSendDispatchOrdering_MixedSizes is a regression guard for the
// per-peer FIFO dispatch guarantee. It interleaves big (2 MiB) and
// tiny (8 B) messages from a2 to a1; before the sequence-number fix
// the small messages drained ahead of the large ones and arrived at
// the byte handler in swapped pairs (1, 0, 3, 2, 5, 4, …). With the
// fix the dispatch order must equal the send order.
func TestSendDispatchOrdering_MixedSizes(t *testing.T) {
	const port1 = 16201
	const port2 = 16202

	a1, a2, cleanup := startTestPair(t, port1, port2)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const N = 50

	var (
		mu       sync.Mutex
		received []int
	)
	done := make(chan struct{})

	a1.Handle("", func(_ context.Context, msg Message) {
		idx := int(msg.Data[0])<<8 | int(msg.Data[1])
		mu.Lock()
		received = append(received, idx)
		if len(received) == N {
			close(done)
		}
		mu.Unlock()
	})

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}

	for i := 0; i < N; i++ {
		var data []byte
		if i%2 == 0 {
			data = make([]byte, 2*1024*1024)
		} else {
			data = make([]byte, 8)
		}
		data[0] = byte(i >> 8)
		data[1] = byte(i & 0xff)
		if _, err := a2.SendTo(ctx, target, "", data); err != nil {
			t.Fatalf("SendTo[%d]: %v", i, err)
		}
	}

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("timeout: only %d/%d messages received", len(received), N)
	}

	mu.Lock()
	defer mu.Unlock()

	for i, got := range received {
		if got != i {
			t.Errorf("position %d: expected msg index %d, got %d (full order: %v)", i, i, got, received)
			return
		}
	}
}

// TestSendDispatchOrdering_ReconnectResetsEpoch verifies that when a
// sender goes away and a fresh Alan instance takes over (its
// outboundSeq starts at 1 again, with a fresh outboundEpoch), the
// receiver picks up the new connection epoch from frame headers, drops
// any half-buffered state from the old era, and resumes dispatch
// starting at seq=1 — without dropping the new messages as "replays"
// against its stale nextSeq.
//
// To model "different connection era" we use a fresh sender bound to
// a different port so a1 sees a brand-new peer record (and brand-new
// epoch) for the second batch.
func TestSendDispatchOrdering_ReconnectResetsEpoch(t *testing.T) {
	const port1 = 16205
	const port2a = 16206
	const port2b = 16209

	a1, a2a, cleanupA := startTestPair(t, port1, port2a)
	defer cleanupA()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const N = 20

	var (
		mu       sync.Mutex
		received []string
	)
	allDone := make(chan struct{})

	a1.Handle("", func(_ context.Context, msg Message) {
		mu.Lock()
		received = append(received, string(msg.Data))
		if len(received) == 2*N {
			close(allDone)
		}
		mu.Unlock()
	})

	go a1.Start(ctx)
	go a2a.Start(ctx)
	<-a1.Ready()
	<-a2a.Ready()

	connectPeers(t, a1, a2a)

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}

	for i := 0; i < N; i++ {
		payload := []byte("a:" + string(rune('A'+i)))
		if _, err := a2a.SendTo(ctx, target, "", payload); err != nil {
			t.Fatalf("a2a SendTo[%d]: %v", i, err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := len(received)
		mu.Unlock()
		if got >= N || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	if len(received) < N {
		t.Fatalf("first era: only %d/%d received", len(received), N)
	}
	mu.Unlock()

	a2a.Stop()

	a2b, err := New(Config{
		BindAddr:          "127.0.0.1",
		Port:              port2b,
		HeartbeatInterval: 1 * time.Second,
		HeartbeatTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new a2b: %v", err)
	}
	defer a2b.Stop()
	go a2b.Start(ctx)
	<-a2b.Ready()
	connectPeers(t, a1, a2b)

	for i := 0; i < N; i++ {
		payload := []byte("b:" + string(rune('A'+i)))
		if _, err := a2b.SendTo(ctx, target, "", payload); err != nil {
			t.Fatalf("a2b SendTo[%d]: %v", i, err)
		}
	}

	select {
	case <-allDone:
	case <-time.After(15 * time.Second):
		mu.Lock()
		got := len(received)
		mu.Unlock()
		t.Fatalf("timeout: only %d/%d received", got, 2*N)
	}

	mu.Lock()
	defer mu.Unlock()
	// Note: a1 sees these as messages from two different peers (different
	// addresses), so each peer has its own per-peer queue and ordering.
	// Verify each batch is in order within its own era. Since we have
	// only one handler appending to a single slice, and the two senders
	// stream concurrently after a2b connects, we can only assert that
	// the "a:" prefix messages appear in order among themselves and the
	// "b:" prefix messages appear in order among themselves.
	var aSeq, bSeq []string
	for _, m := range received {
		if len(m) >= 2 && m[0] == 'a' {
			aSeq = append(aSeq, m)
		} else if len(m) >= 2 && m[0] == 'b' {
			bSeq = append(bSeq, m)
		}
	}
	for i, m := range aSeq {
		want := "a:" + string(rune('A'+i))
		if m != want {
			t.Errorf("'a' era pos %d: got %q want %q (full a-seq: %v)", i, m, want, aSeq)
			break
		}
	}
	for i, m := range bSeq {
		want := "b:" + string(rune('A'+i))
		if m != want {
			t.Errorf("'b' era pos %d: got %q want %q (full b-seq: %v)", i, m, want, bSeq)
			break
		}
	}
}

// TestSendDispatchOrdering_ConcurrentSenders verifies that even when
// multiple goroutines on the sender call SendTo against the same peer
// concurrently, the receiver still sees a strict per-peer FIFO. This
// is a stronger property than the single-goroutine case: it relies on
// the per-peer outboundSeq counter being claimed under an atomic
// add BEFORE the QUIC stream is opened, so the seq order matches the
// "happens-before" order of the send calls — not the order in which
// QUIC happens to assign stream IDs (which may differ when multiple
// OpenStreamSync calls race).
//
// We do not assert a specific permutation (the goroutines race), only
// that the received sequence is monotonic per the per-peer seq stamps
// the framework chose. Because the framework hides seq from the
// handler, we instead assert that no two received indices are out of
// order relative to a stable per-sender numbering: each goroutine
// emits in increasing index order, so the receiver must see each
// goroutine's messages in increasing order.
func TestSendDispatchOrdering_ConcurrentSenders(t *testing.T) {
	const port1 = 16203
	const port2 = 16204

	a1, a2, cleanup := startTestPair(t, port1, port2)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const goroutines = 4
	const perGoroutine = 25
	const total = goroutines * perGoroutine

	var (
		mu       sync.Mutex
		bySender = make(map[int][]int)
	)
	done := make(chan struct{})

	a1.Handle("", func(_ context.Context, msg Message) {
		// Encoding: byte0 = goroutine id, byte1..2 = per-goroutine index.
		gid := int(msg.Data[0])
		idx := int(msg.Data[1])<<8 | int(msg.Data[2])
		mu.Lock()
		bySender[gid] = append(bySender[gid], idx)
		count := 0
		for _, s := range bySender {
			count += len(s)
		}
		if count == total {
			close(done)
		}
		mu.Unlock()
	})

	go a1.Start(ctx)
	go a2.Start(ctx)
	<-a1.Ready()
	<-a2.Ready()

	connectPeers(t, a1, a2)

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}

	var (
		wg       sync.WaitGroup
		sendErrs []error
		sendMu   sync.Mutex
	)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				size := 8
				if i%3 == 0 {
					size = 256 * 1024
				}
				data := make([]byte, size)
				data[0] = byte(gid)
				data[1] = byte(i >> 8)
				data[2] = byte(i & 0xff)
				if _, err := a2.SendTo(ctx, target, "", data); err != nil {
					sendMu.Lock()
					sendErrs = append(sendErrs, err)
					sendMu.Unlock()
					return
				}
			}
		}(g)
	}
	wg.Wait()

	sendMu.Lock()
	if len(sendErrs) > 0 {
		t.Fatalf("SendTo errors: %v", sendErrs)
	}
	sendMu.Unlock()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		mu.Lock()
		count := 0
		for _, s := range bySender {
			count += len(s)
		}
		t.Fatalf("timeout: only %d/%d messages received; bySender=%v", count, total, bySender)
	}

	mu.Lock()
	defer mu.Unlock()

	for gid, seq := range bySender {
		if len(seq) != perGoroutine {
			t.Errorf("goroutine %d: got %d messages, want %d", gid, len(seq), perGoroutine)
			continue
		}
		for i, got := range seq {
			if got != i {
				t.Errorf("goroutine %d position %d: expected %d, got %d (sequence: %v)", gid, i, i, got, seq)
				break
			}
		}
	}
}
