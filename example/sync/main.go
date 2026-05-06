// Package main is a leader-driven counter sync example for alan.
//
// # Protocol overview
//
// One node is leader (chosen by the alan distributed lock named "sync").
// Writes happen only on the leader; followers learn about new state by
// participating in a 3-message reconciliation handshake initiated by the
// leader after every write.
//
// Message types used:
//
//   - "update" (request/reply, leader→all): "your turn to reconcile".
//     Empty body. Sent by the leader after a local mutation. The
//     follower's reply (also empty) is the leader's per-peer ack and
//     is what unblocks the leader's SendAndWaitReply call.
//
//   - "fetch" (request/reply, follower→leader): carries the follower's
//     current snapshot. Triggered from the follower's "update" handler.
//     The leader uses it to compute a diff and pushes that diff back via
//     a separate "stream" message. The reply body is unused (nil).
//
//   - "stream" (fire-and-forget data, leader→follower): carries either
//     a full snapshot (used by OnPeerJoin) or a counter diff (used
//     during reconciliation). The follower applies it additively:
//     data.Counter += incoming.Counter.
//
// # End-to-end flow on POST /
//
// Leader L (handling the HTTP request), follower F:
//
//  1. L: data.Counter++ (local mutation, behind serverLock)
//  2. L → F: SendAndWaitReply("update", nil)
//  3. F:   "update" handler runs
//  4. F → L: SendToAndWaitReply("fetch", marshal(F.data))
//  5. L:   "fetch" handler runs, computes diff = L.Counter - F.Counter
//  6. L → F: SendToStream("stream", marshal(diff))   [fire-and-forget]
//  7. L → F: Reply(msg, nil)                          [acks step 4]
//  8. F:   "stream" handler runs (some time after 6 arrives), F.Counter += diff
//  9. F → L: Reply(msg, nil)                          [acks step 2]
//  10. L's SendAndWaitReply returns; HTTP request completes.
//
// # Consistency model
//
// Strongly consistent on the happy path: the leader's HTTP handler does
// not return until every peer has acknowledged the "update" cycle, which
// implicitly happens after each peer has received the diff stream (step 8
// is processed before step 9 because both ride the same QUIC connection,
// and QUIC streams within a connection deliver in order from each peer's
// perspective).
//
// On the unhappy path (peer disconnects mid-cycle, partial network
// failure), SendAndWaitReply drops disconnected peers from its waitlist
// rather than erroring; followers may end up out of sync until the next
// write triggers another reconciliation, or until they reconnect and
// receive a snapshot from OnPeerJoin.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/alan"
	"github.com/rakunlabs/chu"
	"github.com/rakunlabs/into"
	"github.com/rakunlabs/logi"
	"golang.org/x/sync/errgroup"
)

var (
	al *alan.Alan
)

type Config struct {
	Alan alan.Config `cfg:"alan"`
}

func main() {
	into.Init(
		run,
		into.WithLogger(logi.InitializeLog(logi.WithCaller(false))),
		into.WithMsgf("alan sync example"),
	)
}

// Data is the synchronized state. Only Counter is replicated.
//
// NOTE: there is no version / Lamport clock. Reconciliation relies
// purely on additive diffs and the assumption that the leader observes
// every write. If a stale leader applies a write during failover, or if
// a follower misses a reconciliation cycle, divergence cannot be
// detected from the data alone.
type Data struct {
	Counter int `json:"counter"`
}

func run(ctx context.Context) error {
	cfg := Config{
		Alan: alan.Config{
			DNSAddr: "alan-chat.local",
			Port:    5000,
			Security: alan.SecurityConfig{
				Key:     []byte("alan-chat-default-key"),
				Enabled: true,
			},
		},
	}

	// Load config from environment
	if err := chu.Load(ctx, "alan", &cfg); err != nil {
		return err
	}

	// ///////////////////////////////////////////

	serverLock := &sync.Mutex{}
	data := &Data{}

	g, ctx := errgroup.WithContext(ctx)

	// ///////////////////////////////////////////

	var err error
	al, err = alan.New(cfg.Alan)
	if err != nil {
		return err
	}

	// OnPeerJoin: only the current leader pushes initial state to a new
	// peer. The state is sent via the "stream" message — the same type
	// the leader uses to push diffs after writes.
	//
	// NOTE: this works today only because a fresh peer's Counter is 0,
	// and the "stream" handler applies messages additively
	// (data.Counter += incoming.Counter). 0 + snapshot == snapshot, so
	// the additive interpretation incidentally produces the right
	// result. If new peers ever started with non-zero state (restart
	// from disk, replay log, etc.), this conflation of "snapshot" and
	// "diff" would silently corrupt their data.
	//
	// NOTE: `data` is read here without holding serverLock. The
	// resulting JSON snapshot may capture a torn read if a write is
	// happening concurrently on the leader.
	al.OnPeerJoin(func(addr *net.UDPAddr) {
		slog.Info("peer joined", "addr", addr.String())
		if al.IsLeader("sync") {
			slog.Info("sending current data to new peer", "peer", addr.String())
			dataRaw, err := json.Marshal(data)
			if err != nil {
				slog.Error("failed to marshal data", "error", err)
				return
			}
			// NOTE: if SendToStream fails, the joiner is left at
			// Counter=0 with no retry. The next leader-driven write
			// will still produce a diff that re-syncs them, so this
			// is recoverable but not immediate.
			_, err = al.SendToStream(ctx, addr, "stream", bytes.NewReader(dataRaw))
			if err != nil {
				slog.Error("failed to send data to new peer", "error", err)
			}
		}
	})

	// OnPeerLeave: log only. Lock release for any locks held by the
	// departing peer happens inside alan itself; this callback is
	// purely informational.
	al.OnPeerLeave(func(addr *net.UDPAddr) {
		slog.Info("peer left", "addr", addr.String())
	})

	// "update" handler — runs on the FOLLOWER.
	//
	// The leader sends an empty "update" to every peer after each
	// local mutation. The role inversion is intentional: instead of
	// the leader pushing the new state directly, the follower sends
	// its own current snapshot back via "fetch" so the leader can
	// compute a diff. This keeps the leader as the only authority on
	// what the new state should be, even if a follower is behind by
	// more than one step.
	//
	// Sequence:
	//   1. Marshal local data.
	//   2. SendToAndWaitReply("fetch", ...) — send our snapshot up,
	//      block on the leader's reply (currently nil; the diff
	//      arrives separately via the "stream" handler).
	//   3. Reply to the leader so its SendAndWaitReply unblocks.
	//
	// NOTE: `data` is read without holding serverLock. Same caveat as
	// OnPeerJoin — the JSON snapshot may be torn relative to a
	// concurrent local "stream" application. In practice followers
	// don't do concurrent writes, so this is benign.
	al.Handle("update", func(ctx context.Context, msg alan.Message) {
		slog.Info("received update from leader")
		dataRaw, err := json.Marshal(data)
		if err != nil {
			slog.Error("failed to marshal data", "error", err)
			al.Reply(ctx, msg, nil)
			return
		}
		reply, err := al.SendToAndWaitReply(ctx, msg.Addr, "fetch", dataRaw)
		if err != nil {
			slog.Error("failed to send reply", "error", err)
			return
		}

		// reply.Data is currently nil — the diff arrives via the
		// "stream" handler, not as the fetch reply. Forwarding it
		// here is harmless but functionally meaningless.
		al.Reply(ctx, msg, reply.Data)
	})

	// "fetch" handler — runs on the LEADER.
	//
	// Receives the follower's current snapshot, computes the diff
	// against the leader's view, and pushes it back via the "stream"
	// fire-and-forget channel. The reply on the request itself is nil
	// and only serves as the ack that unblocks the follower's
	// SendToAndWaitReply in the "update" handler.
	//
	// NOTE: ordering between the "stream" send and the empty Reply is
	// not formally guaranteed, but both ride the same QUIC connection
	// in the same direction (leader → follower) and QUIC delivers each
	// peer's streams in order they were opened. In practice the
	// stream handler runs before the follower's update handler
	// returns, so the sequence is reliable.
	//
	// NOTE: `data.Counter` is read here without holding serverLock.
	// Concurrent POST writes are serialised by serverLock, so this
	// races only against itself (multiple followers fetching at once)
	// — which is read-only and safe by Go's memory model only because
	// int writes are observed atomically on common architectures.
	// Strictly correct code would hold serverLock around the read.
	al.Handle("fetch", func(ctx context.Context, msg alan.Message) {
		slog.Info("received fetch from peer")

		var d Data
		if err := json.Unmarshal(msg.Data, &d); err != nil {
			slog.Error("failed to unmarshal data", "error", err)
			al.Reply(ctx, msg, nil)
			return
		}

		// Compute the additive diff. The follower will apply this
		// as data.Counter += diff.Counter in the "stream" handler.
		diff := Data{
			Counter: data.Counter - d.Counter,
		}
		diffRaw, err := json.Marshal(diff)
		if err != nil {
			slog.Error("failed to marshal diff", "error", err)
			al.Reply(ctx, msg, nil)
			return
		}

		_, err = al.SendToStream(ctx, msg.Addr, "stream", bytes.NewReader(diffRaw))
		if err != nil {
			slog.Error("failed to send diff to stream", "error", err)
		}

		// Empty reply: just an ack. The actual data was delivered
		// out-of-band via the "stream" message above.
		al.Reply(ctx, msg, nil)
	})

	// "stream" handler — runs on the FOLLOWER.
	//
	// Receives either:
	//   - a full snapshot from a leader on peer-join (Counter=N), or
	//   - a diff from the leader during reconciliation (Counter=delta).
	//
	// In both cases the body is applied additively. This works for the
	// snapshot case only because a fresh peer's local Counter is 0;
	// see the NOTE on OnPeerJoin.
	//
	// serverLock here protects against concurrent local handler
	// invocations on this instance (e.g. two diffs arriving for
	// different peers via different ordered queues). It does NOT
	// coordinate state across the cluster — each peer has its own
	// independent serverLock.
	al.HandleStream("stream", func(ctx context.Context, msg alan.Message, body io.Reader) error {
		slog.Info("received stream from leader")

		var diff Data
		if err := json.NewDecoder(body).Decode(&diff); err != nil {
			slog.Error("failed to decode diff", "error", err)
			return err
		}

		serverLock.Lock()
		defer serverLock.Unlock()

		data.Counter += diff.Counter

		slog.Info("current value", "counter", data.Counter)

		return nil
	})

	g.Go(func() error {
		return al.Start(ctx)
	})

	// ///////////////////////////////////////////

	server := ada.New()
	// GET / returns the local snapshot. Any peer can serve this; the
	// returned value is whatever this instance currently believes the
	// counter to be.
	server.GET("/", server.Wrap(func(c *ada.Context) error {
		return c.SendJSON(data)
	}))
	// /healthz returns 200 only when the local instance is the active
	// leader and the cluster still has quorum. Useful as a load-balancer
	// readiness probe — a leader that has been partitioned away from
	// the majority will fail the check and stop receiving traffic.
	server.GET("/healthz", server.Wrap(func(c *ada.Context) error {
		if !al.LeaderHealthy("sync") {
			return c.SetStatus(503).SendString("not leader or no quorum")
		}
		return c.SendString("ok")
	}))
	// POST / increments the counter and waits until every peer has
	// acknowledged the reconciliation cycle (the full update→fetch→
	// stream→reply round trip described at the top of this file)
	// before returning to the HTTP client.
	server.POST("/", server.Wrap(func(a *ada.Context) error {
		// Refuse writes when leadership is unhealthy. RunAsLeader cancels
		// the leader fn's ctx on quorum loss, but external HTTP traffic
		// can still arrive in the small window before the server shuts
		// down — fail fast instead of advancing local state that other
		// peers will not see.
		if !al.LeaderHealthy("sync") {
			return a.SetStatus(503).SendString("leadership lost; refusing write")
		}
		serverLock.Lock()
		defer serverLock.Unlock()

		data.Counter++

		slog.Info("current value", "counter", data.Counter)

		// Broadcast "update" to all peers and block until each has
		// replied. Peers that disconnect mid-flight are dropped from
		// the waitlist (no error) — they will re-sync via OnPeerJoin
		// when they reconnect.
		reply, err := al.SendAndWaitReply(ctx, "update", nil)
		if err != nil {
			return err
		}

		for _, peer := range reply {
			slog.Info("peer acknowledged update", "peer", peer.Addr.String())
		}

		return nil
	}))

	// LeaderLoop re-acquires leadership automatically when quorum is
	// restored after loss. The fn ctx is cancelled by RunAsLeader's
	// internal step-down monitor as soon as quorum drops; the loop then
	// blocks in Lock() until quorum returns, at which point it tries
	// again. Without LeaderLoop the example would simply exit on the
	// first quorum loss.
	g.Go(func() error {
		return al.LeaderLoop(ctx, "sync", time.Second, func(ctx context.Context) error {
			slog.Info("became leader")
			defer slog.Info("stepping down as leader")

			// On (re)taking leadership, force a cluster-wide
			// reconciliation so every peer aligns with this
			// leader's view of the counter. This is important
			// after failover: the new leader's state is treated
			// as authoritative, and peers that were ahead/behind
			// the old leader get reset via the diff computed in
			// the "fetch" handler.
			//
			// NOTE: error is intentionally ignored. If no peers
			// are reachable yet, the broadcast is a no-op; the
			// loop continues and the HTTP server starts anyway.
			_, _ = al.SendAndWaitReply(ctx, "update", nil)

			return server.StartWithContext(ctx, ":8080")
		})
	})

	return g.Wait()
}
