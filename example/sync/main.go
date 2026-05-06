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

	al.OnPeerJoin(func(addr *net.UDPAddr) {
		slog.Info("peer joined", "addr", addr.String())
		if al.IsLeader("sync") {
			slog.Info("sending current data to new peer", "peer", addr.String())
			dataRaw, err := json.Marshal(data)
			if err != nil {
				slog.Error("failed to marshal data", "error", err)
				return
			}
			_, err = al.SendToStream(ctx, addr, "stream", bytes.NewReader(dataRaw))
			if err != nil {
				slog.Error("failed to send data to new peer", "error", err)
			}
		}
	})

	al.OnPeerLeave(func(addr *net.UDPAddr) {
		slog.Info("peer left", "addr", addr.String())
	})

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

		al.Reply(ctx, msg, reply.Data)
	})

	al.Handle("fetch", func(ctx context.Context, msg alan.Message) {
		slog.Info("received fetch from peer")

		var d Data
		if err := json.Unmarshal(msg.Data, &d); err != nil {
			slog.Error("failed to unmarshal data", "error", err)
			al.Reply(ctx, msg, nil)
			return
		}

		// send diff back to requester
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

		al.Reply(ctx, msg, nil)
	})

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

		// Broadcast the update to all peers
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

			// Broadcast a refresh to peers when we (re)take leadership.
			_, _ = al.SendAndWaitReply(ctx, "update", nil)

			return server.StartWithContext(ctx, ":8080")
		})
	})

	return g.Wait()
}
