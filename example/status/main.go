package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"

	"github.com/oklog/ulid/v2"
	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/alan"
	"github.com/rakunlabs/chu"
	"github.com/rakunlabs/chu/loader/loaderenv"
	"github.com/rakunlabs/into"
	"github.com/rakunlabs/logi"
	"golang.org/x/sync/errgroup"
)

var (
	id string
	al *alan.Alan
)

func main() {
	into.Init(
		run,
		into.WithLogger(logi.InitializeLog(logi.WithCaller(false))),
		into.WithMsgf("alan status example"),
	)
}

func run(ctx context.Context) error {
	cfg := alan.Config{}

	// Load config from environment
	if err := chu.Load(ctx, "alan", &cfg, chu.WithLoaderOption(
		loaderenv.New(
			loaderenv.WithPrefix("ALAN_"),
		)),
	); err != nil {
		return err
	}

	// ///////////////////////////////////////////

	id = ulid.Make().String()

	// ///////////////////////////////////////////

	g, ctx := errgroup.WithContext(ctx)

	// ///////////////////////////////////////////

	var err error
	al, err = alan.New(cfg)
	if err != nil {
		return err
	}

	al.OnPeerJoin(func(addr *net.UDPAddr) {
		slog.Info("peer joined", "addr", addr.String())
	})

	al.OnPeerLeave(func(addr *net.UDPAddr) {
		slog.Info("peer left", "addr", addr.String())
	})

	al.Handle("", AlanHandler)
	g.Go(func() error {
		return al.Start(ctx)
	})

	// ///////////////////////////////////////////

	server := ada.New()
	server.GET("/status", server.Wrap(HttpHandler))
	server.GET("/healthz", server.Wrap(func(a *ada.Context) error {
		return a.SendString("OK")
	}))

	g.Go(func() error {
		return server.StartWithContext(ctx, ":8080")
	})

	// ///////////////////////////////////////////

	return g.Wait()
}

func HttpHandler(a *ada.Context) error {
	// Send request to all peers with our request ID
	replies, err := al.SendAndWaitReply(a.Request.Context(), "", []byte("REQ-ID"))
	if err != nil {
		return err
	}

	response := make([]string, 0, len(replies)+1)
	for _, reply := range replies {
		response = append(response, string(reply.Data))
	}

	response = append(response, id)

	return a.SendJSON(response)
}

func AlanHandler(ctx context.Context, msg alan.Message) {
	if msg.IsRequest() {
		if bytes.Equal(msg.Data, []byte("REQ-ID")) {
			// Respond with our ID
			al.Reply(ctx, msg, []byte(id))
		}
	}
}
