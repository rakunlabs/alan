package main

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

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

	// pendingRequests maps request IDs to their response channels
	pendingRequests   = make(map[string]chan string)
	pendingRequestsMu sync.RWMutex
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

	g.Go(func() error {
		return al.Start(ctx, AlanHandler)
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
	// Get peer list atomically to avoid race conditions
	peers := al.Peers()
	peerCount := len(peers)

	// Generate unique request ID for this HTTP request
	reqID := ulid.Make().String()

	// Create response channel for this request (buffer for peers + some extra for safety)
	respChan := make(chan string, peerCount+10)
	pendingRequestsMu.Lock()
	pendingRequests[reqID] = respChan
	pendingRequestsMu.Unlock()

	// Cleanup when done
	defer func() {
		pendingRequestsMu.Lock()
		delete(pendingRequests, reqID)
		pendingRequestsMu.Unlock()
	}()

	// Send request to all peers with our request ID
	al.Send([]byte("REQ-ID:" + reqID))

	// Collect responses with timeout, using map to deduplicate by peer ID
	responses := make(map[string]struct{})
	timeout := time.After(10 * time.Second)

	for len(responses) < peerCount {
		select {
		case resp := <-respChan:
			responses[resp] = struct{}{}
		case <-timeout:
			// Timeout - return what we have
			return a.SendJSON(buildResponse(responses))
		}
	}

	return a.SendJSON(buildResponse(responses))
}

// buildResponse creates the response including own ID and peer IDs
func buildResponse(peerResponses map[string]struct{}) map[string]any {
	peerIDs := make([]string, 0, len(peerResponses))
	for peerID := range peerResponses {
		peerIDs = append(peerIDs, peerID)
	}

	return map[string]any{
		"self":  id,
		"peers": peerIDs,
		"total": len(peerIDs) + 1, // peers + self
	}
}

func AlanHandler(ctx context.Context, msg alan.Message) {
	data := string(msg.Data)

	if after, ok := strings.CutPrefix(data, "REQ-ID:"); ok {
		// This is a request - extract reqID and respond with our ID
		reqID := after
		al.SendTo(msg.Addr, []byte("RESP:"+reqID+":"+id))
	} else if after, ok := strings.CutPrefix(data, "RESP:"); ok {
		// This is a response - route to correct channel
		parts := strings.SplitN(after, ":", 2)
		if len(parts) == 2 {
			reqID := parts[0]
			peerID := parts[1]

			pendingRequestsMu.RLock()
			respChan, ok := pendingRequests[reqID]
			pendingRequestsMu.RUnlock()

			if ok {
				select {
				case respChan <- peerID:
				default:
					// Channel full, skip
				}
			}
		}
	}
}
