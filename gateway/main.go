// The Loom ingest gateway (docs/decisions.md D-010).
//
// Stateless hot path: authenticate (phase 5), validate the ingestion envelope
// against the JSON Schema exported from the Python contracts, rate-limit, and
// forward — either straight to the core engine over HTTP, or into the NATS
// JetStream buffer in the scale shape. No semantics live here; a gateway
// replica can be added or killed at any time.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type config struct {
	listenAddr   string
	schemasPath  string
	forwardURL   string // used when natsURL is empty
	natsURL      string // when set, publish to JetStream instead
	maxBodyBytes int64
	maxBatch     int64   // items per /v1/ingest/batch request (D-034)
	ratePerSec   float64 // 0 disables rate limiting
	stream       streamConfig
}

// streamConfig: how the ingest stream is shaped (D-029). Replicas must
// match the NATS cluster size (1 on a single node, 3 on the HA cluster);
// maxBytes caps what a storm can buffer, discard says which end gives.
type streamConfig struct {
	replicas int
	maxBytes int64  // bytes; default 1 GiB (0 would be unlimited — on a small PVC that is a disk-full)
	discard  string // "old" | "new"
}

func loadConfig() config {
	cfg := config{
		listenAddr:   envOr("LOOM_GATEWAY_ADDR", ":8080"),
		schemasPath:  envOr("LOOM_SCHEMAS_PATH", "/etc/loom/schemas.json"),
		forwardURL:   envOr("LOOM_FORWARD_URL", "http://loom:8000"),
		natsURL:      os.Getenv("LOOM_NATS_URL"),
		maxBodyBytes: envInt("LOOM_MAX_BODY_BYTES", 1<<20),
		maxBatch:     envInt("LOOM_MAX_BATCH", 1000),
		ratePerSec:   float64(envInt("LOOM_RATE_PER_SEC", 0)),
		stream: streamConfig{
			replicas: int(envInt("LOOM_STREAM_REPLICAS", 1)),
			maxBytes: envInt("LOOM_STREAM_MAX_BYTES", 1<<30),
			discard:  envOr("LOOM_STREAM_DISCARD", "old"),
		},
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func main() {
	cfg := loadConfig()

	validator, err := newValidator(cfg.schemasPath)
	if err != nil {
		log.Fatalf("loading contract schema: %v", err)
	}

	auth, err := loadAuth()
	if err != nil {
		log.Fatalf("loading auth config: %v", err)
	}
	switch {
	case auth.path != "":
		log.Printf("auth: %d key(s) from %s (hot-reloaded on change)",
			len(auth.entries), auth.path)
	case auth.enabled():
		log.Printf("auth: %d key entries from LOOM_API_KEYS", len(auth.entries))
	default:
		log.Printf("auth: no LOOM_AUTH_FILE / LOOM_API_KEYS — auth DISABLED (open dev mode)")
	}

	var fwd forwarder
	if cfg.natsURL != "" {
		fwd, err = connectNATS(cfg.natsURL, cfg.stream, 2*time.Minute)
		if err != nil {
			log.Fatalf("connecting to NATS: %v", err)
		}
		log.Printf("forwarding to NATS JetStream at %s (stream replicas=%d maxBytes=%d discard=%s)",
			cfg.natsURL, cfg.stream.replicas, cfg.stream.maxBytes, cfg.stream.discard)
	} else {
		fwd = newHTTPForwarder(cfg.forwardURL)
		log.Printf("forwarding to core engine at %s", cfg.forwardURL)
	}

	// Every timeout set: a slow client or a stalled forward must not pin a
	// connection (and its goroutine) for as long as it likes.
	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           newServer(cfg, validator, fwd, auth),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("ingest gateway listening on %s", cfg.listenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	fwd.close()
}
