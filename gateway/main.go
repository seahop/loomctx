// The LoomCtx ingest gateway (docs/decisions.md D-010).
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
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	rateBurst    int     // bucket size; 0 = the rate, rounded down (at least 1)
	stream       streamConfig
	// Host / Origin / Content-Type guard (D-059). loadConfig always sets
	// it from LOOMCTX_ALLOWED_HOSTS / LOOMCTX_ALLOWED_ORIGINS; nil (unit tests
	// that exercise the handlers alone) serves unguarded.
	hosts *hostPolicy
}

// streamConfig: how the ingest stream is shaped (D-029). Replicas must
// match the NATS cluster size (1 on a single node, 3 on the HA cluster);
// maxBytes caps what a storm can buffer, discard says which end gives.
type streamConfig struct {
	replicas int
	maxBytes int64  // bytes; default 1 GiB (0 would be unlimited — on a small PVC that is a disk-full)
	discard  string // "old" | "new"
}

// loadConfig reads the env. A numeric dial that does not parse is an
// error, never a silent fallback: LOOMCTX_RATE_PER_SEC=0.5 used to go through
// ParseInt, fail, and leave the gateway unlimited.
func loadConfig() (config, error) {
	p := envParser{}
	hosts := hostPolicyFromEnv()
	cfg := config{
		listenAddr:   envOr("LOOMCTX_GATEWAY_ADDR", ":8080"),
		schemasPath:  envOr("LOOMCTX_SCHEMAS_PATH", "/etc/loomctx/schemas.json"),
		forwardURL:   envOr("LOOMCTX_FORWARD_URL", "http://loomctx:8000"),
		natsURL:      os.Getenv("LOOMCTX_NATS_URL"),
		maxBodyBytes: p.intVar("LOOMCTX_MAX_BODY_BYTES", 1<<20),
		maxBatch:     p.intVar("LOOMCTX_MAX_BATCH", 1000),
		ratePerSec:   p.floatVar("LOOMCTX_RATE_PER_SEC", 0),
		rateBurst:    int(p.intVar("LOOMCTX_RATE_BURST", 0)),
		stream: streamConfig{
			replicas: int(p.intVar("LOOMCTX_STREAM_REPLICAS", 1)),
			maxBytes: p.intVar("LOOMCTX_STREAM_MAX_BYTES", 1<<30),
			discard:  envOr("LOOMCTX_STREAM_DISCARD", "old"),
		},
		hosts: &hosts,
	}
	if cfg.ratePerSec < 0 || cfg.rateBurst < 0 {
		p.errs = append(p.errs, "LOOMCTX_RATE_PER_SEC / LOOMCTX_RATE_BURST must not be negative (unset or 0 = unlimited)")
	}
	if len(p.errs) > 0 {
		return cfg, errors.New(strings.Join(p.errs, "; "))
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envParser collects every malformed numeric dial so one start-up error
// names them all.
type envParser struct{ errs []string }

func (p *envParser) intVar(key string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		p.errs = append(p.errs, fmt.Sprintf("%s must be an integer, got %q", key, v))
		return fallback
	}
	return n
}

func (p *envParser) floatVar(key string, fallback float64) float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		p.errs = append(p.errs, fmt.Sprintf("%s must be a number, got %q", key, v))
		return fallback
	}
	return f
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}

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
		log.Printf("auth: %d key entries from LOOMCTX_API_KEYS", len(auth.entries))
	default:
		log.Printf("auth: no LOOMCTX_AUTH_FILE / LOOMCTX_API_KEYS — auth DISABLED (open dev mode)")
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
