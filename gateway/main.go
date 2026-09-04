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
	ratePerSec   float64 // 0 disables rate limiting
}

func loadConfig() config {
	cfg := config{
		listenAddr:   envOr("LOOM_GATEWAY_ADDR", ":8080"),
		schemasPath:  envOr("LOOM_SCHEMAS_PATH", "/etc/loom/schemas.json"),
		forwardURL:   envOr("LOOM_FORWARD_URL", "http://loom:8000"),
		natsURL:      os.Getenv("LOOM_NATS_URL"),
		maxBodyBytes: envInt("LOOM_MAX_BODY_BYTES", 1<<20),
		ratePerSec:   float64(envInt("LOOM_RATE_PER_SEC", 0)),
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

	auth, err := parseAuth(os.Getenv("LOOM_API_KEYS"))
	if err != nil {
		log.Fatalf("parsing LOOM_API_KEYS: %v", err)
	}
	if auth.enabled() {
		log.Printf("auth: %d API key entries loaded", len(auth.entries))
	} else {
		log.Printf("auth: LOOM_API_KEYS unset — auth DISABLED (open dev mode)")
	}

	var fwd forwarder
	if cfg.natsURL != "" {
		fwd, err = newNATSForwarder(cfg.natsURL)
		if err != nil {
			log.Fatalf("connecting to NATS: %v", err)
		}
		log.Printf("forwarding to NATS JetStream at %s", cfg.natsURL)
	} else {
		fwd = newHTTPForwarder(cfg.forwardURL)
		log.Printf("forwarding to core engine at %s", cfg.forwardURL)
	}

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           newServer(cfg, validator, fwd, auth),
		ReadHeaderTimeout: 5 * time.Second,
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
