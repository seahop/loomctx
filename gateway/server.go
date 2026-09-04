package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/time/rate"
)

// ---------------------------------------------------------------- validator

func newValidator(schemasPath string) (*jsonschema.Schema, error) {
	raw, err := os.ReadFile(schemasPath)
	if err != nil {
		return nil, err
	}
	var exported map[string]any
	if err := json.Unmarshal(raw, &exported); err != nil {
		return nil, err
	}
	envelope, ok := exported["IngestEnvelope"]
	if !ok {
		return nil, fmt.Errorf("IngestEnvelope missing from %s", schemasPath)
	}
	// Round-trip through jsonschema's decoder so numbers keep full precision.
	buf, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("envelope.json", doc); err != nil {
		return nil, err
	}
	return compiler.Compile("envelope.json")
}

// --------------------------------------------------------------- forwarders

type forwarder interface {
	// forward relays a validated envelope; kind is "claim" or "document";
	// apiKey travels with it in HTTP mode so the engine re-authenticates.
	forward(ctx context.Context, kind, apiKey string, payload []byte) (status int, body []byte, err error)
	close()
}

type httpForwarder struct {
	url    string
	client *http.Client
}

func newHTTPForwarder(url string) *httpForwarder {
	return &httpForwarder{url: url, client: &http.Client{Timeout: 30 * time.Second}}
}

func (f *httpForwarder) forward(ctx context.Context, _, apiKey string, payload []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.url+"/v1/ingest", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-Loom-Key", apiKey)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

func (f *httpForwarder) close() {}

const streamName = "LOOM_INGEST"

type natsForwarder struct {
	nc *nats.Conn
	js jetstream.JetStream
}

func newNATSForwarder(url string) (*natsForwarder, error) {
	nc, err := nats.Connect(url, nats.MaxReconnects(-1))
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     streamName,
		Subjects: []string{"loom.ingest.>"},
	})
	if err != nil {
		nc.Close()
		return nil, err
	}
	return &natsForwarder{nc: nc, js: js}, nil
}

func (f *natsForwarder) forward(ctx context.Context, kind, _ string, payload []byte) (int, []byte, error) {
	if _, err := f.js.Publish(ctx, "loom.ingest."+kind, payload); err != nil {
		return 0, nil, err
	}
	return http.StatusAccepted, []byte(`{"status":"queued"}`), nil
}

func (f *natsForwarder) close() { f.nc.Close() }

// ------------------------------------------------------------------- server

// limiterPool hands out one token bucket per API key (or one shared bucket
// for the empty key when auth is off), so a misbehaving sender exhausts its
// own budget without starving the others.
type limiterPool struct {
	mu      sync.Mutex
	rate    float64
	buckets map[string]*rate.Limiter
}

func newLimiterPool(perSec float64) *limiterPool {
	if perSec <= 0 {
		return nil
	}
	return &limiterPool{rate: perSec, buckets: map[string]*rate.Limiter{}}
}

func (p *limiterPool) allow(key string) bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	lim, ok := p.buckets[key]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(p.rate), int(p.rate))
		p.buckets[key] = lim
	}
	p.mu.Unlock()
	return lim.Allow()
}

func newServer(cfg config, schema *jsonschema.Schema, fwd forwarder, auth *authConfig) http.Handler {
	limiters := newLimiterPool(cfg.ratePerSec)
	m := &gwMetrics{}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /metrics", m.handler)

	mux.HandleFunc("POST /v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		m.requests.Add(1)
		apiKey := extractKey(r)

		// Cheapest rejections first: no key (when required), then the
		// per-key rate limit — both before the body is even read, so abusive
		// or misconfigured senders cost almost nothing.
		if auth.enabled() && apiKey == "" {
			m.rejectedAuth.Add(1)
			writeJSON(w, http.StatusUnauthorized,
				map[string]string{"detail": "missing API key (X-Loom-Key or Authorization: Bearer)"})
			return
		}
		if !limiters.allow(apiKey) {
			m.rejectedRate.Add(1)
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests,
				map[string]string{"detail": "rate limit exceeded"})
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cfg.maxBodyBytes))
		if err != nil {
			m.rejectedBad.Add(1)
			writeJSON(w, http.StatusRequestEntityTooLarge,
				map[string]string{"detail": "body too large"})
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
		if err != nil {
			m.rejectedBad.Add(1)
			writeJSON(w, http.StatusBadRequest,
				map[string]string{"detail": "invalid JSON"})
			return
		}
		if err := schema.Validate(doc); err != nil {
			m.rejectedBad.Add(1)
			writeJSON(w, http.StatusUnprocessableEntity,
				map[string]string{"detail": fmt.Sprintf("contract violation: %v", err)})
			return
		}
		kind := extractKind(doc)
		if kind == "" {
			m.rejectedBad.Add(1)
			writeJSON(w, http.StatusUnprocessableEntity,
				map[string]string{"detail": "envelope must carry an explicit 'kind'"})
			return
		}
		if auth.enabled() {
			g := auth.grantFor(apiKey)
			if g == nil || !g.allows(extractNamespace(doc), "w") {
				m.rejectedAuth.Add(1)
				writeJSON(w, http.StatusForbidden,
					map[string]string{"detail": "key not authorized to write this namespace"})
				return
			}
			// Data-scoping gates (D-013a): keys write only the slice of the
			// world they're entitled to. Source pinning stops a compromised
			// sender from forging other sources' facts.
			if detail := checkWriteGates(g, kind, doc); detail != "" {
				m.rejectedAuth.Add(1)
				writeJSON(w, http.StatusForbidden, map[string]string{"detail": detail})
				return
			}
		}
		status, respBody, err := fwd.forward(r.Context(), kind, apiKey, body)
		if err != nil {
			m.upstreamErr.Add(1)
			writeJSON(w, http.StatusBadGateway,
				map[string]string{"detail": "upstream unavailable"})
			return
		}
		m.queued.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(respBody)
	})

	return mux
}

func extractNamespace(doc any) string {
	if obj, ok := doc.(map[string]any); ok {
		if ns, ok := obj["namespace"].(string); ok && ns != "" {
			return ns
		}
	}
	return "default"
}

func checkWriteGates(g *grant, kind string, doc any) string {
	obj, ok := doc.(map[string]any)
	if !ok {
		return ""
	}
	if src, ok := obj["source"].(string); ok && !g.allowsSource(src) {
		return fmt.Sprintf("key %q may not write claims for source %q", g.ID, src)
	}
	if kind != "claim" {
		return ""
	}
	if subj, ok := obj["subject"].(map[string]any); ok {
		if t, ok := subj["type"].(string); ok && !g.allowsEntityType(t) {
			return fmt.Sprintf("key %q is not scoped to entity type %q", g.ID, t)
		}
	}
	if o, ok := obj["object"].(map[string]any); ok {
		if t, ok := o["type"].(string); ok && !g.allowsEntityType(t) {
			return fmt.Sprintf("key %q is not scoped to entity type %q", g.ID, t)
		}
	}
	return ""
}

func extractKind(doc any) string {
	obj, ok := doc.(map[string]any)
	if !ok {
		return ""
	}
	kind, _ := obj["kind"].(string)
	return kind
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
