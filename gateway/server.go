package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
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
	// forward relays a validated envelope; kind is "claim" or "document".
	// apiKey travels with it in HTTP mode so the engine re-authenticates;
	// principal (the grant id, never the key) rides on queued messages as a
	// header so the writer can attribute what it stores (H-A10).
	forward(ctx context.Context, kind, apiKey, principal string, payload []byte) (status int, body []byte, err error)
	close()
}

type httpForwarder struct {
	url    string
	client *http.Client
}

func newHTTPForwarder(url string) *httpForwarder {
	return &httpForwarder{url: url, client: &http.Client{Timeout: 30 * time.Second}}
}

func (f *httpForwarder) forward(ctx context.Context, _, apiKey, _ string, payload []byte) (int, []byte, error) {
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

// connectNATS keeps trying until the queue answers or the deadline passes:
// compose/k8s start ordering is best-effort and a gateway that dies on the
// first refused connection leaves the scale shape half-up (H-F3).
func connectNATS(url string, sc streamConfig, wait time.Duration) (*natsForwarder, error) {
	deadline := time.Now().Add(wait)
	for {
		fwd, err := newNATSForwarder(url, sc)
		if err == nil {
			return fwd, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		log.Printf("NATS at %s not ready (%v); retrying", url, err)
		time.Sleep(2 * time.Second)
	}
}

func newNATSForwarder(url string, sc streamConfig) (*natsForwarder, error) {
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
	discard := jetstream.DiscardOld
	if sc.discard == "new" {
		discard = jetstream.DiscardNew
	}
	replicas := sc.replicas
	if replicas < 1 {
		replicas = 1
	}
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     streamName,
		Subjects: []string{"loom.ingest.>"},
		Replicas: replicas,
		MaxBytes: sc.maxBytes,
		Discard:  discard,
	})
	if err != nil {
		nc.Close()
		return nil, err
	}
	return &natsForwarder{nc: nc, js: js}, nil
}

const principalHeader = "Loom-Principal"

func (f *natsForwarder) forward(ctx context.Context, kind, _, principal string, payload []byte) (int, []byte, error) {
	msg := &nats.Msg{Subject: "loom.ingest." + kind, Data: payload, Header: nats.Header{}}
	if principal != "" {
		msg.Header.Set(principalHeader, principal)
	}
	// A leader election or a node restart in the cluster makes a publish
	// fail for a moment; retry briefly before telling the sender 502.
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if _, err = f.js.PublishMsg(ctx, msg); err == nil {
			return http.StatusAccepted, []byte(`{"status":"queued"}`), nil
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(time.Duration(200*(attempt+1)) * time.Millisecond):
		}
	}
	return 0, nil, err
}

func (f *natsForwarder) close() { f.nc.Close() }

// ------------------------------------------------------------------- server

// limiterPool hands out one token bucket per *authenticated principal*
// (grant id) — or one shared bucket when auth is off — so a misbehaving
// sender exhausts its own budget without starving the others. Buckets are
// keyed by grant, never by the raw header value: an unauthenticated caller
// can't mint a fresh bucket per request by rotating a bogus key (H-A4).
// The map is bounded as a belt-and-braces guard.
type limiterPool struct {
	mu      sync.Mutex
	rate    float64
	buckets map[string]*rate.Limiter
}

const maxLimiterBuckets = 10000

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
		if len(p.buckets) >= maxLimiterBuckets {
			for k := range p.buckets { // evict one arbitrary entry
				delete(p.buckets, k)
				break
			}
		}
		lim = rate.NewLimiter(rate.Limit(p.rate), int(p.rate))
		p.buckets[key] = lim
	}
	p.mu.Unlock()
	return lim.Allow()
}

// allowN takes n tokens at once (a batch of n envelopes costs n).
func (p *limiterPool) allowN(key string, n int) bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	lim, ok := p.buckets[key]
	if !ok {
		if len(p.buckets) >= maxLimiterBuckets {
			for k := range p.buckets {
				delete(p.buckets, k)
				break
			}
		}
		lim = rate.NewLimiter(rate.Limit(p.rate), int(p.rate))
		p.buckets[key] = lim
	}
	p.mu.Unlock()
	if n > lim.Burst() {
		return false // a batch larger than the burst can never pass; refuse cleanly
	}
	return lim.AllowN(time.Now(), n)
}

func (p *limiterPool) size() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.buckets)
}

func newServer(cfg config, schema *jsonschema.Schema, fwd forwarder, auth *authConfig) http.Handler {
	return newServerWithLimiters(cfg, schema, fwd, auth, newLimiterPool(cfg.ratePerSec))
}

func newServerWithLimiters(cfg config, schema *jsonschema.Schema, fwd forwarder,
	auth *authConfig, limiters *limiterPool) http.Handler {
	m := &gwMetrics{}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /metrics", m.handler)

	// Batch ingest (D-034): a JSON array or NDJSON of envelopes, each
	// validated and gated individually and forwarded one message at a time
	// (consumers batch on their side). One bad record never blocks the rest.
	mux.HandleFunc("POST /v1/ingest/batch", func(w http.ResponseWriter, r *http.Request) {
		m.requests.Add(1)
		apiKey := extractKey(r)
		var g *grant
		bucket := ""
		if auth.enabled() {
			if apiKey == "" {
				m.rejectedAuth.Add(1)
				writeJSON(w, http.StatusUnauthorized,
					map[string]string{"detail": "missing API key (X-Loom-Key or Authorization: Bearer)"})
				return
			}
			g = auth.grantFor(apiKey)
			if g == nil {
				m.rejectedAuth.Add(1)
				writeJSON(w, http.StatusForbidden,
					map[string]string{"detail": "unknown, expired, or disabled API key"})
				return
			}
			bucket = g.ID
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cfg.maxBodyBytes))
		if err != nil {
			m.rejectedBad.Add(1)
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"detail": "body too large"})
			return
		}
		items, err := splitBatch(body, r.Header.Get("Content-Type"))
		if err != nil {
			m.rejectedBad.Add(1)
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid batch: " + err.Error()})
			return
		}
		if int64(len(items)) > cfg.maxBatch {
			m.rejectedBad.Add(1)
			writeJSON(w, http.StatusRequestEntityTooLarge,
				map[string]string{"detail": fmt.Sprintf("batch of %d exceeds %d items", len(items), cfg.maxBatch)})
			return
		}
		if !limiters.allowN(bucket, len(items)) {
			m.rejectedRate.Add(1)
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"detail": "rate limit exceeded"})
			return
		}
		principal := ""
		if g != nil {
			principal = g.ID
		}
		type itemResult struct {
			Index  int    `json:"index"`
			Status string `json:"status"`
			Detail string `json:"detail,omitempty"`
		}
		results := make([]itemResult, 0, len(items))
		counts := map[string]int{"recorded": 0, "accepted": 0, "rejected": 0}
		reject := func(i int, detail string) {
			m.rejectedBad.Add(1)
			results = append(results, itemResult{Index: i, Status: "rejected", Detail: detail})
			counts["rejected"]++
		}
		for i, raw := range items {
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				reject(i, "invalid JSON")
				continue
			}
			if err := schema.Validate(doc); err != nil {
				reject(i, fmt.Sprintf("contract violation: %v", err))
				continue
			}
			kind := extractKind(doc)
			if kind == "" {
				reject(i, "envelope must carry an explicit 'kind'")
				continue
			}
			if g != nil {
				if !g.allows(extractNamespace(doc), "w") {
					reject(i, "key not authorized to write this namespace")
					continue
				}
				if detail := checkWriteGates(g, kind, doc); detail != "" {
					reject(i, detail)
					continue
				}
			}
			if _, _, err := fwd.forward(r.Context(), kind, apiKey, principal, raw); err != nil {
				m.upstreamErr.Add(1)
				writeJSON(w, http.StatusBadGateway, map[string]string{"detail": "upstream unavailable"})
				return
			}
			m.queued.Add(1)
			status := "recorded"
			if kind == "document" {
				status = "accepted"
			}
			results = append(results, itemResult{Index: i, Status: status})
			counts[status]++
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"total": len(items), "recorded": counts["recorded"], "accepted": counts["accepted"],
			"rejected": counts["rejected"], "results": results,
		})
	})

	mux.HandleFunc("POST /v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		m.requests.Add(1)
		apiKey := extractKey(r)

		// Cheapest rejections first, all before the body is read: no key
		// (when required), unknown key (one hash compare), then the
		// per-principal rate limit. Authentication precedes the limiter so
		// only real principals get buckets.
		var g *grant
		bucket := "" // shared bucket when auth is off
		if auth.enabled() {
			if apiKey == "" {
				m.rejectedAuth.Add(1)
				writeJSON(w, http.StatusUnauthorized,
					map[string]string{"detail": "missing API key (X-Loom-Key or Authorization: Bearer)"})
				return
			}
			g = auth.grantFor(apiKey)
			if g == nil {
				m.rejectedAuth.Add(1)
				writeJSON(w, http.StatusForbidden,
					map[string]string{"detail": "unknown, expired, or disabled API key"})
				return
			}
			bucket = g.ID
		}
		if !limiters.allow(bucket) {
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
		if g != nil {
			if !g.allows(extractNamespace(doc), "w") {
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
		principal := ""
		if g != nil {
			principal = g.ID
		}
		status, respBody, err := fwd.forward(r.Context(), kind, apiKey, principal, body)
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

// splitBatch turns a request body into individual envelope documents:
// NDJSON (one per line), a JSON array, or a single object.
func splitBatch(body []byte, contentType string) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}
	isND := strings.Contains(contentType, "ndjson") || strings.Contains(contentType, "x-ldjson") ||
		(trimmed[0] != '[' && bytes.ContainsRune(trimmed, '\n') && !strings.HasPrefix(contentType, "application/json"))
	if isND {
		var out []json.RawMessage
		for _, line := range bytes.Split(trimmed, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			if !json.Valid(line) {
				return nil, fmt.Errorf("line %d is not valid JSON", len(out)+1)
			}
			out = append(out, json.RawMessage(line))
		}
		return out, nil
	}
	if trimmed[0] == '{' {
		var wrapper struct {
			Items   []json.RawMessage `json:"items"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err == nil && (wrapper.Items != nil || wrapper.Records != nil) {
			if wrapper.Items != nil {
				return wrapper.Items, nil
			}
			return wrapper.Records, nil
		}
		return []json.RawMessage{json.RawMessage(trimmed)}, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(trimmed, &arr); err != nil {
		return nil, fmt.Errorf("expected a JSON array or NDJSON")
	}
	return arr, nil
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
