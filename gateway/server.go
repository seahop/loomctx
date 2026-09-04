package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	forward(ctx context.Context, kind string, payload []byte) (status int, body []byte, err error)
	close()
}

type httpForwarder struct {
	url    string
	client *http.Client
}

func newHTTPForwarder(url string) *httpForwarder {
	return &httpForwarder{url: url, client: &http.Client{Timeout: 30 * time.Second}}
}

func (f *httpForwarder) forward(ctx context.Context, _ string, payload []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.url+"/v1/ingest", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
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

func (f *natsForwarder) forward(ctx context.Context, kind string, payload []byte) (int, []byte, error) {
	if _, err := f.js.Publish(ctx, "loom.ingest."+kind, payload); err != nil {
		return 0, nil, err
	}
	return http.StatusAccepted, []byte(`{"status":"queued"}`), nil
}

func (f *natsForwarder) close() { f.nc.Close() }

// ------------------------------------------------------------------- server

func newServer(cfg config, schema *jsonschema.Schema, fwd forwarder) http.Handler {
	var limiter *rate.Limiter
	if cfg.ratePerSec > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.ratePerSec), int(cfg.ratePerSec))
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		if limiter != nil && !limiter.Allow() {
			writeJSON(w, http.StatusTooManyRequests,
				map[string]string{"detail": "rate limit exceeded"})
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cfg.maxBodyBytes))
		if err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge,
				map[string]string{"detail": "body too large"})
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
		if err != nil {
			writeJSON(w, http.StatusBadRequest,
				map[string]string{"detail": "invalid JSON"})
			return
		}
		if err := schema.Validate(doc); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity,
				map[string]string{"detail": fmt.Sprintf("contract violation: %v", err)})
			return
		}
		kind := extractKind(doc)
		if kind == "" {
			writeJSON(w, http.StatusUnprocessableEntity,
				map[string]string{"detail": "envelope must carry an explicit 'kind'"})
			return
		}
		status, respBody, err := fwd.forward(r.Context(), kind, body)
		if err != nil {
			writeJSON(w, http.StatusBadGateway,
				map[string]string{"detail": "upstream unavailable"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(respBody)
	})

	return mux
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
