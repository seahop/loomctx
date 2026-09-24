package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-059: a numeric dial that does not parse fails start-up. A fractional
// rate used to go through ParseInt and silently leave the gateway unlimited.
func TestRateDialsParseFloatsAndRejectGarbage(t *testing.T) {
	t.Setenv("LOOM_RATE_PER_SEC", "0.5")
	t.Setenv("LOOM_RATE_BURST", "3")
	cfg, err := loadConfig()
	if err != nil || cfg.ratePerSec != 0.5 || cfg.rateBurst != 3 || cfg.hosts == nil {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	for _, bad := range []string{"fast", "1/s", "-1", "NaN"} {
		t.Setenv("LOOM_RATE_PER_SEC", bad)
		if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "LOOM_RATE_PER_SEC") {
			t.Fatalf("LOOM_RATE_PER_SEC=%q: err=%v", bad, err)
		}
	}
	t.Setenv("LOOM_RATE_PER_SEC", "")
	t.Setenv("LOOM_MAX_BATCH", "lots")
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "LOOM_MAX_BATCH") {
		t.Fatalf("LOOM_MAX_BATCH garbage: err=%v", err)
	}
	// a fractional rate actually limits: one request, then 429
	h := guardedServer(t, &fakeForwarder{}, "", func(c *config) { c.ratePerSec = 0.5 })
	codes := []int{send(h, "POST", "/v1/ingest", validClaim, nil).Code,
		send(h, "POST", "/v1/ingest", validClaim, nil).Code}
	if codes[0] != http.StatusOK || codes[1] != http.StatusTooManyRequests {
		t.Fatalf("rate 0.5: %v", codes)
	}
}

func guardedServer(t *testing.T, fwd forwarder, keys string, tweak func(*config)) http.Handler {
	t.Helper()
	schema, err := newValidator("../contracts/schemas.json")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := parseAuth(keys)
	if err != nil {
		t.Fatal(err)
	}
	hosts := parseHostPolicy("loom.example.com", "https://app.example.com")
	cfg := config{maxBodyBytes: 1 << 20, maxBatch: 1000, hosts: &hosts}
	if tweak != nil {
		tweak(&cfg)
	}
	return newServer(cfg, schema, fwd, auth)
}

func send(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "localhost:8081"
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// D-059: DNS rebinding (foreign Host), cross-site requests (foreign
// Origin) and simple-request bodies (text/plain, no type) never reach a
// handler; the deployment shapes' own names and addresses do.
func TestBrowserGuard(t *testing.T) {
	fwd := &fakeForwarder{}
	h := guardedServer(t, fwd, "", nil)
	for _, host := range []string{"localhost:8081", "127.0.0.1:8081", "[::1]:8081", "10.4.0.12:8080",
		"loom-gateway", "gateway:8080", "loom-gateway.loom.svc.cluster.local", "loom.example.com"} {
		if rec := send(h, "POST", "/v1/ingest", validClaim, map[string]string{"Host": host}); rec.Code != http.StatusOK {
			t.Fatalf("host %q: status=%d body=%s", host, rec.Code, rec.Body.String())
		}
	}
	for _, host := range []string{"evil.example.net", "evil.example.net:8081", "loom.example.com.evil.net"} {
		rec := send(h, "POST", "/v1/ingest", validClaim, map[string]string{"Host": host})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "LOOM_ALLOWED_HOSTS") {
			t.Fatalf("host %q: status=%d", host, rec.Code)
		}
	}
	if rec := send(h, "GET", "/healthz", "", map[string]string{"Host": "evil.example.net"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("probe path under a foreign host: %d", rec.Code)
	}
	for origin, want := range map[string]int{
		"https://evil.example.net": http.StatusForbidden,
		"null":                     http.StatusForbidden,
		"https://app.example.com":  http.StatusOK,
		"http://localhost:6274":    http.StatusOK,
		"http://localhost:8081":    http.StatusOK,
	} {
		if rec := send(h, "POST", "/v1/ingest", validClaim, map[string]string{"Origin": origin}); rec.Code != want {
			t.Fatalf("origin %q: status=%d want %d", origin, rec.Code, want)
		}
	}
	for ct, want := range map[string]int{
		"text/plain":                        http.StatusUnsupportedMediaType,
		"application/x-www-form-urlencoded": http.StatusUnsupportedMediaType,
		"":                                  http.StatusUnsupportedMediaType,
		"application/json; charset=utf-8":   http.StatusOK,
	} {
		if rec := send(h, "POST", "/v1/ingest", validClaim, map[string]string{"Content-Type": ct}); rec.Code != want {
			t.Fatalf("content-type %q: status=%d want %d", ct, rec.Code, want)
		}
	}
	calls := fwd.calls
	if rec := send(h, "POST", "/v1/ingest/batch", "["+validClaim+"]", map[string]string{"Content-Type": "text/plain"}); rec.Code != http.StatusUnsupportedMediaType || fwd.calls != calls {
		t.Fatalf("text/plain batch: status=%d forwarded=%d", rec.Code, fwd.calls-calls)
	}
	var compact bytes.Buffer
	_ = json.Compact(&compact, []byte(validClaim))
	if rec := send(h, "POST", "/v1/ingest/batch", compact.String()+"\n", map[string]string{"Content-Type": "application/x-ndjson"}); rec.Code != http.StatusAccepted {
		t.Fatalf("ndjson batch: status=%d body=%s", rec.Code, rec.Body.String())
	}
	// "*" lifts the Host check (a proxy in front validates it)
	open := parseHostPolicy("*", "")
	if !open.allowsHost("anything.example.net") {
		t.Fatal("LOOM_ALLOWED_HOSTS=* must allow any host")
	}
}

// D-059: a batch bigger than the key's bucket can never pass — 413 with a
// reason, not a 429 a shipper would retry forever. LOOM_RATE_BURST sizes
// the default bucket.
func TestBatchLargerThanBurstIs413(t *testing.T) {
	fwd := &fakeForwarder{}
	h := guardedServer(t, fwd, "", func(c *config) { c.ratePerSec = 1; c.rateBurst = 3 })
	body := "[" + strings.Repeat(validClaim+",", 3) + validClaim + "]"
	rec := send(h, "POST", "/v1/ingest/batch", body, nil)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "burst of 3") || fwd.calls != 0 {
		t.Fatalf("status=%d body=%s forwarded=%d", rec.Code, rec.Body.String(), fwd.calls)
	}
	body = "[" + strings.Repeat(validClaim+",", 2) + validClaim + "]"
	if rec := send(h, "POST", "/v1/ingest/batch", body, nil); rec.Code != http.StatusAccepted || fwd.calls != 3 {
		t.Fatalf("batch of 3: status=%d forwarded=%d", rec.Code, fwd.calls)
	}
	if rec := send(h, "POST", "/v1/ingest/batch", "["+validClaim+"]", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("bucket drained: status=%d", rec.Code)
	}
}

// scriptedForwarder answers each forward with the next scripted status.
type scriptedForwarder struct {
	codes    []int
	bodies   []string
	payloads [][]byte
}

func (f *scriptedForwarder) forward(_ context.Context, _, _, _ string, payload []byte) (int, []byte, error) {
	i := len(f.payloads)
	f.payloads = append(f.payloads, payload)
	if i < len(f.codes) {
		return f.codes[i], []byte(f.bodies[i]), nil
	}
	return http.StatusOK, []byte(`{"status":"recorded"}`), nil
}

func (f *scriptedForwarder) close() {}

// D-059: in the HTTP-forward shape the engine's verdict per item is the
// outcome — an item it refused is "rejected" with its detail, not
// "recorded"; an engine 5xx is a 502 for the request (the sender retries;
// event_id dedupe absorbs what already landed).
func TestBatchForwardPropagatesEngineVerdicts(t *testing.T) {
	fwd := &scriptedForwarder{
		codes:  []int{http.StatusOK, http.StatusUnprocessableEntity, http.StatusForbidden},
		bodies: []string{`{"status":"recorded"}`, `{"detail":"predicate 'runs_os' takes a scalar"}`, `not json`},
	}
	h := guardedServer(t, fwd, "", nil)
	body := "[" + validClaim + "," + validClaim + "," + validClaim + "]"
	rec := send(h, "POST", "/v1/ingest/batch", body, nil)
	var out struct {
		Recorded, Rejected int
		Results            []struct{ Status, Detail string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if out.Recorded != 1 || out.Rejected != 2 || out.Results[1].Detail != "predicate 'runs_os' takes a scalar" ||
		!strings.Contains(out.Results[2].Detail, "HTTP 403") {
		t.Fatalf("results: %+v", out)
	}
	fwd = &scriptedForwarder{codes: []int{http.StatusServiceUnavailable}, bodies: []string{`{}`}}
	h = guardedServer(t, fwd, "", nil)
	if rec := send(h, "POST", "/v1/ingest/batch", body, nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("engine 503: status=%d", rec.Code)
	}
}

const validDoc = `{"kind": "document", "text": "report", "source": "auth-log",
  "observed_at": "2026-09-01T14:03:00Z", "attrs": {"team": "ir"}}`

// D-059: the uploader of a document is recorded by Loom, never by the
// sender. In the NATS shape the gateway stamps it (the writer sees only the
// principal header); in the HTTP shape the engine does, so the gateway
// forwards the bytes untouched. A sender-supplied stamp is refused.
func TestDocumentUploaderStamp(t *testing.T) {
	key := "loomk_docs"
	sum := sha256.Sum256([]byte(key))
	path := filepath.Join(t.TempDir(), "keys.json")
	doc := fmt.Sprintf(`{"keys":[{"id":"ir-shipper","sha256":"%x","namespaces":["default"],"perms":"w",
	  "entity_types":["host"]}]}`, sum)
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := &authConfig{path: path}
	if err := auth.reload(); err != nil {
		t.Fatal(err)
	}
	schema, err := newValidator("../contracts/schemas.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, nats := range []bool{true, false} {
		fwd := &scriptedForwarder{}
		cfg := config{maxBodyBytes: 1 << 20, maxBatch: 1000}
		if nats {
			cfg.natsURL = "nats://unused:4222"
		}
		h := newServer(cfg, schema, fwd, auth)
		rec := send(h, "POST", "/v1/ingest", validDoc, map[string]string{"X-Loom-Key": key})
		if rec.Code != http.StatusOK || len(fwd.payloads) != 1 {
			t.Fatalf("nats=%v: status=%d body=%s", nats, rec.Code, rec.Body.String())
		}
		var got struct {
			Attrs map[string]any `json:"attrs"`
			Text  string         `json:"text"`
		}
		if err := json.Unmarshal(fwd.payloads[0], &got); err != nil {
			t.Fatal(err)
		}
		stamp, stamped := got.Attrs[uploaderAttr].(map[string]any)
		if nats != stamped || got.Attrs["team"] != "ir" || got.Text != "report" {
			t.Fatalf("nats=%v: forwarded %s", nats, fwd.payloads[0])
		}
		if nats && (stamp["grant"] != "ir-shipper" || fmt.Sprint(stamp["entity_types"]) != "[host]") {
			t.Fatalf("stamp: %+v", stamp)
		}
		forged := strings.Replace(validDoc, `"team": "ir"`, `"loom.uploader": {"grant": "admin"}`, 1)
		rec = send(h, "POST", "/v1/ingest", forged, map[string]string{"X-Loom-Key": key})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "reserved") {
			t.Fatalf("nats=%v forged stamp: status=%d", nats, rec.Code)
		}
		rec = send(h, "POST", "/v1/ingest/batch", "["+forged+"]", map[string]string{"X-Loom-Key": key})
		if !strings.Contains(rec.Body.String(), "reserved") || len(fwd.payloads) != 1 {
			t.Fatalf("nats=%v forged stamp in a batch: %s", nats, rec.Body.String())
		}
	}
}
