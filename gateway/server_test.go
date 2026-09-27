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

type fakeForwarder struct {
	kind      string
	payload   []byte
	principal string
	calls     int
}

func (f *fakeForwarder) forward(_ context.Context, kind, _, principal string, payload []byte) (int, []byte, error) {
	f.calls++
	f.kind = kind
	f.payload = payload
	f.principal = principal
	return http.StatusOK, []byte(`{"status":"recorded"}`), nil
}

func (f *fakeForwarder) close() {}

const validClaim = `{
  "kind": "claim",
  "subject": {"type": "host", "key": "web-01"},
  "predicate": "logged_in_by",
  "object": {"type": "user", "key": "jdoe"},
  "observed_at": "2026-09-01T14:03:00Z",
  "source": "auth-log"
}`

func testServer(t *testing.T, fwd forwarder) http.Handler {
	t.Helper()
	return testServerAuth(t, fwd, "")
}

func testServerAuth(t *testing.T, fwd forwarder, keys string) http.Handler {
	t.Helper()
	schema, err := newValidator("../contracts/schemas.json")
	if err != nil {
		t.Fatalf("loading schema: %v", err)
	}
	auth, err := parseAuth(keys)
	if err != nil {
		t.Fatalf("parsing keys: %v", err)
	}
	return newServer(config{maxBodyBytes: 1 << 20, maxBatch: 1000}, schema, fwd, auth)
}

func post(h http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestValidClaimIsForwardedWithKind(t *testing.T) {
	fwd := &fakeForwarder{}
	rec := post(testServer(t, fwd), validClaim)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if fwd.calls != 1 || fwd.kind != "claim" {
		t.Fatalf("forwarder calls=%d kind=%q", fwd.calls, fwd.kind)
	}
}

func TestValidDocumentIsForwarded(t *testing.T) {
	fwd := &fakeForwarder{}
	doc := `{"kind":"document","text":"report","source":"ir-pipeline",
	         "observed_at":"2026-09-02T09:00:00Z"}`
	rec := post(testServer(t, fwd), doc)
	if rec.Code != http.StatusOK || fwd.kind != "document" {
		t.Fatalf("status=%d kind=%q body=%s", rec.Code, fwd.kind, rec.Body.String())
	}
}

func TestContractViolationIsRejectedBeforeForwarding(t *testing.T) {
	fwd := &fakeForwarder{}
	// confidence above the contract's maximum of 1.0
	bad := strings.Replace(validClaim, `"source": "auth-log"`,
		`"source": "auth-log", "confidence": 2.5`, 1)
	rec := post(testServer(t, fwd), bad)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", rec.Code, rec.Body.String())
	}
	if fwd.calls != 0 {
		t.Fatal("invalid envelope must not reach the forwarder")
	}
}

func TestGarbageJSONRejected(t *testing.T) {
	fwd := &fakeForwarder{}
	rec := post(testServer(t, fwd), "{not json")
	if rec.Code != http.StatusBadRequest || fwd.calls != 0 {
		t.Fatalf("status = %d, calls = %d", rec.Code, fwd.calls)
	}
}

func TestMissingKindRejected(t *testing.T) {
	fwd := &fakeForwarder{}
	noKind := strings.Replace(validClaim, `"kind": "claim",`, "", 1)
	rec := post(testServer(t, fwd), noKind)
	if rec.Code != http.StatusUnprocessableEntity || fwd.calls != 0 {
		t.Fatalf("status = %d, calls = %d, body = %s", rec.Code, fwd.calls, rec.Body.String())
	}
}

func postWithKey(h http.Handler, body, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest", strings.NewReader(body))
	if key != "" {
		req.Header.Set("X-LoomCtx-Key", key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// validClaim has no explicit namespace, so it lands in "default".
const authKeys = "agentsecret:default:w,readonly:default:r,other:elsewhere:w"

func TestAuthMissingKeyIs401BeforeValidation(t *testing.T) {
	fwd := &fakeForwarder{}
	rec := postWithKey(testServerAuth(t, fwd, authKeys), validClaim, "")
	if rec.Code != http.StatusUnauthorized || fwd.calls != 0 {
		t.Fatalf("status=%d calls=%d", rec.Code, fwd.calls)
	}
}

func TestAuthWrongPermsOrNamespaceIs403(t *testing.T) {
	fwd := &fakeForwarder{}
	h := testServerAuth(t, fwd, authKeys)
	for _, key := range []string{"readonly", "other", "nonsense"} {
		rec := postWithKey(h, validClaim, key)
		if rec.Code != http.StatusForbidden || fwd.calls != 0 {
			t.Fatalf("key %q: status=%d calls=%d", key, rec.Code, fwd.calls)
		}
	}
}

func TestAuthValidKeyForwards(t *testing.T) {
	fwd := &fakeForwarder{}
	rec := postWithKey(testServerAuth(t, fwd, authKeys), validClaim, "agentsecret")
	if rec.Code != http.StatusOK || fwd.calls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", rec.Code, fwd.calls, rec.Body.String())
	}
	// the principal (grant id) is attributed, the key itself never travels
	if fwd.principal != "env-0" {
		t.Fatalf("principal = %q, want env-0", fwd.principal)
	}
}

func TestWildcardNamespaceKey(t *testing.T) {
	fwd := &fakeForwarder{}
	rec := postWithKey(testServerAuth(t, fwd, "root:*:rw"), validClaim, "root")
	if rec.Code != http.StatusOK || fwd.calls != 1 {
		t.Fatalf("status=%d calls=%d", rec.Code, fwd.calls)
	}
}

func TestPerKeyRateLimit(t *testing.T) {
	fwd := &fakeForwarder{}
	schema, err := newValidator("../contracts/schemas.json")
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := parseAuth(authKeys)
	h := newServer(config{maxBodyBytes: 1 << 20, ratePerSec: 1}, schema, fwd, auth)
	first := postWithKey(h, validClaim, "agentsecret")
	second := postWithKey(h, validClaim, "agentsecret")
	if first.Code != http.StatusOK || second.Code != http.StatusTooManyRequests {
		t.Fatalf("first=%d second=%d", first.Code, second.Code)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
}

func TestScopedFileKeyGates(t *testing.T) {
	key := "loomctxk_gwtest"
	sum := sha256.Sum256([]byte(key))
	doc := fmt.Sprintf(`{"keys":[{"id":"shipper","sha256":"%x",
	  "namespaces":["default"],"perms":"w",
	  "entity_types":["host","user"],"sources":["auth-log"]}]}`, sum)
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := &authConfig{path: path}
	if err := auth.reload(); err != nil {
		t.Fatal(err)
	}
	fwd := &fakeForwarder{}
	schema, err := newValidator("../contracts/schemas.json")
	if err != nil {
		t.Fatal(err)
	}
	h := newServer(config{maxBodyBytes: 1 << 20}, schema, fwd, auth)

	if rec := postWithKey(h, validClaim, key); rec.Code != http.StatusOK {
		t.Fatalf("in-scope claim: %d %s", rec.Code, rec.Body.String())
	}
	forged := strings.Replace(validClaim, `"source": "auth-log"`,
		`"source": "forged-feed"`, 1)
	if rec := postWithKey(h, forged, key); rec.Code != http.StatusForbidden {
		t.Fatalf("forged source must be 403, got %d", rec.Code)
	}
	outOfScope := strings.Replace(validClaim, `{"type": "host"`,
		`{"type": "vendor"`, 1)
	if rec := postWithKey(h, outOfScope, key); rec.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope entity type must be 403, got %d", rec.Code)
	}
	if fwd.calls != 1 {
		t.Fatalf("only the in-scope claim may be forwarded, got %d", fwd.calls)
	}
}

func TestKeysFileHotReload(t *testing.T) {
	key := "loomctxk_rotateme"
	sum := sha256.Sum256([]byte(key))
	path := filepath.Join(t.TempDir(), "keys.json")
	entry := func(disabled bool) string {
		return fmt.Sprintf(`{"keys":[{"id":"k","sha256":"%x",
		  "namespaces":["*"],"perms":"rw","disabled":%v}]}`, sum, disabled)
	}
	if err := os.WriteFile(path, []byte(entry(false)), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := &authConfig{path: path}
	if err := auth.reload(); err != nil {
		t.Fatal(err)
	}
	if auth.grantFor(key) == nil {
		t.Fatal("key should resolve before revocation")
	}
	if err := os.WriteFile(path, []byte(entry(true)), 0o600); err != nil {
		t.Fatal(err)
	}
	// force an mtime difference regardless of filesystem resolution
	future := auth.mtime.Add(2e9)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if auth.grantFor(key) != nil {
		t.Fatal("revoked key must stop resolving after hot reload")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	h := testServer(t, &fakeForwarder{})
	post(h, validClaim)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "loomctx_gateway_requests_total 1") {
		t.Fatalf("metrics: %d %s", rec.Code, rec.Body.String())
	}
}

func TestOversizeBodyRejected(t *testing.T) {
	fwd := &fakeForwarder{}
	schema, err := newValidator("../contracts/schemas.json")
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := parseAuth("")
	h := newServer(config{maxBodyBytes: 64}, schema, fwd, auth)
	rec := post(h, validClaim)
	if rec.Code != http.StatusRequestEntityTooLarge || fwd.calls != 0 {
		t.Fatalf("status = %d, calls = %d", rec.Code, fwd.calls)
	}
}

// H-A4: an unauthenticated caller rotating bogus keys must neither bypass
// the limiter nor grow the bucket map; buckets belong to real principals.
func TestUnknownKeysGetNoBuckets(t *testing.T) {
	fwd := &fakeForwarder{}
	schema, err := newValidator("../contracts/schemas.json")
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := parseAuth(authKeys)
	limiters := newLimiterPool(1)
	h := newServerWithLimiters(config{maxBodyBytes: 1 << 20, ratePerSec: 1}, schema, fwd, auth, limiters)
	for i := 0; i < 25; i++ {
		rec := postWithKey(h, validClaim, fmt.Sprintf("bogus-%d", i))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("bogus key %d: status=%d", i, rec.Code)
		}
	}
	if limiters.size() != 0 {
		t.Fatalf("bogus keys created %d buckets", limiters.size())
	}
	// the same principal presenting its key twice shares ONE bucket
	first := postWithKey(h, validClaim, "agentsecret")
	second := postWithKey(h, validClaim, "agentsecret")
	if first.Code != http.StatusOK || second.Code != http.StatusTooManyRequests {
		t.Fatalf("first=%d second=%d", first.Code, second.Code)
	}
	if limiters.size() != 1 {
		t.Fatalf("expected 1 bucket, got %d", limiters.size())
	}
}

// R-10: a key's own rate_per_sec / rate_burst cap that principal even when
// LOOMCTX_RATE_PER_SEC is unset; keys without the fields stay unlimited, and
// a zero rate is a bad entry (skipped), not "unlimited".
func TestPerKeyRateOverride(t *testing.T) {
	fwd := &fakeForwarder{}
	schema, err := newValidator("../contracts/schemas.json")
	if err != nil {
		t.Fatal(err)
	}
	capped, plain, zero := "loomctxk_capped", "loomctxk_plain", "loomctxk_zero"
	sumC, sumP, sumZ := sha256.Sum256([]byte(capped)), sha256.Sum256([]byte(plain)), sha256.Sum256([]byte(zero))
	doc := fmt.Sprintf(`{"keys":[
	  {"id":"capped","sha256":"%x","namespaces":["default"],"perms":"w","rate_per_sec":1,"rate_burst":2,"rate_llm_per_sec":0.5},
	  {"id":"plain","sha256":"%x","namespaces":["default"],"perms":"w"},
	  {"id":"zero","sha256":"%x","namespaces":["default"],"perms":"w","rate_per_sec":0}
	]}`, sumC, sumP, sumZ)
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOOMCTX_AUTH_FILE", path)
	auth, err := loadAuth()
	if err != nil {
		t.Fatal(err)
	}
	if g := auth.grantFor(capped); g == nil || g.ID != "capped" || g.RatePerSec == nil || *g.RateBurst != 2 {
		t.Fatalf("capped grant not parsed: %+v", g)
	}
	if g := auth.grantFor(zero); g != nil {
		t.Fatalf("rate_per_sec 0 must disable that entry, got %+v", g)
	}
	limiters := newLimiterPool(0) // no default limit
	h := newServerWithLimiters(config{maxBodyBytes: 1 << 20}, schema, fwd, auth, limiters)
	codes := []int{}
	for i := 0; i < 3; i++ {
		codes = append(codes, postWithKey(h, validClaim, capped).Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("capped key: %v", codes)
	}
	for i := 0; i < 10; i++ {
		if rec := postWithKey(h, validClaim, plain); rec.Code != http.StatusOK {
			t.Fatalf("plain key request %d: %d", i, rec.Code)
		}
	}
	if limiters.size() != 1 {
		t.Fatalf("only the capped key should hold a bucket, got %d", limiters.size())
	}
}

// H-A5/H-A13: a bad entry disables only itself; naive expires is UTC.
func TestKeysFileToleratesBadEntries(t *testing.T) {
	good := "loomctxk_good"
	sum := sha256.Sum256([]byte(good))
	doc := fmt.Sprintf(`{"keys":[
	  {"id":"broken","sha256":"nothex","namespaces":["default"],"perms":"w"},
	  {"id":"noperms","sha256":"%x","namespaces":["default"]},
	  {"id":"expired","sha256":"%x","namespaces":["default"],"perms":"w","expires":"2001-01-01T00:00:00"},
	  {"id":"ok","sha256":"%x","namespaces":["default"],"perms":"w","expires":"2099-01-01T00:00:00"}
	]}`, sum, sum, sum)
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOOMCTX_AUTH_FILE", path)
	auth, err := loadAuth()
	if err != nil {
		t.Fatalf("a bad entry must not fail the whole file: %v", err)
	}
	g := auth.grantFor(good)
	if g == nil || g.ID != "ok" {
		t.Fatalf("expected the 'ok' grant, got %+v", g)
	}
}


// D-034: batch ingest — array and NDJSON, per-item outcomes, gates per item.
func TestBatchIngestArrayAndNDJSON(t *testing.T) {
	fwd := &fakeForwarder{}
	h := testServerAuth(t, fwd, authKeys)
	bad := `{"kind": "claim", "predicate": "broken"}`
	other := strings.Replace(validClaim, `"kind": "claim",`, `"kind": "claim", "namespace": "elsewhere",`, 1)
	body := "[" + validClaim + "," + bad + "," + other + "," + validClaim + "]"
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LoomCtx-Key", "agentsecret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Total, Recorded, Rejected int
		Results                   []struct {
			Index  int
			Status string
			Detail string
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 4 || out.Recorded != 2 || out.Rejected != 2 || fwd.calls != 2 {
		t.Fatalf("total=%d recorded=%d rejected=%d forwarded=%d", out.Total, out.Recorded, out.Rejected, fwd.calls)
	}
	if out.Results[1].Status != "rejected" || !strings.Contains(out.Results[1].Detail, "contract violation") {
		t.Fatalf("item 1: %+v", out.Results[1])
	}
	if out.Results[2].Status != "rejected" || !strings.Contains(out.Results[2].Detail, "namespace") {
		t.Fatalf("item 2: %+v", out.Results[2])
	}
	// NDJSON: one envelope per line (the fixture is pretty-printed, so compact it)
	fwd.calls = 0
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(validClaim)); err != nil {
		t.Fatal(err)
	}
	nd := compact.String() + "\n" + compact.String() + "\n"
	req = httptest.NewRequest(http.MethodPost, "/v1/ingest/batch", strings.NewReader(nd))
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("X-LoomCtx-Key", "agentsecret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || fwd.calls != 2 {
		t.Fatalf("ndjson: status=%d forwarded=%d body=%s", rec.Code, fwd.calls, rec.Body.String())
	}
	// no key at all -> 401 for the whole request
	req = httptest.NewRequest(http.MethodPost, "/v1/ingest/batch", strings.NewReader(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key: status=%d", rec.Code)
	}
}
