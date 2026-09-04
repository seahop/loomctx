package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeForwarder struct {
	kind    string
	payload []byte
	calls   int
}

func (f *fakeForwarder) forward(_ context.Context, kind, _ string, payload []byte) (int, []byte, error) {
	f.calls++
	f.kind = kind
	f.payload = payload
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
	return newServer(config{maxBodyBytes: 1 << 20}, schema, fwd, auth)
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
		req.Header.Set("X-Loom-Key", key)
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
	key := "loomk_gwtest"
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
	key := "loomk_rotateme"
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
		!strings.Contains(rec.Body.String(), "loom_gateway_requests_total 1") {
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
