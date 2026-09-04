package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeForwarder struct {
	kind    string
	payload []byte
	calls   int
}

func (f *fakeForwarder) forward(_ context.Context, kind string, payload []byte) (int, []byte, error) {
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
	schema, err := newValidator("../contracts/schemas.json")
	if err != nil {
		t.Fatalf("loading schema: %v", err)
	}
	return newServer(config{maxBodyBytes: 1 << 20}, schema, fwd)
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

func TestOversizeBodyRejected(t *testing.T) {
	fwd := &fakeForwarder{}
	schema, err := newValidator("../contracts/schemas.json")
	if err != nil {
		t.Fatal(err)
	}
	h := newServer(config{maxBodyBytes: 64}, schema, fwd)
	rec := post(h, validClaim)
	if rec.Code != http.StatusRequestEntityTooLarge || fwd.calls != 0 {
		t.Fatalf("status = %d, calls = %d", rec.Code, fwd.calls)
	}
}
