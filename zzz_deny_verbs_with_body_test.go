package traefik_modsecurity

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serveWithDenyVerbs drives one request and returns status plus bodies read by WAF and next.
func serveWithDenyVerbs(t *testing.T, method string, payload []byte, denyVerbs []string) (status int, nextCalled bool, wafBody, nextBody []byte) {
	t.Helper()
	var gotWaf []byte
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotWaf, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(waf.Close)

	nextCalled = false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		nextBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	if denyVerbs != nil {
		cfg.DenyVerbsWithBody = denyVerbs
	}
	middleware, err := New(context.Background(), next, cfg, "deny-verbs-with-body-test")
	if err != nil {
		t.Fatal(err)
	}

	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	req := httptest.NewRequest(method, "http://example/protected", bodyReader)
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	return rec.Code, nextCalled, gotWaf, nextBody
}

// TestModsecurity_DefaultGetWithBodyIsRejected checks CreateConfig GET+body is HTTP 400.
func TestModsecurity_DefaultGetWithBodyIsRejected(t *testing.T) {
	status, nextCalled, wafBody, _ := serveWithDenyVerbs(t, http.MethodGet, []byte("attack-in-get-body"), nil)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", status)
	}
	if nextCalled {
		t.Fatal("next must not be called")
	}
	if len(wafBody) != 0 {
		t.Fatalf("sidecar body %q, want unused", wafBody)
	}
}

// TestModsecurity_DefaultDeleteWithBodyIsRejected checks CreateConfig DELETE+body is HTTP 400.
func TestModsecurity_DefaultDeleteWithBodyIsRejected(t *testing.T) {
	status, nextCalled, _, _ := serveWithDenyVerbs(t, http.MethodDelete, []byte("attack-in-delete-body"), nil)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", status)
	}
	if nextCalled {
		t.Fatal("next must not be called")
	}
}

// TestModsecurity_PostBodyIsInspectedAndForwarded checks POST is not on the default deny list.
func TestModsecurity_PostBodyIsInspectedAndForwarded(t *testing.T) {
	payload := []byte("post-body")
	status, nextCalled, wafBody, nextBody := serveWithDenyVerbs(t, http.MethodPost, payload, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if !nextCalled {
		t.Fatal("next was not called")
	}
	if string(wafBody) != string(payload) {
		t.Fatalf("WAF body %q, want %q", wafBody, payload)
	}
	if string(nextBody) != string(payload) {
		t.Fatalf("next body %q, want %q", nextBody, payload)
	}
}

// TestModsecurity_EmptyDenyListInspectsGetBody checks explicit empty denyVerbsWithBody forwards GET bodies.
func TestModsecurity_EmptyDenyListInspectsGetBody(t *testing.T) {
	payload := []byte("get-body-inspected")
	status, nextCalled, wafBody, nextBody := serveWithDenyVerbs(t, http.MethodGet, payload, []string{})
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if !nextCalled {
		t.Fatal("next was not called")
	}
	if string(wafBody) != string(payload) {
		t.Fatalf("WAF body %q, want %q", wafBody, payload)
	}
	if string(nextBody) != string(payload) {
		t.Fatalf("next body %q, want %q", nextBody, payload)
	}
}

// TestModsecurity_DefaultGetWithoutBodyIsAllowed checks empty GET still reaches next.
func TestModsecurity_DefaultGetWithoutBodyIsAllowed(t *testing.T) {
	status, nextCalled, _, _ := serveWithDenyVerbs(t, http.MethodGet, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if !nextCalled {
		t.Fatal("next was not called")
	}
}

// tripUnhealthyThenServe trips fail-open with a sidecar 503, then serves method+payload under default deny.
func tripUnhealthyThenServe(t *testing.T, method string, payload []byte) (status int, nextCalled bool) {
	t.Helper()
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(waf.Close)

	nextCalled = false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.UnhealthyWafBackOffPeriodSecs = 30
	cfg.UnhealthyWafFailureThreshold = 1
	middleware, err := New(context.Background(), next, cfg, "deny-verbs-unhealthy-test")
	if err != nil {
		t.Fatal(err)
	}

	trip := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	middleware.ServeHTTP(httptest.NewRecorder(), trip)
	nextCalled = false

	req := httptest.NewRequest(method, "http://example/protected", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	return rec.Code, nextCalled
}

// TestModsecurity_DefaultGetWithBodyIsRejectedWhenWAFUnhealthy checks deny still 400s on fail-open.
func TestModsecurity_DefaultGetWithBodyIsRejectedWhenWAFUnhealthy(t *testing.T) {
	status, nextCalled := tripUnhealthyThenServe(t, http.MethodGet, []byte("x"))
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", status)
	}
	if nextCalled {
		t.Fatal("next must not be called")
	}
}
