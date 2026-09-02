package traefik_modsecurity

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serveIgnoredVerb drives one request and returns status plus bodies read by WAF and next.
func serveIgnoredVerb(t *testing.T, method string, payload []byte, deny bool) (status int, nextCalled bool, wafBody, nextBody []byte, nextContentLength int64, nextContentLengthHeader string) {
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
		nextContentLength = r.ContentLength
		nextContentLengthHeader = r.Header.Get("Content-Length")
		nextBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.IgnoreBodyForVerbsDeny = deny
	middleware, err := New(context.Background(), next, cfg, "ignored-verb-body-test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(method, "http://example/protected", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	return rec.Code, nextCalled, gotWaf, nextBody, nextContentLength, nextContentLengthHeader
}

// TestModsecurity_IgnoredVerbGetBodyIsWithheldFromNext checks default GET bodies never reach next.
func TestModsecurity_IgnoredVerbGetBodyIsWithheldFromNext(t *testing.T) {
	payload := []byte("attack-in-get-body")
	status, nextCalled, wafBody, nextBody, nextCL, nextCLHeader := serveIgnoredVerb(t, http.MethodGet, payload, false)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if !nextCalled {
		t.Fatal("next was not called")
	}
	if len(wafBody) != 0 {
		t.Fatalf("WAF body %q, want empty", wafBody)
	}
	if len(nextBody) != 0 {
		t.Fatalf("next body %q, want empty", nextBody)
	}
	if nextCL != 0 {
		t.Fatalf("next ContentLength %d, want 0", nextCL)
	}
	if nextCLHeader != "" {
		t.Fatalf("next Content-Length header %q, want empty", nextCLHeader)
	}
}

// TestModsecurity_IgnoredVerbDeleteBodyIsWithheldFromNext checks default DELETE bodies never reach next.
func TestModsecurity_IgnoredVerbDeleteBodyIsWithheldFromNext(t *testing.T) {
	payload := []byte("attack-in-delete-body")
	status, nextCalled, wafBody, nextBody, nextCL, nextCLHeader := serveIgnoredVerb(t, http.MethodDelete, payload, false)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if !nextCalled {
		t.Fatal("next was not called")
	}
	if len(wafBody) != 0 {
		t.Fatalf("WAF body %q, want empty", wafBody)
	}
	if len(nextBody) != 0 {
		t.Fatalf("next body %q, want empty", nextBody)
	}
	if nextCL != 0 {
		t.Fatalf("next ContentLength %d, want 0", nextCL)
	}
	if nextCLHeader != "" {
		t.Fatalf("next Content-Length header %q, want empty", nextCLHeader)
	}
}

// TestModsecurity_PostBodyIsInspectedAndForwarded checks POST still reaches WAF and next.
func TestModsecurity_PostBodyIsInspectedAndForwarded(t *testing.T) {
	payload := []byte("post-body")
	status, nextCalled, wafBody, nextBody, _, _ := serveIgnoredVerb(t, http.MethodPost, payload, false)
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

// TestModsecurity_IgnoredVerbDenyRejectsGetBody checks deny=true returns 400 for GET with a body.
func TestModsecurity_IgnoredVerbDenyRejectsGetBody(t *testing.T) {
	status, nextCalled, _, _, _, _ := serveIgnoredVerb(t, http.MethodGet, []byte("x"), true)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", status)
	}
	if nextCalled {
		t.Fatal("next must not be called")
	}
}

// tripWAFUnhealthyThenServe trips fail-open with a sidecar 503, then serves method+payload.
func tripWAFUnhealthyThenServe(t *testing.T, method string, payload []byte, deny bool) (status int, nextCalled bool, wafHits int, nextBody []byte, nextContentLength int64, nextContentLengthHeader string) {
	t.Helper()
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wafHits++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(waf.Close)

	nextCalled = false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		nextContentLength = r.ContentLength
		nextContentLengthHeader = r.Header.Get("Content-Length")
		nextBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.IgnoreBodyForVerbsDeny = deny
	cfg.UnhealthyWafBackOffPeriodSecs = 30
	cfg.UnhealthyWafFailureThreshold = 1
	middleware, err := New(context.Background(), next, cfg, "ignored-verb-unhealthy-test")
	if err != nil {
		t.Fatal(err)
	}

	trip := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	middleware.ServeHTTP(httptest.NewRecorder(), trip)
	wafHitsAfterTrip := wafHits
	nextCalled = false
	nextBody = nil
	nextContentLength = 0
	nextContentLengthHeader = ""

	req := httptest.NewRequest(method, "http://example/protected", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	if wafHits != wafHitsAfterTrip {
		t.Fatalf("sidecar hits %d after trip, want %d", wafHits, wafHitsAfterTrip)
	}
	return rec.Code, nextCalled, wafHits, nextBody, nextContentLength, nextContentLengthHeader
}

// TestModsecurity_IgnoredVerbGetBodyIsWithheldWhenWAFUnhealthy checks fail-open still withholds GET bodies from next.
func TestModsecurity_IgnoredVerbGetBodyIsWithheldWhenWAFUnhealthy(t *testing.T) {
	payload := []byte("attack-in-get-body")
	status, nextCalled, _, nextBody, nextCL, nextCLHeader := tripWAFUnhealthyThenServe(t, http.MethodGet, payload, false)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if !nextCalled {
		t.Fatal("next was not called")
	}
	if len(nextBody) != 0 {
		t.Fatalf("next body %q, want empty", nextBody)
	}
	if nextCL != 0 {
		t.Fatalf("next ContentLength %d, want 0", nextCL)
	}
	if nextCLHeader != "" {
		t.Fatalf("next Content-Length header %q, want empty", nextCLHeader)
	}
}

// TestModsecurity_IgnoredVerbDenyRejectsGetBodyWhenWAFUnhealthy checks deny=true still 400s on fail-open.
func TestModsecurity_IgnoredVerbDenyRejectsGetBodyWhenWAFUnhealthy(t *testing.T) {
	status, nextCalled, _, _, _, _ := tripWAFUnhealthyThenServe(t, http.MethodGet, []byte("x"), true)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", status)
	}
	if nextCalled {
		t.Fatal("next must not be called")
	}
}
