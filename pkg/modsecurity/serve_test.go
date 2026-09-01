package modsecurity

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// testWhoamiSizedBody stands in for traefik/whoami's typical allow-path body.
const testWhoamiSizedBody = "Hostname: dummy\nIP: 172.18.0.2\nRemoteAddr: 172.18.0.5:12345\nGET / HTTP/1.1\nHost: dummy\n"

func TestPlugin_AllowPathReusesSidecarConnection(t *testing.T) {
	var newConns atomic.Int64
	waf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, testWhoamiSizedBody)
	}))
	waf.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	waf.Start()
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	plugin, err := New("reuse-test", cfg, NewLogger("reuse-test", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "next")
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	const requests = 20
	for i := 0; i < requests; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
		rec := httptest.NewRecorder()
		route.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, rec.Code)
		}
		if rec.Body.String() != "next" {
			t.Fatalf("request %d: body %q, want next", i, rec.Body.String())
		}
	}

	if got := newConns.Load(); got != 1 {
		t.Fatalf("new sidecar connections = %d, want 1 across %d allows", got, requests)
	}
}

func TestPlugin_BlockPathStripsHopByHopAndServer(t *testing.T) {
	const blockBody = "sidecar error page"
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Connection", "close")
		w.Header().Set("Proxy-Authenticate", "Basic")
		w.Header().Set("Server", "Apache")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, blockBody)
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	plugin, err := New("block-header-test", cfg, NewLogger("block-header-test", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)

	nextCalled := false
	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "next")
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("next was called on a block")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if rec.Body.String() != blockBody {
		t.Fatalf("body %q, want %q", rec.Body.String(), blockBody)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html" {
		t.Fatalf("Content-Type %q, want text/html", got)
	}
	if got := rec.Header().Get("Server"); got != "" {
		t.Fatalf("Server %q, want empty", got)
	}
	if got := rec.Header().Get("Connection"); got != "" {
		t.Fatalf("Connection %q, want empty", got)
	}
	if got := rec.Header().Get("Proxy-Authenticate"); got != "" {
		t.Fatalf("Proxy-Authenticate %q, want empty", got)
	}
}

func TestForwardResponse_StripsHopByHopAndServer(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header: http.Header{
			"Content-Type":       []string{"text/html"},
			"Connection":         []string{"close, X-Sidecar-Hop"},
			"X-Sidecar-Hop":      []string{"1"},
			"Proxy-Authenticate": []string{"Basic"},
			"Keep-Alive":         []string{"timeout=5"},
			"Transfer-Encoding":  []string{"chunked"},
			"Upgrade":            []string{"websocket"},
			"Te":                 []string{"trailers"},
			"Trailer":            []string{"Expires"},
			"Server":             []string{"Apache"},
			"Set-Cookie":         []string{"sid=1"},
		},
		Body: io.NopCloser(strings.NewReader("sidecar error page")),
	}
	rec := httptest.NewRecorder()
	forwardResponse(resp, rec)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if rec.Body.String() != "sidecar error page" {
		t.Fatalf("body %q, want sidecar error page", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html" {
		t.Fatalf("Content-Type %q, want text/html", got)
	}
	if got := rec.Header().Get("Set-Cookie"); got != "sid=1" {
		t.Fatalf("Set-Cookie %q, want sid=1", got)
	}
	for _, name := range []string{
		"Connection", "X-Sidecar-Hop", "Proxy-Authenticate", "Keep-Alive",
		"Transfer-Encoding", "Upgrade", "Te", "Trailer", "Server",
	} {
		if got := rec.Header().Get(name); got != "" {
			t.Fatalf("%s %q, want empty", name, got)
		}
	}
}
