package modsecurity

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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

// TestPlugin_InboundCancelAbortsSidecarCall checks that canceling the inbound
// request context stops the sidecar call instead of waiting for timeoutMillis.
func TestPlugin_InboundCancelAbortsSidecarCall(t *testing.T) {
	started := make(chan struct{})
	waf := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		// Stay blocked until the client hangs up this sidecar request.
		<-r.Context().Done()
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.TimeoutMillis = 5000
	plugin, err := New("cancel-test", cfg, NewLogger("cancel-test", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		route.ServeHTTP(rec, req)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("sidecar did not receive the request")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ServeHTTP did not return after inbound cancel")
	}
}

// newTestHealthRoute builds a plugin with fail-open backoff enabled and a next that writes 200.
func newTestHealthRoute(t *testing.T, name, wafURL string, timeoutMillis int64) (*Plugin, http.Handler) {
	t.Helper()
	cfg := CreateConfig()
	cfg.ModSecurityUrl = wafURL
	cfg.TimeoutMillis = timeoutMillis
	cfg.UnhealthyWafBackOffPeriodSecs = 30
	cfg.UnhealthyWafFailureThreshold = 1
	plugin, err := New(name, cfg, NewLogger(name, cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}
	return plugin, route
}

// startTestBlockingWAF starts a sidecar that waits until its request context is done.
func startTestBlockingWAF(t *testing.T) (wafURL string, started <-chan struct{}) {
	t.Helper()
	ready := make(chan struct{})
	waf := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(ready)
		<-r.Context().Done()
	}))
	t.Cleanup(waf.Close)
	return waf.URL, ready
}

// TestPlugin_InboundCancelDoesNotTripHealth checks a client disconnect is not a WAF health failure.
func TestPlugin_InboundCancelDoesNotTripHealth(t *testing.T) {
	wafURL, started := startTestBlockingWAF(t)
	plugin, route := newTestHealthRoute(t, "cancel-health", wafURL, 5000)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		route.ServeHTTP(rec, req)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("sidecar did not receive the request")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ServeHTTP did not return after inbound cancel")
	}
	if plugin.IsUnhealthy() {
		t.Fatal("inbound cancel must not mark the WAF unhealthy")
	}
}

// TestPlugin_InboundDeadlineDoesNotTripHealth checks an inbound deadline is not a WAF health failure.
func TestPlugin_InboundDeadlineDoesNotTripHealth(t *testing.T) {
	wafURL, started := startTestBlockingWAF(t)
	plugin, route := newTestHealthRoute(t, "deadline-health", wafURL, 5000)

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	t.Cleanup(cancel)
	req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		route.ServeHTTP(rec, req)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("sidecar did not receive the request")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeHTTP did not return after inbound deadline")
	}
	if plugin.IsUnhealthy() {
		t.Fatal("inbound deadline must not mark the WAF unhealthy")
	}
}

// TestPlugin_ClientTimeoutTripsHealth checks timeoutMillis still counts as a WAF health failure.
func TestPlugin_ClientTimeoutTripsHealth(t *testing.T) {
	waf := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	t.Cleanup(waf.Close)
	plugin, route := newTestHealthRoute(t, "timeout-health", waf.URL, 150)

	req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if !plugin.IsUnhealthy() {
		t.Fatal("client timeout must mark the WAF unhealthy")
	}
}

// TestPlugin_UnreachableSidecarTripsHealth checks a live-inbound transport error still trips health.
func TestPlugin_UnreachableSidecarTripsHealth(t *testing.T) {
	plugin, route := newTestHealthRoute(t, "unreach-health", "http://127.0.0.1:1", 200)
	req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if !plugin.IsUnhealthy() {
		t.Fatal("unreachable sidecar must mark the WAF unhealthy")
	}
}

// TestPlugin_SidecarRequestCopiesHostAndForwardingHeaders checks Host is set and Traefik headers are copied as-is.
func TestPlugin_SidecarRequestCopiesHostAndForwardingHeaders(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		remoteAddr     string
		realIP         string
		priorForwarded string
		wantHost       string
		wantRealIP     string
		wantForwarded  string
	}{
		{
			name:          "host forwarded; remote addr does not invent xff",
			host:          "app.example",
			remoteAddr:    "203.0.113.9:54321",
			wantHost:      "app.example",
			wantForwarded: "",
		},
		{
			name:       "copies incoming x-real-ip",
			host:       "app.example",
			remoteAddr: "203.0.113.9:54321",
			realIP:     "198.51.100.10",
			wantHost:   "app.example",
			wantRealIP: "198.51.100.10",
		},
		{
			name:           "copies incoming xff without appending remote addr",
			host:           "app.example",
			remoteAddr:     "203.0.113.9:54321",
			priorForwarded: "198.51.100.10",
			wantHost:       "app.example",
			wantForwarded:  "198.51.100.10",
		},
		{
			name:           "copies both headers; remote addr stays off xff",
			host:           "app.example",
			remoteAddr:     "[2001:db8::1]:54321",
			realIP:         "198.51.100.10",
			priorForwarded: "203.0.113.9",
			wantHost:       "app.example",
			wantRealIP:     "198.51.100.10",
			wantForwarded:  "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sawHost, sawForwarded, sawRealIP string
			waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sawHost = r.Host
				sawForwarded = r.Header.Get("X-Forwarded-For")
				sawRealIP = r.Header.Get("X-Real-Ip")
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(waf.Close)

			cfg := CreateConfig()
			cfg.ModSecurityUrl = waf.URL
			plugin, err := New("host-copy-test", cfg, NewLogger("host-copy-test", cfg))
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

			req := httptest.NewRequest(http.MethodGet, "http://app.example/protected", nil)
			req.Host = tt.host
			req.RemoteAddr = tt.remoteAddr
			if tt.priorForwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.priorForwarded)
			}
			if tt.realIP != "" {
				req.Header.Set("X-Real-Ip", tt.realIP)
			}
			rec := httptest.NewRecorder()
			route.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, want 200", rec.Code)
			}
			if rec.Body.String() != "next" {
				t.Fatalf("body %q, want next", rec.Body.String())
			}
			if sawHost != tt.wantHost {
				t.Fatalf("sidecar Host = %q, want %q", sawHost, tt.wantHost)
			}
			if sawForwarded != tt.wantForwarded {
				t.Fatalf("sidecar X-Forwarded-For = %q, want %q", sawForwarded, tt.wantForwarded)
			}
			if sawRealIP != tt.wantRealIP {
				t.Fatalf("sidecar X-Real-Ip = %q, want %q", sawRealIP, tt.wantRealIP)
			}
		})
	}
}
