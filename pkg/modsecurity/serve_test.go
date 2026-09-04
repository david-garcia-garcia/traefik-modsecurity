package modsecurity

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testWhoamiSizedBody stands in for traefik/whoami's typical allow-path body.
const testWhoamiSizedBody = "Hostname: dummy\nIP: 172.18.0.2\nRemoteAddr: 172.18.0.5:12345\nGET / HTTP/1.1\nHost: dummy\n"

func TestPlugin_SidecarResponseReusesConnection(t *testing.T) {
	tests := []struct {
		name             string
		wafStatus        int
		wantClientStatus int
		wantNext         bool
	}{
		{
			name:             "allow 200",
			wafStatus:        http.StatusOK,
			wantClientStatus: http.StatusOK,
			wantNext:         true,
		},
		{
			name:             "block 403",
			wafStatus:        http.StatusForbidden,
			wantClientStatus: http.StatusForbidden,
		},
		{
			name:             "failure 503",
			wafStatus:        http.StatusServiceUnavailable,
			wantClientStatus: http.StatusOK,
			wantNext:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var newConns atomic.Int64
			waf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(tt.wafStatus)
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
			plugin, err := New("reuse-test-"+tt.name, cfg, NewLogger("reuse-test-"+tt.name, cfg))
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
				if rec.Code != tt.wantClientStatus {
					t.Fatalf("request %d: status %d, want %d", i, rec.Code, tt.wantClientStatus)
				}
				if tt.wantNext {
					if rec.Body.String() != "next" {
						t.Fatalf("request %d: body %q, want next", i, rec.Body.String())
					}
				} else if rec.Body.String() == "next" {
					t.Fatalf("request %d: next ran, want sidecar-handled response", i)
				}
			}

			if got := newConns.Load(); got != 1 {
				t.Fatalf("new sidecar connections = %d, want 1 across %d requests", got, requests)
			}
		})
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

// TestPlugin_WafFailureDefaultFailOpen checks omitted failClosed fail-opens to next (200), never 502.
func TestPlugin_WafFailureDefaultFailOpen(t *testing.T) {
	tests := []struct {
		name        string
		backoffSecs int
		threshold   int
		setupWAF    func() (url string, cleanup func())
	}{
		{
			name:        "sidecar 503 without backoff",
			backoffSecs: 0,
			setupWAF: func() (string, func()) {
				waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(w, "sidecar down")
				}))
				return waf.URL, waf.Close
			},
		},
		{
			name:        "sidecar 500 without backoff",
			backoffSecs: 0,
			setupWAF: func() (string, func()) {
				waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = io.WriteString(w, "sidecar down")
				}))
				return waf.URL, waf.Close
			},
		},
		{
			name:        "transport error without backoff",
			backoffSecs: 0,
			setupWAF: func() (string, func()) {
				waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				url := waf.URL
				waf.Close()
				return url, func() {}
			},
		},
		{
			name:        "sidecar 503 below unhealthy threshold",
			backoffSecs: 30,
			threshold:   3,
			setupWAF: func() (string, func()) {
				waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				return waf.URL, waf.Close
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wafURL, cleanup := tt.setupWAF()
			t.Cleanup(cleanup)

			cfg := CreateConfig()
			cfg.ModSecurityUrl = wafURL
			cfg.UnhealthyWafBackOffPeriodSecs = tt.backoffSecs
			if tt.threshold > 0 {
				cfg.UnhealthyWafFailureThreshold = tt.threshold
			}
			cfg.ModSecurityStatusRequestHeader = "X-Waf-Status"
			plugin, err := New("waf-fail-open-"+tt.name, cfg, NewLogger("waf-fail-open-"+tt.name, cfg))
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

			if rec.Code == http.StatusBadGateway {
				t.Fatal("WAF failure must not return 502 Bad Gateway")
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, want 200 fail-open", rec.Code)
			}
			if !nextCalled {
				t.Fatal("next must run on WAF failure")
			}
			if rec.Body.String() != "next" {
				t.Fatalf("body %q, want next", rec.Body.String())
			}
			if got := req.Header.Get("X-Waf-Status"); got != "error" {
				t.Fatalf("status header %q, want error", got)
			}
		})
	}
}

// TestPlugin_FailClosedWafFailureReturns502 checks failClosed refuses the client and does not call next.
func TestPlugin_FailClosedWafFailureReturns502(t *testing.T) {
	tests := []struct {
		name     string
		setupWAF func() (url string, cleanup func())
	}{
		{
			name: "sidecar 503",
			setupWAF: func() (string, func()) {
				waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(w, "sidecar down")
				}))
				return waf.URL, waf.Close
			},
		},
		{
			name: "sidecar 500",
			setupWAF: func() (string, func()) {
				waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = io.WriteString(w, "sidecar down")
				}))
				return waf.URL, waf.Close
			},
		},
		{
			name: "transport error",
			setupWAF: func() (string, func()) {
				waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				url := waf.URL
				waf.Close()
				return url, func() {}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wafURL, cleanup := tt.setupWAF()
			t.Cleanup(cleanup)

			cfg := CreateConfig()
			cfg.ModSecurityUrl = wafURL
			cfg.FailClosed = true
			cfg.ModSecurityStatusRequestHeader = "X-Waf-Status"
			plugin, err := New("waf-fail-closed-"+tt.name, cfg, NewLogger("waf-fail-closed-"+tt.name, cfg))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(plugin.Close)

			nextCalled := false
			route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			}))
			if err != nil {
				t.Fatalf("ForRoute: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
			rec := httptest.NewRecorder()
			route.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status %d, want 502", rec.Code)
			}
			if nextCalled {
				t.Fatal("next must not run when failClosed")
			}
			if got := req.Header.Get("X-Waf-Status"); got != "error" {
				t.Fatalf("status header %q, want error", got)
			}
		})
	}
}

// TestPlugin_FailClosedUnhealthySkipReturns502 checks an already-unhealthy skip fail-closes without calling the sidecar.
func TestPlugin_FailClosedUnhealthySkipReturns502(t *testing.T) {
	sidecarCalls := 0
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sidecarCalls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.FailClosed = true
	cfg.UnhealthyWafBackOffPeriodSecs = 30
	cfg.UnhealthyWafFailureThreshold = 1
	cfg.ModSecurityStatusRequestHeader = "X-Waf-Status"
	plugin, err := New("waf-fail-closed-unhealthy", cfg, NewLogger("waf-fail-closed-unhealthy", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)

	nextCalled := 0
	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled++
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	first := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	firstRec := httptest.NewRecorder()
	route.ServeHTTP(firstRec, first)
	if firstRec.Code != http.StatusBadGateway {
		t.Fatalf("first status %d, want 502", firstRec.Code)
	}
	if sidecarCalls != 1 {
		t.Fatalf("sidecar calls %d, want 1 after first WAF failure", sidecarCalls)
	}

	second := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	secondRec := httptest.NewRecorder()
	route.ServeHTTP(secondRec, second)
	if secondRec.Code != http.StatusBadGateway {
		t.Fatalf("second status %d, want 502", secondRec.Code)
	}
	if sidecarCalls != 1 {
		t.Fatalf("sidecar calls %d, want 1 (unhealthy skip)", sidecarCalls)
	}
	if nextCalled != 0 {
		t.Fatalf("next called %d, want 0", nextCalled)
	}
	if got := second.Header.Get("X-Waf-Status"); got != "unhealthy" {
		t.Fatalf("status header %q, want unhealthy", got)
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

// TestPlugin_InboundDeadlineTripsHealth checks a request deadline while waiting on the sidecar counts as a WAF health failure.
func TestPlugin_InboundDeadlineTripsHealth(t *testing.T) {
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
	if !plugin.IsUnhealthy() {
		t.Fatal("inbound deadline must mark the WAF unhealthy")
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

// TestPlugin_Sidecar413DoesNotTripHealth checks a sidecar oversize-body 413 is a block, not a WAF health failure.
func TestPlugin_Sidecar413DoesNotTripHealth(t *testing.T) {
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = io.WriteString(w, "Request Entity Too Large")
	}))
	t.Cleanup(waf.Close)
	plugin, route := newTestHealthRoute(t, "sidecar-413-health", waf.URL, 2000)

	req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
	if rec.Body.String() != "Request Entity Too Large" {
		t.Fatalf("body %q, want sidecar 413 page", rec.Body.String())
	}
	if plugin.IsUnhealthy() {
		t.Fatal("sidecar 413 must not mark the WAF unhealthy")
	}
}

// TestPlugin_Sidecar5xxTripsHealth checks sidecar 5xx statuses count as WAF health failures.
func TestPlugin_Sidecar5xxTripsHealth(t *testing.T) {
	statuses := []struct {
		name   string
		status int
	}{
		{name: "500", status: http.StatusInternalServerError},
		{name: "503", status: http.StatusServiceUnavailable},
	}
	for _, tt := range statuses {
		t.Run(tt.name, func(t *testing.T) {
			waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, "sidecar down")
			}))
			t.Cleanup(waf.Close)
			plugin, route := newTestHealthRoute(t, "sidecar-5xx-health-"+tt.name, waf.URL, 2000)

			req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
			rec := httptest.NewRecorder()
			route.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, want fail-open 200", rec.Code)
			}
			if !plugin.IsUnhealthy() {
				t.Fatalf("sidecar %d must mark the WAF unhealthy", tt.status)
			}
		})
	}
}

// TestPlugin_Sidecar5xxFailOpenRestoresBody checks fail-open still gives next the inbound body already read for the sidecar.
func TestPlugin_Sidecar5xxFailOpenRestoresBody(t *testing.T) {
	const inboundBody = "payload-for-backend"
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.TimeoutMillis = 2000
	cfg.UnhealthyWafBackOffPeriodSecs = 30
	cfg.UnhealthyWafFailureThreshold = 1
	plugin, err := New("sidecar-5xx-restore-body", cfg, NewLogger("sidecar-5xx-restore-body", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)

	var gotBody string
	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("next ReadAll: %v", readErr)
		}
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example/protected", strings.NewReader(inboundBody))
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want fail-open 200", rec.Code)
	}
	if gotBody != inboundBody {
		t.Fatalf("next body %q, want %q", gotBody, inboundBody)
	}
	if !plugin.IsUnhealthy() {
		t.Fatal("sidecar 503 must mark the WAF unhealthy")
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
