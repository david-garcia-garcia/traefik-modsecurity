package modsecurity

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

// TestPlugin_SidecarRequestUsesIncomingHostAndForwardedFor checks the mock WAF sees incoming Host and appended X-Forwarded-For.
func TestPlugin_SidecarRequestUsesIncomingHostAndForwardedFor(t *testing.T) {
	tests := []struct {
		name             string
		host             string
		remoteAddr       string
		priorForwarded   string
		wantHost         string
		wantForwarded    string
		wantForwardedSet bool
	}{
		{
			name:             "original host and first hop",
			host:             "app.example",
			remoteAddr:       "203.0.113.9:54321",
			wantHost:         "app.example",
			wantForwarded:    "203.0.113.9",
			wantForwardedSet: true,
		},
		{
			name:             "appends peer to existing chain",
			host:             "app.example",
			remoteAddr:       "203.0.113.9:54321",
			priorForwarded:   "198.51.100.10",
			wantHost:         "app.example",
			wantForwarded:    "198.51.100.10, 203.0.113.9",
			wantForwardedSet: true,
		},
		{
			name:             "ipv6 peer is unbracketed host",
			host:             "app.example",
			remoteAddr:       "[2001:db8::1]:54321",
			wantHost:         "app.example",
			wantForwarded:    "2001:db8::1",
			wantForwardedSet: true,
		},
		{
			name:             "unparseable remote addr leaves existing xff",
			host:             "app.example",
			remoteAddr:       "not-a-host-port",
			priorForwarded:   "198.51.100.10",
			wantHost:         "app.example",
			wantForwarded:    "198.51.100.10",
			wantForwardedSet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sawHost, sawForwarded string
			waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sawHost = r.Host
				sawForwarded = r.Header.Get("X-Forwarded-For")
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(waf.Close)

			cfg := CreateConfig()
			cfg.ModSecurityUrl = waf.URL
			plugin, err := New("host-xff-test", cfg, NewLogger("host-xff-test", cfg))
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
			if tt.wantForwardedSet && sawForwarded != tt.wantForwarded {
				t.Fatalf("sidecar X-Forwarded-For = %q, want %q", sawForwarded, tt.wantForwarded)
			}
		})
	}
}
