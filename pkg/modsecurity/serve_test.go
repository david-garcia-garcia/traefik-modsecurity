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
