package modsecurity

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// autheliaFirstFactorPath is Authelia’s first-factor login API (issue #13).
const autheliaFirstFactorPath = "/api/firstfactor"

// autheliaLoginBody is a typical username/password form POST, not a CRS probe.
const autheliaLoginBody = "username=alice&password=secret"

// TestPlugin_UpstreamIssue13_PostFirstFactorNeverEmits405 maps
// acouvreur/traefik-modsecurity-plugin#13: this plugin does not invent HTTP 405
// on Authelia’s login POST. An allow sidecar yields next; a sidecar 405 is
// copied as a block. Host and Traefik identity headers reach the sidecar as-is.
func TestPlugin_UpstreamIssue13_PostFirstFactorNeverEmits405(t *testing.T) {
	const portalHost = "auth.example.com"
	const priorXFF = "198.51.100.1"
	const realIP = "198.51.100.10"
	const clientRemote = "203.0.113.9:54321"

	tests := []struct {
		name             string
		sidecarStatus    int
		wantClientStatus int
		wantNext         bool
	}{
		{
			name:             "allow sidecar does not invent 405",
			sidecarStatus:    http.StatusOK,
			wantClientStatus: http.StatusOK,
			wantNext:         true,
		},
		{
			name:             "sidecar 405 is copied and next is skipped",
			sidecarStatus:    http.StatusMethodNotAllowed,
			wantClientStatus: http.StatusMethodNotAllowed,
			wantNext:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sawHost, sawForwarded, sawRealIP, sawMethod, sawPath, sawSidecarBody string
			waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sawHost = r.Host
				sawForwarded = r.Header.Get("X-Forwarded-For")
				sawRealIP = r.Header.Get("X-Real-Ip")
				sawMethod = r.Method
				sawPath = r.URL.Path
				body, _ := io.ReadAll(r.Body)
				sawSidecarBody = string(body)
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(tt.sidecarStatus)
				_, _ = io.WriteString(w, "sidecar-405-or-ok")
			}))
			t.Cleanup(waf.Close)

			cfg := CreateConfig()
			cfg.ModSecurityUrl = waf.URL
			plugin, err := New("issue-13-"+tt.name, cfg, NewLogger("issue-13-"+tt.name, cfg))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(plugin.Close)

			nextCalled := false
			route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				got, readErr := io.ReadAll(r.Body)
				if readErr != nil {
					t.Errorf("next ReadAll: %v", readErr)
				}
				if string(got) != autheliaLoginBody {
					t.Errorf("next body %q, want restored login POST", got)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "authelia-next")
			}))
			if err != nil {
				t.Fatalf("ForRoute: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "http://"+portalHost+autheliaFirstFactorPath, strings.NewReader(autheliaLoginBody))
			req.Host = portalHost
			req.RemoteAddr = clientRemote
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Forwarded-For", priorXFF)
			req.Header.Set("X-Real-Ip", realIP)
			rec := httptest.NewRecorder()
			route.ServeHTTP(rec, req)

			if rec.Code == http.StatusMethodNotAllowed && tt.sidecarStatus != http.StatusMethodNotAllowed {
				t.Fatal("plugin invented 405 on POST /api/firstfactor; issue #13 claim reproduced")
			}
			if rec.Code != tt.wantClientStatus {
				t.Fatalf("status %d, want %d", rec.Code, tt.wantClientStatus)
			}
			if nextCalled != tt.wantNext {
				t.Fatalf("next called=%v, want %v", nextCalled, tt.wantNext)
			}
			if sawMethod != http.MethodPost {
				t.Fatalf("sidecar method %q, want POST", sawMethod)
			}
			if sawPath != autheliaFirstFactorPath {
				t.Fatalf("sidecar path %q, want %s", sawPath, autheliaFirstFactorPath)
			}
			if sawSidecarBody != autheliaLoginBody {
				t.Fatalf("sidecar body %q, want login POST", sawSidecarBody)
			}
			if sawHost != portalHost {
				t.Fatalf("sidecar Host %q, want %q (not sidecar URL host)", sawHost, portalHost)
			}
			if sawForwarded != priorXFF {
				t.Fatalf("sidecar X-Forwarded-For %q, want copied %q (RemoteAddr not appended)", sawForwarded, priorXFF)
			}
			if sawRealIP != realIP {
				t.Fatalf("sidecar X-Real-Ip %q, want %q", sawRealIP, realIP)
			}
			if tt.wantNext && rec.Body.String() != "authelia-next" {
				t.Fatalf("body %q, want next", rec.Body.String())
			}
			if !tt.wantNext && rec.Body.String() != "sidecar-405-or-ok" {
				t.Fatalf("body %q, want copied sidecar page", rec.Body.String())
			}
		})
	}
}
