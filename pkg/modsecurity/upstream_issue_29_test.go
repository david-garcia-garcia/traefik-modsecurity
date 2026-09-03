package modsecurity

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Backend CORS + custom header from acouvreur/traefik-modsecurity-plugin#29.
// Reporter: allow-path client lost Access-Control-Allow-* (and other backend
// headers) while body/status survived.
const (
	issue29AllowOrigin  = "*"
	issue29AllowHeaders = "Content-Type, Authorization"
	issue29AllowMethods = "GET, POST, OPTIONS"
	issue29BackendID    = "php"
	issue29Body         = `{"ok":true}`
	issue29SidecarWaf   = "should-not-leak"
)

// issue29Backend writes the reporter's CORS set plus X-Backend.
func issue29Backend(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", issue29AllowOrigin)
	w.Header().Set("Access-Control-Allow-Headers", issue29AllowHeaders)
	w.Header().Set("Access-Control-Allow-Methods", issue29AllowMethods)
	w.Header().Set("X-Backend", issue29BackendID)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, issue29Body)
}

// issue29WAF is a sidecar allow (200) that also sets X-Waf so a leak is visible.
func issue29WAF(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("X-Waf", issue29SidecarWaf)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "sidecar allow")
}

// issue29NewRoute builds a Plugin route: WAF 200 sidecar, next is issue29Backend.
func issue29NewRoute(t *testing.T) http.Handler {
	t.Helper()
	waf := httptest.NewServer(http.HandlerFunc(issue29WAF))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	plugin, err := New("issue-29", cfg, NewLogger("issue-29", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)

	route, err := plugin.ForRoute(http.HandlerFunc(issue29Backend))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}
	return route
}

// issue29AssertClientHeaders fails unless status, body, CORS, and X-Backend match next and X-Waf is absent.
func issue29AssertClientHeaders(t *testing.T, h http.Header, body string, status int) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if body != issue29Body {
		t.Fatalf("body %q, want %q", body, issue29Body)
	}
	if got := h.Get("Access-Control-Allow-Origin"); got != issue29AllowOrigin {
		t.Fatalf("Access-Control-Allow-Origin %q, want %q", got, issue29AllowOrigin)
	}
	if got := h.Get("Access-Control-Allow-Headers"); got != issue29AllowHeaders {
		t.Fatalf("Access-Control-Allow-Headers %q, want %q", got, issue29AllowHeaders)
	}
	if got := h.Get("Access-Control-Allow-Methods"); got != issue29AllowMethods {
		t.Fatalf("Access-Control-Allow-Methods %q, want %q", got, issue29AllowMethods)
	}
	if got := h.Get("X-Backend"); got != issue29BackendID {
		t.Fatalf("X-Backend %q, want %q", got, issue29BackendID)
	}
	if got := h.Get("X-Waf"); got != "" {
		t.Fatalf("sidecar X-Waf leaked onto client: %q", got)
	}
}

// TestPlugin_UpstreamIssue29_AllowPathKeepsBackendHeaders maps
// acouvreur/traefik-modsecurity-plugin#29: WAF 200, next sets CORS and
// X-Backend. Both a real net/http ResponseWriter (httptest.NewServer,
// implements requestTooLarge) and httptest.Recorder must keep those
// headers. Sidecar headers must not overlay the client.
func TestPlugin_UpstreamIssue29_AllowPathKeepsBackendHeaders(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodOptions, http.MethodPost}

	t.Run("real ResponseWriter", func(t *testing.T) {
		front := httptest.NewServer(issue29NewRoute(t))
		t.Cleanup(front.Close)

		for _, method := range methods {
			t.Run(method, func(t *testing.T) {
				var body io.Reader
				if method == http.MethodPost {
					body = strings.NewReader("name=alice")
				}
				req, err := http.NewRequest(method, front.URL+"/api", body)
				if err != nil {
					t.Fatalf("NewRequest: %v", err)
				}
				if method == http.MethodPost {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("Do: %v", err)
				}
				defer func() { _ = resp.Body.Close() }()
				got, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("ReadAll: %v", err)
				}
				issue29AssertClientHeaders(t, resp.Header, string(got), resp.StatusCode)
			})
		}
	})

	t.Run("recorder", func(t *testing.T) {
		route := issue29NewRoute(t)
		for _, method := range methods {
			t.Run(method, func(t *testing.T) {
				var body io.Reader
				if method == http.MethodPost {
					body = strings.NewReader("name=alice")
				}
				req := httptest.NewRequest(method, "http://example/api", body)
				if method == http.MethodPost {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				rec := httptest.NewRecorder()
				route.ServeHTTP(rec, req)
				issue29AssertClientHeaders(t, rec.Header(), rec.Body.String(), rec.Code)
			})
		}
	})
}
