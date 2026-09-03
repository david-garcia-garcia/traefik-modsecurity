package modsecurity

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// largeNonFileFormBody is a text form POST (not multipart / not a file).
// Size is above the default pool cap so readInboundBody uses the ad-hoc path,
// same class as the reporter's ~8 MiB base64-in-form body.
const largeNonFileFormBodyBytes = 6 * 1024 * 1024

// TestPlugin_UpstreamIssue11_LargeNonFileBodyNeverReturns500 maps
// acouvreur/traefik-modsecurity-plugin#11: a large non-file body must not
// become a client 500. Plugin oversize is 413; sidecar 413 is a block;
// sidecar 5xx is a WAF failure (502), never a forwarded 500.
func TestPlugin_UpstreamIssue11_LargeNonFileBodyNeverReturns500(t *testing.T) {
	body := strings.Repeat("a", largeNonFileFormBodyBytes)

	tests := []struct {
		name             string
		maxBody          int64
		sidecarStatus    int
		wantClientStatus int
		wantHeader       string
		wantNext         bool
		wantSidecarHit   bool
	}{
		{
			name:             "plugin cap exceeded is 413 not 500",
			maxBody:          1024,
			sidecarStatus:    http.StatusOK,
			wantClientStatus: http.StatusRequestEntityTooLarge,
			wantHeader:       "blocked",
			wantNext:         false,
			wantSidecarHit:   false,
		},
		{
			name:             "sidecar 413 (NoFilesLimit) is copied as a block",
			maxBody:          10 * 1024 * 1024,
			sidecarStatus:    http.StatusRequestEntityTooLarge,
			wantClientStatus: http.StatusRequestEntityTooLarge,
			wantHeader:       "blocked",
			wantNext:         false,
			wantSidecarHit:   true,
		},
		{
			name:             "sidecar 500 is 502 WAF failure not a copied 500",
			maxBody:          10 * 1024 * 1024,
			sidecarStatus:    http.StatusInternalServerError,
			wantClientStatus: http.StatusBadGateway,
			wantHeader:       "error",
			wantNext:         false,
			wantSidecarHit:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sidecarHits int
			waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sidecarHits++
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(tt.sidecarStatus)
				_, _ = io.WriteString(w, "sidecar page")
			}))
			t.Cleanup(waf.Close)

			cfg := CreateConfig()
			cfg.ModSecurityUrl = waf.URL
			cfg.MaxBodySizeBytes = tt.maxBody
			cfg.MaxBodySizeBytesForPool = 5 * 1024 * 1024
			cfg.UnhealthyWafBackOffPeriodSecs = 0
			cfg.ModSecurityStatusRequestHeader = "X-Waf-Status"
			plugin, err := New("issue-11-"+tt.name, cfg, NewLogger("issue-11-"+tt.name, cfg))
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

			req := httptest.NewRequest(http.MethodPost, "http://example/form", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			route.ServeHTTP(rec, req)

			if rec.Code == http.StatusInternalServerError {
				t.Fatalf("client status 500; issue #11 claim reproduced")
			}
			if rec.Code != tt.wantClientStatus {
				t.Fatalf("status %d, want %d", rec.Code, tt.wantClientStatus)
			}
			if got := req.Header.Get("X-Waf-Status"); got != tt.wantHeader {
				t.Fatalf("status header %q, want %q", got, tt.wantHeader)
			}
			if nextCalled != tt.wantNext {
				t.Fatalf("next called=%v, want %v", nextCalled, tt.wantNext)
			}
			if (sidecarHits > 0) != tt.wantSidecarHit {
				t.Fatalf("sidecar hits=%d, want hit=%v", sidecarHits, tt.wantSidecarHit)
			}
		})
	}
}
