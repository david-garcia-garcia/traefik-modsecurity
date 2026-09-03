package modsecurity

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestPlugin_BypassRules asserts method/path match, miss, method-only, path-only, unanchored substring skip, operator exact anchor, header token, and inspect-when-empty.
func TestPlugin_BypassRules(t *testing.T) {
	tests := []struct {
		name         string
		bypassRules  []BypassRule
		method       string
		path         string
		headerName   string
		wantWAF      bool
		wantHeader   string
		wantNoHeader bool
	}{
		{
			name:        "method and path match skips WAF",
			bypassRules: []BypassRule{{Method: http.MethodGet, PathRegexp: `/search/v1/statement/executing/`}},
			method:      http.MethodGet,
			path:        "/search/v1/statement/executing/abc123",
			headerName:  "X-Waf-Status",
			wantHeader:  bypassStatusToken,
		},
		{
			name:        "method miss still inspects",
			bypassRules: []BypassRule{{Method: http.MethodGet, PathRegexp: `/search/v1/statement/executing/`}},
			method:      http.MethodPost,
			path:        "/search/v1/statement/executing/abc123",
			headerName:  "X-Waf-Status",
			wantWAF:     true,
			wantHeader:  "ok",
		},
		{
			name:        "path miss still inspects",
			bypassRules: []BypassRule{{Method: http.MethodGet, PathRegexp: `/search/v1/statement/executing/`}},
			method:      http.MethodGet,
			path:        "/search/v1/statement/queued/abc123",
			headerName:  "X-Waf-Status",
			wantWAF:     true,
			wantHeader:  "ok",
		},
		{
			name:        "method-only skips any path",
			bypassRules: []BypassRule{{Method: http.MethodGet}},
			method:      http.MethodGet,
			path:        "/any/path",
			headerName:  "X-Waf-Status",
			wantHeader:  bypassStatusToken,
		},
		{
			name:        "path-only skips any method",
			bypassRules: []BypassRule{{PathRegexp: `/health`}},
			method:      http.MethodPost,
			path:        "/health",
			headerName:  "X-Waf-Status",
			wantHeader:  bypassStatusToken,
		},
		{
			name:        "lowercase config method matches GET",
			bypassRules: []BypassRule{{Method: "get", PathRegexp: `/admin`}},
			method:      http.MethodGet,
			path:        "/admin",
			headerName:  "X-Waf-Status",
			wantHeader:  bypassStatusToken,
		},
		{
			name:        "no rules inspects",
			method:      http.MethodGet,
			path:        "/search/v1/statement/executing/abc123",
			headerName:  "X-Waf-Status",
			wantWAF:     true,
			wantHeader:  "ok",
		},
		{
			name:         "match with empty header name adds no token",
			bypassRules:  []BypassRule{{Method: http.MethodGet, PathRegexp: `/admin`}},
			method:       http.MethodGet,
			path:         "/admin",
			wantNoHeader: true,
		},
		{
			name:        "unanchored slash-health skips healthz",
			bypassRules: []BypassRule{{PathRegexp: `/health`}},
			method:      http.MethodGet,
			path:        "/healthz",
			headerName:  "X-Waf-Status",
			wantHeader:  bypassStatusToken,
		},
		{
			name:        "unanchored slash-health skips later segment",
			bypassRules: []BypassRule{{PathRegexp: `/health`}},
			method:      http.MethodGet,
			path:        "/index.php/health",
			headerName:  "X-Waf-Status",
			wantHeader:  bypassStatusToken,
		},
		{
			name:        "operator exact anchor inspects longer path",
			bypassRules: []BypassRule{{PathRegexp: `^/health$`}},
			method:      http.MethodGet,
			path:        "/healthz",
			headerName:  "X-Waf-Status",
			wantWAF:     true,
			wantHeader:  "ok",
		},
		{
			name:        "unanchored slash-health skips dot-dot path",
			bypassRules: []BypassRule{{PathRegexp: `/health`}},
			method:      http.MethodGet,
			path:        "/health/../index.php",
			headerName:  "X-Waf-Status",
			wantHeader:  bypassStatusToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wafCalled atomic.Bool
			waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				wafCalled.Store(true)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(waf.Close)

			var captured http.Header
			cfg := CreateConfig()
			cfg.ModSecurityUrl = waf.URL
			cfg.ModSecurityStatusRequestHeader = tt.headerName
			cfg.BypassRules = tt.bypassRules
			plugin, err := New("bypass-test-"+tt.name, cfg, NewLogger("bypass-test", cfg))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(plugin.Close)

			route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured = r.Header.Clone()
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "next")
			}))
			if err != nil {
				t.Fatalf("ForRoute: %v", err)
			}

			req := httptest.NewRequest(tt.method, "http://proxy.example"+tt.path, http.NoBody)
			rec := httptest.NewRecorder()
			route.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, want 200", rec.Code)
			}
			if wafCalled.Load() != tt.wantWAF {
				t.Fatalf("waf called = %v, want %v", wafCalled.Load(), tt.wantWAF)
			}
			if tt.wantNoHeader {
				if got := captured.Get("X-Waf-Status"); got != "" {
					t.Fatalf("status header %q, want empty", got)
				}
				return
			}
			if tt.headerName == "" {
				return
			}
			if got := captured.Get(tt.headerName); got != tt.wantHeader {
				t.Fatalf("status header %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

// TestPlugin_BypassRules_GetWithBodyIsNot400 asserts a bypassed GET with a body is not reject by denyVerbsWithBody.
func TestPlugin_BypassRules_GetWithBodyIsNot400(t *testing.T) {
	var wafCalled atomic.Bool
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		wafCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.BypassRules = []BypassRule{{Method: http.MethodGet}}
	plugin, err := New("bypass-get-body", cfg, NewLogger("bypass-get-body", cfg))
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

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example/any", strings.NewReader("body"))
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (not denyVerbsWithBody 400)", rec.Code)
	}
	if wafCalled.Load() {
		t.Fatal("WAF must not be called on a bypassed GET")
	}
	if !nextCalled {
		t.Fatal("next must be called")
	}
}

// TestNew_InvalidBypassPathRegexp asserts an unclosed group in pathRegexp fails plugin construction.
func TestNew_InvalidBypassPathRegexp(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	cfg.BypassRules = []BypassRule{{PathRegexp: "a(b"}}
	_, err := New("bad-regexp", cfg, NewLogger("bad-regexp", cfg))
	if err == nil {
		t.Fatal("expected error for invalid pathRegexp")
	}
	if !strings.Contains(err.Error(), "invalid bypass rule pathRegexp") {
		t.Fatalf("error %q, want invalid bypass rule pathRegexp", err)
	}
}

// TestCompileBypassByMethod_OneRegexpPerMethod asserts two GET rules compile to one GET map entry, not two.
func TestCompileBypassByMethod_OneRegexpPerMethod(t *testing.T) {
	compiled, err := compileBypassByMethod([]BypassRule{
		{Method: http.MethodGet, PathRegexp: `/a`},
		{Method: http.MethodGet, PathRegexp: `/b`},
		{Method: http.MethodPost, PathRegexp: `/c`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.byMethod) != 2 {
		t.Fatalf("byMethod len %d, want 2 (one compiled regexp per verb)", len(compiled.byMethod))
	}
	if compiled.byMethod[http.MethodGet] == nil || compiled.byMethod[http.MethodPost] == nil {
		t.Fatal("GET and POST must each have one compiled regexp")
	}
}
