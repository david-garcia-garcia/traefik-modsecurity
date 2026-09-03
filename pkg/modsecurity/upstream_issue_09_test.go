package modsecurity

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// issue09LoginBody is a login-form POST like acouvreur/traefik-modsecurity-plugin#9.
const issue09LoginBody = "username=alice&password=secret"

type issue09Harness struct {
	plugin     *Plugin
	route      http.Handler
	nextCalled bool
}

// newIssue09Route builds a Plugin + route with a 200 WAF. cfg.ModSecurityUrl is overwritten.
func newIssue09Route(t *testing.T, cfg *Config) *issue09Harness {
	t.Helper()
	h := &issue09Harness{}
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(waf.Close)

	if cfg == nil {
		cfg = &Config{}
	}
	cfg.ModSecurityUrl = waf.URL
	plugin, err := New("issue-09", cfg, NewLogger("issue-09", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	h.plugin = plugin

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h.nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}
	h.route = route
	return h
}

func postIssue09Login(t *testing.T, h *issue09Harness) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://example/login", strings.NewReader(issue09LoginBody))
	rec := httptest.NewRecorder()
	h.route.ServeHTTP(rec, req)
	return rec
}

// TestUpstreamIssue09_OmittedMaxBodySizeBytesSmallPOSTIs200 is the Yaegi-omit path.
// Upstream 1.2.0 left the handler limit at 0 and 413'd every non-empty POST.
func TestUpstreamIssue09_OmittedMaxBodySizeBytesSmallPOSTIs200(t *testing.T) {
	h := newIssue09Route(t, &Config{})
	if h.plugin.maxBodySizeBytes != 8*1024*1024 {
		t.Fatalf("handler maxBodySizeBytes = %d, want 8 MiB after Prepare", h.plugin.maxBodySizeBytes)
	}
	rec := postIssue09Login(t, h)
	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("small POST was 413 (upstream 1.2.0 zero-limit bug); body %q", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !h.nextCalled {
		t.Fatal("next was not called")
	}
}

// TestUpstreamIssue09_ExplicitZeroMaxBodySizeBytesSmallPOSTIs200 is operator maxBodySizeBytes: 0.
func TestUpstreamIssue09_ExplicitZeroMaxBodySizeBytesSmallPOSTIs200(t *testing.T) {
	cfg := CreateConfig()
	cfg.MaxBodySizeBytes = 0
	h := newIssue09Route(t, cfg)
	if h.plugin.maxBodySizeBytes != 8*1024*1024 {
		t.Fatalf("handler maxBodySizeBytes = %d, want 8 MiB after Prepare remaps 0", h.plugin.maxBodySizeBytes)
	}
	rec := postIssue09Login(t, h)
	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("small POST was 413 (upstream 1.2.0 zero-limit bug); body %q", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !h.nextCalled {
		t.Fatal("next was not called")
	}
}

// TestUpstreamIssue09_ForcedZeroHandlerLimitDoesNot413 applies the 1.2.0 wiring on our read path.
// We skip MaxBytesReader when maxBodySizeBytes is 0, so a login POST is not 413.
func TestUpstreamIssue09_ForcedZeroHandlerLimitDoesNot413(t *testing.T) {
	h := newIssue09Route(t, CreateConfig())
	h.plugin.maxBodySizeBytes = 0
	rec := postIssue09Login(t, h)
	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("forced handler limit 0 returned 413; our readInboundBody must skip MaxBytesReader when limit is 0")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !h.nextCalled {
		t.Fatal("next was not called")
	}
}

// TestUpstreamIssue09_StdlibMaxBytesReaderZeroRejectsSmallBody is the 1.2.0 mechanism, not our path.
func TestUpstreamIssue09_StdlibMaxBytesReaderZeroRejectsSmallBody(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://example/login", strings.NewReader(issue09LoginBody))
	req.Body = http.MaxBytesReader(rec, req.Body, 0)
	_, err := io.ReadAll(req.Body)
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Fatalf("MaxBytesReader(0) err = %v, want *http.MaxBytesError", err)
	}
	if maxErr.Limit != 0 {
		t.Fatalf("MaxBytesError.Limit = %d, want 0", maxErr.Limit)
	}
}
