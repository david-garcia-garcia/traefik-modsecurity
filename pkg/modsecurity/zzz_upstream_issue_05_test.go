package modsecurity

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newIssue05AllowRoute builds a plugin+route that forwards to a 200 next.
func newIssue05AllowRoute(t *testing.T, name, wafURL string) (*Plugin, http.Handler) {
	t.Helper()
	cfg := CreateConfig()
	cfg.ModSecurityUrl = wafURL
	cfg.TimeoutMillis = 5000
	plugin, err := New(name, cfg, NewLogger(name, cfg))
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
	return plugin, route
}

// startIssue05AllowWAF starts a sidecar that allows every request.
func startIssue05AllowWAF(t *testing.T) *httptest.Server {
	t.Helper()
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(waf.Close)
	return waf
}

// TestPlugin_UpstreamIssue05_EmptyHeadersDoNotPanic maps
// acouvreur/traefik-modsecurity-plugin#5: Yaegi blamed isWebsocket at
// v1.1.0 line 56. Header.Values on a missing or nil map is a nil slice.
// The plugin no longer classifies a handshake; ServeHTTP still must not panic.
func TestPlugin_UpstreamIssue05_EmptyHeadersDoNotPanic(t *testing.T) {
	waf := startIssue05AllowWAF(t)
	_, route := newIssue05AllowRoute(t, "issue-05-empty-headers", waf.URL)

	tests := []struct {
		name string
		prep func(*http.Request)
	}{
		{
			name: "reporter font GET no Upgrade",
			prep: func(req *http.Request) {
				req.Header = http.Header{}
			},
		},
		{
			name: "nil Header map",
			prep: func(req *http.Request) {
				req.Header = nil
			},
		},
		{
			name: "Upgrade key absent",
			prep: func(req *http.Request) {
				req.Header = http.Header{"Connection": []string{"keep-alive"}}
			},
		},
		{
			name: "forged Upgrade without Connection token",
			prep: func(req *http.Request) {
				req.Header = http.Header{"Upgrade": []string{"websocket"}}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("ServeHTTP panicked: %v", rec)
				}
			}()
			req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
			tt.prep(req)
			rec := httptest.NewRecorder()
			route.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, want 200", rec.Code)
			}
		})
	}
}

// TestPlugin_ServeHTTP_HandshakeHitsSidecar checks a handshake-shaped GET is
// inspected. Sidecar 403 is copied; next is not called.
func TestPlugin_ServeHTTP_HandshakeHitsSidecar(t *testing.T) {
	sidecarHits := 0
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sidecarHits++
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "blocked")
	}))
	t.Cleanup(waf.Close)

	nextHits := 0
	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.TimeoutMillis = 5000
	cfg.ModSecurityStatusRequestHeader = "X-Waf-Status"
	plugin, err := New("handshake-inspect", cfg, NewLogger("handshake-inspect", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextHits++
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "next")
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example/ws-echo", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("X-Waf-Status", "ok")
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if sidecarHits != 1 {
		t.Fatalf("sidecar hits %d, want 1", sidecarHits)
	}
	if nextHits != 0 {
		t.Fatalf("next hits %d, want 0", nextHits)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if rec.Body.String() != "blocked" {
		t.Fatalf("body %q, want blocked", rec.Body.String())
	}
	if got := req.Header.Get("X-Waf-Status"); got != "blocked" {
		t.Fatalf("status header %q, want blocked", got)
	}
}

// TestPlugin_UpstreamIssue05_ReporterFontGETDoesNotPanic serves the access-log
// shape from #5 (HTTP GET, RequestContentSize 0, no Upgrade). httptest.NewRequest
// with a nil body arg uses http.NoBody (non-nil), matching a server request.
func TestPlugin_UpstreamIssue05_ReporterFontGETDoesNotPanic(t *testing.T) {
	waf := startIssue05AllowWAF(t)
	_, route := newIssue05AllowRoute(t, "issue-05-font-get", waf.URL)

	req := httptest.NewRequest(http.MethodGet, "http://example/build/fonts/fa-light-300.c92b45dd.ttf", nil)
	if req.Body == nil {
		t.Fatal("httptest.NewRequest Body is nil; server requests use NoBody")
	}
	req.Header = nil

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("ServeHTTP panicked on reporter-shaped GET: %v", rec)
		}
	}()
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if rec.Body.String() != "next" {
		t.Fatalf("body %q, want next", rec.Body.String())
	}
}

// TestPlugin_UpstreamIssue05_NilBodyPanicsOnServeHTTP documents the residual:
// a hand-built req.Body == nil panics in the denyVerbsWithBody peek
// (MaxBytesReader.Read → nil.Read). Traefik/net/http servers set NoBody.
func TestPlugin_UpstreamIssue05_NilBodyPanicsOnServeHTTP(t *testing.T) {
	waf := startIssue05AllowWAF(t)
	_, route := newIssue05AllowRoute(t, "issue-05-nil-body", waf.URL)

	req := httptest.NewRequest(http.MethodGet, "http://example/protected", nil)
	req.Body = nil
	rec := httptest.NewRecorder()

	defer func() {
		recov := recover()
		if recov == nil {
			t.Fatal("expected panic when req.Body is nil")
		}
	}()
	route.ServeHTTP(rec, req)
}

// TestPlugin_UpstreamIssue05_InboundCancelDoesNotNilDeref checks a client abort
// (canceled inbound context) is an error return, not a plugin panic.
func TestPlugin_UpstreamIssue05_InboundCancelDoesNotNilDeref(t *testing.T) {
	wafURL, started := startTestBlockingWAF(t)
	_, route := newIssue05AllowRoute(t, "issue-05-cancel", wafURL)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://example/build/fonts/fa-light-300.c92b45dd.ttf", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	var recovered any
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { recovered = recover() }()
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
	if recovered != nil {
		t.Fatalf("ServeHTTP panicked on inbound cancel: %v", recovered)
	}
}

// TestPlugin_UpstreamIssue05_HTTP2ClientAbortIsNotNilDeref reproduces the
// reporter's HTTP/2 RST_STREAM (browser cancel of an in-flight font GET).
// Go may panic http.ErrAbortHandler when the handler writes after reset;
// that is server abort, not a plugin nil-deref.
func TestPlugin_UpstreamIssue05_HTTP2ClientAbortIsNotNilDeref(t *testing.T) {
	wafURL, started := startTestBlockingWAF(t)
	_, route := newIssue05AllowRoute(t, "issue-05-h2-abort", wafURL)

	var (
		proto     string
		recovered any
	)
	handlerDone := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		proto = r.Proto
		defer func() { recovered = recover() }()
		route.ServeHTTP(w, r)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := srv.Client()
	if tr, ok := client.Transport.(*http.Transport); ok {
		tr.ForceAttemptHTTP2 = true
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		tr.TLSClientConfig.NextProtos = []string{"h2"}
	}

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/build/fonts/fa-light-300.c92b45dd.ttf", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		resp, doErr := client.Do(req)
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		errCh <- doErr
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("sidecar did not receive the request")
	}
	cancel()

	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return after HTTP/2 client cancel")
	}
	if proto != "HTTP/2.0" {
		t.Fatalf("proto %q, want HTTP/2.0 (HTTP/2 abort not reproduced)", proto)
	}
	if recovered != nil && recovered != http.ErrAbortHandler {
		t.Fatalf("panic %v, want nil or http.ErrAbortHandler", recovered)
	}
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("client Do did not return after cancel")
	}
}
