package modsecurity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingBufferPool counts Get/Put so copy-out paths can assert pool conservation.
type countingBufferPool struct {
	inner sync.Pool
	gets  atomic.Int64
	puts  atomic.Int64
}

func newCountingBufferPool() *countingBufferPool {
	return &countingBufferPool{
		inner: sync.Pool{New: func() any { return new(bytes.Buffer) }},
	}
}

func (p *countingBufferPool) Get() any {
	p.gets.Add(1)
	return p.inner.Get()
}

func (p *countingBufferPool) Put(x any) {
	p.puts.Add(1)
	p.inner.Put(x)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func allowOKRoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Request:    req,
	}, nil
}

// TestPlugin_EmptyPooledBodyAlwaysPuts proves empty POST still Get+Puts (copy-out path).
func TestPlugin_EmptyPooledBodyAlwaysPuts(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.MaxBodySizeBytesForPool = 1024
	cfg.UnhealthyWafBackOffPeriodSecs = 0
	plugin, err := New("empty-put", cfg, NewLogger("empty-put", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newCountingBufferPool()
	plugin.bodyBufferPool = pool
	plugin.httpClient.Transport = roundTripFunc(allowOKRoundTrip)

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://example/empty", http.NoBody)
		req.ContentLength = 0
		rec := httptest.NewRecorder()
		route.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200", i, rec.Code)
		}
	}
	if got := pool.puts.Load(); got != 3 {
		t.Fatalf("Puts %d, want 3 (each empty pooled read must release)", got)
	}
	if pool.gets.Load() != pool.puts.Load() {
		t.Fatalf("Gets %d Puts %d, want equal", pool.gets.Load(), pool.puts.Load())
	}
}

// TestPlugin_InboundBodyReadErrorPuts proves 413 still Puts the checkout (copy-out + defer Put).
func TestPlugin_InboundBodyReadErrorPuts(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 100
	body := bytes.Repeat([]byte("z"), 200)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.MaxBodySizeBytes = maxBody
	cfg.MaxBodySizeBytesForPool = poolCap
	cfg.UnhealthyWafBackOffPeriodSecs = 0
	plugin, err := New("413-put", cfg, NewLogger("413-put", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newCountingBufferPool()
	plugin.bodyBufferPool = pool
	plugin.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("sidecar must not run on 413")
		return nil, errors.New("unexpected")
	})

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("next must not run on 413")
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
	if got := pool.puts.Load(); got != 1 {
		t.Fatalf("Puts %d, want 1 after MaxBytesReader error", got)
	}
	if pool.gets.Load() != 1 {
		t.Fatalf("Gets %d, want 1", pool.gets.Load())
	}
}

// TestPlugin_TransportDoErrorFailOpenPuts proves fail-open after Do error still Put (Put before Do).
func TestPlugin_TransportDoErrorFailOpenPuts(t *testing.T) {
	body := bytes.Repeat([]byte("d"), 120)
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.MaxBodySizeBytesForPool = 1024
	cfg.UnhealthyWafBackOffPeriodSecs = 0
	cfg.ModSecurityStatusRequestHeader = "X-Waf-Status"
	plugin, err := New("do-err-put", cfg, NewLogger("do-err-put", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newCountingBufferPool()
	plugin.bodyBufferPool = pool
	plugin.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial waf: connection refused")
	})

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want fail-open 200", rec.Code)
	}
	if got := req.Header.Get("X-Waf-Status"); got != "error" {
		t.Fatalf("X-Waf-Status %q, want error", got)
	}
	if got := pool.puts.Load(); got != 1 {
		t.Fatalf("Puts %d, want 1 after transport Do error fail-open", got)
	}
}

// TestPlugin_NewRequestErrorPutsPooledBuffer proves NewRequest failure after pooled read still Put.
func TestPlugin_NewRequestErrorPutsPooledBuffer(t *testing.T) {
	body := bytes.Repeat([]byte("n"), 90)
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.MaxBodySizeBytesForPool = 1024
	plugin, err := New("newreq-err-put", cfg, NewLogger("newreq-err-put", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newCountingBufferPool()
	plugin.bodyBufferPool = pool

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("next must not run when NewRequest fails")
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	u, err := url.Parse("http://example/test")
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	req := &http.Request{
		Method:        "BAD METHOD",
		URL:           u,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Host:          "example",
	}
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	if got := pool.puts.Load(); got != 1 {
		t.Fatalf("Puts %d, want 1 after NewRequest error", got)
	}
}

// TestPlugin_InboundCancelPutsPooledBuffer proves cancel after sidecar accept still Put.
func TestPlugin_InboundCancelPutsPooledBuffer(t *testing.T) {
	body := bytes.Repeat([]byte("c"), 150)
	started := make(chan struct{})
	waf := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	t.Cleanup(func() {
		waf.CloseClientConnections()
		waf.Close()
	})

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.MaxBodySizeBytesForPool = 1024
	cfg.TimeoutMillis = 5000
	plugin, err := New("cancel-put", cfg, NewLogger("cancel-put", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newCountingBufferPool()
	plugin.bodyBufferPool = pool

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("next must not run on inbound cancel")
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "http://example/protected", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
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
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	if got := pool.puts.Load(); got != 1 {
		t.Fatalf("Puts %d, want 1 after inbound cancel with pooled body", got)
	}
}

// TestPlugin_PoolGetsEqualPutsAcrossMixedPaths is Get/Put conservation across allow/empty/413.
func TestPlugin_PoolGetsEqualPutsAcrossMixedPaths(t *testing.T) {
	bodyOK := bytes.Repeat([]byte("m"), 80)
	bodyOver := bytes.Repeat([]byte("o"), 200)
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.MaxBodySizeBytes = 150
	cfg.MaxBodySizeBytesForPool = 1024
	cfg.UnhealthyWafBackOffPeriodSecs = 0
	plugin, err := New("conserve-put", cfg, NewLogger("conserve-put", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newCountingBufferPool()
	plugin.bodyBufferPool = pool
	plugin.httpClient.Transport = roundTripFunc(allowOKRoundTrip)

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://example/ok", bytes.NewReader(bodyOK))
		req.ContentLength = int64(len(bodyOK))
		rec := httptest.NewRecorder()
		route.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ok[%d] status %d", i, rec.Code)
		}
	}
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://example/empty", http.NoBody)
		req.ContentLength = 0
		rec := httptest.NewRecorder()
		route.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("empty[%d] status %d", i, rec.Code)
		}
	}
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://example/big", bytes.NewReader(bodyOver))
		req.ContentLength = int64(len(bodyOver))
		rec := httptest.NewRecorder()
		route.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("413[%d] status %d", i, rec.Code)
		}
	}

	gets, puts := pool.gets.Load(), pool.puts.Load()
	if gets != puts {
		t.Fatalf("Gets %d Puts %d, want equal (no stranded checkout)", gets, puts)
	}
	if gets == 0 {
		t.Fatal("expected at least one pool Get")
	}
}

// TestPlugin_SidecarRequestSetsContentLength proves proxyReq is not forced chunked.
func TestPlugin_SidecarRequestSetsContentLength(t *testing.T) {
	body := bytes.Repeat([]byte("c"), 512)
	var gotCL int64 = -2
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.MaxBodySizeBytesForPool = 4096
	plugin, err := New("cl-test", cfg, NewLogger("cl-test", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)

	plugin.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotCL = req.ContentLength
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Request:    req,
		}, nil
	})

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if gotCL != int64(len(body)) {
		t.Fatalf("sidecar ContentLength %d, want %d", gotCL, len(body))
	}
}
