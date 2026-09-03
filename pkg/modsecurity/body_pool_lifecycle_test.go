package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingBufferPool counts Put so tests can assert pool return.
type recordingBufferPool struct {
	inner sync.Pool
	puts  atomic.Int32
}

func newTestRecordingBufferPool() *recordingBufferPool {
	return &recordingBufferPool{
		inner: sync.Pool{New: func() interface{} { return new(bytes.Buffer) }},
	}
}

func (p *recordingBufferPool) Get() any { return p.inner.Get() }

func (p *recordingBufferPool) Put(x any) {
	p.puts.Add(1)
	p.inner.Put(x)
}

func newPoolAllowRoute(t *testing.T, name string, poolCap, maxBody int64, next http.Handler) (*Plugin, http.Handler, *recordingBufferPool) {
	t.Helper()
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.MaxBodySizeBytes = maxBody
	cfg.MaxBodySizeBytesForPool = poolCap
	plugin, err := New(name, cfg, NewLogger(name, cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newTestRecordingBufferPool()
	plugin.bodyBufferPool = pool

	route, err := plugin.ForRoute(next)
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}
	return plugin, route, pool
}

// TestPlugin_EmptyPooledBodyAlwaysPuts proves empty POST returns the buffer even when
// Bytes() would be nil on a fresh pool buffer (Opus F1).
func TestPlugin_EmptyPooledBodyAlwaysPuts(t *testing.T) {
	_, route, pool := newPoolAllowRoute(t, "empty-put", 1024, 8192, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Short-circuit: never Close Body (ReverseProxy ContentLength==0 path).
		w.WriteHeader(http.StatusOK)
	}))

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
}

// TestPlugin_AllowPathPutsWhenNextOmitsClose proves gate is not stranded when next
// returns without Closing req.Body (Opus F2).
func TestPlugin_AllowPathPutsWhenNextOmitsClose(t *testing.T) {
	body := bytes.Repeat([]byte("s"), 200)
	_, route, pool := newPoolAllowRoute(t, "allow-no-close", 1024, 8192, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		// Deliberately no Close — mimics short-circuit middleware / Traefik edge cases.
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := pool.puts.Load(); got != 1 {
		t.Fatalf("Puts %d, want 1 after allow when next omits Close", got)
	}
}

// TestPlugin_FailOpenPutsWhenNextOmitsClose covers WAF 5xx fail-open (Opus F2).
func TestPlugin_FailOpenPutsWhenNextOmitsClose(t *testing.T) {
	body := bytes.Repeat([]byte("f"), 100)
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.MaxBodySizeBytesForPool = 1024
	cfg.UnhealthyWafBackOffPeriodSecs = 0
	plugin, err := New("failopen-put", cfg, NewLogger("failopen-put", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newTestRecordingBufferPool()
	plugin.bodyBufferPool = pool

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
	if got := pool.puts.Load(); got != 1 {
		t.Fatalf("Puts %d, want 1 after fail-open", got)
	}
}

// TestPlugin_SidecarRequestSetsContentLength proves proxyReq is not forced chunked (Opus F5).
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestPlugin_LargeBodyUsesNopCloserNotDoneReader proves non-pooled path skips doneReadCloser (Opus F4).
func TestPlugin_LargeBodyUsesNopCloserNotDoneReader(t *testing.T) {
	const poolCap int64 = 256
	body := bytes.Repeat([]byte("L"), 1024)
	var sawDoneReader bool
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.MaxBodySizeBytes = 8192
	cfg.MaxBodySizeBytesForPool = poolCap
	plugin, err := New("large-nop", cfg, NewLogger("large-nop", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Body.(*doneReadCloser); ok {
			sawDoneReader = true
		}
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
	if sawDoneReader {
		t.Fatal("large body must use NopCloser, not doneReadCloser")
	}
}

// TestDoneReadCloser_CloseDoesNotHoldMuDuringDone proves Put/done cannot deadlock a Read (Opus F7).
func TestDoneReadCloser_CloseDoesNotHoldMuDuringDone(t *testing.T) {
	var d *doneReadCloser
	started := make(chan struct{})
	finished := make(chan struct{})
	d = newDoneReadCloser(bytes.NewReader([]byte("abcd")), func() {
		close(started)
		// If Close still holds mu, this Read deadlocks.
		_, _ = d.Read(make([]byte, 1))
		close(finished)
	})
	_ = d.Close()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Close held mu while calling done; Read deadlocked")
	}
}

// TestPlugin_ChunkedBodyOverPoolCapStillPuts proves ContentLength -1 that exceeds the
// pool cap still Returns the checkout buffer (Opus M4). Without a bounded peek, io.Copy
// grows Cap and the Cap guard drops the buffer — pool drain under chunked uploads.
func TestPlugin_ChunkedBodyOverPoolCapStillPuts(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("a"), 4096)

	_, route, pool := newPoolAllowRoute(t, "chunk-over", poolCap, maxBody, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("next ReadAll: %v", err)
		}
		_ = r.Body.Close()
		if !bytes.Equal(got, body) {
			t.Errorf("next body %d bytes, want %d", len(got), len(body))
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = -1
	req.Header.Del("Content-Length")
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := pool.puts.Load(); got != 1 {
		t.Fatalf("Puts %d, want 1 (overflow must Put pool buffer, not grow-and-drop)", got)
	}
}

// TestPlugin_AllowPathPutsWhenTransportOmitsSidecarClose proves allow path does not
// strand the gate when a custom RoundTripper skips Request.Body.Close (Opus H3).
func TestPlugin_AllowPathPutsWhenTransportOmitsSidecarClose(t *testing.T) {
	body := bytes.Repeat([]byte("t"), 100)
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.MaxBodySizeBytesForPool = 1024
	plugin, err := New("allow-no-sidecar-close", cfg, NewLogger("allow-no-sidecar-close", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newTestRecordingBufferPool()
	plugin.bodyBufferPool = pool

	plugin.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			// Violate RoundTripper contract: do not Close request body.
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
		// Also omit Close on next — ServeHTTP must finish both consumers.
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
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := pool.puts.Load(); got != 1 {
		t.Fatalf("Puts %d, want 1 (allow must Close sidecar even if Transport does not)", got)
	}
}

// TestPlugin_FailOpen5xxPutsWhenTransportOmitsSidecarClose covers 5xx fail-open + H3.
func TestPlugin_FailOpen5xxPutsWhenTransportOmitsSidecarClose(t *testing.T) {
	body := bytes.Repeat([]byte("e"), 80)
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.MaxBodySizeBytesForPool = 1024
	cfg.UnhealthyWafBackOffPeriodSecs = 0
	plugin, err := New("5xx-no-sidecar-close", cfg, NewLogger("5xx-no-sidecar-close", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newTestRecordingBufferPool()
	plugin.bodyBufferPool = pool

	plugin.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
		}
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("waf down"))),
			Request:    req,
		}, nil
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
	if got := pool.puts.Load(); got != 1 {
		t.Fatalf("Puts %d, want 1 after 5xx fail-open without Transport Close", got)
	}
}

// TestPlugin_BlockPathClosesSidecarBody proves block path does not rely only on Transport (Opus F9).
func TestPlugin_BlockPathClosesSidecarBody(t *testing.T) {
	body := bytes.Repeat([]byte("b"), 100)
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.MaxBodySizeBytesForPool = 1024
	plugin, err := New("block-close", cfg, NewLogger("block-close", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newTestRecordingBufferPool()
	plugin.bodyBufferPool = pool

	plugin.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Violate RoundTripper contract: do not Close request body.
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("block"))),
			Request:    req,
		}, nil
	})

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("next must not run on block")
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if got := pool.puts.Load(); got != 1 {
		t.Fatalf("Puts %d, want 1 (block must Close both consumers even if Transport does not)", got)
	}
}
