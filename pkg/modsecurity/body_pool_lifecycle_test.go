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

// recordingBufferPool counts Get/Put so tests can assert pool return.
type recordingBufferPool struct {
	inner sync.Pool
	gets  atomic.Int32
	puts  atomic.Int32
}

func newTestRecordingBufferPool() *recordingBufferPool {
	return &recordingBufferPool{
		inner: sync.Pool{New: func() interface{} { return new(bytes.Buffer) }},
	}
}

func (p *recordingBufferPool) Get() any {
	p.gets.Add(1)
	return p.inner.Get()
}

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

// TestPlugin_TransportDoErrorFailOpenPuts proves a RoundTrip error fail-open still Puts (Opus GAP-C).
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
	pool := newTestRecordingBufferPool()
	plugin.bodyBufferPool = pool

	plugin.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Transport error without reading/closing the body.
		return nil, errors.New("dial waf: connection refused")
	})

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		// Omit Close — defer must still release.
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

// TestPlugin_InboundCancelPutsPooledBuffer proves cancel after sidecar accept Puts (Opus GAP-D).
func TestPlugin_InboundCancelPutsPooledBuffer(t *testing.T) {
	body := bytes.Repeat([]byte("c"), 150)
	started := make(chan struct{})
	waf := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		// Stay until inbound cancel aborts the sidecar request (or a safety timeout).
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
	pool := newTestRecordingBufferPool()
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

// TestPlugin_InboundBodyReadErrorPuts proves 413 MaxBytesReader Puts immediately (Opus GAP-F).
func TestPlugin_InboundBodyReadErrorPuts(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 100
	body := bytes.Repeat([]byte("z"), 200)

	_, route, pool := newPoolAllowRoute(t, "413-put", poolCap, maxBody, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("next must not run on 413")
		w.WriteHeader(http.StatusOK)
	}))

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
}

// TestPlugin_NewRequestErrorPutsPooledBuffer proves NewRequest failure still Puts (Opus GAP-E).
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
	pool := newTestRecordingBufferPool()
	plugin.bodyBufferPool = pool

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("next must not run when NewRequest fails")
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	// Method with a space makes NewRequestWithContext fail after the pooled read.
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

// TestPlugin_TransportDelayedReadAfterDoSeesNoCorruption proves defer Close + Put cannot
// hand the aliased slice to a later Get while a late Transport Read is still in flight.
func TestPlugin_TransportDelayedReadAfterDoSeesNoCorruption(t *testing.T) {
	const bodySize = 4096
	firstPayload := bytes.Repeat([]byte{0xAA}, bodySize)
	secondPayload := bytes.Repeat([]byte{0xBB}, bodySize)

	readStarted := make(chan struct{})
	readFinished := make(chan []byte, 1)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.MaxBodySizeBytesForPool = int64(bodySize)
	plugin, err := New("delayed-rt-put", cfg, NewLogger("delayed-rt-put", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	pool := newTestRecordingBufferPool()
	plugin.bodyBufferPool = pool

	var first int32
	plugin.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if atomic.AddInt32(&first, 1) == 1 {
			body := req.Body
			go func() {
				// Yield so ServeHTTP can return, defer Close, and Put before we Read.
				time.Sleep(20 * time.Millisecond)
				close(readStarted)
				got, err := io.ReadAll(body)
				if err != nil && !errors.Is(err, http.ErrBodyReadAfterClose) {
					readFinished <- append([]byte(nil), got...)
					return
				}
				if errors.Is(err, http.ErrBodyReadAfterClose) {
					readFinished <- nil // closed before late read — correct, not corruption
					return
				}
				readFinished <- got
				_ = body.Close()
			}()
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader([]byte("block"))),
				Request:    req,
			}, nil
		}
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
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "http://example/one", bytes.NewReader(firstPayload))
	req1.ContentLength = int64(len(firstPayload))
	route.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusForbidden {
		t.Fatalf("first status %d, want 403", rec1.Code)
	}

	<-readStarted
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "http://example/two", bytes.NewReader(secondPayload))
	req2.ContentLength = int64(len(secondPayload))
	route.ServeHTTP(rec2, req2)

	select {
	case got := <-readFinished:
		if got == nil {
			return // ErrBodyReadAfterClose — Put after Close is safe
		}
		if bytes.Contains(got, []byte{0xBB}) {
			t.Fatalf("late Transport read saw 0xBB from a later Put — pool alias corruption")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late Transport read did not finish")
	}
}

// TestPlugin_PoolGetsEqualPutsAcrossMixedPaths is a Get/Put conservation check (Opus #7).
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
	pool := newTestRecordingBufferPool()
	plugin.bodyBufferPool = pool

	plugin.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
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
