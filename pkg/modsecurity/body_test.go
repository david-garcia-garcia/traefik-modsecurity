package modsecurity

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// bodyReadHarness is one Plugin core, a 200 WAF, and a next that records the restored body.
type bodyReadHarness struct {
	plugin     *Plugin
	route      http.Handler
	nextCalled bool
	nextBody   []byte
	wafBody    []byte
}

func newTestBodyReadRoute(t *testing.T, maxBody int64) *bodyReadHarness {
	t.Helper()
	h := &bodyReadHarness{}
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.wafBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "WAF OK")
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.MaxBodySizeBytes = maxBody
	cfg.ModSecurityStatusRequestHeader = "X-Waf-Status"
	plugin, err := New("body-read-test", cfg, NewLogger("body-read-test", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	h.plugin = plugin

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.nextCalled = true
		h.nextBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}
	h.route = route
	return h
}

func TestPlugin_UnknownLengthForwardsBody(t *testing.T) {
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("a"), 4096)

	h := newTestBodyReadRoute(t, maxBody)
	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = -1
	req.Header.Del("Content-Length")

	rec := httptest.NewRecorder()
	h.route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !h.nextCalled {
		t.Fatal("next was not called")
	}
	if !bytes.Equal(h.nextBody, body) || !bytes.Equal(h.wafBody, body) {
		t.Fatalf("sidecar/next body mismatch: waf=%d next=%d want=%d", len(h.wafBody), len(h.nextBody), len(body))
	}
	if req.Header.Get("X-Waf-Status") != "ok" {
		t.Fatalf("status header %q, want ok", req.Header.Get("X-Waf-Status"))
	}
}

func TestPlugin_ParsedLengthForwardsBody(t *testing.T) {
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("b"), 4096)

	h := newTestBodyReadRoute(t, maxBody)
	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Length", "100")

	rec := httptest.NewRecorder()
	h.route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !h.nextCalled {
		t.Fatal("next was not called")
	}
	if !bytes.Equal(h.nextBody, body) || !bytes.Equal(h.wafBody, body) {
		t.Fatalf("sidecar/next body mismatch")
	}
}

func TestPlugin_UnknownLengthOverMaxReturns413(t *testing.T) {
	const maxBody int64 = 2048
	body := bytes.Repeat([]byte("x"), 4096)

	h := newTestBodyReadRoute(t, maxBody)
	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = -1
	req.Header.Del("Content-Length")

	rec := httptest.NewRecorder()
	h.route.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
	if h.nextCalled {
		t.Fatal("next must not be called on 413")
	}
	if req.Header.Get("X-Waf-Status") != "blocked" {
		t.Fatalf("status header %q, want blocked", req.Header.Get("X-Waf-Status"))
	}
}

func TestPlugin_HTTP1ChunkedForwardsBody(t *testing.T) {
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("c"), 4096)

	h := newTestBodyReadRoute(t, maxBody)
	srv := httptest.NewServer(h.route)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/test", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = -1
	req.Header.Del("Content-Length")

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if !h.nextCalled {
		t.Fatal("next was not called")
	}
	if !bytes.Equal(h.nextBody, body) || !bytes.Equal(h.wafBody, body) {
		t.Fatalf("sidecar/next body mismatch")
	}
}

func TestPlugin_HTTP1ChunkedOverMaxReturns413(t *testing.T) {
	const maxBody int64 = 2048
	body := bytes.Repeat([]byte("d"), 4096)

	h := newTestBodyReadRoute(t, maxBody)
	srv := httptest.NewServer(h.route)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/test", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = -1
	req.Header.Del("Content-Length")

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", resp.StatusCode)
	}
	if h.nextCalled {
		t.Fatal("next must not be called on 413")
	}
}

type capturedMixedBody struct {
	waf  []byte
	next []byte
}

func TestPlugin_ConcurrentMixedBodySizesDoNotRace(t *testing.T) {
	const maxBody int64 = 8192
	small := bytes.Repeat([]byte("s"), 200)
	large := bytes.Repeat([]byte("L"), 4096)

	var mu sync.Mutex
	got := map[string]*capturedMixedBody{}

	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Test-Req")
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen := got[id]
		if seen == nil {
			seen = &capturedMixedBody{}
			got[id] = seen
		}
		seen.waf = append([]byte(nil), body...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.MaxBodySizeBytes = maxBody
	plugin, err := New("body-read-concurrent", cfg, NewLogger("body-read-concurrent", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Test-Req")
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen := got[id]
		if seen == nil {
			seen = &capturedMixedBody{}
			got[id] = seen
		}
		seen.next = append([]byte(nil), body...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	errCh := make(chan string, n*2)
	serve := func(id string, payload []byte) {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(payload))
		req.Header.Set("X-Test-Req", id)
		req.ContentLength = int64(len(payload))
		rec := httptest.NewRecorder()
		route.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			errCh <- fmt.Sprintf("%s status %d", id, rec.Code)
		}
	}
	for i := 0; i < n; i++ {
		wg.Add(2)
		go serve(fmt.Sprintf("small-%d", i), small)
		go serve(fmt.Sprintf("large-%d", i), large)
	}
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Error(msg)
	}

	for i := 0; i < n; i++ {
		smallID := fmt.Sprintf("small-%d", i)
		largeID := fmt.Sprintf("large-%d", i)
		mu.Lock()
		smallSeen := got[smallID]
		largeSeen := got[largeID]
		mu.Unlock()
		if smallSeen == nil {
			t.Fatalf("missing %s", smallID)
		}
		if !bytes.Equal(smallSeen.waf, small) || !bytes.Equal(smallSeen.next, small) {
			t.Fatalf("%s body mismatch", smallID)
		}
		if largeSeen == nil {
			t.Fatalf("missing %s", largeID)
		}
		if !bytes.Equal(largeSeen.waf, large) || !bytes.Equal(largeSeen.next, large) {
			t.Fatalf("%s body mismatch", largeID)
		}
	}
}

// recordingBufferPool counts Put and records Cap so tests can assert pool return.
type recordingBufferPool struct {
	inner      sync.Pool
	mu         sync.Mutex
	puts       int
	lastPutCap int
}

func newRecordingBufferPool() *recordingBufferPool {
	return &recordingBufferPool{
		inner: sync.Pool{New: func() interface{} { return new(bytes.Buffer) }},
	}
}

func (p *recordingBufferPool) Get() any {
	return p.inner.Get()
}

func (p *recordingBufferPool) Put(x any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.puts++
	if buf, ok := x.(*bytes.Buffer); ok {
		p.lastPutCap = buf.Cap()
	}
	p.inner.Put(x)
}

func (p *recordingBufferPool) putCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.puts
}

func (p *recordingBufferPool) putCap() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastPutCap
}

// TestPlugin_UnknownLengthOverPoolCapPutsBoundedCheckout reproduces the pool leak where
// unbounded io.Copy into a pooled buffer grew Cap past maxBodySizeBytesForPool and the
// Cap guard skipped Put — abandoning an oversized buffer. LimitReader + peek must Put
// a bounded checkout and forward an owned full body.
func TestPlugin_UnknownLengthOverPoolCapPutsBoundedCheckout(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("x"), 4096)

	pool := newRecordingBufferPool()
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) {
			t.Errorf("sidecar body len=%d, want %d", len(got), len(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.MaxBodySizeBytes = maxBody
	cfg.MaxBodySizeBytesForPool = poolCap
	plugin, err := New("chunked-pool-put", cfg, NewLogger("chunked-pool-put", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	plugin.bodyBufferPool = pool

	var nextBody []byte
	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example/upload", bytes.NewReader(body))
	req.ContentLength = -1
	req.Header.Del("Content-Length")
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !bytes.Equal(nextBody, body) {
		t.Fatalf("next body len=%d, want %d", len(nextBody), len(body))
	}
	if pool.putCount() != 1 {
		t.Fatalf("pool Put count %d, want 1 (checkout must return before serve continues)", pool.putCount())
	}
	if cap := pool.putCap(); int64(cap) > poolCap*2 {
		t.Fatalf("Put buffer Cap=%d exceeds 2*poolCap=%d (unbounded Copy grew the checkout)", cap, poolCap*2)
	}
}

// TestPlugin_SpoofedSmallContentLengthOverPoolCapPutsBoundedCheckout covers a declared
// ContentLength under the pool cap with a larger actual body — without LimitReader the
// pooled buffer would still grow past the Cap Put guard.
func TestPlugin_SpoofedSmallContentLengthOverPoolCapPutsBoundedCheckout(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("y"), 4096)

	pool := newRecordingBufferPool()
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) {
			t.Errorf("sidecar body len=%d, want %d", len(got), len(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.MaxBodySizeBytes = maxBody
	cfg.MaxBodySizeBytesForPool = poolCap
	plugin, err := New("spoof-cl-pool-put", cfg, NewLogger("spoof-cl-pool-put", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	plugin.bodyBufferPool = pool

	var nextBody []byte
	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example/upload", bytes.NewReader(body))
	req.ContentLength = 100 // under poolCap; actual body is larger
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !bytes.Equal(nextBody, body) {
		t.Fatalf("next body len=%d, want %d", len(nextBody), len(body))
	}
	if pool.putCount() != 1 {
		t.Fatalf("pool Put count %d, want 1", pool.putCount())
	}
	if cap := pool.putCap(); int64(cap) > poolCap*2 {
		t.Fatalf("Put buffer Cap=%d exceeds 2*poolCap=%d", cap, poolCap*2)
	}
}

// checkoutStickyPool returns the same buffer only when not checked out (Put returned).
type checkoutStickyPool struct {
	mu  sync.Mutex
	buf *bytes.Buffer
	out bool
}

func (p *checkoutStickyPool) Get() any {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.out {
		return new(bytes.Buffer)
	}
	p.out = true
	return p.buf
}

func (p *checkoutStickyPool) Put(x any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if x == p.buf {
		p.out = false
	}
}

// TestPlugin_PooledBodyNotAliasedWhileCheckedOut checks a second request cannot reuse the
// pooled buffer while the first sidecar RoundTrip still holds it (no Put yet).
func TestPlugin_PooledBodyNotAliasedWhileCheckedOut(t *testing.T) {
	const bodySize = 1 << 20
	firstPayload := bytes.Repeat([]byte{0xAA}, bodySize)
	secondPayload := bytes.Repeat([]byte{0xBB}, bodySize)

	firstInFlight := make(chan struct{})
	secondServeDone := make(chan struct{})
	gotFirstBody := make(chan []byte, 1)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf.test"
	cfg.TimeoutMillis = 30000
	plugin, err := New("body-alias", cfg, NewLogger("body-alias", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)
	plugin.bodyBufferPool = &checkoutStickyPool{buf: new(bytes.Buffer)}
	plugin.httpClient.Transport = &testHoldThenReadRoundTripper{
		firstInFlight: firstInFlight,
		readAfter:     secondServeDone,
		got:           gotFirstBody,
	}

	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next must not run on a 403 block")
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "http://example/upload", bytes.NewReader(firstPayload))
		req.Header.Set("X-Req", "first")
		req.ContentLength = int64(len(firstPayload))
		rec := httptest.NewRecorder()
		route.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("first status %d, want 403", rec.Code)
		}
	}()

	select {
	case <-firstInFlight:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for first RoundTrip")
	}

	req2 := httptest.NewRequest(http.MethodPost, "http://example/upload", bytes.NewReader(secondPayload))
	req2.Header.Set("X-Req", "second")
	req2.ContentLength = int64(len(secondPayload))
	rec2 := httptest.NewRecorder()
	route.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("second status %d, want 403", rec2.Code)
	}
	close(secondServeDone)

	var got []byte
	select {
	case got = <-gotFirstBody:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for first sidecar body read")
	}
	wg.Wait()

	aa := bytes.Count(got, []byte{0xAA})
	bb := bytes.Count(got, []byte{0xBB})
	if bb > 0 {
		t.Fatalf("cross-request leak: first sidecar body contains %d bytes from the second request (0xBB); 0xAA=%d len=%d", bb, aa, len(got))
	}
	if !bytes.Equal(got, firstPayload) {
		t.Fatalf("first sidecar body mismatch: len=%d 0xAA=%d 0xBB=%d, want %d 0xAA", len(got), aa, bb, bodySize)
	}
}

type testHoldThenReadRoundTripper struct {
	firstInFlight chan struct{}
	readAfter     <-chan struct{}
	got           chan []byte
	once          sync.Once
}

func (t *testHoldThenReadRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("X-Req") == "first" {
		t.once.Do(func() { close(t.firstInFlight) })
		select {
		case <-t.readAfter:
		case <-time.After(15 * time.Second):
			t.got <- []byte("timeout")
			return nil, io.EOF
		}
		got, _ := io.ReadAll(req.Body)
		if req.Body != nil {
			_ = req.Body.Close()
		}
		t.got <- append([]byte(nil), got...)
	} else if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	header := make(http.Header)
	header.Set("Content-Type", "text/plain")
	return &http.Response{
		Status:        "403 Forbidden",
		StatusCode:    http.StatusForbidden,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader([]byte("block"))),
		ContentLength: 5,
		Request:       req,
	}, nil
}
