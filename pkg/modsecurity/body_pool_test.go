package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// bodyPoolHarness is one Plugin core, a 200 WAF, and a next that records the restored body.
type bodyPoolHarness struct {
	plugin     *Plugin
	route      http.Handler
	nextCalled bool
	nextBody   []byte
	wafBody    []byte
}

// newTestBodyPoolRoute builds a plugin and route with a 200 WAF and a next that records the restored body.
func newTestBodyPoolRoute(t *testing.T, maxBody, poolCap int64) *bodyPoolHarness {
	t.Helper()
	h := &bodyPoolHarness{}
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.wafBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "WAF OK")
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.MaxBodySizeBytes = maxBody
	cfg.MaxBodySizeBytesForPool = poolCap
	cfg.ModSecurityStatusRequestHeader = "X-Waf-Status"
	plugin, err := New("body-pool-test", cfg, NewLogger("body-pool-test", cfg))
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

// pooledBufferCap returns the capacity of the next buffer taken from this Plugin core's pool.
func pooledBufferCap(p *Plugin) int {
	buf := p.bodyBufferPool.Get().(*bytes.Buffer)
	return buf.Cap()
}

// TestPlugin_UnknownLengthDoesNotRetainOversizedPoolBuffer checks a ContentLength -1 read does not Put a grown buffer.
func TestPlugin_UnknownLengthDoesNotRetainOversizedPoolBuffer(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("a"), 4096)

	h := newTestBodyPoolRoute(t, maxBody, poolCap)
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
	if got := pooledBufferCap(h.plugin); int64(got) > poolCap {
		t.Fatalf("pool retained buffer cap %d, want <= %d", got, poolCap)
	}
}

// TestPlugin_ParsedLengthAbovePoolCapSkipsPool checks a large parsed length is not kept in the pool even if the header is small.
func TestPlugin_ParsedLengthAbovePoolCapSkipsPool(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("b"), 4096)

	h := newTestBodyPoolRoute(t, maxBody, poolCap)
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
	if got := pooledBufferCap(h.plugin); int64(got) > poolCap {
		t.Fatalf("pool retained buffer cap %d, want <= %d", got, poolCap)
	}
}

// TestPlugin_SmallPooledReadReturnsBuffer checks a body under the pool cap is Put back.
func TestPlugin_SmallPooledReadReturnsBuffer(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("s"), 200)

	h := newTestBodyPoolRoute(t, maxBody, poolCap)
	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	rec := httptest.NewRecorder()
	h.route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	got := pooledBufferCap(h.plugin)
	if got == 0 {
		t.Fatal("small pooled read must Put a buffer (Get after ServeHTTP allocated New with cap 0)")
	}
	if int64(got) > poolCap {
		t.Fatalf("pool retained buffer cap %d, want <= %d", got, poolCap)
	}
}

// TestPlugin_UnknownLengthOverMaxReturns413 checks a pooled read that hits MaxBytesReader is 413 and does not call next.
func TestPlugin_UnknownLengthOverMaxReturns413(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 2048
	body := bytes.Repeat([]byte("x"), 4096)

	h := newTestBodyPoolRoute(t, maxBody, poolCap)
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

// TestPlugin_HTTP1ChunkedAbovePoolCapDoesNotRetain sends a real HTTP/1 chunked POST through net/http.
func TestPlugin_HTTP1ChunkedAbovePoolCapDoesNotRetain(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("c"), 4096)

	h := newTestBodyPoolRoute(t, maxBody, poolCap)
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
		t.Fatalf("sidecar/next body mismatch: waf=%d next=%d want=%d", len(h.wafBody), len(h.nextBody), len(body))
	}
	if got := pooledBufferCap(h.plugin); int64(got) > poolCap {
		t.Fatalf("pool retained buffer cap %d, want <= %d", got, poolCap)
	}
}

// TestPlugin_HTTP1ChunkedOverMaxReturns413 sends a chunked POST larger than maxBodySizeBytes.
func TestPlugin_HTTP1ChunkedOverMaxReturns413(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 2048
	body := bytes.Repeat([]byte("d"), 4096)

	h := newTestBodyPoolRoute(t, maxBody, poolCap)
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

// TestPlugin_BodyBufferPoolIsPerCore checks two Plugin cores do not share a body buffer pool.
func TestPlugin_BodyBufferPoolIsPerCore(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://127.0.0.1:9"
	a, err := New("body-pool-a", cfg, NewLogger("body-pool-a", cfg))
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	t.Cleanup(a.Close)
	b, err := New("body-pool-b", cfg, NewLogger("body-pool-b", cfg))
	if err != nil {
		t.Fatalf("New b: %v", err)
	}
	t.Cleanup(b.Close)
	if a.bodyBufferPool == nil || b.bodyBufferPool == nil {
		t.Fatal("New must own a body buffer pool")
	}
	if a.bodyBufferPool == b.bodyBufferPool {
		t.Fatal("distinct Plugin cores must not share a body buffer pool")
	}
}
