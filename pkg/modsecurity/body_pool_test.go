package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestBodyPoolRoute builds a plugin and route with a 200 WAF and a next that sets nextCalled and drains the body.
func newTestBodyPoolRoute(t *testing.T, maxBody, poolCap int64) (*Plugin, http.Handler, *bool) {
	t.Helper()
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "WAF OK")
	}))
	t.Cleanup(waf.Close)

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	cfg.MaxBodySizeBytes = maxBody
	cfg.MaxBodySizeBytesForPool = poolCap
	plugin, err := New("body-pool-test", cfg, NewLogger("body-pool-test", cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(plugin.Close)

	nextCalled := false
	route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("ForRoute: %v", err)
	}
	return plugin, route, &nextCalled
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

	plugin, route, nextCalled := newTestBodyPoolRoute(t, maxBody, poolCap)
	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = -1
	req.Header.Del("Content-Length")

	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !*nextCalled {
		t.Fatal("next was not called")
	}
	if got := pooledBufferCap(plugin); int64(got) > poolCap {
		t.Fatalf("pool retained buffer cap %d, want <= %d", got, poolCap)
	}
}

// TestPlugin_ParsedLengthAbovePoolCapSkipsPool checks a large parsed length is not kept in the pool even if the header is small.
func TestPlugin_ParsedLengthAbovePoolCapSkipsPool(t *testing.T) {
	const poolCap int64 = 1024
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("b"), 4096)

	plugin, route, nextCalled := newTestBodyPoolRoute(t, maxBody, poolCap)
	req := httptest.NewRequest(http.MethodPost, "http://example/test", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Length", "100")

	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !*nextCalled {
		t.Fatal("next was not called")
	}
	if got := pooledBufferCap(plugin); int64(got) > poolCap {
		t.Fatalf("pool retained buffer cap %d, want <= %d", got, poolCap)
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
