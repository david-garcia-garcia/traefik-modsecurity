package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// isolateBodyBufferPool swaps in a fresh pool so Get after the request sees only this test's Put.
func isolateBodyBufferPool(t *testing.T) {
	t.Helper()
	original := bodyBufferPool
	bodyBufferPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
	t.Cleanup(func() {
		bodyBufferPool = original
	})
}

// newTestBodyPoolRoute builds a plugin and route with a 200 WAF and a next that records the body.
func newTestBodyPoolRoute(t *testing.T, maxBody, poolCap int64) (http.Handler, *bool) {
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
	return route, &nextCalled
}

// pooledBufferCap returns the capacity of the next buffer taken from bodyBufferPool.
func pooledBufferCap() int {
	buf := bodyBufferPool.Get().(*bytes.Buffer)
	return buf.Cap()
}

func TestPlugin_UnknownLengthDoesNotRetainOversizedPoolBuffer(t *testing.T) {
	isolateBodyBufferPool(t)
	const poolCap int64 = 1024
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("a"), 4096)

	route, nextCalled := newTestBodyPoolRoute(t, maxBody, poolCap)
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
	if got := pooledBufferCap(); int64(got) > poolCap {
		t.Fatalf("pool retained buffer cap %d, want <= %d", got, poolCap)
	}
}

func TestPlugin_ParsedLengthAbovePoolCapSkipsPool(t *testing.T) {
	isolateBodyBufferPool(t)
	const poolCap int64 = 1024
	const maxBody int64 = 8192
	body := bytes.Repeat([]byte("b"), 4096)

	route, nextCalled := newTestBodyPoolRoute(t, maxBody, poolCap)
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
	if got := pooledBufferCap(); int64(got) > poolCap {
		t.Fatalf("pool retained buffer cap %d, want <= %d", got, poolCap)
	}
}
