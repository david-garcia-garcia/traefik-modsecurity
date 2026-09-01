package traefik_modsecurity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/david-garcia-garcia/traefik-modsecurity/pkg/modsecurity"
	"github.com/david-garcia-garcia/traefik-modsecurity/pkg/reclaim"
)

func testReuseConfig(wafURL string) *Config {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = wafURL
	return cfg
}

func testNextOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func testRoute(t *testing.T, h http.Handler) *modsecurity.Route {
	t.Helper()
	route, ok := h.(*modsecurity.Route)
	if !ok {
		t.Fatalf("handler type %T, want *modsecurity.Route", h)
	}
	return route
}

func TestNew_SameNameAndConfig_SharesCore(t *testing.T) {
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

	cfg := testReuseConfig("http://127.0.0.1:9")
	ctx := context.Background()
	a, err := New(ctx, testNextOK(), cfg, "waf")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(ctx, testNextOK(), cfg, "waf")
	if err != nil {
		t.Fatal(err)
	}
	ra, rb := testRoute(t, a), testRoute(t, b)
	if !ra.SameCore(rb) {
		t.Fatal("same name+config must share one plugin core")
	}
	if ra.HTTPClient() == nil || ra.HTTPClient() != rb.HTTPClient() {
		t.Fatal("shared core must own one HTTP client")
	}
}

func TestNew_DifferentName_DoesNotShareCore(t *testing.T) {
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

	cfg := testReuseConfig("http://127.0.0.1:9")
	ctx := context.Background()
	a, err := New(ctx, testNextOK(), cfg, "waf-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(ctx, testNextOK(), cfg, "waf-b")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, a).SameCore(testRoute(t, b)) {
		t.Fatal("different middleware names must not share a core")
	}
}

func TestNew_DifferentConfig_DoesNotShareCore(t *testing.T) {
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

	cfgA := testReuseConfig("http://127.0.0.1:9")
	cfgB := testReuseConfig("http://127.0.0.1:9")
	cfgB.TimeoutMillis = 9000
	ctx := context.Background()
	a, err := New(ctx, testNextOK(), cfgA, "waf")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(ctx, testNextOK(), cfgB, "waf")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, a).SameCore(testRoute(t, b)) {
		t.Fatal("different prepared config must not share a core")
	}
}

func TestNew_AfterDispose_NewIncarnation(t *testing.T) {
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

	cfg := testReuseConfig("http://127.0.0.1:9")
	ctx, cancel := context.WithCancel(context.Background())
	first, err := New(ctx, testNextOK(), cfg, "waf")
	if err != nil {
		t.Fatal(err)
	}
	firstCore := testRoute(t, first).HTTPClient()
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		probeCtx, probeCancel := context.WithCancel(context.Background())
		second, err := New(probeCtx, testNextOK(), cfg, "waf")
		if err != nil {
			probeCancel()
			t.Fatal(err)
		}
		different := testRoute(t, second).HTTPClient() != firstCore
		probeCancel()
		if different {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("after last holder and zero grace, New must create a new core")
}

func TestNew_SharedHealthTracker(t *testing.T) {
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

	cfg := testReuseConfig("http://127.0.0.1:1")
	cfg.UnhealthyWafBackOffPeriodSecs = 30
	cfg.UnhealthyWafFailureThreshold = 1
	ctx := context.Background()
	a, err := New(ctx, testNextOK(), cfg, "waf")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(ctx, testNextOK(), cfg, "waf")
	if err != nil {
		t.Fatal(err)
	}
	ra, rb := testRoute(t, a), testRoute(t, b)
	if !ra.SameCore(rb) {
		t.Fatal("expected shared core for health test")
	}

	req := httptest.NewRequest(http.MethodGet, "http://incoming.example/probe", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if !ra.IsUnhealthy() {
		t.Fatal("first failure must trip the shared health tracker")
	}
	if !rb.IsUnhealthy() {
		t.Fatal("second handler must observe the same unhealthy state")
	}
}
