package traefik_modsecurity

import (
	"context"
	"net/http"
	"testing"

	"github.com/david-garcia-garcia/traefik-modsecurity/pkg/modsecurity"
	"github.com/david-garcia-garcia/traefik-modsecurity/pkg/reclaim"
)

func TestPluginConfigHash_FailModeChangesKey(t *testing.T) {
	openCfg := CreateConfig()
	openCfg.ModSecurityUrl = "http://waf"
	closedCfg := CreateConfig()
	closedCfg.ModSecurityUrl = "http://waf"
	closedCfg.FailMode = modsecurity.FailModeClose
	if err := modsecurity.Prepare(openCfg, "n"); err != nil {
		t.Fatal(err)
	}
	if err := modsecurity.Prepare(closedCfg, "n"); err != nil {
		t.Fatal(err)
	}
	if pluginConfigHash(openCfg) == pluginConfigHash(closedCfg) {
		t.Fatal("prepared failMode must change the reclaim hash")
	}
}

func TestNew_DifferentFailModeCreatesTwoCores(t *testing.T) {
	t.Cleanup(reclaim.Reset)
	reclaim.Reset()

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	openCfg := CreateConfig()
	openCfg.ModSecurityUrl = "http://waf"
	closedCfg := CreateConfig()
	closedCfg.ModSecurityUrl = "http://waf"
	closedCfg.FailMode = modsecurity.FailModeClose

	first, err := New(context.Background(), next, openCfg, "waf")
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(context.Background(), next, closedCfg, "waf")
	if err != nil {
		t.Fatal(err)
	}
	openRoute, ok := first.(*modsecurity.Route)
	if !ok {
		t.Fatalf("want *modsecurity.Route, got %T", first)
	}
	closedRoute, ok := second.(*modsecurity.Route)
	if !ok {
		t.Fatalf("want *modsecurity.Route, got %T", second)
	}
	if openRoute.SameCore(closedRoute) {
		t.Fatal("different failMode must not share a core")
	}
}
