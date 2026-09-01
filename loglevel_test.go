package traefik_modsecurity

import (
	"context"
	"net/http"
	"testing"

	"github.com/david-garcia-garcia/traefik-modsecurity/pkg/modsecurity"
	"github.com/david-garcia-garcia/traefik-modsecurity/pkg/reclaim"
)

func TestPluginConfigHash_LogLevelChangesKey(t *testing.T) {
	infoCfg := CreateConfig()
	infoCfg.ModSecurityUrl = "http://waf"
	debugCfg := CreateConfig()
	debugCfg.ModSecurityUrl = "http://waf"
	debugCfg.LogLevel = "debug"
	if err := modsecurity.Prepare(infoCfg, "n"); err != nil {
		t.Fatal(err)
	}
	if err := modsecurity.Prepare(debugCfg, "n"); err != nil {
		t.Fatal(err)
	}
	if pluginConfigHash(infoCfg) == pluginConfigHash(debugCfg) {
		t.Fatal("prepared logLevel must change the reclaim hash")
	}
}

func TestNew_DifferentLogLevelCreatesTwoCores(t *testing.T) {
	t.Cleanup(reclaim.Reset)
	reclaim.Reset()

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	infoCfg := CreateConfig()
	infoCfg.ModSecurityUrl = "http://waf"
	debugCfg := CreateConfig()
	debugCfg.ModSecurityUrl = "http://waf"
	debugCfg.LogLevel = "debug"

	first, err := New(context.Background(), next, infoCfg, "waf")
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(context.Background(), next, debugCfg, "waf")
	if err != nil {
		t.Fatal(err)
	}
	infoRoute, ok := first.(*modsecurity.Route)
	if !ok {
		t.Fatalf("want *modsecurity.Route, got %T", first)
	}
	debugRoute, ok := second.(*modsecurity.Route)
	if !ok {
		t.Fatalf("want *modsecurity.Route, got %T", second)
	}
	if infoRoute.SameCore(debugRoute) {
		t.Fatal("different logLevel must not share a core")
	}
}
