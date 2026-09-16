package traefik_modsecurity

import (
	"testing"
	"time"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim"
)

// resetPluginReclaimForTest replaces the shared table with one at grace, then restores DefaultGrace.
func resetPluginReclaimForTest(t *testing.T, grace time.Duration) {
	t.Helper()
	pluginReclaim.Reset()
	pluginReclaim = reclaim.New(reclaim.Config{Grace: grace})
	t.Cleanup(func() {
		pluginReclaim.Reset()
		pluginReclaim = reclaim.New(reclaim.Config{Grace: reclaim.DefaultGrace})
	})
}
