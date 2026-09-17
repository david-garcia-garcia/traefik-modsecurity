# Scope

| Ticket | Demand | In diff | Status |
|--------|--------|---------|--------|
| 2026-09-16-upstream-health-probe | Remove the custom `pkg/health` tracker | `pkg/health/tracker.go` and `pkg/health/tracker_test.go` deleted | OK |
| 2026-09-16-upstream-health-probe | Wire the plugin through upstream `backendbackoff` | `pkg/modsecurity/plugin.go` (`newWafGate`), `pkg/modsecurity/serve.go` (`Allow`/`Report`), `vendor/.../backendbackoff/` | OK |
| 2026-09-16-upstream-health-probe | Preserve operator-visible WAF backoff or document new knobs | Existing backoff knobs kept; `unhealthyWafFailureRatio` and `unhealthyWafMaxBackOffPeriodSecs` added and documented in `README.md` | OK |
| 2026-09-16-upstream-health-probe | Replace or extend tests for probe, trip, recovery, and fail-open (unit plus plugin-level) | `pkg/modsecurity/serve_test.go` (trip, fail-open, `TestPlugin_OneProbeAfterCooldown`, concurrent probe skip); `pkg/modsecurity/config_test.go` | OK |

none.
