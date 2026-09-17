# Devdocs impact
change: adopt-upstream-backendbackoff

## Units
- WAF backoff gate — subsystem — `pkg/modsecurity/plugin.go`, `pkg/modsecurity/serve.go`, `openspec/changes/adopt-upstream-backendbackoff/specs/core_plugin_middleware_waf-backoff`
- Middleware — subsystem — `pkg/modsecurity/`, `knowledge/devdocs/core_plugin_middleware.md`
- Layout — subsystem — `knowledge/devdocs/core_plugin_layout.md`
- Reclaim table — subsystem — `knowledge/devdocs/core_plugin_reclaim.md`
- Unit tests — pattern — `knowledge/devdocs/build_testing_go.md`

## Findings
- [x] stale-usage  Unit tests — `build_testing_go` still named `TestRecordFailure_WindowReset` after `pkg/health` was deleted
