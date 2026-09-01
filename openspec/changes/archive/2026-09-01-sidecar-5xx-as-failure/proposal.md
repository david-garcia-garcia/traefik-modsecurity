## Why

A ModSecurity sidecar that answers HTTP 5xx is treated as a security block. Clients get the sidecar error page and `modSecurityStatusRequestHeader` is set to `blocked`, while `health.Tracker.RecordFailure` never runs, so `unhealthyWafBackOffPeriodSecs` fail-open cannot trip on the most common sidecar failure mode.

## What Changes

- Split sidecar status classes in `ServeHTTP`: `4xx` remains a security block; `5xx` is a WAF failure.
- On sidecar `5xx`, call `RecordFailure` when a health tracker exists and take the same path as an `httpClient.Do` transport error (fail-open when unhealthy; otherwise 502 with an empty body).
- Set `modSecurityStatusRequestHeader` to `error` on every sidecar `5xx`, not `blocked`.
- Add unit tests for sidecar 5xx (header, no forwarded sidecar page when not failing open, fail-open after threshold).
- No new public config keys. Not **BREAKING** for 4xx blocks. Operators who today see a forwarded sidecar 5xx page will instead see 502 or fail-open.

## Capabilities

### New Capabilities

- `core_plugin_middleware_waf-status`: How the plugin classifies the ModSecurity sidecar HTTP status as pass, security block, or WAF failure.

### Modified Capabilities

None.

## Impact

- `pkg/modsecurity/serve.go` — status-class split and 5xx failure path.
- `modsecurity_test.go` — 5xx cases.
- `knowledge/devdocs/core_plugin_middleware.md` and `knowledge/devdocs/core_plugin_health.md` — usage contract (devdocsimpact).
- Existing 403/406 block tests stay green.
