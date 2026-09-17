## Why

The plugin still trips WAF backoff with a local tumbling-window counter in `pkg/health` while `traefik-middleware-utilities` already ships a Yaegi-safe `backendbackoff` gate with a half-open probe. Keeping the fork drifts operator backoff from that shared module and leaves probe recovery untested here.

## What Changes

- Delete `pkg/health` and construct an upstream `backendbackoff.Gate` on the Plugin when `unhealthyWafBackOffPeriodSecs` is greater than zero.
- Call `Allow` / `Report` around the sidecar `httpClient.Do` instead of `IsUnhealthy` / `RecordFailure`.
- Map `unhealthyWafFailureThreshold` to `TripFailures` and `unhealthyWafBackOffPeriodSecs` to `BaseCooldown` (and `MaxCooldown` unless the max knob is set).
- Keep `unhealthyWafFailureWindowSecs` on Config for Prepare and reclaim hash; do not pass it to the gate.
- Add `unhealthyWafFailureRatio` (0 means packaged 0.30) and `unhealthyWafMaxBackOffPeriodSecs` (0 means equal to base).
- **BREAKING** (behavior): after cooldown the plugin admits one half-open probe instead of sending every request; successes refill credit; the tumbling window no longer resets the failure count.
- Rename the `health-tracker` spec leaf to `waf-backoff` (the leaf named the deleted tracker).
- Cover trip, skip, one probe after cooldown, inbound cancel, 5xx, and sidecar status below 500 at plugin level.

## Capabilities

### New Capabilities
- `core_plugin_middleware_waf-backoff`: WAF admission gate owned by one Plugin core — enablement, knob mapping, Allow/Report, half-open probe, failMode while OPEN.

### Modified Capabilities
- `core_plugin_middleware_health-tracker`: remove the tumbling-window tracker requirements (unit renamed to `waf-backoff`).
- `core_plugin_middleware_health-failures`: inbound cancel still does not Report; timeout, deadline, and unreachable sidecar still Report failure.
- `core_plugin_middleware_prepare-validation`: reject negative `unhealthyWafFailureRatio` and `unhealthyWafMaxBackOffPeriodSecs`; reject a ratio outside (0, 1) when set.
- `core_plugin_middleware_instance-reuse`: the shared core owns the Gate, not a health tracker.

## Impact

- `pkg/health/` deleted.
- `pkg/modsecurity/plugin.go`, `serve.go`, `config.go`, and health-related tests.
- `go.mod` / `vendor/` gain the `backendbackoff` package from the already-required `traefik-middleware-utilities v1.0.3`.
- Public JSON: two new knobs; window field unused by the gate; recovery is half-open.
- Usage packets `core_plugin_health.md`, `core_plugin_layout.md`, `core_plugin_middleware.md`.
- Drain-stack compose may keep `unhealthyWafFailureWindowSecs`; Pester resume still waits the backoff period, then expects one sidecar consult.
