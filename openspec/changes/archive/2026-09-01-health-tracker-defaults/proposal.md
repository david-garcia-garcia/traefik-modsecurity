## Why

Enabling WAF fail-open the way the README shows (`unhealthyWafBackOffPeriodSecs: 30`) trips after a single `httpClient.Do` error and never tumbles the failure count. That turns a graceful-degradation knob into a 30-second unfiltered window an attacker can re-trigger.

## What Changes

- Default `unhealthyWafFailureThreshold` becomes `5` (was `1`) so one timeout or dropped connection does not trip.
- Default `unhealthyWafFailureWindowSecs` becomes `10` (was `0`). `Prepare` fills an omitted zero, same as the other numeric fields, so the window always tumbles after config prepare.
- `health.New` starts `lastFailureReset` at construction when a window is set, so the first window is `[New, New+window)`.
- README and the health usage packet document the new defaults.
- **BREAKING** for operators who enabled backoff and relied on trip-on-first-error or lifetime accumulation without setting threshold/window. They can still set `unhealthyWafFailureThreshold: 1` explicitly.

## Capabilities

### New Capabilities

- `core_plugin_middleware_health-tracker`: WAF health-tracker trip defaults, tumbling failure window, and fail-open while unhealthy.

### Modified Capabilities

None.

## Impact

- `pkg/modsecurity/config.go` — `CreateConfig` / `Prepare` defaults
- `pkg/health/tracker.go` — `New` initializes `lastFailureReset`
- Tests under `pkg/health/` and `pkg/modsecurity/` that assume the old defaults
- `README.md` — documented defaults for threshold and window
- `knowledge/devdocs/core_plugin_health.md` — gotchas that currently state threshold `1` and window `0`
- Public config keys are unchanged; only omitted-zero defaults change
