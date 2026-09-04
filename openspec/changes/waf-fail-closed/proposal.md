## Why

On `main`, a WAF communication failure always calls `next` (fail-open). Operators who must not send traffic to the backend when ModSecurity cannot inspect the request have no setting.

## What Changes

- Add public middleware config `failClosed` (bool). Omitted or false keeps today’s fail-open. True fail-closes.
- On WAF communication failure (sidecar transport error except inbound cancel, or sidecar 5xx), `failClosed: true` returns empty HTTP 502 and does not call `next`.
- The already-unhealthy skip uses the same choice: fail-close returns empty HTTP 502 with status-header `unhealthy` instead of calling `next`.
- Default remains fail-open. Not **BREAKING**.
- README documents the knob. Specs that currently forbid 502 on WAF failure become conditional.

## Capabilities

### New Capabilities

- `core_plugin_middleware_fail-closed`: Operator `failClosed` knob, default false, and how fail-close refuses the client when the WAF cannot inspect.

### Modified Capabilities

- `core_plugin_middleware_waf-status`: WAF communication failure SHALL fail-open unless `failClosed` is true; then empty HTTP 502, no `next`.
- `core_plugin_middleware_health-tracker`: Already-unhealthy skip and “backoff off” WAF failure follow `failClosed` instead of always calling `next`.
- `core_plugin_middleware_log-level`: WAF forward-failure log scenario is true for both fail-open and fail-close.
- `core_plugin_middleware_sidecar-response`: Drain 5xx body before fail-open to `next` or fail-close 502.

## Impact

- `pkg/modsecurity/config.go` (`Config`, `CreateConfig`; bool zero is the default, no Prepare fill).
- `pkg/modsecurity/plugin.go` (store the flag on `Plugin`).
- `pkg/modsecurity/serve.go` (WAF failure and already-unhealthy paths).
- Unit tests that currently require fail-open-only (`pkg/modsecurity/serve_test.go` and related).
- `README.md` configuration section.
- Usage packets `knowledge/devdocs/core_plugin_middleware.md` and `knowledge/devdocs/core_plugin_health.md` (devdocs-impact).
