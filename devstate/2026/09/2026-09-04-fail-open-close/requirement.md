# Requirement
IssueKey: 2026-09-04-fail-open-close

## Problem
When the ModSecurity sidecar cannot be reached or returns 5xx, this plugin always calls the next handler (fail-open). An operator who wants the opposite — refuse the request when WAF cannot inspect it — has no setting.

## Current (code)
- `pkg/modsecurity/config.go` — `Config` has timeout, health-tracker, body, bypass, and status-header fields. No fail-open / fail-close knob.
- `pkg/modsecurity/serve.go` (`ServeHTTP` after `httpClient.Do` error, excluding inbound `Canceled`) — `recordWafFailure` then `next.ServeHTTP` (fail-open).
- `pkg/modsecurity/serve.go` (sidecar status `>= 500`) — same: `recordWafFailure` then `next`.
- `pkg/modsecurity/serve.go` (`healthTracker.IsUnhealthy`) — skip sidecar and call `next` with status-header `unhealthy` (fail-open for later requests after trip).
- `pkg/modsecurity/serve.go` (`http.NewRequestWithContext` error) — `http.Error` HTTP 502; does not call `next`.
- `pkg/modsecurity/serve.go` (inbound `Canceled`) — HTTP 502; not a WAF health failure.
- `pkg/modsecurity/serve_test.go` `TestPlugin_WafFailureNeverFailClosed` — WAF transport/5xx must be HTTP 200 from `next`, never 502.
- `openspec/specs/core_plugin_middleware_waf-status/spec.md` — WAF communication failure SHALL call next; SHALL NOT return HTTP 502.
- `README.md` — “When ModSecurity is down, this plugin always fail-opens the current request”.

## Desired
The operator chooses fail-open or fail-close. Today’s behavior stays the default (fail-open). Fail-close means the client does not reach the backend when the WAF cannot inspect the request.

## Affected
- Public `Config` in `pkg/modsecurity/config.go` (and README / compose examples).
- `Plugin` + `ServeHTTP` WAF-failure and already-unhealthy paths in `pkg/modsecurity/serve.go`.
- Unit tests that assert fail-open-only (`pkg/modsecurity/serve_test.go` and related).
- Specs that currently forbid 502 on WAF failure (`core_plugin_middleware_waf-status`, `core_plugin_middleware_health-tracker`).
- Usage packet `knowledge/devdocs/core_plugin_middleware.md` and `knowledge/devdocs/core_plugin_health.md`.

## Out of scope
- Changing health-tracker threshold, window, or backoff defaults.
- Changing inbound-cancel 502, local 413 oversize, `denyVerbsWithBody` 400, bypass-rule skip, or security-block (3xx/4xx) copy.
- Inventing a new client status other than the existing 502 used on other plugin-owned refusals.
- Changing Traefik Hub / other WAF products.

## Unknowns
- Public field shape: boolean (`failClosed`) vs string mode.
- Whether fail-close also applies to the already-unhealthy skip (today that path always calls `next`).
- Exact client body on fail-close (empty 502 like `http.Error(rw, "", 502)` elsewhere vs a message).

## Tensions
- Ticket asks for operator-chosen fail-close; current specs and `TestPlugin_WafFailureNeverFailClosed` require fail-open and forbid 502 on WAF failure. Those specs and tests must change with the setting; default must stay fail-open so existing deploys do not flip.
