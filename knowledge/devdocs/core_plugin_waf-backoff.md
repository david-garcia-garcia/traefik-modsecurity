# WAF backoff gate

## Language

**WAF backoff gate**:
Per Plugin core admission gate for sidecar calls. After the configured threshold of WAF communication failures it skips the sidecar for a cooldown, then admits one probe.
_Avoid_: circuit breaker, health tracker

## Overview

The Plugin core owns one `backendbackoff.Gate` when `unhealthyWafBackOffPeriodSecs` is greater than zero. Routes that share that core share the trip. `Allow` decides whether this request may call the sidecar. `Report` records only admitted attempts.

## How to use

- Build the gate in `New` when backoff seconds are greater than zero. Map threshold to `TripFailures`, backoff seconds to `BaseCooldown`, and max backoff (or the same base) to `MaxCooldown`. Leave Jitter 0. Pass an explicit `FailureRatio` only when the operator set one.
- Call `Allow` with key `waf` before `httpClient.Do`. On deny, follow prepared `failMode` and do not `Report`.
- After an admitted call: do not `Report` inbound `Canceled`. `Report(false)` on other transport errors and sidecar `5xx`. `Report(true)` on sidecar status below 500. Match cancel with `errors.Is` on `req.Context().Err()`.
- When skipped, follow `failMode`: `open` forwards to `next`; `close` writes empty HTTP 502. Set the status request header to `unhealthy`. Still return HTTP 400 first when `denyVerbsWithBody` lists the method and a body is present (`core_plugin_middleware.md`).
- Close the gate from `Plugin.Close`.

## Key files

- `pkg/modsecurity/plugin.go` — `newWafGate`, `Plugin.Close`.
- `pkg/modsecurity/serve.go` — `Allow` / `Report` on the request path.
- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff/` — imported gate.

## Gotchas

- `Allow` is not a peek. Do not call it to implement `IsUnhealthy`.
- Window seconds stay on Config for Prepare and reclaim hash. They do not reset the credit budget.
- Threshold `0` is replaced by `Prepare` with the CreateConfig default (`5`).
- Sharing one gate across routes of the same name+config is intentional.
- Inbound cancel aborts the WAF call and is not a WAF outage. Log it as inbound-done.
