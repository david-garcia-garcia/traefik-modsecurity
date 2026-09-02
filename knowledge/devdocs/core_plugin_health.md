# Health tracker

## Language

**Health tracker**:
Per Plugin core counter of WAF client failures. After the configured threshold it marks the WAF unhealthy for a backoff period.
_Avoid_: circuit breaker

## Overview

`pkg/health` trips when outbound calls to ModSecurity fail, including a sidecar HTTP 5xx. The Plugin core owns one tracker when `unhealthyWafBackOffPeriodSecs` is greater than zero. Routes that share that core share the trip.

## How to use

- Build the tracker in `New` when backoff seconds are greater than zero. Pass the Plugin slog logger. Trip at warn (expected backoff); backoff expiry at info.
- Call `RecordFailure` after `httpClient.Do` errors unless the inbound request is `context.Canceled`, and after a sidecar `5xx`. Match cancel with `errors.Is` on `req.Context().Err()`. Inbound `DeadlineExceeded` still counts. Call `IsUnhealthy` before sending to the WAF.
- When unhealthy, forward to `next` (fail-open) and optionally set the status request header to `unhealthy`. Still return HTTP 400 first when `denyVerbsWithBody` lists the method and a body is present (`core_plugin_middleware.md`).
- On a sidecar `5xx`, set the status request header to `error` when configured (every such request, not only the trip).

## Key files

- `pkg/health/tracker.go` — `Tracker`, `New`, `RecordFailure`, `IsUnhealthy`.
- `pkg/modsecurity/plugin.go` — constructs the tracker.
- `pkg/modsecurity/serve.go` — uses it on the request path.

## Gotchas

- Threshold `< 0` never trips inside `health.New`. Plugin `Prepare` rejects a negative `unhealthyWafFailureThreshold`, so that opt-out is not reachable from public config. Threshold `0` is replaced by `Prepare` with the CreateConfig default (`5`).
- Window `0` is replaced by `Prepare` with the CreateConfig default (`10`). After prepare the window always tumbles. `health.New` with window `0` still never resets (tests).
- `health.New` starts the first window at construction when a window is set.
- Sharing one tracker across routes of the same name+config is intentional.
- Inbound cancel aborts the WAF call and is not “fail to send HTTP request to modsec”. Log it as inbound-done. Inbound deadline and live-inbound sidecar/transport failures still trip health; keep the Error string for those.
