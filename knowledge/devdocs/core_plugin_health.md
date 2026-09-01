# Health tracker

## Language

**Health tracker**:
Per Plugin core counter of WAF client failures. After the configured threshold it marks the WAF unhealthy for a backoff period.
_Avoid_: circuit breaker

## Overview

`pkg/health` trips when outbound calls to ModSecurity fail. The Plugin core owns one tracker when `unhealthyWafBackOffPeriodSecs` is greater than zero. Routes that share that core share the trip.

## How to use

- Build the tracker in `NewCore` when backoff seconds are greater than zero.
- Call `RecordFailure` after `httpClient.Do` errors. Call `IsUnhealthy` before sending to the WAF.
- When unhealthy, forward to `next` (fail-open) and optionally set the status request header to `unhealthy`.

## Key files

- `pkg/health/tracker.go` — `Tracker`, `New`, `RecordFailure`, `IsUnhealthy`.
- `pkg/modsecurity/plugin.go` — constructs the tracker.
- `pkg/modsecurity/serve.go` — uses it on the request path.

## Gotchas

- Threshold `< 0` never trips. Threshold `0` is replaced by `Prepare` with the CreateConfig default (`1`).
- Window `0` means the failure count never resets until backoff expires.
- Sharing one tracker across routes of the same name+config is intentional.
