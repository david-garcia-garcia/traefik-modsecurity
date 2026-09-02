## Context

See proposal.md — Why. `Plugin.ServeHTTP` binds the sidecar request with `http.NewRequestWithContext(req.Context(), …)` in `pkg/modsecurity/serve.go`. The `Do` error path always calls `healthTracker.RecordFailure()` when a tracker exists.

Parent change `waf-request-context` parked health classification: treating inbound cancel as a non-failure was an explicit non-goal.

Research: `knowledge/research/ext_http_client_request-context/`. Measured: inbound cancel sets `req.Context().Err()` and `Do` unwraps to `context.Canceled`. `http.Client.Timeout` leaves inbound `Err()` nil and `Do` unwraps to `context.DeadlineExceeded` with `Client.Timeout exceeded while awaiting headers`.

## Goals / Non-Goals

**Goals:**

- Skip `RecordFailure` when the inbound request context is already done.
- Keep `RecordFailure` for `timeoutMillis` and other sidecar/transport errors while inbound stays live.
- Prove both with unit tests.

**Non-Goals:**

- Changing tracker threshold, window, backoff, or `IsUnhealthy` fail-open.
- Changing the non-trip `Do` error response (502).
- New config keys.
- Recording or skipping failures on body-read or request-prepare errors.

## Decisions

### Skip from inbound `Context.Err()`, not from the `Do` error

`req.Context().Err() != nil` means the inbound request is done. That is the owner of inbound-done. Do not use `errors.Is(doErr, context.DeadlineExceeded)`: `Client.Timeout` also unwraps to that while inbound `Err()` is nil.

Alternatives considered: skip whenever `errors.Is(doErr, context.Canceled) || errors.Is(doErr, context.DeadlineExceeded)`. Rejected — client timeout would be skipped. Alternative: parse the `Client.Timeout exceeded` string. Rejected — the inbound context already owns the fact.

### Keep the existing non-trip `Do` path

After skip, fall through to the current error log and `http.Error` 502. Do not fail-open the canceled request. Ticket: do not invent other health-tracker behavior.

Alternatives considered: treat inbound cancel as success and call `next`. Rejected — that would be a new fail-open rule.

### Unit tests next to the existing cancel test

Extend `pkg/modsecurity/serve_test.go`. Enable `UnhealthyWafBackOffPeriodSecs` and threshold 1. Assert `plugin.IsUnhealthy()` false after inbound cancel / inbound deadline, true after client timeout with a live inbound context. Existing `httptest` mock WAF is enough.

Alternatives considered: change `pkg/health` to accept an error and classify inside the tracker. Rejected — the tracker owns counts and backoff, not request-context ownership. Classification belongs at the `Do` call site that has `req`.

## Risks / Trade-offs

- [Risk] A sidecar outage that coincides with a client disconnect is not counted. → Accepted. The inbound context is done; counting it would restore the disconnect-flood trip.
- [Risk] Future code that cancels the inbound context on sidecar errors could hide real failures. → No such cancel exists today. Do not add one.

## Migration Plan

No config or API migration. Deploy the new plugin version. Rollback is revert of the `Do` error-path skip.
