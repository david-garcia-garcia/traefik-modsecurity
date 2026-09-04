## Context

`ServeHTTP` fail-opens on sidecar transport errors (except inbound cancel) and sidecar 5xx. The already-unhealthy skip also calls `next`. `http.NewRequestWithContext` failure already returns empty HTTP 502. Operators need a knob; default must stay fail-open.

## Goals / Non-Goals

**Goals:**

- Public `failClosed` bool, default false.
- Fail-close = empty HTTP 502, no `next`, on WAF communication failure and on already-unhealthy skip.
- Keep health-tracker `RecordFailure` and status-header tokens (`error` / `unhealthy`).
- Keep inbound cancel, local 413, deny-verb 400, bypass, and 3xx/4xx copy unchanged.

**Non-Goals:**

- String failure-mode enum.
- New HTTP status besides existing 502.
- Changing tracker threshold/window/backoff defaults.

## Decisions

- Bool `failClosed` with `json:"failClosed,omitempty"`. False is the Go zero; CreateConfig can omit it; Prepare does not need a fill. Reclaim hash already JSON-marshals Config, so the field participates automatically once it is on the struct.
- Store the flag on `Plugin` in `New`. Branch in `ServeHTTP` after `recordWafFailure` and on the unhealthy early return. Do not duplicate 502 writing; one helper that writes empty 502 (reuse `http.Error(rw, "", http.StatusBadGateway)`).
- Fail-close on unhealthy skip: otherwise after trip, fail-close is bypassed. `denyVerbsWithBody` still 400s before that skip (`core_plugin_health.md`).
- Drain sidecar 5xx body before either next or 502 so the idle pool still works.

## Risks / Trade-offs

- Fail-close makes a down sidecar look like an outage to clients (502). That is the operator’s choice; document it in README.
- Tests named `NeverFailClosed` must become default-path tests plus explicit `failClosed: true` cases.

## Migration Plan

- Existing deploys omit the field → fail-open, same as `main`.
- Operators who want fail-close set `failClosed: true` in the middleware plugin YAML/labels.
