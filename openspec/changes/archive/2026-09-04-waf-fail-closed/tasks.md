## 1. Config and Plugin

- [x] Add `FailMode string` to `Config` with `json:"failMode,omitempty"` in `pkg/modsecurity/config.go`. CreateConfig default `open`. Prepare fills empty to `open`, normalizes case, rejects other values.
- [x] Store prepared `failMode` on `Plugin` in `New` (`pkg/modsecurity/plugin.go`).
- [x] Document `failMode` in `README.md` next to the health-tracker knob.

## 2. ServeHTTP

- [x] After `recordWafFailure` on transport error and sidecar 5xx: fail-open to `next` when `failMode` is `open`; empty HTTP 502 when `close`.
- [x] On already-unhealthy skip: same choice; keep status-header `unhealthy`; do not call the sidecar.
- [x] Keep inbound `Canceled` and `NewRequestWithContext` failure on their existing 502 paths.
- [x] Drain sidecar 5xx body before fail-open or fail-close.

## 3. Tests

- [x] Keep default (`failMode` omitted/`open`) cases asserting fail-open (replace “never fail-closed” as the only mode).
- [x] Add `failMode: close` cases for sidecar 5xx, transport error, and already-unhealthy skip (502, `next` not called, status-header `error` or `unhealthy`).
- [x] Prove omitted `failMode` still fail-opens so existing deploys do not flip.
- [x] Prove unknown `failMode` fails Prepare.

## 4. Specs

- [x] Implement `core_plugin_middleware_fail-closed` scenarios.
- [x] Align waf-status, health-tracker, log-level, and sidecar-response deltas.
