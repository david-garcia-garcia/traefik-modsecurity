## 1. Config and Plugin

- [ ] Add `FailClosed bool` to `Config` with `json:"failClosed,omitempty"` in `pkg/modsecurity/config.go`. Do not treat omitted as a Prepare fill (false is the default).
- [ ] Store `failClosed` on `Plugin` in `New` (`pkg/modsecurity/plugin.go`).
- [ ] Document `failClosed` in `README.md` next to the health-tracker knob.

## 2. ServeHTTP

- [ ] After `recordWafFailure` on transport error and sidecar 5xx: fail-open to `next` when `failClosed` is false; empty HTTP 502 when true.
- [ ] On already-unhealthy skip: same choice; keep status-header `unhealthy`; do not call the sidecar.
- [ ] Keep inbound `Canceled` and `NewRequestWithContext` failure on their existing 502 paths.
- [ ] Drain sidecar 5xx body before fail-open or fail-close.

## 3. Tests

- [ ] Keep default (`failClosed` omitted/false) cases asserting fail-open (replace “never fail-closed” as the only mode).
- [ ] Add `failClosed: true` cases for sidecar 5xx, transport error, and already-unhealthy skip (502, `next` not called, status-header `error` or `unhealthy`).
- [ ] Prove omitted `failClosed` still fail-opens so existing deploys do not flip.

## 4. Specs

- [ ] Implement `core_plugin_middleware_fail-closed` scenarios.
- [ ] Align waf-status, health-tracker, log-level, and sidecar-response deltas.
