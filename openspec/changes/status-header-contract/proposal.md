## Why

Operators configure `modSecurityStatusRequestHeader` so Traefik access logs can alert on WAF outcomes. The README promises a sidecar HTTP status on block and `error` on communication failure, but the plugin writes the literal `blocked` (including for local 413s that never reached ModSecurity) and writes `error` only on the request that trips the health tracker. Client-controllable rejections also log at Error, so an attacker can generate unbounded Error volume.

## What Changes

- On a sidecar block (`status >= 400`), write the decimal status code (e.g. `403`) on the status request header instead of `blocked`.
- On a local MaxBytesError 413, write `toolarge` instead of `blocked`.
- On every sidecar `httpClient.Do` failure, write `error` when the header is configured, whether or not a health tracker exists or this request tripped it.
- Downgrade ignore-verb-has-body and both body-too-large logs from Error to Warn.
- Document `toolarge` in the README header-value list. Keep `unhealthy` and `cannotforward`.
- Update unit tests that still expect `blocked` on WAF-block cases.

## Capabilities

### New Capabilities

- `core_plugin_middleware_status-header`: Values written on `modSecurityStatusRequestHeader` for WAF block, local 413, sidecar communication failure, unhealthy backoff, and cannot-forward.

### Modified Capabilities

- `core_plugin_middleware_log-level`: Client-fault request rejections (ignore-verb body present, body too large) SHALL log at `warn`, not `error`. Infrastructure failures (cannot reach ModSecurity, cannot prepare the forwarded request) stay at `error`.

## Impact

- `pkg/modsecurity/serve.go` — header writes and three log levels
- `modsecurity_test.go` — WAF-block header expectations
- `README.md` — documented header values
- Access-log consumers that already match `blocked` on WAF blocks will see decimal status strings instead (**BREAKING** for those matchers)
