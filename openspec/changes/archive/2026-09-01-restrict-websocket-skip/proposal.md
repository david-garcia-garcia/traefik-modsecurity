## Why

`ServeHTTP` skips ModSecurity whenever `Upgrade` is exactly `websocket`. That header is hop-by-hop and easy to forge, so any client can disable the WAF on `POST` and other ordinary requests. The skip is still needed for a real handshake so the plugin does not buffer a long-lived stream.

## What Changes

- **BREAKING** for anyone who treated a lone `Upgrade: websocket` header as a WAF skip: only a GET handshake (`Connection` contains the `upgrade` token, `Upgrade` matches `websocket` case-insensitively) bypasses inspection.
- A request that only adds `Upgrade: websocket` (wrong method, or no `upgrade` token in `Connection`) takes the normal WAF path.
- Usage gotcha text names the handshake, not the one-header string.
- Unit tests lock the handshake skip and the forged-header inspect path.

## Capabilities

### New Capabilities

- `core_plugin_middleware_websocket-skip`: When a request may skip ModSecurity because it is a WebSocket handshake.

### Modified Capabilities

- None.

## Impact

- `pkg/modsecurity/serve.go` (`isWebsocket` predicate; the `ServeHTTP` early return stays)
- `modsecurity_test.go` (rewrite the existing websocket case; add forged-Upgrade still-inspected)
- `knowledge/devdocs/core_plugin_middleware.md` (gotcha)
- No new config key, no new dependency
