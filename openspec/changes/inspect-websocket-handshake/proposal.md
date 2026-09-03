## Why

On `main`, a GET with `Connection: Upgrade` and `Upgrade: websocket` skips ModSecurity. That skip is client-controlled, so SQLi/XSS/scanner probes on ordinary GET routes bypass the WAF. It was added in 2021 as a copy of [ModSecurity#1368](https://github.com/owasp-modsecurity/ModSecurity/issues/1368) (“not capable to inspect WebSockets”), which is about **frames after the protocol switch**, not the opening HTTP GET. Other WAFs inspect that opening HTTP request and do not inspect frames after 101. This plugin can do the same: frames never enter `ServeHTTP` after Traefik tunnels. The skip is the bug. Independently, the WebSocket skip is the only path that forwards a client-supplied `modSecurityStatusRequestHeader`.

## What Changes

- **BREAKING:** Remove `isWebsocket`. The opening HTTP request (including a real WebSocket handshake GET) is sent to the sidecar like any other request. Traefik still tunnels frames after the backend's 101; this plugin never sees those frames.
- Delete the configured `modSecurityStatusRequestHeader` from `req.Header` at the start of `ServeHTTP` so a client cannot forge `ok`.
- Operators who need a skip for a WebSocket path that CRS false-positives use existing `bypassRules` (or a Traefik router without this middleware). That is an operator allowlist, not a header sniff.
- Rename spec `core_plugin_middleware_websocket-skip` → `core_plugin_middleware_websocket-handshake` (the skip is the removed unit).
- Tests: handshake-shaped GET is inspected; mixed-case Upgrade is inspected; status header is overwritten or absent, never the client's value. Integration `/ws-echo` must complete a real RFC 6455 handshake **and** a full text-frame round trip (send, echo, close) on that same connection — not 101-only.

## Capabilities

### New Capabilities

- `core_plugin_middleware_websocket-handshake`: The opening HTTP request of a WebSocket upgrade is inspected like any other GET. Frames after 101 are not this plugin's unit. The plugin SHALL NOT skip the sidecar because `Upgrade` / `Connection` are present.

### Modified Capabilities

- `core_plugin_middleware_websocket-skip`: Removed. The skip is the unit this change deletes; replaced by `core_plugin_middleware_websocket-handshake`.
- `core_plugin_middleware_status-header`: Delete the configured name from the request at the start of `ServeHTTP`. After sidecar allow, a handshake GET writes `ok` like any other allow. SHALL NOT leave a client-supplied value. SHALL NOT mention a WebSocket skip.
- `core_plugin_middleware_bypass-rules`: Omitted `bypassRules` inspects every request subject only to already-unhealthy backoff (no WebSocket skip). A handshake GET that matches a bypass rule still writes `bypassrule`.

## Impact

- `pkg/modsecurity/serve.go` (`isWebsocket` removed; status header `Del` at top)
- `modsecurity_test.go` WebSocket cases; `pkg/modsecurity/upstream_issue_05_test.go` handshake `want`
- `openspec/specs/core_plugin_middleware_websocket-skip` replaced by `websocket-handshake`
- `knowledge/devdocs/core_plugin_middleware.md` Language + gotcha
- `README.md` bypass default comment
- Integration `Invoke-WebSocketEcho` / `/ws-echo` behind `waf-middleware`
