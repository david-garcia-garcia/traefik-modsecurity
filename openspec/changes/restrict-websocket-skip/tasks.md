## 1. Predicate

- [ ] 1.1 Tighten `isWebsocket` in `pkg/modsecurity/serve.go`: require `GET`, `Connection` token `upgrade` (comma-split, case-insensitive), `Upgrade` equals `websocket` via `EqualFold`. Leave the `ServeHTTP` early return in place.
- [ ] 1.2 Add a small local token helper in the same file (no new package, no new module). Comment the function and the token-scan block.

## 2. Tests

- [ ] 2.1 Rewrite `modsecurity_test.go` case `"Does not forward Websockets"` to a real handshake (`GET`, `Connection: upgrade`, `Upgrade: websocket`) and keep asserting the backend is reached.
- [ ] 2.2 Add a case that a `POST` (or other non-GET) with only `Upgrade: websocket` still reaches the WAF mock (forged header does not skip).
- [ ] 2.3 Add a case for mixed-case `Upgrade: WebSocket` plus `Connection: Upgrade` that still skips.

## 3. Usage doc

- [ ] 3.1 Update the websocket gotcha in `knowledge/devdocs/core_plugin_middleware.md` so it names the handshake checks, not a lone `Upgrade: websocket` header.
