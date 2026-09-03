## 1. Write failing test

- [x] 1.1 In `modsecurity_test.go`, add a case: GET with `Connection: upgrade`, `Upgrade: websocket`, sidecar 403, `modSecurityStatusRequestHeader` set, client sent that header as `ok`. Expect sidecar body 403 (not next) and the request header value `blocked` or the plugin-written token, not the client `ok`. Confirm the test fails on current `isWebsocket` skip.
- [x] 1.2 In `modsecurity_test.go`, change "Does not forward Websockets" and mixed-case handshake cases so they expect sidecar intercept (403) instead of skip. Confirm they fail.
- [x] 1.3 In `pkg/modsecurity/upstream_issue_05_test.go`, change `real GET handshake` so `isWebsocket` is no longer asserted true (function will be removed). Add a ServeHTTP case that a handshake-shaped GET hits the sidecar. Confirm it fails while `isWebsocket` still skips.

## 2. Inspect handshake HTTP

- [x] 2.1 Delete `isWebsocket` and its call in `pkg/modsecurity/serve.go`. Handshake-shaped GET follows the ordinary sidecar path. Keep `headerValuesContainToken` for hop-by-hop sidecar response stripping (`omitSidecarResponseHeader`).
- [x] 2.2 At the top of `ServeHTTP`, when `modSecurityStatusRequestHeader` is set, `Del` that name from `req.Header` before `bypassRules` and every other branch. Then existing `Set`s write the outcome token.
- [x] 2.3 Re-run the failing tests from §1 and `go test ./...` until they pass.

## 3. Docs and usage

- [x] 3.1 Update `knowledge/devdocs/core_plugin_middleware.md`: WebSocket handshake Language (RFC opening GET, still inspected); How to use / Gotchas: no skip; status header `Del` then `Set`; `bypassRules` is the operator skip for CRS false positives.
- [x] 3.2 Update `README.md` so the bypass default is not “subject to WebSocket … skips”. Say handshake GETs are inspected; frames after 101 are Traefik’s tunnel.

## 4. Integration

- [x] 4.1 Keep `Invoke-WebSocketEcho` (`scripts/TestHelpers.ps1`) as the only WebSocket client. One connection: RFC 6455 handshake, then **at least two** distinct text frames each echoed before the next send, then a normal close. Assert payloads, not 101-only. Target `ws://localhost:8000/ws-echo`. If CRS 403s the handshake, add a test-only `bypassRules` for that path — do not restore `isWebsocket`.
- [x] 4.2 Add an `It` that GET `/protected` with handshake Upgrade headers plus SQLi is 403 (the skip is gone on a live stack).
- [x] 4.3 Run `go test ./...`. Integration: “WebSocket through WAF middleware”. Record pass/fail on `handoff.yaml` `localTests`.
