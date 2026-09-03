# Coraza WAF WebSocket

Coraza’s HTTP middleware inspects the opening handshake as a normal request (phases 1–2). A matching deny rule returns 403 before 101. After `Hijack()` / 101, it skips HTTP response-body processing. It does not inspect WebSocket frames. `Upgrade` headers do not skip request inspection. Official seclang docs do not mention WebSocket.

## Official: seclang docs are HTTP-only

[Coraza actions](https://www.coraza.io/docs/seclang/actions/) documents SecLang actions for HTTP transactions. The page does not mention WebSocket, Upgrade, or 101.

Owner: [Actions | OWASP Coraza](https://www.coraza.io/docs/seclang/actions/).

Extract: `.sources/coraza-seclang-actions.md`

## Source: handshake is processRequest (phases 1–2)

`corazawaf/coraza@5c9a34ab5b860479f18fa237bea7a05c6c3f9d93` (shallow clone 2026-09-03).

`http/middleware.go` `WrapHandler`: unless `IsRuleEngineOff()`, every request runs `processRequest` (ProcessConnection, ProcessURI, request headers, request body). Interruption writes the deny status and returns; the next handler (upgrade) does not run.

`TestWebSocketUpgradeBlockedByWAF` in `http/websocket_test.go`: a deny rule on `REQUEST_HEADERS:X-Attack` against a GET `/ws` with `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13` yields **403**, not 101.

Owner: `corazawaf/coraza@5c9a34a:http/middleware.go`, `http/websocket_test.go`.

Extracts: `.sources/middleware.go.md`, `.sources/websocket_test.go.md`

## Source: 101 flushes; hijack skips response processing; frames are a raw tunnel

`http/interceptor.go`:

- `WriteHeader(101)` flushes immediately: “The connection is about to be hijacked for bidirectional communication and there will be no HTTP response body to process.”
- `hijackerTracker.Hijack` sets `isHijacked`.
- `processResponse` returns nil when `isHijacked` so it does not write HTTP response body into the taken-over connection.

`TestWAFNotBypassedAfterWebSocketUpgrade`: after one connection upgrades and echoes a frame, a later ordinary HTTP request still hits the WAF (malicious blocked, benign allowed). Frame echo is a test of tunnel integrity, not WAF frame rules.

Owner: `corazawaf/coraza@5c9a34a:http/interceptor.go`, `http/interceptor_test.go`.

Extract: `.sources/interceptor.go.md`

## Skip-on-Upgrade

No. Request inspection runs before the handler. Only `SecRuleEngine Off` skips WAF entirely (`WrapHandler` early return). That is an operator setting, not an Upgrade-header bypass.

Owner: `corazawaf/coraza@5c9a34a:http/middleware.go`.

## Operators bypassing paths

Coraza does not require WebSocket path allowlists. Operators who turn the engine off to “make WS work” skip handshake inspection too; current source is meant to keep the engine on and still complete 101.
