# Requirement
IssueKey: 2026-09-03-websocketbypass

## Problem

A client can skip ModSecurity on any GET by sending `Connection: Upgrade` and `Upgrade: websocket`. `ServeHTTP` then calls `next` with no sidecar call. That same branch is the only terminal path that does not overwrite `modSecurityStatusRequestHeader`, so a client-supplied value (for example `X-Waf-Status: ok`) is forwarded. Go `ReverseProxy` only tunnels on HTTP 101; a non-WebSocket backend still answers ordinary HTTP 200. GET SQLi, XSS, path-traversal, and scanner probes therefore skip the WAF.

The human forbids product code until explore answers: (1) what other WAF products do when they cannot reliably tell a WebSocket handshake from a forged `Upgrade`; (2) whether this plugin should drop automatic WebSocket detection and rely on operator `bypassRules` for WebSocket paths.

## Current (code)

- `pkg/modsecurity/serve.go:28-31` — `isWebsocket(req)` then `next.ServeHTTP` with no sidecar and no status-header `Set`.
- `pkg/modsecurity/serve.go:171-185` — `isWebsocket` is GET + `Connection` token `upgrade` + `Upgrade` `EqualFold` `websocket`. No `Sec-WebSocket-Key`, `Sec-WebSocket-Version`, or route check.
- Bypass, unhealthy, blocked, error, and ok all `Set` the status header (`serve.go` 20-23, 45-48, 76-77, 111-112, 126-127, 136-137, 149-150). The WebSocket skip does not.
- `modsecurity_test.go:82` ("Does not forward Websockets") asserts skip with those two headers and `modSecurityStatusRequestHeader: ""`. Mixed-case handshake skip at line 117. Upgrade-only POST is inspected (line 100).
- Spec `openspec/specs/core_plugin_middleware_websocket-skip/spec.md` SHALL skip on that GET+Upgrade+Connection check and SHALL NOT require `Sec-WebSocket-*`.
- Spec `openspec/specs/core_plugin_middleware_status-header/spec.md:76` SHALL NOT write `ok` on a WebSocket skip (header left as the client sent it).
- `bypassRules` already skip chosen method+path before the WebSocket check (`pkg/modsecurity/bypass.go`, spec `openspec/specs/core_plugin_middleware_bypass-rules/spec.md`).
- RFC 6455 handshake needs `Sec-WebSocket-Key` and `Sec-WebSocket-Version: 13` (`knowledge/research/ext_http_websocket_handshake/notes.md`). Traefik restore of Upgrade is any upgrade protocol, not a genuine-handshake test (`knowledge/research/ext_traefik_proxy_upgrade-headers/notes.md`).
- Integration stacks drive a live WebSocket echo through the same middleware (`docker-compose.test.yml`, `Invoke-WebSocketEcho`).

## Desired

- Close the client-controlled WAF skip: a pair of Upgrade headers on GET must not by itself skip inspection of an ordinary HTTP request.
- Independently: a client-supplied `modSecurityStatusRequestHeader` must not survive on any `ServeHTTP` path.
- Before any skip-policy code: research other WAF products’ WebSocket / Upgrade handling, then decide whether to keep auto-detection (tightened) or drop it and tell operators to `bypassRules` WebSocket paths.
- Do not implement the skip policy until explore records that decision.

## Affected

- `pkg/modsecurity/serve.go` (`isWebsocket`, `ServeHTTP` skip and status header)
- `modsecurity_test.go` WebSocket cases
- `openspec/specs/core_plugin_middleware_websocket-skip/spec.md`
- `openspec/specs/core_plugin_middleware_status-header/spec.md`
- `openspec/specs/core_plugin_middleware_bypass-rules/spec.md` (mentions WebSocket skip)
- `knowledge/devdocs/core_plugin_middleware.md`
- `README.md` (bypass default still says “subject to WebSocket … skips”)
- Integration WebSocket echo if skip is removed or the handshake is sent to the sidecar

## Out of scope

- Other `opus_review.md` findings (unanchored bypass regex, body-pool aliasing, and the rest)
- Changing Traefik’s hop-by-hop Upgrade restore
- Teaching the CRS sidecar to terminate WebSocket frames
- The leftover `fix-websocket-bypass` branch/worktree (handshake-only skip already landed there; this run starts from `main`)

## Unknowns

- What Cloudflare, AWS WAF, ModSecurity/CRS, Coraza, and similar products do with WebSocket / `Upgrade` (no research folder yet except RFC 6455 and Traefik)
- Whether a request with valid `Sec-WebSocket-*` can still skip a non-WebSocket route
- Whether sending the handshake HTTP request to the sidecar breaks the later 101 upgrade (body buffer, hop-by-hop headers)
- Whether dropping auto-skip and using only `bypassRules` is operable (how operators name WebSocket paths)

## Tensions

- Current spec and tests encode GET+Upgrade+Connection skip without `Sec-*` as intended (`core_plugin_middleware_websocket-skip`; test “Does not forward Websockets”).
- The opus finding wants a stricter handshake and still sending the handshake to the sidecar.
- The human: we cannot reliably determine WebSocket; maybe drop detection and use `bypassRules`.
- Status spec currently allows leaving the header unset on a WebSocket skip, which is how the client spoof survives.
- Prior `fix-websocket-bypass` (not `main`) already chose “real handshake only”; this ticket reopens that design.
