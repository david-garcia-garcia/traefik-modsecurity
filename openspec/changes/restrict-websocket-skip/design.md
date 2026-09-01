## Context

See proposal.md — Why. `ServeHTTP` already returns early when `isWebsocket` is true (`pkg/modsecurity/serve.go`). The design is the predicate only. Go 1.21; no new module. `httpguts` is not a dependency.

## Goals / Non-Goals

**Goals:**

- Make the skip match an HTTP/1.1 handshake: `GET`, `Connection` token `upgrade`, `Upgrade` equals `websocket` (case-insensitive).
- Tokenize `Connection` on commas so `keep-alive, upgrade` works and a substring such as `upgrade-insecure-requests` does not.
- Keep the early return so a real upgrade is not body-buffered into the WAF client.

**Non-Goals:**

- Requiring `Sec-WebSocket-Key` / `Sec-WebSocket-Version`.
- HTTP/2 `CONNECT` websocket (`:protocol`). Those requests stay inspected.
- Changing Traefik hop-by-hop header stripping.
- Other `report.md` findings.

## Decisions

- **Keep one function at the `ServeHTTP` gate.** Alternative: move the check into health/body code — rejected; the skip must stay first so we never read the body of a stream.
- **Local comma-token scan, not a new dependency.** Alternative: import `golang.org/x/net/http/httpguts` — rejected; one token check does not justify a module.
- **EqualFold each `Upgrade` header value as sent.** Alternative: also split `Upgrade` on commas — a browser handshake is a single `websocket` value; ticket asked for EqualFold. `Upgrade: websocket, h2c` as one field will be inspected (rare).
- **`GET` only.** Alternative: also skip `CONNECT` — ticket asked for `GET`; HTTP/2 is out of scope this change.

## Risks / Trade-offs

- [Legitimate `Upgrade: WebSocket` clients that omit `Connection: upgrade`] → Mitigation: that is not a legal handshake; they already go to the WAF today if they used mixed-case `Upgrade` without our new Connection check. After this change they stay inspected unless both headers are present. Operators must send a real handshake.
- [HTTP/2 websocket still inspected] → Mitigation: documented as assumed; can be a later leaf if Traefik presents those on this middleware.

## Migration Plan

Ship as a plugin version bump. No config migration. Rollback is the previous plugin version (the forgeable skip returns).
