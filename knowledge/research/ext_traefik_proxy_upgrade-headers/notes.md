# Upgrade headers

Traefik strips hop-by-hop headers named by `Connection` before the middleware chain. It does **not** drop `Upgrade` when `Connection` contains the `Upgrade` token: it puts `Upgrade` and `Connection: Upgrade` back. That restore is any upgrade protocol, not WebSocket-only. Official docs state the strip; the restore is source.

## Official: Connection headers leave before middleware

As per RFC7230, Traefik removes header fields listed in the request `Connection` (and `Connection` itself when empty) as soon as it handles the request. Those headers are **not** available when the request passes through the middleware chain. `entryPoints.*.forwardedHeaders.connection` is an allow-list of Connection-named headers that may pass through middleware **before** removal. Names on that list are not case-sensitive; Traefik canonicalizes them.

Owner: [Traefik EntryPoints — forwardedHeaders.connection](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/).

Extract: `.sources/entrypoints-forwardedheaders-connection.md`

## Official: WebSocket is detected; Sec-* are preserved

Traefik supports WS/WSS with ordinary HTTP routing. It "automatically detects and handles the WebSocket upgrade" and "preserves WebSocket headers including `Origin`, `Sec-WebSocket-Key`, and `Sec-WebSocket-Version`". That sentence does not mention `Upgrade` / `Connection`.

Owner: [Exposing Services — WebSocket](https://doc.traefik.io/traefik/expose/overview/).

Extract: `.sources/expose-overview-websocket.md`

## Official: `Upgrade: h2c` is not forwarded (v3.7.13+)

Starting with Traefik v3.7.13, Traefik does not forward `Upgrade: h2c` or `HTTP2-Settings` to backends. It does not implement the deprecated h2c upgrade; unencrypted HTTP/2 is prior-knowledge only (`h2c://` server URL). This HEAD (`237f13c`) has no matching `Del("Upgrade")` for `h2c`; the claim is owned by the migration doc, not this tree.

Owner: [Migration v3.7.13 — h2c Upgrade Requests](https://doc.traefik.io/traefik/migrate/v3/).

Extract: `.sources/migrate-v3-h2c-upgrade.md`

## Source: restore `Upgrade` when Connection lists it

`traefik/traefik@237f13c677edb45ab696b7347b517e1f6b46b849` (shallow master, 2026-09-01).

`pkg/middlewares/forwardedheaders/forwarded_header.go` `removeConnectionHeaders`:

1. If `httpguts.HeaderValuesContainsToken(Connection, "Upgrade")`, save the `Upgrade` value.
2. Split each `Connection` field on commas, trim, canonicalize. Delete that header unless it is a Traefik-managed `X-Forwarded-*` or on `forwardedHeaders.connection`.
3. If a value was saved, append `Upgrade` to the kept Connection list and `Set("Upgrade", saved)`.
4. Rewrite `Connection` to the kept list, or delete it.

The unit test `remove and upgrade` uses `Upgrade: test` (not `websocket`) and expects `Upgrade` plus `Connection: Upgrade` to remain. So Traefik keeps `Upgrade` for a **genuine HTTP upgrade** (`Connection` token `Upgrade`), not only a WebSocket handshake.

`isWebsocketRequest` in the same file (used for `X-Forwarded-Proto` `ws`/`wss`): comma-split both headers, `EqualFold` each token to `upgrade` / `websocket`. It does not require GET, `Sec-WebSocket-Key`, or `Sec-WebSocket-Version`.

Owner: `traefik/traefik@237f13c:pkg/middlewares/forwardedheaders/forwarded_header.go` and `forwarded_header_test.go`.

Extract: `.sources/forwarded_header.go.md`

## Source: backend hop-by-hop strip, then put Upgrade back

`pkg/proxy/fast/proxy.go` copies headers, runs `removeConnectionHeaders` (comma-split `Connection`, delete each named field), then deletes a fixed hop list that **includes `Upgrade`**. `upgradeType` returns `Header.Get("Upgrade")` only when `HeaderValuesContainsToken(Connection, "Upgrade")`; otherwise `""`. If `reqUpType != ""`, it sets `Connection: Upgrade` and `Upgrade: reqUpType`. WebSocket casing cleanup runs only when `EqualFold(reqUpType, "websocket")`.

`pkg/proxy/httputil/proxy.go` `isWebSocketUpgrade`: `HeaderValuesContainsToken(Connection, "Upgrade")` **and** `EqualFold(Get("Upgrade"), "websocket")` on the **whole** field (not tokenized). That misses `Upgrade: websocket, IRC/6.9`. It only recases `Sec-WebSocket-*`; it does not decide whether to strip `Upgrade`.

Owner: `traefik/traefik@237f13c:pkg/proxy/fast/proxy.go`, `pkg/proxy/fast/upgrade.go`, `pkg/proxy/httputil/proxy.go`.

Extracts: `.sources/fast-proxy.go.md`, `.sources/httputil-proxy.go.md`

## Implication for a Yaegi plugin

After entrypoint forwarded-headers, a request that listed `Upgrade` on `Connection` still has `Upgrade` and `Connection: Upgrade` on the middleware `http.Request`. A lone `Upgrade` without that token is not restored as an upgrade; RFC 9110 says it ought to be ignored. Plugin `isWebsocket` must tokenize `Connection` the same way (`HeaderValuesContainsToken` or comma-split + `EqualFold`), not substring-match.
