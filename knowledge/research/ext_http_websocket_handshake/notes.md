# WebSocket handshake

A legal WebSocket opening handshake is an HTTP/1.1+ GET that pairs hop-by-hop `Upgrade` with a `Connection` token `Upgrade`, names protocol `websocket`, and carries `Sec-WebSocket-Key` plus `Sec-WebSocket-Version: 13`. GET + `Connection` contains `upgrade` + `EqualFold(Upgrade, "websocket")` is a subset, not the RFC handshake.

## Client MUST send (RFC 6455 §4.1)

The client opening handshake MUST be a valid HTTP request. Required fields:

1. Method **GET**, HTTP version **at least 1.1**.
2. `Host` matching the target authority.
3. `Upgrade` whose value **includes the `websocket` keyword**.
4. `Connection` whose value **includes the `Upgrade` token**.
5. `Sec-WebSocket-Key`: one nonce, 16 random bytes, base64-encoded. MUST NOT appear more than once.
6. `Sec-WebSocket-Version` value **13**.

`Origin` is required from a browser client and optional otherwise. `Sec-WebSocket-Protocol` and `Sec-WebSocket-Extensions` are optional. Header field **names** are case-insensitive.

Owner: [RFC 6455 §4.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.1) and [§11.3.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-11.3.1) / [§11.3.5](https://www.rfc-editor.org/rfc/rfc6455.html#section-11.3.5).

Extract: `.sources/rfc6455.md`

## Server MUST reject a mismatch (RFC 6455 §4.2.1)

If the request does not match this list (including ABNF), the server MUST stop and return an HTTP error (example: 400). The parts a server must parse:

1. HTTP/1.1+ **GET**.
2. `Host`.
3. `Upgrade` containing `websocket`, **ASCII case-insensitive**.
4. `Connection` that includes the token `Upgrade`, **ASCII case-insensitive**.
5. `Sec-WebSocket-Key` that base64-decodes to **16 bytes**.
6. `Sec-WebSocket-Version` with value **13**.

So **yes**: `Sec-WebSocket-Key` and `Sec-WebSocket-Version` are required for a legal handshake. A check that only tests GET + `Connection` upgrade + `EqualFold` on `Upgrade` accepts requests the RFC tells a server to reject.

Owner: [RFC 6455 §4.2.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.1).

## `Upgrade` / `Connection` are lists, not whole-field strings

`Upgrade` is `#protocol` (comma-separated protocol tokens). Recipients SHOULD match each `protocol-name` case-insensitively. A field `Upgrade: websocket, IRC/6.9` still includes the `websocket` keyword.

`Connection` is `#connection-option`. Options are **case-insensitive**. Recipients MUST parse the comma list (ignore a reasonable number of empty elements). A sender of `Upgrade` MUST also send the `Upgrade` connection option. A connection-specific field received **without** that option ought to be ignored.

Substring search on `Connection` is not the RFC test. The unit is a **token** (`1*tchar`), separated by `OWS "," OWS`. `Connection: keep-alive, upgrade` is a handshake-shaped Connection; `Connection: X-Upgrade-Foo` is not the `Upgrade` token.

Owner: [RFC 9110 §5.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#name-lists-rule-abnf-extension), [§5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#name-tokens), [§7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#name-connection), [§7.8](https://www.rfc-editor.org/rfc/rfc9110.html#name-upgrade). Same rules in [RFC 7230 §6.1](https://www.rfc-editor.org/rfc/rfc7230.html#section-6.1) / [§6.7](https://www.rfc-editor.org/rfc/rfc7230.html#section-6.7) (obsoleted by 9110; Traefik docs still cite 7230).

Extracts: `.sources/rfc9110-connection-upgrade.md`, `.sources/rfc7230-connection-upgrade.md`
