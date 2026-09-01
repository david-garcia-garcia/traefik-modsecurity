---
url: https://www.rfc-editor.org/rfc/rfc7230.html
title: RFC 7230 HTTP/1.1 Message Syntax and Routing
fetched: 2026-09-01
authority: official
---

Obsoleted by RFC 9110 for these rules. Traefik's entrypoint docs still cite RFC7230. Same hop-by-hop contract:

§6.1 Connection:

- Proxy or gateway MUST remove or replace received connection options before forwarding.
- MUST parse Connection and, for each connection-option, remove header fields with that name, then remove or replace Connection.
- Grammar: `Connection = 1#connection-option`; `connection-option = token`.
- Connection options are case-insensitive.
- A connection-specific header received without a corresponding connection option usually indicates improper forwarding and ought to be ignored.

§6.7 Upgrade:

- `Upgrade = 1#protocol` (comma-separated protocol list).
- When Upgrade is sent, the sender MUST also send a Connection field that contains an "upgrade" connection option, to prevent Upgrade from being accidentally forwarded.
- A server MUST ignore Upgrade received in an HTTP/1.0 request.
