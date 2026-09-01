---
url: https://www.rfc-editor.org/rfc/rfc9110.html
title: RFC 9110 HTTP Semantics
fetched: 2026-09-01
authority: official
---

§5.6.1 Lists (#rule): field values use comma-delimited lists. Sender: `element *( OWS "," OWS element )`. Recipient MUST parse and ignore a reasonable number of empty list elements: `#element => [ element ] *( OWS "," OWS [ element ] )`.

§5.6.2 Tokens: `token = 1*tchar`. Tokens do not include whitespace or delimiters. Collected ABNF: `Connection = [ connection-option *( OWS "," OWS connection-option ) ]`. `Upgrade = [ protocol *( OWS "," OWS protocol ) ]`.

§7.6.1 Connection:

- `Connection = #connection-option`; `connection-option = token`.
- Connection options are case-insensitive.
- When a field besides Connection supplies connection control, the sender MUST list that field name in Connection.
- Intermediaries MUST parse Connection before forwarding and, for each connection-option, remove header/trailer fields with that name, then remove or replace Connection itself.
- Connection distinguishes hop-by-hop fields from end-to-end fields.
- Intermediaries SHOULD remove known hop-by-hop fields even if they are not listed, including Upgrade (§7.8).
- A connection-specific field received without a corresponding connection option usually indicates improper forwarding and ought to be ignored.

§7.8 Upgrade:

- `Upgrade = #protocol`; `protocol = protocol-name ["/" protocol-version]`; `protocol-name = token`.
- Recipients SHOULD use case-insensitive comparison when matching each protocol-name.
- Example request lists several protocols: `Connection: upgrade` plus `Upgrade: websocket, IRC/6.9, RTA/x11`.
- A sender of Upgrade MUST also send an "Upgrade" connection option in Connection so intermediaries do not forward Upgrade.
- A server that receives Upgrade on HTTP/1.0 MUST ignore that Upgrade field.
