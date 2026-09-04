# Cloudflare WAF WebSocket

Cloudflare WAF inspects the opening HTTP upgrade as an ordinary HTTP request. After a connection is established, it does not inspect WebSocket frames. Official docs do not skip WAF because `Upgrade` / `Connection` are present, and they do not tell operators to allowlist WebSocket paths.

## Official: handshake HTTP is WAF-inspected; frames are not

Compatibility table, WAF row: “The initial HTTP 101 request is subject to WAF managed rules, custom rules, rate limiting rules, and other WAF features like any other WebSockets connection. However, once a connection has been established, the WAF does not perform any further inspections.”

Requests accounting: “Cloudflare recognizes only the initial upgrade request per WebSocket connection as an HTTP request.” Bidirectional messages on the established connection count as that same long-lived HTTP request, not as extra HTTP requests.

Owner: [WebSockets · Cloudflare Network settings](https://developers.cloudflare.com/network/websockets/).

Extract: `.sources/network-websockets.md`

## Official: WebSockets is a Network toggle, not a WAF bypass

Operators enable WebSockets on the Network page (or API setting `websockets` = `"on"`). That is how proxied WS/WSS reaches origin. The WAF row above still applies to the initial upgrade. The page does not say to exclude WebSocket paths from WAF.

Owner: [WebSockets · Cloudflare Network settings](https://developers.cloudflare.com/network/websockets/).

## Official: no skip-on-Upgrade; forged Upgrade is still HTTP

The WAF sentence treats the initial upgrade as “like any other” HTTP WAF evaluation. Docs do not say that `Upgrade: websocket` or `Connection: upgrade` without `Sec-WebSocket-Key` / `Sec-WebSocket-Version` skip WAF. A request that never becomes an established connection remains an HTTP request subject to those same WAF features.

Owner: [WebSockets · Cloudflare Network settings](https://developers.cloudflare.com/network/websockets/).

## Official: managed-rule gap for SSRF via WebSocket upgrades

WAF changelog (2025-04-22, GraphQL): GHSA-c4j6-fc7j-m34r, “SSRF via WebSocket upgrades”, High. Cloudflare’s note: “Not possible to safely enable a managed WAF rule without potentially breaking application behavior.” That is a coverage gap, not a documented Upgrade skip.

Owner: [Cloudflare WAF changelog](https://developers.cloudflare.com/waf/change-log/changelog/).

Extract: `.sources/waf-changelog-websocket-ssrf.md`
