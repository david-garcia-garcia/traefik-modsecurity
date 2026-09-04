# Azure WAF WebSocket

Azure Front Door and Application Gateway WAF inspect the HTTP establishment (handshake). After 101 they pass frames without WAF inspection. Official docs do not skip WAF because `Upgrade` is present. Operators must disable Front Door caching on WebSocket routes so the Upgrade header is forwarded; that is not a WAF path bypass.

## Official: Front Door WAF on establishment only

“Web Application Firewall (WAF) inspections are applied during the WebSocket establishment phase. After the connection is established, the WAF doesn't perform further inspections.”

After upgrade, Front Door “transmits data between clients and the origin server without performing any inspections or manipulations during the established connection.”

Handshake is documented as HTTP Upgrade with `Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Key`, and `Sec-WebSocket-Version`.

Caching: “Disable caching for WebSocket routes. For routes with caching enabled, Azure Front Door doesn't forward the WebSocket Upgrade header to the origin and treats it as an HTTP request, disregarding cache rules. This behavior results in a failed WebSocket upgrade request.”

Owner: [WebSocket - Azure Front Door](https://learn.microsoft.com/en-us/azure/frontdoor/standard-premium/websocket).

Extract: `.sources/frontdoor-websocket.md`

## Official: Application Gateway WAF cannot parse post-upgrade data

“After a connection is upgraded to WebSocket, as an intermediary/terminating proxy, Application Gateway simply sends the data received from the frontend to the backend and vice-versa, without any inspection or manipulation capability. Therefore, the Web Application Firewall (WAF) can't parse any content and doesn't perform any inspections on such data.”

Handshake is HTTP with Upgrade headers (same RFC 6455 example). After success, “HTTP is completely out of the picture.”

Owner: [WebSocket support in Azure Application Gateway](https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-websocket).

Extract: `.sources/app-gateway-websocket.md`

## Skip-on-Upgrade

Neither page says `Upgrade` / `Connection` without `Sec-WebSocket-*` skip WAF. Front Door applies WAF during establishment. A request that never upgrades remains HTTP and stays in WAF scope. Caching can drop the Upgrade header (treat as ordinary HTTP) — that is origin-forwarding behavior, not a WAF skip.

## Operators bypassing paths

Official Front Door requirement is disable caching (and they document idle timeout / connection limits), not exclude the path from WAF. Application Gateway uses the same HTTP listener; no WAF-off for WS paths.
