---
url: https://learn.microsoft.com/en-us/azure/frontdoor/standard-premium/websocket
title: WebSocket - Azure Front Door
fetched: 2026-09-03
authority: official
---

After upgrading a connection to WebSocket, Azure Front Door transmits data between clients and the origin without inspections or manipulations during the established connection.

WAF inspections are applied during the WebSocket establishment phase. After the connection is established, the WAF doesn't perform further inspections.

Handshake uses Connection: Upgrade, Upgrade: websocket, Sec-WebSocket-Key, and Sec-WebSocket-Version.

Disable caching for WebSocket routes. If caching is enabled, Front Door does not forward the WebSocket Upgrade header to the origin and treats the request as HTTP, so the upgrade fails.
