---
url: https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-websocket
title: WebSocket support in Azure Application Gateway
fetched: 2026-09-03
authority: official
---

After a successful HTTP handshake, HTTP is completely out of the picture; data uses the WebSocket protocol until close.

After upgrade, Application Gateway forwards bytes without inspection or manipulation. Therefore WAF can't parse any content and doesn't perform any inspections on such data. Header/URL rewrites also do not apply after the WebSocket connection is established.

Initial handshake is HTTP with Upgrade: websocket, Connection: Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version.
