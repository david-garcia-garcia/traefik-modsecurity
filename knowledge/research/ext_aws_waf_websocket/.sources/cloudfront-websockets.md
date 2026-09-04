---
url: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-working-with.websockets.html
title: Use WebSockets with CloudFront distributions
fetched: 2026-09-03
authority: official
---

To establish a WebSocket connection, the client sends a regular HTTP request that uses HTTP upgrade semantics. The server completes the handshake. The connection remains open and either side can send data frames.

WebSocket requests must comply with RFC 6455. Sample client request: GET, Upgrade: websocket, Connection: Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version: 13.

Origin request policy must forward all viewer headers (AllViewer) or at least Sec-WebSocket-Key and Sec-WebSocket-Version.

CloudFront supports WebSocket only over HTTP/1.1.
