---
url: https://doc.traefik.io/traefik/expose/overview/
title: Exposing Services with Traefik Proxy — WebSocket
fetched: 2026-09-01
authority: official
---

Traefik Proxy supports WebSocket (WS) and WebSocket Secure (WSS) out of the box. No special configuration beyond standard HTTP routing.

Traefik automatically detects and handles the WebSocket upgrade.

Traefik preserves WebSocket headers including Origin, Sec-WebSocket-Key, and Sec-WebSocket-Version. Use the Headers middleware to modify headers for origin checking.

The page does not say whether Upgrade or Connection are stripped before middleware.
