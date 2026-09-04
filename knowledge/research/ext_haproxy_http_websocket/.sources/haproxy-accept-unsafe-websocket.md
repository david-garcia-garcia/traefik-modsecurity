---
url: https://www.haproxy.com/documentation/haproxy-configuration-manual/latest/
title: option accept-unsafe-violations-in-http-request
fetched: 2026-09-03
authority: official
---

Default: HAProxy complies with HTTP RFCs; malformed messages return an error because they are used to build attacks and bypass security filtering.

When option accept-unsafe-violations-in-http-request is set, H1 WebSocket (RFC6455) requests failing to present a valid Sec-Websocket-Key header field will be accepted.

When option accept-unsafe-violations-in-http-response is set, H1 WebSocket responses failing to present a valid Sec-Websocket-Accept header field will be accepted.

Both options say they should never be enabled by default because they hide application bugs and open security breaches.
