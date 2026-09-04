---
url: https://developers.cloudflare.com/network/websockets/
title: WebSockets · Cloudflare Network settings docs
fetched: 2026-09-03
authority: official
---

Cloudflare supports proxied WebSocket connections without additional configuration beyond enabling the Network WebSockets toggle (dashboard or API PATCH with setting name websockets, value "on").

WAF compatibility (Yes*): the initial HTTP 101 request is subject to WAF managed rules, custom rules, rate limiting rules, and other WAF features like any other WebSockets connection. Once a connection has been established, the WAF does not perform any further inspections.

Requests: Cloudflare recognizes only the initial upgrade request per WebSocket connection as an HTTP request. A bidirectional message stream on the established connection is counted as a single long-lived HTTP request.

The page does not say Upgrade/Connection headers skip WAF, and it does not tell operators to allowlist WebSocket paths out of WAF.
