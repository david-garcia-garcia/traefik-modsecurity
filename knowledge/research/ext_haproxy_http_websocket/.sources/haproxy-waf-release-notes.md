---
url: https://www.haproxy.com/documentation/haproxy-enterprise/release-notes/
title: HAProxy Enterprise release notes
fetched: 2026-09-03
authority: official
---

3.2r1 HTTP protocol: accept-unsafe-violations-in-http-request and -response allow WebSocket requests missing Sec-WebSocket-Key and responses missing Sec-WebSocket-Accept.

WAF module notes in the same file: http-request waf-evaluate applies Intelligent WAF Engine rules on-demand in a frontend, backend, or listen proxy; waf-profile applies to filter waf or http-request waf-evaluate. No statement that WAF inspects WebSocket frames or skips on Upgrade.
