---
url: https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works.html
title: How AWS WAF works
fetched: 2026-09-03
authority: official
---

AWS WAF controls how protected resources respond to HTTP(S) web requests. You define a web ACL and associate it with web application resources. Associated resources forward incoming requests to AWS WAF for inspection.

Rules define traffic patterns to look for in requests and actions (allow, block, count, CAPTCHA, challenge). The documented inspection unit is a web request, not a WebSocket frame.
