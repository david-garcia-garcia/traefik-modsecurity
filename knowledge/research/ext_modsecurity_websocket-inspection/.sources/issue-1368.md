---
url: https://github.com/owasp-modsecurity/ModSecurity/issues/1368
title: ModSecurity to monitor websocket connection proxied by nginx
fetched: 2026-09-03
authority: vendor
---

zimmerle (2017-05-05): Currently ModSecurity is not capable to inspect WebSockets. It is only capable to understand the http requests.

jptosso: websockets are data streams and you can't intercept stream blocks to analyze.
