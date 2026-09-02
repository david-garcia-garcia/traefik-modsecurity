---
url: https://github.com/apache/httpd/blob/2.4.58/modules/proxy/mod_proxy_http.c
title: modules/proxy/mod_proxy_http.c
fetched: 2026-09-01
authority: source
ref: apache/httpd@2.4.58:modules/proxy/mod_proxy_http.c
---

Connect to origin (`ap_proxy_connect_backend` fails): log APLOGNO(01114) “failed to make connection to backend”; `status = HTTP_SERVICE_UNAVAILABLE` (503).

Error reading from remote: `ap_proxyerror(..., HTTP_BAD_GATEWAY, "Error reading from remote server")` (502). Corrupt status line: 502.

First request on the connection fails in a “fishy” way: `HTTP_INTERNAL_SERVER_ERROR` (500).

Read timeout on status line sets note `proxy_timedout`. 100-Continue timeout: 503.
