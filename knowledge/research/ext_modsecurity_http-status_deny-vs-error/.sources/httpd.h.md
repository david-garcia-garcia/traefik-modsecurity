---
url: https://github.com/apache/httpd/blob/2.4.58/include/httpd.h
title: include/httpd.h
fetched: 2026-09-01
authority: source
ref: apache/httpd@2.4.58:include/httpd.h
---

`HTTP_BAD_GATEWAY` 502, `HTTP_SERVICE_UNAVAILABLE` 503, `HTTP_GATEWAY_TIME_OUT` 504, `HTTP_INTERNAL_SERVER_ERROR` 500, `HTTP_FORBIDDEN` 403.

`mod_proxy.c` (trunk/2.4): no valid protocol handler → `HTTP_INTERNAL_SERVER_ERROR`. Worker connect/unavailable path uses `HTTP_SERVICE_UNAVAILABLE`.
