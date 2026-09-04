---
url: https://nginx.org/en/docs/http/ngx_http_core_module.html#etag
title: nginx ngx_http_core_module etag
fetched: 2026-09-03
authority: official
---

Syntax: `etag on | off;` Default: `etag on;` Context: `http`, `server`, `location`. Appeared in 1.3.3.

Enables or disables automatic generation of the “ETag” response header field for static resources.

Does not mention If-None-Match or the not_modified filter.
