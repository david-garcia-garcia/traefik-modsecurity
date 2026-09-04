---
url: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header
title: nginx ngx_http_proxy_module proxy_set_header
fetched: 2026-09-03
authority: official
---

Syntax: `proxy_set_header field value;` Default: `Host $proxy_host` and `Connection close`. Context: `http`, `server`, `location`.

Allows redefining or appending fields to the request header passed to the proxied server.

If caching is enabled, If-Modified-Since, If-Unmodified-Since, If-None-Match, If-Match, Range, and If-Range from the original request are not passed to the proxied server. That cache exception is not the empty-string form.

If the value of a header field is an empty string then this field will not be passed to a proxied server. Documented example: `proxy_set_header Accept-Encoding "";`.
