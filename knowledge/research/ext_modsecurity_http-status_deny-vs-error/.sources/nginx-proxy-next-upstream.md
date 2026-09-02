---
url: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream
title: ngx_http_proxy_module — proxy_next_upstream
fetched: 2026-09-01
authority: official
---

Default: `proxy_next_upstream error timeout`.

`error` / `timeout` / `invalid_header`: unsuccessful communication with the proxied server (connect, send, or read response header).

`http_500`, `http_502`, `http_503`, `http_504` are listed as **upstream response** codes (retry only if named). `http_403` is listed separately and is never an unsuccessful attempt.
