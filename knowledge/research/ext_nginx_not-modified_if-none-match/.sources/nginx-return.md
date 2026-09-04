---
url: https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return
title: nginx ngx_http_rewrite_module return
fetched: 2026-09-03
authority: official
---

Context: `server`, `location`, `if`.

`return code [text]` / `return code URL` / `return URL`: stops processing and returns the specified code to a client.

Rewrite-module directives (`break`, `if`, `return`, `rewrite`, `set`) are processed as: server-level rewrite directives, then location search, then location-level rewrite directives.
