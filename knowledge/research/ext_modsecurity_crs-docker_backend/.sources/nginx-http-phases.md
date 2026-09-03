---
url: https://nginx.org/en/docs/dev/development_guide.html#http_phases
title: nginx development guide — HTTP request phases
fetched: 2026-09-03
authority: official
---

Phases run successively. Relevant order:

- `NGX_HTTP_REWRITE_PHASE` — rewrite rules in the chosen location (`ngx_http_rewrite_module`).
- `NGX_HTTP_PREACCESS_PHASE` — e.g. limit_conn / limit_req.
- `NGX_HTTP_ACCESS_PHASE` — access / auth.
- `NGX_HTTP_CONTENT_PHASE` — response generation (index/static).
- `NGX_HTTP_LOG_PHASE` — logging at the end.

`return` is a rewrite-module directive (see nginx-return.md), so it is evaluated in rewrite, before preaccess/access/content.
