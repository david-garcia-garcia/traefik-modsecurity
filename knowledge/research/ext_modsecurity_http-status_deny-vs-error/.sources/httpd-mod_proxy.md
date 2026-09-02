---
url: https://httpd.apache.org/docs/2.4/mod/mod_proxy.html
title: Apache HTTP Server 2.4 — mod_proxy
fetched: 2026-09-01
authority: official
---

`ProxyPass` worker `retry` default 60s: if the worker is in error state, httpd does not forward until the timeout. `retry=0` always retries.

`ProxyTimeout`: timeout on proxy requests when the appserver hangs; fail instead of waiting forever.

Bad backend header lines: `IsError` aborts with **502 Bad Gateway** (default).

`ProxyErrorOverride` default Off. When On, overrides proxied error pages for codes 400–599. Example: `ProxyErrorOverride On 403 405 500 501 502 503 504`.
