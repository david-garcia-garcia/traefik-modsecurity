---
url: https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page
title: nginx ngx_http_core_module error_page
fetched: 2026-09-03
authority: official
---

Syntax: `error_page code ... [=[response]] uri;` Context: `http`, `server`, `location`, `if in location`.

Defines the URI that will be shown for the specified errors. Causes an internal redirect to that URI (method becomes GET except GET/HEAD).

`error_page 404 =200 /empty.gif` changes the response code of that error path to 200.

Examples use 403, 404, 500–504. The page does not describe intercepting a header-filter status rewrite of 200 to 304.
