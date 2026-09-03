---
url: https://github.com/apache/httpd/blob/trunk/server/core.c
title: Apache httpd default_handler — POST on a regular file
fetched: 2026-09-03
authority: source
---

`default_handler` (static content):

- `ap_allow_standard_methods(..., M_GET, M_OPTIONS, M_POST, -1)`.
- Discards the request body (`ap_discard_request_body`).
- For `M_GET` or `M_POST`, opens the file. If method is not GET and `deliver_script` is unset: log APLOGNO(00131) “This resource does not accept the %s method.” and `return HTTP_METHOD_NOT_ALLOWED` (405).
- Comment: the only possible non-GET method at that point is POST; only GET normally returns content.

Same `M_POST` / `HTTP_METHOD_NOT_ALLOWED` branch is present on the 2.4.x `server/core.c` tree.
