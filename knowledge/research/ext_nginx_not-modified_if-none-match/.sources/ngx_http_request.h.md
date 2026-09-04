---
url: https://github.com/nginx/nginx/blob/231a60ee3e90a43b829b9ca0a3013a8359b98d7e/src/http/ngx_http_request.h
title: ngx_http_request.h status constants and If-None-Match field
fetched: 2026-09-03
authority: source
ref: nginx/nginx@231a60ee3e90a43b829b9ca0a3013a8359b98d7e:src/http/ngx_http_request.h
---

`NGX_HTTP_OK` is 200. `NGX_HTTP_NO_CONTENT` is 204. `NGX_HTTP_NOT_MODIFIED` is 304.

`ngx_http_headers_in_t` has first-class pointers `if_modified_since` and `if_none_match`.

`ngx_http_request_s` has bit `disable_not_modified`. The not_modified filter skips the 304 rewrite when that bit is set. This header does not document a config directive that sets it.
