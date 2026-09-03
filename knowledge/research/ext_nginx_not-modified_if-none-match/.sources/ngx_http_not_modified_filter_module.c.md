---
url: https://github.com/nginx/nginx/blob/231a60ee3e90a43b829b9ca0a3013a8359b98d7e/src/http/modules/ngx_http_not_modified_filter_module.c
title: ngx_http_not_modified_filter_module.c
fetched: 2026-09-03
authority: source
ref: nginx/nginx@231a60ee3e90a43b829b9ca0a3013a8359b98d7e:src/http/modules/ngx_http_not_modified_filter_module.c
---

Header filter `ngx_http_not_modified_header_filter` is installed as `ngx_http_top_header_filter`. No module directives.

Skip (pass to next filter) unless `r->headers_out.status == NGX_HTTP_OK`, `r == r->main`, and `!r->disable_not_modified`.

Failed `If-Unmodified-Since` / `If-Match` call `ngx_http_filter_finalize_request` with 412.

When `If-Modified-Since` or `If-None-Match` is present:

- If `If-Modified-Since` is present and `ngx_http_test_if_modified` is true, keep 200.
- If `If-None-Match` is present and `ngx_http_test_if_match` is false, keep 200.
- Else set `r->headers_out.status = NGX_HTTP_NOT_MODIFIED`, clear status line / content-type / content-length / accept-ranges / content-encoding, then continue the header-filter chain. No `filter_finalize`.

`ngx_http_test_if_modified`: if `if_modified_since == NGX_HTTP_IMS_OFF`, return 1 (treat as modified). That function is not called unless the request has `If-Modified-Since`.

`ngx_http_test_if_match`: if `header->value` length is 1 and the byte is `*`, return 1. Only then, if `r->headers_out.etag == NULL`, return 0.
