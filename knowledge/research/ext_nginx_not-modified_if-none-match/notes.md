# If-None-Match asterisk

nginx’s `ngx_http_not_modified_filter_module` is an output **header** filter. After a handler produces **200**, `If-None-Match: *` makes that filter rewrite the status to **304**, even when no `ETag` is generated. Official nginx docs do not name this filter; RFC 9110 owns the header meaning; nginx source owns the rewrite.

Do not duplicate [CRS Docker BACKEND](../ext_modsecurity_crs-docker_backend/notes.md) for overlay/`BACKEND` wiring.

## Official: `*` means any current representation

RFC 9110 §13.1.2: `If-None-Match` makes the method conditional on the origin “not having any current representation of the target resource, when the field value is `*`”. Evaluation step 1: if the field value is `*`, the condition is **false** when the origin has a current representation. For GET/HEAD, a false condition **MUST** be answered with 304 Not Modified (412 for other methods).

Owner: [RFC 9110 §13.1.2 If-None-Match](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-none-match).

Extract: `.sources/rfc9110-if-none-match.md`

## Source: nginx rewrites only 200, and `*` matches before ETag

Pinned: `nginx/nginx@231a60ee3e90a43b829b9ca0a3013a8359b98d7e` (tag message `nginx-1.31.5-RELEASE`, 2026-09-02). No temp clone; file read at that commit.

`NGX_HTTP_OK` is 200. `NGX_HTTP_NO_CONTENT` is 204. `NGX_HTTP_NOT_MODIFIED` is 304.

`ngx_http_not_modified_header_filter` returns the next filter unchanged unless `r->headers_out.status == NGX_HTTP_OK`, `r == r->main`, and `!r->disable_not_modified`. So a `return 204` never enters the 304 rewrite.

When `If-None-Match` is present and `ngx_http_test_if_match(..., if_none_match, 1)` succeeds, the filter sets `r->headers_out.status = NGX_HTTP_NOT_MODIFIED` and continues the header-filter chain. It does **not** call `ngx_http_filter_finalize_request` (that path is 412 for failed `If-Match` / `If-Unmodified-Since`).

`ngx_http_test_if_match`: if the header value is exactly one byte `*`, return 1 immediately. Only after that does it require `r->headers_out.etag`. So `etag off` (no ETag on the response) does not stop `*`.

`if_modified_since off` is consulted only inside `ngx_http_test_if_modified`, and that function runs only when `If-Modified-Since` is also present. A lone `If-None-Match: *` never reads that directive.

Owner: `nginx/nginx@231a60ee3e90a43b829b9ca0a3013a8359b98d7e:src/http/modules/ngx_http_not_modified_filter_module.c`, `src/http/ngx_http_request.h`.

Extracts: `.sources/ngx_http_not_modified_filter_module.c.md`, `.sources/ngx_http_request.h.md`

## Official: `etag` and `if_modified_since` do not mention If-None-Match

`etag on|off` (default `on`, since 1.3.3): “Enables or disables automatic generation of the “ETag” response header field for static resources.”

`if_modified_since off|exact|before` (default `exact`): “Specifies how to compare modification time of a response with the time in the “If-Modified-Since” request header field.” `off` (0.7.34): “the response is always considered modified.”

Neither directive claims to disable `If-None-Match` processing.

Owner: [ngx_http_core_module `etag`](https://nginx.org/en/docs/http/ngx_http_core_module.html#etag), [`if_modified_since`](https://nginx.org/en/docs/http/ngx_http_core_module.html#if_modified_since).

Extracts: `.sources/nginx-etag.md`, `.sources/nginx-if-modified-since.md`

## Ticket: measured 200 becomes 304 even with those directives

2026-09-03, ticket `2026-09-03-remove-dummy`. Against `nginx:alpine` and this repo’s CRS nginx drain (`return 200` on `127.0.0.1:18081`; public `:8080` `proxy_pass` to that origin): `If-None-Match: *` returned **304** on the loopback origin, the public sidecar, and Traefik. `etag off;` plus `if_modified_since off;` on the throwaway `nginx:alpine` still 304.

Owner: run journal `devstate/2026/09/2026-09-03-remove-dummy/explore.md` (Measured).

Extract: `.sources/ticket-2026-09-03-remove-dummy-measured.md`

## Official: `error_page` is for specified errors

`error_page` “Defines the URI that will be shown for the specified errors.” `error_page 404 =200 /empty.gif` changes **that error’s** response code. The page does not say a header-filter 304 re-enters this path.

Owner: [ngx_http_core_module `error_page`](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page).

Extract: `.sources/nginx-error-page.md`

## Ticket: `error_page 304 =200` did not stop the 304

Same measurement on `nginx:alpine`: `error_page 304 =200` still returned 304.

Inference (files above): the filter assigns 304 on the header-filter chain after a successful 200; it does not finalize as an error, so `error_page` does not rewrite it back.

Owner of the measured outcome: same ticket journal. Extract: `.sources/ticket-2026-09-03-remove-dummy-measured.md`

## Official + source: `return 204` stays 204

`return` “Stops processing and returns the specified `code` to a client.” Combined with the filter gate (`status != NGX_HTTP_OK`), a 204 never becomes 304.

Owner: [ngx_http_rewrite_module `return`](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return); filter source above.

Extract: `.sources/nginx-return.md`

Ticket: `return 204` stayed 204 on `nginx:alpine`. This product will **not** use 204 as the drain allow status — keep 200.

Owner of that product choice: same ticket journal (Open questions / Decisions).

## Official: empty `proxy_set_header` drops the field to the proxied server

“If the value of a header field is an empty string then this field will not be passed to a proxied server.” Example in the same paragraph: `proxy_set_header Accept-Encoding "";`.

So `proxy_set_header If-None-Match "";` and `proxy_set_header If-Modified-Since "";` omit those fields on the **upstream** request. They do not remove them from the request nginx already received.

Owner: [ngx_http_proxy_module `proxy_set_header`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header).

Extract: `.sources/nginx-proxy-set-header.md`

Ticket: two-server throwaway (`proxy_set_header` clear, then `proxy_pass` to `return 200`) stayed **200**.

## Official: request phases finish before `proxy_pass`

Phase order: `NGX_HTTP_REWRITE_PHASE` → `NGX_HTTP_PREACCESS_PHASE` → `NGX_HTTP_ACCESS_PHASE` → `NGX_HTTP_CONTENT_PHASE`. `proxy_pass` is content. `return` is a rewrite-module directive (rewrite phase).

ModSecurity-nginx v1.0.4 (CRS bake pin) registers request headers on rewrite and request body on preaccess. Those run on the public server **before** `proxy_pass` builds the upstream request. Clearing `If-None-Match` on `proxy_set_header` still leaves the client header visible to ModSecurity on that public server.

Owner: [nginx development guide — HTTP phases](https://nginx.org/en/docs/dev/development_guide.html#http_phases); connector hooks in [CRS Docker BACKEND](../ext_modsecurity_crs-docker_backend/notes.md) (`.sources/modsecurity-nginx-v1.0.4.md` there).

Extract: `.sources/nginx-http-phases.md`
