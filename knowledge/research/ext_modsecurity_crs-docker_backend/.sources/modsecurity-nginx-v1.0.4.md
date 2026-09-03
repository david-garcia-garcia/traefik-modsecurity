---
url: https://github.com/owasp-modsecurity/ModSecurity-nginx/blob/v1.0.4/src/ngx_http_modsecurity_module.c
title: ModSecurity-nginx v1.0.4 phase hooks and request-body handler
fetched: 2026-09-03
authority: source
ref: owasp-modsecurity/ModSecurity-nginx@v1.0.4:src/ngx_http_modsecurity_module.c
---

`ngx_http_modsecurity_init` registers:

- `NGX_HTTP_REWRITE_PHASE` → `ngx_http_modsecurity_rewrite_handler` (comment: cannot hook FIND_CONFIG; next option is REWRITE).
- `NGX_HTTP_PREACCESS_PHASE` → `ngx_http_modsecurity_pre_access_handler` (comment: “Processing the request body on the preaccess phase.”).
- `NGX_HTTP_LOG_PHASE` → `ngx_http_modsecurity_log_handler`.

`ngx_http_modsecurity_pre_access.c`: if `modsecurity` enabled, calls `ngx_http_read_client_request_body`, appends buffers or `msc_request_body_from_file`, then `msc_process_request_body`. That is the phase-2 / request-body path on this tag.

Current CRS docker bake (`5e3cda3`) sets `modsecurity-nginx-version` to `1.0.4`. The 4.3.0 image pin was not opened.
