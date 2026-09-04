# CRS Docker BACKEND

Official `owasp/modsecurity-crs` images are reverse proxies. `BACKEND` / `BACKEND_WS` select the next hop. This folder is the inspect-only / overlay contract for dropping that hop (ticket `2026-09-03-remove-2nd-hop`).

This product’s pins are `owasp/modsecurity-crs:4.3.0-apache-alpine-202406090906` and `4.3.0-nginx-alpine-202406090906`. Templates below were read from `coreruleset/modsecurity-crs-docker@5e3cda3` (2026-08-19). The 4.3.0 pin was not docker-inspected; this worktree’s Apache overlay is a copy of that pin’s vhost and still uses the same `ProxyPass` / `BACKEND_WS` lines.

Do not duplicate [CRS Docker nginx real_ip env](../ext_modsecurity_crs-docker_nginx-real-ip/notes.md). Do not duplicate [If-None-Match asterisk](../ext_nginx_not-modified_if-none-match/notes.md) for the 200→304 header filter.

## BACKEND and BACKEND_WS

Official README Common ENV: `BACKEND` is the “Partial URL for the remote server of the `ProxyPass` (httpd) and `proxy_pass` (nginx) directives.” Table default: `http://localhost:80` (nginx column is “-”, same as httpd).

Owner: [CRS Docker README — Common ENV Variables](https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/README.md). Extract: `.sources/crs-docker-readme.md`.

Image `ENV` when `BACKEND` is omitted (current tree):

| Image Dockerfile | `BACKEND` | `BACKEND_WS` |
| --- | --- | --- |
| `nginx/Dockerfile`, `nginx/Dockerfile-alpine` | `http://localhost:80` | (none) |
| `apache/Dockerfile` | `http://localhost:80` | `ws://localhost:8081` |
| `apache/Dockerfile-alpine` | `http://localhost:8080` | `ws://localhost:8081` |

Official README vs alpine Apache `ENV`: conflict. Follow **source** for what the alpine image starts with (`http://localhost:8080`). README still says `http://localhost:80`. This product’s alpine pin was not opened; current alpine Dockerfile is the owner for today’s alpine default.

Owner: `coreruleset/modsecurity-crs-docker@5e3cda3:nginx/Dockerfile-alpine`, `apache/Dockerfile-alpine`, `apache/Dockerfile`. Extract: `.sources/dockerfile-backend-env.md`.

Apache vhost uses both:

```
ProxyPass / ${BACKEND}/ disablereuse=on
ProxyPassReverse / ${BACKEND}/
RewriteRule .* "${BACKEND_WS}%{REQUEST_URI}" [P]
```

(`RewriteCond` Upgrade/Connection websocket.) Apache expands `${BACKEND}` / `${BACKEND_WS}` from the process environment.

Owner: `coreruleset/modsecurity-crs-docker@5e3cda3:apache/conf/extra/httpd-vhosts.conf`; [Apache configuration files — `${VAR}`](https://httpd.apache.org/docs/2.4/configuring.html). Extracts: `.sources/apache-vhosts-locations.md`, `.sources/apache-configuring-env.md`.

nginx `location /` includes `includes/proxy_backend.conf`, which ends with `proxy_pass ${BACKEND};`. There is no `BACKEND_WS` on nginx; WebSocket uses `proxy_set_header Upgrade` / `Connection` on the same `proxy_pass`.

Owner: `coreruleset/modsecurity-crs-docker@5e3cda3:nginx/templates/includes/proxy_backend.conf.template`, `nginx/templates/conf.d/default.conf.template`. Extract: `.sources/nginx-templates-backend.md`.

Official Proxy Configuration: default images “act as reverse proxies and require a running backend at the address specified through the `BACKEND` environment variable.” If `BACKEND` is unset or nothing listens there, “nothing useful will happen” unless configuration is overridden.

Owner: [CRS Docker README — Proxy Configuration](https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/README.md).

## Overlay mount paths

### nginx — `/etc/nginx/templates/` and `20-envsubst-on-templates.sh`

CRS nginx images are based on upstream nginx. The README escape hatch: mount a replacement as a **template**, e.g. local `nginx/default.conf` → `/etc/nginx/templates/conf.d/default.conf.template`. “Files in the templates directory will be copied and subdirectories will be preserved.” Kubernetes note names `/docker-entrypoint.d/20-envsubst-on-templates.sh` (the official nginx image script).

Owner: [CRS Docker README — Nginx based images breaking change](https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/README.md).

Official nginx image: templates under `/etc/nginx/templates/` with suffix `.template` are `envsubst`’d. Default output dir is `/etc/nginx/conf.d`. CRS sets `NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx`, so the template tree maps 1:1 under `/etc/nginx/`.

Exact overlay paths for this image:

| Replace | Mount this template | Written file |
| --- | --- | --- |
| `proxy_pass` / proxy headers | `/etc/nginx/templates/includes/proxy_backend.conf.template` | `/etc/nginx/includes/proxy_backend.conf` |
| whole `location /` (and servers) | `/etc/nginx/templates/conf.d/default.conf.template` | `/etc/nginx/conf.d/default.conf` |

Owner: [Docker Hub nginx — Using environment variables](https://hub.docker.com/_/nginx); `coreruleset/modsecurity-crs-docker@5e3cda3:nginx/Dockerfile-alpine` (`NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx`). Extracts: `.sources/nginx-docker-hub-templates.md`, `.sources/dockerfile-backend-env.md`.

### Apache — vhost path (no templates dir)

`COPY apache/conf/extra/*.conf /usr/local/apache2/conf/extra/`. `httpd.conf` includes `conf/extra/httpd-vhosts.conf`. Overlay the **installed** file:

`/usr/local/apache2/conf/extra/httpd-vhosts.conf`

Keep `${ENV}` placeholders; Apache substitutes them. This worktree already mounts `./crs-apache/httpd-vhosts.conf` at that path.

Owner: `coreruleset/modsecurity-crs-docker@5e3cda3:apache/Dockerfile-alpine`; this worktree `docker-compose.yml` / `crs-apache/httpd-vhosts.conf`. Extracts: `.sources/dockerfile-backend-env.md`, `.sources/this-repo-4.3.0-pin.md`.

`/healthz` lives in `httpd-locations.conf`, not the vhost. Replacing only the vhost leaves `/healthz` in place.

## nginx `return 200` and ModSecurity phase 2

**Official CRS / nginx docs do not say** whether `return 200` in `location /` still runs ModSecurity request-body inspection. The following is **authority: inference** from files read.

CRS nginx enables ModSecurity at **http** level, not inside `location /`:

```
modsecurity on;
modsecurity_rules_file /etc/modsecurity.d/setup.conf;
```

That file is `nginx/templates/conf.d/modsecurity.conf.template` → `/etc/nginx/conf.d/modsecurity.conf`, included by `nginx.conf` (`include /etc/nginx/conf.d/*.conf` inside `http`). `/healthz` does **not** set `modsecurity off`.

Owner: `coreruleset/modsecurity-crs-docker@5e3cda3:nginx/templates/conf.d/modsecurity.conf.template`, `nginx/templates/nginx.conf.template`, `nginx/templates/includes/location_common.conf.template`. Extract: `.sources/nginx-templates-backend.md`.

Current bake pins the connector at **ModSecurity-nginx v1.0.4**. That tag registers:

- request headers / phase 1: `NGX_HTTP_REWRITE_PHASE` → `ngx_http_modsecurity_rewrite_handler`
- request body / phase 2: `NGX_HTTP_PREACCESS_PHASE` → `ngx_http_modsecurity_pre_access_handler` (`ngx_http_read_client_request_body`, then `msc_process_request_body`)

Owner: `owasp-modsecurity/ModSecurity-nginx@v1.0.4:src/ngx_http_modsecurity_module.c`, `…/ngx_http_modsecurity_pre_access.c`; `coreruleset/modsecurity-crs-docker@5e3cda3:docker-bake.hcl` (`modsecurity-nginx-version = 1.0.4`). Extract: `.sources/modsecurity-nginx-v1.0.4.md`.

Official nginx: `return` “Stops processing and returns the specified `code` to a client.” Rewrite-module directives (including `return`) run in the location rewrite phase. Official phase order: `REWRITE` → `PREACCESS` → `ACCESS` → content.

Owner: [ngx_http_rewrite_module `return`](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return); [nginx development guide — HTTP phases](https://nginx.org/en/docs/dev/development_guide.html#http_phases). Extracts: `.sources/nginx-return.md`, `.sources/nginx-http-phases.md`.

**Inference:** `return 200` in `location /` finalizes in rewrite and does not reach `NGX_HTTP_PREACCESS_PHASE`. On v1.0.4 that is the only hook that reads the body and calls `msc_process_request_body`. So an inspect-only overlay that replaces `proxy_pass` with `return 200` is not documented to run phase 2; the files above imply it skips it. Whether the rewrite-phase handler (phase 1) still runs depends on handler order inside `REWRITE`; official docs do not say. The 4.3.0 pin’s connector tag was not read from the image.

Vendor GitHub comments (not owners) report the same skip; they must not override the above.

## Apache DocumentRoot / `index.html` and POST 405

CRS Apache vhost has **no** `DocumentRoot` / `DirectoryIndex`. Default config is `ProxyPass /`, not a static site.

Owner: `coreruleset/modsecurity-crs-docker@5e3cda3:apache/conf/extra/httpd-vhosts.conf`.

Apache `default_handler` (static files): for `POST`, if `deliver_script` is unset (normal file, not a script handler), it logs “This resource does not accept the %s method.” and returns `HTTP_METHOD_NOT_ALLOWED` (**405**). GET is served. OPTIONS is handled separately.

Owner: [apache/httpd `server/core.c` `default_handler`](https://github.com/apache/httpd/blob/trunk/server/core.c) (read 2026-09-03; same `M_POST` / `HTTP_METHOD_NOT_ALLOWED` branch on the 2.4.x tree). Extract: `.sources/apache-core-default-handler.md`.

**Inference:** if `ProxyPass /` is removed and the request is handled as a regular file under the base image `DocumentRoot` (`index.html`), POST returns 405 after Apache has already run earlier request hooks. Official CRS docs do not describe that overlay. This product treats sidecar 3xx/4xx as a WAF block (ticket context, not a CRS fact).

## `/healthz` — 200 without proxy (nginx)

nginx `includes/location_common.conf` (included from both HTTP and SSL servers, **sibling** of `location /`, so it is not `proxy_pass`’d):

```
location /healthz {
    access_log off;
    add_header Content-Type text/plain;
    return 200 "OK";
}
```

README: images return HTTP 200 from `/healthz`. Image `HEALTHCHECK` curls `/healthz`.

Owner: `coreruleset/modsecurity-crs-docker@5e3cda3:nginx/templates/includes/location_common.conf.template`; README “Container Health Checks”; `src/bin/healthcheck`. Extracts: `.sources/nginx-templates-backend.md`, `.sources/crs-docker-readme.md`, `.sources/healthcheck.md`.

Apache parallel (not requested, same script): `<Location "/healthz">` uses `RewriteRule .* - [R=200,L]`, `ErrorDocument 200 "OK"`, `ProxyPass !`.

Owner: `coreruleset/modsecurity-crs-docker@5e3cda3:apache/conf/extra/httpd-locations.conf`.

## Unknowns

- Exact `BACKEND` default and ModSecurity-nginx tag **inside** `4.3.0-*-202406090906` (image not pulled).
- Official statement that `return` does or does not run phase 2 — none found; inference only.
- Whether phase 1 still runs on a `return 200` `location /` (rewrite-handler order).
- Measured POST status if this pin’s `DocumentRoot`/`index.html` is used without `ProxyPass` (source says 405 for static files; not runtime-tested).
