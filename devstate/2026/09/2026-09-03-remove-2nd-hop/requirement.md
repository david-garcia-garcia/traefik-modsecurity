# Requirement
IssueKey: 2026-09-03-remove-2nd-hop

## Problem

The OWASP CRS sidecar still reverse-proxies every inspected request to an unlabeled `dummy` `traefik/whoami`. That second hop is not the real app (Traefik `next` is). It adds latency and turns dummy/whoami behavior into false WAF blocks (Apache body pass `AH01084`, `Range` → sidecar `416` copied as a security block). Operators also confuse dummy with the protected backend.

## Current (code)

- Apache overlay still proxies: `crs-apache/httpd-vhosts.conf` has `ProxyPass / ${BACKEND}/`, `ProxyPassReverse`, `ProxyErrorOverride`, `ProxyPreserveHost`, `ProxyTimeout`, and websocket `RewriteRule` `[P]` to `${BACKEND_WS}`. `RemoteIPHeader X-Real-IP` is already overlaid.
- Compose wires dummy as that origin: `BACKEND=http://dummy` plus unlabeled `dummy: traefik/whoami` in `docker-compose.yml`, `docker-compose.local.yml`, `docker-compose.test.yml`, `docker-compose.test.nginx.yml`.
- Nginx has no proxy overlay: `crs-nginx/realip.conf` only (`zz-realip.conf`). `docker-compose.test.nginx.yml` still sets `BACKEND=http://dummy`. Image `proxy_pass ${BACKEND}` is unchanged. Healthcheck probes `http://127.0.0.1:8080/` (not `/healthz`).
- Plugin already treats sidecar status `< 300` as allow and calls `next`: `pkg/modsecurity/serve.go` (3xx/4xx copied as security block). No inspect-only Config knob exists.
- README tells operators dummy exists so WAF “respond with 200 OK all the time”: `README.md` (“How it works”).
- Integration usage still names dummy as the WAF origin: `knowledge/devdocs/build_testing_integration.md`. Sidecar-vs-next language already exists: `knowledge/devdocs/core_plugin_middleware.md`.
- No `Benchmark*` in this tree. README still documents `go test -bench=BenchmarkProtectedEndpoint`: `README.md`, `knowledge/devdocs/build_testing_go.md`.
- CRS image `BACKEND` default if omitted is still a proxy (`http://localhost:80`): `knowledge/research/ext_modsecurity_http-status_deny-vs-error/notes.md`. Overlay contract for replacing `proxy_pass` with inspect-only 200: not found in this tree (research in flight).

## Desired

- After ModSecurity **request** phases, the sidecar answers **HTTP 200** itself (GET and POST/PUT). Traefik `next` stays the real app.
- Nginx: overlay `proxy_backend.conf.template` (mount `/etc/nginx/templates/includes/proxy_backend.conf.template`) so `location /` is method-agnostic 2xx, not `proxy_pass ${BACKEND}`. Keep `crs-nginx/realip.conf`. Keep cors include. Mount on every nginx compose that today sets dummy (`docker-compose.test.nginx.yml` at minimum).
- Apache: edit existing `crs-apache/httpd-vhosts.conf` — remove ProxyPass family and websocket `[P]` to BACKEND_WS; keep RemoteIP / Unique-ID / X-Forwarded-Proto; add method-agnostic 200 **after** request processing (not a static file / POST 405).
- Compose: delete unlabeled `dummy`; drop `BACKEND=http://dummy` once nothing interpolates it. Keep labeled whoami apps. Nginx `/` healthcheck must still pass.
- Docs: rewrite dummy/always-200 as shadow WAF (sidecar inspect + 200; `next` is the app).
- Prove on live CRS (Pester / curl through Traefik **and** curl at `waf:8080`): allow GET+POST body; URI CRS block; **POST-body CRS block** (abort nginx `return` if phase 2 is skipped); Range must not be sidecar 416; client-IP audit tests; no dummy service.
- Fallback if `return 200` skips body rules: same-container loopback drain-200, still no extra compose service; document why `return` failed.
- **Throughput (caller):** measure allow-path throughput **before** the overlay and **after**. Put before, after, and delta on the delivery card. Do not treat that as a license to add `Benchmark*` or bombardier CI unless measurement cannot be done otherwise.

## Affected

- `crs-apache/httpd-vhosts.conf`
- new nginx overlay under `crs-nginx/` plus `docker-compose.test.nginx.yml` volume
- `docker-compose.yml`, `docker-compose.local.yml`, `docker-compose.test.yml`, `docker-compose.test.nginx.yml`
- `README.md` How-it-works dummy paragraph
- usage packets that still call dummy the WAF origin (`knowledge/devdocs/build_testing_integration.md`; possibly `core_plugin_middleware.md` if dummy is named)
- Pester integration suite (authority for overlays; Go unit tests mock the sidecar)

## Out of scope

- Changing `pkg/modsecurity/serve.go` (3xx/4xx-as-block, allow `< 300`, no new Config knob)
- Pointing `BACKEND` at Traefik or the real app; `BACKEND=http://127.0.0.1:8080` loop; DetectionOnly as a substitute for dropping ProxyPass
- Removing labeled whoami apps (`website-with-waf`, `whoami-protected`, …)
- Dropping X-Real-IP / REMOTEIP / nginx real_ip overlays
- Plugin `maxBodySizeBytes` default / README 5 MB (#20)
- Durable allow-path CORS / Yaegi (#29)
- In-process libmodsecurity
- Committing new `Benchmark*` functions or bombardier CI (measure for the card; do not sneak a bench suite)

## Unknowns

- Whether nginx `return 200` in `location /` still runs CRS request-body inspection (phase 2) on pin `4.3.0-nginx-alpine-202406090906`.
- Which Apache method-agnostic 200 (Lua `DONE`, CGI drain, other) actually runs after request phases on pin `4.3.0-apache-alpine-202406090906`.
- Before-change allow-path throughput on this machine (not yet measured).
- Official CRS Docker overlay paths for this pin vs `main` (research in flight).

## Tensions

- Brief says do not add bombardier benches; caller says measure throughput before and after and put improvement on the delivery card. This run measures and reports; it does not add a `Benchmark*` suite unless that is the only way to get the numbers.
- Brief says this is compose + CRS overlay, not a plugin feature. README still documents `BenchmarkProtectedEndpoint`, which is not in the tree — not taken here.
- Dummy whoami is both the CRS origin (remove) and the labeled app behind Traefik (keep). Only the unlabeled `dummy` service is in scope.
