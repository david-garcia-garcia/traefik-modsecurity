## 1. Write failing test

- [ ] 1.1 In `scripts/integration-tests.Tests.ps1`, add an `It` that GET `/protected` with `Range: bytes=10240-` via `Invoke-SafeWebRequest` and asserts the client status is not 416 (use `-Because`). Confirm it fails on current Apache compose (today is 416).
- [ ] 1.2 Add an `It` that POST `/protected` with a CRS SQL-injection body (`Content-Type: application/x-www-form-urlencoded`) via `Invoke-SafeWebRequest` and asserts status ≥ 400. Confirm it passes today (control — must stay failing-if-broken after overlays).
- [ ] 1.3 Add an `It` that `dummy` is not a running compose service (assert via existing Docker helpers in `scripts/TestHelpers.ps1`, or add a small helper there if inspect is non-trivial). Confirm it fails while `dummy` still exists.

## 2. Apache inspect-only overlay

- [ ] 2.1 Edit `crs-apache/httpd-vhosts.conf`: remove `ProxyPass` / `ProxyPassReverse` / unused proxy knobs and websocket `[P]` to `${BACKEND_WS}`. Keep `RemoteIPHeader X-Real-IP`, `RemoteIPInternalProxy`, Unique-ID / X-Forwarded-Proto request headers.
- [ ] 2.2 Add the image `/healthz` rewrite pattern on `/` (`RewriteRule` `[R=200]` + `ErrorDocument 200`) and `RequestHeader unset Range` / `If-Range`.
- [ ] 2.3 Drop unlabeled `dummy` and `BACKEND=http://dummy` from `docker-compose.yml`, `docker-compose.local.yml`, and `docker-compose.test.yml`. Keep labeled whoami apps.

## 3. Nginx drain-200 overlay

- [ ] 3.1 Add `crs-nginx/` loopback drain (entrypoint.d script using image `nc`, listen `127.0.0.1:18081` or the next free high port) that always writes HTTP 200 and ignores `Range`.
- [ ] 3.2 Point `docker-compose.test.nginx.yml` `BACKEND` at that loopback URL; mount the script into `/docker-entrypoint.d/`. Keep `crs-nginx/realip.conf`. Do not use nginx `return 200` on `location /`.
- [ ] 3.3 Drop unlabeled `dummy` from `docker-compose.test.nginx.yml`.

## 4. Docs

- [ ] 4.1 Rewrite README How-it-works dummy/always-200 as shadow WAF (sidecar inspect + 200; Traefik `next` is the app).
- [ ] 4.2 Update `knowledge/devdocs/build_testing_integration.md` so dummy is not named as the CRS origin.

## 5. Prove and measure

- [ ] 5.1 Run `./Test-Integration.ps1` (Apache compose) and `./Test-Integration.ps1 -ComposeFile ./docker-compose.test.nginx.yml`. Tasks 1.1–1.3 SHALL pass. Use helpers from `scripts/TestHelpers.ps1` only (see `knowledge/devdocs/build_testing_integration.md`).
- [ ] 5.2 Curl `waf:8080` GET allow, POST allow, URI block, POST-body block, Range not 416. Record on the delivery card.
- [ ] 5.3 Bombardier after, same flags as explore (`-c 50 -d 15s`, `http://localhost:8000/protected` GET and POST). Put before (GET 5077 req/s, POST 1098 req/s), after, and delta on the delivery card. Do not add `Benchmark*` to the tree.
