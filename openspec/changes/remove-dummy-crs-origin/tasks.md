## 1. Nginx drain origin 304

- [x] 1.1 Add `crs-nginx/proxy_backend.drain.conf.template`: this pin’s stock `includes/proxy_backend.conf.template` (`Host $host`, `proxy_pass $upstream`) plus empty `If-None-Match` / `If-Modified-Since`. Mount it at `/etc/nginx/templates/includes/proxy_backend.conf.template`. Do not copy later-image `${PROXY_HOST_HEADER}` / `${BACKEND}` names — nginx rejects them on `4.3.0-nginx-alpine-202406090906`.
- [x] 1.2 Keep `crs-nginx/drain-origin.conf` loopback `return 200` + `max_ranges 0`. Do not put `return` on CRS `location /`.

## 2. Apache drain vhost

- [x] 2.1 In `crs-apache/httpd-vhosts.drain.conf`, unset `If-Modified-Since` and `If-None-Match` early (same pattern as Range / If-Range).
- [x] 2.2 Delete `crs-apache/httpd-vhosts.conf` (ProxyPass dummy hop) once nothing mounts it.

## 3. Compose and runner

- [x] 3.1 `docker-compose.test.yml`: drop `dummy` service and `BACKEND=http://dummy`; mount `httpd-vhosts.drain.conf`. Delete `docker-compose.test.apache-drain.yml`.
- [x] 3.2 `docker-compose.test.nginx.yml`: drop `dummy`; `BACKEND=http://127.0.0.1:18081`; mount `drain-origin.conf` and the drain `proxy_backend` template. Keep `crs-nginx/realip.conf`. Delete `docker-compose.test.nginx-drain.yml`.
- [x] 3.3 `Test-Integration.ps1` / `Get-IntegrationStackComposeFiles`: stacks `apache-drain` and `nginx-drain` only; default Apache drain. `-AllStacks` runs those two.

## 4. Pester and CI

- [x] 4.1 Remove dummy-present / whoami-origin skip helpers that exist only for the four-stack matrix. Keep a no-dummy assertion on both remaining stacks.
- [x] 4.2 Assert Range not 416, `If-None-Match: *` not 304, and `If-Modified-Since` not 304 on `/protected`. Keep URI and POST-body CRS denies.
- [x] 4.3 `.github/workflows/integration-test.yml` matrix: `apache-drain`, `nginx-drain` only. Update required-file list (no whoami overlays / ProxyPass vhost).

## 5. Docs

- [x] 5.1 README: remove dummy architecture, dummy benches, and the stale RemoteIP link to `httpd-vhosts.conf`. Tell operators to mount `crs-apache/httpd-vhosts.drain.conf` (Apache) and `crs-nginx/drain-origin.conf` plus the drain `proxy_backend` overlay and `crs-nginx/realip.conf` (nginx). Link those files.
- [x] 5.2 Update `knowledge/devdocs/build_testing_integration.md` to two drain stacks.

## 6. Verify

- [x] 6.1 `./Test-Integration.ps1 -Stack apache-drain` and `-Stack nginx-drain` (or `-AllStacks`). Tasks 4.1–4.2 SHALL pass.
- [x] 6.2 Curl `/protected` GET allow, POST allow, URI block, POST-body block; Range not 416; `If-None-Match: *` not 304. Record on the delivery card.
