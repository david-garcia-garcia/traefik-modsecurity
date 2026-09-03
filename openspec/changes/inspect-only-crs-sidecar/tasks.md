## 1. Write failing test

- [x] 1.1 In `scripts/integration-tests.Tests.ps1`, add an `It` that GET `/protected` with `Range: bytes=10240-` via `Invoke-SafeWebRequest` and asserts the client status is not 416 (use `-Because`). Skip on whoami-origin stacks.
- [x] 1.2 Add an `It` that POST `/protected` with a CRS SQL-injection body (`Content-Type: application/x-www-form-urlencoded`) via `Invoke-SafeWebRequest` and asserts status ≥ 400. Confirm it passes on all four stacks.
- [x] 1.3 Add Its that `dummy` is absent on drain stacks and present on whoami stacks (`Get-DummyContainerName`).

## 2. Apache inspect-only overlay

- [x] 2.1 Keep whoami `crs-apache/httpd-vhosts.conf` as ProxyPass (restore from main). Add `crs-apache/httpd-vhosts.drain.conf`: no `ProxyPass` / websocket `[P]`; keep `RemoteIPHeader X-Real-IP`.
- [x] 2.2 Drain vhost: image `/healthz` rewrite on `/` (`RewriteRule` `[R=200]` + `ErrorDocument 200`) and `RequestHeader unset Range` / `If-Range` `early`.
- [x] 2.3 Demo `docker-compose.yml` / `docker-compose.local.yml`: drop dummy, mount drain vhost. `docker-compose.test.yml`: keep dummy + `BACKEND=http://dummy`. Add `docker-compose.test.apache-drain.yml` overlay.

## 3. Nginx drain overlay

- [x] 3.1 Add `crs-nginx/drain-origin.conf` loopback `server` on `127.0.0.1:18081` (`max_ranges 0`, `return 200`). Do not use `return` on CRS `location /`.
- [x] 3.2 Add `docker-compose.test.nginx-drain.yml`: `BACKEND=http://127.0.0.1:18081`, mount drain-origin; keep `crs-nginx/realip.conf` on the base file.
- [x] 3.3 Keep unlabeled `dummy` on `docker-compose.test.nginx.yml`. Drain overlay sets dummy `profiles: [whoami-origin]`.

## 4. Docs and runner

- [x] 4.1 Rewrite README How-it-works dummy/always-200 as shadow WAF for demo/drain; whoami test stacks still use dummy.
- [x] 4.2 Update `knowledge/devdocs/build_testing_integration.md` for four stacks, skips, and bombardier benches.
- [x] 4.3 `Test-Integration.ps1 -Stack` / `-AllStacks`. CI matrix of four stacks; install bombardier.

## 5. Prove and measure

- [x] 5.1 Run `./Test-Integration.ps1 -Stack apache-whoami`, `nginx-whoami`, `apache-drain`, `nginx-drain` (or `-AllStacks`). Tasks 1.1–1.3 SHALL pass on the stacks they apply to.
- [x] 5.2 Curl `waf:8080` GET allow, POST allow, URI block, POST-body block; Range not 416 on drain only. Record on the delivery card.
- [x] 5.3 Bombardier on all four stacks, same flags as explore (`-c 50 -d 15s`, `http://localhost:8000/protected` GET and POST). Put before (Apache whoami GET 5077 req/s, POST 1098 req/s), after for all four, and delta on the delivery card. Pin upstream [acouvreur#2](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/2). Do not add Go `Benchmark*` to the tree.
