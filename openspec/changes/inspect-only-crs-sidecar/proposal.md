## Why

The OWASP CRS sidecar still reverse-proxies every inspect to an unlabeled dummy whoami. That hop is not Traefik `next`, so dummy/whoami behavior (Range 416, large-body proxy errors) is copied as a WAF block, operators confuse dummy with the app, and every allow pays an extra origin round-trip. Demo compose should be inspect-only. The test suite must still keep the dummy hop so whoami vs drain can be compared, including throughput.

## What Changes

- Apache CRS drain overlay (`crs-apache/httpd-vhosts.drain.conf`): stop `ProxyPass` / websocket `[P]` to `${BACKEND}`; after request phases answer HTTP 200 with the image’s `/healthz` rewrite pattern; unset `Range` / `If-Range` so a tiny 200 is not 416. Whoami Apache vhost (`httpd-vhosts.conf`) stays ProxyPass for the whoami test stack.
- Nginx CRS drain overlay: do **not** use `return 200` on the CRS-facing `location /` (measured: URI and POST-body CRS probes become 200). Loopback origin after `proxy_pass` (`crs-nginx/drain-origin.conf`, `BACKEND=http://127.0.0.1:18081`); keep `crs-nginx/realip.conf`.
- Demo compose (`docker-compose.yml`, `docker-compose.local.yml`): drain Apache overlay, no dummy.
- Test suite: four stacks — apache+whoami, nginx+whoami, apache+drain, nginx+drain. Pester benches all four. Plugin `ServeHTTP` unchanged.
- README / integration usage: dummy is the whoami-origin test hop; drain/demo is shadow WAF (sidecar inspect + 200; `next` is the app).

## Capabilities

### New Capabilities

- `core_crs_sidecar_inspect-only`: CRS Docker sidecar used by this repo’s demo and drain stacks answers HTTP 200 after ModSecurity request phases, without a dummy origin, while still blocking URI and POST-body CRS hits and not emitting sidecar 416 on `Range`. Whoami test stacks keep dummy. The suite measures allow-path throughput on all four.

### Modified Capabilities

None. Plugin sidecar request/response specs stay; this is compose + CRS overlay, not `ServeHTTP`.

## Impact

- `crs-apache/httpd-vhosts.conf` (whoami), `crs-apache/httpd-vhosts.drain.conf`, `crs-nginx/drain-origin.conf`
- `docker-compose.yml`, `docker-compose.local.yml`, `docker-compose.test.yml`, `docker-compose.test.nginx.yml`, drain overlays, `Test-Integration.ps1`, `.github/workflows/integration-test.yml`
- `README.md` How it works; `knowledge/devdocs/build_testing_integration.md`
- Pester live CRS suite is the authority. Go unit tests mock the sidecar and will not catch a broken overlay.
- No plugin Config key. No `pkg/modsecurity/serve.go` change. No committed Go `Benchmark*` tests; throughput lives in Pester via bombardier.
