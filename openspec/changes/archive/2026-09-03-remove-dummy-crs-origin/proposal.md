## Why

Demo compose already inspects without a dummy CRS origin. Integration whoami stacks and README still run or document unlabeled `dummy` (`BACKEND=http://dummy`). That hop can return Range 416 or nginx `If-None-Match: *` 304, which this plugin copies as a WAF block. Drain Apache already stays 200 on those probes; nginx drain still 304s until `proxy_pass` omits the conditional headers. Tests and docs should match the demo: drain only.

## What Changes

- Bake inspect-only drain into the Apache and nginx **test** compose files. Delete unlabeled `dummy`, `BACKEND=http://dummy`, whoami-origin stacks, and the drain overlay files (they become the base).
- Nginx: on `proxy_pass` to the loopback origin, omit `If-None-Match` and `If-Modified-Since` so the origin `return 200` is not rewritten to 304. Keep `drain-origin.conf` (`max_ranges 0`, `return 200`). Do not `return` on CRS `location /`.
- Apache: keep `httpd-vhosts.drain.conf`; also unset `If-Modified-Since` / `If-None-Match` early (same pattern as Range). Delete `crs-apache/httpd-vhosts.conf` (ProxyPass dummy hop).
- Pester + CI: two stacks (`apache-drain`, `nginx-drain`). Assert Range is not 416 and `If-None-Match: *` / `If-Modified-Since` are not 304. Keep URI and POST-body CRS denies. Default `Test-Integration.ps1` is Apache drain.
- README: remove dummy architecture and dummy benches. Tell operators to mount the same sample files the tests use (`httpd-vhosts.drain.conf`, `drain-origin.conf`, `crs-nginx/realip.conf`).
- Plugin `ServeHTTP` 3xx/4xx copy rule is unchanged.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_crs_sidecar_inspect-only`: all demo and test compose stacks are inspect-only (no dummy hop). Conditional request headers MUST NOT become sidecar 304/416. Suite is two drain stacks, not four.

## Impact

- `docker-compose.test.yml`, `docker-compose.test.nginx.yml`, delete drain overlays and `crs-apache/httpd-vhosts.conf`
- `crs-nginx/drain-origin.conf`, new nginx `proxy_backend` drain overlay, `crs-apache/httpd-vhosts.drain.conf`
- `Test-Integration.ps1`, `scripts/TestHelpers.ps1`, `scripts/integration-tests.Tests.ps1`, `.github/workflows/integration-test.yml`
- `README.md`, `knowledge/devdocs/build_testing_integration.md`
- No plugin Config key. No `pkg/modsecurity/serve.go` change.
