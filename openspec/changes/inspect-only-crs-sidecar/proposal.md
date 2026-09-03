## Why

The OWASP CRS sidecar still reverse-proxies every inspect to an unlabeled dummy whoami. That hop is not Traefik `next`, so dummy/whoami behavior (Range 416, large-body proxy errors) is copied as a WAF block, operators confuse dummy with the app, and every allow pays an extra origin round-trip.

## What Changes

- Apache CRS overlay (`crs-apache/httpd-vhosts.conf`): stop `ProxyPass` / websocket `[P]` to `${BACKEND}`; after request phases answer HTTP 200 with the image’s `/healthz` rewrite pattern; unset `Range` / `If-Range` so a tiny 200 is not 416.
- Nginx CRS overlay: do **not** use `return 200` (measured: URI and POST-body CRS probes become 200). Same-container loopback drain-200 plus `BACKEND` to that listener; keep `crs-nginx/realip.conf`.
- Compose: delete unlabeled `dummy` on demo and test files. Keep labeled whoami apps. Plugin `ServeHTTP` unchanged.
- README / integration usage: dummy-as-always-200 becomes shadow WAF (sidecar inspect + 200; `next` is the app).

## Capabilities

### New Capabilities

- `core_crs_sidecar_inspect-only`: CRS Docker sidecar used by this repo’s compose answers HTTP 200 after ModSecurity request phases, without a dummy origin, while still blocking URI and POST-body CRS hits and not emitting sidecar 416 on `Range`.

### Modified Capabilities

None. Plugin sidecar request/response specs stay; this is compose + CRS overlay, not `ServeHTTP`.

## Impact

- `crs-apache/httpd-vhosts.conf`, new files under `crs-nginx/`, `docker-compose.yml`, `docker-compose.local.yml`, `docker-compose.test.yml`, `docker-compose.test.nginx.yml`
- `README.md` How it works; `knowledge/devdocs/build_testing_integration.md` dummy wording
- Pester live CRS suite is the authority. Go unit tests mock the sidecar and will not catch a broken overlay.
- No plugin Config key. No `pkg/modsecurity/serve.go` change.
