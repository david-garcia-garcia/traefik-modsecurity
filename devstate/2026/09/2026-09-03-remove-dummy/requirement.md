# Requirement
IssueKey: 2026-09-03-remove-dummy

## Problem
The CRS sidecar still has a dummy whoami origin on integration whoami stacks (`BACKEND=http://dummy`). That origin can answer with non-security 4xx/3xx (Range 416, 304 Not Modified). The plugin copies any sidecar `300–499` as a WAF block (`pkg/modsecurity/serve.go`), so dummy origin behavior becomes a false block. Demo compose already uses inspect-only drain (no dummy). The ask is: if drain is robust enough, drop dummy from tests and docs entirely, document only drain, and point README at the sample Apache/nginx CRS files the tests already use.

## Current (code)
- Demo Apache is already inspect-only: `docker-compose.yml` and `docker-compose.local.yml` mount `crs-apache/httpd-vhosts.drain.conf` and do not run a `dummy` service.
- Test Apache whoami still sets `BACKEND=http://dummy` and runs unlabeled `dummy` (`docker-compose.test.yml`). Overlay `docker-compose.test.apache-drain.yml` profiles `dummy` off and remounts the drain vhost.
- Test nginx whoami still sets `BACKEND=http://dummy` (`docker-compose.test.nginx.yml`). Overlay `docker-compose.test.nginx-drain.yml` points `BACKEND` at loopback `http://127.0.0.1:18081` and mounts `crs-nginx/drain-origin.conf`.
- Apache drain vhost: no `ProxyPass`; `RewriteRule .* - [R=200,L]`; unsets `Range` / `If-Range` early (`crs-apache/httpd-vhosts.drain.conf`). Does not unset `If-Modified-Since` / `If-None-Match`.
- nginx drain: in-process `server` on `127.0.0.1:18081`, `max_ranges 0`, `return 200` (`crs-nginx/drain-origin.conf`). Comment: do not put `return` on CRS `location /` (skips request-body phase).
- Whoami Apache overlay still reverse-proxies `${BACKEND}` (`crs-apache/httpd-vhosts.conf`).
- Pester keeps both origins: dummy-absent / Range-not-416 skip on whoami; dummy-present skips on drain (`scripts/integration-tests.Tests.ps1`). Helpers: `Get-DummyContainerName`, `Get-IntegrationOriginKind` (`scripts/TestHelpers.ps1`).
- Runner default is `apache-whoami` (`Test-Integration.ps1`). `-AllStacks` runs four names. CI matrix is four stacks (`.github/workflows/integration-test.yml`).
- README Architecture still draws optional dummy whoami and publishes dummy vs no-dummy benches (`README.md`). Demo RemoteIP section still links `crs-apache/httpd-vhosts.conf` while demo compose mounts `httpd-vhosts.drain.conf`.
- Unarchived change `openspec/changes/inspect-only-crs-sidecar/` on main requires whoami stacks to keep dummy (`specs/core_crs_sidecar_inspect-only/spec.md`). Main catalog has no `openspec/specs/core_crs_sidecar_inspect-only/`.
- Plugin block predicate is still `resp.StatusCode >= 300 && resp.StatusCode < 500` (`pkg/modsecurity/serve.go`). Conditional headers are copied to the sidecar. This is the 304 false-block path when the origin can 304.

## Desired
- Decide from evidence whether drain Apache and nginx are robust enough that dummy can be removed completely from tests and documentation.
- If yes: integration tests and CI run drain only (Apache + nginx); drop unlabeled `dummy` / `BACKEND=http://dummy` / whoami-origin stacks; stop documenting dummy; README tells operators how to configure Apache and nginx CRS by linking the sample files tests already use (`httpd-vhosts.drain.conf`, `drain-origin.conf`, plus existing realip overlays).
- Improve drain integration coverage if that is what makes the removal honest (Range, conditional headers / 304, POST body CRS, allow GET/POST).
- If drain is not robust enough: keep dummy stacks, record the gap, do not pretend removal.

## Affected
- `docker-compose.test.yml`, `docker-compose.test.nginx.yml`, drain overlays, `Test-Integration.ps1`, `scripts/TestHelpers.ps1`, `scripts/integration-tests.Tests.ps1`, `.github/workflows/integration-test.yml`
- `crs-apache/httpd-vhosts.conf` (whoami ProxyPass overlay) if dummy stacks go away
- `README.md`, `knowledge/devdocs/build_testing_integration.md`
- `openspec/changes/inspect-only-crs-sidecar/` (whoami-keep-dummy requirement) and any follow-on spec

## Out of scope
- Changing the plugin 3xx/4xx copy rule in `serve.go` (the ticket asks to remove dummy so those origin statuses stop happening, not to retune the classifier).
- Pointing `BACKEND` at Traefik or the real application.
- New CRS image pins or CRS rule-set changes.
- Labeled whoami *application* services (`whoami-protected`, demo `website-with-waf`) — those are Traefik `next`, not the CRS dummy origin.

## Unknowns
- Whether drain Apache `R=200` or nginx loopback `return 200` can still emit 304 / other 3xx when the plugin copies `If-Modified-Since` / `If-None-Match`.
- Whether the four-stack suite on `origin/main` currently passes (not re-run in prepare).
- Whether `httpd-vhosts.conf` (ProxyPass) must stay as a negative example or can be deleted with dummy.

## Tensions
- Existing inspect-only spec on main still requires dummy whoami stacks for comparison; this ticket asks to delete that hop.
- README says demo mounts `httpd-vhosts.conf` for RemoteIP; demo compose actually mounts `httpd-vhosts.drain.conf`.
- opus_review 304 finding is plugin+origin; drain-only tests do not fix the classifier if a drain origin can still 304.
