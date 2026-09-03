## Why

The four-stack GitHub Actions matrix never asserts four Plugin `ServeHTTP` contracts that already exist in specs and Go unit tests: handshake-only WAF skip against live CRS, deny-verb 400 while fail-open, health-tracker backoff resume, and sidecar HTTP 5xx not copied as a block. A live Traefik+CRS regression of those paths would not fail CI.

## What Changes

- Add Pester `It`s in `scripts/integration-tests.Tests.ps1` (the file the four-stack matrix already runs) for those four behaviours.
- Add a tiny HTTP 503 fixture origin and a Traefik route whose `modSecurityUrl` points at it (backoff off) so behaviour 4 is observable. Mirror labels in `docker-compose.test.yml` and `docker-compose.test.nginx.yml`.
- Reuse `Invoke-TcpHttpRequest` and `Invoke-WebSocketEcho` in `scripts/TestHelpers.ps1`. Add a helper only if an existing one cannot send the request.
- Update `knowledge/devdocs/build_testing_integration.md` for the new route, fixture, and Its.
- Plugin `ServeHTTP` is unchanged unless a new It proves current behaviour is already wrong.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_websocket-skip`: the four-stack integration suite SHALL prove forged `Upgrade: websocket` is still CRS-inspected and a real handshake with a CRS probe in the query still skips.
- `core_plugin_middleware_deny-verbs-with-body`: the suite SHALL prove a GET with a body is still HTTP 400 after `/threshold-test` has tripped fail-open.
- `core_plugin_middleware_health-tracker`: the suite SHALL prove that after backoff elapses and the WAF is healthy again, `/threshold-test` consults the sidecar (a CRS probe is blocked).
- `core_plugin_middleware_waf-status`: the suite SHALL prove a sidecar HTTP 503 with a distinctive body is not copied to the client; with backoff off the client gets 502 and `X-Waf-Status` is `error`.

## Impact

- `scripts/integration-tests.Tests.ps1`, possibly `scripts/TestHelpers.ps1`
- `docker-compose.test.yml`, `docker-compose.test.nginx.yml` (503 fixture + route)
- `knowledge/devdocs/build_testing_integration.md`
- `.github/workflows/integration-test.yml` only if a new test file must join the matrix (not planned)
- No public Config key. No `pkg/modsecurity/serve.go` change planned.
