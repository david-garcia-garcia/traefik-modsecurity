# Requirement
IssueKey: 2026-09-03-improve-test-coverage

## Problem

The four-stack GitHub Actions matrix (`.github/workflows/integration-test.yml`) runs only `scripts/integration-tests.Tests.ps1`. Several Plugin `ServeHTTP` contracts in `pkg/modsecurity/serve.go` and `openspec/specs/core_plugin_middleware_*` are covered by Go unit tests but have no live Traefik+CRS Pester `It`. The ticket asks to pick the four most critical of those gaps and close them in the integration suite.

## Current (code)

- Matrix stacks: `apache-whoami`, `nginx-whoami`, `apache-drain`, `nginx-drain` in `.github/workflows/integration-test.yml`. CI path is `./scripts/integration-tests.Tests.ps1` only (`knowledge/devdocs/build_testing_integration.md`).
- Live coverage that exists: CRS deny on query/POST body, Host and ClientHost on deny audit, origin-form and absolute-form Request-URI, status-header `ok` / `blocked` / `error` / `unhealthy`, fail-open trip at `/threshold-test` (threshold 3), body 413 on `/protected` and chunked pool on `/pool-test`, default `denyVerbsWithBody` GET/HEAD/DELETE, reclaim_put/dispose, WebSocket echo on `/ws-echo`, drain Range not-416, bombardier allow-path (`scripts/integration-tests.Tests.ps1`).
- `scripts/integration-tests.BodySize.Tests.ps1` exists but is not in the CI matrix.
- Handshake skip vs inspect: `isWebsocket` in `pkg/modsecurity/serve.go`. Live suite has only “handshake and echo” (`Describe "WebSocket through WAF middleware"`). Spec scenarios “forged Upgrade is inspected”, “Connection without upgrade token is inspected”, and “skip does not set status header” are `openspec/specs/core_plugin_middleware_websocket-skip/spec.md` / `core_plugin_middleware_status-header` — not found as Pester `It`.
- Sidecar 5xx vs 4xx: `ServeHTTP` copies 3xx/4xx and treats `>= 500` as WAF failure (`pkg/modsecurity/serve.go`). Integration never drives a live sidecar 5xx. Go coverage: `pkg/modsecurity/serve_test.go` `TestPlugin_Sidecar5xxTripsHealth`, `modsecurity_test.go` `TestModsecurity_Sidecar5xxIsWafFailure`.
- Health backoff resume and window tumble: `/threshold-test` trips unhealthy after 3 stops; it does not wait `unhealthyWafBackOffPeriodSecs` and assert the sidecar is tried again, and it does not assert the failure window reset (`openspec/specs/core_plugin_middleware_health-tracker/spec.md`). Window reset is unit-only (`pkg/health/tracker_test.go`).
- Denied-verb body while fail-open: spec `core_plugin_middleware_deny-verbs-with-body` “GET with a body is rejected when the WAF is unhealthy”. Go: `deny_verbs_with_body_test.go` `TestModsecurity_DefaultGetWithBodyIsRejectedWhenWAFUnhealthy`. Not found in Pester. `/force-test` only covers GET/HEAD/DELETE with body while WAF is up.
- Inbound cancel is not a health failure (`core_plugin_middleware_health-failures`): Go `TestPlugin_InboundCancelDoesNotTripHealth`. Not found in Pester.
- Allow-path must not copy sidecar response headers (`core_plugin_middleware_sidecar-response`): Go `TestPlugin_UpstreamIssue29_AllowPathKeepsBackendHeaders`. Not found in Pester.
- Default list also includes OPTIONS/TRACE/CONNECT (`pkg/modsecurity/config.go` `CreateConfig`); Pester does not send those methods with a body.
- Plugin must not append `RemoteAddr` to `X-Forwarded-For` (`core_plugin_middleware_sidecar-request`): Go `TestPlugin_SidecarRequestCopiesHostAndForwardingHeaders`. Live suite asserts audit `REMOTE_ADDR` equals Traefik ClientHost, not the no-append contract.

## Desired

Add Pester coverage, on the four-stack matrix file (`scripts/integration-tests.Tests.ps1` or a file that CI also runs), for the four most critical currently untested integration behaviours. Explore names those four. Product `ServeHTTP` behaviour does not change unless a test proves it is already wrong.

## Affected

- `scripts/integration-tests.Tests.ps1` (and `scripts/TestHelpers.ps1` if a new helper is required)
- `.github/workflows/integration-test.yml` only if a new test file must join the matrix
- `docker-compose.test.yml` / `docker-compose.test.nginx.yml` / drain overlays only if a new route or fixture is required to observe a behaviour
- `knowledge/devdocs/build_testing_integration.md` if helpers or stacks change
- Specs under `openspec/specs/core_plugin_middleware_*` for the four chosen behaviours (fold, do not invent parallel leaves)

## Out of scope

- Exhaustive Pester for every spec scenario
- New Go unit tests (unless a chosen behaviour cannot be observed on the live stack at all — then say so; do not silently drop it)
- Changing plugin deny/allow/fail-open semantics
- Moving or rewriting `scripts/integration-tests.BodySize.Tests.ps1` unless one of the four chosen behaviours lives there
- Performance/bombardier floors, reclaim internals beyond what the four require

## Unknowns

- Which four behaviours are “most critical” (explore decides from the inventory above; not a product ask to test everything)
- Whether a live sidecar 5xx needs a compose fixture (CRS whoami/drain origins do not emit 5xx on `/protected` today)

## Tensions

None versus the caller spec. Tension with completeness: the inventory is larger than four; the ticket caps the apply at four.
