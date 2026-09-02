## Why

`origin/main` already covers most of the `report.md` enforcement-path holes. Three weaker spots remain: two `TestModsecurity_ServeHTTP` rows share one `*http.Request` (the table still PASSes), `Prepare` does not have a reject-negative case for every numeric field the spec already names, and there is no concurrent mixed-body `ServeHTTP` test — CI `go test` also does not pass `-race`, so the body-pool `buf.Bytes()` alias is unguarded on the PR.

## What Changes

- Clone every `TestModsecurity_ServeHTTP` row so each case has its own request and body.
- Add `Prepare` tests for every remaining negative numeric field (`unhealthyWafBackOffPeriodSecs`, threshold, window, conn limits, remaining timeouts, pool cap).
- Add a concurrent mixed-body-size `ServeHTTP` test on one Plugin core (pooled small + ad-hoc large).
- Pass `-race` on the `.github/workflows/go.yml` Test step. `build.yml` stays `go test -v ./...`.
- Do not change plugin runtime behavior. Do not add a ServeHTTP zero-window case (`Prepare` replaces window 0 with 10). Do not add an extra inbound-header matrix (Host / XFF / X-Real-Ip already asserted).

## Capabilities

### New Capabilities

- `build_ci_github_go-test`: The `go.yml` Test job on pull requests to protected branches runs `go test` with the race detector.

### Modified Capabilities

- `core_plugin_middleware_prepare-validation`: Add scenarios so every numeric field named in the existing SHALL has a negative-reject case, not only timeout and max body size.
- `core_plugin_middleware_body-pool`: Concurrent mixed-size `ServeHTTP` on one Plugin core MUST NOT race (pooled small + ad-hoc large).

## Impact

- `modsecurity_test.go` — clone remaining shared `req` rows.
- `pkg/modsecurity/config_test.go` — remaining `rejectNegative` fields.
- `pkg/modsecurity/body_pool_test.go` (or `serve_test.go`) — concurrent mixed-body `ServeHTTP`.
- `.github/workflows/go.yml` — `go test -race`.
- Specs listed above. No public Config keys. No sidecar or Traefik wiring change.
