## 1. Vendor backendbackoff

- [x] 1.1 Confirm `go.mod` stays on `traefik-middleware-utilities v1.0.3` and `go mod vendor` includes `backendbackoff`.

## 2. Config knobs

- [x] 2.1 Add `UnhealthyWafFailureRatio` and `UnhealthyWafMaxBackOffPeriodSecs` to `Config` / `CreateConfig`.
- [x] 2.2 Extend `Prepare` to reject negatives, reject a non-zero ratio outside (0, 1), and reject a non-zero max below base. Keep window default 10.

## 3. Wire the gate

- [x] 3.1 Build `backendbackoff.New` in `Plugin.New` when backoff seconds are greater than zero (threshold → TripFailures, backoff → BaseCooldown, max knob or base → MaxCooldown, Jitter 0).
- [x] 3.2 In `ServeHTTP`, `Allow` key `waf` before the sidecar call; on deny follow failMode and do not Report.
- [x] 3.3 After an admitted call: no Report on inbound `Canceled`; `Report(false)` on other transport errors and sidecar 5xx; `Report(true)` on sidecar status below 500.
- [x] 3.4 Close the Gate from `Plugin.Close`. Remove `Plugin.IsUnhealthy` and delete `pkg/health`.

## 4. Unit tests

- [x] 4.1 Rewrite `pkg/modsecurity` health tests to observe sidecar hit counts and `modSecurityStatusRequestHeader` (`Test<Type>_<Behavior>` in `serve_test.go` / `plugin_reuse_test.go` / `modsecurity_test.go`). Cover trip, skip, one probe after cooldown, concurrent skip during probe, inbound cancel, 5xx, and status below 500.
- [x] 4.2 Add Prepare tests for the new knobs. Drop `pkg/health/tracker_test.go` with the package.
- [x] 4.3 Run `go test -race ./...` (or `run-tests go`).

## 5. Docs and compose

- [x] 5.1 Update README and `docker-compose.test.yml` / `docker-compose.test.nginx.yml` comments so window is documented as unused by the gate.
- [x] 5.2 Confirm existing Pester `/threshold-test` resume uses `Wait-ForWafHealthy`, `Wait-ForThresholdRouteInspecting`, and `Invoke-SafeWebRequest` from `scripts/TestHelpers.ps1` and still expects a sidecar consult after the 10s backoff. Do not add a new helper unless an It becomes non-linear.

## 6. Usage packets

- [x] 6.1 Update `knowledge/devdocs/core_plugin_health.md` (and layout / middleware pointers) for Allow/Report. Rename the packet if the leaf rename requires it.
