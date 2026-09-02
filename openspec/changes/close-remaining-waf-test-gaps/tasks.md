## 1. Isolate ServeHTTP table rows

- [ ] 1.1 In `modsecurity_test.go` `TestModsecurity_ServeHTTP`, clone `req` for `"Adds remediation header when request is blocked"` and `"Adds remediation header with different status codes"` so no row passes the shared `req`.

## 2. Prepare reject-negative coverage

- [ ] 2.1 In `pkg/modsecurity/config_test.go`, add a table that calls `Prepare` with `-1` for each remaining numeric field (`unhealthyWafBackOffPeriodSecs`, `unhealthyWafFailureThreshold`, `unhealthyWafFailureWindowSecs`, `maxConnsPerHost`, `maxIdleConnsPerHost`, `responseHeaderTimeoutMillis`, `expectContinueTimeoutMillis`, `maxBodySizeBytesForPool`) and asserts construction fails.

## 3. Concurrent mixed-body ServeHTTP

- [ ] 3.1 In `pkg/modsecurity/body_pool_test.go`, add a concurrent `ServeHTTP` test on one Plugin core that mixes pooled small bodies and ad-hoc large bodies and asserts each sidecar and `next` sees that request's own payload.

## 4. CI race detector

- [ ] 4.1 In `.github/workflows/go.yml`, change the Test step to `go test -race -v ./...`. Leave `build.yml` unchanged.
