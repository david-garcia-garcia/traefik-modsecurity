## 1. Write failing test

- [x] 1.1 In `modsecurity_test.go`, add `TestModsecurity_Sidecar5xxIsWafFailure` (or table cases) that send a mock sidecar 503 with `modSecurityStatusRequestHeader` set and `unhealthyWafBackOffPeriodSecs` 0. Assert header is not `blocked`, client is not 503 with the sidecar body, and next is not called. Confirm the test fails on current `serve.go`.
- [x] 1.2 Add a case with `unhealthyWafBackOffPeriodSecs` > 0 and `unhealthyWafFailureThreshold` 1 that asserts next is called (fail-open) on sidecar 503. Confirm it fails today.

## 2. Core implementation

- [x] 2.1 Extract one WAF-failure helper in `pkg/modsecurity` that records a tracker failure when present, fail-opens to next when unhealthy, and otherwise returns 502 with an empty body.
- [x] 2.2 In `serve.go`, treat sidecar `StatusCode >= 500` as that failure: set the status request header to `error` when configured, then call the helper. Leave `4xx` on the existing block path. Route transport `err != nil` through the same helper without changing when transport sets `error`.
- [x] 2.3 Keep the existing deferred sidecar body `Close` on the 5xx path. Do not `forwardResponse` a 5xx.

## 3. Verify

- [x] 3.1 Re-run the new 5xx tests and existing `TestModsecurity_ServeHTTP` 403/406 cases via `run-tests`. All SHALL pass.
