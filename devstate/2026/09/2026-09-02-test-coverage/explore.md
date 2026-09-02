# Explore
IssueKey: 2026-09-02-test-coverage

## Concepts

Report.md listed ten enforcement-path test holes. `origin/main` already closed most of them (websocket handshake vs forged Upgrade, sidecar 5xx/3xx, fail-open through ServeHTTP, Host/XFF/X-Real-Ip, deny-verbs-with-body, ConnState reuse, inbound cancel, and several Prepare validations).

Remaining work is test hygiene and the few holes that still have no case:

```
report.md holes
        │
        ├─ already on main ──► do not duplicate
        │
        └─ still open
              ├─ TestModsecurity_ServeHTTP shares *http.Request on two rows
              ├─ rejectNegative fields without a Prepare test
              ├─ no concurrent mixed-body ServeHTTP (no -race in CI)
              ├─ zero-window ServeHTTP ──► not reachable after Prepare
              └─ extra inbound headers ──► Host/XFF/X-Real-Ip already asserted
```

`buf.Bytes()` aliases the pooled array (`pkg/modsecurity/body.go`). A concurrent mixed-size ServeHTTP test is the guard the body-pool packet already warns about.

`Prepare` treats window `0` and threshold `0` as omitted and replaces them with CreateConfig defaults (`10` / `5`). `health.New` window `0` never resets, but that constructor is not the public config surface. `knowledge/devdocs/core_plugin_health.md` already states this.

## Decisions

- Clone every `TestModsecurity_ServeHTTP` row. Do not share `req`.
- Add `Prepare` reject-negative cases for every numeric field listed in `core_plugin_middleware_prepare-validation`, not only timeout and max body size.
- Add a concurrent mixed-body-size `ServeHTTP` test on one Plugin core (pooled small + ad-hoc large).
- Pass `-race` on the `go.yml` Test step so that guard actually runs on the PR. Leave `build.yml` as `go test -v ./...` (overlapping job; do not double race runtime).
- Do not add a ServeHTTP zero-window test. Do not add a general extra-header matrix.

## Open questions

- Q: Should a zero failure window be tested through ServeHTTP?
  Decision: resolved — no. `Prepare` replaces `unhealthyWafFailureWindowSecs` 0 with 10. `pkg/health/tracker_test.go` already covers `health.New` with window 0 (`TestNew_ZeroWindowLeavesClockUnset`, `TestRecordFailure_UnderThresholdDoesNotTrip_AtThresholdTrips`).
  By: explore

- Q: Should CI gain `-race`, or only a unit test that is race-safe when someone runs `go test -race` locally?
  Decision: assumed — add the concurrent mixed-body test and pass `-race` on `.github/workflows/go.yml` Test only. `build.yml` stays without `-race`.
  By: explore

- Q: Do we still need a test that arbitrary inbound headers (beyond Host / XFF / X-Real-Ip) reach the sidecar?
  Decision: resolved — no. `pkg/modsecurity/serve_test.go` already asserts Host, X-Forwarded-For, and X-Real-Ip, which was the product gap the report named.
  By: explore

- Q: Will in-flight sibling worktrees add these remaining tests before merge?
  Decision: assumed — ignore sibling trees; close the holes on this branch against `origin/main`.
  By: explore
