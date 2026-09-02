# Requirement
IssueKey: 2026-09-02-test-coverage

## Problem

`report.md` (lines 149–161) listed ten test holes around WAF enforcement. On `origin/main` (`727d1e7`) most of those holes already have tests; a few still do not. This ticket is to close the remaining holes, not to re-add coverage that already exists.

## Current (code)

Closed on this tree (do not treat as missing):

- Websocket: `modsecurity_test.go` `"Does not forward Websockets"` now sends `GET` plus `Connection: upgrade`. `"Inspects forged Upgrade websocket without handshake"` asserts a `POST` with only `Upgrade: websocket` is inspected (403 from WAF). Mixed-case handshake is covered.
- Sidecar 5xx / 3xx: `modsecurity_test.go` `TestModsecurity_Sidecar5xxIsWafFailure` (503/500 → `"error"`, fail-open at threshold 1). `pkg/modsecurity/serve_test.go` `"failure 503"` and sidecar-5xx fail-open cases. 302 block: `"Intercepts request when WAF returns redirect without Location"` and `TestModsecurity_ServeHTTP_RedirectWithLocation`.
- Health through `ServeHTTP`: `pkg/modsecurity/serve_test.go` (`TestPlugin_InboundCancelDoesNotTripHealth`, deadline, client timeout, unreachable sidecar, 413 vs 5xx, fail-open body restore). `modsecurity_test.go` fail-open at threshold 1. Tracker isolation remains in `pkg/health/tracker_test.go` (`TestNew_ZeroWindowLeavesClockUnset`, `TestRecordFailure_UnderThresholdDoesNotTrip_AtThresholdTrips` with window 0).
- WAF request shape: `pkg/modsecurity/serve_test.go` asserts sidecar `r.Host`, `X-Forwarded-For`, `X-Real-Ip`.
- Verb+body: `deny_verbs_with_body_test.go` (`TestModsecurity_DefaultGetWithBodyIsRejected`, `TestModsecurity_DefaultDeleteWithBodyIsRejected`, empty deny list inspects GET body).
- Connection reuse: `pkg/modsecurity/serve_test.go` `TestPlugin_SidecarResponseReusesConnection` (`ConnState`, 20 requests, want 1 new conn) for allow 200, block 403, failure 503.
- Cancellation: `pkg/modsecurity/serve_test.go` `TestPlugin_InboundCancelAbortsSidecarCall`.
- Config: `pkg/modsecurity/config_test.go` rejects negative `timeoutMillis` / `maxBodySizeBytes`, scheme-less URL (`waf:80`), URL with path; plus health-tracker defaults.

Still open on this tree:

- `TestModsecurity_ServeHTTP` still passes the shared `req` (not a clone) in `"Adds remediation header when request is blocked"` and `"Adds remediation header with different status codes"` (`modsecurity_test.go` around those two cases). Other rows clone.
- No `ServeHTTP` test that a zero failure window does not reset the counter after time passes (tracker unit tests cover clock-unset and window 0, not that end-to-end).
- No assertion that arbitrary inbound headers (beyond Host / XFF / X-Real-Ip) reach the sidecar.
- `config_test.go` does not reject-negative the other `Prepare` numeric fields (`unhealthyWafBackOffPeriodSecs`, threshold, window, conn limits, remaining timeouts, pool cap) even though `pkg/modsecurity/config.go` `rejectNegative` covers them.
- No parallel mixed-body-size `ServeHTTP` test. No `t.Parallel` in `*_test.go`. CI (`.github/workflows/go.yml`, `build.yml`) runs `go test -v ./...` without `-race`.

## Desired

- Every `TestModsecurity_ServeHTTP` row clones the request.
- Tests that remain missing from the list above: zero-window counter through `ServeHTTP` if still a real hole; remaining `rejectNegative` fields; a concurrent mixed-body `ServeHTTP` guard (race detector).
- Do not duplicate tests that already exist on `origin/main`.

## Affected

- `modsecurity_test.go`
- `pkg/modsecurity/config_test.go`
- `pkg/modsecurity/serve_test.go` and/or `pkg/modsecurity/body_pool_test.go` (concurrency)
- possibly `.github/workflows/go.yml` / `build.yml` if `-race` is taken as part of the test, not a separate CI ticket

## Out of scope

- Product behavior changes (websocket handshake, 5xx-as-error, 3xx block, deny-verbs-with-body, Host/XFF copy, drain/reuse). Those already live on `origin/main`.
- Re-implementing coverage that already exists.
- Sibling worktrees (`fix-websocket-bypass`, `add-host-and-ip`, `fix-connection-reuse`, `waf-request-context`, `strip-hop-by-hop`, `drain-explore`, `status-header-contract`) except as something explore may note.

## Unknowns

- Whether a zero-window “never resets” `ServeHTTP` case is still worth adding given `pkg/health/tracker_test.go` already uses window 0.
- Whether CI should gain `-race`, or only a unit test that is race-safe when someone runs `go test -race`.
- Whether in-flight PRs on sibling branches add more of the remaining tests before this branch merges.

## Tensions

- The report said none of the high/critical findings were tested. On `origin/main` that is no longer true for websocket, 5xx, 3xx, health fail-open, Host/XFF, verb+body, reuse, cancel, and most config validation.
- `"Does not forward Websockets"` still exists but now requires a real handshake; it no longer locks in the forged-header bypass.
- Default verb+body behavior is now deny (400), not “ignore body and forward”; the old “ignored-verb bypass” test would be the wrong assertion.
