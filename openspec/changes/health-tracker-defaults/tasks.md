## 1. Write failing test

- [ ] 1.1 Add a `Prepare` test that sets only `ModSecurityUrl` and `UnhealthyWafBackOffPeriodSecs` and asserts threshold becomes 5 and window becomes 10 (fails on current defaults).
- [ ] 1.2 Add a `health.New` test that a window is set and the first `RecordFailure` does not reset solely because `lastFailureReset` was zero (fails until `New` initializes the clock).
- [ ] 1.3 Run the new tests and confirm they fail for the current code.

## 2. Defaults and window clock

- [ ] 2.1 Set `CreateConfig` `UnhealthyWafFailureThreshold` to 5 and `UnhealthyWafFailureWindowSecs` to 10.
- [ ] 2.2 In `Prepare`, when `UnhealthyWafFailureWindowSecs` is 0, fill it from `CreateConfig` (same pattern as the other numeric fields).
- [ ] 2.3 In `health.New`, when `failureWindow > 0`, set `lastFailureReset` to `time.Now()`.
- [ ] 2.4 Re-run the tests from 1.x and the existing `pkg/health` and `pkg/modsecurity` unit tests.

## 3. Docs

- [ ] 3.1 Document the new threshold and window defaults in `README.md` next to `unhealthyWafBackOffPeriodSecs`.
- [ ] 3.2 Update `knowledge/devdocs/core_plugin_health.md` gotchas so they no longer say threshold default 1 / window 0 never resets.

## 4. Verify

- [ ] 4.1 Run `go test ./pkg/health/ ./pkg/modsecurity/`.
