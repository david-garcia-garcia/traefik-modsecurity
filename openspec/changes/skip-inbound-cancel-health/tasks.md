## 1. Write failing tests

- [ ] 1.1 Add a unit test that cancels the inbound request context while a mock WAF blocks, with health tracker threshold 1, and asserts the WAF is not marked unhealthy
- [ ] 1.2 Add a unit test that lets `timeoutMillis` fire while the inbound context stays live, with health tracker threshold 1, and asserts the WAF is marked unhealthy
- [ ] 1.3 Add a unit test that fires the inbound context deadline while a mock WAF blocks, with health tracker threshold 1, and asserts the WAF is not marked unhealthy
- [ ] 1.4 Run those tests and confirm the cancel and inbound-deadline cases fail on current `RecordFailure` for every `Do` error

## 2. Skip inbound-done on the Do error path

- [ ] 2.1 In `pkg/modsecurity/serve.go`, record a health failure only when the inbound request context is still live
- [ ] 2.2 Re-run the new tests and confirm they pass
- [ ] 2.3 Re-run the existing Go tests that cover `ServeHTTP` and health (`serve_test.go`, `modsecurity_test.go`, `pkg/health`) and confirm they still pass

## 3. Usage notes

- [ ] 3.1 Update `knowledge/devdocs/core_plugin_health.md` so `RecordFailure` is not documented as running on every `Do` error
- [ ] 3.2 Update `knowledge/devdocs/core_plugin_middleware.md` Gotchas so inbound cancel is not recorded as a WAF health failure
