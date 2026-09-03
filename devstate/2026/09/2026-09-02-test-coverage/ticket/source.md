# Test coverage for report.md WAF enforcement-path gaps

Caller spec from `report.md` lines 149–161 (chat, 2026-09-02). Issue slug `test-coverage`. Dedicated worktree. Review these test gaps; some might already be fixed.

The existing tests cover body-size limiting thoroughly and log-level normalization adequately. None of them would catch any of the high or critical findings:

- **The websocket bypass is tested as a feature, not a hole.** `modsecurity_test.go` ("Does not forward Websockets") constructs a request with only `Upgrade: websocket` — no `Connection: Upgrade`, no handshake headers — and asserts the backend is reached. That test *documents and locks in* the critical bypass. A test is needed asserting that a `POST` with a forged `Upgrade: websocket` and no `Connection: upgrade` still gets inspected.
- **No WAF 5xx test.** Nothing exercises a sidecar returning 502/503/504. Such a test would immediately expose both the `"blocked"` mislabeling and the fact that the health tracker never records the failure. Similarly there is no 3xx case, so the redirect-action bypass is untested.
- **No health-tracker integration test through `ServeHTTP`.** `pkg/health/tracker_test.go` tests the tracker in isolation; nothing verifies the end-to-end fail-open path, that the default threshold of 1 trips on a single error, or that a zero failure window never resets the counter.
- **No test that the WAF sees the right request.** The mock WAF handlers only capture the URL (`TestModsecurity_AbsoluteFormRequestURI`) or the body length. No assertion on `r.Host`, `X-Forwarded-For`, or that method-specific headers survive — so the `Host` and client-IP gaps are invisible.
- **No test on the ignored-verb path.** Nothing sends a `DELETE` or `GET` with a body and asserts either that the WAF saw the body or that the backend did not. The default-config bypass would be caught by one such test.
- **No connection-reuse assertion.** A test counting distinct connections to the mock WAF across N allowed requests (via `httptest.Server`'s `ConnState` hook) would catch the undrained-body regression and would be a durable guard on the hot path.
- **No cancellation test.** Nothing asserts the WAF request is aborted when the client context is canceled.
- **Shared-request contamination weakens the existing table test.** In `TestModsecurity_ServeHTTP`, two cases pass `request: req` directly while the others use `req.Clone(...)`. The shared `req`'s body is consumed by the first of those cases, so the later one sends an empty body to the WAF, and the `X-Waf-Block` header set by the earlier case persists on the shared request into subsequent subtests — which is why the "no header should be present" assertions can pass for the wrong reason. All cases should clone.
- **`config_test.go` covers only `logLevel`.** No cases for negative numeric fields or for an unparseable/scheme-less `ModSecurityUrl`, which is why those validation gaps went unnoticed.
- **No `-race` concurrency test.** A parallel `ServeHTTP` test with mixed body sizes would guard the shared buffer pool and the `body`-aliases-pooled-buffer behavior.
