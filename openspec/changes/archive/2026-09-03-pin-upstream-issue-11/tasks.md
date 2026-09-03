## 1. Land pin test

- [x] 1.1 Commit `pkg/modsecurity/upstream_issue_11_test.go` (adapt only if `New` / `ForRoute` / `CreateConfig` differ from origin/main).
- [x] 1.2 Confirm the three cases: plugin cap → 413 `blocked` no sidecar; sidecar 413 → 413 `blocked`; sidecar 500 → 502 `error`; never client 500.

## 2. Verify

- [x] 2.1 `go test ./pkg/modsecurity/ ./ -count=1 -timeout 120s -run "TestPlugin_UpstreamIssue11_LargeNonFileBodyNeverReturns500"`
- [x] 2.2 `openspec validate pin-upstream-issue-11 --strict` if the CLI supports it; otherwise `openspec status --change pin-upstream-issue-11`
