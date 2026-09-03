## 1. Unit pin

- [ ] 1.1 Land `pkg/modsecurity/upstream_issue_13_test.go` (adapt only if `New` / `ForRoute` / `NewLogger` differ from the starter).
- [ ] 1.2 Confirm `go test ./pkg/modsecurity/ -count=1 -timeout 60s -run TestPlugin_UpstreamIssue13_PostFirstFactorNeverEmits405` passes.

## 2. Usage pointer

- [ ] 2.1 Add a Key files line on `knowledge/devdocs/build_testing_go.md` for `pkg/modsecurity/upstream_issue_13_test.go`.
