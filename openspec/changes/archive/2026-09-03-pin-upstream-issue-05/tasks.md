## 1. Land coverage

- [x] 1.1 Add `pkg/modsecurity/upstream_issue_05_test.go` (starter file; adapt helpers only if `New` / `ForRoute` / `CreateConfig` fail to compile)
- [x] 1.2 Confirm product `ServeHTTP` has no `recover` and was not edited

## 2. Verify

- [x] 2.1 Run `go test ./pkg/modsecurity -count=1 -timeout 60s -run TestPlugin_UpstreamIssue05`
- [x] 2.2 Run `go test ./pkg/modsecurity -count=1` so neighbors still pass
