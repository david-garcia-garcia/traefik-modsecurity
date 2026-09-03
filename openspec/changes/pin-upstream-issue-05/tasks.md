## 1. Land coverage

- [ ] 1.1 Add `pkg/modsecurity/upstream_issue_05_test.go` (starter file; adapt helpers only if `New` / `ForRoute` / `CreateConfig` fail to compile)
- [ ] 1.2 Confirm product `ServeHTTP` has no `recover` and was not edited

## 2. Verify

- [ ] 2.1 Run `go test ./pkg/modsecurity -count=1 -timeout 60s -run TestPlugin_UpstreamIssue05`
- [ ] 2.2 Run `go test ./pkg/modsecurity -count=1` so neighbors still pass
