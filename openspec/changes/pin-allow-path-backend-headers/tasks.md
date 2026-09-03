## 1. Land allow-path header coverage

- [x] 1.1 Add `pkg/modsecurity/upstream_issue_29_test.go` (starter as-is unless `New` / `ForRoute` APIs differ).
- [x] 1.2 Run `go test -count=1 -timeout 60s -v -run TestPlugin_UpstreamIssue29 ./pkg/modsecurity` and record pass.
- [x] 1.3 Add one usage sentence to `knowledge/devdocs/core_plugin_middleware.md` that allow keeps `next` response headers and does not overlay sidecar headers.

## 2. Confirm no runtime change

- [x] 2.1 Verify `pkg/modsecurity/serve.go` is unchanged versus `origin/main`.
