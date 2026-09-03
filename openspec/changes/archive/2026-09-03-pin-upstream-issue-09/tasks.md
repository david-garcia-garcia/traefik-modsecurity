## 1. Land regression tests

- [x] 1.1 Add `pkg/modsecurity/upstream_issue_09_test.go` (starter as-is unless APIs differ)
- [x] 1.2 Run `go test ./pkg/modsecurity/ -run TestUpstreamIssue09` and confirm all four cases pass

## 2. Usage sentence

- [x] 2.1 Add one sentence to `knowledge/devdocs/core_plugin_middleware.md` that `readInboundBody` wraps with `MaxBytesReader` only when `maxBodySizeBytes > 0`

## 3. Verify

- [x] 3.1 Run `go test ./pkg/modsecurity/` and record `localTests` on handoff
