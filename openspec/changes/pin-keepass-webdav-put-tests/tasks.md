## 1. Land coverage

- [x] 1.1 Add `pkg/modsecurity/upstream_issue_14_test.go` from the starter (adapt only if `New` / `ForRoute` / `Close` differ).
- [x] 1.2 Confirm `TestCreateConfig_PutIsNotDeniedAndKeepassSizeFitsDefaultCap` and `TestPlugin_KeepassWebDAVPutIsForwardedAndSidecar4xxCopied` pass.
- [x] 1.3 Run `go test ./pkg/modsecurity/ -count=1 -timeout 60s` and record the result.
- [x] 1.4 Confirm no production `.go` file outside tests changed.
