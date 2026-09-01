## 1. Write failing test

- [ ] 1.1 Add `pkg/modsecurity/config_test.go` cases that expect `Prepare` to reject `TimeoutMillis=-1` and `MaxBodySizeBytes=-1`
- [ ] 1.2 Add cases that expect `Prepare` to reject `ModSecurityUrl` values `waf:80` and `http://waf:80/modsec`
- [ ] 1.3 Add a case that expects `Prepare` to accept `http://waf:80/` and store `http://waf:80`
- [ ] 1.4 Run `go test ./pkg/modsecurity/ -run TestPrepare_ -count=1` and confirm the new cases fail

## 2. Prepare validation

- [ ] 2.1 In `Prepare`, reject each numeric `Config` field when it is less than 0 (after the existing `== 0` defaults)
- [ ] 2.2 Parse `ModSecurityUrl` with `url.Parse`; require absolute `http`/`https`, non-empty host, path empty or `/`, no query/userinfo/fragment; trim a trailing slash and store the result
- [ ] 2.3 Re-run `go test ./pkg/modsecurity/ -run TestPrepare_ -count=1` and confirm the new cases pass

## 3. Regression

- [ ] 3.1 Run `go test ./...` (unit tests only; no new Pester cases — helpers in `scripts/TestHelpers.ps1` unused) and confirm existing `http://waf` / `httptest.Server.URL` callers still pass
