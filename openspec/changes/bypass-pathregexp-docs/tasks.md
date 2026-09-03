## 1. Pin unanchored contract

- [ ] 1.1 In `pkg/modsecurity/bypass_test.go`, add cases: `{ pathRegexp: /health }` skips `GET /healthz` and `GET /index.php/health`; `{ pathRegexp: ^/health$ }` still inspects `GET /healthz`; `{ pathRegexp: /health }` skips `GET /health/../index.php`.
- [ ] 1.2 Run `go test ./pkg/modsecurity -run TestPlugin_BypassRules -count=1` and confirm those cases pass on current matcher (no compile change).

## 2. Operator-facing docs

- [ ] 2.1 In `README.md` `bypassRules` comments: keep the unanchored warning; replace example `pathRegexp: /healthz` with `^/healthz$`; keep `^/admin/` as the prefix example; say match is `req.URL.Path` (percent-decoded, not slash-normalized).
- [ ] 2.2 On `BypassRule` in `pkg/modsecurity/config.go`, document unanchored `MatchString` on `req.URL.Path` and that the operator writes `^` / `$` for prefix or exact.

## 3. Prove

- [ ] 3.1 Run `go test ./pkg/modsecurity -count=1`.
- [ ] 3.2 Confirm `pkg/modsecurity/bypass.go` still wraps `(?:pattern)` only and does not insert `\A` or `$`.
