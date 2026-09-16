## 1. Module and vendor

- [ ] 1.1 Add `github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.3` to `go.mod` / `go.sum`
- [ ] 1.2 Run `go mod vendor` and confirm `vendor/modules.txt` lists the new module and transitives

## 2. Production reclaim wiring

- [ ] 2.1 Add lazy-init package-scoped `*reclaim.Table` in `modsecurity.go` using upstream `New` + `DefaultGrace`
- [ ] 2.2 Rewrite `bindPlugin` to call `OpenTyped[*modsecurity.Plugin]` with `Hooks.Close` invoking `Plugin.Close()` and `EnforceCloseBeforeOpen: false`
- [ ] 2.3 Remove all imports of `github.com/david-garcia-garcia/traefik-modsecurity/pkg/reclaim`

## 3. Tests

- [ ] 3.1 Add root-package test helper wrapping `(*Table).Reset()` with grace restore on `t.Cleanup`
- [ ] 3.2 Update `plugin_reuse_test.go` and `loglevel_test.go` to use the helper instead of `reclaim.Reset` / `ResetWith`
- [ ] 3.3 Delete `pkg/reclaim/` (sources and tests)
- [ ] 3.4 Run `go test -count=1 ./...` and confirm PASS

## 4. Verification

- [ ] 4.1 Run reclaim-related Pester integration tests (if tagged) without fixture changes
- [ ] 4.2 Update `knowledge/devdocs/core_plugin_reclaim.md` during devdocsimpact (import path, table scope, test helper)
