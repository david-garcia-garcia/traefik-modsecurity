## 1. Rename product tests

- [ ] 1.1 `git mv` each product `*_test.go` to `zzz_<original>` (nineteen files: root package, `pkg/health/tracker_test.go`, twelve under `pkg/modsecurity/`)
- [ ] 1.2 Confirm no product `*_test.go` remains without a `zzz_` prefix
- [ ] 1.3 Confirm `.agents/` (if present) was not renamed

## 2. Live citations

- [ ] 2.1 Update path names on `knowledge/devdocs/build_testing_go.md`
- [ ] 2.2 Update the Go tests line on `openspec/project.md`

## 3. Verify

- [ ] 3.1 Run `go test ./...` so prefixed files still compile as tests
