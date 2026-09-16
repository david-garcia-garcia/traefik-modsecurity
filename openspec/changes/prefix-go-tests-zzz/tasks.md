## 1. Rename product tests

- [x] 1.1 `git mv` each product `*_test.go` to `zzz_<original>` (nineteen files: root package, `pkg/health/tracker_test.go`, twelve under `pkg/modsecurity/`)
- [x] 1.2 Confirm no product `*_test.go` remains without a `zzz_` prefix
- [x] 1.3 Confirm `.agents/` (if present) was not renamed

## 2. Live citations

- [x] 2.1 Update path names on `knowledge/devdocs/build_testing_go.md`
- [x] 2.2 Update the Go tests line on `openspec/project.md`

## 3. Verify

- [x] 3.1 Run `go test ./...` so prefixed files still compile as tests
