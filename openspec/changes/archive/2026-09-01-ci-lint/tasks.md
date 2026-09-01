## 1. Linter config

- [x] 1.1 Add root `.golangci.yml` in the golangci-lint v2 schema, default enabled linters (errcheck, unused, staticcheck stay on)
- [x] 1.2 Confirm `golangci-lint config verify` (v2) accepts that file

## 2. GitHub Actions job

- [x] 2.1 Add `.github/workflows/golangci-lint.yml`: `pull_request` to `main`/`master`/`develop`, job `lint` on `ubuntu-latest`
- [x] 2.2 Steps: `actions/checkout@v6`, `actions/setup-go@v6` with `go-version: "1.24"`, `golangci/golangci-lint-action@v9` with `version: v2.13`
- [x] 2.3 Leave `only-new-issues` unset; do not add a lint step to `go.yml` or `build.yml`

## 3. First-green findings

- [x] 3.1 Run golangci-lint v2 on `./...` and record the finding list
- [x] 3.2 Fix `errcheck` on `io.Copy` in `pkg/modsecurity/serve.go` (and any test copy of that pattern)
- [x] 3.3 Remove or use unused `chunkedReader` / `newChunkedReader` in `modsecurity_test.go`; check `w.Write` errors in test handlers
- [x] 3.4 Re-run golangci-lint v2 until exit 0; run `go test ./...`

## 4. Verify

- [x] 4.1 Confirm the new workflow YAML is valid (compose/read) and the lint job is not the `go test` job
