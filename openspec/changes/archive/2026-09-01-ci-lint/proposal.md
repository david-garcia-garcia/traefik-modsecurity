## Why

Pull requests to this repo run `go build` and `go test` but never a linter. A PR can merge with unchecked errors and unused code. Adding lint to CI makes those findings a required check.

## What Changes

- Add a GitHub Actions pull-request job that runs golangci-lint and fails when findings remain.
- Commit a root `.golangci.yml` so the enabled set is explicit.
- Fix existing default-linter findings so the new check can go green (measured locally: `errcheck` on `io.Copy` / `w.Write`, unused `chunkedReader` helpers).
- Document the lint job in `knowledge/devdocs/build_ci_github.md` (later usage-doc phase).

## Capabilities

### New Capabilities

- `build_ci_github_lint`: golangci-lint runs as a required GitHub Actions check on pull requests to `main`, `master`, and `develop`.

### Modified Capabilities

None.

## Impact

- New `.github/workflows/golangci-lint.yml`
- New `.golangci.yml`
- Product/test sources that currently fail default golangci-lint (`pkg/modsecurity/serve.go`, `modsecurity_test.go`)
- `openspec/specs/domains.md` gains `build` / `ci`
- No public middleware config, API, or Traefik label change
