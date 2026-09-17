## Why

Product Go unit tests use unprefixed `*_test.go` names. The requester wants every product test file to sort and filter under a `zzz_` prefix without changing package names, `Test*` symbols, or eval fixtures.

## What Changes

- Rename each product `*_test.go` to `zzz_<original>` (keep the `_test.go` suffix). Nineteen files on `main`.
- Update live path citations on `knowledge/devdocs/build_testing_go.md` and `openspec/project.md`.
- Leave `.agents/` fixtures and `openspec/changes/archive/**` unchanged.
- Do not change test logic, `Test*` names, CI command lines, or plugin runtime behavior.

## Capabilities

### New Capabilities

- `build_testing_go_test-file-prefix`: product Go unit test files SHALL use a `zzz_` filename prefix while remaining `*_test.go` so `go test ./...` still discovers them.

### Modified Capabilities

None.

## Impact

- Nineteen product test paths (root package, `pkg/health`, `pkg/modsecurity`).
- Live usage lines in `knowledge/devdocs/build_testing_go.md` and the Go tests line in `openspec/project.md`.
- No config, deploy, ServeHTTP, or CI workflow command change (`.github/workflows/go.yml` already runs `go test -race -v ./...`).
