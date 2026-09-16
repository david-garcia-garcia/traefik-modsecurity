## Context

See proposal.md Why. On `origin/main` there are nineteen product `*_test.go` files and none start with `zzz_`. `.github/workflows/go.yml` discovers tests with `go test -race -v ./...`. Live docs name the old basenames (`knowledge/devdocs/build_testing_go.md`, `openspec/project.md`).

## Goals / Non-Goals

**Goals:**

- `git mv` each product `*_test.go` to `zzz_<original>`.
- Refresh the two live citations so they name the new paths.
- Keep package names and `Test*` / `Benchmark*` identifiers.

**Non-Goals:**

- Renaming test functions or changing assertions.
- Rewriting CI workflows.
- Touching `.agents/` or archived OpenSpec change folders.
- Changing plugin runtime behavior.

## Decisions

- **Prefix only, no package move.** Alternative: one `zzz` test package. Rejected: breaks `_test` package locality and the usage packet’s “live next to the package” rule.
- **New spec `build_testing_go_test-file-prefix`.** FindSpecHost: do not fold into `build_ci_github_go-test` (that leaf is the race-detector PR job). Domain `testing` is already on the usage allowlist; the spec allowlist gains it at archive.
- **Update two live citations; leave archive history.** Explore assumed this. Alternative: leave docs stale. Rejected: `build_testing_go.md` Key files would name files that no longer exist.
- **Nineteen files, not eighteen.** Explore counted twelve under `pkg/modsecurity` plus seven elsewhere.

## Risks / Trade-offs

- [Out-of-tree IDE run configs pin old paths] → ignore; not found in-repo.
- [Someone adds a new `*_test.go` without the prefix later] → the spec is the contract; this change only migrates the current set.

## Migration Plan

1. `git mv` the nineteen product files.
2. Replace basename strings on the two live docs.
3. Run `go test ./...` so discovery still sees every `Test*`.

## Open Questions

None. Explore rows that stay assumed: out-of-tree scripts (ignore).
