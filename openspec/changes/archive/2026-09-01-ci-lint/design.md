## Context

See proposal.md — Why. Today `.github/workflows/go.yml` and `build.yml` both run `go build` + `go test` on PRs; neither runs a linter. `knowledge/devdocs/build_ci_github.md` documents that overlap. Official golangci-lint Action README says keep lint in a job separate from `go test` and recommends `.github/workflows/golangci-lint.yml`.

Local golangci-lint v1.63.4 already fails this tree (`errcheck` on `io.Copy` / `w.Write`, unused `chunkedReader` in `modsecurity_test.go`). CI will pin golangci-lint v2; implement measures v2 and fixes those findings.

## Goals / Non-Goals

**Goals:**

- A dedicated PR lint job that fails on any golangci-lint finding
- One committed v2 config shared by CI and local runs
- Tree green under that config after this change

**Non-Goals:**

- Merging or deleting `go.yml` / `build.yml`
- Lint on tag/release
- `only-new-issues` (would hide existing findings)
- Makefile lint target
- PowerShell / YAML lint
- Multi-OS lint matrix

## Decisions

1. **Official Action, own workflow**
   - Use `golangci/golangci-lint-action@v9` with `version: v2.13` (README simple example).
   - New file `.github/workflows/golangci-lint.yml`, one job named `lint`.
   - Alternative rejected: a step on `go.yml` — serializes lint with test and touches the overlapping pair we are not consolidating.

2. **Triggers and toolchain**
   - `on.pull_request.branches: [main, master, develop]` — same as `go.yml`.
   - `ubuntu-latest`, `actions/checkout@v6`, `actions/setup-go@v6`, `go-version: "1.24"` (match this repo, not `stable`).
   - Alternative rejected: `go-version: stable` — drifts from the 1.24 pin in existing jobs.

3. **Fail the whole tree**
   - Leave `only-new-issues` unset (default false).
   - Alternative rejected: only-new-issues — ticket is add lint to CI, not warn on new lines.

4. **Config and first-green**
   - Commit `.golangci.yml` in the golangci-lint v2 schema. Keep default enabled linters (errcheck, unused, staticcheck).
   - Fix current findings: check `io.Copy` / `Write` errors; remove unused `chunkedReader` helpers (or use them). Do not disable errcheck.
   - Alternative rejected: empty config + ignore failures — would not make lint a real check.

## Risks / Trade-offs

- [v2 default set differs from local v1.63.4] → Implement runs golangci-lint v2 before push; treat that list as the fix set.
- [Action v9 needs Node 24 on the runner] → `ubuntu-latest` on GitHub already provides it; if the job cannot start, pin a runner image that has Node 24.
- [Default linters flag more than the v1 sample] → Fix findings in this change; do not widen scope to style-only linters beyond defaults.

## Migration Plan

- Land the workflow + config + source fixes on `ci-linter`. After merge, every PR to `main`/`master`/`develop` gets the lint check. No rollback of plugin runtime; disable by deleting the workflow file if needed.

## Open Questions

None that change specs or tasks. Explore assumed rows stand.
