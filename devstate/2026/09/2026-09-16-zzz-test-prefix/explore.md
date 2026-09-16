# Explore

## Concepts

- Product Go unit test file: a `*_test.go` next to the package it covers. The toolchain matches the suffix; the basename prefix is not a package or `Test*` name.
- `zzz_` prefix: a filename prefix only (`serve_test.go` → `zzz_serve_test.go`). Package clause and test function names stay.
- Live citation: a current-tree doc that names those basenames. Observed: `knowledge/devdocs/build_testing_go.md` (Key files / How to use) and `openspec/project.md` (Go tests line). `openspec/changes/archive/**` is history.
- Dest: `origin/main` (`97fb2ff`). Caller said `master`; that ref is not on origin.

```
origin/main filenames
        │
        ▼
  git mv  *_test.go  →  zzz_*_test.go
        │
        ▼
  go test ./... still matches the suffix
```

## Decisions

- Rename every product `*_test.go` on this checkout: **19** files (requirement counted 18 and “eleven under `pkg/modsecurity/`”; the tree has twelve there plus seven at root/`pkg/health`).
- One `git mv` per file to `zzz_<original>`. Keep the `_test.go` suffix. Do not rename `Test*` symbols or change test bodies.
- Leave `.agents/` fixtures untouched (none in this worktree’s product tree).
- CI does not pin basenames: `.github/workflows/go.yml` Test step is `go test -race -v ./...`.
- When files move, update live citations on `knowledge/devdocs/build_testing_go.md` and `openspec/project.md`. Leave archived change folders as written.
- No `knowledge/research/` write: Go’s `*_test.go` discovery is the existing convention; no vendor unknown.
- Dest stays `main`.

## Open questions

- Q: Should live docs that cite old test basenames be updated in this change?
  Rank: additive incidental — string updates on existing usage/docs; requirement Affected calls them optional, not a Desired SHALL
  Decision: resolved — updated `knowledge/devdocs/build_testing_go.md` and `openspec/project.md`; archive folders unchanged.
  By: implement

- Q: Does any in-repo runner hard-code old test filenames?
  Rank: additive asked — Desired is a rename; a pinned basename would break CI or scripts
  Decision: resolved — `.github/workflows/go.yml` runs `go test -race -v ./...`; no `_test.go` hits under `.github/`.
  By: explore

- Q: Do out-of-tree IDE or local scripts hard-code the old paths?
  Rank: additive asked — requirement Unknowns names this; criterion fallback is in-repo only
  Decision: assumed — ignore out-of-tree; not found in this repo.
  By: explore

- Q: Should this change add an OpenSpec spec for the `zzz_` filename convention?
  Rank: additive incidental — Out of scope says adding OpenSpec unless a later phase requires it
  Decision: resolved — FindSpecHost `new` `build_testing_go_test-file-prefix` (do not fold into `build_ci_github_go-test`); change `prefix-go-tests-zzz`.
  By: propose
