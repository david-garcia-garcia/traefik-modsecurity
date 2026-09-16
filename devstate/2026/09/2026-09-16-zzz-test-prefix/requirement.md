# Requirement
IssueKey: 2026-09-16-zzz-test-prefix

## Problem
Product Go tests use default `*_test.go` names. The requester wants every product test file renamed with a `zzz_` filename prefix (for example `serve_test.go` → `zzz_serve_test.go`) without touching eval fixtures under `.agents/`.

## Current (code)
At `origin/main` (`97fb2ff`), eighteen product `*_test.go` files exist with no `zzz_` prefix: `modsecurity_test.go`, `loglevel_test.go`, `failmode_test.go`, `plugin_reuse_test.go`, `reclaim_test.go`, `deny_verbs_with_body_test.go`, `pkg/health/tracker_test.go`, and eleven under `pkg/modsecurity/` (`serve_test.go`, `config_test.go`, `bypass_test.go`, `body_test.go`, `body_bench_test.go`, `body_pool_put_test.go`, and `upstream_issue_05_test.go` through `upstream_issue_29_test.go`). Go discovers tests by `*_test.go` suffix; filenames do not change package or `Test*` symbol names. `.agents/**` eval `*_test.go` fixtures: not found in this checkout (path excluded from product tree if present elsewhere). Docs and archived OpenSpec changes cite old basenames (for example `openspec/project.md` mentions `modsecurity_test.go`); no CI script enumerates specific test filenames.

## Desired
Rename each product `*_test.go` file to `zzz_<original>` (keep the `_test.go` suffix). Leave `.agents/` eval fixtures unchanged. Branch base is `main`, not `master`.

## Affected
All eighteen product test paths above; `git mv` renames only. Optional doc path updates if a phase chooses to refresh stale basename mentions (not required by the ticket).

## Out of scope
Renaming test functions, changing test logic, adding OpenSpec unless a later phase requires it, renaming non-Go tests, renaming anything under `.agents/`, changing `DestBranch` name in git remotes.

## Unknowns
Whether any out-of-tree tooling (IDE run configs, local scripts) hard-codes old test file paths — not found in-repo.

## Tensions
Caller asked for dest `master`; repository default and `origin/HEAD` is `main` — prepare uses `main`.
