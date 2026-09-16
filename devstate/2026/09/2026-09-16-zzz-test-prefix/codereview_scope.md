# Scope

| Ticket | Demand | In diff | Status |
|--------|--------|---------|--------|
| 2026-09-16-zzz-test-prefix | Rename each product `*_test.go` file to `zzz_<original>` (keep the `_test.go` suffix) | `git mv` of 19 product tests to `zzz_*_test.go` (root, `pkg/health`, `pkg/modsecurity`) | OK |
| 2026-09-16-zzz-test-prefix | Leave `.agents/` eval fixtures unchanged | no `.agents/` hunks | OK |
| 2026-09-16-zzz-test-prefix | Branch base is `main`, not `master` | pinned apply vs `origin/main` (`97fb2ff`) | OK |

none.
