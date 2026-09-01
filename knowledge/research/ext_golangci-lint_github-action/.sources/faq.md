---
url: https://golangci-lint.run/docs/welcome/faq/
title: FAQ
fetched: 2026-09-01
authority: official
---

Supported Go versions: the same as the Go team (the two latest minor versions). golangci-lint supports Go versions lower or equal to the Go version used to compile it. New Go is not automatic; some linters may need adaptation.

CI: run golangci-lint and fail the build on a non-zero exit.

`typecheck` is compiler errors labeled as reports, not a linter. It cannot be disabled or ignored. Code under analysis must compile.

Large existing issue sets: do not fix everything. Use `--new-from-merge-base=main` or `--new-from-rev=HEAD~1`. `--new` is unsafe in CI that creates unstaged files. If an issue line is outside the diff hunk, add `--whole-files`.
