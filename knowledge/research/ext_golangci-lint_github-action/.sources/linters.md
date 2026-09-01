---
url: https://golangci-lint.run/docs/linters/
title: Linters
fetched: 2026-09-01
authority: official
---

`golangci-lint help linters` lists supported linters and default enablement. `golangci-lint linters` lists what the current config enables.

`staticcheck` is a current linter (“the set of rules from staticcheck”, autofix).

`typecheck` is not in this catalog as an enable/disable linter; see FAQ.

Filter chips on the page include Default, New, Autofix, Fast, Slow, Deprecated. The configuration file’s `linters.default: standard` points at this Default set (`#all-linters`).
