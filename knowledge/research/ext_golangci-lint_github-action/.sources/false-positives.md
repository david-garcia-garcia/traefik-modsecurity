---
url: https://golangci-lint.run/docs/linters/false-positives/
title: False Positives
fetched: 2026-09-01
authority: official
---

Per-linter settings can turn off rules. `staticcheck` example: `linters.settings.staticcheck.checks` with `-SA1000`.

Path/text/source excludes: `linters.exclusions.rules` and `linters.exclusions.paths`.

`//nolint` is a directive (`//(line |extern |export |[a-z0-9]+:[a-z0-9])`). No spaces between `//`, `nolint`, `:`, and the linter name.

Valid: `//nolint:staticcheck`. Invalid: `// nolint`, `//nolint :xxx`, `//nolint: xxx`.

- End of line: that line.
- Start of line: following block.
- Above `package`: whole file.
- All linters: `//nolint:all`.
- Reason on the same line: `//nolint:gocyclo // reason`.

Presets (`comments`, `common-false-positives`, `legacy`, `std-error-handling`) are opt-in under `linters.exclusions.presets`. The `comments` preset includes staticcheck `ST1000|ST1020|ST1021|ST1022`.
