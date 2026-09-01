---
url: https://golangci-lint.run/docs/product/migration-guide/
title: Migration guide
fetched: 2026-09-01
authority: official
---

`golangci-lint migrate` converts a v1 config to v2. Comments are not migrated. Deprecated/unknown v1 fields are not migrated. Writes a backup `<name>.bck.<ext>`.

v2 has no timeout by default; migrate ignores existing `run.timeout`. Stats are on by default in v2.

`version` property was added. Required form:

```yaml
version: "2"
```

`linters.disable-all` → `linters.default: none`. `linters.enable-all` → `linters.default: all`.

Formatters `gci`, `gofmt`, `gofumpt`, `goimports` moved out of `linters.enable` into `formatters`.

`gosimple`, `stylecheck`, and `staticcheck` merged into `staticcheck`.

`linters-settings` split into `linters.settings` and `formatters.settings`.

`typecheck` is not a linter and cannot be enabled or disabled.

`run.timeout` is disabled by default (`0`).
