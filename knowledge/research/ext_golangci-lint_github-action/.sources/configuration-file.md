---
url: https://golangci-lint.run/docs/configuration/file/
title: Configuration File
fetched: 2026-09-01
authority: official
---

Looks for config from the current working directory, in order: `.golangci.yml`, `.golangci.yaml`, `.golangci.toml`, `.golangci.json`. Then walks from the first analyzed path up to the filesystem root, then the home directory. `-v` shows which file was used.

File options match CLI options. Per-linter settings exist only in the file.

Reference dump of every option: `.golangci.reference.yml` (not a recommended config).

JSON Schema: `golangci.jsonschema.json`.

v2 file skeleton:

```yaml
version: "2"
linters: { }
formatters: { }
issues: { }
output: { }
run: { }
severity: { }
```

`version` — only possible value is `"2"`.

`linters.default`: `standard` | `all` | `none` | `fast`. Default `standard` (the Default set on the linters page).

`linters.settings` holds per-linter options.

`linters.exclusions` does not skip `typecheck`. `generated`: `strict` | `lax` | `disable` (default `strict`). `presets` default `[]`. Named presets: `comments`, `std-error-handling`, `common-false-positives`, `legacy`.

`formatters.enable` default `[]` (standard Go formatting). Includes `gci`, `gofmt`, `gofumpt`, `goimports`, `golines`, `swaggo`.

`issues.max-issues-per-linter` default 50. `max-same-issues` default 3. `new`, `new-from-merge-base`, `new-from-rev`, `new-from-patch`, `whole-files`, `fix`.

`run.timeout` default `0` (disabled). `relative-path-mode` default `cfg`. `issues-exit-code` default `1`. `tests` default `true`. `go` default: `go.mod`, then `GOVERSION`, then `1.22`. `modules-download-mode`: `readonly` | `vendor` | `mod`.

`output.formats.text` is the default format (colors, line number, linter name).
