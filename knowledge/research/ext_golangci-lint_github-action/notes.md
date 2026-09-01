# golangci-lint GitHub Action

Official `golangci/golangci-lint-action` plus golangci-lint **v2** config file schema. Facts for adding a lint job to GitHub Actions CI. This repo has no `.golangci.yml` and no lint job today.

Pinned action release: `golangci/golangci-lint-action@v9.3.0` (`ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a`, tag date 2026-06-29). Docs site last updated 2026-09-01.

## Official action

The vendor’s GitHub Action is [`golangci/golangci-lint-action`](https://github.com/golangci/golangci-lint-action). It installs golangci-lint (default `install-mode: binary`), runs it, caches `~/.cache/golangci-lint`, and emits line annotations from the default `text` output.

Owner: [action README](https://github.com/golangci/golangci-lint-action/blob/v9.3.0/README.md). Same recommendation on [CI Installation](https://golangci-lint.run/docs/welcome/install/ci/).

Extracts: `.sources/golangci-lint-action-readme.md`, `.sources/ci-installation.md`

### Majors that matter for v2

From the README Compatibility section:

- **v9** (`v9.0.0+`) — current. Runs on **Node.js 24**. `action.yml` at v9.3.0: `using: node24`.
- **v8** — golangci-lint **≥ v2.1.0**.
- **v7** — golangci-lint **v2 only**.
- **v6** — last major aimed at v1-era examples (`version: v1.60` on the stale `master` branch). Removes `annotations` and the old default `github-actions` output format.
- **v4+** — requires an explicit `actions/setup-go` step first. `skip-go-installation` is gone.

The default branch is **`main`**. `master` still serves older v6 + golangci-lint v1.60 examples. Follow `main` / `@v9`.

Owner: [action README — Compatibility](https://github.com/golangci/golangci-lint-action/blob/v9.3.0/README.md). Runtime: `golangci/golangci-lint-action@ba0d7d2:action.yml`.

Extracts: `.sources/golangci-lint-action-readme.md`, `.sources/action.yml.md`

### Job shape

README: run lint in a **job separate** from `go test` so jobs can run in parallel. Minimal steps in the v9 example:

1. `actions/checkout` (example uses `@v6`; this repo’s Go workflow uses `@v4`)
2. `actions/setup-go` with a Go version (example uses `@v6` and `go-version: stable`; compatibility text still names `@v5` as the required setup step)
3. `golangci/golangci-lint-action@v9` with `version: v2.12`

Permissions in the example: `contents: read`. Add `pull-requests: read` when using `only-new-issues`. Annotations need the default `text` format **and** either `actions/setup-go` in the job or `problem-matchers: true`. The v9 README no longer lists `checks: write`.

Owner: [action README — How to use / Annotations](https://github.com/golangci/golangci-lint-action/blob/v9.3.0/README.md).

## Action inputs (v9.3.0)

Owner: `golangci/golangci-lint-action@ba0d7d2:action.yml` and the same README Options section.

| Input | Default | Fact |
| --- | --- | --- |
| `version` | (unset) | Binary mode: `v2.3`, `v2.3.4`, or `latest`. Pin a release; CI docs forbid floating on `linters.default: all` and recommend a **specific** golangci-lint version. |
| `version-file` | — | `.golangci-lint-version` or `.tool-versions`. Binary mode only. |
| `install-mode` | `binary` | `binary` \| `goinstall` \| `none`. `goinstall` is not recommended. |
| `install-only` | `false` | Install, do not run. |
| `verify` | `true` | If a config file is found, validate it against the JSON Schema **for that golangci-lint version**. No config → skip. |
| `args` | `""` | Extra CLI flags. Config defaults to repo-root `.golangci.yml`. Override with `--config=`. **Must use `=`** (`--config=path`); the action splits `args` on spaces. |
| `only-new-issues` | `false` | PR/push: GitHub API diff + `--new-from-patch`. `merge_group`: `--new-from-rev` and `checkout` `fetch-depth: 0`. Needs `github-token` (defaults to `github.token`). |
| `working-directory` | project root | Monorepos. |
| `skip-cache` / `skip-save-cache` | `false` | Analysis cache under `~/.cache/golangci-lint`. Go module cache is `setup-go`’s job. |
| `cache-invalidation-interval` | `7` | Days. `<= 0` always invalidates. |
| `problem-matchers` | `false` | Embedded matchers; only the default `text` format. |
| `experimental` | `""` | `automatic-module-directories`, `no-run-logs-group`. |

Extract: `.sources/action.yml.md`

## Pin the linter version

[CI Installation](https://golangci-lint.run/docs/welcome/install/ci/): reproducible CI — a new upstream linter or `linters.default: all` can fail every build at once. Install a **specific** version from the releases page. The Action can take a minor (`v2.12`) and resolve the latest patch.

[FAQ](https://golangci-lint.run/docs/welcome/faq/): fail the build on a non-zero exit. golangci-lint is built for the same Go minors as the Go team (two latest). It supports analyzing Go **≤** the Go version used to compile that binary. New Go is not automatic.

This repo’s workflows pin **Go 1.24**. Implementers must pick a golangci-lint v2 release compiled with Go ≥ 1.24 (confirm with `golangci-lint version`).

Extracts: `.sources/ci-installation.md`, `.sources/faq.md`

## v2 config file schema

Owner: [Configuration File](https://golangci-lint.run/docs/configuration/file/).

Search order from the working directory: `.golangci.yml`, `.golangci.yaml`, `.golangci.toml`, `.golangci.json`, then parents up to root, then `$HOME`. `-v` prints which file was used. Linter-specific settings exist **only** in the file, not the CLI.

Required version field — only legal value:

```yaml
version: "2"
```

Top-level keys (all optional except `version` when a file exists): `version`, `linters`, `formatters`, `issues`, `output`, `run`, `severity`.

Validate with the published JSON Schema (`golangci.jsonschema.json` on that page) or `golangci-lint config verify`. The Action’s `verify: true` does that when a file is present.

[Configuration](https://golangci-lint.run/docs/configuration/): CLI wins over the file for the same bool/string/int. Slice options (enabled linters, etc.) are **combined**.

Extracts: `.sources/configuration-file.md`, `.sources/configuration.md`

### `linters`

- `default`: `standard` (Default set on the linters page) \| `all` \| `none` \| `fast`. File-page default: `standard`.
- `enable` / `disable`: named linters.
- `settings`: per-linter options (v1 `linters-settings`).
- `exclusions`: `generated` (`strict` \| `lax` \| `disable`; default `strict`), `presets` (default **empty** — not on unless listed), `rules`, `paths`, `paths-except`. Exclusions do **not** skip `typecheck`.

`staticcheck` is a current linter (autofix). v2 **merged** v1 `gosimple` and `stylecheck` into `staticcheck`.

Owner: [Configuration File — linters](https://golangci-lint.run/docs/configuration/file/), [Linters](https://golangci-lint.run/docs/linters/), [Migration guide](https://golangci-lint.run/docs/product/migration-guide/).

Extracts: `.sources/configuration-file.md`, `.sources/linters.md`, `.sources/migration-guide.md`

### `formatters`

Separate from linters. `gci`, `gofmt`, `gofumpt`, `goimports` (and others) live here, not under `linters.enable`. Default `enable: []` (standard Go formatting).

### `run`

- `timeout`: default **0 (disabled)** in v2 (v1 had a timeout).
- `tests`: default `true`.
- `issues-exit-code`: default `1`.
- `go`: default from `go.mod`, else `GOVERSION`, else `1.22`.
- `modules-download-mode`: `readonly` \| `vendor` \| `mod`.
- `relative-path-mode`: default `cfg`.

### `issues`

`max-issues-per-linter` default 50; `max-same-issues` default 3; `new` / `new-from-merge-base` / `new-from-rev` / `new-from-patch` for “new code only.” FAQ prefers `--new-from-merge-base=main` or `--new-from-rev=HEAD~1` over `--new` in CI that creates unstaged files. `--whole-files` if an issue line is outside the diff hunk.

## v1 → v2 (this repo has no file)

This tree has **no** `.golangci.yml`, so there is nothing to `golangci-lint migrate`. A new file must be **v2** (`version: "2"`). Do not copy a v1 skeleton.

Owner: [Migration guide](https://golangci-lint.run/docs/product/migration-guide/).

If someone did bring a v1 file: `golangci-lint migrate` rewrites it, backs up to `*.bck.*`, and does not keep comments. Notable renames: `linters.disable-all` → `linters.default: none`; `linters.enable-all` → `linters.default: all`; `linters-settings` → `linters.settings` + `formatters.settings`; formatters leave `linters.enable`.

Extract: `.sources/migration-guide.md`

## `//nolint` (existing `staticcheck` directive)

Owner: [False Positives](https://golangci-lint.run/docs/linters/false-positives/).

`//nolint` is a **directive**, not a free comment. No spaces: `//nolint:staticcheck` is valid; `// nolint:staticcheck` and `//nolint: staticcheck` are not.

- Inline (end of line): that line only.
- Start of line: the following block (function, `var` group).
- Immediately above `package`: the file.
- All linters: `//nolint:all`.
- Optional justification: `//nolint:gocyclo // reason`.

`typecheck` cannot be disabled or nolinted — it is compiler errors, not a linter.

This repo already has `//nolint:staticcheck` in `pkg/reclaim/table_test.go`. That spelling matches the official syntax. It only suppresses `staticcheck` if that linter is enabled (`standard` includes it as a named linter on the current linters catalog).

Extract: `.sources/false-positives.md`
