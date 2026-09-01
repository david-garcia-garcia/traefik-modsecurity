---
url: https://github.com/golangci/golangci-lint-action/blob/ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a/action.yml
title: golangci-lint-action action.yml
fetched: 2026-09-01
authority: source
ref: golangci/golangci-lint-action@ba0d7d2:action.yml
---

Name: "Golangci-lint". Description: official action with line-attached annotations, caching, and parallel execution.

`runs.using`: `node24`. `main`: `dist/run/index.js`. `post`: `dist/post_run/index.js`.

Inputs (defaults in quotes when set):

- `version` — optional. Binary: `v2.3`, `v2.3.4`, or `latest`. `goinstall`: patch, `latest`, or commit hash. `none`: ignored.
- `version-file` — optional. Relative to repo root or `working-directory`. Supports `.golangci-lint-version` and `.tool-versions`. Binary mode only.
- `install-mode` — default `binary`. `binary` | `goinstall` | `none`.
- `install-only` — default `false`.
- `working-directory` — optional. Default project root.
- `github-token` — default `${{ github.token }}`. Used to fetch a PR patch for `only-new-issues`.
- `verify` — default `true`. Verify config against JSON Schema.
- `only-new-issues` — default `false`.
- `args` — default empty. golangci-lint CLI arguments.
- `skip-cache` — default `false`. Disables all caching; wins over other cache inputs.
- `skip-save-cache` — default `false`. Restore allowed, save skipped.
- `cache-invalidation-interval` — default `7` (days).
- `problem-matchers` — default `false`.
- `debug` — optional. Comma-separated: `cache`, `clean`.
- `experimental` — optional. Comma-separated: `automatic-module-directories`, `no-run-logs-group`.
