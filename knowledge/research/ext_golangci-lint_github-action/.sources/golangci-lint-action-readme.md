---
url: https://github.com/golangci/golangci-lint-action/blob/v9.3.0/README.md
title: golangci-lint-action README
fetched: 2026-09-01
authority: official
ref: golangci/golangci-lint-action@ba0d7d2:README.md
---

Official GitHub Action for golangci-lint from its authors. Default branch is `main` (not `master`).

Recommend a job separate from `go test` so jobs run in parallel.

v9 simple example:

```yaml
permissions:
  contents: read
jobs:
  golangci:
    name: lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version: stable
      - name: golangci-lint
        uses: golangci/golangci-lint-action@v9
        with:
          version: v2.12
```

Compatibility:

- `v9.0.0` requires Node.js `node24`.
- `v8.0.0` works with golangci-lint >= `v2.1.0`.
- `v7.0.0` supports golangci-lint v2 only.
- `v6.0.0+` removes `annotations` and the default `github-actions` output format.
- `v4.0.0+` requires explicit `actions/setup-go` first (docs still show `uses: actions/setup-go@v5`). `skip-go-installation` removed.

`version` (binary mode): `v2.3`, `v2.3.4`, or `latest`.

`verify` defaults true. Validates a detected config against the JSON Schema for the installed golangci-lint version. No config file → skip.

`args`: default config is repo-root `.golangci.yml`. Change with `--config=`. Flags must use `=` because the action splits `args` on spaces.

`only-new-issues`: PR uses GitHub API + `--new-from-patch`; `merge_group` uses `--new-from-rev` and needs `fetch-depth: 0` on checkout.

Annotations: GitHub parses `text` output. Need `contents: read`. `pull-requests: read` for `only-new-issues`. Use default `text` format plus `actions/setup-go` or `problem-matchers: true`. v9 README does not require `checks: write`.

Cache: `~/.cache/golangci-lint`. Key includes runner OS, working directory, 7-day interval, `go.mod` hash. Go module cache is `actions/setup-go`.
