# GitHub

## Overview

Pull requests to `main`, `master`, or `develop` run Go build/test, golangci-lint, and a Compose+Pester job. A tag matching `v*.*.*` creates a GitHub Release. This plugin is not compiled into a shipped binary in CI — Traefik loads the module.

## How to use

- Put PR Go checks in `.github/workflows/go.yml` and `.github/workflows/build.yml`. Both run `go build` on `ubuntu-latest` with Go 1.24. `go.yml` Test is `go test -race -v ./...`. `build.yml` Test stays `go test -v ./...`.
- Put PR lint in `.github/workflows/golangci-lint.yml` (its own job, not a step on `go.yml`). That job runs `golangci/golangci-lint-action@v9` with golangci-lint v2.13 and Go 1.24. The Action reads root `.golangci.yml`.
- Run the same lint locally with `golangci-lint run ./...` (v2) from the repo root. Do not pass `--config` unless you are pointing at that file.
- Put Compose+Pester checks in `.github/workflows/integration-test.yml`. That job matrix starts each drain stack (`apache-drain`, `nginx-drain`), waits on Traefik API / bypass / protected, installs bombardier, then runs `./scripts/integration-tests.Tests.ps1` only.
- Cut a release by pushing a `v*.*.*` tag. `.github/workflows/release.yml` calls `softprops/action-gh-release` with generated notes. It does not run `go build` or lint.

## Key files

- `.github/workflows/go.yml` — PR: `go build -v ./...` then `go test -race -v ./...`.
- `.github/workflows/build.yml` — PR: `go build -v .` then `go test -v ./...`.
- `.github/workflows/golangci-lint.yml` — PR: dedicated `lint` job, golangci-lint v2.13.
- `.golangci.yml` — golangci-lint v2 config (`version: "2"`, `linters.default: standard`).
- `.github/workflows/integration-test.yml` — PR: two-stack drain matrix, Compose up, Pester (including bombardier benches), logs on failure, `down -v`.
- `.github/workflows/release.yml` — tag `v*.*.*` → GitHub Release.

## Gotchas

- `go.yml` and `build.yml` overlap. A PR to `main`/`master`/`develop` runs both Go jobs plus `lint`. Only `go.yml` passes `-race`.
- `golangci-lint.yml` leaves `only-new-issues` unset, so the whole tree must pass, not only new lines.
- `integration-test.yml` hard-codes `./scripts/integration-tests.Tests.ps1`. It does not run `scripts/integration-tests.BodySize.Tests.ps1`.
- Tag release is `release.yml` only. There is no semantic-release or Makefile in this repo.
