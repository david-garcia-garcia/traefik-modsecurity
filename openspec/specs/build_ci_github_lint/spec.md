# build_ci_github_lint

## Purpose

Runs a Go linter on every pull request to the protected branches so findings fail the check instead of merging unseen.

## Requirements

### Requirement: Pull-request lint check

A pull request targeting `main`, `master`, or `develop` SHALL run a lint job that executes golangci-lint against the repository Go packages. The job SHALL use the committed root linter configuration. The job SHALL fail when golangci-lint reports any finding. The job SHALL NOT be the same job that runs `go test`.

#### Scenario: Lint runs on a pull request to main

- **WHEN** a pull request targets `main`
- **THEN** GitHub Actions SHALL start a lint job that runs golangci-lint

#### Scenario: Findings fail the check

- **WHEN** golangci-lint reports one or more findings
- **THEN** the lint job SHALL fail

#### Scenario: Clean tree passes

- **WHEN** golangci-lint reports no findings
- **THEN** the lint job SHALL succeed

### Requirement: Shared root configuration

The repository SHALL contain a root `.golangci.yml` that golangci-lint v2 can validate. CI and a local `golangci-lint run` SHALL read that same file. The configuration SHALL keep the default enabled linters that include errcheck, unused, and staticcheck.

#### Scenario: Config is at the repository root

- **WHEN** golangci-lint runs without a `--config` override
- **THEN** it SHALL load `.golangci.yml` from the repository root
