## Purpose

Runs the repository Go unit tests with the race detector on every pull request to the protected branches so data races fail the check instead of merging unseen.

## ADDED Requirements

### Requirement: Pull-request Go tests use the race detector

A pull request targeting `main`, `master`, or `develop` SHALL run a GitHub Actions job named by `.github/workflows/go.yml` that executes `go test` with the race detector against the repository Go packages. That job SHALL fail when tests fail or when the race detector reports a race. The overlapping `build.yml` job is not required to pass `-race`.

#### Scenario: go.yml Test uses -race on a pull request to main

- **WHEN** a pull request targets `main`
- **THEN** the `go.yml` Test step SHALL run `go test` with `-race`

#### Scenario: A data race fails the check

- **WHEN** the race detector reports a race during that job
- **THEN** the job SHALL fail
