# build_testing_go_test-file-prefix

## Purpose

Keeps product Go unit test filenames prefixed with `zzz_` so they sort last and stay discoverable by the `*_test.go` suffix.

## Requirements

### Requirement: Product unit tests use a zzz_ prefix

Every product Go unit test file in the repository (root plugin package, `pkg/health`, and `pkg/modsecurity`) SHALL have a filename that starts with `zzz_` and ends with `_test.go`. The file SHALL keep the same package clause and the same `Test*` / `Benchmark*` identifiers as before the rename. Files under `.agents/` are outside this requirement.

#### Scenario: A product test file is named with the prefix

- **WHEN** a Go unit test file lives in the product tree next to the package it covers
- **THEN** its basename SHALL match `zzz_*_test.go`

#### Scenario: Go test discovery still matches the suffix

- **WHEN** `go test ./...` runs against the repository packages
- **THEN** those prefixed files SHALL still be compiled as test files because they end with `_test.go`

### Requirement: Eval fixtures are not renamed

Files under `.agents/` SHALL NOT be renamed to satisfy the product `zzz_` prefix.

#### Scenario: An agents eval test fixture is left as-is

- **WHEN** a `*_test.go` file exists only under `.agents/`
- **THEN** this change SHALL NOT rename that file
