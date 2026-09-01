# Modules

## Overview

This module is `github.com/david-garcia-garcia/traefik-modsecurity` (`go.mod`, `go 1.21`). Direct requires and their transitives are committed under `vendor/`.

## How to use

- Add or bump a module with `go get`, then refresh `vendor/` and `vendor/modules.txt` so Yaegi/CI see the same tree.
- Keep production `modsecurity.go` on the standard library plus `pkg/` imports. The only direct require in `go.mod` today is `github.com/stretchr/testify v1.9.0` (used from `*_test.go`).
- Import testify as `github.com/stretchr/testify/assert` in tests. Do not add it to production files.
- After a dep change, confirm `vendor/modules.txt` lists the new module; that file is the vendor inventory (`# github.com/stretchr/testify v1.9.0` and three transitives).

## Key files

- `go.mod` — module path, Go version, requires.
- `vendor/modules.txt` — vendored package list.
- `vendor/` — source snapshots (`testify`, `go-spew`, `go-difflib`, `yaml.v3`).

## Gotchas

- CI workflows install Go 1.24 (`.github/workflows/go.yml`, `build.yml`) while `go.mod` says `go 1.21`. Do not raise the module version without checking both workflows.
- I did not find a `replace` directive or a private module proxy in `go.mod`.
