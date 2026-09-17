# Unit

## Language

**Product unit test file**:
A `*_test.go` beside the package it covers in the product tree (root plugin package, `pkg/modsecurity`). Its basename starts with `zzz_` and still ends with `_test.go`.
_Avoid_: eval fixture (files under `.agents/`); test package (`zzz` is not a package name)

**zzz_ prefix**:
A filename prefix only on a product unit test file. The package clause and `Test*` / `Benchmark*` identifiers stay.
_Avoid_: `Test` function prefix; package name

## Overview

Go unit tests live next to the package they cover. Product test filenames use a `zzz_` prefix (`zzz_*_test.go`). They mock the WAF with `httptest` and do not start Docker. Local default is `go test ./...`. The `go.yml` PR Test job uses `go test -race -v ./...`.

## How to use

- Name a new product test file `zzz_<area>_test.go`. Keep the `_test.go` suffix so `go test ./...` discovers it. Do not prefix or rename files under `.agents/`.
- Add root-plugin cases in `zzz_modsecurity_test.go` (`package traefik_modsecurity`). Add Plugin WAF backoff cases in `pkg/modsecurity/zzz_serve_test.go` (`package modsecurity`).
- Name production-facing tests `Test<Type>_<Behavior>` (observed: `TestModsecurity_ServeHTTP`, `TestPlugin_FailOpenUnhealthySkipCallsNext`). Name test-only helpers with `test` or `Test` in the identifier (`newChunkedReader` in `zzz_modsecurity_test.go`).
- Drive `New` + `ServeHTTP` with `httptest.NewServer` as the WAF and a stub `next` handler. Assert status, body, and optional `ModSecurityStatusRequestHeader`.
- Run the suite with `go test -v ./...`. Match CI’s race check with `go test -race -v ./...`. Coverage: `go test -v -cover`. Benchmarks exist in README as `go test -bench=. -benchmem`; I did not find a `Benchmark*` function in this tree.
- Agents: `openspec/project.md` says delegate runs to the `run-tests` agent (`run-tests go` or `run-tests go <TestFunctionName>`).

## Pattern snippet

```go
func TestModsecurity_ServeHTTP(t *testing.T) {
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer waf.Close()

	cfg := CreateConfig()
	cfg.ModSecurityUrl = waf.URL
	handler, err := New(context.Background(), next, cfg, "test")
	assert.NoError(t, err)
	handler.ServeHTTP(rec, req)
}
```

## Key files

- `zzz_modsecurity_test.go` — `ServeHTTP` pass/block, absolute-form URI, body-size cases.
- `pkg/modsecurity/zzz_upstream_issue_13_test.go` — Authelia-shaped `POST /api/firstfactor`: allow is not 405; sidecar 405 is copied.
- `pkg/modsecurity/zzz_serve_test.go` — WAF backoff trip, skip, probe, cancel, 5xx.
- `zzz_test_file_prefix_test.go` — walks the module and fails a product `*_test.go` whose basename lacks `zzz_`.
- `.github/workflows/go.yml` — `go test -race -v ./...`. `build.yml` — `go test -v ./...`.

## Gotchas

- A new product `*_test.go` without the `zzz_` prefix fails `TestProductGoTestFiles_HaveZzzPrefix`. Files under `.agents/`, `.git`, and `vendor` are skipped.
- Root tests import `github.com/stretchr/testify/assert`. Keep that in test files only.
- Large-body exact allow/deny is covered here; `scripts/integration-tests.BodySize.Tests.ps1` only checks that near-limit bodies do not produce 5xx transport errors.
