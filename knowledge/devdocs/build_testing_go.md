# Unit

## Overview

Go unit tests live next to the package they cover. They mock the WAF with `httptest` and do not start Docker. CI and local both use `go test ./...`.

## How to use

- Add root-plugin cases in `modsecurity_test.go` (`package traefik_modsecurity`). Add `pkg/health` cases in `pkg/health/tracker_test.go` (`package health`).
- Name production-facing tests `Test<Type>_<Behavior>` (observed: `TestModsecurity_ServeHTTP`, `TestRecordFailure_WindowReset`). Name test-only helpers with `test` or `Test` in the identifier (`newChunkedReader` in `modsecurity_test.go`).
- Drive `New` + `ServeHTTP` with `httptest.NewServer` as the WAF and a stub `next` handler. Assert status, body, and optional `ModSecurityStatusRequestHeader`.
- Run the suite with `go test -v ./...`. Coverage: `go test -v -cover`. Benchmarks exist in README as `go test -bench=. -benchmem`; I did not find a `Benchmark*` function in this tree.
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

- `modsecurity_test.go` — `ServeHTTP` pass/block, absolute-form URI, body-size cases.
- `pkg/health/tracker_test.go` — `Tracker` trip, window, backoff, concurrency.
- `.github/workflows/go.yml` / `build.yml` — `go test -v ./...`.

## Gotchas

- Root tests import `github.com/stretchr/testify/assert`. Keep that in test files only.
- Large-body exact allow/deny is covered here; `scripts/integration-tests.BodySize.Tests.ps1` only checks that near-limit bodies do not produce 5xx transport errors.
