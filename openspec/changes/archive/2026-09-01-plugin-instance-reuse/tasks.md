## 1. Health tracker on this branch

- [x] 1.1 Commit `pkg/health` (`tracker.go`, `tracker_test.go`) as used by the shared core (not on `origin/main`)
- [x] 1.2 Keep `modsecurity.go` health wiring compiling until the core move (step 3)

## 2. Reclaim table

- [x] 2.1 Add `pkg/reclaim` copied from geoblock (`table.go`, `default.go`) with this module’s import path
- [x] 2.2 Add `pkg/reclaim` tests for Open reuse, different keys, and dispose after grace

## 3. Standalone plugin core

- [x] 3.1 Add `pkg/modsecurity` with `Config`, `CreateConfig`, `Prepare`, `Plugin`, `NewCore`, `ForRoute`, `Close`, and current `ServeHTTP` behavior
- [x] 3.2 `NewCore` owns `http.Client` (dialer/transport), `log.Logger`, and `health.Tracker` when backoff is enabled
- [x] 3.3 Thin root `modsecurity.go`: alias `Config`, `CreateConfig`, `New` → `Prepare`, `reclaim.Open` keyed by `plugin:`+name+config hash, `ForRoute(next)`
- [x] 3.4 Root MUST NOT import a cycle; `pkg/` MUST NOT import the root package

## 4. Tests

- [x] 4.1 Unit test: two `New` with same name+config share core (client and tracker)
- [x] 4.2 Unit test: different name or different config do not share a core
- [x] 4.3 Unit test: after last holder and grace, a later `New` is a new core
- [x] 4.4 Existing `modsecurity_test.go` request-path cases still pass through root `New`
- [x] 4.5 Run Go unit tests (`run-tests` go)

## 5. Docs on apply (usage packets later)

- [x] 5.1 Do not rewrite `knowledge/devdocs` here; `devdocsimpact` owns that after review
