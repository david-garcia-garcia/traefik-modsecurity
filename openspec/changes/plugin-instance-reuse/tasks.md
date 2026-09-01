## 1. Health tracker on this branch

- [ ] 1.1 Commit `pkg/health` (`tracker.go`, `tracker_test.go`) as used by the shared core (not on `origin/main`)
- [ ] 1.2 Keep `modsecurity.go` health wiring compiling until the core move (step 3)

## 2. Reclaim table

- [ ] 2.1 Add `pkg/reclaim` copied from geoblock (`table.go`, `default.go`) with this module’s import path
- [ ] 2.2 Add `pkg/reclaim` tests for Open reuse, different keys, and dispose after grace

## 3. Standalone plugin core

- [ ] 3.1 Add `pkg/modsecurity` with `Config`, `CreateConfig`, `Prepare`, `Plugin`, `NewCore`, `ForRoute`, `Close`, and current `ServeHTTP` behavior
- [ ] 3.2 `NewCore` owns `http.Client` (dialer/transport), `log.Logger`, and `health.Tracker` when backoff is enabled
- [ ] 3.3 Thin root `modsecurity.go`: alias `Config`, `CreateConfig`, `New` → `Prepare`, `reclaim.Open` keyed by `plugin:`+name+config hash, `ForRoute(next)`
- [ ] 3.4 Root MUST NOT import a cycle; `pkg/` MUST NOT import the root package

## 4. Tests

- [ ] 4.1 Unit test: two `New` with same name+config share core (client and tracker)
- [ ] 4.2 Unit test: different name or different config do not share a core
- [ ] 4.3 Unit test: after last holder and grace, a later `New` is a new core
- [ ] 4.4 Existing `modsecurity_test.go` request-path cases still pass through root `New`
- [ ] 4.5 Run Go unit tests (`run-tests` go)

## 5. Docs on apply (usage packets later)

- [ ] 5.1 Do not rewrite `knowledge/devdocs` here; `devdocsimpact` owns that after review
