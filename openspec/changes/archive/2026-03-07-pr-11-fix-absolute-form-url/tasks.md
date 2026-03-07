## 1. Write Failing Test

- [x] 1.1 Add a Pester `It` block in `scripts/integration-tests.Tests.ps1` that sends a request with an absolute-form RequestURI (e.g. `http://traefik/protected/`) to the protected endpoint and asserts it is handled correctly (not a DNS/connection error)
- [x] 1.2 Run `run-tests integration` and confirm the new test **fails** (proving the bug is reproducible)

## 2. Fix URL Construction

- [x] 2.1 In `modsecurity.go` `ServeHTTP`, replace `req.RequestURI` with `req.URL.RequestURI()` in the ModSecurity forwarding URL construction

## 3. Verify Fix

- [x] 3.1 Run `run-tests integration` and confirm all integration tests pass (including the previously failing test)
