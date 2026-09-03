## 1. Range pins (acouvreur#25)

- [x] 1.1 Read `knowledge/devdocs/build_testing_integration.md` and `scripts/TestHelpers.ps1`. Use `Invoke-SafeWebRequest`, `Test-IsDrainOrigin`, and `Test-IsWhoamiOrigin`. Do not call raw `Invoke-WebRequest`.
- [x] 1.2 In `scripts/integration-tests.Tests.ps1`, strengthen the drain Range `It` (`Range: bytes=10240-` on GET `/protected`): assert not 416, status 200 or 206, and labeled-app markers (`Hostname` in the body). Skip unless `Test-IsDrainOrigin`.
- [x] 1.3 Add an `It` that expects HTTP 416 on `apache-whoami` for the same Range GET. Guard with `Test-IsWhoamiOrigin` and `$env:INTEGRATION_STACK -eq 'apache-whoami'`. Skip `nginx-whoami`.

## 2. Large-POST pin (acouvreur#23)

- [x] 2.1 Add `/large-body-test` to `Wait-ForAllServices` in `scripts/integration-tests.Tests.ps1` `BeforeAll`.
- [x] 2.2 Add a drain `It` that POSTs 16 MiB via `New-RequestBodyOfSizeBytes` to `/large-body-test` with `Invoke-SafeWebRequest` `-TimeoutSec 60`. Assert status is less than 500. Skip unless `Test-IsDrainOrigin`. Do not require 200. Do not assert whoami-stack 5xx.
- [x] 2.3 Leave `Should block a CRS SQL-injection probe in the POST body` in place and still asserting deny (status >= 400).

## 3. Verify

- [ ] 3.1 Run Pester locally if Docker is available (`./Test-Integration.ps1 -Stack apache-drain` and `-Stack apache-whoami` at least). Record pass/fail/not-run on `handoff.yaml` `localTests`.
- [x] 3.2 Confirm `.github/workflows/integration-test.yml` still runs only `./scripts/integration-tests.Tests.ps1`.
