## 1. Write failing test

- [ ] 1.1 In `modsecurity_test.go` `TestModsecurity_ServeHTTP`, change the 403 and 406 header expectations from `blocked` to `403` and `406`, and confirm those cases fail
- [ ] 1.2 Add a unit test that a sidecar `httpClient.Do` failure with `unhealthyWafBackOffPeriodSecs` 0 sets the status header to `error`
- [ ] 1.3 Add a unit test that a MaxBytesError 413 sets the status header to `toolarge` (not `blocked`)

## 2. Header values and log levels

- [ ] 2.1 On the sidecar `>= 400` path in `pkg/modsecurity/serve.go`, write `strconv.Itoa(resp.StatusCode)` instead of `blocked`
- [ ] 2.2 On both MaxBytesError branches, write `toolarge` instead of `blocked` and log at Warn
- [ ] 2.3 On every `httpClient.Do` error, set the status header to `error` when the name is configured, then keep the existing tracker / 502 / fail-open flow
- [ ] 2.4 Downgrade the ignore-verb-has-body log from Error to Warn

## 3. Docs and integration asserts

- [ ] 3.1 Add `toolarge` to the README `modSecurityStatusRequestHeader` value list and keep status-code / `error` / `unhealthy` / `cannotforward`
- [ ] 3.2 In `scripts/integration-tests.BodySize.Tests.ps1`, change the two access-log asserts from `blocked` to `toolarge` (reuse `Get-TraefikAccessLogEntries` / `Get-LastAccessLogEntryForPath`)
- [ ] 3.3 Run `TestModsecurity_ServeHTTP` and the new unit tests; they SHALL pass
