## 1. Write failing test

- [x] 1.1 Add a root-package unit test that sends GET with a non-empty body under default `CreateConfig`, asserts the mock WAF body is empty, and asserts `next` reads an empty body. Confirm it fails on current `ServeHTTP`.
- [x] 1.2 Add the DELETE sibling of 1.1 (same assertions). Confirm it fails.
- [x] 1.3 Add a POST allow-path control: WAF and `next` both receive the body.
- [x] 1.4 Add a deny=true GET-with-body case: HTTP 400 and `next` not called.
- [x] 1.5 Add GET-with-body while the WAF is already unhealthy: `next` reads empty; sidecar is not called. Deny=true still 400s.

## 2. Discard on the ignore path

- [x] 2.1 In `pkg/modsecurity/serve.go`, when the method is on `ignoreBodyForVerbs` and deny did not reject, consume `req.Body`, set `req.Body` to `http.NoBody`, set `ContentLength` to 0, and delete `Content-Length`.
- [x] 2.2 Run deny and discard before the unhealthy early-forward so fail-open does not deliver an ignored-verb body.
- [x] 2.3 Re-run the tests from §1 and confirm they pass.

## 3. Docs

- [x] 3.1 Update README `ignoreBodyForVerbs` so it states the body is discarded and not forwarded, and that ModSecurity still does not inspect it.
- [x] 3.2 Keep `ignoreBodyForVerbsDeny` default documented as false.

## 4. Verification

- [x] 4.1 Run `go test ./...` and report pass/fail. No new Pester case: `knowledge/devdocs/build_testing_integration.md` already covers deny=true via `whoami-force-test`; this change is visible to `next` in a unit test.
