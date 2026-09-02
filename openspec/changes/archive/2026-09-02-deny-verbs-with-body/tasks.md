## 1. Write failing tests

- [x] 1.1 Default GET with a body returns HTTP 400 and does not call `next` or the sidecar. Confirm it fails on current `ServeHTTP`.
- [x] 1.2 Default DELETE with a body returns HTTP 400.
- [x] 1.3 POST with a body is still inspected and forwarded.
- [x] 1.4 Explicit empty `denyVerbsWithBody` inspects and forwards a GET body.
- [x] 1.5 Default GET with a body still 400s when the WAF is already unhealthy.
- [x] 1.6 Prepare: nil list becomes the default; empty slice stays empty.

## 2. Replace the knobs

- [x] 2.1 Replace `IgnoreBodyForVerbs` / `IgnoreBodyForVerbsDeny` with `DenyVerbsWithBody` on `Config`, `CreateConfig`, `Prepare` (nil vs empty), and `Plugin`.
- [x] 2.2 In `ServeHTTP`, 400 on listed methods with a body before the unhealthy early-forward. Remove discard and the skip-WAF-body branch. Always read the body for the sidecar after the probe.
- [x] 2.3 Re-run the tests from §1 and confirm they pass.

## 3. Docs and integration

- [x] 3.1 README: document `denyVerbsWithBody`, default list, empty-array opt-out, and the removed keys.
- [x] 3.2 Drop `ignoreBodyForVerbsDeny=true` from test compose; keep `/force-test` as the default-deny integration surface. Update Pester names.
- [x] 3.3 Rename live spec `core_plugin_middleware_ignored-verb-body` → `core_plugin_middleware_deny-verbs-with-body`. Update middleware and health usage packets.
- [x] 3.4 Run `go test ./...`. No new Pester helper.
