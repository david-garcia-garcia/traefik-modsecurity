## Why

`main` has no test that a 228565-byte WebDAV PUT (acouvreur/traefik-modsecurity-plugin#14) is allowed by `denyVerbsWithBody`, fits the 8 MiB plugin cap, is forwarded to the sidecar, and that a sidecar 400/413 is copied as a security block. Without that pin, a later deny-list or cap change could recreate the plugin half of that issue with no failing test.

## What Changes

- Add `pkg/modsecurity/upstream_issue_14_test.go` (starter coverage, already passing on this tree).
- Add spec scenarios on existing middleware leaves for PUT + this size and sidecar 400/413 copy.
- No `Config` field, no `ServeHTTP` change, no plugin knob that shadows `SecRequestBodyNoFilesLimit`.
- No README or demo compose edit (docs P2 is out of scope).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_deny-verbs-with-body`: methods not on the default list already inspect and forward; add a PUT / 228565-byte WebDAV scenario so that verb and size stay pinned.
- `core_plugin_middleware_sidecar-response`: 3xx/4xx already copy as a security block; add sidecar 400 and 413 on that PUT so the copy is not mistaken for a local deny-verb 400 or local oversize 413.

## Impact

- Tests: `pkg/modsecurity/upstream_issue_14_test.go` only.
- Runtime: none.
- Sidecar / CRS-docker `MODSEC_REQ_BODY_NOFILES_LIMIT`: unchanged; tests stub 400/413.
