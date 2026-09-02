# Proposal: deny-verbs-with-body

## Why

Silent discard of GET/DELETE bodies is undiagnosable: the client gets HTTP 200, the application sees an empty body, and ModSecurity never logged the payload. `ignoreBodyForVerbs` mixed two jobs (skip WAF inspection, and hide or reject leftover bytes). Operators need one visible contract: listed methods must not have a body.

## What Changes

- Replace `ignoreBodyForVerbs` and `ignoreBodyForVerbsDeny` with one array, `denyVerbsWithBody` (Go `DenyVerbsWithBody`).
- Default remains `HEAD`, `GET`, `DELETE`, `OPTIONS`, `TRACE`, `CONNECT`. A body on those methods is HTTP 400, including when the WAF is already unhealthy.
- Omitted / nil applies that default. An explicit empty array denies nothing.
- Methods not on the list send the body to ModSecurity and to `next` (no skip list, no silent drain).
- Rename live spec `core_plugin_middleware_ignored-verb-body` to `core_plugin_middleware_deny-verbs-with-body` (removed unit).

## Capabilities

### New Capabilities

None. Same family; the old leaf names a unit this change deletes.

### Modified Capabilities

- `core_plugin_middleware_deny-verbs-with-body`: 400 on listed methods that carry a body; inspect and forward otherwise.

## Impact

- Breaking public config: YAML keys `ignoreBodyForVerbs` and `ignoreBodyForVerbsDeny` are removed. Leftover keys are ignored by JSON decode.
- Default GET/DELETE-with-body becomes HTTP 400 instead of reaching the backend (on `main`) or being silently drained (this branch).
- Elasticsearch-style GET-with-body: remove `GET` from `denyVerbsWithBody`.
- Integration `/force-test` no longer needs `ignoreBodyForVerbsDeny=true`; the default list already 400s.
