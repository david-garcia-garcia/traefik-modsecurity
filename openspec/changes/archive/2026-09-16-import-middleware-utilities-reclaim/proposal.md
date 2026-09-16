## Why

The plugin keeps a fork of reclaim logic in `pkg/reclaim` that duplicates `github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim`, increasing maintenance cost and drift risk whenever grace, typing, or lifecycle behavior evolves upstream.

## What Changes

- Add `github.com/david-garcia-garcia/traefik-middleware-utilities` at **v1.0.3** to `go.mod` / `go.sum` and refresh `vendor/`.
- Wire root `bindPlugin` through upstream reclaim: package-scoped `*reclaim.Table`, `OpenTyped[*modsecurity.Plugin]`, and `Hooks.Close` calling `Plugin.Close()`.
- Replace test-only `reclaim.Reset` / `ResetWith` with a root-package helper on the shared table.
- Remove `pkg/reclaim/` (sources and tests).
- Do **not** import simpleredis, windowcounter, tokenbucket, backendbackoff, or iplookup in this change.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

(none — observable instance-reuse behavior, keys, grace, and dispose semantics stay as documented in `core_plugin_middleware_instance-reuse`; only the reclaim implementation source changes)

## Impact

- `go.mod`, `go.sum`, `vendor/`
- `modsecurity.go` (imports, table init, `bindPlugin`)
- `plugin_reuse_test.go`, `loglevel_test.go`
- Deletes `pkg/reclaim/*`
- `knowledge/devdocs/core_plugin_reclaim.md` updates deferred to implement / devdocsimpact
