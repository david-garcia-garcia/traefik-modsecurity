# Requirement
IssueKey: 2026-09-16-import-middleware-utilities

## Problem
The ModSecurity Traefik plugin keeps a process-wide plugin instance across Traefik reloads using an in-tree `pkg/reclaim` table. Maintaining a fork of that logic here duplicates the shared `traefik-middleware-utilities` module and increases drift risk.

## Current (code)
- `pkg/reclaim/` — local `Table`, `Open`, `Default`, `Reset` / `ResetWith` (`pkg/reclaim/table.go`, `pkg/reclaim/default.go`); tests in `pkg/reclaim/table_test.go`.
- `modsecurity.go` — `bindPlugin` calls `reclaim.Open` with key `plugin:<name>:<hash>` and expects `*modsecurity.Plugin` (`modsecurity.go`).
- `pkg/modsecurity/config.go` — `Prepare` normalizes config so the reclaim hash stays stable.
- `plugin_reuse_test.go`, `loglevel_test.go` — integration tests call `reclaim.Reset` / `ResetWith`.
- `go.mod` — no dependency on `github.com/david-garcia-garcia/traefik-middleware-utilities`.

## Desired
Add `traefik-middleware-utilities` as a Go module dependency and route all reclaim usage through its `reclaim` package instead of `pkg/reclaim`. Remove the in-tree reclaim implementation once imports and tests pass. Do not import or reimplement the other upstream packages (simpleredis, windowcounter, tokenbucket, backendbackoff, iplookup) in this ticket.

## Affected
- `go.mod` / `go.sum`
- `modsecurity.go` (import path)
- `plugin_reuse_test.go`, `loglevel_test.go` (test helpers / reset API)
- Delete `pkg/reclaim/` (source and tests)

## Out of scope
- Adopting simpleredis, windowcounter, tokenbucket, backendbackoff, or iplookup from upstream.
- Rewriting ModSecurity plugin behavior beyond reclaim wiring.
- Changing Traefik/Yaegi plugin surface or public config schema for unrelated reasons.

## Unknowns
- Published semver/tag of `traefik-middleware-utilities` to pin in `go.mod`.
- Whether upstream `reclaim` API matches local `Open(ctx, key, logger, create)` and test-only `Reset` / `ResetWith` without adapter code.

## Tensions
- none
