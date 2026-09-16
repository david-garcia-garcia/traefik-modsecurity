# Requirement
IssueKey: 2026-09-16-upstream-health-probe

## Problem
The ModSecurity plugin keeps a bespoke WAF health tracker in-tree while the shared `traefik-middleware-utilities` module already ships a Yaegi-safe backend backoff gate with probe semantics and extensive tests. Duplicating that logic in `pkg/health` increases drift and leaves half-open recovery untested here.

## Current (code)
- `pkg/health/tracker.go` — `Tracker` with tumbling-window `RecordFailure`, fixed `backoffTimeout`, and `IsUnhealthy` auto-recovery.
- `pkg/health/tracker_test.go` — unit tests for window, threshold, and backoff expiry on the local tracker.
- `pkg/modsecurity/plugin.go` — builds `health.New(...)` when `unhealthyWafBackOffPeriodSecs > 0`; exposes `IsUnhealthy()`.
- `pkg/modsecurity/config.go` — JSON knobs `unhealthyWafBackOffPeriodSecs`, `unhealthyWafFailureThreshold`, `unhealthyWafFailureWindowSecs` (defaults and negative validation).
- `pkg/modsecurity/serve.go` — skips sidecar when unhealthy; `recordWafFailure` calls `RecordFailure`; ignores client cancel for health.
- `pkg/modsecurity/serve_test.go` — integration-style tests for unreachable sidecar and unhealthy skip paths.
- `go.mod` — requires `traefik-middleware-utilities v1.0.3`; no `backendbackoff` import yet.
- `knowledge/research/ext_traefik-middleware-utilities_backendbackoff/notes.md` — upstream `Allow`/`Report` gate at v1.0.3 (not in vendor tree yet).

## Desired
Remove the custom `pkg/health` tracker and wire the plugin through upstream `backendbackoff` from `traefik-middleware-utilities`, preserving operator-visible WAF backoff behavior or documenting new knobs the upstream gate needs. Replace or extend tests so probe, trip, recovery, and fail-open paths are thoroughly covered (unit plus plugin-level).

## Affected
- `pkg/health/` (delete or replace)
- `pkg/modsecurity/plugin.go`, `serve.go`, `config.go`
- `pkg/modsecurity/serve_test.go` and any dedicated health tests
- `go.mod` / `vendor/` (add `backendbackoff` subpackage)
- `knowledge/devdocs/` packets that mention `pkg/health` or health tracker wiring

## Out of scope
- Importing simpleredis, windowcounter, tokenbucket, or iplookup from upstream.
- Changing deny-verbs, bypass rules, reclaim wiring, or fail-open vs fail-close policy except where required to call `Allow`/`Report` correctly.
- Bumping the utilities module beyond v1.0.3 unless explore proves backendbackoff fixes require a newer tag.

## Unknowns
- Exact mapping from the three existing unhealthy JSON fields to `backendbackoff.Config` (ratio/window vs credit model; fixed backoff vs exponential cooldown).
- Whether operators need new public fields (FailureRatio, Jitter, TTL, MaxCooldown) or hidden defaults are acceptable.
- Single static gate key vs per-route keys when one Plugin core serves many Traefik routes.

## Tensions
- Ticket text says “health probe in pkg/health”; upstream name is `backendbackoff` with different semantics (half-open probe, credit budget) — behavior may shift unless config mapping is chosen carefully in explore.
