## Context

See proposal.md Why. Today `pkg/modsecurity/plugin.go` builds `health.New` when backoff seconds are greater than zero, `serve.go` peeks `IsUnhealthy` then `RecordFailure` after transport errors and sidecar 5xx, and `pluginConfigHash` JSON-marshals the whole Config. Utilities v1.0.3 already required by `go.mod` exports `backendbackoff` (`New`, `Allow`, `Report`, `Close`). Reclaim already keeps one Plugin core per name+config.

## Goals / Non-Goals

**Goals:**
- Replace the local tracker with one Gate on the Plugin.
- Keep enablement as `unhealthyWafBackOffPeriodSecs > 0`.
- Map existing knobs plus the two new ones without wrapping Allow as a peek.
- Prove trip, skip, one probe, cancel, 5xx, and status-below-500 at plugin level.

**Non-Goals:**
- Bumping utilities past v1.0.3.
- Importing other utilities packages.
- Changing failMode, deny-verbs, bypass, or reclaim keys.
- Exposing Jitter or TTL.
- Re-testing gate credit math (upstream `gate_test.go`).

## Decisions

- **Call Allow/Report in ServeHTTP, delete pkg/health.** Alternative: a Tracker adapter. Rejected because Allow starts the half-open probe; a peek would consume it.
- **One key `waf` on the Plugin's Gate.** Alternative: per-route keys. Rejected — the core is already the share unit (`pluginKey`).
- **Jitter 0, MaxCooldown = base unless the max knob is set.** Alternative: packaged jitter 0.10 and Max 10s. Rejected — operators today have a fixed skip; tests need a stable cooldown.
- **Keep window on Config.** Alternative: drop the JSON field. Rejected — compose files and `pluginConfigHash` still send it; Prepare keeps default 10.
- **Do not Report inbound Canceled.** Alternative: Report(false). Rejected — health-failures forbids treating client disconnect as a WAF outage.
- **Report(true) on sidecar status below 500.** Alternative: failures only. Rejected — the gate requires an outcome on every admitted attempt; a 403 means the WAF answered.
- **Close the Gate from Plugin.Close.** Same incarnation as idle HTTP close. Do not Close on reclaim Sleep (none today).
- **Vendor `backendbackoff` via the existing module.** `go mod vendor` after confirming v1.0.3.

## Risks / Trade-offs

- [Operators who relied on the tumbling window] → Document that credit + successes replace the window; keep the YAML field so deploys do not fail.
- [Half-open sends one request into a still-down sidecar] → That is the commissioned probe; failMode still applies to that probe's failure.
- [Allow on a canceled inbound ctx returns ctx.Err] → Treat like construction failure: 502, no Report, no trip.
- [Plugin.IsUnhealthy tests break] → Rewrite to sidecar hit counts and the status-request header.

## Migration Plan

1. Land on the ticket branch; existing `unhealthyWafBackOffPeriodSecs` / threshold YAML keep working.
2. Operators who set only the window see no hash change; trip no longer resets on that window.
3. Rollback is revert of the PR; `pkg/health` returns.

## Open Questions

None. Product choices live on `devstate/explore.md`.
