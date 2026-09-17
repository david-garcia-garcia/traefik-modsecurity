# Explore
IssueKey: 2026-09-16-upstream-health-probe

## Concepts

```
  inbound request
        │
        ▼
  gate.Allow(ctx, "waf")     ← replaces IsUnhealthy peek
        │
        ├─ denied ── skip sidecar ── failMode open|close
        │
        └─ admitted
              │
              ▼
         httpClient.Do
              │
              ├─ inbound Canceled ── no Report ── 502
              ├─ transport / sidecar 5xx ── Report(false) ── failMode
              └─ sidecar < 500 ── Report(true) ── block or next
```

Local `pkg/health.Tracker` is a tumbling-window failure counter plus a fixed cooldown. Upstream `backendbackoff.Gate` (utilities v1.0.3) is a CLOSED / OPEN / HALF-OPEN credit gate: `Allow` admits or denies, `Report` records only admitted attempts, half-open allows one probe, cooldown is `BaseCooldown * 2^n` capped at `MaxCooldown`.

Owner: `github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de:backendbackoff/gate.go`, `backendbackoff/allow.go`. Local owner today: `pkg/health/tracker.go`, `pkg/modsecurity/serve.go`.

Baseline: `go test -count=1 ./pkg/health/ ./pkg/modsecurity/ -run "Health|Unhealthy|RecordFailure|InboundCancel|threshold"` passed on this worktree (0.797s / 3.404s). No product bug to reproduce — this is a replacement.

## Decisions

- Delete `pkg/health`. Wire `backendbackoff.New` on the Plugin when `unhealthyWafBackOffPeriodSecs > 0`. Call `Allow` / `Report` on the request path. Do not wrap the gate as `RecordFailure` / `IsUnhealthy` — `Allow` has side effects (half-open probe).
- Stay on `traefik-middleware-utilities v1.0.3` (latest tag; `backendbackoff` is in that tree).
- One Gate per Plugin core, one static key `waf`. The core is already shared per middleware name + prepared config (`modsecurity.go` `pluginKey`).
- Map `unhealthyWafFailureThreshold` → `TripFailures`. Map `unhealthyWafBackOffPeriodSecs` → `BaseCooldown`. `MaxCooldown` equals base unless the new max knob is set (fixed backoff by default). `Jitter` 0 so cooldown stays deterministic. `TTL` stays the packaged 60s.
- Keep `unhealthyWafFailureWindowSecs` on `Config` (Prepare default 10, reject negative, reclaim hash) but do not pass it to the gate. Credit + idle TTL replace the tumbling window.
- Add `unhealthyWafFailureRatio` (0 → packaged 0.30) and `unhealthyWafMaxBackOffPeriodSecs` (0 → same as base).
- `Report(true)` on an admitted sidecar status below 500 (WAF answered). `Report(false)` on transport errors except inbound `Canceled`, and on sidecar 5xx. Do not `Report` a denied `Allow`.
- Drop `Plugin.IsUnhealthy`. Tests observe sidecar hit counts and `modSecurityStatusRequestHeader`.
- Plugin tests own trip / skip / one probe after cooldown / cancel / 5xx / block-as-success. Do not retest gate math; upstream already has `gate_test.go`.

## Open questions

- Q: How do the three existing unhealthy JSON fields map onto `backendbackoff.Config`?
  Rank: bounded asked — Desired on `requirement.md` names the mapping; existing call sites enumerated (3 public fields + Prepare/hash in `pkg/modsecurity/config.go`, `modsecurity.go` `pluginConfigHash`, compose labels, `openspec/specs/core_plugin_middleware_health-tracker`)
  Decision: resolved — threshold → TripFailures; backoff seconds → BaseCooldown and, unless the max knob is set, MaxCooldown; window stays on Config for hash/YAML and is not passed to the gate; Jitter 0; TTL packaged 60s.
  By: explore

- Q: Which extra public knobs does the plugin need beyond the three existing fields?
  Rank: additive asked — caller asked for extra knobs so the plugin can keep backoff behavior or expose what the gate needs
  Decision: resolved — add `unhealthyWafFailureRatio` (0 means packaged 0.30) and `unhealthyWafMaxBackOffPeriodSecs` (0 means equal to base, fixed cooldown). Do not expose Jitter or TTL.
  By: explore

- Q: Single static gate key versus a per-route key when one Plugin core serves many Traefik routes?
  Rank: additive asked — listed under Unknowns on `requirement.md`
  Decision: resolved — one key `waf` on the Plugin's Gate. Routes that share the core already share one trip (`core_plugin_reclaim.md`, `plugin_reuse_test.go`).
  By: explore

- Q: Delete `pkg/health` or keep a Tracker-shaped adapter over the gate?
  Rank: structural asked — Desired on `requirement.md` says remove the custom tracker and wire through upstream
  Decision: resolved — delete `pkg/health`. `Allow` / `Report` live in `pkg/modsecurity/serve.go`. An adapter that peeks with `Allow` would consume the half-open probe.
  By: explore

- Q: Keep `Plugin.IsUnhealthy` after the swap?
  Rank: bounded incidental — 6 production/test call sites enumerated (`plugin.go`, `serve.go`, `serve_test.go`, `plugin_reuse_test.go`, `modsecurity_test.go`, `deny_verbs_with_body_test.go`)
  Decision: resolved — remove it. Tests assert sidecar calls and the status-request header.
  By: explore

- Q: Report success on sidecar 2xx/3xx/4xx, or only record failures like today's tracker?
  Rank: bounded incidental — `serve.go` outcomes enumerated (ok, blocked, error, 5xx, inbound cancel)
  Decision: resolved — `Report(true)` when the admitted sidecar returns below 500; `Report(false)` on transport error except inbound cancel and on 5xx. The gate requires a Report on every admitted attempt.
  By: explore

- Q: After `Allow` admitted the attempt, does inbound `Canceled` Report?
  Rank: bounded asked — `openspec/specs/core_plugin_middleware_health-failures` and Desired (preserve cancel)
  Decision: resolved — do not Report; keep empty HTTP 502. Same as `recordWafFailure` skipping cancel today.
  By: explore

- Q: Does this change need a utilities module newer than v1.0.3?
  Rank: additive asked — Out of scope on `requirement.md` unless explore proves a newer tag is required
  Decision: resolved — no. Latest release is v1.0.3; `backendbackoff` is in that tag (`950b08de`).
  By: explore
