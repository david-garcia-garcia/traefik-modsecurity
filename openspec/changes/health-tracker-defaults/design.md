## Context

See proposal.md Why. `CreateConfig` today sets threshold `1` and window `0`. `Prepare` copies the threshold default when the field is `0` and never fills the window. `pkg/health.Tracker.RecordFailure` resets only when `failureWindow > 0`. `New` leaves `lastFailureReset` as the zero time, so the first `RecordFailure` with a window always takes the reset branch.

Public keys already exist. This change only adjusts omitted-zero defaults and the window clock start.

## Goals / Non-Goals

**Goals:**

- Align `CreateConfig` and `Prepare` so omitted threshold is 5 and omitted window is 10.
- Start the tumbling window at tracker construction.
- Keep explicit `unhealthyWafFailureThreshold: 1` as trip-on-first-error.

**Non-Goals:**

- New config keys or sentinels for “window disabled”.
- Changing when `RecordFailure` is called or the fail-open vs 502 split.
- Changing the backoff default (`0` = feature off).

## Decisions

- **Both CreateConfig and Prepare use 10 for the window.** Alternative: fill only in Prepare. Rejected: every other numeric default is set in CreateConfig and copied in Prepare so the reclaim hash is stable.
- **Prepare treats window `0` as omitted.** Alternative: keep `0` as lifetime accumulation. Rejected: `omitempty` cannot distinguish omit from zero; the ticket asked for a window that always tumbles after prepare.
- **`health.New` sets `lastFailureReset = time.Now()` when `failureWindow > 0`.** Alternative: start the clock on first failure (today’s zero-time reset). Rejected: the ticket asked for a real first window from construction.
- **Threshold `0` still becomes the CreateConfig default (now 5).** Same Prepare rule as today; operators cannot request threshold 0 via YAML.

## Risks / Trade-offs

- [Operators who depended on trip-on-first-error without setting threshold] → Mitigation: document the new defaults; they can set `unhealthyWafFailureThreshold: 1`.
- [Lifetime accumulation is no longer reachable from plugin config] → Mitigation: tests may still pass window `0` into `health.New`; operators who need a long window set a large `unhealthyWafFailureWindowSecs`.
- [First window is shorter than later windows if the core has been idle] → Mitigation: that is the requested construction-time clock; it makes accidental trip harder, not easier.

## Migration Plan

- Ship as a default change. No config schema migration.
- Rollback: revert the defaults to 1 / 0.

## Open Questions

None. Explore decisions stand (`devstate/explore.md`).
