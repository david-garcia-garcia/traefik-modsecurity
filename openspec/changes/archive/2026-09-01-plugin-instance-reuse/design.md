## Context

Traefik constructs one middleware instance per route. Today `New` in `modsecurity.go` builds `net.Dialer`, `http.Transport`, `http.Client`, `log.Logger`, and optional `health.Tracker` every time. Many routes that share one middleware definition therefore open independent idle pools to the same WAF.

Geoblock solves this with `pkg/reclaim`: `Open(ctx, key, logger, create)` stores one value per key, binds each Traefik `New` context as a holder, and after the last holder plus grace calls `Close` if the value has it. The create func is `func() (any, error)` because Yaegi cannot pass the lifetime context into create.

Human decisions: reclaim key is name+config; health tracker lives on the shared core.

## Goals / Non-Goals

**Goals:**

- One plugin core per middleware name + prepared config while holders or grace remain.
- Thin per-route wrapper holds only `next` and a pointer to the core.
- Shared core owns HTTP client (dialer/transport/pool), `log.Logger`, and `health.Tracker`.
- Root package remains the Yaegi entry.
- Copy `pkg/reclaim` into this module (do not import geoblock).
- Include `pkg/health` in this change.

**Non-Goals:**

- Geoblock slog / file-log buffers.
- New Traefik config keys or default-value changes.
- Keying reclaim by config hash only.
- Per-route health trackers.

## Decisions

1. **Package split.** Core types and `ServeHTTP` live in `pkg/modsecurity`. Root aliases `Config`, implements `CreateConfig` / `New`, hashes config, calls `reclaim.Open`, then `ForRoute(next)`.
2. **Reclaim key.** `plugin:` + name + hex FNV-64a of `json.Marshal` after `Prepare`. `Prepare` applies the same defaults `CreateConfig` / `New` already apply so omitted zeros hash stably.
3. **Create signature.** `func() (any, error)` returning `*modsecurity.Plugin`. Type-assert after `Open`.
4. **Close.** Core `Close` calls `http.Client.CloseIdleConnections`. Reclaim already invokes `Close` when the incarnation ends.
5. **Health.** `NewCore` builds `health.Tracker` when `UnhealthyWafBackOffPeriodSecs > 0` and stores it on the core. Shared trip is intentional.
6. **Logger.** One `log.New(os.Stdout, "", log.LstdFlags)` on the core. Reclaim’s `Open` needs `*slog.Logger`; use a discard or stdout slog only for reclaim debug lines, not request logs.
7. **Grace.** Use reclaim `DefaultGrace` (10s) via `reclaim.Open` / `Default()`.
8. **Yaegi.** Keep reclaim non-generic (`map[string]*slot`, `any`) as in geoblock.

## Risks / Trade-offs

- **Shared `MaxConnsPerHost`** becomes one cap for all routes of that name+config. Protects the WAF; bursts may wait. Accept: current defaults stay.
- **Shared health** trips every route on that core. Accept: one WAF, one backoff.
- **Copy vs depend.** Copied `pkg/reclaim` can drift from geoblock. Accept: Yaegi must not load geoblock.
- **`pkg/health` not on main.** This PR includes it. If dest later gains a different tracker, merge will conflict — Sync at implement.

## Migration Plan

1. Land core package, reclaim, health, and thin root `New`.
2. Unit tests for same-key reuse, name isolation, config isolation, dispose+recreate.
3. Existing request-path tests keep calling root `New`.
4. No operator config migration.

## Open Questions

Answered in `devstate/explore.md`. No further design questions.
