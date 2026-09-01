## Context

See proposal.md — Why. Request/health use `*log.Logger` on unfiltered stdout (`pkg/modsecurity/plugin.go`). Reclaim requires `*slog.Logger` and today gets a text handler on `io.Discard` (`modsecurity.go`). `reclaim.Open` runs before `modsecurity.New` returns, so the logger must exist in `bindPlugin` first.

Explore decisions: `devstate/explore.md`.

## Goals / Non-Goals

**Goals:**

- One `*slog.Logger` pointer for Plugin, health tracker, and reclaim.
- Prepare-time validate/normalize of `logLevel`.
- Existing reclaim Debug message names stay (`reclaim_put`, …).

**Non-Goals:**

- File output, `logPath`, `logFormat`, buffers.
- Changing reclaim’s message set or grace behavior.
- A new Pester that scrapes Traefik stdout (compose may set `logLevel=debug` so that scrape is possible).

## Decisions

1. **slog, not std `log`**
   - Why: reclaim already takes `*slog.Logger`; one type is the one-logger ask.
   - Alternative: keep `*log.Logger` and wrap slog — two types, two sinks.

2. **Build in `bindPlugin`, store on Plugin**
   - `newPluginLogger(cfg)` (or equivalent) after `Prepare`: `slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parsed})`.
   - Pass that pointer to `reclaim.Open` and `modsecurity.New`.
   - Alternative: Plugin.New builds its own and Open gets a second instance at the same level — two loggers, same config. Rejected.

3. **Accepted values and errors**
   - `debug|info|warn|error`, case-insensitive, store lowercase.
   - Empty → `info` in `CreateConfig` and `Prepare`.
   - Unknown → `Prepare` error.
   - Alternative: silent fallback to `info` — hides operator typos.

4. **Level map**
   - error: ServeHTTP failures + health trip.
   - info: backoff expired.
   - debug: reclaim messages already at Debug.
   - No per-request “still unhealthy” line.

5. **Health tracker API**
   - `New(..., logger *slog.Logger)`. Tests switch from `log.Default()` to `slog.Default()` or a recording handler.

6. **Tests**
   - Prepare: default, normalize, reject.
   - `pluginConfigHash` differs when only `logLevel` differs.
   - Reclaim unit tests already gate on handler Enabled; plugin tests assert Open is not given Discard.
   - `docker-compose.test.yml`: `logLevel=debug` on at least one middleware.

## Risks / Trade-offs

- [Yaegi slog] → stdlib `log/slog` is in the Go version this plugin already uses; no new import path beyond stdlib.
- [Debug flood if default is wrong] → default `info`; reclaim stays Debug.
- [Two cores when only case differs] → Prepare lowercases before hash.

## Migration Plan

- New optional field. Existing deployments omit it and get `info`. Request/health lines that always printed become error/info and still appear at default `info` (failures and backoff expiry). That is slightly quieter (no change to those messages’ visibility at info) and reclaim stays hidden until `debug`.
- Rollback: omit `logLevel` or revert the plugin version.

## Open Questions

None. Ticket questions live on `devstate/explore.md`.
