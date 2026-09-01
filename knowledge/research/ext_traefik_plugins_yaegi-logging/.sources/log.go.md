---
url: https://github.com/traefik/traefik/blob/65f9d0663202b0ebf7941da0c4af0f1953525ce6/pkg/observability/logs/log.go
title: pkg/observability/logs/log.go
fetched: 2026-09-01
authority: source
ref: github.com/traefik/traefik@65f9d0663202b0ebf7941da0c4af0f1953525ce6:pkg/observability/logs/log.go
---

Tag v3.6.9. Same temp clone as middlewareyaegi.go.

`NoLevel(logger, level)` returns `logger.Hook(NewNoLevelHook(logger.GetLevel(), level))`.

`NoLevelHook.Run`:

- If `minLevel` (Traefik logger’s current level) is **greater than** the forced `level`, `e.Discard()`.
- If the event’s level is `zerolog.NoLevel` (typical for raw `io.Writer` writes into a zerolog.Logger), it stamps `level` as the forced level’s string.

Used by Yaegi plugin stdout as forced `DebugLevel` and stderr as forced `ErrorLevel`. Plugin stdout captured on that writer is dropped when Traefik `--log.level` is above DEBUG.
