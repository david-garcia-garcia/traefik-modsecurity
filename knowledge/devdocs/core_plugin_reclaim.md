# Reclaim table

## Language

**Reclaim table**:
A process-wide map that keeps one value per key while any bound Traefik `New` context is live or grace has not elapsed.
_Avoid_: cache, pool (the HTTP transport pool is a different object)

## Overview

`pkg/reclaim` stores one plugin core per middleware name+config. `Open` creates or reuses the value and watches `ctx`. After the last holder and grace, it calls `Close` if the value has it.

## How to use

- Call `reclaim.Open(ctx, key, logger, create)` from root `New` with the Plugin logger (`modsecurity.NewLogger(name, cfg)`). `create` is `func() (any, error)` with no context argument (Yaegi).
- Key as `plugin:` + name + hex hash of prepared config.
- Implement `Close()` on the stored value to drop idle HTTP connections.
- Use `reclaim.Reset` / `ResetWith` only in tests.

## Pattern snippet

```go
stored, err := reclaim.Open(ctx, key, logger, func() (any, error) {
	return modsecurity.New(name, cfg)
})
```

## Key files

- `pkg/reclaim/table.go` — `Table`, `Open`, grace, dispose.
- `pkg/reclaim/default.go` — process-wide `Default` table.
- `modsecurity.go` — `pluginKey` and `bindPlugin`.

## Gotchas

- A later `Open` for the same key during grace reclaims the value and stops the timer.
- Zero grace disposes as soon as the last holder’s context is done.
- `logger` is required. Pass the Plugin slog logger. Reclaim lines are Debug (`reclaim_put`, `reclaim_bind`, `reclaim_dispose`); they appear only when `logLevel` is `debug`.
