# Reclaim table

## Language

**Reclaim table**:
A process-wide map that keeps one value per key while any bound Traefik `New` context is live or grace has not elapsed.
_Avoid_: cache, pool (the HTTP transport pool is a different object)

## Overview

The plugin holds one `*reclaim.Table` from `github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim` at package scope in `modsecurity.go`. `OpenTyped` creates or reuses the Plugin and watches `ctx`. After the last holder and grace, `Hooks.Close` calls `Plugin.Close()`.

## How to use

- Call `reclaim.OpenTyped[*modsecurity.Plugin](ctx, pluginReclaim, key, logger, create)` from root `bindPlugin`. Keep that call a call expression in package `traefik_modsecurity` (Yaegi).
- `create` returns `(any, reclaim.Hooks, error)`. Set `Hooks.Close` to `Plugin.Close`. Leave `EnforceCloseBeforeOpen` false unless the value owns an exclusive resource that cannot exist twice.
- Key as `plugin:` + name + hex hash of prepared config.
- Reset the shared table only from tests via `resetPluginReclaimForTest` in `reclaim_test.go`.

## Pattern snippet

```go
pluginInstance, err := reclaim.OpenTyped[*modsecurity.Plugin](ctx, pluginReclaim, key, logger, func() (any, reclaim.Hooks, error) {
	created, createErr := modsecurity.New(name, cfg, logger)
	if createErr != nil {
		return nil, reclaim.Hooks{}, createErr
	}
	return created, reclaim.Hooks{Close: func() { created.Close() }}, nil
})
```

## Key files

- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/` — imported table (`New`, `OpenTyped`, `Hooks`, grace).
- `modsecurity.go` — package-scoped `pluginReclaim`, `pluginKey`, `bindPlugin`.
- `reclaim_test.go` — test-only table reset.

## Gotchas

- A later `OpenTyped` for the same key during grace reclaims the value and stops the timer.
- Zero grace disposes as soon as the last holder’s context is done.
- `logger` is required. Pass the Plugin slog logger. Reclaim lines are Debug (`reclaim_put`, `reclaim_bind`, `reclaim_dispose`); they appear only when `logLevel` is `debug`.
- Do not import a second utilities package (simpleredis, windowcounter, tokenbucket, backendbackoff, iplookup) unless a later change asks for it.
