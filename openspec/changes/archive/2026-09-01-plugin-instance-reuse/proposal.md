## Why

Traefik calls `New` once per route. This plugin builds a new HTTP transport, client, logger, and optional WAF health tracker on every call, so many routes that share one middleware name and config open independent connection pools to the same ModSecurity URL and trip health independently.

## What Changes

- Move plugin core types and `ServeHTTP` into a standalone `pkg/` package. Root package stays the Yaegi entry (`CreateConfig`, `New`, `Config` alias).
- Add a process-wide reclaim table. `New` reuses one core for the same middleware name + prepared config and returns a thin route wrapper that holds `next`.
- Shared core owns the HTTP client (dialer, transport, pool), logger, and `health.Tracker`.
- When the last Traefik `New` context for a key is done, the table waits grace then calls `Close` on the core (idle connections).
- Land `pkg/health` on this branch so the shared core can own a tracker (not on `origin/main` today).
- No public Traefik `Config` JSON keys or defaults change.

## Capabilities

### New Capabilities

- `core_plugin_middleware_instance-reuse`: one plugin core per middleware name+config; thin per-route wrapper; shared client, logger, and health tracker; reclaim/dispose on last holder.

### Modified Capabilities

- (none — `openspec/specs/` has no baseline folders)

## Impact

- Root `modsecurity.go` becomes a thin constructor.
- New `pkg/modsecurity`, `pkg/reclaim`; existing/uncommitted `pkg/health`.
- Unit tests for same-key reuse and different-key isolation.
- Yaegi still loads `CreateConfig` and `New` from the module root.
- Operators see no new config keys. Routes that share a middleware name and config share one WAF connection pool and one health backoff.
