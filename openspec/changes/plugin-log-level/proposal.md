## Why

Yaegi plugins do not inherit Traefik `--log.level`. This middleware has two sinks and no operator knob: request and health lines always print to stdout, and reclaim Debug is discarded. Operators cannot set a level, and nobody can prove reclaim bind/put/dispose from Traefik container logs.

## What Changes

- Add public `logLevel` on middleware `Config` (Docker label / YAML). Default `info`.
- Own one slog logger on the shared Plugin core. Gate request, health, and reclaim output with that level.
- Stop passing `io.Discard` into `reclaim.Open`. Reclaim Debug appears only when `logLevel` is `debug`.
- Changing `logLevel` is a prepared-config change, so the reclaim key changes and a new core is built (existing instance-reuse rule).
- Document `logLevel` for operators. No file logger (`logPath`, `logFormat`, buffers).

## Capabilities

### New Capabilities

- `core_plugin_middleware_log-level`: Public `logLevel`, one plugin-owned logger, and the level map for request, health, and reclaim lines.

### Modified Capabilities

None. `core_plugin_middleware_instance-reuse` already requires one core per name+prepared config and that the core owns the logger. `logLevel` after Prepare is another prepared field; no new reuse requirement.

## Impact

- `pkg/modsecurity/config.go` — `logLevel` field, default, Prepare validate/normalize
- `pkg/modsecurity/plugin.go` — store `*slog.Logger`
- `pkg/modsecurity/serve.go` — leveled request-path logs
- `pkg/health/tracker.go` — slog; trip at error, backoff expired at info
- `modsecurity.go` — build logger, pass same pointer to reclaim and Plugin
- `README.md`, `docker-compose.test.yml`, Go tests
- Public config surface only. No new Go module dependency (stdlib `log/slog`).
