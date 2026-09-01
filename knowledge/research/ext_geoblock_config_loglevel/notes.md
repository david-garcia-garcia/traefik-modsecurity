# logLevel

The pattern is **github.com/david-garcia-garcia/traefik-geoblock** (pinned `0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf`, tag v1.2.0), not PascalMinder/geoblock.

Public field name: `logLevel` (Go `Config.LogLevel`). It sets the plugin’s own slog level and writes to process stdout. Traefik `--log.level` is not read.

## Not PascalMinder/geoblock

https://github.com/PascalMinder/geoblock (catalog GeoBlock) has **no** `logLevel`. Its `Config` uses per-event bools (`logLocalRequests`, `logAllowedRequests`, `logApiRequests`) and `logFilePath`. `CreateConfig` returns an empty `Config{}`. That repo is not this pattern.

Owner: `PascalMinder/geoblock@main:geoblock.go`.

Extract: `.sources/pascalminder-geoblock.go.md`

## Field, values, default

On the pattern repo:

- Go field: `LogLevel string` — comment lists `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`. No `json` or `mapstructure` tag.
- Dynamic YAML / Docker label key: `logLevel` (README and compose labels). Traefik decodes plugin maps with mapstructure (see `ext_traefik_plugins_yaegi-logging`).
- `CreateConfig` default: `"info"`.
- Accepted (case-insensitive via `strings.ToLower`): `trace`, `debug`, `info`, `warn`, `error`.
- Empty or unknown → `info`. Unknown non-empty also `Warn`s `"Unknown log level"` on the bootstrap logger.

Owner: `david-garcia-garcia/traefik-geoblock@0c2f46d:pkg/geoblock/config.go` and `pkg/logging/logging.go`.

Extracts: `.sources/config.go.md`, `.sources/logging.go.md`, `.sources/readme.md`

## How it gates stdout

`PluginLogger(name, cfg)` builds `logging.New(name, cfg.LogLevel, cfg.LogFormat, bootstrap)`.

`logging.New` installs a slog handler whose `Level` is the parsed `logLevel`. Lines below that level are not written.

`StdoutWriter.Write` calls `os.Stdout.Write` — process stdout (Traefik’s stdio), not Traefik’s injected logger.

`trace` is `slog.LevelDebug - 4`. Per-request `Trace` is a no-op unless `logLevel` is `trace`.

Owner: `…@0c2f46d:pkg/geoblock/plugin.go`, `pkg/logging/logging.go`.

Extracts: `.sources/plugin.go.md`, `.sources/logging.go.md`

## Out of scope here

`logFormat` (`json` | `text`, default `text`) is a sibling stdout format knob, not a level.

File logging (`logPath`, buffers) is **not** on this fork’s current `Config`. PascalMinder still has `logFilePath`. File output is out of scope for this ticket.
