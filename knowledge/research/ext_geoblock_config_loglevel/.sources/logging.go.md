---
url: https://github.com/david-garcia-garcia/traefik-geoblock/blob/0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf/pkg/logging/logging.go
title: pkg/logging/logging.go
fetched: 2026-09-01
authority: source
ref: github.com/david-garcia-garcia/traefik-geoblock@0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf:pkg/logging/logging.go
---

`StdoutWriter.Write` → `os.Stdout.Write`.

`parseLevel` lowercases then maps:

- `trace` → `LevelTrace` (`slog.LevelDebug - 4`)
- `debug` → `slog.LevelDebug`
- `info` → `slog.LevelInfo`
- `warn` → `slog.LevelWarn`
- `error` → `slog.LevelError`
- default → `slog.LevelInfo`, `ok == false`

`New(name, level, format, bootstrap)`:

- If `parseLevel` fails and `level != ""`, `bootstrap.Warn("Unknown log level", "level", level)`.
- Handler `Level` is the parsed slog level (unknown/empty → info).
- `format == "json"` → `slog.NewJSONHandler`; otherwise text.
- Logger is tagged `"plugin", name`.

`Trace` logs at `LevelTrace`. No-op unless handler level is trace.
