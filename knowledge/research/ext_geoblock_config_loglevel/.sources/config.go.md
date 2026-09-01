---
url: https://github.com/david-garcia-garcia/traefik-geoblock/blob/0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf/pkg/geoblock/config.go
title: pkg/geoblock/config.go
fetched: 2026-09-01
authority: source
ref: github.com/david-garcia-garcia/traefik-geoblock@0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf:pkg/geoblock/config.go
---

Inspected at commit `0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf` (tag v1.2.0) from a temp clone of the named repo.

```go
LogLevel  string // Log level: "trace", "debug", "info", "warn", "error"
LogFormat string // Log format: "json" or "text"
```

No `json` or `mapstructure` tags on either field. No `logPath` / buffer fields on `Config`.

`CreateConfig()` sets `LogLevel: "info"` and `LogFormat: "text"`.
