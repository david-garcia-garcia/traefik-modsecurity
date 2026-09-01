---
url: https://github.com/david-garcia-garcia/traefik-geoblock/blob/0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf/pkg/geoblock/plugin.go
title: pkg/geoblock/plugin.go
fetched: 2026-09-01
authority: source
ref: github.com/david-garcia-garcia/traefik-geoblock@0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf:pkg/geoblock/plugin.go
---

`PluginLogger(name, cfg)`:

```go
bootstrap := logging.NewBootstrap(name, cfg.LogLevel)
return logging.New(name, cfg.LogLevel, cfg.LogFormat, bootstrap)
```

`NewCore` uses that logger. Init `Debug` includes `"logLevel", cfg.LogLevel`. Traefik’s logger is not referenced.
