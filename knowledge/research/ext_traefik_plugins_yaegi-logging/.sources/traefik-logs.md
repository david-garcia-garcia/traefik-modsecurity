---
url: https://doc.traefik.io/traefik/reference/install-configuration/observability/logs-and-accesslogs/
title: Logs & AccessLogs
fetched: 2026-09-01
authority: official
---

Traefik process logs are install (static) configuration. CLI form: `--log.level=INFO`. YAML: `log.level`. Env: `TRAEFIK_LOG_LEVEL`.

`log.level` accepted values: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`, `PANIC`. Default: `ERROR`.

This page documents Traefik’s own logger. It does not mention plugins, Yaegi, or passing the level into middleware `New`.
