---
url: https://github.com/PascalMinder/geoblock/blob/main/geoblock.go
title: PascalMinder/geoblock Config
fetched: 2026-09-01
authority: source
ref: github.com/PascalMinder/geoblock@main:geoblock.go
---

Catalog plugin at https://github.com/PascalMinder/geoblock (https://plugins.traefik.io/plugins/62947313ffc0cd18356a97ca/geo-block).

`Config` has no `logLevel` / `LogLevel`. Logging-related fields:

- `LogLocalRequests`, `LogAllowedRequests`, `LogAPIRequests` (bools)
- `LogFilePath` (`yaml:"logFilePath"`)

`CreateConfig()` returns `&Config{}` (zero values; no default level string).

This is not the `logLevel` pattern. File path logging is out of scope for this ticket.
