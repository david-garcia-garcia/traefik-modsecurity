---
url: https://httpd.apache.org/docs/2.4/configuring.html
title: Apache HTTP Server — configuration file ${VAR} expansion
fetched: 2026-09-03
authority: official
---

Values of `Define` variables or shell environment variables can be used in configuration lines as `${VAR}`. If VAR is valid, its value is substituted. `Define` wins over the shell environment. If VAR is missing, `${VAR}` is left unchanged and a warning is logged.

Only shell environment variables defined **before** the server starts are usable. `SetEnv` in the config is too late.

CRS Apache vhost `${BACKEND}` / `${BACKEND_WS}` rely on this (image `ENV` + compose `-e`).
