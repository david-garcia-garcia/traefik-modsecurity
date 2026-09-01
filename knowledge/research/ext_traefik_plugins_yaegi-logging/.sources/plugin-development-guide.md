---
url: https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide
title: Plugin Development Guide
fetched: 2026-09-01
authority: official
---

Traefik Hub guide for public and private plugins. Same Yaegi middleware constructor as plugindemo:

`func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error)`

Required exports: Config struct, `CreateConfig()`, `New()` returning `http.Handler`.

The sample `New` copies config fields onto the handler. It does not receive a Traefik logger or log level.

Manifest `.traefik.yml` may set `runtime` to `yaegi` (default) or `wasm`. This finding is Yaegi HTTP middleware only.
