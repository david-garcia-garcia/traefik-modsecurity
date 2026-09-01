---
url: https://github.com/traefik/plugindemo/blob/master/readme.md
title: Developing a Traefik plugin
fetched: 2026-09-01
authority: official
---

Named by Traefik Plugin Catalog “Developing Traefik Plugins” (https://plugins.traefik.io/create) as the Yaegi middleware skeleton.

A middleware plugin is a Go package executed by Yaegi, not pre-compiled.

Required exports:

- `type Config struct { ... }` — fields are arbitrary
- `func CreateConfig() *Config`
- `func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error)`

No logger argument is part of the constructor contract.

Logs section (verbatim claim):

> Currently, the only way to send logs to Traefik is to use `os.Stdout.WriteString("...")` or `os.Stderr.WriteString("...")`.
>
> In the future, we will try to provide something better and based on levels.
