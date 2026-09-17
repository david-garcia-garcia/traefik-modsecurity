# Layout

## Overview

The Yaegi entry lives in the root Go package `traefik_modsecurity`. Isolated components go under `pkg/<name>/` as their own package. Tests, Compose, CI, and OpenSpec sit beside that, not inside `pkg/`.

## How to use

- Put Traefik catalog exports (`CreateConfig`, `New`, `Config` alias) in the root package so Yaegi can find them at the module root.
- Put the Plugin core in `pkg/<name>/`. Import it from the root package. Keep the reclaim table as the imported `traefik-middleware-utilities/reclaim` instance held in the root package. The WAF backoff gate is the imported `backendbackoff` instance held on the Plugin.
- Do not import the root package from `pkg/`. `openspec/project.md` states that direction: root → `pkg/`, never the reverse.
- Keep integration tests in `scripts/*.Tests.ps1` and helpers in `scripts/TestHelpers.ps1`. Do not place Pester files next to Go sources.
- Keep vendored modules in `vendor/`. Do not delete that tree to “clean up” a local build.

## Key files

- `modsecurity.go` / `modsecurity_test.go` / `plugin_reuse_test.go` — root package.
- `pkg/modsecurity/` — Plugin core and request path.
- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/` — imported process table.
- `pkg/modsecurity/` — Plugin core, ServeHTTP, and WAF backoff gate wiring.
- `scripts/` — Pester suites and helpers.
- `vendor/` — committed modules.
- `openspec/` — project context and changes.
- `.github/workflows/` — CI.
- `.cursor/` — agent skills (not production).

## Gotchas

- The Go module path is `github.com/david-garcia-garcia/traefik-modsecurity`. Traefik local-plugin mounts must use that full path under `/plugins-local/src/`.
- A new isolated component is a new `pkg/<name>/`, not a file dropped into an existing pkg.
