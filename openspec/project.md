# Project: Traefik ModSecurity Plugin

Project-specific context for OpenSpec. When designing features or creating proposals, use this as the source of truth for architecture, conventions, and domain knowledge.

---

## Repository

- **Remote**: `origin` → `git@github.com:david-garcia-garcia/traefik-modsecurity.git`
- **Owner**: `david-garcia-garcia`
- **Repo**: `traefik-modsecurity`
- **Main branch**: `main`

## Tech stack

- **Language**: Go
- **Integration**: Traefik v3 HTTP plugin (middleware)
- **Domain**: WAF (Web Application Firewall) — this plugin proxies HTTP requests to an external ModSecurity service and enforces block/pass based on its response.

## Architecture

- **Package**: Single package `traefik_modsecurity`.
- **Flow**: Incoming `http.Request` → optional body read (size/verb limits) → proxy to `ModSecurityUrl` → on block: return 403 and optional status header; on pass: call `next.ServeHTTP`.
- **Key types**:
  - `Config`: plugin configuration (YAML/JSON), created via `CreateConfig()` with documented defaults.
  - `Modsecurity`: handler holding `http.Client`, WAF URL, backoff state, body limits; built via `New(ctx, next, config, name)`.

## Conventions

- Config: JSON struct tags; optional fields with `omitempty`; sensible defaults in `CreateConfig()`.
- Performance: `sync.Pool` for body buffers; configurable timeouts, connection limits, max body size.
- Body handling: configurable verbs that skip body (e.g. GET, HEAD); optional deny for body on those verbs.
- Logging: use the plugin’s `logger`; no direct `log` package for plugin behavior.

## Where to extend

- **New config knobs**: add fields to `Config` and `Modsecurity`, set defaults in `CreateConfig()`, apply in `New()` and in the handler.
- **New behavior**: implement in `ServeHTTP`; keep `next.ServeHTTP` for the “pass” path.
- **New specs**: add or update `openspec/specs/<capability>/spec.md` so proposals and implementation stay aligned with requirements.

## Testing

Use the **`run-tests` agent** to run tests. Never run test commands directly — always delegate to this agent.

| What to run | Request |
|-------------|---------|
| All tests | `run-tests all` |
| Go unit tests only | `run-tests go` |
| All integration tests | `run-tests integration` |
| Specific Go test | `run-tests go <TestFunctionName>` |
| Specific integration suite | `run-tests integration "<Suite Name>"` |
| Body size suite only | `run-tests integration bodysize` |
| By Pester tag | `run-tests integration tag <TagName>` |

**Go tests** (`modsecurity_test.go`): standard `go test`, no external deps, fast.
**Integration tests** (`scripts/*.Tests.ps1`): Pester v5 + Docker Compose; starts Traefik + ModSecurity + whoami, then runs HTTP assertions. Requires Docker Desktop and PowerShell.
