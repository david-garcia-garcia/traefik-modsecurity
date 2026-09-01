# Integration

## Overview

Pester v5 tests hit a live Traefik + ModSecurity + whoami stack from `docker-compose.test.yml`. The local runner is `Test-Integration.ps1`. Helpers live in `scripts/TestHelpers.ps1`.

## How to use

- Read `scripts/TestHelpers.ps1` before writing an `It` block. Call a helper instead of raw `Invoke-WebRequest`, Docker inspect, or TCP.
- Dot-source helpers from `BeforeAll` (`. "$PSScriptRoot/TestHelpers.ps1"`). Put shared URLs and `Wait-ForAllServices` there, not inside each `It`.
- Keep each `It` linear: setup → action → assert. Extract anything longer than a short sequence into `TestHelpers.ps1`.
- Use `-Because` when the assertion reason is not obvious. Do not repeat `$BaseUrl` or readiness checks inside each `It`.
- Send HTTP through `Invoke-SafeWebRequest`. Use `Test-WafBlocking` / `Test-MaliciousPatterns` / `Test-BypassPatterns` for block/pass batches.
- Run the full local suite with `./Test-Integration.ps1` (default `-TestPath ./scripts/*.Tests.ps1`, `-ComposeFile ./docker-compose.test.yml`).
- Filter with `-PesterFullNameFilter` or `-PesterTagFilter`. Debug with `-SkipDockerCleanup` or `-SkipWait`.
- Agents: `openspec/project.md` says delegate to `run-tests` (`run-tests integration`, `run-tests integration "<Suite Name>"`, `run-tests integration bodysize`, `run-tests integration tag <TagName>`).

## Pattern snippet

```powershell
BeforeAll {
    . "$PSScriptRoot/TestHelpers.ps1"
    $script:BaseUrl = "http://localhost:8000"
    Wait-ForAllServices -Services @(
        @{ Url = "$BaseUrl/protected"; Name = "Protected service" }
    )
}

It "Should allow normal GET requests" {
    $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected/normal-path"
    $response.StatusCode | Should -Be 200
}
```

## Key files

- `Test-Integration.ps1` — Compose up, optional wait, `Invoke-Pester`, Compose down.
- `scripts/integration-tests.Tests.ps1` — main suite (`$BaseUrl` `http://localhost:8000`).
- `scripts/integration-tests.BodySize.Tests.ps1` — large-body transport checks.
- `scripts/TestHelpers.ps1` — HTTP, WAF assertions, container names, access-log parse, body builder, Traefik stdout / reclaim log parse. Helpers include `Invoke-SafeWebRequest`, `Test-WafBlocking`, `Get-TraefikAccessLogEntries`, `Get-TraefikStdoutLines`, `Get-ReclaimLogEvents`, `Wait-ReclaimLogCount`, `Set-ReclaimDynamicTimeoutMillis`.
- `docker-compose.test.yml` — Traefik local plugin on `:8000`, WAF, dummy, labeled whoami routes, file-provider directory `test-dynamic/`.
- `test-dynamic/reclaim.yml` — two routers (`/reclaim-a`, `/reclaim-b`) share `waf-reclaim` (`logLevel=debug`). Tests rewrite `timeoutMillis` to force a new reclaim key.

## Gotchas

- Prerequisites observed in `README.md` and the runner: Docker, Compose, PowerShell 7+, Pester v5. The runner installs Pester if the module is missing.
- CI (`.github/workflows/integration-test.yml`) runs only `./scripts/integration-tests.Tests.ps1`. A BodySize-only change will pass CI unless you also cover it in the main file or change that workflow.
- Container helpers match `*-traefik-1` and `*-waf-1` so compose project names (local vs CI) still resolve.
- Protected middleware in `docker-compose.test.yml` sets `maxBodySizeBytes=1024` on `/protected`. Do not assume the Go `CreateConfig` default (8 MiB) on that route.
- Reclaim stdout tests need a fresh Traefik (`docker logs` is cumulative). Do not change `/protected` labels to force a new core; rewrite `test-dynamic/reclaim.yml` via `Set-ReclaimDynamicTimeoutMillis`. After a rewrite, `touch` the file in the container so file-watch fires on bind mounts. `DefaultGrace` is 10s; wait longer than that for `reclaim_dispose`.
