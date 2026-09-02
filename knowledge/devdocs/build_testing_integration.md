# Integration

## Overview

Pester v5 tests hit a live Traefik + ModSecurity + whoami stack. Apache CRS is `docker-compose.test.yml` (default). nginx CRS is `docker-compose.test.nginx.yml`. The local runner is `Test-Integration.ps1`. Helpers live in `scripts/TestHelpers.ps1`.

## How to use

- Read `scripts/TestHelpers.ps1` before writing an `It` block. Call a helper instead of raw `Invoke-WebRequest`, Docker inspect, or TCP.
- Dot-source helpers from `BeforeAll` (`. "$PSScriptRoot/TestHelpers.ps1"`). Put shared URLs and `Wait-ForAllServices` there, not inside each `It`.
- Keep each `It` linear: setup → action → assert. Extract anything longer than a short sequence into `TestHelpers.ps1`.
- Use `-Because` when the assertion reason is not obvious. Do not repeat `$BaseUrl` or readiness checks inside each `It`.
- Send HTTP through `Invoke-SafeWebRequest`. Send chunked POSTs through `Invoke-ChunkedHttpRequest` (`Invoke-WebRequest` sets `Content-Length` and cannot hit `req.ContentLength == -1`). Use `Test-WafBlocking` / `Test-MaliciousPatterns` / `Test-BypassPatterns` for block/pass batches. Drive a live WebSocket through `Invoke-WebSocketEcho` (do not invent a second client).
- Run the full local suite with `./Test-Integration.ps1` (default `-TestPath ./scripts/*.Tests.ps1`, `-ComposeFile ./docker-compose.test.yml`). Same suite on nginx: `./Test-Integration.ps1 -ComposeFile ./docker-compose.test.nginx.yml`.
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
- `scripts/TestHelpers.ps1` — HTTP, WAF assertions, container names, access-log parse, WAF audit-log parse, body builder, Traefik stdout / reclaim log parse, WebSocket echo. Helpers include `Invoke-SafeWebRequest`, `Invoke-TcpHttpRequest`, `Invoke-ChunkedHttpRequest`, `Invoke-WebSocketEcho`, `Test-WafBlocking`, `Get-TraefikAccessLogEntries`, `Get-TraefikClientHost`, `Get-WafAuditLogRecords`, `Get-WafAuditClientIp`, `Get-WafAuditHost`, `Get-TraefikStdoutLines`, `Get-ReclaimLogEvents`, `Wait-ReclaimLogCount`, `Set-ReclaimDynamicTimeoutMillis`.
- `docker-compose.test.yml` — Traefik local plugin on `:8000`, Apache CRS WAF, dummy, labeled whoami routes, `echo-ws` (`jmalloc/echo-server`) on `/ws-echo` behind `waf-middleware`, file-provider directory `test-dynamic/`. The `waf` service sets `REMOTEIP_HEADER=X-Real-IP`, RFC1918 `REMOTEIP_INT_PROXY`, and `MODSEC_AUDIT_LOG=/var/log/modsec_audit.log` so a deny records Traefik `ClientHost` as `REMOTE_ADDR`.
- `docker-compose.test.nginx.yml` — same Traefik/plugin/routes; `waf` is nginx CRS with `REAL_IP_HEADER=X-Real-IP` and comma-separated RFC1918 `SET_REAL_IP_FROM`.
- `test-dynamic/reclaim.yml` — two routers (`/reclaim-a`, `/reclaim-b`) share `waf-reclaim` (`logLevel=debug`). Tests rewrite `timeoutMillis` to force a new reclaim key.

## Gotchas

- Prerequisites observed in `README.md` and the runner: Docker, Compose, PowerShell 7+, Pester v5. The runner installs Pester if the module is missing.
- CI (`.github/workflows/integration-test.yml`) runs `./scripts/integration-tests.Tests.ps1` on both Apache and nginx compose files (matrix). A BodySize-only change will pass CI unless you also cover it in the main file or change that workflow.
- Container helpers match `*-traefik-1` and `*-waf-1` so compose project names (local vs CI) still resolve.
- Protected middleware in `docker-compose.test.yml` sets `maxBodySizeBytes=1024` on `/protected`. Do not assume the Go `CreateConfig` default (8 MiB) on that route.
- Reclaim stdout tests need a fresh Traefik (`docker logs` is cumulative). Do not change `/protected` labels to force a new core; rewrite `test-dynamic/reclaim.yml` via `Set-ReclaimDynamicTimeoutMillis`. After a rewrite, `touch` the file in the container so file-watch fires on bind mounts. `DefaultGrace` is 10s; wait longer than that for `reclaim_dispose`.
