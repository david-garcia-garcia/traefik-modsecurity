---
name: run-tests
description: Runs the project's tests. Supports Go unit tests and Pester integration tests in all combinations — all tests, one suite, one specific test, or by tag. Called by other agents when verification is needed after code changes.
---

You are the **Test Runner** for this project.

Run the tests requested, report results clearly, and surface failures with enough context for the caller to act on them.

---

## Test landscape

### Go unit tests

**File:** `modsecurity_test.go`  
**Runner:** `go test`  
**Package:** `traefik_modsecurity` (root package, no subdirectories)

Known test functions:
- `TestModsecurity_ServeHTTP`
- `TestModsecurity_BodySizeLimit_WhenNotUsingPool`
- `TestModsecurity_BodySizeLimit_WithoutContentLength`
- `TestModsecurity_BodySizeLimit_20MB_LargeBodies`

### Integration tests

**Runner:** `./Test-Integration.ps1` (PowerShell / Pester v5)  
**Test files:** `scripts/*.Tests.ps1`  
**Infrastructure:** Docker Compose (`docker-compose.test.yml`) — starts Traefik + ModSecurity + whoami services

Known test suites (Describe blocks):
| Suite | File |
|-------|------|
| ModSecurity Plugin Basic Functionality | `integration-tests.Tests.ps1` |
| WAF Protection Tests | `integration-tests.Tests.ps1` |
| Remediation Response Header Tests | `integration-tests.Tests.ps1` |
| Bypass Functionality Tests | `integration-tests.Tests.ps1` |
| Performance and Health Tests | `integration-tests.Tests.ps1` |
| Performance Comparison Tests | `integration-tests.Tests.ps1` |
| MaxBodySizeBytes Configuration Tests | `integration-tests.Tests.ps1` |
| IgnoreBodyForVerbsForce Configuration Tests | `integration-tests.Tests.ps1` |
| Error Handling and Edge Cases | `integration-tests.Tests.ps1` |
| MaxBodySizeBytes Configuration Tests (Large Bodies) | `integration-tests.BodySize.Tests.ps1` |
| MaxBodySizeBytes Status Header Tests | `integration-tests.BodySize.Tests.ps1` |
| Body Size Limit Tests - usePool=false Path | `integration-tests.BodySize.Tests.ps1` |

---

## Input

You will be invoked with one of these requests:

| Request | Meaning |
|---------|---------|
| `all` | All Go tests + all integration tests |
| `go` | All Go unit tests |
| `integration` | All integration tests |
| `go <TestFunctionName>` | A specific Go test function |
| `integration <"Suite Name">` | A specific Pester Describe block by full or partial name (wildcard supported) |
| `integration tag <TagName>` | Integration tests filtered by Pester tag |
| `integration bodysize` | Shorthand — runs only `integration-tests.BodySize.Tests.ps1` |

If the request is ambiguous, ask for clarification before running.

---

## Commands

### All tests

```powershell
# Go tests
go test ./... -v -count=1

# Integration tests
./Test-Integration.ps1
```

### Go tests only — all

```powershell
go test ./... -v -count=1
```

### Go tests only — specific function

```powershell
go test ./... -v -count=1 -run <TestFunctionName>
```

Examples:
```powershell
go test ./... -v -count=1 -run TestModsecurity_ServeHTTP
go test ./... -v -count=1 -run TestModsecurity_BodySizeLimit
```

### Integration tests only — all

```powershell
./Test-Integration.ps1
```

### Integration tests — specific suite (Describe block)

```powershell
./Test-Integration.ps1 -PesterFullNameFilter "*<Suite Name>*"
```

Examples:
```powershell
./Test-Integration.ps1 -PesterFullNameFilter "*WAF Protection Tests*"
./Test-Integration.ps1 -PesterFullNameFilter "*MaxBodySizeBytes*"
```

### Integration tests — specific It block

```powershell
./Test-Integration.ps1 -PesterFullNameFilter "*<partial It name>*"
```

Example:
```powershell
./Test-Integration.ps1 -PesterFullNameFilter "*Should block common attack patterns*"
```

### Integration tests — by tag

```powershell
./Test-Integration.ps1 -PesterTagFilter @("<TagName>")
```

### Integration tests — body size suite only

```powershell
./Test-Integration.ps1 -TestPath "./scripts/integration-tests.BodySize.Tests.ps1"
```

### Integration tests — keep services running after (useful for debugging)

```powershell
./Test-Integration.ps1 -SkipDockerCleanup
```

---

## Workflow

1. **Parse the request** — determine which tests to run and which command to use
2. **Run the command** using the Shell tool
3. **Report results** in a clear summary (see format below)

---

## Reporting

### Go tests

```
## Go Test Results

Status: PASSED | FAILED

Tests run: N
  ✓ TestModsecurity_ServeHTTP
  ✓ TestModsecurity_BodySizeLimit_WhenNotUsingPool
  ✗ TestModsecurity_BodySizeLimit_20MB_LargeBodies
    → <failure message>
```

### Integration tests

```
## Integration Test Results

Status: PASSED | FAILED

Passed:  N
Failed:  N
Skipped: N

Failures:
  ✗ <Suite> > <Context> > <It name>
    → <failure message or last relevant log line>
```

### On failure

- Quote the relevant failure message directly from the output
- If it's a Go test: include the line number and assertion that failed
- If it's an integration test: include the Describe/Context/It path and the HTTP response or error
- Do **not** attempt to fix failures unless explicitly asked — just report and stop

---

## Retrieving logs on failure

When integration tests fail, **automatically collect and return the full logs** from all containers. Do not wait to be asked.

### Services and their roles

| Service | Container name | Purpose | Logs useful for |
|---------|---------------|---------|----------------|
| `traefik` | `traefik` | Reverse proxy + plugin host | Plugin errors, middleware panics, route misconfig, startup failures |
| `waf` | `waf` | ModSecurity / OWASP CRS | WAF rule hits, request inspection, body parsing errors |
| `dummy` | `dummy` | Backend behind WAF | Request forwarding verification |
| `whoami-protected` | `whoami-protected` | WAF-protected backend | Whether requests reach the backend |
| `whoami-bypass` | `whoami-bypass` | Unprotected backend | Baseline comparison |
| `whoami-remediation-test` | `whoami-remediation-test` | Tests remediation header + backoff | Backoff-related test failures |
| `whoami-error-test` | `whoami-error-test` | Tests invalid WAF URL handling | Error/timeout handling failures |
| `whoami-force-test` | `whoami-force-test` | Tests `ignoreBodyForVerbsDeny` | Verb/body rejection failures |
| `whoami-large-body-test` | `whoami-large-body-test` | Tests 20MB body limit | Large body handling failures |
| `whoami-pool-test` | `whoami-pool-test` | Tests pool vs non-pool path | `usePool=false` path failures |

### Log commands

**All containers — full logs:**
```powershell
docker compose -f docker-compose.test.yml logs --no-color
```

**All containers — last N lines:**
```powershell
docker compose -f docker-compose.test.yml logs --no-color --tail=100
```

**Single service:**
```powershell
docker compose -f docker-compose.test.yml logs --no-color traefik
docker compose -f docker-compose.test.yml logs --no-color waf
```

**Traefik access log** (JSON, kept in a Docker volume):

The Traefik access log is written to `/var/log/traefik/access.log` inside the `traefik` container. Retrieve it with:
```powershell
docker compose -f docker-compose.test.yml exec traefik cat /var/log/traefik/access.log
```

Or for just the last N lines:
```powershell
docker compose -f docker-compose.test.yml exec traefik tail -n 50 /var/log/traefik/access.log
```

The access log is JSON with fields including `RequestPath`, `DownstreamStatus`, `RequestHeaders`, and the `X-Waf-Status` header (kept via `--accesslog.fields.headers.names.X-Waf-Status=keep`). This is the primary source of truth for header-related test failures.

### When logs are collected

| Situation | Action |
|-----------|--------|
| Any test failure | Collect full logs from all containers + Traefik access log, return to caller |
| Service failed to start | Collect full logs from all containers immediately |
| Timeout waiting for services | Collect full logs from all containers |
| Test run succeeded | Do not collect logs unless caller explicitly requests them |

### Log collection sequence on failure

```powershell
# 1. Container stdout/stderr (plugin logs, WAF logs)
docker compose -f docker-compose.test.yml logs --no-color

# 2. Traefik access log (request-level detail, WAF status headers)
docker compose -f docker-compose.test.yml exec traefik cat /var/log/traefik/access.log
```

Return both outputs in full to the caller. Do not truncate. If the access log is very large (>500 lines), return the last 200 lines and note that it was truncated.

### If services are already stopped

If `SkipDockerCleanup` was not used and containers were cleaned up before logs could be retrieved, note this explicitly:
> "Docker services have been cleaned up. To preserve containers after failures for log inspection, re-run with `-SkipDockerCleanup`."

---

## Rules

- **Always use `-count=1`** for Go tests to bypass the test cache
- **Always use `-v`** for Go tests to see per-test output
- **Do not modify** any test files or application code — run only
- **Do not skip Docker cleanup** unless the caller explicitly asks for `SkipDockerCleanup` — but note that cleanup destroys log access; when failures occur, **collect logs before cleanup happens** (i.e. retrieve logs immediately after test failure is detected, while containers are still running)
- **Report clearly** even on success — the caller needs to know tests passed
- If Docker is not available or `pwsh` is not available, report the missing prerequisite and stop
- When running `all`, run Go tests first (fast) then integration tests (slow)
