# Integration Test Conventions

> Maintained by: project team  
> Last updated: 2026-03-07

Integration tests live in `scripts/*.Tests.ps1` and use Pester v5. Helpers live in `scripts/TestHelpers.ps1`, which is dot-sourced in every test file's `BeforeAll`.

---

## Rule 1: Always read TestHelpers.ps1 before writing a test

Before writing any `It` block, read `scripts/TestHelpers.ps1` to know what helpers exist. Never reach for raw PowerShell (raw TCP, `Invoke-WebRequest` directly, etc.) when a helper covers the use case.

**Available helpers (summary):**

| Helper | Purpose |
|--------|---------|
| `Invoke-SafeWebRequest -Uri <url> [-Method] [-Headers] [-Body]` | All HTTP requests. Returns response object; does not throw on 4xx/5xx. |
| `Test-WafBlocking -Url <url>` | Assert a request is blocked (≥400). Logs the status. |
| `Test-MaliciousPatterns -BaseUrl <url> -Patterns <array>` | Assert multiple malicious patterns are all blocked. |
| `Test-BypassPatterns -BaseUrl <url> -Patterns <array>` | Assert multiple patterns pass through the bypass route. |
| `Test-ResponseTime -Url <url> [-MaxResponseTimeMs]` | Assert response is ≤ time limit. |
| `Get-TraefikAccessLogEntries` | Parse the Traefik JSON access log. Returns array of log objects. |
| `Get-LastAccessLogEntryForPath -Entries <array> -PathPrefix <string>` | Find last access log entry for a given path. |
| `New-RequestBodyOfSizeBytes -TargetSizeBytes <int>` | Build a request body of exact byte size. |
| `Get-TraefikContainerName` | Get the Traefik container name (works across compose project names). |
| `Get-WafContainerName` | Get the WAF container name. |
| `Wait-ForAllServices -Services <array>` | Wait for all services to become healthy before tests run. |

---

## Rule 2: Keep `It` blocks simple and linear

The body of an `It` block should be: **setup → action → assert**. A reader must be able to understand what is being tested in one pass without jumping around.

```powershell
# Good
It "Should allow normal GET requests" {
    $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected/normal-path"
    $response.StatusCode | Should -Be 200
}

# Bad — branching, loops, error handling inside It block
It "Should allow normal GET requests" {
    try {
        $response = Invoke-WebRequest -Uri "$BaseUrl/protected/normal-path" -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            $true | Should -Be $true
        } else {
            throw "unexpected"
        }
    } catch {
        $false | Should -Be $true
    }
}
```

---

## Rule 3: Extract complexity to TestHelpers.ps1, not into the `It` block

If a test needs logic that is more than ~5 lines (e.g. raw TCP, multi-step setup, parsing), extract it as a named function in `scripts/TestHelpers.ps1` first, then call it from the `It` block.

This keeps `It` blocks readable and makes the helper reusable by future tests.

```powershell
# In TestHelpers.ps1 — extracted function
function Invoke-RawHttpRequest {
    param(
        [string]$Host,
        [int]$Port,
        [string]$RawRequestLine,    # e.g. "GET http://example.com/path HTTP/1.1"
        [string[]]$Headers          # e.g. @("Host: localhost:8000", "Connection: close")
    )
    $tcp = New-Object System.Net.Sockets.TcpClient($Host, $Port)
    try {
        $stream = $tcp.GetStream()
        $raw = $RawRequestLine + "`r`n" + ($Headers -join "`r`n") + "`r`n`r`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($raw)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        $reader = New-Object System.IO.StreamReader($stream)
        return $reader.ReadToEnd()
    } finally {
        $tcp.Close()
    }
}

# In the test file — the It block stays clean
It "Should handle absolute-form RequestURI correctly" {
    $response = Invoke-RawHttpRequest -Host "localhost" -Port 8000 `
        -RawRequestLine "GET http://traefik/protected/ HTTP/1.1" `
        -Headers @("Host: localhost:8000", "Connection: close")

    $response | Should -Match 'HTTP/1\.\d 2\d\d' -Because "absolute-form URI must be normalised; not a DNS error"
    $response | Should -Match "Hostname"
}
```

---

## Rule 4: Use `-Because` in assertions when the reason isn't obvious

```powershell
# Good
$response.StatusCode | Should -Be 200 -Because "legitimate requests must pass the WAF"

# Only skip -Because when the assertion is self-evident
$response.StatusCode | Should -Be 200
```

---

## Rule 5: Never duplicate setup across `It` blocks

Use `BeforeAll` or `BeforeEach` at the `Describe`/`Context` scope for shared setup. Do not repeat `$BaseUrl` definitions or service readiness checks inside individual tests.

