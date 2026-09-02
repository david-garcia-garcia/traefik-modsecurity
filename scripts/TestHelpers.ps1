# PowerShell Test Helper Functions for Traefik ModSecurity Plugin
# These functions can be reused across multiple test files

# Test configuration constants
$script:DefaultTimeout = 15
$script:DefaultRetryInterval = 2

function Get-TraefikContainerName {
    # Discover by service suffix so it works across different
    # docker-compose project names (local vs CI).
    $name = docker ps --format "{{.Names}}" | Where-Object { $_ -like "*-traefik-1" } | Select-Object -First 1
    if (-not $name) {
        throw "Traefik container not found (searched for '*-traefik-1'; optionally set TRAEFIK_CONTAINER_NAME env var)"
    }
    return $name
}

function Get-WafContainerName {
    # Discover by service suffix so it works across different
    # docker-compose project names (local vs CI).
    $name = docker ps --format "{{.Names}}" | Where-Object { $_ -like "*-waf-1" } | Select-Object -First 1
    if (-not $name) {
        throw "WAF container not found (searched for '*-waf-1'; optionally set WAF_CONTAINER_NAME env var)"
    }
    return $name
}

function Wait-ForWafHealthy {
    param(
        [Parameter(Mandatory)]
        [string]$ContainerName,
        [int]$TimeoutSeconds = 90,
        [int]$PollSeconds = 3
    )

    Write-Host "Waiting for WAF container '$ContainerName' health..." -ForegroundColor Cyan
    $elapsed = 0
    $health = $null

    do {
        $health = docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}" $ContainerName 2>$null
        if ($health -eq "healthy") {
            Write-Host "✅ WAF container is healthy" -ForegroundColor Green
            return $true
        }
        # nginx CRS (and some custom images) may omit HEALTHCHECK. Running is enough.
        if ($health -eq "none") {
            $running = docker inspect --format "{{.State.Running}}" $ContainerName 2>$null
            if ($running -eq "true") {
                Write-Host "✅ WAF container is running (no Docker HEALTHCHECK)" -ForegroundColor Green
                return $true
            }
        }

        Start-Sleep -Seconds $PollSeconds
        $elapsed += $PollSeconds
    } while ($elapsed -lt $TimeoutSeconds)

    throw "WAF container '$ContainerName' did not become healthy within ${TimeoutSeconds}s (status='$health')"
}

<#
.SYNOPSIS
    Makes HTTP requests with comprehensive error handling

.DESCRIPTION
    A robust wrapper around Invoke-WebRequest with consistent error handling,
    timeout management, and optional security bypass for testing scenarios

.PARAMETER Uri
    The URL to make the request to

.PARAMETER Method
    HTTP method (GET, POST, etc.)

.PARAMETER Headers
    Hash table of headers to include

.PARAMETER Body
    Request body content

.PARAMETER TimeoutSec
    Request timeout in seconds

.PARAMETER AllowInsecure
    Skip certificate validation for HTTPS
#>
function Invoke-SafeWebRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [int]$TimeoutSec = 10,
        [switch]$AllowInsecure
    )
    
    try {
        $params = @{
            Uri = $Uri
            Method = $Method
            Headers = $Headers
            TimeoutSec = $TimeoutSec
            UseBasicParsing = $true
            SkipHttpErrorCheck = $true
        }
        
        if ($Body) {
            $params.Body = $Body
        }
        
        if ($AllowInsecure) {
            $params.SkipCertificateCheck = $true
        }
        
        return Invoke-WebRequest @params
    }
    catch {
        Write-Host "Request failed: $($_.Exception.Message)" -ForegroundColor Yellow
        throw
    }
}

<#
.SYNOPSIS
    Sends a raw HTTP request over TCP and returns the response as text.

.DESCRIPTION
    Used when the request line must be controlled exactly (e.g. absolute-form
    Request-URI for testing). Connects to Host:Port, sends the request line
    plus headers, then reads the response until the connection closes.

.PARAMETER TargetHost
    Target host (e.g. localhost).

.PARAMETER Port
    Target port (e.g. 8000).

.PARAMETER RequestLine
    Full HTTP request line (e.g. "GET http://traefik/protected/ HTTP/1.1").

.PARAMETER Headers
    Optional hashtable of headers. If not provided, Host and Connection: close are added.
#>
function Invoke-TcpHttpRequest {
    param(
        [Parameter(Mandatory)]
        [string]$TargetHost,
        [Parameter(Mandatory)]
        [int]$Port,
        [Parameter(Mandatory)]
        [string]$RequestLine,
        [hashtable]$Headers = @{}
    )

    $defaultHeaders = @{
        "Host" = "${TargetHost}:${Port}"
        "Connection" = "close"
    }
    $merged = @{}
    foreach ($k in $defaultHeaders.Keys) { $merged[$k] = $defaultHeaders[$k] }
    foreach ($k in $Headers.Keys) { $merged[$k] = $Headers[$k] }

    $headerLines = ($merged.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "`r`n"
    $request = "$RequestLine`r`n${headerLines}`r`n`r`n"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($request)

    $tcp = New-Object System.Net.Sockets.TcpClient($TargetHost, $Port)
    try {
        $stream = $tcp.GetStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        $reader = New-Object System.IO.StreamReader($stream)
        $responseText = $reader.ReadToEnd()
        $reader.Close()
        $stream.Close()
        return $responseText
    }
    finally {
        $tcp.Close()
    }
}

<#
.SYNOPSIS
    Waits for a service to become ready by checking its health endpoint

.DESCRIPTION
    Polls a service endpoint until it returns a successful response or timeout is reached.
    Uses exponential backoff for efficient waiting.

.PARAMETER Url
    The health check URL for the service

.PARAMETER ServiceName
    Human-readable name for logging

.PARAMETER TimeoutSeconds
    Maximum time to wait before giving up

.PARAMETER RetryInterval
    Time between retry attempts in seconds
#>
function Wait-ForService {
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [Parameter(Mandatory)]
        [string]$ServiceName,
        [int]$TimeoutSeconds = 30,
        [int]$RetryInterval = 2
    )
    
    Write-Host "Waiting for $ServiceName to be ready..." -ForegroundColor Cyan
    $elapsed = 0
    
    do {
        try {
            $response = Invoke-SafeWebRequest -Uri $Url -TimeoutSec 10
            if ($response.StatusCode -eq 200) {
                Write-Host "✅ $ServiceName is ready!" -ForegroundColor Green
                return $true
            }
        }
        catch {
            # Service not ready yet, continue waiting
        }
        
        Start-Sleep $RetryInterval
        $elapsed += $RetryInterval
        
        if ($elapsed % 10 -eq 0) {
            Write-Host "  Still waiting for $ServiceName... ($elapsed/$TimeoutSeconds seconds)" -ForegroundColor Gray
        }
        
    } while ($elapsed -lt $TimeoutSeconds)
    
    Write-Host "❌ $ServiceName failed to become ready within $TimeoutSeconds seconds" -ForegroundColor Red
    return $false
}

<#
.SYNOPSIS
    Tests multiple services for readiness

.PARAMETER Services
    Array of service objects with Url and Name properties

.PARAMETER TimeoutSeconds
    Per-service timeout in seconds
#>
function Wait-ForAllServices {
    param(
        [Parameter(Mandatory)]
        [array]$Services,
        [int]$TimeoutSeconds = 30
    )
    
    Write-Host "`n🔄 Waiting for all services to be ready..." -ForegroundColor Cyan
    
    $servicesReady = @()
    foreach ($service in $Services) {
        $servicesReady += (Wait-ForService -Url $service.Url -ServiceName $service.Name -TimeoutSeconds $TimeoutSeconds)
    }
    
    if ($servicesReady -contains $false) {
        throw "One or more services failed to start properly"
    }
    
    Write-Host "✅ All services are ready for testing!`n" -ForegroundColor Green
    return $true
}

function Get-TraefikAccessLogEntries {
    param(
        [Parameter(Mandatory)]
        [string]$TraefikContainerName
    )

    $accessLogContent = docker exec $TraefikContainerName cat /var/log/traefik/access.log 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read traefik access log from container: $TraefikContainerName"
    }

    $logLines = $accessLogContent -split "`n" | Where-Object { $_.Trim() -ne "" }

    $entries = @()
    foreach ($line in $logLines) {
        try {
            $entry = $line | ConvertFrom-Json
            $entries += $entry
        } catch {
            # Skip malformed JSON lines
        }
    }

    return $entries
}

# Default Apache path. Get-WafAuditLogPath reads MODSEC_AUDIT_LOG from the running container
# so nginx (/tmp/modsecurity/modsec_audit.log) does not need a second helper.
$script:WafAuditLogPath = "/var/log/modsec_audit.log"

function Get-WafAuditLogPath {
    param(
        [Parameter(Mandatory)]
        [string]$WafContainerName
    )

    if ($env:WAF_AUDIT_LOG_PATH) {
        return $env:WAF_AUDIT_LOG_PATH
    }
    $fromContainer = docker exec $WafContainerName printenv MODSEC_AUDIT_LOG 2>$null
    if ($LASTEXITCODE -eq 0 -and $fromContainer) {
        return ([string]$fromContainer).Trim()
    }
    return $script:WafAuditLogPath
}

# Get-TraefikClientHost returns the peer IP Traefik logged (ClientHost, else ClientAddr host).
function Get-TraefikClientHost {
    param(
        [Parameter(Mandatory)]
        $AccessLogEntry
    )

    if ($AccessLogEntry.ClientHost) {
        return [string]$AccessLogEntry.ClientHost
    }
    $clientAddr = [string]$AccessLogEntry.ClientAddr
    if ($clientAddr -match '^\[(.+)\]:\d+$') {
        return $Matches[1]
    }
    if ($clientAddr -match '^(.+):\d+$') {
        return $Matches[1]
    }
    return $clientAddr
}

# Get-WafAuditLogRecords reads JSON audit lines from the waf container (not Traefik access.log).
function Get-WafAuditLogRecords {
    param(
        [Parameter(Mandatory)]
        [string]$WafContainerName
    )

    $auditLogPath = Get-WafAuditLogPath -WafContainerName $WafContainerName
    $auditLogContent = docker exec $WafContainerName cat $auditLogPath 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read WAF audit log $auditLogPath from container: $WafContainerName"
    }

    $logLines = $auditLogContent -split "`n" | Where-Object { $_.Trim() -ne "" }
    $records = @()
    foreach ($line in $logLines) {
        try {
            $records += ($line | ConvertFrom-Json)
        } catch {
            # Skip malformed JSON lines
        }
    }
    return $records
}

# Get-WafAuditClientIp returns REMOTE_ADDR as logged.
# Apache CRS 4.3 JSON: transaction.remote_address. nginx CRS 4.3 JSON: transaction.client_ip.
function Get-WafAuditClientIp {
    param(
        [Parameter(Mandatory)]
        $AuditRecord
    )

    $candidates = @(
        $AuditRecord.transaction.remote_address,
        $AuditRecord.transaction.client_ip,
        $AuditRecord.transaction.remote_addr,
        $AuditRecord.transaction.client.ip
    )
    foreach ($value in $candidates) {
        if ($value) {
            return [string]$value
        }
    }
    return $null
}

# Get-WafAuditRequestUri returns the request line used to match a deny to its audit record.
function Get-WafAuditRequestUri {
    param(
        [Parameter(Mandatory)]
        $AuditRecord
    )

    $candidates = @(
        $AuditRecord.request.request_line,
        $AuditRecord.transaction.request.request_line,
        $AuditRecord.transaction.request.uri,
        $AuditRecord.request.uri
    )
    foreach ($value in $candidates) {
        if ($value) {
            return [string]$value
        }
    }
    return $null
}

# Get-WafAuditHost returns the Host CRS logged.
# Apache CRS 4.3 JSON: request.headers.Host. nginx CRS 4.3 JSON: transaction.request.headers.Host.
function Get-WafAuditHost {
    param(
        [Parameter(Mandatory)]
        $AuditRecord
    )

    $candidates = @(
        $AuditRecord.request.headers.Host,
        $AuditRecord.transaction.request.headers.Host,
        $AuditRecord.request.headers.host,
        $AuditRecord.transaction.request.headers.host
    )
    foreach ($value in $candidates) {
        if ($value) {
            return [string]$value
        }
    }
    return $null
}

function New-RequestBodyOfSizeBytes {
    param(
        [Parameter(Mandatory)]
        [int]$TargetSizeBytes,
        [string]$Prefix = "data="
    )

    if ($TargetSizeBytes -le 0) {
        throw "TargetSizeBytes must be positive, got $TargetSizeBytes."
    }

    $encoding = [System.Text.Encoding]::UTF8
    $prefixLength = $encoding.GetByteCount($Prefix)

    if ($TargetSizeBytes -lt $prefixLength) {
        throw "TargetSizeBytes ($TargetSizeBytes) is smaller than prefix byte length ($prefixLength)."
    }

    $payloadLength = $TargetSizeBytes - $prefixLength
    return $Prefix + ("a" * $payloadLength)
}

function Get-LastAccessLogEntryForPath {
    param(
        [Parameter(Mandatory)]
        [array]$Entries,
        [Parameter(Mandatory)]
        [string]$PathPrefix
    )

    $matches = $Entries | Where-Object { $_.RequestPath -like "$PathPrefix*" }
    if (-not $matches -or $matches.Count -eq 0) {
        return $null
    }

    return $matches[-1]
}

<#
.SYNOPSIS
    Tests if a request is blocked by WAF

.DESCRIPTION
    Attempts a potentially malicious request and verifies it gets blocked
    with an appropriate HTTP error status

.PARAMETER Url
    The URL to test (should include malicious payload)

.PARAMETER ExpectedMinStatus
    Minimum expected HTTP status code for blocked requests (default: 400)
#>
function Test-WafBlocking {
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [int]$ExpectedMinStatus = 400
    )

    # Invoke-SafeWebRequest is configured to skip HTTP error checks, so it will return
    # a response object even for 4xx/5xx statuses. We can assert directly on the status code.
    $response = Invoke-SafeWebRequest -Uri $Url
    $statusCode = [int]$response.StatusCode

    $statusCode | Should -BeGreaterOrEqual $ExpectedMinStatus -Because "Malicious requests should be blocked by WAF"
    Write-Host "✅ WAF blocked request with status: $statusCode" -ForegroundColor Green
    return $statusCode
}

<#
.SYNOPSIS
    Tests multiple malicious patterns to ensure they're blocked

.PARAMETER BaseUrl
    Base URL for the protected endpoint

.PARAMETER Patterns
    Array of malicious query string patterns to test
#>
function Test-MaliciousPatterns {
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [Parameter(Mandatory)]
        [array]$Patterns
    )
    
    foreach ($pattern in $Patterns) {
        $testUrl = "$BaseUrl$pattern"
        Test-WafBlocking -Url $testUrl
        Write-Host "✅ Pattern blocked: $pattern" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Tests multiple patterns to ensure they're allowed through

.PARAMETER BaseUrl
    Base URL for the bypass endpoint

.PARAMETER Patterns
    Array of query string patterns that should be allowed
#>
function Test-BypassPatterns {
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [Parameter(Mandatory)]
        [array]$Patterns
    )
    
    foreach ($pattern in $Patterns) {
        $bypassUrl = "$BaseUrl$pattern"
        $response = Invoke-SafeWebRequest -Uri $bypassUrl
        $response.StatusCode | Should -Be 200
        Write-Host "✅ Bypass allowed: $pattern" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Measures response time for a given endpoint

.PARAMETER Url
    URL to test response time for

.PARAMETER MaxResponseTimeMs
    Maximum acceptable response time in milliseconds
#>
function Test-ResponseTime {
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [int]$MaxResponseTimeMs = 5000
    )
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $response = Invoke-SafeWebRequest -Uri $Url
    $stopwatch.Stop()
    
    $response.StatusCode | Should -Be 200
    $stopwatch.ElapsedMilliseconds | Should -BeLessThan $MaxResponseTimeMs
    
    Write-Host "Response time: $($stopwatch.ElapsedMilliseconds)ms" -ForegroundColor Cyan
    return $stopwatch.ElapsedMilliseconds
}



function Get-ReclaimDynamicConfigPath {
    # Host path of the file-provider fixture Traefik watches (two routers, one waf-reclaim).
    return Join-Path (Split-Path $PSScriptRoot -Parent) "test-dynamic/reclaim.yml"
}

function Get-TraefikStdoutLines {
    param(
        [Parameter(Mandatory)]
        [string]$TraefikContainerName
    )

    # Plugin slog is remapped onto Traefik process logs (Yaegi stdout → Traefik DEBUG).
    $raw = docker logs $TraefikContainerName 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read Traefik stdout from container: $TraefikContainerName"
    }

    return @($raw | ForEach-Object { "$_" })
}

function Get-ReclaimLogEvents {
    param(
        [Parameter(Mandatory)]
        [string]$TraefikContainerName,
        [Parameter(Mandatory)]
        [string]$Middleware,
        [string]$Message
    )

    # slog text: msg=reclaim_put middleware=waf-reclaim@file key=plugin:waf-reclaim@file:…
    $events = @()
    foreach ($line in (Get-TraefikStdoutLines -TraefikContainerName $TraefikContainerName)) {
        $text = "$line"
        if ($text -notlike "*$Middleware*") {
            continue
        }
        if ($text -notmatch 'msg=(?<msg>reclaim_\w+)') {
            continue
        }
        $msg = $Matches['msg']
        if ($Message -and $msg -ne $Message) {
            continue
        }
        $key = $null
        if ($text -match 'key=(?<key>\S+)') {
            $key = $Matches['key'].Trim('"')
        }
        $events += [pscustomobject]@{
            Message = $msg
            Key     = $key
            Line    = $text
        }
    }

    return @($events)
}

function Wait-ReclaimLogCount {
    param(
        [Parameter(Mandatory)]
        [string]$TraefikContainerName,
        [Parameter(Mandatory)]
        [string]$Middleware,
        [Parameter(Mandatory)]
        [string]$Message,
        [Parameter(Mandatory)]
        [int]$Count,
        [int]$TimeoutSeconds = 30
    )

    $elapsed = 0
    $events = @()
    do {
        $events = @(Get-ReclaimLogEvents -TraefikContainerName $TraefikContainerName -Middleware $Middleware -Message $Message)
        if ($events.Count -ge $Count) {
            return $events
        }
        Start-Sleep -Seconds 1
        $elapsed += 1
    } while ($elapsed -lt $TimeoutSeconds)

    throw "Timed out waiting for $Count $Message line(s) for middleware $Middleware (saw $($events.Count))"
}

function Set-ReclaimDynamicTimeoutMillis {
    param(
        [Parameter(Mandatory)]
        [int]$TimeoutMillis,
        [Parameter(Mandatory)]
        [string]$TraefikContainerName
    )

    # Rewrite the watched YAML so Traefik rebuilds waf-reclaim (new plugin key). Touch kicks inotify on bind mounts.
    $path = Get-ReclaimDynamicConfigPath
    $template = @'
# File-provider middleware shared by two routers. Tests rewrite timeoutMillis to force a new reclaim key.
http:
  routers:
    reclaim-a:
      rule: "PathPrefix(`/reclaim-a`)"
      entryPoints:
        - web
      service: reclaim-whoami
      middlewares:
        - waf-reclaim
    reclaim-b:
      rule: "PathPrefix(`/reclaim-b`)"
      entryPoints:
        - web
      service: reclaim-whoami
      middlewares:
        - waf-reclaim
  services:
    reclaim-whoami:
      loadBalancer:
        servers:
          - url: http://whoami-reclaim:80
  middlewares:
    waf-reclaim:
      plugin:
        traefik-modsecurity:
          modSecurityUrl: http://waf:8080
          timeoutMillis: __TIMEOUT__
          logLevel: debug
'@
    $yaml = $template.Replace('__TIMEOUT__', "$TimeoutMillis")
    $yaml = $yaml -replace "`r`n", "`n"
    if (-not $yaml.EndsWith("`n")) {
        $yaml += "`n"
    }
    [System.IO.File]::WriteAllText($path, $yaml)
    docker exec $TraefikContainerName touch /etc/traefik/dynamic/reclaim.yml
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to touch reclaim.yml in container: $TraefikContainerName"
    }
}

<#
.SYNOPSIS
    Opens a WebSocket, sends one text frame, and returns the echoed payload.

.DESCRIPTION
    Uses System.Net.WebSockets.ClientWebSocket so the test drives a real
    RFC 6455 handshake (GET, Connection: upgrade, Upgrade: websocket, Key, Version)
    through Traefik and this plugin, then checks the backend still speaks frames.

.PARAMETER Uri
    WebSocket URL (ws://host/path).

.PARAMETER Message
    Text frame to send.

.PARAMETER TimeoutSec
    Connect/send/receive deadline.
#>
function Invoke-WebSocketEcho {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [string]$Message,
        [int]$TimeoutSec = 10
    )

    $ws = [System.Net.WebSockets.ClientWebSocket]::new()
    $cts = [System.Threading.CancellationTokenSource]::new()
    $cts.CancelAfter([TimeSpan]::FromSeconds($TimeoutSec))
    try {
        $null = $ws.ConnectAsync([Uri]$Uri, $cts.Token).GetAwaiter().GetResult()
        if ($ws.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
            throw "WebSocket connect finished in state $($ws.State)"
        }

        $sendBytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
        $sendSegment = [System.ArraySegment[byte]]::new($sendBytes)
        $null = $ws.SendAsync(
            $sendSegment,
            [System.Net.WebSockets.WebSocketMessageType]::Text,
            $true,
            $cts.Token
        ).GetAwaiter().GetResult()

        $recvBuffer = [byte[]]::new(4096)
        $recvSegment = [System.ArraySegment[byte]]::new($recvBuffer)
        $echoed = $null
        while ($true) {
            $received = $ws.ReceiveAsync($recvSegment, $cts.Token).GetAwaiter().GetResult()
            if ($received.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
                throw "WebSocket closed before the payload was echoed"
            }
            $text = [System.Text.Encoding]::UTF8.GetString($recvBuffer, 0, $received.Count)
            # echo-server writes an empty or hostname greeting before it echoes.
            if ($text -eq $Message) {
                $echoed = $text
                break
            }
        }

        $null = $ws.CloseAsync(
            [System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure,
            "done",
            $cts.Token
        ).GetAwaiter().GetResult()

        return $echoed
    }
    finally {
        $ws.Dispose()
        $cts.Dispose()
    }
}

# Helper functions are available when dot-sourced
# No Export-ModuleMember needed for dot-sourcing
