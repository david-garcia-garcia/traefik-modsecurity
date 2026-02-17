BeforeAll {
    # Import test helper functions
    . "$PSScriptRoot/TestHelpers.ps1"
    
    # Test configuration
    $script:BaseUrl = "http://localhost:8000"
    $script:TraefikApiUrl = "http://localhost:8080"
    
    # Find the Traefik container name dynamically after services are ready.
    $script:traefikContainer = docker ps --filter "name=traefik-modsecurity-plugin-traefik" --format "{{.Names}}" | Select-Object -First 1
    if (-not $script:traefikContainer) {
        throw "Traefik container not found"
    }
    Write-Host "Using Traefik container: $script:traefikContainer" -ForegroundColor Cyan

    # Find the WAF container and wait for it to become healthy.
    $script:wafContainer = docker ps --filter "name=traefik-modsecurity-plugin-waf" --format "{{.Names}}" | Select-Object -First 1
    if (-not $script:wafContainer) {
        throw "WAF container not found"
    }
    Write-Host "Using WAF container: $script:wafContainer" -ForegroundColor Cyan

    Write-Host "Waiting for WAF container health..." -ForegroundColor Cyan
    $maxWaitSeconds = 90
    $elapsed = 0
    do {
        $health = docker inspect --format "{{.State.Health.Status}}" $script:wafContainer 2>$null
        if ($health -eq "healthy") {
            Write-Host "✅ WAF container is healthy" -ForegroundColor Green
            break
        }
        Start-Sleep -Seconds 3
        $elapsed += 3
    } while ($elapsed -lt $maxWaitSeconds)
    if ($health -ne "healthy") {
        throw "WAF container did not become healthy within ${maxWaitSeconds}s (status='$health')"
    }

    # Ensure all services are ready before running tests
    $services = @(
        @{ Url = "$TraefikApiUrl/api/rawdata"; Name = "Traefik API" },
        @{ Url = "$BaseUrl/protected"; Name = "Protected service" },
        @{ Url = "$BaseUrl/pool-test"; Name = "Pool test service" }
    )
    
    Wait-ForAllServices -Services $services
}

Describe "MaxBodySizeBytes Configuration Tests (Large Bodies)" {
    Context "Body Size Limit Enforcement - Large Bodies" {
        It "Should properly enforce body size limit for large requests near the limit" {
            # Using 16MB body with 20MB limit (as reported in the issue)
            $bodySizeMB = 16
            $bodySizeBytes = $bodySizeMB * 1024 * 1024
            $largeData = "data=" + ("a" * ($bodySizeBytes - 5))  # 16MB - 5 bytes to stay under limit
            
            try {
                $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body $largeData -TimeoutSec 60
                $response.StatusCode | Should -Be 200 -Because "16MB request should be allowed when limit is 20MB"
            } catch {
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    if ($statusCode -eq 413) {
                        throw "16MB request was rejected with 413, but it should be within a 20MB limit"
                    }
                }
                throw "Unexpected error: $($_.Exception.Message)"
            }
        }
        
        It "Should reject requests exceeding body size limit (large body)" {
            $bodySizeMB = 21  # Exceeds 20MB limit
            $bodySizeBytes = $bodySizeMB * 1024 * 1024
            $largeData = "data=" + ("a" * ($bodySizeBytes - 5))  # 21MB - 5 bytes
            
            try {
                $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body $largeData -TimeoutSec 60
                throw "Expected HTTP 413 Request Entity Too Large for 21MB request with 20MB limit"
            } catch {
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    $statusCode | Should -Be 413 -Because "21MB request should be rejected when limit is 20MB"
                } else {
                    $errorMessage = $_.Exception.Message
                    if ($errorMessage -notlike "*413*" -and $errorMessage -notlike "*Request Entity Too Large*" -and $errorMessage -notlike "*body too large*") {
                        throw "Expected 413 error for oversized request, got: $errorMessage"
                    }
                }
            }
        }
    }
}

Describe "Body Size Limit Tests - usePool=false Path" {
    # The pool-test service has maxBodySizeBytesForPool=1024 (1KB) and maxBodySizeBytes=5120 (5KB)
    # This means requests with Content-Length > 1KB will use the usePool=false path
    
    Context "Body Size Limit Enforcement when usePool=false" {
        It "Should allow requests within limit that trigger usePool=false path" {
            # 2KB body - within 5KB limit but > 1KB pool threshold, so triggers usePool=false
            $bodySize = 2 * 1024  # 2KB
            $bodyData = "data=" + ("a" * ($bodySize - 5))  # 2KB - 5 bytes
            
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/pool-test" -Method POST -Body $bodyData -TimeoutSec 10
            $response.StatusCode | Should -Be 200 -Because "2KB body should pass (within 5KB limit, triggers usePool=false)"
        }
        
        It "Should reject requests exceeding limit when usePool=false" {
            # 6KB body - exceeds 5KB limit and > 1KB pool threshold, so triggers usePool=false
            $bodySize = 6 * 1024  # 6KB
            $bodyData = "data=" + ("a" * ($bodySize - 5))  # 6KB - 5 bytes
            
            try {
                $response = Invoke-SafeWebRequest -Uri "$BaseUrl/pool-test" -Method POST -Body $bodyData -TimeoutSec 10
                throw "Expected HTTP 413 Request Entity Too Large for 6KB request with 5KB limit, but got status $($response.StatusCode)"
            } catch {
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    $statusCode | Should -Be 413 -Because "6KB body should be rejected (exceeds 5KB limit, triggers usePool=false)"
                } else {
                    $errorMessage = $_.Exception.Message
                    if ($errorMessage -notlike "*413*" -and $errorMessage -notlike "*Request Entity Too Large*" -and $errorMessage -notlike "*body too large*") {
                        throw "Expected 413 error for oversized request, got: $errorMessage"
                    }
                }
            }
        }
        
        It "Should allow requests exactly at limit when usePool=false" {
            # 5KB body - exactly at limit, > 1KB pool threshold, so triggers usePool=false
            $bodySize = 5 * 1024  # 5KB
            $bodyData = "data=" + ("a" * ($bodySize - 5))  # 5KB - 5 bytes
            
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/pool-test" -Method POST -Body $bodyData -TimeoutSec 10
            $response.StatusCode | Should -Be 200 -Because "5KB body should pass (exactly at limit, triggers usePool=false)"
        }
    }
    
    Context "Backend call verification" {
        It "Should verify backend is NOT called when request exceeds limit (usePool=false)" {
            $bodySize = 6 * 1024  # 6KB - exceeds 5KB limit
            $bodyData = "data=" + ("a" * ($bodySize - 5))
            
            try {
                $null = Invoke-SafeWebRequest -Uri "$BaseUrl/pool-test" -Method POST -Body $bodyData -TimeoutSec 10
            } catch {
                # expected
            }
            
            Start-Sleep -Seconds 2
            
            $accessLogContent = docker exec $script:traefikContainer cat /var/log/traefik/access.log 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to read traefik access log"
            }
            
            $logLines = $accessLogContent -split "`n" | Where-Object { $_.Trim() -ne "" }
            $poolTestEntries = @()
            foreach ($line in $logLines) {
                try {
                    $logEntry = $line | ConvertFrom-Json
                    if ($logEntry.RequestPath -like "/pool-test*") {
                        $poolTestEntries += $logEntry
                    }
                } catch { }
            }
            
            $poolTestEntries.Count | Should -BeGreaterThan 0 -Because "We should have at least one /pool-test entry in access logs"
            $latestEntry = $poolTestEntries[-1]
            $latestEntry.DownstreamStatus | Should -Be 413 -Because "Oversized request should be rejected before reaching backend"
        }
    }
}

