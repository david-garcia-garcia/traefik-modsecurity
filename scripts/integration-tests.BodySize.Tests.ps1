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
        It "Should exercise pooled vs non-pooled paths across boundary sizes" {
            # Current docker-compose.test.yml config for pool-test:
            # - maxBodySizeBytes=5120 (5KB)
            # - maxBodySizeBytesForPool=1024 (1KB)
            #
            # We cover 5 sizes:
            # 1)  <  poolThreshold       -> pooled, should be 200
            # 2) ==  poolThreshold       -> pooled, should be 200
            # 3)  >  poolThreshold < max -> non-pooled, should be 200 (desired behaviour)
            # 4) ==  maxBodySize         -> non-pooled, should be 200
            # 5)  >  maxBodySize         -> non-pooled, should be 413
            $poolThreshold = 1024
            $maxBody = 5120

            $cases = @(
                [pscustomobject]@{
                    Name           = "below pool threshold"
                    Size           = $poolThreshold - 10
                    ExpectedStatus = 200
                },
                [pscustomobject]@{
                    Name           = "exactly at pool threshold"
                    Size           = $poolThreshold
                    ExpectedStatus = 200
                },
                [pscustomobject]@{
                    Name           = "above pool threshold but below max"
                    Size           = $poolThreshold + 10
                    ExpectedStatus = 200
                },
                [pscustomobject]@{
                    Name           = "exactly at max body size"
                    Size           = $maxBody
                    ExpectedStatus = 200
                },
                [pscustomobject]@{
                    Name           = "above max body size"
                    Size           = $maxBody + 10
                    ExpectedStatus = 413
                }
            )

            foreach ($case in $cases) {
                $size = [int]$case.Size
                if ($size -lt 1) {
                    continue
                }

                $body = "data=" + ("a" * ([Math]::Max($size - 5, 1)))
                $status = $null
                try {
                    $resp = Invoke-SafeWebRequest -Uri "$BaseUrl/pool-test" -Method POST -Body $body -TimeoutSec 10
                    $status = [int]$resp.StatusCode
                } catch {
                    if ($_.Exception.Response) {
                        $status = [int]$_.Exception.Response.StatusCode
                    } else {
                        throw ("Unexpected error for '{0}' (size={1}): {2}" -f $case.Name, $size, $_.Exception.Message)
                    }
                }

                $status | Should -Be $case.ExpectedStatus -Because ("'{0}' (size={1}) should return {2}, got {3}" -f $case.Name, $size, $case.ExpectedStatus, $status)
            }
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

