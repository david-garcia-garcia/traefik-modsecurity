BeforeAll {
    # Import test helper functions
    . "$PSScriptRoot/TestHelpers.ps1"
    
    # Test configuration
    $script:BaseUrl = "http://localhost:8000"
    $script:TraefikApiUrl = "http://localhost:8080"
    
    # Find containers and wait for WAF health using helpers.
    $script:traefikContainer = Get-TraefikContainerName
    Write-Host "Using Traefik container: $script:traefikContainer" -ForegroundColor Cyan

    $script:wafContainer = Get-WafContainerName
    Write-Host "Using WAF container: $script:wafContainer" -ForegroundColor Cyan

    Wait-ForWafHealthy -ContainerName $script:wafContainer

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
        It "Should handle 16MB request near 20MB limit without 5xx transport errors" {
            # Using 16MB body against a middleware configured with a 20MB limit on /large-body-test.
            # The purpose of this integration test is to ensure that large bodies near the limit
            # do not trigger the historical Content-Length/body mismatch bug that produced 5xx
            # transport errors from Traefik. Exact allow/deny semantics are covered by Go unit tests.
            $largeData = New-RequestBodyOfSizeBytes -TargetSizeBytes (16 * 1024 * 1024)
            
            try {
                $response = Invoke-SafeWebRequest -Uri "$BaseUrl/large-body-test" -Method POST -Body $largeData -TimeoutSec 60
                $statusCode = [int]$response.StatusCode
                $statusCode | Should -BeLessThan 500 -Because "16MB request near the limit should not cause a 5xx transport error"
            } catch {
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    $statusCode | Should -BeLessThan 500 -Because "16MB request near the limit should not cause a 5xx transport error"
                } else {
                    throw "Unexpected error for 16MB request: $($_.Exception.Message)"
                }
            }
        }
        
        It "Should reject requests exceeding body size limit (large body)" {
            # 21MB body - exceeds 20MB limit
            $largeData = New-RequestBodyOfSizeBytes -TargetSizeBytes (21 * 1024 * 1024)
            
            try {
                $null = Invoke-SafeWebRequest -Uri "$BaseUrl/large-body-test" -Method POST -Body $largeData -TimeoutSec 60
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

Describe "MaxBodySizeBytes Status Header Tests" {
    Context "Pooled path body size enforcement (/protected)" {
        It "Should mark 413 body-too-large responses as blocked in access logs (usePool=true)" {
            # First, send a small request that should pass to verify the happy path.
            $smallBody = New-RequestBodyOfSizeBytes -TargetSizeBytes 512  # Below 1KB limit
            $smallResponse = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body $smallBody -TimeoutSec 10
            $smallResponse.StatusCode | Should -Be 200 -Because "Requests within maxBodySizeBytes should be accepted"

            # Now send an oversized body that exceeds the 1KB limit but still uses the pooled path.
            $body = New-RequestBodyOfSizeBytes -TargetSizeBytes 2000

            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body $body -TimeoutSec 10
            $response.StatusCode | Should -Be 413 -Because "Requests exceeding maxBodySizeBytes should be rejected with HTTP 413"

            Start-Sleep -Seconds 2

            $entries = Get-TraefikAccessLogEntries -TraefikContainerName $script:traefikContainer
            $latestEntry = Get-LastAccessLogEntryForPath -Entries $entries -PathPrefix "/protected"

            $latestEntry | Should -Not -BeNullOrEmpty -Because "We should have at least one /protected entry in access logs"
            $latestEntry.DownstreamStatus | Should -Be 413 -Because "Oversized request should be rejected before reaching backend"
            $latestEntry.'request_X-Waf-Status' | Should -Be "blocked" -Because "Middleware body size enforcement should be logged as blocked (pooled path)"
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
                if ($size -lt 1) { continue }

                $body = New-RequestBodyOfSizeBytes -TargetSizeBytes $size
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
            $bodyData = New-RequestBodyOfSizeBytes -TargetSizeBytes (6 * 1024)  # 6KB - exceeds 5KB limit

            # Send request and capture HTTP status without treating non-2xx as an exception.
            # Invoke-SafeWebRequest is configured to skip HTTP error checks and only throw on
            # real transport errors.
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/pool-test" -Method POST -Body $bodyData -TimeoutSec 10
            $response.StatusCode | Should -Be 413 -Because "Oversized request should be rejected with HTTP 413"
            
            Start-Sleep -Seconds 2
            
            $entries = Get-TraefikAccessLogEntries -TraefikContainerName $script:traefikContainer
            $latestEntry = Get-LastAccessLogEntryForPath -Entries $entries -PathPrefix "/pool-test"
            
            $latestEntry | Should -Not -BeNullOrEmpty -Because "We should have at least one /pool-test entry in access logs"
            $latestEntry.DownstreamStatus | Should -Be 413 -Because "Oversized request should be rejected before reaching backend"
            $latestEntry.'request_X-Waf-Status' | Should -Be "blocked" -Because "MaxBodySizeBytes enforcement in middleware should be logged as blocked"
        }
    }
}

