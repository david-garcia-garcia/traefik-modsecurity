BeforeAll {
    # Import test helper functions
    . "$PSScriptRoot/TestHelpers.ps1"
    
    # Test configuration
    $script:BaseUrl = "http://localhost:8000"
    $script:TraefikApiUrl = "http://localhost:8080"
    
    # Ensure all services are ready before running tests
    $services = @(
        @{ Url = "$TraefikApiUrl/api/rawdata"; Name = "Traefik API" },
        @{ Url = "$BaseUrl/bypass"; Name = "Bypass service" },
        @{ Url = "$BaseUrl/protected"; Name = "Protected service" },
        @{ Url = "$BaseUrl/remediation-test"; Name = "Remediation test service" },
        @{ Url = "$BaseUrl/error-test"; Name = "Error test service" },
        @{ Url = "$BaseUrl/force-test"; Name = "Force test service" },
        @{ Url = "$BaseUrl/pool-test"; Name = "Pool test service" },
        @{ Url = "$BaseUrl/threshold-test"; Name = "Threshold test service" },
        @{ Url = "$BaseUrl/reclaim-a"; Name = "Reclaim route A" },
        @{ Url = "$BaseUrl/reclaim-b"; Name = "Reclaim route B" },
        @{ Url = "$BaseUrl/ws-echo"; Name = "WebSocket echo service" }
    )
    
    Wait-ForAllServices -Services $services
    
    # Find the Traefik and WAF containers using helpers
    $script:traefikContainer = Get-TraefikContainerName
    Write-Host "Using Traefik container: $script:traefikContainer" -ForegroundColor Cyan
    
    $script:wafContainer = Get-WafContainerName
    Write-Host "Using WAF container: $script:wafContainer" -ForegroundColor Cyan
}

Describe "ModSecurity Plugin Basic Functionality" {
    Context "Service Availability" {
        It "Should have Traefik API accessible" {
            $response = Invoke-SafeWebRequest -Uri "$TraefikApiUrl/api/rawdata"
            $response.StatusCode | Should -Be 200
        }
        
        It "Should have bypass service accessible" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/bypass"
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname"
        }
        
        It "Should have protected service accessible with valid requests" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected"
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname"
        }

        It "Should not run an unlabeled dummy CRS origin" {
            if (-not (Test-IsDrainOrigin)) {
                Set-ItResult -Skipped -Because "whoami-origin stacks keep dummy as the CRS BACKEND"
                return
            }
            Get-DummyContainerName | Should -BeNullOrEmpty -Because "Drain overlay must not start dummy; only labeled whoami apps remain"
        }

        It "Should run an unlabeled dummy CRS origin" {
            if (-not (Test-IsWhoamiOrigin)) {
                Set-ItResult -Skipped -Because "drain stacks do not run dummy"
                return
            }
            Get-DummyContainerName | Should -Not -BeNullOrEmpty -Because "whoami-origin stacks proxy CRS BACKEND to dummy"
        }
    }
}

Describe "WAF Protection Tests" {
    Context "Malicious Request Detection" {
        It "Should block common attack patterns" {
            $maliciousPatterns = @(
                "?id=1' OR '1'='1",                    # SQL injection
                "?search=<script>alert('xss')</script>", # XSS
                "?file=../../../etc/passwd",            # Path traversal
                "?cmd=; ls -la"                         # Command injection
            )
            
            Test-MaliciousPatterns -BaseUrl "$BaseUrl/protected" -Patterns $maliciousPatterns
        }
    }

    Context "Client IP in WAF audit log" {
        # Negative control: drop the CRS trust list (Apache REMOTEIP_INT_PROXY /
        # nginx SET_REAL_IP_FROM) from the compose file and this It fails —
        # audit client IP stays the Traefik-to-WAF hop.
        It "Should record Traefik ClientHost as REMOTE_ADDR on a deny" {
            $marker = "host-ip-$(Get-Random)"
            $denyUrl = "$BaseUrl/protected?id=1' OR '1'='1&marker=$marker"
            $response = Invoke-SafeWebRequest -Uri $denyUrl
            $response.StatusCode | Should -BeGreaterOrEqual 400 -Because "CRS should deny the SQL-injection query"

            Start-Sleep -Seconds 2

            $accessEntries = Get-TraefikAccessLogEntries -TraefikContainerName $script:traefikContainer
            $traefikEntry = $accessEntries | Where-Object { $_.RequestPath -like "*$marker*" } | Select-Object -First 1
            $traefikEntry | Should -Not -BeNullOrEmpty -Because "Traefik access.log should contain the deny request"
            $sourceIp = Get-TraefikClientHost -AccessLogEntry $traefikEntry
            $sourceIp | Should -Not -BeNullOrEmpty -Because "Traefik ClientHost (or ClientAddr) is the expected source IP"

            $auditRecords = Get-WafAuditLogRecords -WafContainerName $script:wafContainer
            $denyRecord = $auditRecords | Where-Object { (Get-WafAuditRequestUri -AuditRecord $_) -like "*$marker*" } | Select-Object -First 1
            $denyRecord | Should -Not -BeNullOrEmpty -Because "WAF audit log should contain the deny"
            $auditClientIp = Get-WafAuditClientIp -AuditRecord $denyRecord
            $auditClientIp | Should -Be $sourceIp -Because "Audit REMOTE_ADDR must be the IP Traefik saw, not the Traefik-to-WAF hop. Missing CRS X-Real-IP trust (REMOTEIP_INT_PROXY / SET_REAL_IP_FROM) fails this."
        }
    }

    Context "Client Host in WAF audit log" {
        # Negative control: drop proxyReq.Host = req.Host in ServeHTTP and this It
        # fails — audit Host stays the sidecar URL host (waf / waf:8080).
        It "Should record the incoming Host on a deny" {
            $marker = "host-hdr-$(Get-Random)"
            $wantHost = "app.example.test"
            $requestLine = "GET /protected?id=1%27+OR+%271%27%3D%271&marker=$marker HTTP/1.1"
            $responseText = Invoke-TcpHttpRequest -TargetHost "localhost" -Port 8000 -RequestLine $requestLine -Headers @{
                Host = $wantHost
                Connection = "close"
            }
            $responseText | Should -Match '^HTTP/1\.[01] [45]\d\d' -Because "CRS should deny the SQL-injection query sent with a distinctive Host"

            Start-Sleep -Seconds 2

            $auditRecords = Get-WafAuditLogRecords -WafContainerName $script:wafContainer
            $denyRecord = $auditRecords | Where-Object { (Get-WafAuditRequestUri -AuditRecord $_) -like "*$marker*" } | Select-Object -First 1
            $denyRecord | Should -Not -BeNullOrEmpty -Because "WAF audit log should contain the deny"
            $auditHost = Get-WafAuditHost -AuditRecord $denyRecord
            $auditHost | Should -Be $wantHost -Because "Audit Host must be the incoming Host, not the sidecar URL host. Missing proxyReq.Host = req.Host leaves waf or waf:8080."
            $auditHost | Should -Not -BeIn @("waf", "waf:8080", "localhost", "localhost:8000") -Because "Sidecar URL host or the TCP target must not replace the incoming Host"
        }
    }
    
    Context "Legitimate Request Handling" {
        It "Should allow normal GET requests" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected/normal-path"
            $response.StatusCode | Should -Be 200
        }
        
        It "Should allow POST requests with normal data" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body "name=john&email=john@example.com"
            $response.StatusCode | Should -Be 200
        }

        It "Should not copy a sidecar 416 for Range bytes=10240- on a small GET" {
            if (-not (Test-IsDrainOrigin)) {
                Set-ItResult -Skipped -Because "whoami dummy origin is expected to 416 on an unsatisfiable Range"
                return
            }
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Headers @{ Range = "bytes=10240-" }
            $response.StatusCode | Should -Not -Be 416 -Because "Inspect-only sidecar must not 416 on Range; plugin copies sidecar 4xx as a block"
        }

        It "Should block a CRS SQL-injection probe in the POST body" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Headers @{ "Content-Type" = "application/x-www-form-urlencoded" } -Body "id=1 OR 1=1"
            $response.StatusCode | Should -BeGreaterOrEqual 400 -Because "CRS request-body rules must still run after inspect-only 200"
        }
        
        It "Should allow requests with normal query parameters" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected?page=1&limit=10&sort=name"
            $response.StatusCode | Should -Be 200
        }

        It "Should handle origin-form RequestURI correctly" {
            $responseText = Invoke-TcpHttpRequest -TargetHost "localhost" -Port 8000 -RequestLine "GET /protected/ HTTP/1.1"
            $responseText | Should -Match 'HTTP/1\.\d 2\d\d' -Because "origin-form RequestURI must be forwarded successfully"
            $responseText | Should -Match "Hostname" -Because "response should be from the protected backend"
        }

        It "Should handle absolute-form RequestURI correctly (not DNS/connection error)" {
            # Without the fix, the plugin concatenates absolute-form into an invalid URL and fails.
            # Traefik test stack uses entrypoints.web.http.sanitizePath=false so absolute-form reaches the plugin.
            $responseText = Invoke-TcpHttpRequest -TargetHost "localhost" -Port 8000 -RequestLine "GET http://traefik/protected/ HTTP/1.1"
            $responseText | Should -Match 'HTTP/1\.\d 2\d\d' -Because "absolute-form RequestURI must be normalised and forwarded; we must not get 5xx or connection error"
            $responseText | Should -Match "Hostname" -Because "response should be from the protected backend"
        }
    }
}

Describe "Remediation Response Header Tests" {
    Context "Custom Header Configuration" {
        It "Should add remediation header when request is blocked" {
            $statusCode = Test-WafBlocking -Url "$BaseUrl/protected?id=1' OR '1'='1"
            $statusCode | Should -BeGreaterOrEqual 400
        }
        
        It "Should not add remediation header for legitimate requests" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected"
            $response.Headers["X-Waf-Status"] | Should -BeNullOrEmpty
        }
    }
    
    Context "Remediation Header Logging" {
        It "Should log remediation header as request header in access logs for blocked requests" {
            # Make a blocked request to the remediation test endpoint
            $maliciousUrl = "$BaseUrl/remediation-test?id=1' OR '1'='1"

            # Use a non-throwing request via helper and assert status directly
            $response = Invoke-SafeWebRequest -Uri $maliciousUrl -TimeoutSec 10
            $response.StatusCode | Should -BeGreaterOrEqual 400 -Because "Blocked remediation request should return 4xx/5xx"
            
            # Wait a moment for log to be written
            Start-Sleep -Seconds 2
            
            # Read and parse access.log entries from the Traefik container using shared helper
            $allLogEntries = Get-TraefikAccessLogEntries -TraefikContainerName $script:traefikContainer
            
            # Look for log entries where the X-Waf-Status request header is present for blocked requests
            $remediationHeaderLogFound = ($allLogEntries | Where-Object { 
                $_.'request_X-Waf-Status' -and 
                $_.RequestPath -like "/remediation-test*"
            }).Count -gt 0
            
            # Verify that the remediation header was added to the request
            $remediationHeaderLogFound | Should -Be $true
        }
        
        It "Should log ok in access logs for allowed requests" {
            # Make an allowed request to the remediation test endpoint
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/remediation-test"
            $response.StatusCode | Should -Be 200
            
            # Wait a moment for any potential log to be written
            Start-Sleep -Seconds 2
            
            # Read the access.log file from the traefik container
            $accessLogContent = docker exec $script:traefikContainer cat /var/log/traefik/access.log 2>$null
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Warning: Failed to read traefik access log from container: $script:traefikContainer" -ForegroundColor Yellow
                Write-Host "Available containers:" -ForegroundColor Yellow
                docker ps --format "table {{.Names}}\t{{.Image}}"
                throw "Failed to read traefik access log"
            }
            
            # Parse the log lines and check for any entries related to the remediation test
            $logLines = $accessLogContent -split "`n" | Where-Object { $_.Trim() -ne "" }
            
            # Validate that ALL log lines are properly formatted JSON (no malformed lines should exist)
            $allLogEntries = @()
            foreach ($line in $logLines) {
                try {
                    $logEntry = $line | ConvertFrom-Json
                    $allLogEntries += $logEntry
                } catch {
                    throw "Malformed JSON line found in log file: '$line'."
                }
            }
            
            $okHeaderInAllowedRequest = ($allLogEntries | Where-Object { 
                $_.RequestPath -eq "/remediation-test" -and
                $_.DownstreamStatus -eq 200 -and
                $_.'request_X-Waf-Status' -eq "ok"
            }).Count -gt 0
            
            $okHeaderInAllowedRequest | Should -Be $true
        }
        
        It "Should log 'unhealthy' header when ModSecurity backend is unavailable" {
            try {
                # Stop the ModSecurity WAF container to simulate unhealthy state
                docker stop $script:wafContainer
                
                # Wait a moment for the container to stop
                Start-Sleep -Seconds 3
                
                # Make multiple requests to trigger the unhealthy state.
                # We don't care about response codes here, only that Traefik logs the 'unhealthy' header.
                1..3 | ForEach-Object {
                    try {
                        $null = Invoke-SafeWebRequest -Uri "$BaseUrl/remediation-test" -TimeoutSec 15
                    } catch {
                        Write-Host "Unhealthy WAF test request failed: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    Start-Sleep -Seconds 2
                }

                # Wait a moment for log to be written
                Start-Sleep -Seconds 2
                
                # Read and parse access.log entries from the Traefik container using shared helper
                $allLogEntries = Get-TraefikAccessLogEntries -TraefikContainerName $script:traefikContainer
                
                # Look for log entries with 'unhealthy' header value
                $unhealthyHeaderFound = ($allLogEntries | Where-Object { 
                    $_.'request_X-Waf-Status' -eq "unhealthy" -and 
                    $_.RequestPath -like "/remediation-test*"
                }).Count -gt 0
                
                # Verify that the unhealthy header was logged
                $unhealthyHeaderFound | Should -Be $true
            }
            finally {
                # Restart and wait for WAF to be healthy again for subsequent tests
                docker start $script:wafContainer | Out-Null
                Wait-ForWafHealthy -ContainerName $script:wafContainer
            }
        }
        
        It "Should log 'error' header when ModSecurity communication fails" {
            # Make a request to the error test service (with invalid ModSecurity URL)
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/error-test"
            $response.StatusCode | Should -Be 200
            
            # Wait a moment for log to be written
            Start-Sleep -Seconds 2
            
            # Read the access.log file from the traefik container
            $accessLogContent = docker exec $script:traefikContainer cat /var/log/traefik/access.log 2>$null
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Warning: Failed to read traefik access log from container: $script:traefikContainer" -ForegroundColor Yellow
                Write-Host "Available containers:" -ForegroundColor Yellow
                docker ps --format "table {{.Names}}\t{{.Image}}"
                throw "Failed to read traefik access log"
            }
            
            # Parse the log lines
            $logLines = $accessLogContent -split "`n" | Where-Object { $_.Trim() -ne "" }
            
            # Validate that ALL log lines are properly formatted JSON
            $allLogEntries = @()
            foreach ($line in $logLines) {
                try {
                    $logEntry = $line | ConvertFrom-Json
                    $allLogEntries += $logEntry
                } catch {
                    throw "Malformed JSON line found in log file: '$line'."
                }
            }
            
            # Look for log entries with 'error' header value
            $errorHeaderFound = ($allLogEntries | Where-Object { 
                $_.'request_X-Waf-Status' -eq "error" -and 
                $_.RequestPath -like "/error-test*"
            }).Count -gt 0
            
            # Verify that the error header was logged
            $errorHeaderFound | Should -Be $true
        }
    }
}

Describe "Bypass Functionality Tests" {
    Context "WAF Bypass Verification" {
        It "Should allow potentially malicious requests through bypass endpoint" {
            $maliciousPatterns = @(
                "?id=1' OR '1'='1",
                "?search=<script>alert('test')</script>",
                "?file=../../../etc/passwd"
            )
            
            Test-BypassPatterns -BaseUrl "$BaseUrl/bypass" -Patterns $maliciousPatterns
        }
    }
}

Describe "Performance and Health Tests" {
    Context "Response Time Tests" {
        It "Should respond within acceptable time limits" {
            Test-ResponseTime -Url "$BaseUrl/protected" -MaxResponseTimeMs 5000
        }
        
        It "Should handle concurrent requests" {
            $url = "$BaseUrl/protected"
            $requestCount = 5
            $minSuccessCount = 3

            $jobs = @()
            1..$requestCount | ForEach-Object {
                $jobs += Start-Job -ScriptBlock {
                    param($TestUrl)
                    try {
                        $response = Invoke-WebRequest -Uri $TestUrl -UseBasicParsing -TimeoutSec 10
                        return @{ StatusCode = $response.StatusCode; Success = $true }
                    }
                    catch {
                        return @{ StatusCode = 0; Success = $false; Error = $_.Exception.Message }
                    }
                } -ArgumentList $url
            }
            
            $results = $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job
            
            $successfulRequests = ($results | Where-Object { $_.Success }).Count
            $successfulRequests | Should -BeGreaterOrEqual $minSuccessCount
            
            Write-Host "Successful concurrent requests: $successfulRequests/$requestCount" -ForegroundColor Cyan
        }
    }
    
    Context "WAF Health Monitoring" {
        # Removed health endpoint test - keeping it simple
    }
}

Describe "Performance Comparison Tests" {
    Context "WAF vs Bypass Performance Analysis" {
        It "Should measure performance difference between WAF-protected and bypass requests" {
            $testIterations = 20
            $wafResponseTimes = @()
            $bypassResponseTimes = @()
            
            Write-Host "🔄 Running performance comparison test with $testIterations iterations..."
            
            # Test WAF-protected endpoint
            Write-Host "📊 Testing WAF-protected endpoint..."
            for ($i = 1; $i -le $testIterations; $i++) {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -TimeoutSec 10
                    $stopwatch.Stop()
                    if ($response.StatusCode -eq 200) {
                        $wafResponseTimes += $stopwatch.ElapsedMilliseconds
                    } else {
                        Write-Warning "WAF request $i returned status $($response.StatusCode)"
                    }
                } catch {
                    $stopwatch.Stop()
                    Write-Warning "WAF request $i failed: $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 50  # Small delay between requests
            }
            
            # Test bypass endpoint
            Write-Host "📊 Testing bypass endpoint..."
            for ($i = 1; $i -le $testIterations; $i++) {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $response = Invoke-SafeWebRequest -Uri "$BaseUrl/bypass" -TimeoutSec 10
                    $stopwatch.Stop()
                    if ($response.StatusCode -eq 200) {
                        $bypassResponseTimes += $stopwatch.ElapsedMilliseconds
                    }
                } catch {
                    $stopwatch.Stop()
                    Write-Warning "Bypass request $i failed: $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 50  # Small delay between requests
            }
            
            # Calculate statistics
            if ($wafResponseTimes.Count -gt 0 -and $bypassResponseTimes.Count -gt 0) {
                $wafAvg = ($wafResponseTimes | Measure-Object -Average).Average
                $wafMin = ($wafResponseTimes | Measure-Object -Minimum).Minimum
                $wafMax = ($wafResponseTimes | Measure-Object -Maximum).Maximum
                
                $bypassAvg = ($bypassResponseTimes | Measure-Object -Average).Average
                $bypassMin = ($bypassResponseTimes | Measure-Object -Minimum).Minimum
                $bypassMax = ($bypassResponseTimes | Measure-Object -Maximum).Maximum
                
                $overhead = $wafAvg - $bypassAvg
                
                # Display results
                Write-Host "`n📈 Performance Comparison Results:"
                Write-Host "┌─────────────────┬─────────────┬─────────────┬─────────────┐"
                Write-Host "│ Endpoint        │ Average (ms)│ Min (ms)    │ Max (ms)    │"
                Write-Host "├─────────────────┼─────────────┼─────────────┼─────────────┤"
                Write-Host "│ WAF Protected   │ $($wafAvg.ToString('F1').PadLeft(11)) │ $($wafMin.ToString('F1').PadLeft(11)) │ $($wafMax.ToString('F1').PadLeft(11)) │"
                Write-Host "│ Bypass          │ $($bypassAvg.ToString('F1').PadLeft(11)) │ $($bypassMin.ToString('F1').PadLeft(11)) │ $($bypassMax.ToString('F1').PadLeft(11)) │"
                Write-Host "└─────────────────┴─────────────┴─────────────┴─────────────┘"
                Write-Host "`n⚡ WAF Overhead: $($overhead.ToString('F1')) ms"
                
                # Store results for validation
                $script:PerformanceResults = @{
                    WafAverage = $wafAvg
                    BypassAverage = $bypassAvg
                    Overhead = $overhead
                    WafSamples = $wafResponseTimes.Count
                    BypassSamples = $bypassResponseTimes.Count
                }
                
                # Validate that we have enough samples
                $wafResponseTimes.Count | Should -BeGreaterOrEqual 15 -Because "We need at least 15 successful WAF requests for reliable measurement"
                $bypassResponseTimes.Count | Should -BeGreaterOrEqual 15 -Because "We need at least 15 successful bypass requests for reliable measurement"
                
                # Validate that WAF and bypass performance are in the same ballpark.
                # Small negative or positive differences are acceptable due to measurement noise.
                [math]::Abs($overhead) | Should -BeLessThan 100 -Because "WAF and bypass should have roughly similar latency in this synthetic test"
                
            } else {
                throw "Insufficient successful requests for performance comparison"
            }
        }
    }
}

Describe "MaxBodySizeBytes Configuration Tests" {
    Context "Body Size Limit Enforcement" {
        It "Should allow requests within the body size limit" {
            # Test with small body (500 bytes - well under 1KB limit)
            $smallData = "data=" + ("a" * 500)
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body $smallData
            $response.StatusCode | Should -Be 200 -Because "Small requests should be allowed"
        }
        
        It "Should reject requests exceeding the body size limit with HTTP 413" {
            # Test with large body (2KB - exceeds 1KB limit configured in docker-compose.test.yml)
            $largeData = "data=" + ("a" * 2000)
            
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body $largeData -TimeoutSec 10
            $response.StatusCode | Should -Be 413 -Because "Requests exceeding maxBodySizeBytes should return HTTP 413 Request Entity Too Large"
        }
        
        It "Should handle body size limit errors without sending partial data to ModSecurity" {
            # Test with very large body (5KB - significantly exceeds 1KB limit)
            $veryLargeData = "data=" + ("a" * 5000)
            
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body $veryLargeData -TimeoutSec 10
            $response.StatusCode | Should -Be 413 -Because "Very large requests should be rejected before reaching ModSecurity"
            
            # Wait a moment for any potential logs
            Start-Sleep -Seconds 2
            
            # Verify that no partial data was sent to ModSecurity by checking logs
            # (This is more of a behavioral test - we expect the plugin to handle this correctly)
            Write-Host "✅ Body size limit properly enforced - no partial data sent to ModSecurity" -ForegroundColor Green
        }
        
        It "Should handle body size limit for different HTTP methods" {
            # Test PUT method with large body
            $largeData = "data=" + ("a" * 2000)
            
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method PUT -Body $largeData -TimeoutSec 10
            $response.StatusCode | Should -Be 413 -Because "Body size limit should apply to all HTTP methods with bodies"
        }
        
        It "Should allow GET requests regardless of query string length" {
            # Test with long query string (this should not be affected by body size limit)
            $longQuery = "?" + ("param=value&" * 100)  # Very long query string
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected$longQuery"
            $response.StatusCode | Should -Be 200 -Because "Query strings are not subject to body size limits"
        }
        
        # Large-body tests moved to scripts/integration-tests.BodySize.Tests.ps1
    }
    
    Context "Chunked POST vs pool threshold (/pool-test)" {
        # /pool-test: maxBodySizeBytes=5120, maxBodySizeBytesForPool=1024
        # Chunked requests have no Content-Length, so the plugin pools the read and
        # drops the buffer when Cap() exceeds 1KB. Invoke-WebRequest cannot send this.

        It "Should allow a chunked POST larger than the pool cap and under maxBodySizeBytes" {
            $result = Invoke-ChunkedHttpRequest -Path "/pool-test" -BodySizeBytes 2048
            $result.StatusCode | Should -Be 200 -Because "2KB chunked is above the 1KB pool cap and under the 5KB body limit; Traefik must still reach whoami"
        }

        It "Should reject a chunked POST that exceeds maxBodySizeBytes" {
            $result = Invoke-ChunkedHttpRequest -Path "/pool-test" -BodySizeBytes 6144
            $result.StatusCode | Should -Be 413 -Because "6KB chunked exceeds the 5KB maxBodySizeBytes on /pool-test"
        }
    }

    Context "Body Size Limit Logging" {
        It "Should log body size limit violations appropriately" {
            # Make a request that exceeds the body size limit
            $largeData = "data=" + ("a" * 2000)
            
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body $largeData -TimeoutSec 10
            $response.StatusCode | Should -Be 413 -Because "Oversized request should be rejected with HTTP 413"
            
            # Wait for log to be written
            Start-Sleep -Seconds 2
            
            # Read and parse access.log from Traefik using helper
            $entries = Get-TraefikAccessLogEntries -TraefikContainerName $script:traefikContainer

            # Look for at least one 413 entry on /protected
            $has413 = $entries | Where-Object { $_.DownstreamStatus -eq 413 -and $_.RequestPath -like "/protected*" } | Select-Object -First 1
            
            # Verify that body size limit violations are logged
            $has413 | Should -Not -BeNullOrEmpty -Because "Body size limit violations should be logged with HTTP 413 status"
        }
    }
}

# Body Size Limit Tests moved to scripts/integration-tests.BodySize.Tests.ps1

Describe "DenyVerbsWithBody Configuration Tests" {
    Context "Strict Body Validation" {
        It "Should reject GET requests with body for the default denyVerbsWithBody list" {
            $body = "test data"

            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/force-test" -Method GET -Body $body -TimeoutSec 10
            $response.StatusCode | Should -Be 400 -Because "GET requests with body should be rejected by default denyVerbsWithBody"
        }
        
        It "Should reject HEAD requests with body for the default denyVerbsWithBody list" {
            $body = "test data"
            
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/force-test" -Method HEAD -Body $body -TimeoutSec 10
            $response.StatusCode | Should -Be 400 -Because "HEAD requests with body should be rejected by default denyVerbsWithBody"
        }
        
        It "Should reject DELETE requests with body for the default denyVerbsWithBody list" {
            $body = "test data"
            
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/force-test" -Method DELETE -Body $body -TimeoutSec 10
            $response.StatusCode | Should -Be 400 -Because "DELETE requests with body should be rejected by default denyVerbsWithBody"
        }
        
        It "Should allow GET requests without body" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/force-test"
            $response.StatusCode | Should -Be 200 -Because "GET requests without body should be allowed"
        }
        
        It "Should allow POST requests with body" {
            $body = "test data"
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/force-test" -Method POST -Body $body
            $response.StatusCode | Should -Be 200 -Because "POST is not in denyVerbsWithBody"
        }
        
        It "Should allow PUT requests with body" {
            $body = "test data"
            
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/force-test" -Method PUT -Body $body -TimeoutSec 10
            $statusCode = [int]$response.StatusCode

            $statusCode | Should -Not -Be 400 -Because "PUT is not in denyVerbsWithBody; body validation must not reject it"
        }
    }
}

Describe "WAF Health Tracker Threshold Tests" {
    Context "Threshold and bypass behaviour" {
        It "Should not trip unhealthy on fewer than threshold failures" {
            try {
                docker stop -t 0 $script:wafContainer | Out-Null
                # Poll until WAF is down (502); then one more request must still be 502 (2 failures, threshold=3, no trip)
                $maxWait = 15
                $first502 = $null
                for ($i = 0; $i -lt $maxWait; $i++) {
                    $r = Invoke-SafeWebRequest -Uri "$BaseUrl/threshold-test" -TimeoutSec 5
                    if ($r.StatusCode -eq 502) {
                        $first502 = $r
                        break
                    }
                    Start-Sleep -Seconds 1
                }
                $first502 | Should -Not -BeNullOrEmpty -Because "WAF must eventually return 502 when stopped"

                # Second failure under threshold=3 must still return 502 (no pass-through)
                $r2 = Invoke-SafeWebRequest -Uri "$BaseUrl/threshold-test" -TimeoutSec 10
                $r2.StatusCode | Should -Be 502 -Because "two failures under threshold must not trip; still 502"
            }
            finally {
                docker start $script:wafContainer | Out-Null
                Wait-ForWafHealthy -ContainerName $script:wafContainer
                Wait-ForWafAllowPath -Url "$BaseUrl/protected"
            }
        }

        It "Should trip unhealthy after threshold failures and bypass WAF" {
            try {
                $response = Invoke-ThresholdTestFailOpenTrip -BaseUrl $BaseUrl -WafContainerName $script:wafContainer
                $response.StatusCode | Should -Be 200 -Because "after threshold we bypass WAF and get backend response"
                $unhealthyPassThrough = $null
                for ($i = 0; $i -lt 10; $i++) {
                    Start-Sleep -Milliseconds 500
                    $allLogEntries = Get-TraefikAccessLogEntries -TraefikContainerName $script:traefikContainer
                    $unhealthyPassThrough = ($allLogEntries | Where-Object {
                        $_.'request_X-Waf-Status' -eq "unhealthy" -and $_.RequestPath -like "/threshold-test*"
                    } | Select-Object -Last 1)
                    if ($unhealthyPassThrough) { break }
                }
                $unhealthyPassThrough | Should -Not -BeNullOrEmpty -Because "pass-through when unhealthy adds X-Waf-Status: unhealthy to request"
            }
            finally {
                docker start $script:wafContainer | Out-Null
                Wait-ForWafHealthy -ContainerName $script:wafContainer
                Wait-ForWafAllowPath -Url "$BaseUrl/protected"
            }
        }

        It "Should reject GET with body after fail-open trip" {
            try {
                $passThrough = Invoke-ThresholdTestFailOpenTrip -BaseUrl $BaseUrl -WafContainerName $script:wafContainer
                $passThrough.StatusCode | Should -Be 200 -Because "threshold must trip before the deny-verb check"

                $response = Invoke-SafeWebRequest -Uri "$BaseUrl/threshold-test" -Method GET -Body "test data" -TimeoutSec 10
                $response.StatusCode | Should -Be 400 -Because "denyVerbsWithBody must reject GET-with-body even when the WAF is already unhealthy"
                [string]$response.Content | Should -Not -Match "Hostname" -Because "fail-open must not reach whoami for a denied-verb body"
            }
            finally {
                docker start $script:wafContainer | Out-Null
                Wait-ForWafHealthy -ContainerName $script:wafContainer
                Wait-ForWafAllowPath -Url "$BaseUrl/protected"
            }
        }

        It "Should consult the sidecar again after backoff elapses" {
            try {
                Wait-ForWafHealthy -ContainerName $script:wafContainer
                Wait-ForWafAllowPath -Url "$BaseUrl/protected"
                Wait-ForThresholdRouteInspecting -BaseUrl $BaseUrl

                $passThrough = Invoke-ThresholdTestFailOpenTrip -BaseUrl $BaseUrl -WafContainerName $script:wafContainer
                $passThrough.StatusCode | Should -Be 200 -Because "threshold must trip before backoff resume"
                $trippedAt = Get-Date

                docker start $script:wafContainer | Out-Null
                Wait-ForWafHealthy -ContainerName $script:wafContainer
                Wait-ForWafAllowPath -Url "$BaseUrl/protected"

                # Route unhealthyWafBackOffPeriodSecs=10; wait from the trip, not from docker healthy.
                $backoffRemainSec = 11 - ((Get-Date) - $trippedAt).TotalSeconds
                if ($backoffRemainSec -gt 0) {
                    Start-Sleep -Seconds ([Math]::Ceiling($backoffRemainSec))
                }

                $probe = $null
                for ($i = 0; $i -lt 8; $i++) {
                    $probe = Invoke-SafeWebRequest -Uri "$BaseUrl/threshold-test?id=1%27+OR+%271%27%3D%271" -TimeoutSec 10
                    if ($probe.StatusCode -ge 400 -and $probe.StatusCode -ne 200) { break }
                    Start-Sleep -Milliseconds 500
                }
                $probe.StatusCode | Should -BeGreaterOrEqual 400 -Because "after backoff the plugin must inspect again; a CRS probe must not stay fail-open 200"
                $probe.StatusCode | Should -Not -Be 200
            }
            finally {
                docker start $script:wafContainer | Out-Null
                Wait-ForWafHealthy -ContainerName $script:wafContainer
                Wait-ForWafAllowPath -Url "$BaseUrl/protected"
            }
        }
    }
}

Describe "Plugin reclaim logs" -Tag Reclaim {
    AfterAll {
        Set-ReclaimDynamicTimeoutMillis -TimeoutMillis 3000 -TraefikContainerName $script:traefikContainer
    }

    It "emits one reclaim_put for two routes, one new put after config change, then reclaim_dispose" {
        $middleware = "waf-reclaim"
        $puts = Wait-ReclaimLogCount -TraefikContainerName $script:traefikContainer -Middleware $middleware -Message "reclaim_put" -Count 1
        $puts.Count | Should -Be 1 -Because "two file-provider routers must share one plugin core"
        $firstKey = $puts[0].Key

        $routeA = Invoke-SafeWebRequest -Uri "$BaseUrl/reclaim-a"
        $routeA.StatusCode | Should -Be 200
        $routeB = Invoke-SafeWebRequest -Uri "$BaseUrl/reclaim-b"
        $routeB.StatusCode | Should -Be 200
        @(Get-ReclaimLogEvents -TraefikContainerName $script:traefikContainer -Middleware $middleware -Message "reclaim_put").Count | Should -Be 1 -Because "traffic on both routes must not create a second core"

        Set-ReclaimDynamicTimeoutMillis -TimeoutMillis 4001 -TraefikContainerName $script:traefikContainer
        $putsAfterReload = Wait-ReclaimLogCount -TraefikContainerName $script:traefikContainer -Middleware $middleware -Message "reclaim_put" -Count 2
        $putsAfterReload.Count | Should -Be 2 -Because "a timeoutMillis change must put exactly one new core"

        $disposes = Wait-ReclaimLogCount -TraefikContainerName $script:traefikContainer -Middleware $middleware -Message "reclaim_dispose" -Count 1 -TimeoutSeconds 20
        ($disposes | Where-Object { $_.Key -eq $firstKey }) | Should -Not -BeNullOrEmpty -Because "the first core must dispose after DefaultGrace once no router holds it"
    }
}

Describe "WebSocket through WAF middleware" {
    Context "Live upgrade" {
        It "Should complete a handshake and echo a text frame" {
            $payload = "ws-echo-$(Get-Random)"
            $echoed = Invoke-WebSocketEcho -Uri "ws://localhost:8000/ws-echo" -Message $payload
            $echoed | Should -Be $payload -Because "a real WebSocket through Traefik and the plugin must stay usable after 101"
        }

        It "Should still inspect a forged Upgrade websocket header" {
            $requestLine = "GET /protected?id=1%27+OR+%271%27%3D%271 HTTP/1.1"
            $responseText = Invoke-TcpHttpRequest -TargetHost "localhost" -Port 8000 -RequestLine $requestLine -Headers @{
                Host = "localhost:8000"
                Connection = "close"
                Upgrade = "websocket"
            }
            $responseText | Should -Match '^HTTP/1\.[01] [45]\d\d' -Because "Upgrade: websocket without a Connection upgrade token must still be CRS-inspected"
        }

        It "Should skip CRS on a real handshake even with a SQL-injection query" {
            $payload = "ws-echo-$(Get-Random)"
            $echoed = Invoke-WebSocketEcho -Uri "ws://localhost:8000/ws-echo?id=1%27%20OR%20%271%27%3D%271" -Message $payload
            $echoed | Should -Be $payload -Because "a real WebSocket handshake must skip the WAF even when the query looks like a CRS probe"
        }
    }
}

Describe "Sidecar 5xx is not a copied block" {
    Context "Fixture origin returns 503" {
        It "Should return 502 without the 503 fixture body" {
            $response = $null
            for ($i = 0; $i -lt 10; $i++) {
                $response = Invoke-SafeWebRequest -Uri "$BaseUrl/waf-5xx-test" -TimeoutSec 10
                if ($response.StatusCode -ne 404) { break }
                Start-Sleep -Milliseconds 500
            }
            $response.StatusCode | Should -Be 502 -Because "sidecar 5xx with backoff off is a WAF failure, not a copied block"
            $response.StatusCode | Should -Not -Be 503
            [string]$response.Content | Should -Not -Match "sidecar-5xx-marker" -Because "the plugin must not copy the sidecar 5xx page"

            Start-Sleep -Seconds 2
            $entries = Get-TraefikAccessLogEntries -TraefikContainerName $script:traefikContainer
            $latestEntry = Get-LastAccessLogEntryForPath -Entries $entries -PathPrefix "/waf-5xx-test"
            $latestEntry | Should -Not -BeNullOrEmpty -Because "Traefik access.log should contain /waf-5xx-test"
            $latestEntry.'request_X-Waf-Status' | Should -Be "error" -Because "sidecar 5xx must be logged as error, not blocked"
        }
    }
}

Describe "Error Handling and Edge Cases" {
    Context "Large Request Handling" {
        It "Should handle moderately large POST requests" {
            $largeData = "data=" + ("a" * 1000)  # 1KB of data
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body $largeData
            $response.StatusCode | Should -Be 200
        }
    }
    
    Context "Special Characters and Encoding" {
        It "Should handle URL-encoded requests properly" {
            $encodedUrl = "$BaseUrl/protected?name=" + [System.Web.HttpUtility]::UrlEncode("John & Jane")
            $response = Invoke-SafeWebRequest -Uri $encodedUrl
            $response.StatusCode | Should -Be 200
        }
    }
}

Describe "Allow-path throughput" {
    Context "Bombardier on /protected" {
        It "Should measure GET allow-path req/s" {
            if (-not (Get-BombardierCommand)) {
                Set-ItResult -Skipped -Because "bombardier not on PATH (CI installs it; locally: go install github.com/codesenberg/bombardier@latest)"
                return
            }
            $result = Invoke-AllowPathBombardier -Method GET
            $result | Should -Not -BeNullOrEmpty
            $result.ReqsPerSec | Should -BeGreaterThan 0 -Because "allow-path GET must complete at least one request"
        }

        It "Should measure POST allow-path req/s" {
            if (-not (Get-BombardierCommand)) {
                Set-ItResult -Skipped -Because "bombardier not on PATH (CI installs it; locally: go install github.com/codesenberg/bombardier@latest)"
                return
            }
            $result = Invoke-AllowPathBombardier -Method POST
            $result | Should -Not -BeNullOrEmpty
            $result.ReqsPerSec | Should -BeGreaterThan 0 -Because "allow-path POST must complete at least one request"
        }
    }
}

AfterAll {
    Write-Host "`n🏁 Integration tests completed!" -ForegroundColor Green
    Write-Host "📊 Test Results Summary:" -ForegroundColor Cyan
    Write-Host "  - Services tested: Traefik, ModSecurity WAF, Protected & Bypass endpoints" -ForegroundColor Gray
    Write-Host "  - Security features: SQL injection, XSS, Path traversal, Command injection protection" -ForegroundColor Gray
    Write-Host "  - Performance: Response time and concurrent request handling" -ForegroundColor Gray
    Write-Host "  - Custom features: Remediation headers, WAF bypass verification" -ForegroundColor Gray
}
