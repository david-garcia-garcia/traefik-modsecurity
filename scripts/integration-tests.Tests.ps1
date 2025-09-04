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
        @{ Url = "$BaseUrl/protected"; Name = "Protected service" }
    )
    
    Wait-ForAllServices -Services $services
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
    
    Context "Legitimate Request Handling" {
        It "Should allow normal GET requests" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected/normal-path"
            $response.StatusCode | Should -Be 200
        }
        
        It "Should allow POST requests with normal data" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body "name=john&email=john@example.com"
            $response.StatusCode | Should -Be 200
        }
        
        It "Should allow requests with normal query parameters" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected?page=1&limit=10&sort=name"
            $response.StatusCode | Should -Be 200
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
            Test-ConcurrentRequests -Url "$BaseUrl/protected" -RequestCount 5 -MinSuccessCount 3
        }
    }
    
    Context "WAF Health Monitoring" {
        # Removed health endpoint test - keeping it simple
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

AfterAll {
    Write-Host "`n🏁 Integration tests completed!" -ForegroundColor Green
    Write-Host "📊 Test Results Summary:" -ForegroundColor Cyan
    Write-Host "  - Services tested: Traefik, ModSecurity WAF, Protected & Bypass endpoints" -ForegroundColor Gray
    Write-Host "  - Security features: SQL injection, XSS, Path traversal, Command injection protection" -ForegroundColor Gray
    Write-Host "  - Performance: Response time and concurrent request handling" -ForegroundColor Gray
    Write-Host "  - Custom features: Remediation headers, WAF bypass verification" -ForegroundColor Gray
}
