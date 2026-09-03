#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Runs integration tests for the Traefik ModSecurity Plugin

.DESCRIPTION
    This script starts the Docker Compose services, waits for them to be ready,
    runs the Pester integration tests, and then cleans up the services.

    Four stacks (CRS engine × origin):
      apache-whoami  docker-compose.test.yml
      nginx-whoami   docker-compose.test.nginx.yml
      apache-drain   docker-compose.test.yml + docker-compose.test.apache-drain.yml
      nginx-drain    docker-compose.test.nginx.yml + docker-compose.test.nginx-drain.yml

.PARAMETER SkipDockerCleanup
    Skip stopping Docker services after tests complete (useful for debugging)

.PARAMETER SkipWait
    Skip waiting for services to be ready (assumes they're already running)

.PARAMETER TestPath
    Path to the Pester test file (defaults to ./scripts/*.Tests.ps1)

.PARAMETER ComposeFile
    Path to a single Docker Compose file (ignored when -Stack or -AllStacks is set)

.PARAMETER Stack
    Named stack: apache-whoami, nginx-whoami, apache-drain, nginx-drain

.PARAMETER AllStacks
    Run the four stacks in sequence (compose down between each)

.EXAMPLE
    ./Test-Integration.ps1
    Apache + dummy whoami origin (default)

.EXAMPLE
    ./Test-Integration.ps1 -Stack apache-drain
    Apache inspect-only drain origin

.EXAMPLE
    ./Test-Integration.ps1 -AllStacks
    All four stacks, including bombardier benches when bombardier is installed

.EXAMPLE
    ./Test-Integration.ps1 -ComposeFile ./docker-compose.test.nginx.yml
    Same as -Stack nginx-whoami
#>

[CmdletBinding()]
param(
    [switch]$SkipDockerCleanup,
    [switch]$SkipWait,
    [string]$TestPath = "./scripts/*.Tests.ps1",
    [string]$ComposeFile = "./docker-compose.test.yml",
    [ValidateSet('apache-whoami', 'nginx-whoami', 'apache-drain', 'nginx-drain')]
    [string]$Stack,
    [switch]$AllStacks,
    # Pester filter options (Pester v5)
    # - FullName supports wildcards and matches Describe/Context/It names
    [string]$PesterFullNameFilter,
    # Tags: tests can be tagged in Pester, filter supports multiple tags
    [string[]]$PesterTagFilter
)

$ErrorActionPreference = "Stop"

function Get-IntegrationStackComposeFiles {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('apache-whoami', 'nginx-whoami', 'apache-drain', 'nginx-drain')]
        [string]$Stack
    )
    switch ($Stack) {
        'apache-whoami' { @('./docker-compose.test.yml') }
        'nginx-whoami' { @('./docker-compose.test.nginx.yml') }
        'apache-drain' { @('./docker-compose.test.yml', './docker-compose.test.apache-drain.yml') }
        'nginx-drain' { @('./docker-compose.test.nginx.yml', './docker-compose.test.nginx-drain.yml') }
    }
}

# Colors for output
$Colors = @{
    Info = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Gray = "Gray"
}

function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "🔄 $Message" -ForegroundColor $Color
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor $Colors.Success
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor $Colors.Warning
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor $Colors.Error
}

function Get-ComposeDashF {
    param([string[]]$Files)
    $out = @()
    foreach ($f in $Files) {
        $out += '-f'
        $out += $f
    }
    return $out
}

function Get-StackNameFromComposeFiles {
    param([string[]]$Files)
    $joined = ($Files -join ' ')
    if ($joined -match 'apache-drain') { return 'apache-drain' }
    if ($joined -match 'nginx-drain') { return 'nginx-drain' }
    if ($joined -match 'nginx') { return 'nginx-whoami' }
    return 'apache-whoami'
}

function Test-ServiceHealth {
    param(
        [string]$Url,
        [string]$ServiceName,
        [int]$TimeoutSeconds = 30,
        [int]$RetryIntervalSeconds = 3
    )
    
    Write-Step "Waiting for $ServiceName to be ready..."
    $elapsed = 0
    
    do {
        try {
            $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 5 -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                Write-Success "$ServiceName is ready!"
                return $true
            }
        }
        catch {
            # Service not ready yet, continue waiting
        }
        
        Start-Sleep $RetryIntervalSeconds
        $elapsed += $RetryIntervalSeconds
        
        if ($elapsed % 15 -eq 0) {
            Write-Host "  Still waiting for $ServiceName... ($elapsed/$TimeoutSeconds seconds)" -ForegroundColor $Colors.Gray
        }
        
    } while ($elapsed -lt $TimeoutSeconds)
    
    Write-Error "$ServiceName failed to become ready within $TimeoutSeconds seconds"
    return $false
}

function Test-DockerCompose {
    Write-Step "Checking Docker Compose availability..."
    try {
        $dockerComposeVersion = docker compose version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker Compose is available: $($dockerComposeVersion -split "`n" | Select-Object -First 1)"
        } else {
            throw "Docker Compose not found"
        }
    }
    catch {
        Write-Error "Docker Compose is not available. Please install Docker Desktop or Docker Compose."
        return $false
    }
    return $true
}

function Start-TestServices {
    param([string[]]$ComposeFiles)
    
    $dashF = Get-ComposeDashF $ComposeFiles
    Write-Step "Starting Docker Compose services using $($ComposeFiles -join ', ')..."
    try {
        # Stop any existing containers first
        docker compose @dashF down -v --remove-orphans 2>$null | Out-Null
        
        # Start fresh containers
        $output = docker compose @dashF up -d 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Docker Compose Output:" -ForegroundColor $Colors.Gray
            Write-Host $output -ForegroundColor $Colors.Gray
            throw "Failed to start Docker services (exit code: $LASTEXITCODE)"
        }
        Write-Success "Docker services started successfully"
        
        # Show running containers for verification
        Write-Host "`nRunning containers:" -ForegroundColor $Colors.Info
        docker compose @dashF ps | Out-Host
        
    }
    catch {
        Write-Error "Failed to start Docker services: $($_.Exception.Message)"
        throw
    }
}

function Wait-ForAllServices {
    param([string[]]$ComposeFiles)

    Write-Step "Waiting for all services to become ready..."
    
    $services = @(
        @{ Url = "http://localhost:8080/api/rawdata"; Name = "Traefik API" },
        @{ Url = "http://localhost:8000/bypass"; Name = "Whoami Bypass service" },
        @{ Url = "http://localhost:8000/protected"; Name = "Whoami Protected service" }
    )
    
    $servicesReady = @()
    foreach ($service in $services) {
        $servicesReady += (Test-ServiceHealth -Url $service.Url -ServiceName $service.Name -TimeoutSeconds 30)
    }
    
    if ($servicesReady -contains $false) {
        Write-Error "One or more services failed to start properly"
        Write-Host "`nContainer logs for debugging:" -ForegroundColor $Colors.Warning
        $dashF = Get-ComposeDashF $ComposeFiles
        docker compose @dashF logs --tail=20 | Out-Host
        return $false
    }
    
    Write-Success "All services are ready for testing!"
    return $true
}

function Invoke-IntegrationStack {
    param(
        [string[]]$ComposeFiles,
        [string]$StackName
    )

    $code = 1
    foreach ($f in $ComposeFiles) {
        if (-not (Test-Path -LiteralPath $f)) {
            Write-Error "Docker Compose file not found: $f"
            return 1
        }
    }

    $env:INTEGRATION_STACK = $StackName
    Write-Host ""
    Write-Host "Stack: $StackName" -ForegroundColor $Colors.Info
    Write-Host "Compose: $($ComposeFiles -join ', ')" -ForegroundColor $Colors.Gray

    try {
        Start-TestServices -ComposeFiles $ComposeFiles

        $hasPesterFilters = [bool]$PesterFullNameFilter -or ($PesterTagFilter -and $PesterTagFilter.Count -gt 0)
        if (-not $SkipWait) {
            if ($hasPesterFilters) {
                Write-Warning "Pester filters detected; skipping runner-level readiness checks (tests will wait for their own required services)"
            } else {
                if (-not (Wait-ForAllServices -ComposeFiles $ComposeFiles)) {
                    return 1
                }
            }
        } else {
            Write-Warning "Skipping service readiness check (assuming services are already running)"
        }

        Write-Step "Running Pester integration tests..."
        Write-Host ""
    
        $pesterConfig = New-PesterConfiguration
        $pesterConfig.Run.Path = $TestPath
        $pesterConfig.Output.Verbosity = 'Detailed'
        $pesterConfig.Run.Exit = $false
        $pesterConfig.Run.PassThru = $true

        if ($PesterFullNameFilter) {
            $pesterConfig.Filter.FullName = $PesterFullNameFilter
        }
        if ($PesterTagFilter -and $PesterTagFilter.Count -gt 0) {
            $pesterConfig.Filter.Tag = $PesterTagFilter
        }
        
        $result = Invoke-Pester -Configuration $pesterConfig
        
        Write-Host ""
        if ($result -and $result.FailedCount -eq 0) {
            Write-Success "All integration tests passed for $StackName"
            Write-Host "📊 Test Summary: $($result.PassedCount) passed, $($result.FailedCount) failed, $($result.SkippedCount) skipped" -ForegroundColor $Colors.Info
            $code = 0
        } elseif ($result) {
            Write-Error "$($result.FailedCount) test(s) failed out of $($result.TotalCount) total tests ($StackName)"
            Write-Host "📊 Test Summary: $($result.PassedCount) passed, $($result.FailedCount) failed, $($result.SkippedCount) skipped" -ForegroundColor $Colors.Warning
            $code = 1
        } else {
            Write-Warning "Could not determine test results"
            $code = 1
        }
    }
    catch {
        Write-Error "Failed to run Pester tests: $($_.Exception.Message)"
        $code = 1
    }
    finally {
        if (-not $SkipDockerCleanup) {
            Write-Step "Cleaning up Docker services ($StackName)..."
            try {
                $dashF = Get-ComposeDashF $ComposeFiles
                docker compose @dashF down -v --remove-orphans 2>$null | Out-Null
                Write-Success "Docker services stopped and cleaned up"
            }
            catch {
                Write-Warning "Failed to clean up Docker services: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "Skipping Docker cleanup (services left running for debugging)"
            $dashFDisplay = (Get-ComposeDashF $ComposeFiles) -join ' '
            Write-Host "To manually stop services, run: docker compose $dashFDisplay down -v" -ForegroundColor $Colors.Gray
            Write-Host "To view logs, run: docker compose $dashFDisplay logs" -ForegroundColor $Colors.Gray
        }
    }

    return $code
}

# Main execution
$exitCode = 0
try {
    Write-Host ""
    Write-Host "🚀 Traefik ModSecurity Plugin Integration Test Runner" -ForegroundColor $Colors.Info
    Write-Host "=====================================================" -ForegroundColor $Colors.Info
    Write-Host ""

    if ($AllStacks -and $Stack) {
        Write-Error "Use either -Stack or -AllStacks, not both"
        exit 1
    }
    
    if (-not (Test-Path $TestPath) -and -not (Get-Item $TestPath -ErrorAction SilentlyContinue)) {
        $matches = @(Get-Item $TestPath -ErrorAction SilentlyContinue)
        if ($matches.Count -eq 0) {
            Write-Error "Test file not found: $TestPath"
            exit 1
        }
    }

    # Check if Pester is available
    Write-Step "Checking Pester availability..."
    try {
        Import-Module Pester -Force -ErrorAction Stop
        $pesterVersion = (Get-Module Pester).Version
        Write-Success "Pester $pesterVersion is available"
    }
    catch {
        Write-Warning "Pester module not found. Installing Pester..."
        try {
            Install-Module -Name Pester -Force -Scope CurrentUser -SkipPublisherCheck -AllowClobber
            Import-Module Pester -Force
            Write-Success "Pester installed and imported successfully"
        }
        catch {
            Write-Error "Failed to install Pester: $($_.Exception.Message)"
            exit 1
        }
    }

    # Check Docker Compose
    if (-not (Test-DockerCompose)) {
        exit 1
    }

    $runs = @()
    if ($AllStacks) {
        foreach ($name in @('apache-whoami', 'nginx-whoami', 'apache-drain', 'nginx-drain')) {
            $runs += @{ Name = $name; Files = @(Get-IntegrationStackComposeFiles -Stack $name) }
        }
    } elseif ($Stack) {
        $runs += @{ Name = $Stack; Files = @(Get-IntegrationStackComposeFiles -Stack $Stack) }
    } else {
        $files = @($ComposeFile)
        $runs += @{ Name = (Get-StackNameFromComposeFiles -Files $files); Files = $files }
    }

    $failedStacks = @()
    foreach ($run in $runs) {
        $code = [int](@(Invoke-IntegrationStack -ComposeFiles $run.Files -StackName $run.Name)[-1])
        if ($code -ne 0) {
            $failedStacks += $run.Name
            $exitCode = 1
        }
    }
    if ($failedStacks.Count -gt 0) {
        Write-Error "Failed stacks: $($failedStacks -join ', ')"
    }
}
catch {
    Write-Error "Unexpected error: $($_.Exception.Message)"
    $exitCode = 1
}

Write-Host ""
Write-Host "=====================================================" -ForegroundColor $Colors.Info
if ($exitCode -eq 0) {
    Write-Host "🏁 Integration tests completed successfully!" -ForegroundColor $Colors.Success
} else {
    Write-Host "🏁 Integration tests completed with failures!" -ForegroundColor $Colors.Error
}
Write-Host ""

exit $exitCode
