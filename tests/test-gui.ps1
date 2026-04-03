<#
.SYNOPSIS
    Manual smoke test for the M365Permissions GUI.
.DESCRIPTION
    Starts the GUI server and runs basic HTTP checks against all API endpoints.
.PARAMETER Port
    Port to test on. Default 8080.
#>
[CmdletBinding()]
param(
    [int]$Port = 8080
)

$ErrorActionPreference = 'Stop'
$baseUrl = "http://localhost:$Port"

Write-Host "Testing M365Permissions GUI at $baseUrl" -ForegroundColor Cyan
Write-Host "=" * 60

function Test-Endpoint {
    param([string]$Method, [string]$Path, [int]$ExpectedStatus = 200)
    
    try {
        $uri = "$baseUrl$Path"
        $response = Invoke-WebRequest -Uri $uri -Method $Method -SkipHttpErrorCheck -UseBasicParsing
        $status = $response.StatusCode
        $pass = $status -eq $ExpectedStatus
        $icon = if ($pass) { "PASS" } else { "FAIL" }
        $color = if ($pass) { "Green" } else { "Red" }
        Write-Host "  [$icon] $Method $Path -> $status (expected $ExpectedStatus)" -ForegroundColor $color
        return $pass
    }
    catch {
        Write-Host "  [FAIL] $Method $Path -> ERROR: $_" -ForegroundColor Red
        return $false
    }
}

$results = @()

Write-Host "`nAPI Endpoints:" -ForegroundColor Yellow
$results += Test-Endpoint -Method GET -Path '/api/status'
$results += Test-Endpoint -Method GET -Path '/api/config'
$results += Test-Endpoint -Method GET -Path '/api/scans'

Write-Host "`nStatic Files:" -ForegroundColor Yellow
$results += Test-Endpoint -Method GET -Path '/'
$results += Test-Endpoint -Method GET -Path '/style.css'
$results += Test-Endpoint -Method GET -Path '/app.js'

Write-Host "`nSPA Fallback:" -ForegroundColor Yellow
$results += Test-Endpoint -Method GET -Path '/nonexistent-page'

$passed = ($results | Where-Object { $_ }).Count
$total = $results.Count

Write-Host "`n" + "=" * 60
Write-Host "Results: $passed/$total passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Red" })
