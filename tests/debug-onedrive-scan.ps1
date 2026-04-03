#!/usr/bin/env pwsh
# Debug OneDrive scanner — test the exact Graph query used by OneDriveScanner.ScanAsync
# Run: pwsh ./tests/debug-onedrive-scan.ps1

Add-Type -AssemblyName System.Security

$rtPath = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'LiebenConsultancy' 'M365Permissions' '.rt'
if (-not (Test-Path $rtPath)) { Write-Error "No refresh token found at $rtPath"; exit 1 }

$encrypted = [System.IO.File]::ReadAllBytes($rtPath)
$plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$refreshToken = [System.Text.Encoding]::UTF8.GetString($plainBytes)

# Get Graph token
Write-Host "`n=== Getting Graph token ===" -ForegroundColor Cyan
$body = @{
    client_id     = '0ee7aa45-310d-4b82-9cb5-11cc01ad38e4'
    grant_type    = 'refresh_token'
    refresh_token = $refreshToken
    scope         = 'https://graph.microsoft.com/.default offline_access openid profile'
}
$tokenResp = Invoke-RestMethod -Uri 'https://login.microsoftonline.com/common/oauth2/v2.0/token' -Method Post -Body $body
$graphToken = $tokenResp.access_token
Write-Host "Got Graph token" -ForegroundColor Green

$headers = @{ 
    Authorization    = "Bearer $graphToken"
    ConsistencyLevel = "eventual"
}

# Test 1: Exact same query as OneDriveScanner
Write-Host "`n=== Test 1: Exact OneDrive user enumeration query ===" -ForegroundColor Cyan
$url = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,assignedLicenses,mySite&$filter=accountEnabled eq true&$count=true'
Write-Host "URL: $url"
try {
    $resp = Invoke-RestMethod -Uri $url -Headers $headers
    Write-Host "Total users returned: $($resp.value.Count)" -ForegroundColor Green
    if ($resp.'@odata.count') { Write-Host "@odata.count: $($resp.'@odata.count')" }
    
    $licensedUsers = $resp.value | Where-Object { $_.assignedLicenses.Count -gt 0 }
    Write-Host "Licensed users: $($licensedUsers.Count)"
    
    $usersWithMySite = $licensedUsers | Where-Object { $_.mySite }
    Write-Host "Licensed users with mySite: $($usersWithMySite.Count)"
    
    foreach ($u in $licensedUsers | Select-Object -First 5) {
        Write-Host "  - $($u.displayName) | UPN: $($u.userPrincipalName) | mySite: '$($u.mySite)' | Licenses: $($u.assignedLicenses.Count)"
    }
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
    Write-Host "Status: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
}

# Test 2: Without filter (simpler)
Write-Host "`n=== Test 2: Users without filter ===" -ForegroundColor Cyan
$url2 = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,assignedLicenses,mySite&$top=5'
try {
    $resp2 = Invoke-RestMethod -Uri $url2 -Headers @{ Authorization = "Bearer $graphToken" }
    Write-Host "Returned: $($resp2.value.Count) users"
    foreach ($u in $resp2.value) {
        Write-Host "  - $($u.displayName) | mySite: '$($u.mySite)' | Licenses: $($u.assignedLicenses.Count)"
    }
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}

# Test 3: Try to get a specific user's drive
Write-Host "`n=== Test 3: First licensed user's drive ===" -ForegroundColor Cyan
if ($licensedUsers.Count -gt 0) {
    $testUser = $licensedUsers[0]
    $driveUrl = "https://graph.microsoft.com/v1.0/users/$($testUser.id)/drive?`$select=id,webUrl"
    Write-Host "URL: $driveUrl"
    try {
        $driveResp = Invoke-RestMethod -Uri $driveUrl -Headers @{ Authorization = "Bearer $graphToken" }
        Write-Host "Drive ID: $($driveResp.id)" -ForegroundColor Green
        Write-Host "Drive webUrl: $($driveResp.webUrl)"
    } catch {
        Write-Host "FAILED: $_" -ForegroundColor Red
    }
}

Write-Host "`nDone." -ForegroundColor Cyan
