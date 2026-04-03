#!/usr/bin/env pwsh
# Debug script to test Azure DevOps API calls using the persisted refresh token
# Run: pwsh ./tests/debug-ado-api.ps1

Add-Type -AssemblyName System.Security

$rtPath = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'LiebenConsultancy' 'M365PermissionsV2' '.rt'
if (-not (Test-Path $rtPath)) { Write-Error "No refresh token found at $rtPath"; exit 1 }

$encrypted = [System.IO.File]::ReadAllBytes($rtPath)
$plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$refreshToken = [System.Text.Encoding]::UTF8.GetString($plainBytes)

# Get ADO token
Write-Host "`n=== Getting Azure DevOps token ===" -ForegroundColor Cyan
$body = @{
    client_id     = '0ee7aa45-310d-4b82-9cb5-11cc01ad38e4'
    grant_type    = 'refresh_token'
    refresh_token = $refreshToken
    scope         = '499b84ac-1321-427f-aa17-267ca6975798/user_impersonation offline_access'
}
try {
    $tokenResp = Invoke-RestMethod -Uri 'https://login.microsoftonline.com/common/oauth2/v2.0/token' -Method Post -Body $body
    $adoToken = $tokenResp.access_token
    Write-Host "Got token: $($adoToken.Substring(0,30))..." -ForegroundColor Green
} catch {
    Write-Error "Token acquisition failed: $_"
    exit 1
}

$headers = @{ Authorization = "Bearer $adoToken" }

# 1) Profile
Write-Host "`n=== Profile API ===" -ForegroundColor Cyan
$profile = Invoke-RestMethod -Uri 'https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1-preview.3' -Headers $headers
Write-Host "Member ID (publicAlias): $($profile.publicAlias)"
Write-Host "Display Name: $($profile.displayName)"

# 2) Organizations
Write-Host "`n=== Organizations API ===" -ForegroundColor Cyan
$orgs = Invoke-RestMethod -Uri "https://app.vssps.visualstudio.com/_apis/accounts?memberId=$($profile.publicAlias)&api-version=7.1-preview.1" -Headers $headers
Write-Host "Found $($orgs.value.Count) organization(s):"
foreach ($org in $orgs.value) {
    Write-Host "  - $($org.accountName) (ID: $($org.accountId))"
}

# Test first org
$orgName = $orgs.value[0].accountName
Write-Host "`n=== Testing org: $orgName ===" -ForegroundColor Cyan

# 3) Groups
Write-Host "`n--- Groups API ---" -ForegroundColor Yellow
$groupsResp = Invoke-RestMethod -Uri "https://vssps.dev.azure.com/$orgName/_apis/graph/groups?api-version=7.1-preview.1" -Headers $headers
Write-Host "Found $($groupsResp.value.Count) groups"

# Find Project Collection Administrators
$pcaGroup = $groupsResp.value | Where-Object { $_.displayName -eq 'Project Collection Administrators' }
if ($pcaGroup) {
    Write-Host "`nProject Collection Administrators group:"
    Write-Host "  displayName: $($pcaGroup.displayName)"
    Write-Host "  descriptor: $($pcaGroup.descriptor)"
    Write-Host "  principalName: $($pcaGroup.principalName)"
    
    # 4) Memberships for PCA group
    Write-Host "`n--- Memberships API (direction=Down) ---" -ForegroundColor Yellow
    $membershipsUrl = "https://vssps.dev.azure.com/$orgName/_apis/graph/memberships/$([Uri]::EscapeDataString($pcaGroup.descriptor))?direction=Down&api-version=7.1-preview.1"
    Write-Host "URL: $membershipsUrl"
    $memberships = Invoke-RestMethod -Uri $membershipsUrl -Headers $headers
    Write-Host "Found $($memberships.value.Count) membership(s):"
    foreach ($m in $memberships.value) {
        Write-Host "  memberDescriptor: $($m.memberDescriptor)"
    }
    
    # 5) Subject Lookup for those members
    if ($memberships.value.Count -gt 0) {
        Write-Host "`n--- Subject Lookup API ---" -ForegroundColor Yellow
        $lookupKeys = @($memberships.value | ForEach-Object { @{ descriptor = $_.memberDescriptor } })
        $lookupBody = @{ lookupKeys = $lookupKeys } | ConvertTo-Json -Depth 3
        Write-Host "Request body: $lookupBody"
        
        $lookupResp = Invoke-RestMethod -Uri "https://vssps.dev.azure.com/$orgName/_apis/graph/subjectlookup?api-version=7.1-preview.1" -Method Post -Headers $headers -Body $lookupBody -ContentType 'application/json'
        Write-Host "Subject lookup response type: $($lookupResp.GetType().Name)"
        Write-Host "Subject lookup value type: $($lookupResp.value.GetType().Name)"
        
        # The response.value is an object where keys are descriptors
        $resolvedSubjects = $lookupResp.value
        Write-Host "Resolved subjects:"
        if ($resolvedSubjects -is [PSCustomObject]) {
            $resolvedSubjects.PSObject.Properties | ForEach-Object {
                Write-Host "  Key: $($_.Name)"
                $s = $_.Value
                Write-Host "    displayName: $($s.displayName)"
                Write-Host "    mailAddress: $($s.mailAddress)"
                Write-Host "    subjectKind: $($s.subjectKind)"
                Write-Host "    originId: $($s.originId)"
            }
        } else {
            Write-Host "  Raw: $($resolvedSubjects | ConvertTo-Json -Depth 3)"
        }
    }
} else {
    Write-Host "Project Collection Administrators group NOT found!" -ForegroundColor Red
    Write-Host "Available groups with 'Administrator' in name:"
    $groupsResp.value | Where-Object { $_.displayName -like '*Administrator*' } | ForEach-Object {
        Write-Host "  - $($_.displayName) | principalName: $($_.principalName) | descriptor: $($_.descriptor)"
    }
}

# Show a few sample groups with principalName patterns
Write-Host "`n--- Sample group principalNames ---" -ForegroundColor Yellow
$groupsResp.value | Select-Object -First 10 | ForEach-Object {
    Write-Host "  $($_.displayName) => $($_.principalName)"
}
