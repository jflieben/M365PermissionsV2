function Get-M365Scan {
    <#
    .SYNOPSIS
        Lists scans, or gets one scan by ID.
    .PARAMETER ScanId
        Return only this scan.
    .PARAMETER TenantId
        Only scans of this tenant. Default: the connected tenant; all tenants when not connected.
    .PARAMETER AllTenants
        Include scans of every tenant.
    .PARAMETER Limit
        Maximum number of scans, newest first. Default 50.
    .EXAMPLE
        Get-M365Scan
    .EXAMPLE
        Get-M365Scan -AllTenants | Where-Object Status -eq 'Completed'
    #>
    [CmdletBinding()]
    param(
        [long]$ScanId,
        [string]$TenantId,
        [switch]$AllTenants,
        [ValidateRange(1, 1000)]
        [int]$Limit = 50
    )

    $engine = Get-M365Engine
    if ($ScanId -gt 0) {
        $scan = $engine.GetScan($ScanId)
        if ($null -eq $scan) { Write-Warning "Scan $ScanId not found." }
        return $scan
    }

    $tenantArg = $null
    if ($TenantId) { $tenantArg = $TenantId }
    elseif (-not $AllTenants) {
        $status = $engine.GetStatus()
        if ($status.Connected -and $status.TenantId) { $tenantArg = $status.TenantId }
    }
    return $engine.GetScans($tenantArg, $Limit)
}
