function Export-M365Permissions {
    <#
    .SYNOPSIS
        Exports scan results to an XLSX or CSV file.
    .DESCRIPTION
        CSV is streamed to disk, so it works for scans of any size. XLSX holds the workbook in
        memory and is limited to 250,000 rows (per exported category); it includes an About sheet
        with the scan's tenant, date, per-category status and risk counts.
    .PARAMETER ScanId
        The scan to export. Default: the latest Completed or CompletedWithErrors scan of the
        connected tenant.
    .PARAMETER Category
        Export only this category.
    .PARAMETER Format
        Output format: XLSX or CSV. Default XLSX.
    .PARAMETER OutputPath
        File to write. Relative paths are resolved against the current location. Default:
        M365Permissions_<Category|All>_<ScanId>.<ext> in the current location.
    .EXAMPLE
        Export-M365Permissions
    .EXAMPLE
        Export-M365Permissions -ScanId 3 -Category Exchange -Format CSV -OutputPath .\exchange.csv
    #>
    [CmdletBinding()]
    param(
        [long]$ScanId,
        [ValidateSet('SharePoint', 'OneDrive', 'Entra', 'Teams', 'Exchange', 'PowerBI', 'PowerAutomate', 'Azure', 'AzureDevOps', 'Purview')]
        [string]$Category,
        [ValidateSet('XLSX', 'CSV')]
        [string]$Format = 'XLSX',
        [string]$OutputPath
    )

    $engine = Get-M365Engine
    if ($ScanId -eq 0) {
        $defaultScan = $engine.GetDefaultScanId()
        if ($null -eq $defaultScan) {
            Write-Warning "No completed scans found. Run Start-M365Scan first."
            return
        }
        $ScanId = $defaultScan
    }

    $categoryArg = if ($Category) { $Category } else { $null }
    if (-not $OutputPath) {
        $suffix = if ($Category) { $Category } else { 'All' }
        $OutputPath = "M365Permissions_${suffix}_${ScanId}.$($Format.ToLower())"
    }
    # .NET resolves relative paths against the process directory, not the PowerShell location.
    $fullPath = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

    $null = $engine.ExportScanToFile($ScanId, $Format.ToLower(), $categoryArg, $fullPath)
    Write-Host "Exported scan $ScanId to $fullPath" -ForegroundColor Green
    return $fullPath
}
