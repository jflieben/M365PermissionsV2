function Get-M365Permissions {
    <#
    .SYNOPSIS
        Retrieves permission entries from a scan.
    .DESCRIPTION
        Without -All, returns one page (a PagedResult with Items and TotalCount).
        With -All, streams every matching PermissionEntry to the pipeline, reading the
        database a page at a time.
    .PARAMETER ScanId
        The scan to query. Default: the latest Completed or CompletedWithErrors scan of the
        connected tenant.
    .PARAMETER Category
        Filter by category: SharePoint, OneDrive, Entra, Teams, Exchange, PowerBI,
        PowerAutomate, Azure, AzureDevOps or Purview.
    .PARAMETER SearchText
        Free-text search across target paths, principal names and roles.
    .PARAMETER RiskLevel
        Only return entries with these risk levels.
    .PARAMETER All
        Stream all matching entries instead of returning one page.
    .PARAMETER Page
        Page number (1-based). Default 1. Ignored with -All.
    .PARAMETER PageSize
        Results per page (max 1000). Default 100. Ignored with -All.
    .EXAMPLE
        Get-M365Permissions -Category SharePoint -SearchText "contoso.com"
    .EXAMPLE
        Get-M365Permissions -All -RiskLevel Critical, High | Export-Csv risky.csv
    #>
    [CmdletBinding()]
    param(
        [long]$ScanId,
        [ValidateSet('SharePoint', 'OneDrive', 'Entra', 'Teams', 'Exchange', 'PowerBI', 'PowerAutomate', 'Azure', 'AzureDevOps', 'Purview')]
        [string]$Category,
        [string]$SearchText,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string[]]$RiskLevel,
        [switch]$All,
        [int]$Page = 1,
        [ValidateRange(1, 1000)]
        [int]$PageSize = 100
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
    $searchArg = if ($SearchText) { $SearchText } else { $null }

    if ($All) {
        $riskArg = if ($RiskLevel) { [string[]]$RiskLevel } else { $null }
        foreach ($entry in $engine.StreamPermissions($ScanId, $categoryArg, $riskArg, $searchArg)) {
            $entry
        }
        return
    }

    $filters = $null
    if ($RiskLevel) {
        $filters = [System.Collections.Generic.Dictionary[string, string]]::new()
        $filters['risk_level'] = $RiskLevel -join '|'
    }
    return $engine.QueryPermissions($ScanId, $categoryArg, $searchArg, $Page, $PageSize, $null, $null, $filters)
}
