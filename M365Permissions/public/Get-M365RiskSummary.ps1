function Get-M365RiskSummary {
    <#
    .SYNOPSIS
        Counts the permission entries of a scan per risk level, and the change since the previous scan.
    .PARAMETER ScanId
        The scan to summarise. Default: the latest Completed or CompletedWithErrors scan of the
        connected tenant.
    .PARAMETER Category
        Count only this category (the delta always covers the whole scan).
    .EXAMPLE
        Get-M365RiskSummary
    .EXAMPLE
        Get-M365RiskSummary -ScanId 12 -Category SharePoint
    #>
    [CmdletBinding()]
    param(
        [long]$ScanId,
        [ValidateSet('SharePoint', 'OneDrive', 'Entra', 'Teams', 'Exchange', 'PowerBI', 'PowerAutomate', 'Azure', 'AzureDevOps', 'Purview')]
        [string]$Category
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
    $counts = $engine.GetRiskSummary($ScanId, $categoryArg)
    $delta = $engine.GetRiskDelta($ScanId)

    return [pscustomobject]@{
        ScanId              = $ScanId
        Category            = if ($Category) { $Category } else { 'All' }
        Critical            = [int]$counts['Critical']
        High                = [int]$counts['High']
        Medium              = [int]$counts['Medium']
        Low                 = [int]$counts['Low']
        Info                = [int]$counts['Info']
        PreviousScanId      = $delta.PreviousScanId
        NewCritical         = $delta.NewCritical
        NewHigh             = $delta.NewHigh
        Added               = $delta.TotalAdded
        Removed             = $delta.TotalRemoved
        Changed             = $delta.TotalChanged
        NotComparedCategories = @($delta.ExcludedCategories | ForEach-Object { $_.Category })
    }
}
