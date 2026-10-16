function Compare-M365Scans {
    <#
    .SYNOPSIS
        Compares two scans of the same tenant to find permission changes (added, removed, changed).
    .DESCRIPTION
        Only categories that completed in both scans are compared; the result lists the others in
        ExcludedCategories, and categories that completed with errors in FlaggedCategories.
        Scans of different tenants can't be compared.
    .PARAMETER OldScanId
        The baseline scan.
    .PARAMETER NewScanId
        The scan to compare with the baseline.
    .PARAMETER Category
        Compare only this category.
    .EXAMPLE
        Compare-M365Scans -OldScanId 1 -NewScanId 2
    .EXAMPLE
        (Compare-M365Scans -OldScanId 1 -NewScanId 2 -Category Entra).Added
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [long]$OldScanId,

        [Parameter(Mandatory)]
        [long]$NewScanId,

        [ValidateSet('SharePoint', 'OneDrive', 'Entra', 'Teams', 'Exchange', 'PowerBI', 'PowerAutomate', 'Azure', 'AzureDevOps', 'Purview')]
        [string]$Category
    )

    $engine = Get-M365Engine
    $categoryArg = if ($Category) { $Category } else { $null }
    $result = $engine.CompareScans($OldScanId, $NewScanId, $categoryArg, $null)
    foreach ($note in $result.ExcludedCategories) {
        Write-Warning "Not compared: $($note.Category) ($($note.Reason))"
    }
    foreach ($note in $result.FlaggedCategories) {
        Write-Warning "Partial: $($note.Category) ($($note.Reason))"
    }
    Write-Host "Tip: the M365Permissions Cloud Edition compares every scheduled scan automatically and emails changes or sends them to Microsoft Sentinel: https://m365permissions.com/features" -ForegroundColor DarkGray
    return $result
}
