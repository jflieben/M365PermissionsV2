function Invoke-M365PolicyEvaluation {
    <#
    .SYNOPSIS
        Evaluates the enabled policies against every row of a scan, or re-scores the scan.
    .DESCRIPTION
        Risk levels are stored when a scan runs. Without -Rescore this reports what the current
        policies match (counts per policy plus the most severe violating rows) without changing
        anything. With -Rescore the current policies are re-applied and the stored risk levels of
        the scan are updated.
    .PARAMETER ScanId
        The scan. Default: the latest Completed or CompletedWithErrors scan of the connected tenant.
    .PARAMETER Category
        Evaluate only this category (ignored with -Rescore, which always covers the whole scan).
    .PARAMETER MaxViolations
        Number of violating rows to return (most severe first). Default 500.
    .PARAMETER Rescore
        Update the stored risk levels of the scan with the current policies.
    .EXAMPLE
        Invoke-M365PolicyEvaluation
    .EXAMPLE
        (Invoke-M365PolicyEvaluation -ScanId 7).PerPolicy | Format-Table
    .EXAMPLE
        Invoke-M365PolicyEvaluation -ScanId 7 -Rescore
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [long]$ScanId,
        [ValidateSet('SharePoint', 'OneDrive', 'Entra', 'Teams', 'Exchange', 'PowerBI', 'PowerAutomate', 'Azure', 'AzureDevOps', 'Purview')]
        [string]$Category,
        [ValidateRange(0, 5000)]
        [int]$MaxViolations = 500,
        [switch]$Rescore
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

    if ($Rescore) {
        if (-not $PSCmdlet.ShouldProcess("Scan $ScanId", 'Re-score stored risk levels with the current policies')) { return }
        $result = $engine.RescoreScan($ScanId)
        Write-Host "Scan $ScanId re-scored: $($result.EntriesChanged) of $($result.EntriesScored) rows changed." -ForegroundColor Green
        return $result
    }

    $categoryArg = if ($Category) { $Category } else { $null }
    $result = $engine.EvaluatePolicies($ScanId, $categoryArg, $MaxViolations)
    foreach ($warning in $result.Warnings) { Write-Warning $warning }
    return $result
}
