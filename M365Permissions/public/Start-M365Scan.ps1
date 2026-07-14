function Start-M365Scan {
    <#
    .SYNOPSIS
        Starts a permission scan across selected Microsoft 365 services.
    .PARAMETER ScanTypes
        Which services to scan. Default is all available: SharePoint, Entra, Exchange.
    .EXAMPLE
        Start-M365Scan
    .EXAMPLE
        Start-M365Scan -ScanTypes SharePoint, Entra
    .EXAMPLE
        Start-M365Scan -ScanTypes Entra, Teams -Wait
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('SharePoint', 'Entra', 'Teams', 'Exchange', 'OneDrive', 'PowerBI', 'PowerAutomate', 'Azure', 'AzureDevOps', 'Purview')]
        [string[]]$ScanTypes = @('SharePoint', 'Entra', 'Exchange'),

        # Block until the scan finishes, showing a progress bar instead of returning immediately.
        [switch]$Wait
    )

    $engine = Get-M365Engine
    $task = $engine.StartScanAsync($ScanTypes)
    $scanId = $task.GetAwaiter().GetResult()
    Write-Host "Scan started (ID: $scanId)." -ForegroundColor Cyan

    if (-not $Wait) {
        Write-Host "Use Get-M365ScanStatus to monitor progress." -ForegroundColor Cyan
        return $scanId
    }

    try {
        while ($true) {
            Start-Sleep -Seconds 2
            $progress = $engine.GetScanProgress()
            if ($null -eq $progress) { continue }

            $status = $progress.OverallStatus.ToString()
            $percent = [math]::Min(100, [int]$progress.OverallPercent)
            $eta = $progress.EstimatedTimeRemaining
            Write-Progress -Activity "M365 Scan #$scanId" -Status "$status - $percent%$(if ($eta) { " ($eta)" })" -PercentComplete $percent

            if ($status -notin @('Running', 'Pending')) { break }
        }
    }
    finally {
        Write-Progress -Activity "M365 Scan #$scanId" -Completed
    }

    $final = $engine.GetScanProgress()
    $finalStatus = if ($final) { $final.OverallStatus.ToString() } else { 'Unknown' }
    $color = if ($finalStatus -eq 'Completed') { 'Green' } elseif ($finalStatus -eq 'CompletedWithErrors') { 'Yellow' } else { 'Red' }
    Write-Host "Scan #$scanId finished: $finalStatus" -ForegroundColor $color
    return $scanId
}
