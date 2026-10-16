function Remove-M365Scan {
    <#
    .SYNOPSIS
        Deletes a scan and all its results, progress and logs from the local database.
    .PARAMETER ScanId
        The scan(s) to delete. Accepts pipeline input from Get-M365Scan.
    .EXAMPLE
        Remove-M365Scan -ScanId 4
    .EXAMPLE
        Get-M365Scan | Where-Object Status -eq 'Failed' | Remove-M365Scan -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [long[]]$ScanId
    )

    begin {
        $engine = Get-M365Engine
    }

    process {
        foreach ($id in $ScanId) {
            if (-not $PSCmdlet.ShouldProcess("Scan $id", 'Delete scan and all its results')) { continue }
            if ($engine.DeleteScan($id)) {
                Write-Host "Deleted scan $id." -ForegroundColor Yellow
            }
            else {
                Write-Warning "Scan $id not found."
            }
        }
    }
}
