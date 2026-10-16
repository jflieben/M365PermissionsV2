function Set-M365Config {
    <#
    .SYNOPSIS
        Updates module configuration settings.
    .PARAMETER GuiPort
        TCP port for the web GUI (default 8080).
    .PARAMETER MaxThreads
        Maximum parallel threads for scanning (default 5).
    .PARAMETER OutputFormat
        Default export format: XLSX or CSV.
    .PARAMETER LogLevel
        Which scan log lines are saved to the database: None, Minimal (warnings and errors), Normal (+ info) or Verbose (everything).
    .PARAMETER DefaultTimeoutMinutes
        Default scan timeout in minutes (default 120).
    .EXAMPLE
        Set-M365Config -GuiPort 9090 -MaxThreads 10
    .EXAMPLE
        Set-M365Config -DefaultTimeoutMinutes 240
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1024, 65535)]
        [int]$GuiPort,
        [ValidateRange(1, 50)]
        [int]$MaxThreads,
        [ValidateSet('XLSX', 'CSV')]
        [string]$OutputFormat,
        [ValidateSet('None', 'Minimal', 'Normal', 'Verbose')]
        [string]$LogLevel,
        [ValidateRange(1, 1440)]
        [int]$DefaultTimeoutMinutes
    )

    $engine = Get-M365Engine
    $config = $engine.GetConfig()

    if ($PSBoundParameters.ContainsKey('GuiPort'))     { $config.GuiPort = $GuiPort }
    if ($PSBoundParameters.ContainsKey('MaxThreads'))   { $config.MaxThreads = $MaxThreads }
    if ($PSBoundParameters.ContainsKey('OutputFormat')) { $config.OutputFormat = $OutputFormat }
    if ($PSBoundParameters.ContainsKey('LogLevel'))    { $config.LogLevel = $LogLevel }
    if ($PSBoundParameters.ContainsKey('DefaultTimeoutMinutes')) { $config.DefaultTimeoutMinutes = $DefaultTimeoutMinutes }

    $engine.UpdateConfig($config)
    Write-Host "Configuration updated." -ForegroundColor Green
}
