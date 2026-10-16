@{
    RootModule           = 'M365Permissions.psm1'
    ModuleVersion        = '2.1.0'
    CompatiblePSEditions = @('Core')
    GUID                 = '748c97a1-b861-4bc5-8455-53494b565526'
    Author               = 'Jos Lieben (jos@lieben.nu)'
    CompanyName          = 'JSolve B.V.'
    Copyright            = 'https://jsolve.nl/commercial-use.html'
    Description          = @'
M365Permissions - Microsoft 365 & Azure Permission Scanner

For scheduled, unattended scans with change alerts, a risk queue and item-level depth, see the M365Permissions Cloud Edition, which runs in your own Azure subscription: https://m365permissions.com

This module reports on permissions across SharePoint, OneDrive, Entra ID, Teams, Exchange Online, Power BI, Power Platform, Azure RBAC, Azure DevOps and Purview, scores them with risk policies that include remediation advice, and compares scans over time.
It can scan multiple tenants and show an overview of all permissions for e.g. a specific user.

INSTALLATION:
    Install-PSResource -Name M365Permissions -Repository PSGallery

USAGE:
    Import-Module M365Permissions   # Opens GUI automatically in your browser

Free for non-commercial use. See https://jsolve.nl/commercial-use.html
'@
    PowerShellVersion    = '7.4'

    # .NET assemblies loaded from lib/ subfolder
    RequiredAssemblies   = @(
        'lib\M365Permissions.Engine.dll',
        'lib\Microsoft.Data.Sqlite.dll',
        'lib\SQLitePCLRaw.core.dll',
        'lib\SQLitePCLRaw.provider.e_sqlite3.dll',
        'lib\SQLitePCLRaw.batteries_v2.dll',
        'lib\ClosedXML.dll',
        'lib\DocumentFormat.OpenXml.dll',
        'lib\SixLabors.Fonts.dll'
    )

    FunctionsToExport    = @(
        'Connect-M365',
        'Disconnect-M365',
        'Start-M365Scan',
        'Stop-M365Scan',
        'Start-M365GUI',
        'Stop-M365GUI',
        'Get-M365Permissions',
        'Export-M365Permissions',
        'Compare-M365Scans',
        'Get-M365Config',
        'Set-M365Config',
        'Get-M365ScanStatus',
        'Get-M365Scan',
        'Get-M365RiskSummary',
        'Remove-M365Scan',
        'Invoke-M365PolicyEvaluation'
    )

    CmdletsToExport      = @()
    VariablesToExport     = @()
    AliasesToExport       = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('M365Permissions', 'Microsoft365', 'SharePoint', 'Entra', 'Exchange', 'Security', 'Audit', 'Azure', 'PowerBI', 'PowerPlatform', 'DevOps')
            LicenseUri   = 'https://jsolve.nl/commercial-use.html'
            ProjectUri   = 'https://m365permissions.com'
            ReleaseNotes = 'See https://github.com/jflieben/M365PermissionsV2'
        }
    }
}
