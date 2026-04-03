@{
    RootModule           = 'M365PermissionsV2.psm1'
    ModuleVersion        = '2.0.0'
    CompatiblePSEditions = @('Core')
    GUID                 = 'a3e2f8c1-9d4b-4a6e-b7c5-1f8d3e2a4b6c'
    Author               = 'Jos Lieben (jos@lieben.nu)'
    CompanyName          = 'Lieben Consultancy'
    Copyright            = 'https://www.lieben.nu/liebensraum/commercial-use/'
    HelpInfoURI          = 'https://github.com/jflieben/M365PermissionsV2'
    Description          = @'
M365PermissionsV2 - Microsoft 365 Permission Scanner

Reports on permissions across SharePoint, Entra ID, Exchange Online, OneDrive, Power BI, Power Platform, Azure RBAC, and Azure DevOps.
Built on .NET 8 with embedded SQLite database and web GUI.

INSTALLATION:
    Install-PSResource -Name M365PermissionsV2 -Repository PSGallery

USAGE:
    Import-Module M365PermissionsV2   # Opens GUI automatically in your browser

Free for non-commercial use. See https://www.lieben.nu/liebensraum/commercial-use/
For the enterprise Azure-native version, see https://www.m365permissions.com
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
        'Stop-M365GUI'
    )

    CmdletsToExport      = @()
    VariablesToExport     = @()
    AliasesToExport       = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('M365', 'Permissions', 'SharePoint', 'Entra', 'Exchange', 'Security', 'Audit')
            LicenseUri   = 'https://www.lieben.nu/liebensraum/commercial-use/'
            ProjectUri   = 'https://github.com/jflieben/M365PermissionsV2'
            ReleaseNotes = 'Initial release - V2 rewrite with .NET 8 engine, SQLite storage, embedded GUI.'
        }
    }
}
