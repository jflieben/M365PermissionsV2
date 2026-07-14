#Requires -Modules Pester

Describe 'M365Permissions Module' {

    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..' 'M365Permissions'
        $manifestPath = Join-Path $modulePath 'M365Permissions.psd1'
    }

    Context 'Module Manifest' {
        It 'Has a valid manifest' {
            { Test-ModuleManifest -Path $manifestPath } | Should -Not -Throw
        }

        It 'Has the correct module name' {
            $manifest = Test-ModuleManifest -Path $manifestPath
            $manifest.Name | Should -Be 'M365Permissions'
        }

        It 'Exports expected functions' {
            $manifest = Test-ModuleManifest -Path $manifestPath
            $expected = @(
                'Connect-M365', 'Disconnect-M365',
                'Start-M365Scan', 'Stop-M365Scan', 'Get-M365ScanStatus',
                'Get-M365Permissions', 'Export-M365Permissions',
                'Compare-M365Scans',
                'Set-M365Config', 'Get-M365Config',
                'Start-M365GUI', 'Stop-M365GUI'
            )
            foreach ($fn in $expected) {
                $manifest.ExportedFunctions.Keys | Should -Contain $fn
            }
        }

        It 'Requires PowerShell 7.4+' {
            $manifest = Test-ModuleManifest -Path $manifestPath
            $manifest.PowerShellVersion | Should -Be '7.4'
        }
    }

    Context 'Public Functions' {
        It 'All public .ps1 files have valid PowerShell syntax' {
            $publicPath = Join-Path $modulePath 'public'
            Get-ChildItem -Path $publicPath -Filter '*.ps1' -Recurse | ForEach-Object {
                $errors = $null
                [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errors)
                $errors | Should -BeNullOrEmpty -Because "$($_.Name) should have valid syntax"
            }
        }

        It 'Module psm1 has valid syntax' {
            $psm1Path = Join-Path $modulePath 'M365Permissions.psm1'
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($psm1Path, [ref]$null, [ref]$errors)
            $errors | Should -BeNullOrEmpty
        }
    }

    Context 'GUI Files' {
        It 'index.html exists' {
            Join-Path $modulePath 'gui' 'static' 'index.html' | Should -Exist
        }

        It 'app.js exists' {
            Join-Path $modulePath 'gui' 'static' 'app.js' | Should -Exist
        }

        It 'style.css exists' {
            Join-Path $modulePath 'gui' 'static' 'style.css' | Should -Exist
        }
    }
}
