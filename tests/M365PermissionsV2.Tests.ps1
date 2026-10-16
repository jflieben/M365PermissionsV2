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
                'Start-M365GUI', 'Stop-M365GUI',
                'Get-M365Scan', 'Get-M365RiskSummary', 'Remove-M365Scan', 'Invoke-M365PolicyEvaluation'
            )
            foreach ($fn in $expected) {
                $manifest.ExportedFunctions.Keys | Should -Contain $fn
            }
        }

        It 'Exports every public function and has a file for every export' {
            $manifest = Test-ModuleManifest -Path $manifestPath
            $files = Get-ChildItem -Path (Join-Path $modulePath 'public') -Filter '*.ps1' | ForEach-Object BaseName
            foreach ($name in $files) { $manifest.ExportedFunctions.Keys | Should -Contain $name }
            foreach ($name in $manifest.ExportedFunctions.Keys) { $files | Should -Contain $name }
        }

        It 'Has no HelpInfoURI (it breaks Update-Help)' {
            $data = Import-PowerShellDataFile -Path $manifestPath
            $data.ContainsKey('HelpInfoURI') | Should -BeFalse
            $data.PrivateData.PSData.ProjectUri | Should -Not -BeNullOrEmpty
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

        It 'Public functions never call Write-Output (it pollutes return values)' {
            Get-ChildItem -Path (Join-Path $modulePath 'public') -Filter '*.ps1' | ForEach-Object {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null)
                $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Write-Output' }, $true)
                @($calls).Count | Should -Be 0 -Because "$($_.Name) should not use Write-Output"
            }
        }

        It 'Cmdlets expose the documented parameters' -TestCases @(
            @{ Name = 'Get-M365Permissions'; Params = @('ScanId', 'Category', 'SearchText', 'RiskLevel', 'All', 'Page', 'PageSize') }
            @{ Name = 'Export-M365Permissions'; Params = @('ScanId', 'Category', 'Format', 'OutputPath') }
            @{ Name = 'Compare-M365Scans'; Params = @('OldScanId', 'NewScanId', 'Category') }
            @{ Name = 'Set-M365Config'; Params = @('GuiPort', 'MaxThreads', 'OutputFormat', 'LogLevel', 'DefaultTimeoutMinutes') }
            @{ Name = 'Get-M365Scan'; Params = @('ScanId', 'TenantId', 'AllTenants', 'Limit') }
            @{ Name = 'Get-M365RiskSummary'; Params = @('ScanId', 'Category') }
            @{ Name = 'Remove-M365Scan'; Params = @('ScanId') }
            @{ Name = 'Invoke-M365PolicyEvaluation'; Params = @('ScanId', 'Category', 'MaxViolations', 'Rescore') }
        ) {
            param($Name, $Params)
            $path = Join-Path $modulePath 'public' "$Name.ps1"
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
            $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
            $fn | Should -Not -BeNullOrEmpty
            $declared = $fn.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
            foreach ($p in $Params) { $declared | Should -Contain $p }
        }

        It 'Destructive cmdlets support -WhatIf/-Confirm' -TestCases @(
            @{ Name = 'Remove-M365Scan' }
            @{ Name = 'Invoke-M365PolicyEvaluation' }
        ) {
            param($Name)
            $path = Join-Path $modulePath 'public' "$Name.ps1"
            (Get-Content -Raw $path) | Should -Match 'SupportsShouldProcess'
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

        It 'Chart.js is vendored locally, not loaded from a CDN' {
            Join-Path $modulePath 'gui' 'static' 'vendor' 'chart.umd.min.js' | Should -Exist
            $html = Get-Content -Raw (Join-Path $modulePath 'gui' 'static' 'index.html')
            $html | Should -Match 'src="vendor/chart\.umd\.min\.js"'
            $html | Should -Not -Match 'cdn\.jsdelivr\.net'
        }
    }
}
