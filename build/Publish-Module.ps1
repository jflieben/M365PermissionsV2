<#
.SYNOPSIS
    Publishes M365Permissions module to PSGallery.
.PARAMETER NuGetApiKey
    PSGallery API key.
.PARAMETER WhatIf
    Preview what would be published without actually publishing.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$NuGetApiKey,

    [string]$ModulePath = (Join-Path $PSScriptRoot '..' 'module')
)

$ErrorActionPreference = 'Stop'

# Validate module loads
Write-Host "Validating module manifest..." -ForegroundColor Cyan
$manifest = Test-ModuleManifest -Path (Join-Path $ModulePath 'M365Permissions.psd1')
Write-Host "Module: $($manifest.Name) v$($manifest.Version)" -ForegroundColor Green

# Check lib/ exists
$libPath = Join-Path $ModulePath 'lib'
if (-not (Test-Path $libPath)) {
    throw "lib/ directory not found. Run Build-Module.ps1 first."
}

# Publish
if ($PSCmdlet.ShouldProcess("$($manifest.Name) v$($manifest.Version)", "Publish to PSGallery")) {
    Write-Host "Publishing to PSGallery..." -ForegroundColor Cyan
    Publish-Module -Path $ModulePath -NuGetApiKey $NuGetApiKey -Repository PSGallery
    Write-Host "Published $($manifest.Name) v$($manifest.Version) to PSGallery" -ForegroundColor Green
}
