<#
.SYNOPSIS
    Install-Prerequisites.ps1
    Installs all PowerShell modules required by EntraChecks.

.DESCRIPTION
    This helper script checks for and installs the Microsoft Graph SDK
    and Azure PowerShell modules needed to run EntraChecks assessments.

    Run this once before your first assessment. It is safe to run again --
    it skips modules that are already installed.

    Requires an internet connection and PowerShell 5.1 or later.

.EXAMPLE
    .\Install-Prerequisites.ps1
    # Installs everything needed for all modules

.EXAMPLE
    .\Install-Prerequisites.ps1 -GraphOnly
    # Installs only the Microsoft Graph SDK (skip Azure modules)

.NOTES
    Version: 1.0.1
    Author:  David Stells
#>

[CmdletBinding()]
param(
    [switch]$GraphOnly
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message, [string]$Status = "INFO")
    $colors = @{ INFO = "Cyan"; OK = "Green"; WARN = "Yellow"; FAIL = "Red" }
    $symbol = @{ INFO = "[*]"; OK = "[+]"; WARN = "[!]"; FAIL = "[X]" }
    Write-Host "$($symbol[$Status]) $Message" -ForegroundColor $colors[$Status]
}

# -- Header ----------------------------------------------------------------

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host "       EntraChecks -- Prerequisite Installer               " -ForegroundColor Cyan
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host ""

# -- Check PowerShell version ----------------------------------------------

Write-Step "PowerShell version: $($PSVersionTable.PSVersion)"
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Step "PowerShell 5.1 or later is required. Please update Windows Management Framework." "FAIL"
    exit 1
}
Write-Step "PowerShell version OK" "OK"

# -- Check NuGet provider --------------------------------------------------

Write-Step "Checking NuGet package provider..."
$nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
if (-not $nuget -or $nuget.Version -lt [version]"2.8.5.201") {
    Write-Step "Installing NuGet provider..."
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        Write-Step "NuGet provider installed" "OK"
    }
    catch {
        Write-Step "Failed to install NuGet provider: $($_.Exception.Message)" "FAIL"
        Write-Step "Try running PowerShell as Administrator and run this script again." "WARN"
        exit 1
    }
}
else {
    Write-Step "NuGet provider already installed" "OK"
}

# -- Set PSGallery as trusted ----------------------------------------------

$gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
if (-not $gallery) {
    Write-Step "PSGallery not registered -- registering now..."
    Register-PSRepository -Default -ErrorAction SilentlyContinue
    $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
}
if ($gallery -and $gallery.InstallationPolicy -ne "Trusted") {
    Write-Step "Setting PSGallery as trusted repository..."
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

# -- Install function ------------------------------------------------------

function Install-RequiredModule {
    param(
        [string]$ModuleName,
        [string]$Purpose,
        [string]$MinimumVersion = ''
    )

    $existing = Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue
    $latestExisting = $null
    if ($existing) {
        $latestExisting = ($existing | Sort-Object Version -Descending | Select-Object -First 1)
    }

    $needsInstall = $false
    $needsUpgrade = $false

    if (-not $latestExisting) {
        $needsInstall = $true
    }
    elseif ($MinimumVersion) {
        $required = [version]$MinimumVersion
        if ($latestExisting.Version -lt $required) {
            $needsUpgrade = $true
        }
    }

    if (-not $needsInstall -and -not $needsUpgrade) {
        $versionText = if ($MinimumVersion) { "$($latestExisting.Version) (>= $MinimumVersion required)" } else { $latestExisting.Version }
        Write-Step "$ModuleName v$versionText already installed - $Purpose" "OK"
        return
    }

    $action = if ($needsUpgrade) { "Upgrading" } else { "Installing" }
    Write-Step "$action $ModuleName - $Purpose"
    try {
        $installParams = @{}
        $installParams['Name'] = $ModuleName
        $installParams['Scope'] = 'CurrentUser'
        $installParams['Force'] = $true
        $installParams['AllowClobber'] = $true
        $installParams['ErrorAction'] = 'Stop'
        if ($MinimumVersion) { $installParams['MinimumVersion'] = $MinimumVersion }
        Install-Module @installParams

        $ver = (Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Step "$ModuleName v$ver installed successfully" "OK"
    }
    catch {
        Write-Step "Failed to install $ModuleName : $($_.Exception.Message)" "FAIL"
        $minArg = if ($MinimumVersion) { " -MinimumVersion $MinimumVersion" } else { '' }
        Write-Step "You can install it manually later: Install-Module $ModuleName$minArg -Scope CurrentUser -Force" "WARN"
    }
}

# -- Microsoft Graph SDK (required) ----------------------------------------

Write-Host ""
Write-Host "-- Microsoft Graph SDK (Required) --------------------------" -ForegroundColor White
Install-RequiredModule "Microsoft.Graph" "Core Graph API access for all modules"

# -- Azure modules (optional) ----------------------------------------------

if (-not $GraphOnly) {
    Write-Host ""
    Write-Host "-- Azure PowerShell Modules (For AzurePolicy and Defender) --" -ForegroundColor White
    Install-RequiredModule "Az.Accounts"       "Azure authentication"
    Install-RequiredModule "Az.PolicyInsights"  "Azure Policy compliance data"
    Install-RequiredModule "Az.Resources"       "Azure resource inventory"
    Install-RequiredModule "Az.Security"        "Defender for Cloud compliance"

    Write-Host ""
    Write-Host "-- SOC 2 Phase 2 Azure Modules -----------------------------" -ForegroundColor White
    Install-RequiredModule "Az.RecoveryServices"    "SOC 2 Phase 2: backup posture (A1.2)"   -MinimumVersion "6.0.0"
    Install-RequiredModule "Az.Monitor"             "SOC 2 Phase 2: tenant diagnostic settings (CC4.1/CC7.2)" -MinimumVersion "4.0.0"
    Install-RequiredModule "Az.OperationalInsights" "SOC 2 Phase 2: Log Analytics workspace validation"
}
else {
    Write-Host ""
    Write-Step "Skipping Azure modules (-GraphOnly specified)" "INFO"
    Write-Step "Install later if needed: .\Install-Prerequisites.ps1" "INFO"
}

# -- Unblock scripts -------------------------------------------------------

Write-Host ""
Write-Host "-- Unblock EntraChecks Scripts -----------------------------" -ForegroundColor White
$scriptRoot = $PSScriptRoot
if ($scriptRoot) {
    $blocked = Get-ChildItem -Path $scriptRoot -Recurse -Include *.ps1, *.psm1
    $blocked | Unblock-File -ErrorAction SilentlyContinue
    Write-Step "Unblocked $($blocked.Count) script files" "OK"
}

# -- Summary ---------------------------------------------------------------

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Green
Write-Host "              Setup Complete!                               " -ForegroundColor Green
Write-Host "  ========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Next step: run the assessment" -ForegroundColor White
Write-Host ""
Write-Host "    .\Start-EntraChecks.ps1" -ForegroundColor Yellow
Write-Host ""
Write-Host "  This will open a browser for Microsoft sign-in." -ForegroundColor Gray
Write-Host "  Sign in with a Global Reader or Global Admin account." -ForegroundColor Gray
Write-Host ""
