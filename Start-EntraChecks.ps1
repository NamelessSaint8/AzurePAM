<#
.SYNOPSIS
    Start-EntraChecks.ps1
    Unified orchestration script for EntraChecks compliance assessment suite

.DESCRIPTION
    This is the main entry point for the EntraChecks compliance assessment toolkit.
    It provides:
    
    - Interactive menu-driven interface
    - Modular execution (run individual modules or all)
    - Unified authentication management
    - Automatic report generation
    - Snapshot management for delta reporting
    - CI/CD automation support
    
    Use this script to run comprehensive compliance assessments across:
    - Microsoft Entra ID (Azure AD)
    - Microsoft Secure Score
    - Microsoft Defender for Cloud
    - Azure Policy
    - Microsoft Purview Compliance Manager

.PARAMETER Mode
    Execution mode:
    - Interactive: Menu-driven interface (default)
    - Quick: Run all modules with minimal prompts
    - Scheduled: Silent execution for automation

.PARAMETER TenantName
    Name of the tenant being assessed.

.PARAMETER OutputDirectory
    Base directory for all output files.

.PARAMETER Modules
    Specific modules to run. Options:
    - Core: EntraChecks core (25 checks)
    - IdentityProtection: Risk-based checks
    - Devices: Intune/device checks
    - SecureScore: Microsoft Secure Score
    - Defender: Defender for Cloud compliance
    - AzurePolicy: Azure Policy compliance
    - Purview: Compliance Manager
    - All: Run everything

.PARAMETER SkipAuthentication
    Skip authentication prompts (use existing sessions).

.PARAMETER SaveSnapshot
    Save assessment results as a snapshot after completion.

.PARAMETER CompareWithLast
    Compare results with the last snapshot.

.PARAMETER ExportFormat
    Output formats: HTML, CSV, JSON, All

.PARAMETER ConfigFile
    Path to configuration JSON file. When specified, configuration is loaded from file.
    Command-line parameters override configuration file values.

.PARAMETER Environment
    Environment name for environment-specific configuration overrides (e.g., "dev", "staging", "prod").
    Requires a corresponding config file (e.g., entrachecks.config.prod.json).

.EXAMPLE
    .\Start-EntraChecks.ps1
    # Launches interactive menu

.EXAMPLE
    .\Start-EntraChecks.ps1 -Mode Quick -TenantName "Contoso" -Modules All
    # Runs all modules with minimal prompts

.EXAMPLE
    .\Start-EntraChecks.ps1 -Mode Scheduled -Modules Core,SecureScore -SaveSnapshot
    # Automation mode with snapshot

.EXAMPLE
    .\Start-EntraChecks.ps1 -ConfigFile ".\config\entrachecks.config.json"
    # Load configuration from file

.EXAMPLE
    .\Start-EntraChecks.ps1 -ConfigFile ".\config\entrachecks.config.json" -Environment "prod"
    # Load base config with production environment overrides

.EXAMPLE
    .\Start-EntraChecks.ps1 -ConfigFile ".\config\entrachecks.config.json" -Modules Core
    # Load config but override Modules parameter (parameters take precedence)

.NOTES
    Version: 1.0.0
    Author: David Stells
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("Interactive", "Quick", "Scheduled", "Hybrid")]
    [string]$Mode = "Interactive",

    [Parameter()]
    [string]$TenantName,

    [Parameter()]
    [string]$OutputDirectory = ".\Reports",

    [Parameter()]
    [ValidateSet("Core", "IdentityProtection", "Devices", "SecureScore", "Defender", "AzurePolicy", "Purview", "ActiveDirectory", "All")]
    [string[]]$Modules,

    [switch]$SkipAuthentication,

    [switch]$SaveSnapshot,

    [switch]$CompareWithLast,

    [Parameter()]
    [ValidateSet("HTML", "CSV", "JSON", "All")]
    [string]$ExportFormat = "All",

    [Parameter()]
    [string]$ConfigFile,

    [Parameter()]
    [string]$Environment,

    # Comprehensive Reporting Options
    [switch]$GenerateComprehensiveReport,

    [switch]$GenerateExecutiveSummary,

    [switch]$GenerateExcelReport,

    [switch]$GenerateRemediationScripts,

    # PR 2 of Privileged Identity Roster: emit the AD privileged-identity
    # roster as JSON to the output directory. Independent of the full report
    # pipeline so auditors can consume the roster before PR 5 lands its UI.
    [switch]$EmitPrivilegedRoster,

    # PR 4 of Privileged Identity Roster: optional JSON file with operator-
    # asserted AD-SID <-> Entra-Object-ID equivalences. Used by the cross-
    # surface correlator to harden weak/no auto-match cases.
    # Schema: [{ "AdSid": "...", "EntraObjectId": "...", "CanonicalId": "..." }]
    [string]$IdentityOverridesPath,

    # PR 4 of HTML-Reporting-Consolidation-Plan — HTML output routing.
    # Default flipped to 'Cockpit': one analyst-focused HTML per run.
    # Deep dives are opt-in via -HtmlDeepDiveDomains. 'LegacyAll' restores
    # the pre-PR-4 multi-report behavior for users who depend on it.
    [Parameter()]
    [ValidateSet('Cockpit', 'CockpitAndDeepDives', 'DeepDivesOnly', 'LegacyAll')]
    [string]$HtmlReportSet,

    [Parameter()]
    [ValidateSet('SecureScore', 'DefenderCompliance', 'AzurePolicy', 'PurviewCompliance', 'Delta', 'PrivilegedIdentity')]
    [string[]]$HtmlDeepDiveDomains
)

# Default comprehensive report and executive summary to enabled
if (-not $PSBoundParameters.ContainsKey('GenerateComprehensiveReport')) {
    $GenerateComprehensiveReport = [switch]::new($true)
}
if (-not $PSBoundParameters.ContainsKey('GenerateExecutiveSummary')) {
    $GenerateExecutiveSummary = [switch]::new($true)
}

# HTML reporting defaults (PR 4 of HTML-Reporting-Consolidation-Plan).
# Param > config block > hard default. The config block is read after the
# config-file load below — we re-apply the precedence then.
if (-not $PSBoundParameters.ContainsKey('HtmlReportSet')) { $HtmlReportSet = 'Cockpit' }
if (-not $PSBoundParameters.ContainsKey('HtmlDeepDiveDomains')) { $HtmlDeepDiveDomains = @() }

#region ==================== ENCODING FIX ====================
# Fix console encoding to properly display Unicode characters
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
}
catch {
    # Non-fatal: Continue with default encoding if UTF-8 cannot be set
    Write-Verbose "Could not set UTF-8 encoding: $_"
}
#endregion

#region ==================== WAM BROKER FIX ====================
# Disable WAM (Web Account Manager) broker globally before any Az module loads.
# WAM causes Azure.Identity.Broker DLL version conflicts with
# SharedTokenCacheCredentialBrokerOptions constructor errors.
try {
    Update-AzConfig -EnableLoginByWam $false -ErrorAction SilentlyContinue | Out-Null
}
catch {
    Write-Verbose "Az module not yet loaded - WAM config will take effect when loaded: $_"
}
#endregion

#region ==================== CONFIGURATION ====================

$script:Version = "1.0.0"
$script:ScriptRoot = $PSScriptRoot
$script:ModulesPath = Join-Path $PSScriptRoot "Modules"
$script:SnapshotsPath = Join-Path $PSScriptRoot "Snapshots"
$script:LogsPath = Join-Path $PSScriptRoot "Logs"

# Initialize data collection variables
$script:Findings = @()
$script:SecureScoreData = $null
$script:HybridCorrelationData = $null
$script:DefenderComplianceData = $null
$script:AzurePolicyData = $null
$script:PurviewComplianceData = $null

# Import configuration module
$configModule = Join-Path $script:ModulesPath "EntraChecks-Configuration.psm1"
if (Test-Path $configModule) {
    Import-Module $configModule -Force -ErrorAction SilentlyContinue
}

# Load configuration from file if provided
$script:Config = $null
if ($ConfigFile) {
    try {
        Write-Host "Loading configuration from: $ConfigFile" -ForegroundColor Cyan
        $script:Config = Import-Configuration -FilePath $ConfigFile -Environment $Environment
        Write-Host "Configuration loaded successfully!" -ForegroundColor Green

        # Apply configuration values (parameters override config)
        if (-not $PSBoundParameters.ContainsKey('Mode') -and $script:Config.Assessment.Mode) {
            $Mode = $script:Config.Assessment.Mode
        }

        if (-not $PSBoundParameters.ContainsKey('TenantName') -and $script:Config.Assessment.Tenant.TenantName) {
            $TenantName = $script:Config.Assessment.Tenant.TenantName
        }

        if (-not $PSBoundParameters.ContainsKey('OutputDirectory') -and $script:Config.Assessment.Output.Directory) {
            $OutputDirectory = $script:Config.Assessment.Output.Directory
        }

        if (-not $PSBoundParameters.ContainsKey('Modules') -and $script:Config.Assessment.Scope) {
            $Modules = $script:Config.Assessment.Scope
        }

        if (-not $PSBoundParameters.ContainsKey('ExportFormat') -and $script:Config.Assessment.Output.Formats) {
            # Map array to single format or "All"
            if ($script:Config.Assessment.Output.Formats.Count -gt 1) {
                $ExportFormat = "All"
            } else {
                $ExportFormat = $script:Config.Assessment.Output.Formats[0]
            }
        }

        # PR 4 of HTML-Reporting-Consolidation-Plan: HTML routing overrides from
        # the Assessment.Output.Html block. Param > config > hard default.
        $htmlCfg = $null
        if ($script:Config.Assessment.Output -and $script:Config.Assessment.Output.PSObject.Properties['Html']) {
            $htmlCfg = $script:Config.Assessment.Output.Html
        }
        if ($htmlCfg) {
            if (-not $PSBoundParameters.ContainsKey('HtmlReportSet') -and $htmlCfg.ReportSet) {
                $HtmlReportSet = [string]$htmlCfg.ReportSet
            }
            if (-not $PSBoundParameters.ContainsKey('HtmlDeepDiveDomains') -and $htmlCfg.DeepDiveDomains) {
                $HtmlDeepDiveDomains = @($htmlCfg.DeepDiveDomains)
            }
        }

        # Update paths from config
        if ($script:Config.Logging.Directory) {
            $script:LogsPath = $script:Config.Logging.Directory
        }

        Write-Host "Configuration applied:" -ForegroundColor Yellow
        Write-Host "  Mode: $Mode" -ForegroundColor Gray
        Write-Host "  Modules: $($Modules -join ', ')" -ForegroundColor Gray
        Write-Host "  Output Directory: $OutputDirectory" -ForegroundColor Gray
        Write-Host "  Log Directory: $($script:LogsPath)" -ForegroundColor Gray
    }
    catch {
        Write-Error "Failed to load configuration: $_"
        Write-Host "Falling back to parameter-based configuration..." -ForegroundColor Yellow
    }
}

# Ensure directories exist
@($OutputDirectory, $script:SnapshotsPath, $script:LogsPath) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
    }
}

# Import logging module
$loggingModule = Join-Path $script:ModulesPath "EntraChecks-Logging.psm1"
if (Test-Path $loggingModule) {
    Import-Module $loggingModule -Force -ErrorAction SilentlyContinue
}

# Import data sources catalog so Add-Finding can tag each finding with its
# provenance source (auto-derived from the call stack, with optional override).
$dsModule = Join-Path $script:ModulesPath "EntraChecks-DataSources.psm1"
if (Test-Path $dsModule) {
    Import-Module $dsModule -Force -DisableNameChecking -ErrorAction SilentlyContinue
}

# Import the v2 finding schema module (PR 2 of Central-Finding-Schema-GRC-Plan).
# Initialize-FindingsForReport runs at report-generation time to normalize
# every finding to schema v2 and merge optional analyst state. Loaded with
# -ErrorAction SilentlyContinue so legacy installs without the module still
# function — Initialize-FindingsForReport is invoked behind a Get-Command
# guard at the consumer sites.
$schemaModule = Join-Path $script:ModulesPath "EntraChecks-FindingSchema.psm1"
if (Test-Path $schemaModule) {
    Import-Module $schemaModule -Force -ErrorAction SilentlyContinue
}

# Initialize logging subsystem (from config or defaults)
if ($script:Config -and $script:Config.Logging) {
    $logConfig = $script:Config.Logging
    Initialize-LoggingSubsystem `
        -LogDirectory $logConfig.Directory `
        -MinimumLevel $logConfig.MinimumLevel `
        -RetentionDays $logConfig.RetentionDays `
        -MaxFileSizeMB $logConfig.MaxFileSizeMB `
        -BufferSize $logConfig.BufferSize `
        -Targets $logConfig.Targets `
        -StructuredLogging:$logConfig.StructuredLogging
} else {
    # Fallback to defaults
    $logLevel = if ($Mode -eq 'Scheduled') { 'INFO' } else { 'INFO' }
    Initialize-LoggingSubsystem -LogDirectory $script:LogsPath -MinimumLevel $logLevel -RetentionDays 90 -StructuredLogging
}

Write-AuditLog -EventType "SessionStarted" -Description "EntraChecks session started" -Details @{
    Mode = $Mode
    Version = $script:Version
    User = $env:USERNAME
    Computer = $env:COMPUTERNAME
    ConfigFile = $(if ($ConfigFile) { $ConfigFile } else { "None" })
    Environment = $(if ($Environment) { $Environment } else { "None" })
}

#region ==================== ERROR KNOWLEDGE BASE ====================
# Used by module error summary to classify errors for analyst-friendly output
$script:ErrorKnowledge = @{}
$ekEntry = @{}
$ekEntry['Pattern'] = 'AADSTS|authentication failed|token.*expir|login required|InteractiveBrowser'
$ekEntry['Cause'] = 'Authentication session expired or failed'
$ekEntry['Resolution'] = 'Re-run the script and sign in again. If using scheduled mode, check service principal credentials.'
$script:ErrorKnowledge['EC-AUTH'] = $ekEntry
$ekEntry = @{}
$ekEntry['Pattern'] = 'Forbidden|403|Insufficient privileges|Authorization_RequestDenied|insufficient.*scope'
$ekEntry['Cause'] = 'Missing Graph API permissions'
$ekEntry['Resolution'] = 'Have a Global Admin run .\Grant-AdminConsent.ps1 to grant required scopes, or sign in with Global Reader role.'
$script:ErrorKnowledge['EC-PERM'] = $ekEntry
$ekEntry = @{}
$ekEntry['Pattern'] = 'Premium|P2.*required|license.*required|IdentityProtection|AAD_Premium'
$ekEntry['Cause'] = 'Requires Azure AD Premium P2 license'
$ekEntry['Resolution'] = 'This check requires an Azure AD Premium P2 license. Skip it with -ExcludeChecks or upgrade your license.'
$script:ErrorKnowledge['EC-LIC'] = $ekEntry
$ekEntry = @{}
$ekEntry['Pattern'] = '429|throttl|Too Many Requests|rate.*limit'
$ekEntry['Cause'] = 'Graph API rate limiting'
$ekEntry['Resolution'] = 'Too many API requests. Wait a few minutes and re-run, or run fewer modules at once.'
$script:ErrorKnowledge['EC-THROT'] = $ekEntry
$ekEntry = @{}
$ekEntry['Pattern'] = 'Not connected|no.*graph.*session|Connect-MgGraph|network|timeout|socket'
$ekEntry['Cause'] = 'Graph/Azure connection lost'
$ekEntry['Resolution'] = 'Network issue or session timeout. Check connectivity and re-run the script.'
$script:ErrorKnowledge['EC-CONN'] = $ekEntry
$ekEntry = @{}
$ekEntry['Pattern'] = '404|Not Found|does not exist|resource.*not.*found'
$ekEntry['Cause'] = 'Requested resource not found'
$ekEntry['Resolution'] = 'The API endpoint or resource does not exist in this tenant. This may be expected if the feature is not configured.'
$script:ErrorKnowledge['EC-NOTFOUND'] = $ekEntry
$ekEntry = @{}
$ekEntry['Pattern'] = 'Azure\.Identity\.Broker|WAM|Az\.Accounts|AzContext|subscription'
$ekEntry['Cause'] = 'Azure module or authentication issue'
$ekEntry['Resolution'] = 'Check Az module installation (Install-Module Az.Accounts). If WAM errors persist, restart PowerShell.'
$script:ErrorKnowledge['EC-AZ'] = $ekEntry
$ekEntry = @{}
$ekEntry['Pattern'] = 'not recognized|CommandNotFound|Import-Module|module.*not.*found'
$ekEntry['Cause'] = 'Required PowerShell module not installed'
$ekEntry['Resolution'] = 'Run .\Install-Prerequisites.ps1 to install all required modules.'
$script:ErrorKnowledge['EC-MOD'] = $ekEntry
#endregion

# Module definitions
$script:ModuleDefinitions = @{
    Core = @{
        Name = "EntraChecks Core"
        Script = "Invoke-EntraChecks.ps1"
        RequiresGraph = $true
        RequiresAzure = $false
        Description = "25 foundational Entra ID security checks"
    }
    IdentityProtection = @{
        Name = "Identity Protection"
        Module = "EntraChecks-IdentityProtection.psm1"
        RequiresGraph = $true
        RequiresAzure = $false
        Description = "Risk-based identity protection checks (P2)"
    }
    Devices = @{
        Name = "Devices & Intune"
        Module = "EntraChecks-Devices.psm1"
        RequiresGraph = $true
        RequiresAzure = $false
        Description = "Device compliance and management checks"
    }
    SecureScore = @{
        Name = "Microsoft Secure Score"
        Module = "EntraChecks-SecureScore.psm1"
        RequiresGraph = $true
        RequiresAzure = $false
        Description = "Microsoft Secure Score integration"
    }
    Defender = @{
        Name = "Defender for Cloud"
        Module = "EntraChecks-DefenderCompliance.psm1"
        RequiresGraph = $false
        RequiresAzure = $true
        Description = "Regulatory compliance from Defender"
    }
    AzurePolicy = @{
        Name = "Azure Policy"
        Module = "EntraChecks-AzurePolicy.psm1"
        RequiresGraph = $false
        RequiresAzure = $true
        Description = "Azure Policy compliance state"
    }
    Purview = @{
        Name = "Purview Compliance"
        Module = "EntraChecks-PurviewCompliance.psm1"
        RequiresGraph = $true
        RequiresAzure = $false
        Description = "Compliance Manager assessments"
    }
    ActiveDirectory = @{
        Name = "Active Directory (On-Prem)"
        Module = "EntraChecks-ActiveDirectory.psm1"
        RequiresGraph = $false
        RequiresAzure = $false
        Description = "On-premises AD security audit (29 checks)"
    }
}

# Required Graph scopes for all modules
# Updated 2026-02-11: Fixed invalid permission names per Microsoft Graph API documentation
$script:AllGraphScopes = @(
    "Directory.Read.All",
    "Policy.Read.All",
    "SecurityEvents.Read.All",               # Required for Secure Score API
    "AuditLog.Read.All",
    "IdentityRiskEvent.Read.All",
    "IdentityRiskyUser.Read.All",
    "Device.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "InformationProtectionPolicy.Read",            # For Purview Compliance Manager checks
    "BitLockerKey.ReadBasic.All"                   # For BitLocker/device encryption compliance checks
)

#endregion

#region ==================== DISPLAY FUNCTIONS ====================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ║   ███████╗███╗   ██╗████████╗██████╗  █████╗                     ║" -ForegroundColor Cyan
    Write-Host "  ║   ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗                    ║" -ForegroundColor Cyan
    Write-Host "  ║   █████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║                    ║" -ForegroundColor Cyan
    Write-Host "  ║   ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║                    ║" -ForegroundColor Cyan
    Write-Host "  ║   ███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║                    ║" -ForegroundColor Cyan
    Write-Host "  ║   ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝                    ║" -ForegroundColor Cyan
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ║              ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗     ║" -ForegroundColor Magenta
    Write-Host "  ║             ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝     ║" -ForegroundColor Magenta
    Write-Host "  ║             ██║     ███████║█████╗  ██║     █████╔╝ ███████╗     ║" -ForegroundColor Magenta
    Write-Host "  ║             ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ╚════██║     ║" -ForegroundColor Magenta
    Write-Host "  ║             ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████║     ║" -ForegroundColor Magenta
    Write-Host "  ║              ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝     ║" -ForegroundColor Magenta
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ║           Unified Compliance Assessment Suite v$script:Version            ║" -ForegroundColor White
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Show-MainMenu {
    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Gray
    Write-Host "  │                         MAIN MENU                               │" -ForegroundColor White
    Write-Host "  ├─────────────────────────────────────────────────────────────────┤" -ForegroundColor Gray
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   [1] Quick Assessment      - Run all modules (recommended)    │" -ForegroundColor Yellow
    Write-Host "  │   [2] Select Modules        - Choose specific modules to run   │" -ForegroundColor Yellow
    Write-Host "  │   [3] View Last Results     - Open most recent reports         │" -ForegroundColor Yellow
    Write-Host "  │   [4] Compare Snapshots     - Delta reporting                  │" -ForegroundColor Yellow
    Write-Host "  │   [5] Manage Snapshots      - View/delete saved snapshots      │" -ForegroundColor Yellow
    Write-Host "  │   [6] SOC 2 Readiness       - Internal SOC 2 TSC assessment   │" -ForegroundColor Yellow
    Write-Host "  │   [7] SOC 2 Type 2          - Period coverage from snapshots  │" -ForegroundColor Yellow
    Write-Host "  │   [8] Active Directory      - On-premises AD security audit  │" -ForegroundColor Yellow
    Write-Host "  │   [Y] Hybrid Analysis       - Cloud + on-prem + correlation  │" -ForegroundColor Yellow
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   [A] Authentication        - Connect to Graph and Azure       │" -ForegroundColor Cyan
    Write-Host "  │   [D] Disconnect            - Sign out (switch tenant)         │" -ForegroundColor Cyan
    Write-Host "  │   [S] Settings              - Configure output & preferences   │" -ForegroundColor Cyan
    Write-Host "  │   [H] Help                  - Documentation & guides           │" -ForegroundColor Cyan
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   [Q] Quit                  - Quit and disconnect              │" -ForegroundColor Gray
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
    Write-Host ""
}

function Show-ModuleMenu {
    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Gray
    Write-Host "  │                      SELECT MODULES                             │" -ForegroundColor White
    Write-Host "  ├─────────────────────────────────────────────────────────────────┤" -ForegroundColor Gray
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   ENTRA ID (Graph API)                                         │" -ForegroundColor Cyan
    Write-Host "  │   [1] Core Assessment       - 25 foundational checks           │" -ForegroundColor Yellow
    Write-Host "  │   [2] Identity Protection   - Risk-based checks (P2)           │" -ForegroundColor Yellow
    Write-Host "  │   [3] Devices and Intune    - Device compliance                │" -ForegroundColor Yellow
    Write-Host "  │   [4] Secure Score          - Microsoft Secure Score           │" -ForegroundColor Yellow
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   AZURE (ARM API)                                              │" -ForegroundColor Cyan
    Write-Host "  │   [5] Defender for Cloud    - Regulatory compliance            │" -ForegroundColor Yellow
    Write-Host "  │   [6] Azure Policy          - Policy compliance state          │" -ForegroundColor Yellow
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   MICROSOFT 365                                                │" -ForegroundColor Cyan
    Write-Host "  │   [7] Purview Compliance    - Compliance Manager               │" -ForegroundColor Yellow
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   ON-PREMISES                                                  │" -ForegroundColor Cyan
    Write-Host "  │   [8] Active Directory      - On-prem AD security audit       │" -ForegroundColor Yellow
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   [A] Select All            [R] Run Selected                   │" -ForegroundColor Green
    Write-Host "  │   [C] Clear Selection       [B] Back to Main Menu              │" -ForegroundColor Gray
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
    Write-Host ""
}

function Show-AuthStatus {
    Write-Host "`n  Authentication Status:" -ForegroundColor Cyan

    # Check Graph
    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    if ($graphContext) {
        Write-Host "    [OK] Microsoft Graph: Connected as $($graphContext.Account)" -ForegroundColor Green
        # Show granted scopes relevant to EntraChecks
        $keyScopes = @(
            'Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All',
            'SecurityEvents.Read.All', 'IdentityRiskEvent.Read.All',
            'IdentityRiskyUser.Read.All', 'Device.Read.All'
        )
        $grantedScopes = $graphContext.Scopes
        $missingScopes = @()
        foreach ($scope in $keyScopes) {
            if ($grantedScopes -notcontains $scope) {
                $missingScopes += $scope
            }
        }
        if ($missingScopes.Count -gt 0) {
            Write-Host "    [i] Missing scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
            Write-Host "    [i] Some modules may not return data without these permissions" -ForegroundColor Gray
        }
        else {
            Write-Host "    [i] All key Graph scopes granted" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "    [X] Microsoft Graph: Not connected" -ForegroundColor Red
        Write-Host "    [i] Required for: Core checks, Secure Score, Identity Protection, Devices" -ForegroundColor Gray
    }

    # Check Azure
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($azContext -and $azContext.Account) {
        if ($azContext.Subscription -and $azContext.Subscription.Name) {
            Write-Host "    [OK] Azure: Connected to $($azContext.Subscription.Name)" -ForegroundColor Green
            Write-Host "    [i] Subscription ID: $($azContext.Subscription.Id)" -ForegroundColor Gray
        }
        else {
            Write-Host "    [!] Azure: Connected but no subscription selected" -ForegroundColor Yellow
            Write-Host "    [i] Run Set-AzContext -SubscriptionId <id> to select a subscription" -ForegroundColor Gray
        }
        Write-Host "    [i] Account: $($azContext.Account.Id)" -ForegroundColor Gray
    }
    else {
        Write-Host "    [X] Azure: Not connected" -ForegroundColor Red
        Write-Host "    [i] Required for: Defender Compliance, Azure Policy" -ForegroundColor Gray
    }

    Write-Host ""
}

function Show-Progress {
    param(
        [string]$Activity,
        [int]$PercentComplete,
        [string]$Status
    )
    
    $width = 40
    $filled = [math]::Floor($width * $PercentComplete / 100)
    $empty = $width - $filled
    
    $bar = "█" * $filled + "░" * $empty
    
    Write-Host "`r  [$bar] $PercentComplete% - $Status" -NoNewline -ForegroundColor Cyan
}

#endregion

#region ==================== AUTHENTICATION ====================

function Connect-EntraCheck {
    param(
        [switch]$GraphOnly,
        [switch]$AzureOnly,
        [switch]$UseDeviceCode
    )

    Write-Host "`n[+] Authenticating..." -ForegroundColor Cyan
    Write-Log -Level INFO -Message "Starting authentication process" -Category "Authentication" -Properties @{
        GraphOnly = $GraphOnly.IsPresent
        AzureOnly = $AzureOnly.IsPresent
        UseDeviceCode = $UseDeviceCode.IsPresent
    }

    if (-not $AzureOnly) {
        Write-Host "    Connecting to Microsoft Graph..." -ForegroundColor Gray
        Write-Log -Level INFO -Message "Connecting to Microsoft Graph API" -Category "Authentication"

        try {
            # Check if already connected with sufficient scopes
            $existingContext = Get-MgContext -ErrorAction SilentlyContinue
            if ($existingContext -and $existingContext.Account) {
                # Compare against the FULL scope union, not just a 3-scope critical
                # subset. If the cached context is missing any required scope,
                # reconnect once with the full set so downstream module calls do
                # not trigger silent MSAL re-prompts mid-run.
                $grantedScopes = $existingContext.Scopes
                $missingCritical = @($script:AllGraphScopes | Where-Object { $grantedScopes -notcontains $_ })

                if ($missingCritical.Count -eq 0) {
                    Write-Host "    [OK] Already connected as: $($existingContext.Account)" -ForegroundColor Green
                    $context = $existingContext
                }
                else {
                    Write-Host "    [i] Connected but missing scopes: $($missingCritical -join ', ')" -ForegroundColor Yellow
                    Write-Host "    [i] Reconnecting with required scopes..." -ForegroundColor Gray
                    if ($UseDeviceCode) {
                        Connect-MgGraph -Scopes $script:AllGraphScopes -UseDeviceAuthentication -NoWelcome -ErrorAction Stop
                    }
                    else {
                        Connect-MgGraph -Scopes $script:AllGraphScopes -NoWelcome -ErrorAction Stop
                    }
                    $context = Get-MgContext
                    Write-Host "    [OK] Connected as: $($context.Account)" -ForegroundColor Green
                }
            }
            else {
                # Not connected - initiate new connection
                if ($UseDeviceCode) {
                    Write-Host "    Using device code flow - copy the code shown below" -ForegroundColor Yellow
                    Connect-MgGraph -Scopes $script:AllGraphScopes -UseDeviceAuthentication -NoWelcome -ErrorAction Stop
                }
                else {
                    Write-Host "    TIP: If browser auth fails, select [A] Authentication and try device code" -ForegroundColor Gray
                    Connect-MgGraph -Scopes $script:AllGraphScopes -NoWelcome -ErrorAction Stop
                }
                $context = Get-MgContext
                Write-Host "    [OK] Connected as: $($context.Account)" -ForegroundColor Green
            }

            $logProps = @{}
            $logProps['Account'] = $context.Account
            $logProps['TenantId'] = $context.TenantId
            $logProps['Scopes'] = ($context.Scopes -join ', ')
            Write-Log -Level INFO -Message "Microsoft Graph authentication successful" -Category "Authentication" -Properties $logProps
            Write-AuditLog -EventType "AuthenticationSuccess" -Description "Microsoft Graph authentication succeeded" -TargetObject "Microsoft Graph API" -Result "Success"
        }
        catch {
            Write-Host "    [!] Graph connection failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level ERROR -Message "Microsoft Graph authentication failed" -Category "Authentication" -ErrorRecord $_
            Write-AuditLog -EventType "AuthenticationFailure" -Description "Microsoft Graph authentication failed" -TargetObject "Microsoft Graph API" -Result "Failure"
            return $false
        }
    }

    if (-not $GraphOnly) {
        Write-Host "    Connecting to Azure..." -ForegroundColor Gray
        Write-Log -Level INFO -Message "Connecting to Azure" -Category "Authentication"

        try {
            $azContext = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $azContext -or -not $azContext.Account) {
                # WAM broker is disabled globally at script start (see WAM BROKER FIX region)
                Connect-AzAccount -ErrorAction Stop | Out-Null
            }
            $azContext = Get-AzContext

            # If no subscription is selected, try to pick one automatically
            if (-not $azContext.Subscription -or -not $azContext.Subscription.Id) {
                $subs = Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Enabled" }
                if ($subs -and @($subs).Count -gt 0) {
                    $selectedSub = @($subs)[0]
                    Set-AzContext -SubscriptionId $selectedSub.Id -ErrorAction SilentlyContinue | Out-Null
                    $azContext = Get-AzContext
                    Write-Host "    [i] Auto-selected subscription: $($azContext.Subscription.Name)" -ForegroundColor Gray
                }
                else {
                    Write-Host "    [!] Connected to Azure but no enabled subscriptions found" -ForegroundColor Yellow
                    Write-Host "    [i] Defender and Azure Policy modules require an active subscription" -ForegroundColor Gray
                }
            }

            if ($azContext.Subscription -and $azContext.Subscription.Name) {
                Write-Host "    [OK] Connected to: $($azContext.Subscription.Name)" -ForegroundColor Green
            }
            else {
                Write-Host "    [OK] Connected to Azure (no subscription selected)" -ForegroundColor Yellow
            }

            $logProps = @{}
            $logProps['Subscription'] = $azContext.Subscription.Name
            $logProps['SubscriptionId'] = $azContext.Subscription.Id
            $logProps['Account'] = $azContext.Account.Id
            Write-Log -Level INFO -Message "Azure authentication successful" -Category "Authentication" -Properties $logProps
            Write-AuditLog -EventType "AuthenticationSuccess" -Description "Azure authentication succeeded" -TargetObject "Azure ARM API" -Result "Success"
        }
        catch {
            Write-Host "    [!] Azure connection failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "    [i] Some modules (Defender, Azure Policy) will be unavailable" -ForegroundColor Gray
            Write-Log -Level WARN -Message "Azure authentication failed - some modules unavailable" -Category "Authentication" -ErrorRecord $_
            Write-AuditLog -EventType "AuthenticationFailure" -Description "Azure authentication failed" -TargetObject "Azure ARM API" -Result "Warning"
        }
    }

    return $true
}

function Disconnect-EntraCheck {
    <#
    .SYNOPSIS
        Disconnects from Microsoft Graph and Azure sessions.
    .DESCRIPTION
        Clears cached tokens for both Microsoft Graph and Azure to ensure
        sessions do not persist after the tool exits. Important for security
        and for switching between tenants.
    #>
    [CmdletBinding()]
    param(
        [switch]$Silent
    )

    if (-not $Silent) {
        Write-Host "`n[+] Disconnecting sessions..." -ForegroundColor Cyan
    }

    # Disconnect Microsoft Graph
    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    if ($graphContext) {
        try {
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
            if (-not $Silent) {
                Write-Host "    [OK] Microsoft Graph: Disconnected" -ForegroundColor Green
            }
            Write-Log -Level INFO -Message "Microsoft Graph session disconnected" -Category "Authentication"
        }
        catch {
            if (-not $Silent) {
                Write-Host "    [!] Graph disconnect error: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    else {
        if (-not $Silent) {
            Write-Host "    [i] Microsoft Graph: Not connected" -ForegroundColor Gray
        }
    }

    # Disconnect Azure
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($azContext) {
        try {
            Disconnect-AzAccount -ErrorAction Stop | Out-Null
            if (-not $Silent) {
                Write-Host "    [OK] Azure: Disconnected" -ForegroundColor Green
            }
            Write-Log -Level INFO -Message "Azure session disconnected" -Category "Authentication"
        }
        catch {
            if (-not $Silent) {
                Write-Host "    [!] Azure disconnect error: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    else {
        if (-not $Silent) {
            Write-Host "    [i] Azure: Not connected" -ForegroundColor Gray
        }
    }

    if (-not $Silent) {
        Write-Host ""
    }
}

#endregion

#region ==================== MODULE EXECUTION ====================

function Invoke-ModuleAssessment {
    param(
        [Parameter(Mandatory)]
        [string[]]$SelectedModules,
        
        [string]$TenantName,
        [string]$OutputDir
    )
    
    $results = @{
        StartTime = Get-Date
        Modules = @{}
        Errors = @()
    }
    
    $totalModules = $SelectedModules.Count
    $currentModule = 0

    # Validate prerequisites for selected modules
    Write-Host "`n[+] Validating prerequisites..." -ForegroundColor Cyan
    $prerequisitesFailed = @()
    $prerequisitesWarnings = @()

    if ($SelectedModules -contains "Defender" -or $SelectedModules -contains "AzurePolicy") {
        # Check Az modules
        $requiredAzModules = @{
            "Az.Accounts" = "Required for Azure authentication"
            "Az.Security" = "Required for Defender for Cloud compliance"
            "Az.PolicyInsights" = "Required for Azure Policy compliance"
            "Az.Resources" = "Required for Azure Policy compliance"
        }

        $missingAzModules = @()
        foreach ($module in $requiredAzModules.GetEnumerator()) {
            if (-not (Get-Module -Name $module.Key -ListAvailable)) {
                $missingAzModules += $module.Key
                Write-Host "    [!] Missing: $($module.Key) - $($module.Value)" -ForegroundColor Red
            }
        }

        if ($missingAzModules.Count -gt 0) {
            $prerequisitesFailed += "Missing Az modules: $($missingAzModules -join ', ')"
            Write-Host "    [i] Install with: Install-Module $($missingAzModules -join ', ') -Scope CurrentUser" -ForegroundColor Yellow
        }
        else {
            Write-Host "    [OK] All required Az modules installed" -ForegroundColor Green
        }

        # Check Azure connection
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $azContext) {
            $prerequisitesWarnings += "Azure not connected - Defender and AzurePolicy modules will attempt connection"
            Write-Host "    [!] Azure not connected - modules will prompt for authentication" -ForegroundColor Yellow
        }
        else {
            Write-Host "    [OK] Azure connected: $($azContext.Subscription.Name)" -ForegroundColor Green
        }
    }

    # Check Graph connection for all modules
    $mgContext = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $mgContext) {
        $prerequisitesFailed += "Microsoft Graph not connected"
        Write-Host "    [!] Microsoft Graph not connected" -ForegroundColor Red
    }
    else {
        Write-Host "    [OK] Microsoft Graph connected: $($mgContext.Account)" -ForegroundColor Green
    }

    # Handle prerequisites failures
    if ($prerequisitesFailed.Count -gt 0) {
        Write-Host "`n[!] Critical Prerequisites Missing:" -ForegroundColor Red
        foreach ($issue in $prerequisitesFailed) {
            Write-Host "    - $issue" -ForegroundColor Red
        }
        Write-Host "`n[i] Cannot continue without required prerequisites." -ForegroundColor Yellow
        Write-Log -Level ERROR -Message "Prerequisites validation failed" -Category "Prerequisites" -Properties @{
            Failed = ($prerequisitesFailed -join '; ')
        }
        return $null
    }

    if ($prerequisitesWarnings.Count -gt 0) {
        Write-Host "`n[i] Warnings:" -ForegroundColor Yellow
        foreach ($warning in $prerequisitesWarnings) {
            Write-Host "    - $warning" -ForegroundColor Yellow
        }
    }

    foreach ($moduleName in $SelectedModules) {
        $currentModule++

        $moduleDef = $script:ModuleDefinitions[$moduleName]
        Write-Host "`n[$currentModule/$totalModules] Running: $($moduleDef.Name)" -ForegroundColor Magenta
        Write-Host "    $($moduleDef.Description)" -ForegroundColor Gray

        Write-Log -Level INFO -Message "Starting module execution: $($moduleDef.Name)" -Category "ModuleExecution" -Properties @{
            ModuleName = $moduleName
            Description = $moduleDef.Description
            Progress = "$currentModule/$totalModules"
        }

        $moduleStartTime = Get-Date

        try {
            switch ($moduleName) {
                "Core" {
                    $scriptPath = Join-Path (Join-Path $script:ScriptRoot "Scripts") "Invoke-EntraChecks.ps1"
                    if (Test-Path $scriptPath) {
                        # Capture findings from Core assessment
                        $rawOutput = & $scriptPath -NonInteractive
                        # Filter to only actual finding objects (PSCustomObjects with CheckName property)
                        # The script output stream may contain non-finding objects (booleans, strings, hashtables)
                        $coreFindings = @($rawOutput | Where-Object {
                                $_ -is [PSCustomObject] -and $_.PSObject.Properties.Name -contains 'CheckName'
                            })
                        if ($coreFindings.Count -gt 0) {
                            $script:Findings += $coreFindings
                            Write-Log -Level INFO -Message "Captured $($coreFindings.Count) findings from Core module" -Category "ModuleExecution"
                        }
                        $results.Modules.Core = @{ Success = $true; FindingsCount = $coreFindings.Count }
                    }
                }
                
                "IdentityProtection" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-IdentityProtection.psm1"
                    if (Test-Path $modulePath) {
                        # Check Graph connection (required for Identity Protection API)
                        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
                        if (-not $graphContext) {
                            Write-Host "    [!] Microsoft Graph connection required for Identity Protection" -ForegroundColor Yellow
                            Write-Host "    [i] Connect via [A] Authentication menu first" -ForegroundColor Gray
                            $ipSkip = @{}
                            $ipSkip['Success'] = $false
                            $ipSkip['Error'] = "Microsoft Graph not connected"
                            $results.Modules.IdentityProtection = $ipSkip
                            $results.Errors += "IdentityProtection: Microsoft Graph not connected"
                            Write-Log -Level WARN -Message "IdentityProtection skipped: Graph not connected" -Category "ModuleExecution"
                            continue
                        }

                        Import-Module $modulePath -Force
                        try {
                            Invoke-IdentityProtectionChecks
                            # Capture findings from the module's internal collection
                            $ipModule = Get-Module "EntraChecks-IdentityProtection"
                            if ($ipModule) {
                                $moduleFindings = & $ipModule { $script:Findings }
                                if ($moduleFindings) {
                                    $script:Findings += $moduleFindings
                                    Write-Log -Level INFO -Message "Captured $($moduleFindings.Count) findings from Identity Protection module" -Category "ModuleExecution"
                                }
                            }
                            $results.Modules.IdentityProtection = @{ Success = $true }
                        }
                        catch {
                            Write-Host "    [!] Identity Protection error: $($_.Exception.Message)" -ForegroundColor Red
                            $ipCatch = @{}
                            $ipCatch['Success'] = $false
                            $ipCatch['Error'] = $_.Exception.Message
                            $results.Modules.IdentityProtection = $ipCatch
                            $results.Errors += "IdentityProtection: $($_.Exception.Message)"
                            Write-Log -Level ERROR -Message "Identity Protection collection failed" -Category "ModuleExecution" -ErrorRecord $_
                        }
                    }
                }

                "Devices" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-Devices.psm1"
                    if (Test-Path $modulePath) {
                        # Check Graph connection (required for Device/Intune API)
                        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
                        if (-not $graphContext) {
                            Write-Host "    [!] Microsoft Graph connection required for Device checks" -ForegroundColor Yellow
                            Write-Host "    [i] Connect via [A] Authentication menu first" -ForegroundColor Gray
                            $devSkip = @{}
                            $devSkip['Success'] = $false
                            $devSkip['Error'] = "Microsoft Graph not connected"
                            $results.Modules.Devices = $devSkip
                            $results.Errors += "Devices: Microsoft Graph not connected"
                            Write-Log -Level WARN -Message "Devices skipped: Graph not connected" -Category "ModuleExecution"
                            continue
                        }

                        Import-Module $modulePath -Force
                        try {
                            Invoke-DeviceChecks
                            # Capture findings from the module's internal collection
                            $devModule = Get-Module "EntraChecks-Devices"
                            if ($devModule) {
                                $moduleFindings = & $devModule { $script:Findings }
                                if ($moduleFindings) {
                                    $script:Findings += $moduleFindings
                                    Write-Log -Level INFO -Message "Captured $($moduleFindings.Count) findings from Devices module" -Category "ModuleExecution"
                                }
                            }
                            $results.Modules.Devices = @{ Success = $true }
                        }
                        catch {
                            Write-Host "    [!] Device checks error: $($_.Exception.Message)" -ForegroundColor Red
                            $devCatch = @{}
                            $devCatch['Success'] = $false
                            $devCatch['Error'] = $_.Exception.Message
                            $results.Modules.Devices = $devCatch
                            $results.Errors += "Devices: $($_.Exception.Message)"
                            Write-Log -Level ERROR -Message "Device checks collection failed" -Category "ModuleExecution" -ErrorRecord $_
                        }
                    }
                }
                
                "SecureScore" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-SecureScore.psm1"
                    if (Test-Path $modulePath) {
                        # Check Graph connection (required for Secure Score API)
                        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
                        if (-not $graphContext) {
                            Write-Host "    [!] Microsoft Graph connection required for Secure Score" -ForegroundColor Yellow
                            Write-Host "    [i] Connect via [A] Authentication menu first" -ForegroundColor Gray
                            $ssSkip = @{}
                            $ssSkip['Success'] = $false
                            $ssSkip['Error'] = "Microsoft Graph not connected"
                            $results.Modules.SecureScore = $ssSkip
                            $results.Errors += "SecureScore: Microsoft Graph not connected"
                            Write-Log -Level WARN -Message "SecureScore skipped: Graph not connected" -Category "ModuleExecution"
                            continue
                        }

                        Import-Module $modulePath -Force
                        try {
                            $script:SecureScoreData = Get-SecureScore -IncludeHistory

                            # Validate data was collected
                            if ($script:SecureScoreData -and
                                $null -ne $script:SecureScoreData.CurrentScore) {
                                $ssResult = @{}
                                $ssResult['Success'] = $true
                                $ssResult['Score'] = $script:SecureScoreData.ScorePercent
                                $results.Modules.SecureScore = $ssResult
                                Write-Host "    [OK] Secure Score: $($script:SecureScoreData.CurrentScore)/$($script:SecureScoreData.MaxScore)" -ForegroundColor Green
                            }
                            else {
                                $ssResult = @{}
                                $ssResult['Success'] = $false
                                $ssResult['Error'] = "No Secure Score data available (check permissions and API access)"
                                $results.Modules.SecureScore = $ssResult
                                $results.Errors += "SecureScore: No data returned"
                                Write-Host "    [!] No Secure Score data available" -ForegroundColor Yellow
                                Write-Host "    [i] Ensure SecurityEvents.Read.All permission is granted" -ForegroundColor Gray
                                Write-Log -Level WARN -Message "Secure Score module returned no data" -Category "ModuleExecution"
                            }
                        }
                        catch {
                            Write-Host "    [!] Secure Score error: $($_.Exception.Message)" -ForegroundColor Red
                            $ssCatch = @{}
                            $ssCatch['Success'] = $false
                            $ssCatch['Error'] = $_.Exception.Message
                            $results.Modules.SecureScore = $ssCatch
                            $results.Errors += "SecureScore: $($_.Exception.Message)"
                            Write-Log -Level ERROR -Message "Secure Score collection failed" -Category "ModuleExecution" -ErrorRecord $_
                        }
                    }
                }
                
                "Defender" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-DefenderCompliance.psm1"
                    if (Test-Path $modulePath) {
                        # Check Azure connection (required for Defender module)
                        $azContext = Get-AzContext -ErrorAction SilentlyContinue
                        if (-not $azContext) {
                            Write-Host "    [!] Azure connection required for Defender module" -ForegroundColor Yellow
                            Write-Host "    [i] Connect via [A] Authentication menu first" -ForegroundColor Gray
                            $defSkip = @{}
                            $defSkip['Success'] = $false
                            $defSkip['Error'] = "Azure connection required - please run Connect-AzAccount"
                            $results.Modules.Defender = $defSkip
                            $results.Errors += "Defender: Azure connection missing"
                            continue
                        }

                        # Import module and collect data
                        Import-Module $modulePath -Force
                        try {
                            $script:DefenderComplianceData = Get-DefenderComplianceAssessment

                            # Validate data was collected
                            if ($script:DefenderComplianceData -and
                                $script:DefenderComplianceData.Summary -and
                                $script:DefenderComplianceData.Summary.TotalStandards -gt 0) {
                                $defResult = @{}
                                $defResult['Success'] = $true
                                $defResult['Standards'] = $script:DefenderComplianceData.Summary.TotalStandards
                                $defResult['Subscriptions'] = $script:DefenderComplianceData.Summary.TotalSubscriptions
                                $results.Modules.Defender = $defResult
                                Write-Host "    [OK] Collected data for $($script:DefenderComplianceData.Summary.TotalStandards) standards" -ForegroundColor Green
                            }
                            elseif ($script:DefenderComplianceData -and $script:DefenderComplianceData.Summary) {
                                # Data returned but no enabled standards - not a failure
                                $defWarn = @{}
                                $defWarn['Success'] = $true
                                $defWarn['Warning'] = "No regulatory compliance standards enabled in Defender for Cloud"
                                $defWarn['Standards'] = 0
                                $defWarn['Subscriptions'] = $script:DefenderComplianceData.Summary.TotalSubscriptions
                                $results.Modules.Defender = $defWarn
                                Write-Host "    [i] No enabled compliance standards found" -ForegroundColor Yellow
                                Write-Host "    [i] To enable: Azure Portal > Defender for Cloud > Regulatory Compliance > Manage compliance policies" -ForegroundColor Gray
                                Write-Log -Level WARN -Message "Defender module: no enabled compliance standards" -Category "ModuleExecution"
                            }
                            else {
                                $defEmpty = @{}
                                $defEmpty['Success'] = $false
                                $defEmpty['Error'] = "No Defender compliance data collected"
                                $results.Modules.Defender = $defEmpty
                                $results.Errors += "Defender: No compliance data returned"
                                Write-Host "    [!] No Defender compliance data collected" -ForegroundColor Yellow
                                Write-Host "    [i] Possible causes:" -ForegroundColor Gray
                                Write-Host "        - Microsoft.Security resource provider not registered" -ForegroundColor Gray
                                Write-Host "        - Insufficient permissions to read Defender for Cloud data" -ForegroundColor Gray
                                Write-Host "    [i] To enable: Azure Portal > Defender for Cloud > Regulatory Compliance > Manage compliance policies" -ForegroundColor Gray
                                Write-Log -Level WARN -Message "Defender module returned no data" -Category "ModuleExecution"
                            }
                        }
                        catch {
                            Write-Host "    [!] Defender compliance error: $($_.Exception.Message)" -ForegroundColor Red
                            $defCatch = @{}
                            $defCatch['Success'] = $false
                            $defCatch['Error'] = $_.Exception.Message
                            $results.Modules.Defender = $defCatch
                            $results.Errors += "Defender: $($_.Exception.Message)"
                            Write-Log -Level ERROR -Message "Defender compliance collection failed" -Category "ModuleExecution" -ErrorRecord $_
                        }
                    }
                }
                
                "AzurePolicy" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-AzurePolicy.psm1"
                    if (Test-Path $modulePath) {
                        # Check Azure connection (required for Azure Policy module)
                        $azContext = Get-AzContext -ErrorAction SilentlyContinue
                        if (-not $azContext) {
                            Write-Host "    [!] Azure connection required for Azure Policy module" -ForegroundColor Yellow
                            Write-Host "    [i] Please ensure Azure connection via main authentication menu first" -ForegroundColor Gray
                            $results.Modules.AzurePolicy = @{
                                Success = $false
                                Error = "Azure connection required - please run Connect-AzAccount"
                            }
                            $results.Errors += "AzurePolicy: Azure connection missing"
                            continue
                        }

                        # Import module and collect data
                        Import-Module $modulePath -Force
                        $script:AzurePolicyData = Get-AzurePolicyComplianceAssessment

                        # Validate data was collected
                        if ($script:AzurePolicyData -and
                            $script:AzurePolicyData.Summary -and
                            $script:AzurePolicyData.Summary.TotalPolicies -gt 0) {
                            $results.Modules.AzurePolicy = @{
                                Success = $true
                                Policies = $script:AzurePolicyData.Summary.TotalPolicies
                                Subscriptions = $script:AzurePolicyData.Summary.TotalSubscriptions
                            }
                            Write-Host "    [OK] Collected data for $($script:AzurePolicyData.Summary.TotalPolicies) policies" -ForegroundColor Green
                        }
                        else {
                            $results.Modules.AzurePolicy = @{
                                Success = $false
                                Error = "No Azure Policy data collected (may not have policy assignments)"
                            }
                            $results.Errors += "AzurePolicy: No policy data returned"
                            Write-Host "    [!] No Azure Policy data collected" -ForegroundColor Yellow
                            Write-Log -Level WARN -Message "Azure Policy module returned no data" -Category "ModuleExecution"
                        }
                    }
                }
                
                "Purview" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-PurviewCompliance.psm1"
                    if (Test-Path $modulePath) {
                        Import-Module $modulePath -Force
                        $script:PurviewComplianceData = Get-PurviewComplianceAssessment

                        # Validate data was collected (Purview may return partial data)
                        if ($script:PurviewComplianceData -and
                            $script:PurviewComplianceData.Summary) {
                            # Purview is considered successful even with partial data
                            $dataCount = $script:PurviewComplianceData.Summary.TotalAssessments +
                            $script:PurviewComplianceData.Summary.DLPPoliciesCount +
                            $script:PurviewComplianceData.Summary.SensitivityLabelsCount

                            $results.Modules.Purview = @{
                                Success = $true
                                Assessments = $script:PurviewComplianceData.Summary.TotalAssessments
                                ComplianceManager = $script:PurviewComplianceData.Summary.ComplianceManagerAvailable
                                DataCollected = $dataCount
                            }

                            if ($dataCount -gt 0) {
                                Write-Host "    [OK] Collected Purview data: $dataCount items" -ForegroundColor Green
                            }
                            else {
                                Write-Host "    [!] Purview APIs returned limited data (expected - many APIs not available)" -ForegroundColor Yellow
                            }
                        }
                        else {
                            $results.Modules.Purview = @{
                                Success = $false
                                Error = "No Purview data available (APIs may require E5 license or portal access)"
                            }
                            $results.Errors += "Purview: No data returned"
                            Write-Host "    [!] No Purview data available" -ForegroundColor Yellow
                            Write-Host "    [i] Many Purview features require manual access to compliance.microsoft.com" -ForegroundColor Gray
                            Write-Log -Level WARN -Message "Purview module returned no data" -Category "ModuleExecution"
                        }
                    }
                }

                "ActiveDirectory" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-ActiveDirectory.psm1"
                    if (Test-Path $modulePath) {
                        Import-Module $modulePath -Force
                        # Pull per-module config overrides if present.
                        $adConfig = if ($script:Config.ActiveDirectory) { $script:Config.ActiveDirectory } else { @{} }
                        $adParams = @{}
                        if ($adConfig.UserLogonInactivityDays) { $adParams['UserLogonInactivityDays'] = [int]$adConfig.UserLogonInactivityDays }
                        if ($adConfig.UserPasswordAgeDays) { $adParams['UserPasswordAgeDays'] = [int]$adConfig.UserPasswordAgeDays }
                        if ($adConfig.RecentPrivilegedDays) { $adParams['RecentPrivilegedAccountDays'] = [int]$adConfig.RecentPrivilegedDays }
                        if ($adConfig.KrbTgtPasswordAgeDays) { $adParams['KrbTgtPasswordAgeDays'] = [int]$adConfig.KrbTgtPasswordAgeDays }
                        if ($adConfig.KerberoastPasswordAgeDays) { $adParams['KerberoastPasswordAgeDays'] = [int]$adConfig.KerberoastPasswordAgeDays }
                        if ($adConfig.ParallelDCProbing) { $adParams['ParallelDCProbing'] = [bool]$adConfig.ParallelDCProbing }
                        if ($adConfig.Tier0OUDNs) { $adParams['Tier0OUDNs'] = @($adConfig.Tier0OUDNs) }
                        if ($adConfig.AuthorizedPrincipalsExtra) { $adParams['AuthorizedPrincipalsExtra'] = @($adConfig.AuthorizedPrincipalsExtra) }
                        if ($adConfig.DACLReachMaxDepth) { $adParams['DACLReachMaxDepth'] = [int]$adConfig.DACLReachMaxDepth }
                        if ($adConfig.AuditSubcategoryOverrides) {
                            $overrides = @{}
                            foreach ($prop in $adConfig.AuditSubcategoryOverrides.PSObject.Properties) {
                                $overrides[$prop.Name] = [string]$prop.Value
                            }
                            if ($overrides.Count -gt 0) { $adParams['AuditSubcategoryOverrides'] = $overrides }
                        }

                        $adFindings = Invoke-ActiveDirectoryAssessment @adParams
                        if ($adFindings -and $adFindings.Count -gt 0) {
                            $script:Findings += $adFindings
                            Write-Log -Level INFO -Message "Captured $($adFindings.Count) findings from ActiveDirectory module" -Category "ModuleExecution"
                        }
                        $results.Modules.ActiveDirectory = @{
                            Success = $true
                            FindingsCount = if ($adFindings) { $adFindings.Count } else { 0 }
                        }
                    }
                }
            }

            Write-Host "    [OK] Complete" -ForegroundColor Green

            $moduleDuration = (Get-Date) - $moduleStartTime
            Write-Log -Level INFO -Message "Module execution completed: $($moduleDef.Name)" -Category "ModuleExecution" -Properties @{
                ModuleName = $moduleName
                Duration = $moduleDuration.TotalSeconds
                Status = "Success"
            }
            Write-AuditLog -EventType "CheckExecuted" -Description "Module $($moduleDef.Name) executed successfully" -TargetObject $moduleName -Result "Success"
        }
        catch {
            Write-Host "    [!] Error: $($_.Exception.Message)" -ForegroundColor Red

            $moduleDuration = (Get-Date) - $moduleStartTime
            Write-Log -Level ERROR -Message "Module execution failed: $($moduleDef.Name)" -Category "ModuleExecution" -ErrorRecord $_ -Properties @{
                ModuleName = $moduleName
                Duration = $moduleDuration.TotalSeconds
            }
            Write-AuditLog -EventType "CheckExecuted" -Description "Module $($moduleDef.Name) failed" -TargetObject $moduleName -Result "Failure"

            $results.Errors += @{
                Module = $moduleName
                Error = $_.Exception.Message
            }
            $results.Modules[$moduleName] = @{ Success = $false; Error = $_.Exception.Message }
        }
    }
    
    $results.EndTime = Get-Date
    $results.Duration = $results.EndTime - $results.StartTime

    # Display error summary if any issues occurred
    $failedModules = $results.Modules.GetEnumerator() | Where-Object { -not $_.Value.Success }
    if ($results.Errors.Count -gt 0 -or $failedModules.Count -gt 0) {
        Write-Host "`n" -NoNewline
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host " Assessment Issues Summary" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow

        if ($failedModules.Count -gt 0) {
            Write-Host "`n[!] Module Failures:" -ForegroundColor Red
            foreach ($module in $failedModules) {
                $errorMsg = $module.Value.Error
                Write-Host "  - $($module.Key): $errorMsg" -ForegroundColor Red

                # Classify error using knowledge base from Invoke-EntraChecks
                $errorCode = 'EC-UNKNOWN'
                $cause = $null
                $fix = $null
                if ($script:ErrorKnowledge) {
                    foreach ($code in $script:ErrorKnowledge.Keys) {
                        $kb = $script:ErrorKnowledge[$code]
                        if ($errorMsg -match $kb.Pattern) {
                            $errorCode = $code
                            $cause = $kb.Cause
                            $fix = $kb.Resolution
                            break
                        }
                    }
                }
                if ($cause) {
                    Write-Host "    [$errorCode] $cause" -ForegroundColor DarkYellow
                    Write-Host "    Fix: $fix" -ForegroundColor DarkGray
                }
            }
        }

        if ($results.Errors.Count -gt 0) {
            Write-Host "`n[!] Additional Errors:" -ForegroundColor Red
            foreach ($err in $results.Errors) {
                Write-Host "  - $err" -ForegroundColor Red
            }
        }

        Write-Host "`n[i] Troubleshooting Tips:" -ForegroundColor Cyan
        Write-Host "  - Check Azure connection: Get-AzContext" -ForegroundColor Gray
        Write-Host "  - Check Graph connection: Get-MgContext" -ForegroundColor Gray
        Write-Host "  - Verify permissions: (Get-MgContext).Scopes" -ForegroundColor Gray
        Write-Host "  - Review logs: $script:LogsPath" -ForegroundColor Gray
        Write-Host "  - Ensure required Az modules installed: Get-Module Az.* -ListAvailable" -ForegroundColor Gray

        $successfulCount = ($results.Modules.GetEnumerator() | Where-Object { $_.Value.Success }).Count
        Write-Host "`n[i] Modules: $successfulCount successful, $($failedModules.Count) failed" -ForegroundColor $(
            if ($failedModules.Count -eq 0) { "Green" }
            elseif ($successfulCount -gt 0) { "Yellow" }
            else { "Red" }
        )

        # Show log file path for analyst to share with administrator
        $logPath = $null
        if (Get-Command Get-LogFilePath -ErrorAction SilentlyContinue) {
            $logPath = Get-LogFilePath
        }
        if ($logPath) {
            Write-Host "`n[i] Full error log: $logPath" -ForegroundColor Cyan
            Write-Host "    Share this file with your administrator for troubleshooting." -ForegroundColor DarkGray
        }
        else {
            Write-Host "`n[i] Check $script:LogsPath for detailed error logs." -ForegroundColor Cyan
        }
        Write-Host ""
    }
    else {
        Write-Host "`n[OK] All modules completed successfully!" -ForegroundColor Green
    }

    return $results
}

function Invoke-SOC2ReadinessFromMenu {
    <#
    .SYNOPSIS
        Menu handler for SOC 2 Readiness Assessment (option [6]) AND the
        auto-run path invoked from Quick Assessment when SOC2.Enabled = true.
    .DESCRIPTION
        Loads SOC 2 config, ensures baseline findings exist (runs core +
        available modules if needed), invokes Invoke-SOC2Assessment, and
        renders the standalone SOC 2 HTML + workbook.
    .PARAMETER SkipCoreSeed
        When set, skip the "run Core assessment if no findings" seed step.
        Used by the Quick-Assessment auto-run path where findings have
        already been collected by the caller.
    .PARAMETER OpenBrowser
        When set, open the rendered HTML in the default browser at end of
        run. Default $true for interactive UX parity with menu [6]; set
        $false for automation (-Mode Quick / Scheduled).
    #>
    [CmdletBinding()]
    param(
        [string]$TenantName,
        [string]$OutputDirectory,
        [switch]$SkipCoreSeed,
        [bool]$OpenBrowser = $true
    )

    Write-Host "`n ===== SOC 2 Internal Readiness Assessment =====" -ForegroundColor Cyan

    # Load SOC 2 modules (catalog, reporting, branding)
    $soc2Module = Join-Path $script:ModulesPath "EntraChecks-SOC2.psm1"
    $soc2ReportModule = Join-Path $script:ModulesPath "EntraChecks-SOC2Reporting.psm1"
    $soc2AttestModule = Join-Path $script:ModulesPath "EntraChecks-SOC2Attestation.psm1"
    $brandingModule = Join-Path $script:ModulesPath "EntraChecks-Branding.psm1"
    $mappingModule = Join-Path $script:ModulesPath "EntraChecks-ComplianceMapping.psm1"
    foreach ($m in @($brandingModule, $mappingModule, $soc2Module, $soc2AttestModule, $soc2ReportModule)) {
        if (Test-Path $m) {
            Import-Module $m -Force -ErrorAction Stop
        } else {
            Write-Host "  [!] Missing required module: $m" -ForegroundColor Red
            return
        }
    }

    # Load SOC 2 config (fall back to defaults)
    $soc2Cfg = $null
    $configPath = Join-Path $PSScriptRoot "config\entrachecks.config.json"
    if (Test-Path $configPath) {
        try {
            $cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
            if ($cfg.SOC2) { $soc2Cfg = $cfg.SOC2 }
        } catch {
            Write-Host "  [!] Could not parse config; using SOC 2 defaults." -ForegroundColor Yellow
        }
    }

    # Ensure we have findings to map. If the current session's $script:Findings
    # is empty, run the core assessment (minimum) so SOC 2 has something to map.
    # Skipped when caller has just run Quick Assessment (findings already present).
    if (-not $SkipCoreSeed -and (-not $script:Findings -or $script:Findings.Count -eq 0)) {
        Write-Host "  [i] No prior findings in this session; running Core assessment to seed SOC 2 mapping..." -ForegroundColor Gray
        if (-not $TenantName) { $TenantName = Read-Host "  Enter tenant name" }
        if (-not $SkipAuthentication) { Connect-EntraCheck }
        $null = Invoke-ModuleAssessment -SelectedModules @('Core') -TenantName $TenantName -OutputDir $OutputDirectory
    }

    $existingFindings = @()
    if ($script:Findings) { $existingFindings = @($script:Findings) }

    # Resolve tenant info
    $tenantId = ''
    try {
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            $ctx = Get-MgContext -ErrorAction SilentlyContinue
            if ($ctx) { $tenantId = $ctx.TenantId }
        }
    } catch { $tenantId = '' }
    if (-not $tenantId) { $tenantId = 'unknown-tenant' }

    # Assemble assessment parameters from config
    $categories = @('CC', 'A', 'C', 'PI', 'P')
    $redactUsers = $true
    $redactDevices = $true
    $includeManual = $true
    $assessor = $env:USERNAME
    $svcOrg = ''
    # Phase 2 defaults
    $subscriptionFilter = @()
    $licensingOverrides = @{}
    $breakGlassMin = 2
    $breakGlassPatterns = @()
    $backupMinRedundancy = 'GRS'
    $svcHealthThreshold = 98
    $diagCategories = @('AuditLogs', 'SignInLogs')
    $diagWorkspaceId = ''
    $attestationStatePath = ''

    if ($soc2Cfg) {
        if ($soc2Cfg.Categories) { $categories = @($soc2Cfg.Categories) }
        if ($null -ne $soc2Cfg.AttestationStatePath) { $attestationStatePath = [string]$soc2Cfg.AttestationStatePath }
        if ($null -ne $soc2Cfg.Redaction) {
            if ($null -ne $soc2Cfg.Redaction.RedactUserPII) { $redactUsers = [bool]$soc2Cfg.Redaction.RedactUserPII }
            if ($null -ne $soc2Cfg.Redaction.RedactDeviceNames) { $redactDevices = [bool]$soc2Cfg.Redaction.RedactDeviceNames }
        }
        if ($null -ne $soc2Cfg.IncludeManualAttestation) { $includeManual = [bool]$soc2Cfg.IncludeManualAttestation }
        if ($soc2Cfg.Evidence) {
            if ($soc2Cfg.Evidence.Assessor) { $assessor = $soc2Cfg.Evidence.Assessor }
            if ($soc2Cfg.Evidence.ServiceOrganization) { $svcOrg = $soc2Cfg.Evidence.ServiceOrganization }
        }

        # SOC 2 Azure-readiness config (Phase 3 namespace migration)
        # Prefer SOC2.AzureReadiness; fall back to deprecated SOC2.Phase2.
        # The Resolve-SOC2NamespaceConfig shim handles this canonically when
        # config is loaded via Import-Configuration; inline fallback here keeps
        # the menu handler light (no Configuration module import required).
        $azReadinessBlock = $null
        if ($soc2Cfg.AzureReadiness) {
            $azReadinessBlock = $soc2Cfg.AzureReadiness
        } elseif ($soc2Cfg.Phase2) {
            $azReadinessBlock = $soc2Cfg.Phase2
            Write-Host "  [!] SOC2.Phase2 config keys are deprecated; rename to SOC2.AzureReadiness (removed in v1.8.0). See docs/SOC2-Guide.md SS13." -ForegroundColor Yellow
        }

        if ($azReadinessBlock) {
            $ar = $azReadinessBlock
            if ($ar.SubscriptionFilter) { $subscriptionFilter = @($ar.SubscriptionFilter) }
            if ($ar.Backup -and $ar.Backup.MinRedundancyTier) { $backupMinRedundancy = $ar.Backup.MinRedundancyTier }
            if ($ar.ServiceHealth -and $ar.ServiceHealth.AvailabilityThresholdPercent) {
                $svcHealthThreshold = [int]$ar.ServiceHealth.AvailabilityThresholdPercent
            }
            if ($ar.DiagnosticSettings) {
                if ($ar.DiagnosticSettings.RequiredCategories) { $diagCategories = @($ar.DiagnosticSettings.RequiredCategories) }
                if ($ar.DiagnosticSettings.RequiredWorkspaceId) { $diagWorkspaceId = $ar.DiagnosticSettings.RequiredWorkspaceId }
            }
            if ($ar.BreakGlass) {
                if ($ar.BreakGlass.MinimumAccounts) { $breakGlassMin = [int]$ar.BreakGlass.MinimumAccounts }
                if ($ar.BreakGlass.AccountUpnPatterns) { $breakGlassPatterns = @($ar.BreakGlass.AccountUpnPatterns) }
            }
            if ($ar.Licensing -and $ar.Licensing.Overrides) {
                # Coerce PSCustomObject/hashtable to plain hashtable regardless of loader
                if ($ar.Licensing.Overrides -is [hashtable]) {
                    $licensingOverrides = $ar.Licensing.Overrides
                } else {
                    foreach ($prop in $ar.Licensing.Overrides.PSObject.Properties) {
                        $licensingOverrides[$prop.Name] = $prop.Value
                    }
                }
            }
        }
    }

    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $soc2Output = Join-Path $OutputDirectory "SOC2\$timestamp"

    $idMapPath = Join-Path $OutputDirectory 'SOC2\identity-resolution'
    if ($soc2Cfg -and $soc2Cfg.Redaction -and $soc2Cfg.Redaction.IdentityResolutionMapPath) {
        $idMapPath = $soc2Cfg.Redaction.IdentityResolutionMapPath
    }

    Write-Host "  [i] Running SOC 2 assessment (Type 1, categories: $($categories -join ', '))" -ForegroundColor Gray
    $assessmentParams = @{}
    $assessmentParams['ExistingFindings'] = $existingFindings
    $assessmentParams['TenantId'] = $tenantId
    $assessmentParams['TenantName'] = $TenantName
    $assessmentParams['Categories'] = $categories
    $assessmentParams['OutputDirectory'] = $soc2Output
    $assessmentParams['IdentityResolutionDirectory'] = $idMapPath
    $assessmentParams['RedactUsers'] = $redactUsers
    $assessmentParams['RedactDevices'] = $redactDevices
    $assessmentParams['IncludeManualAttestation'] = $includeManual
    $assessmentParams['Assessor'] = $assessor
    $assessmentParams['ServiceOrganization'] = $svcOrg
    # Phase 2
    $assessmentParams['SubscriptionFilter'] = $subscriptionFilter
    $assessmentParams['LicensingOverrides'] = $licensingOverrides
    $assessmentParams['BreakGlassMinimumAccounts'] = $breakGlassMin
    $assessmentParams['BreakGlassUpnPatterns'] = $breakGlassPatterns
    $assessmentParams['BackupMinRedundancyTier'] = $backupMinRedundancy
    $assessmentParams['ServiceHealthThreshold'] = $svcHealthThreshold
    $assessmentParams['DiagnosticSettingsRequiredCategories'] = $diagCategories
    $assessmentParams['DiagnosticSettingsRequiredWorkspaceId'] = $diagWorkspaceId
    # §11.1 Manual Attestation Workflow — resolve the local state path
    # relative to the script root when it's a relative config value.
    if ($attestationStatePath) {
        if (-not [System.IO.Path]::IsPathRooted($attestationStatePath)) {
            $attestationStatePath = Join-Path $PSScriptRoot $attestationStatePath
        }
        $assessmentParams['AttestationStatePath'] = $attestationStatePath
    }

    $result = Invoke-SOC2Assessment @assessmentParams

    # Build branding context + render HTML and workbook
    $branding = Get-ReportBrandingContext `
        -Config ($soc2Cfg.Branding) `
        -ReportTitle 'SOC 2 Internal Readiness Assessment'

    $htmlPath = Join-Path $soc2Output 'SOC2-Report.html'
    $xlsxPath = Join-Path $soc2Output 'SOC2-Workbook.xlsx'

    $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $htmlPath -Branding $branding -IdentityResolutionMapPath $result.IdentityMapPath
    $null = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath $xlsxPath

    Write-Host "`n  [OK] SOC 2 assessment complete." -ForegroundColor Green
    Write-Host "      Findings:        $($result.Findings.Count)" -ForegroundColor White
    Write-Host "      Controls in scope: $($result.Summary.TotalControls)" -ForegroundColor White
    Write-Host "      Evidence bundle: $($result.Evidence.Directory)" -ForegroundColor White
    Write-Host "      Bundle hash:     $($result.Evidence.BundleHash)" -ForegroundColor White
    Write-Host "      HTML report:     $htmlPath" -ForegroundColor White
    if ($result.IdentityMapPath) {
        Write-Host "      Identity map:    $($result.IdentityMapPath)" -ForegroundColor White
    }

    if ($OpenBrowser) {
        try {
            Start-Process $htmlPath
        } catch {
            Write-Host "  [!] Could not open HTML report automatically: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

<#
.SYNOPSIS
    Reads the SOC2.Enabled flag from the given config file. Returns $false
    when the file is absent, unparseable, or the flag is missing/false.
    Pure function - no side effects other than a yellow warning on parse error.

.DESCRIPTION
    Extracted from Invoke-SOC2ReadinessIfEnabled so the flag-reading logic is
    testable in isolation without invoking the full SOC 2 pipeline.
#>
function Get-SOC2EnabledFromConfig {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath
    )

    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $false }
    try {
        $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    } catch {
        Write-Host "  [!] Could not parse config for SOC2.Enabled flag; skipping SOC 2 auto-run. ($($_.Exception.Message))" -ForegroundColor Yellow
        return $false
    }
    if (-not $cfg.SOC2) { return $false }
    if ($null -eq $cfg.SOC2.Enabled) { return $false }
    return [bool]$cfg.SOC2.Enabled
}

<#
.SYNOPSIS
    Runs SOC 2 readiness against already-collected findings when SOC2.Enabled
    is true in config. Otherwise returns quietly.

.DESCRIPTION
    Called from Quick Assessment (menu [1]) and -Mode Quick/Scheduled paths.
    Reads the SOC2.Enabled flag from config/entrachecks.config.json; if true,
    hands off to Invoke-SOC2ReadinessFromMenu with -SkipCoreSeed (findings
    already collected by the caller).

    SOC 2 failure NEVER fails the primary Quick Assessment - errors are
    caught and logged as a yellow warning only.

.PARAMETER TenantName
    Tenant name to forward to the SOC 2 run.

.PARAMETER OutputDirectory
    Output root (same as Quick Assessment's output dir).

.PARAMETER OpenBrowser
    $true for interactive contexts (menu [1]); $false for automation.
#>
function Invoke-SOC2ReadinessIfEnabled {
    [CmdletBinding()]
    param(
        [string]$TenantName,
        [Parameter(Mandatory)]
        [string]$OutputDirectory,
        [bool]$OpenBrowser = $true
    )

    $configPath = Join-Path $PSScriptRoot 'config\entrachecks.config.json'
    if (-not (Get-SOC2EnabledFromConfig -ConfigPath $configPath)) { return }

    Write-Host "`n  [i] SOC2.Enabled = true; running SOC 2 readiness assessment..." -ForegroundColor Cyan
    try {
        Invoke-SOC2ReadinessFromMenu -TenantName $TenantName -OutputDirectory $OutputDirectory -SkipCoreSeed -OpenBrowser $OpenBrowser
    } catch {
        Write-Host "  [!] SOC 2 auto-run failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  [!] The primary Quick Assessment completed successfully; re-run SOC 2 manually via menu option [6] once addressed." -ForegroundColor Yellow
    }
}

function Invoke-SOC2TypeTwoFromMenu {
    <#
    .SYNOPSIS
        Menu handler for SOC 2 Type 2 period coverage (option [7]).
    .DESCRIPTION
        Reads SOC2.AzureReadiness.TypeTwo config + SOC2.TypeTwoPeriod, prompts
        interactively for any missing required values (StartDate/EndDate),
        invokes Get-SOC2PeriodCoverage, builds the evidence bundle, renders
        the standalone HTML report, opens it in the default browser.
    #>
    [CmdletBinding()]
    param(
        [string]$TenantName,
        [string]$OutputDirectory,
        [string]$SnapshotDirectory
    )

    Write-Host "`n ===== SOC 2 Type 2 Period Coverage =====" -ForegroundColor Cyan

    # Load required modules
    $needed = @(
        'EntraChecks-Branding.psm1',
        'EntraChecks-ComplianceMapping.psm1',
        'EntraChecks-SOC2.psm1',
        'EntraChecks-SOC2TypeTwo.psm1'
    )
    foreach ($n in $needed) {
        $p = Join-Path $script:ModulesPath $n
        if (Test-Path $p) {
            Import-Module $p -Force -ErrorAction Stop
        } else {
            Write-Host "  [!] Missing required module: $p" -ForegroundColor Red
            return
        }
    }

    # Read SOC 2 config (raw JSON path; menu handler convention)
    $soc2Cfg = $null
    $configPath = Join-Path $PSScriptRoot 'config\entrachecks.config.json'
    if (Test-Path $configPath) {
        try {
            $cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
            if ($cfg.SOC2) { $soc2Cfg = $cfg.SOC2 }
        } catch {
            Write-Host "  [!] Could not parse config; using Type 2 defaults." -ForegroundColor Yellow
        }
    }

    # Resolve TypeTwo settings (prefer AzureReadiness, fallback Phase2; namespace shim handles canonical reads via Import-Configuration)
    $tt = $null
    if ($soc2Cfg.AzureReadiness -and $soc2Cfg.AzureReadiness.TypeTwo) {
        $tt = $soc2Cfg.AzureReadiness.TypeTwo
    } elseif ($soc2Cfg.Phase2 -and $soc2Cfg.Phase2.TypeTwo) {
        $tt = $soc2Cfg.Phase2.TypeTwo
    }

    $minSnaps = if ($tt -and $tt.MinSnapshotsRequired) { [int]$tt.MinSnapshotsRequired } else { 12 }
    $maxGap = if ($tt -and $tt.MaxGapDays) { [int]$tt.MaxGapDays } else { 10 }
    $exceptionsAllowed = if ($tt -and ($null -ne $tt.ConsistencyExceptionsAllowed)) { [int]$tt.ConsistencyExceptionsAllowed } else { 0 }
    $reportPrefix = if ($tt -and $tt.ReportFilenamePrefix) { $tt.ReportFilenamePrefix } else { 'SOC2-TypeTwo' }
    $cfgSnapshotDir = if ($tt -and $tt.SnapshotDirectory) { $tt.SnapshotDirectory } else { $SnapshotDirectory }

    # Resolve period from SOC2.TypeTwoPeriod (top-level) -> interactive prompt if missing
    $startDate = $null
    $endDate = $null
    if ($soc2Cfg -and $soc2Cfg.TypeTwoPeriod) {
        if ($soc2Cfg.TypeTwoPeriod.StartDate) {
            try {
                $startDate = [DateTime]::Parse($soc2Cfg.TypeTwoPeriod.StartDate)
            } catch {
                Write-Host "  [!] Could not parse SOC2.TypeTwoPeriod.StartDate; will prompt." -ForegroundColor Yellow
            }
        }
        if ($soc2Cfg.TypeTwoPeriod.EndDate) {
            try {
                $endDate = [DateTime]::Parse($soc2Cfg.TypeTwoPeriod.EndDate)
            } catch {
                Write-Host "  [!] Could not parse SOC2.TypeTwoPeriod.EndDate; will prompt." -ForegroundColor Yellow
            }
        }
    }

    if (-not $startDate) {
        $sdInput = Read-Host "  Enter period START date (YYYY-MM-DD, UTC)"
        try { $startDate = [DateTime]::Parse($sdInput) } catch {
            Write-Host "  [!] Could not parse start date." -ForegroundColor Red; return
        }
    }
    if (-not $endDate) {
        $edInput = Read-Host "  Enter period END date (YYYY-MM-DD, UTC)"
        try { $endDate = [DateTime]::Parse($edInput) } catch {
            Write-Host "  [!] Could not parse end date." -ForegroundColor Red; return
        }
    }

    if (-not (Test-Path $cfgSnapshotDir)) {
        Write-Host "  [!] Snapshot directory does not exist: $cfgSnapshotDir" -ForegroundColor Red
        Write-Host "  [i] Use option [1] Quick Assessment with -SaveSnapshot to seed snapshots first." -ForegroundColor Gray
        return
    }

    # Resolve tenant info
    $tenantId = ''
    try {
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            $ctx = Get-MgContext -ErrorAction SilentlyContinue
            if ($ctx) { $tenantId = $ctx.TenantId }
        }
    } catch { $tenantId = '' }
    if (-not $tenantId) { $tenantId = 'unknown-tenant' }

    Write-Host "  [i] Analyzing snapshots from $cfgSnapshotDir over $($startDate.ToString('yyyy-MM-dd')) - $($endDate.ToString('yyyy-MM-dd'))" -ForegroundColor Gray

    $coverage = Get-SOC2PeriodCoverage `
        -SnapshotDirectory $cfgSnapshotDir `
        -StartDate $startDate `
        -EndDate $endDate `
        -MinSnapshotsRequired $minSnaps `
        -MaxGapDays $maxGap `
        -ExceptionsAllowed $exceptionsAllowed

    Write-Host "  [i] Snapshots in period: $($coverage.SnapshotCount); largest gap: $($coverage.LargestGapDays) days" -ForegroundColor Gray
    if (-not $coverage.MeetsTypeTwoThreshold) {
        Write-Host "  [!] Type 2 coverage threshold NOT MET:" -ForegroundColor Yellow
        foreach ($r in $coverage.ThresholdDetail) { Write-Host "      - $r" -ForegroundColor Yellow }
    }

    # Output paths
    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $tt2Output = Join-Path $OutputDirectory "SOC2-TypeTwo\$timestamp"
    $null = New-Item -Path $tt2Output -ItemType Directory -Force

    $assessor = $env:USERNAME
    $svcOrg = ''
    if ($soc2Cfg -and $soc2Cfg.Evidence) {
        if ($soc2Cfg.Evidence.Assessor) { $assessor = $soc2Cfg.Evidence.Assessor }
        if ($soc2Cfg.Evidence.ServiceOrganization) { $svcOrg = $soc2Cfg.Evidence.ServiceOrganization }
    }

    $evidenceDir = Join-Path $tt2Output 'evidence-bundle'
    $evidence = New-SOC2TypeTwoEvidenceBundle `
        -Coverage $coverage `
        -OutputDirectory $evidenceDir `
        -TenantId $tenantId `
        -TenantName $TenantName `
        -Assessor $assessor `
        -ServiceOrganization $svcOrg

    # Branding context
    $branding = $null
    if (Get-Command Get-ReportBrandingContext -ErrorAction SilentlyContinue) {
        $brandingCfg = $null
        if ($soc2Cfg -and $soc2Cfg.Branding) { $brandingCfg = $soc2Cfg.Branding }
        $branding = Get-ReportBrandingContext -Config $brandingCfg -ReportTitle 'SOC 2 Type 2 Period Coverage'
    }

    $htmlPath = Join-Path $tt2Output "$reportPrefix-Report.html"
    $null = New-SOC2TypeTwoReport -Coverage $coverage -Evidence $evidence -OutputPath $htmlPath -Branding $branding

    Write-Host "`n  [OK] SOC 2 Type 2 report complete." -ForegroundColor Green
    Write-Host "      Period:          $($coverage.Period.StartUtc) -> $($coverage.Period.EndUtc) ($($coverage.Period.Days) days)" -ForegroundColor White
    Write-Host "      Snapshots used:  $($coverage.SnapshotCount)" -ForegroundColor White
    Write-Host "      Threshold met:   $($coverage.MeetsTypeTwoThreshold)" -ForegroundColor White
    Write-Host "      Bundle hash:     $($evidence.BundleHash)" -ForegroundColor White
    Write-Host "      HTML report:     $htmlPath" -ForegroundColor White
    Write-Host "      Evidence bundle: $($evidence.Directory)" -ForegroundColor White

    try {
        Start-Process $htmlPath
    } catch {
        Write-Host "  [!] Could not open HTML report automatically: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Export-AssessmentResult {
    param(
        [string]$OutputDir,
        [string]$TenantName,
        [switch]$IncludeUnified,
        [switch]$GenerateComprehensiveReport,
        [switch]$GenerateExecutiveSummary,
        [switch]$GenerateExcelReport,
        [switch]$GenerateRemediationScripts,
        # PR 4 of HTML-Reporting-Consolidation-Plan
        [string]$HtmlReportSet = 'Cockpit',
        [string[]]$HtmlDeepDiveDomains = @()
    )

    Write-Host "`n[+] Generating reports..." -ForegroundColor Cyan
    Write-Log -Level INFO -Message "Starting report generation" -Category "Reporting" -Properties @{
        OutputDirectory = $OutputDir
        TenantName = $TenantName
        IncludeUnified = $IncludeUnified.IsPresent
        HtmlReportSet = $HtmlReportSet
        HtmlDeepDiveDomains = ($HtmlDeepDiveDomains -join ',')
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportDir = Join-Path $OutputDir $timestamp

    if (-not (Test-Path $reportDir)) {
        New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    }

    # PR 4 — consult the routing helper. Returns the concrete plan
    # (which deep dives to emit, whether to render cockpit/comprehensive/
    # unified, plus user-facing warnings).
    $availableSources = @{
        SecureScore = ($null -ne $script:SecureScoreData)
        DefenderCompliance = ($null -ne $script:DefenderComplianceData)
        AzurePolicy = ($null -ne $script:AzurePolicyData)
        PurviewCompliance = ($null -ne $script:PurviewComplianceData)
        Delta = $false  # set later if a delta report is generated
        PrivilegedIdentity = ($null -ne $script:UnifiedPrivilegedRoster)
    }
    $htmlPlan = Get-HtmlReportPlan -HtmlReportSet $HtmlReportSet -HtmlDeepDiveDomains $HtmlDeepDiveDomains -AvailableSources $availableSources
    foreach ($w in @($htmlPlan.Warnings)) { Write-Warning $w }
    Write-Host "    HTML report mode: $HtmlReportSet" -ForegroundColor Gray
    if ($htmlPlan.GenerateDomainReports.Count -gt 0) {
        Write-Host "    Deep dives: $($htmlPlan.GenerateDomainReports -join ', ')" -ForegroundColor Gray
    }

    # Deep-dive subdirectory. Plan §6.2: deep dives land under
    # Reports/<ts>/DeepDives/ so the primary cockpit stays one file at the
    # top of the report folder. LegacyAll mode falls back to the flat
    # layout used pre-PR-4.
    $deepDivesDir = if ($HtmlReportSet -eq 'LegacyAll') { $reportDir } else { Join-Path $reportDir 'DeepDives' }
    $generatedDeepDives = @{}
    if ($htmlPlan.GenerateDomainReports.Count -gt 0 -and -not (Test-Path $deepDivesDir)) {
        New-Item -Path $deepDivesDir -ItemType Directory -Force | Out-Null
    }

    # Generate the requested per-domain deep dives. The domain set is the
    # intersection of (requested or LegacyAll-inferred) and (available data).
    if ('SecureScore' -in $htmlPlan.GenerateDomainReports) {
        $ssModule = Join-Path $script:ModulesPath "EntraChecks-SecureScore.psm1"
        Import-Module $ssModule -Force
        $beforeFiles = @(Get-ChildItem -Path $deepDivesDir -Filter 'SecureScore-Report-*.html' -ErrorAction SilentlyContinue)
        Export-SecureScoreReport -OutputDirectory $deepDivesDir -TenantName $TenantName
        $afterFiles = @(Get-ChildItem -Path $deepDivesDir -Filter 'SecureScore-Report-*.html' -ErrorAction SilentlyContinue)
        $new = ($afterFiles | Where-Object { $_.FullName -notin ($beforeFiles | ForEach-Object FullName) } | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
        if ($new) { $generatedDeepDives['SecureScore'] = $new.FullName }
    }

    if ('DefenderCompliance' -in $htmlPlan.GenerateDomainReports) {
        $defModule = Join-Path $script:ModulesPath "EntraChecks-DefenderCompliance.psm1"
        Import-Module $defModule -Force
        $beforeFiles = @(Get-ChildItem -Path $deepDivesDir -Filter 'DefenderCompliance-Report-*.html' -ErrorAction SilentlyContinue)
        Export-DefenderComplianceReport -OutputDirectory $deepDivesDir -TenantName $TenantName
        $afterFiles = @(Get-ChildItem -Path $deepDivesDir -Filter 'DefenderCompliance-Report-*.html' -ErrorAction SilentlyContinue)
        $new = ($afterFiles | Where-Object { $_.FullName -notin ($beforeFiles | ForEach-Object FullName) } | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
        if ($new) { $generatedDeepDives['DefenderCompliance'] = $new.FullName }
    }

    if ('AzurePolicy' -in $htmlPlan.GenerateDomainReports) {
        $apModule = Join-Path $script:ModulesPath "EntraChecks-AzurePolicy.psm1"
        Import-Module $apModule -Force
        $beforeFiles = @(Get-ChildItem -Path $deepDivesDir -Filter 'AzurePolicy-Report-*.html' -ErrorAction SilentlyContinue)
        Export-AzurePolicyReport -OutputDirectory $deepDivesDir -TenantName $TenantName
        $afterFiles = @(Get-ChildItem -Path $deepDivesDir -Filter 'AzurePolicy-Report-*.html' -ErrorAction SilentlyContinue)
        $new = ($afterFiles | Where-Object { $_.FullName -notin ($beforeFiles | ForEach-Object FullName) } | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
        if ($new) { $generatedDeepDives['AzurePolicy'] = $new.FullName }
    }

    if ('PurviewCompliance' -in $htmlPlan.GenerateDomainReports) {
        $pvModule = Join-Path $script:ModulesPath "EntraChecks-PurviewCompliance.psm1"
        Import-Module $pvModule -Force
        $beforeFiles = @(Get-ChildItem -Path $deepDivesDir -Filter 'PurviewCompliance-Report-*.html' -ErrorAction SilentlyContinue)
        Export-PurviewComplianceReport -OutputDirectory $deepDivesDir -TenantName $TenantName
        $afterFiles = @(Get-ChildItem -Path $deepDivesDir -Filter 'PurviewCompliance-Report-*.html' -ErrorAction SilentlyContinue)
        $new = ($afterFiles | Where-Object { $_.FullName -notin ($beforeFiles | ForEach-Object FullName) } | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
        if ($new) { $generatedDeepDives['PurviewCompliance'] = $new.FullName }
    }
    
    # Privileged Identity Roster — runs BEFORE the unified report so the
    # roster can be passed into the renderer. JSON snapshots are also emitted
    # so auditors get the standalone artefacts even when the full report
    # pipeline is skipped or fails. (PRs 2/3/4/5 of the roster work.)
    $script:UnifiedPrivilegedRoster = $null
    if ($EmitPrivilegedRoster) {
        # PR 2 — Active Directory roster
        Write-Host "`n[+] Building privileged identity roster (AD)..." -ForegroundColor Cyan
        $rosterModuleAD = Join-Path $script:ModulesPath "EntraChecks-PrivilegedIdentityAD.psm1"
        $adRoster = $null
        if (Test-Path $rosterModuleAD) {
            try {
                Import-Module $rosterModuleAD -Force -DisableNameChecking
                $adRoster = Get-PrivilegedIdentityRosterAD
                $rosterJson = Join-Path $reportDir 'PrivilegedIdentityRoster-AD.json'
                $adRoster | ConvertTo-Json -Depth 6 | Out-File -FilePath $rosterJson -Encoding utf8
                if ($adRoster.Available) {
                    Write-Host "    [OK] AD roster: $($adRoster.Statistics.TotalPrincipals) principals · Tier 0=$($adRoster.Statistics.Tier0Count), Tier 1=$($adRoster.Statistics.Tier1Count) -> $rosterJson" -ForegroundColor Green
                }
                else {
                    Write-Host "    [!] AD not available: $($adRoster.FailureReason)" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "    [!] AD roster collection failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "    [!] EntraChecks-PrivilegedIdentityAD.psm1 not found" -ForegroundColor Yellow
        }

        # PR 3 — Entra ID / M365 roster
        Write-Host "`n[+] Building privileged identity roster (Entra)..." -ForegroundColor Cyan
        $rosterModuleEntra = Join-Path $script:ModulesPath "EntraChecks-PrivilegedIdentityEntra.psm1"
        $entraRoster = $null
        if (Test-Path $rosterModuleEntra) {
            try {
                Import-Module $rosterModuleEntra -Force -DisableNameChecking
                $entraRoster = Get-PrivilegedIdentityRosterEntra
                $rosterJson = Join-Path $reportDir 'PrivilegedIdentityRoster-Entra.json'
                $entraRoster | ConvertTo-Json -Depth 6 | Out-File -FilePath $rosterJson -Encoding utf8
                if ($entraRoster.Available) {
                    $pimNote = if ($entraRoster.Statistics.PimAvailable) { 'PIM visible' } else { 'PIM not visible (P2 license required)' }
                    Write-Host "    [OK] Entra roster: $($entraRoster.Statistics.TotalPrincipals) principals · Tier 0=$($entraRoster.Statistics.Tier0Count), Tier 1=$($entraRoster.Statistics.Tier1Count), Tier 2=$($entraRoster.Statistics.Tier2Count), SPs=$($entraRoster.Statistics.ServicePrincipalCount) · $pimNote -> $rosterJson" -ForegroundColor Green
                }
                else {
                    Write-Host "    [!] Entra not available: $($entraRoster.FailureReason)" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "    [!] Entra roster collection failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "    [!] EntraChecks-PrivilegedIdentityEntra.psm1 not found" -ForegroundColor Yellow
        }

        # PR 4 — cross-surface correlation. Runs whenever both rosters returned
        # something; emits unified JSON + findings even when one side is empty.
        if ($adRoster -or $entraRoster) {
            Write-Host "`n[+] Correlating AD <-> Entra privileged identities..." -ForegroundColor Cyan
            $correlatorModule = Join-Path $script:ModulesPath "EntraChecks-PrivilegedIdentityCorrelator.psm1"
            if (Test-Path $correlatorModule) {
                try {
                    Import-Module $correlatorModule -Force -DisableNameChecking
                    $mergeArgs = @{
                        AdRoster = if ($adRoster) { $adRoster } else { @{ Available = $false; Roster = @() } }
                        EntraRoster = if ($entraRoster) { $entraRoster } else { @{ Available = $false; Roster = @() } }
                    }
                    if ($IdentityOverridesPath) { $mergeArgs['IdentityOverridesPath'] = $IdentityOverridesPath }
                    $unified = Merge-PrivilegedIdentityRosters @mergeArgs

                    $unifiedJson = Join-Path $reportDir 'PrivilegedIdentityRoster-Unified.json'
                    $unified | ConvertTo-Json -Depth 7 | Out-File -FilePath $unifiedJson -Encoding utf8
                    Write-Host "    [OK] Unified roster: $($unified.Statistics.Total) identities · CrossSurface=$($unified.Statistics.CrossSurface) · Tier0CrossSurface=$($unified.Statistics.Tier0CrossSurface) · Findings=$(@($unified.Findings).Count) -> $unifiedJson" -ForegroundColor Green

                    foreach ($f in @($unified.Findings)) {
                        $color = switch ($f.Severity) {
                            'Critical' { 'Red' }
                            'High' { 'Yellow' }
                            default { 'Gray' }
                        }
                        Write-Host "      [$($f.Severity)] $($f.Object): $($f.Description)" -ForegroundColor $color
                    }

                    # Cache for the renderers (PR 5) so the unified report and
                    # the comprehensive Excel report can show the roster.
                    $script:UnifiedPrivilegedRoster = $unified

                    # Surface correlator findings in the standard finding stream
                    # so they appear alongside the rest of the report's findings.
                    if (Get-Command Add-Finding -ErrorAction SilentlyContinue) {
                        foreach ($f in @($unified.Findings)) {
                            $status = switch ($f.Severity) {
                                'Critical' { 'FAIL' }
                                'High' { 'FAIL' }
                                'Medium' { 'WARNING' }
                                default { 'INFO' }
                            }
                            Add-Finding -Status $status -Object $f.Object -Description $f.Description -Remediation 'See Privileged Identity Roster section.' -Source 'Internal'
                        }
                    }
                }
                catch {
                    Write-Host "    [!] Correlation failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            else {
                Write-Host "    [!] EntraChecks-PrivilegedIdentityCorrelator.psm1 not found" -ForegroundColor Yellow
            }
        }
    }

    # Generate unified report — gated by the HTML routing plan. PR 4 of
    # HTML-Reporting-Consolidation: only LegacyAll mode emits this; under
    # Cockpit modes the cockpit subsumes the unified report's content.
    if ($IncludeUnified -and $htmlPlan.GenerateUnified) {
        $compModule = Join-Path $script:ModulesPath "EntraChecks-Compliance.psm1"
        if (Test-Path $compModule) {
            Import-Module $compModule -Force

            # Normalize findings to v2 + apply analyst state before the
            # unified renderer reads them (PR 2 of Central-Finding-Schema-GRC-Plan).
            $normalizedUnifiedFindings = $script:Findings
            if (Get-Command Initialize-FindingsForReport -ErrorAction SilentlyContinue) {
                $tenantIdForSchema = ''
                if ($script:TenantCapabilities -and $script:TenantCapabilities.TenantId) {
                    $tenantIdForSchema = [string]$script:TenantCapabilities.TenantId
                }
                $grcCfg = $null
                if ($script:Config -and $script:Config.GRC) { $grcCfg = $script:Config.GRC }
                $normalizedUnifiedFindings = Initialize-FindingsForReport `
                    -Findings @($script:Findings) `
                    -DefaultTenantId $tenantIdForSchema `
                    -ConfigGrc $grcCfg
            }

            $unifiedArgs = @{
                OutputDirectory = $reportDir
                TenantName = $TenantName
                Findings = $normalizedUnifiedFindings
                IncludeSecureScore = ($null -ne $script:SecureScoreData)
                IncludeDefenderCompliance = ($null -ne $script:DefenderComplianceData)
                IncludeAzurePolicy = ($null -ne $script:AzurePolicyData)
                IncludePurviewCompliance = ($null -ne $script:PurviewComplianceData)
                SecureScoreData = $script:SecureScoreData
                DefenderComplianceData = $script:DefenderComplianceData
                AzurePolicyData = $script:AzurePolicyData
                PurviewComplianceData = $script:PurviewComplianceData
            }
            if ($script:UnifiedPrivilegedRoster) {
                $unifiedArgs['PrivilegedIdentityRoster'] = $script:UnifiedPrivilegedRoster
            }
            Export-UnifiedComplianceReport @unifiedArgs
        }
    }

    # Generate the analyst cockpit when the plan says so (PR 4 of
    # HTML-Reporting-Consolidation-Plan). The cockpit replaces the legacy
    # comprehensive + unified reports in default (Cockpit) mode and links
    # out to any deep dives generated above.
    if ($htmlPlan.GenerateCockpit -and $script:Findings -and $script:Findings.Count -gt 0) {
        Write-Host "`n[+] Generating analyst cockpit HTML..." -ForegroundColor Cyan
        $htmlModule = Join-Path $script:ModulesPath 'EntraChecks-HTMLReporting.psm1'
        if (Test-Path $htmlModule) {
            Import-Module $htmlModule -Force

            $tenantInfo = [pscustomobject]@{
                TenantName = $TenantName
                TenantId = if ($script:TenantCapabilities) { [string]$script:TenantCapabilities.TenantId } else { '' }
            }

            # Normalize via Initialize-FindingsForReport so the cockpit sees
            # v2 findings (FindingId/Disposition/Owner/Exception). Same flow
            # the unified-report path uses.
            $normalizedFindings = $script:Findings
            if (Get-Command Initialize-FindingsForReport -ErrorAction SilentlyContinue) {
                $tenantIdForSchema = if ($tenantInfo.TenantId) { $tenantInfo.TenantId } else { '' }
                $grcCfg = $null
                if ($script:Config -and $script:Config.GRC) { $grcCfg = $script:Config.GRC }
                $normalizedFindings = Initialize-FindingsForReport `
                    -Findings @($script:Findings) `
                    -DefaultTenantId $tenantIdForSchema `
                    -ConfigGrc $grcCfg
            }

            $cockpitPath = Join-Path $reportDir "EntraChecks-Analyst-Cockpit-$timestamp.html"
            $cockpitArgs = @{
                Findings = $normalizedFindings
                OutputPath = $cockpitPath
                TenantInfo = $tenantInfo
                SecureScore = $script:SecureScoreData
                DefenderCompliance = $script:DefenderComplianceData
                AzurePolicy = $script:AzurePolicyData
                PurviewCompliance = $script:PurviewComplianceData
                HybridCorrelation = $script:HybridCorrelationData
                PrivilegedIdentityRoster = $script:UnifiedPrivilegedRoster
                DeepDives = $generatedDeepDives
            }
            New-EntraChecksAnalystHtmlReport @cockpitArgs | Out-Null
            Write-Host "    [OK] Analyst cockpit: $cockpitPath" -ForegroundColor Green
        }
        else {
            Write-Warning "EntraChecks-HTMLReporting.psm1 not found — skipping cockpit generation."
        }
    }

    # Generate comprehensive assessment report (LegacyAll mode only).
    if ($htmlPlan.GenerateComprehensive -and $GenerateComprehensiveReport -and $script:Findings -and $script:Findings.Count -gt 0) {
        Write-Host "`n[+] Generating comprehensive assessment report..." -ForegroundColor Cyan

        $comprehensiveReportScript = Join-Path (Join-Path $PSScriptRoot "Scripts") "New-ComprehensiveAssessmentReport.ps1"

        if (Test-Path $comprehensiveReportScript) {
            try {
                # Prepare external data
                $externalData = @{
                    SecureScore = $script:SecureScoreData
                    DefenderCompliance = $script:DefenderComplianceData
                    AzurePolicy = $script:AzurePolicyData
                    PurviewCompliance = $script:PurviewComplianceData
                    HybridCorrelation = $script:HybridCorrelationData
                    PrivilegedIdentityRoster = $script:UnifiedPrivilegedRoster
                }

                # Include assessment errors in external data for the report
                if ($results -and $results.Errors -and $results.Errors.Count -gt 0) {
                    $externalData['AssessmentErrors'] = $results.Errors
                }
                $failedMods = @()
                if ($results -and $results.Modules) {
                    $failedMods = @($results.Modules.GetEnumerator() | Where-Object { -not $_.Value.Success })
                }
                if ($failedMods.Count -gt 0) {
                    $externalData['FailedModules'] = $failedMods
                }

                # Normalize to v2 + apply analyst state before handing off
                # to the comprehensive report generator (PR 2 of
                # Central-Finding-Schema-GRC-Plan).
                $normalizedFindings = $script:Findings
                if (Get-Command Initialize-FindingsForReport -ErrorAction SilentlyContinue) {
                    $tenantIdForSchema = ''
                    if ($script:TenantCapabilities -and $script:TenantCapabilities.TenantId) {
                        $tenantIdForSchema = [string]$script:TenantCapabilities.TenantId
                    }
                    $grcCfg = $null
                    if ($script:Config -and $script:Config.GRC) { $grcCfg = $script:Config.GRC }
                    $normalizedFindings = Initialize-FindingsForReport `
                        -Findings @($script:Findings) `
                        -DefaultTenantId $tenantIdForSchema `
                        -ConfigGrc $grcCfg
                }

                # Build parameters for comprehensive report
                $comprehensiveParams = @{
                    Findings = $normalizedFindings
                    TenantName = $TenantName
                    OutputDirectory = $reportDir
                    ExternalData = $externalData
                }

                # Add optional switches
                if ($GenerateExecutiveSummary) {
                    $comprehensiveParams['GenerateExecutivePDF'] = $true
                }
                if ($GenerateExcelReport) {
                    $comprehensiveParams['GenerateExcelReport'] = $true
                }
                if ($GenerateRemediationScripts) {
                    $comprehensiveParams['GenerateRemediationScripts'] = $true
                }

                # Call the comprehensive report generator
                $comprehensiveResult = & $comprehensiveReportScript @comprehensiveParams

                Write-Host "    [OK] Comprehensive report generated" -ForegroundColor Green
                if ($comprehensiveResult.HTMLReport) {
                    Write-Host "        - HTML Report: $($comprehensiveResult.HTMLReport)" -ForegroundColor Gray
                }
                if ($comprehensiveResult.ExecutiveSummary) {
                    Write-Host "        - Executive Summary: $($comprehensiveResult.ExecutiveSummary)" -ForegroundColor Gray
                }
                if ($comprehensiveResult.ExcelReport) {
                    Write-Host "        - Excel Report: $($comprehensiveResult.ExcelReport)" -ForegroundColor Gray
                }
            }
            catch {
                Write-Host "    [!] Error generating comprehensive report: $($_.Exception.Message)" -ForegroundColor Red
                Write-Log -Level ERROR -Message "Comprehensive report generation failed" -Category "Reporting" -Properties @{
                    Error = $_.Exception.Message
                }
            }
        }
        else {
            Write-Host "    [!] Comprehensive report script not found: $comprehensiveReportScript" -ForegroundColor Yellow
        }
    }
    elseif ($GenerateComprehensiveReport -and (-not $script:Findings -or $script:Findings.Count -eq 0)) {
        Write-Host "    [!] No findings available for comprehensive report" -ForegroundColor Yellow
    }

    Write-Host "    [OK] Reports saved to: $reportDir" -ForegroundColor Green

    Write-Log -Level INFO -Message "Report generation completed" -Category "Reporting" -Properties @{
        ReportDirectory = $reportDir
    }
    Write-AuditLog -EventType "ReportGenerated" -Description "Assessment reports generated" -TargetObject $reportDir -Result "Success"

    return $reportDir
}

#endregion

#region ==================== INTERACTIVE MODE ====================

function Start-InteractiveMode {
    $selectedModules = @()
    $tenantName = $TenantName
    
    while ($true) {
        Show-Banner
        Show-AuthStatus
        Show-MainMenu
        
        $choice = Read-Host "  Select option"
        
        switch ($choice.ToUpper()) {
            "1" {
                # Quick Assessment - All Modules
                if (-not $tenantName) {
                    $tenantName = Read-Host "`n  Enter tenant name"
                }
                
                if (-not $SkipAuthentication) {
                    Connect-EntraCheck
                }
                
                $allModules = @("Core", "IdentityProtection", "Devices", "SecureScore", "Defender", "AzurePolicy", "Purview")
                $results = Invoke-ModuleAssessment -SelectedModules $allModules -TenantName $tenantName -OutputDir $OutputDirectory
                
                $reportDir = Export-AssessmentResult -OutputDir $OutputDirectory -TenantName $tenantName -IncludeUnified -GenerateComprehensiveReport:$GenerateComprehensiveReport -GenerateExecutiveSummary:$GenerateExecutiveSummary -GenerateExcelReport:$GenerateExcelReport -GenerateRemediationScripts:$GenerateRemediationScripts -HtmlReportSet $HtmlReportSet -HtmlDeepDiveDomains $HtmlDeepDiveDomains
                
                if ($SaveSnapshot -or (Read-Host "`n  Save snapshot for future comparison? (Y/N)").ToUpper() -eq "Y") {
                    $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
                    Import-Module $deltaModule -Force
                    Save-ComplianceSnapshot -OutputDirectory $script:SnapshotsPath -TenantName $tenantName `
                        -SecureScoreData $script:SecureScoreData `
                        -DefenderComplianceData $script:DefenderComplianceData `
                        -AzurePolicyData $script:AzurePolicyData `
                        -PurviewComplianceData $script:PurviewComplianceData
                }

                Write-Host "`n  Assessment complete! Duration: $($results.Duration.TotalMinutes.ToString('0.0')) minutes" -ForegroundColor Green
                Write-Host "  Reports saved to: $reportDir" -ForegroundColor Cyan

                # Auto-run SOC 2 readiness when SOC2.Enabled = true in config
                Invoke-SOC2ReadinessIfEnabled -TenantName $tenantName -OutputDirectory $OutputDirectory -OpenBrowser $true

                Read-Host "`n  Press Enter to continue"
            }
            
            "2" {
                # Select Modules
                $selectedModules = @()
                $continueSelection = $true
                
                while ($continueSelection) {
                    Show-Banner
                    Show-ModuleMenu
                    
                    if ($selectedModules.Count -gt 0) {
                        Write-Host "  Selected: $($selectedModules -join ', ')" -ForegroundColor Green
                    }
                    
                    $moduleChoice = Read-Host "  Select option"
                    
                    switch ($moduleChoice.ToUpper()) {
                        "1" { if ("Core" -notin $selectedModules) { $selectedModules += "Core" } }
                        "2" { if ("IdentityProtection" -notin $selectedModules) { $selectedModules += "IdentityProtection" } }
                        "3" { if ("Devices" -notin $selectedModules) { $selectedModules += "Devices" } }
                        "4" { if ("SecureScore" -notin $selectedModules) { $selectedModules += "SecureScore" } }
                        "5" { if ("Defender" -notin $selectedModules) { $selectedModules += "Defender" } }
                        "6" { if ("AzurePolicy" -notin $selectedModules) { $selectedModules += "AzurePolicy" } }
                        "7" { if ("Purview" -notin $selectedModules) { $selectedModules += "Purview" } }
                        "8" { if ("ActiveDirectory" -notin $selectedModules) { $selectedModules += "ActiveDirectory" } }
                        "A" { $selectedModules = @("Core", "IdentityProtection", "Devices", "SecureScore", "Defender", "AzurePolicy", "Purview", "ActiveDirectory") }
                        "C" { $selectedModules = @() }
                        "R" {
                            if ($selectedModules.Count -gt 0) {
                                if (-not $tenantName) {
                                    $tenantName = Read-Host "`n  Enter tenant name"
                                }
                                
                                if (-not $SkipAuthentication) {
                                    Connect-EntraCheck
                                }
                                
                                $results = Invoke-ModuleAssessment -SelectedModules $selectedModules -TenantName $tenantName -OutputDir $OutputDirectory
                                $reportDir = Export-AssessmentResult -OutputDir $OutputDirectory -TenantName $tenantName -IncludeUnified -GenerateComprehensiveReport:$GenerateComprehensiveReport -GenerateExecutiveSummary:$GenerateExecutiveSummary -GenerateExcelReport:$GenerateExcelReport -GenerateRemediationScripts:$GenerateRemediationScripts -HtmlReportSet $HtmlReportSet -HtmlDeepDiveDomains $HtmlDeepDiveDomains
                                
                                Write-Host "`n  Assessment complete!" -ForegroundColor Green
                                Read-Host "  Press Enter to continue"
                            }
                            $continueSelection = $false
                        }
                        "B" { $continueSelection = $false }
                    }
                }
            }
            
            "3" {
                # View Last Results
                $latestDir = Get-ChildItem -Path $OutputDirectory -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($latestDir) {
                    $htmlFile = Get-ChildItem -Path $latestDir.FullName -Filter "*.html" | Select-Object -First 1
                    if ($htmlFile) {
                        Start-Process $htmlFile.FullName
                    }
                    else {
                        Write-Host "`n  No HTML reports found in: $($latestDir.FullName)" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "`n  No previous reports found." -ForegroundColor Yellow
                }
                Read-Host "`n  Press Enter to continue"
            }
            
            "4" {
                # Compare Snapshots
                $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
                if (Test-Path $deltaModule) {
                    Import-Module $deltaModule -Force
                    
                    $snapshots = Get-ComplianceSnapshots -SnapshotDirectory $script:SnapshotsPath
                    
                    if ($snapshots.Count -lt 2) {
                        Write-Host "`n  Need at least 2 snapshots for comparison." -ForegroundColor Yellow
                        Write-Host "  Found: $($snapshots.Count) snapshot(s)" -ForegroundColor Gray
                    }
                    else {
                        Write-Host "`n  Available Snapshots:" -ForegroundColor Cyan
                        $i = 1
                        foreach ($snap in $snapshots) {
                            Write-Host "    [$i] $($snap.CreatedAt) - $($snap.SnapshotId) ($($snap.TenantName))" -ForegroundColor White
                            $i++
                        }
                        
                        $baseIdx = [int](Read-Host "`n  Select BASELINE snapshot number") - 1
                        $currIdx = [int](Read-Host "  Select CURRENT snapshot number") - 1
                        
                        $baseSnapshot = Import-ComplianceSnapshot -SnapshotPath $snapshots[$baseIdx].FilePath
                        $currSnapshot = Import-ComplianceSnapshot -SnapshotPath $snapshots[$currIdx].FilePath
                        
                        $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baseSnapshot -CurrentSnapshot $currSnapshot
                        Export-DeltaReport -DeltaData $delta -OutputDirectory $OutputDirectory -TenantName $tenantName
                    }
                }
                Read-Host "`n  Press Enter to continue"
            }
            
            "5" {
                # Manage Snapshots
                $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
                if (Test-Path $deltaModule) {
                    Import-Module $deltaModule -Force

                    $snapshots = Get-ComplianceSnapshots -SnapshotDirectory $script:SnapshotsPath

                    Write-Host "`n  Saved Snapshots ($($snapshots.Count)):" -ForegroundColor Cyan
                    Write-Host ("  " + ("-" * 70)) -ForegroundColor Gray

                    foreach ($snap in $snapshots) {
                        Write-Host "    $($snap.CreatedAt) | $($snap.SnapshotId) | $($snap.TenantName)" -ForegroundColor White
                    }

                    Write-Host ("  " + ("-" * 70)) -ForegroundColor Gray
                    Write-Host "  Directory: $script:SnapshotsPath" -ForegroundColor Gray
                }
                Read-Host "`n  Press Enter to continue"
            }

            "6" {
                # SOC 2 Internal Readiness Assessment (Type 1)
                Invoke-SOC2ReadinessFromMenu -TenantName $tenantName -OutputDirectory $OutputDirectory
                Read-Host "`n  Press Enter to continue"
            }

            "7" {
                # SOC 2 Type 2 period coverage from snapshots
                Invoke-SOC2TypeTwoFromMenu -TenantName $tenantName -OutputDirectory $OutputDirectory -SnapshotDirectory $script:SnapshotsPath
                Read-Host "`n  Press Enter to continue"
            }

            "8" {
                # Active Directory (On-Prem) assessment
                if (-not $tenantName) {
                    $tenantName = Read-Host "`n  Enter tenant name"
                }
                $results = Invoke-ModuleAssessment -SelectedModules @('ActiveDirectory') -TenantName $tenantName -OutputDir $OutputDirectory
                if ($results) {
                    Write-Host "`n  AD assessment complete. Findings will appear in the next report generation." -ForegroundColor Green
                }
                Read-Host "`n  Press Enter to continue"
            }

            "Y" {
                # Hybrid Analysis — cloud + hybrid + on-prem with correlation.
                $script:TenantName = if ($tenantName) { $tenantName } else { Read-Host "`n  Enter tenant name" }
                $tenantName = $script:TenantName
                Start-HybridMode
                Read-Host "`n  Press Enter to continue"
            }

            "A" {
                # Authentication
                Write-Host ""
                Connect-EntraCheck
                Read-Host "`n  Press Enter to continue"
            }

            "D" {
                # Disconnect / Sign out
                Disconnect-EntraCheck
                Read-Host "  Press Enter to continue"
            }

            "S" {
                # Settings
                Write-Host "`n  Current Settings:" -ForegroundColor Cyan
                Write-Host "    Output Directory: $OutputDirectory" -ForegroundColor White
                Write-Host "    Snapshots Path:   $script:SnapshotsPath" -ForegroundColor White
                Write-Host "    Tenant Name:      $(if ($tenantName) { $tenantName } else { '(not set)' })" -ForegroundColor White
                
                $newTenant = Read-Host "`n  Enter new tenant name (or press Enter to keep current)"
                if ($newTenant) { $tenantName = $newTenant }
                
                Read-Host "`n  Press Enter to continue"
            }
            
            "H" {
                # Help
                Write-Host "`n  EntraChecks Documentation" -ForegroundColor Cyan
                Write-Host " =========================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  Available Modules:" -ForegroundColor White
                foreach ($key in $script:ModuleDefinitions.Keys) {
                    $def = $script:ModuleDefinitions[$key]
                    Write-Host "    - $($def.Name): $($def.Description)" -ForegroundColor Gray
                }
                Write-Host ""
                Write-Host "  For detailed documentation, see the README files in the Modules folder." -ForegroundColor White
                Read-Host "`n  Press Enter to continue"
            }
            
            "Q" {
                Disconnect-EntraCheck -Silent
                Write-Host "`n  Sessions disconnected. Goodbye!" -ForegroundColor Cyan
                return
            }
        }
    }
}

#endregion

#region ==================== QUICK/SCHEDULED MODES ====================

function Invoke-EcfAssessmentSequence {
    <#
    .SYNOPSIS
        Shared non-interactive assessment sequence — the common body of
        Start-QuickMode / Start-ScheduledMode / Start-HybridMode.

    .DESCRIPTION
        Native App Plan, Phase 1 (incremental step 2): a pure,
        behaviour-identical DRY consolidation. The three non-interactive
        modes keep their mode-specific preamble (banner, tenant prompt,
        auth) and call this single sequence. No logic changes — this is
        the seam the runner's event lifecycle wraps in the next step.

        Mode-varying inputs are explicit parameters; everything else is
        read from the script-scope parameters exactly as the three modes
        did inline.

    .PARAMETER TenantNameValue
        Resolved tenant name (modes pass their post-prompt value — the
        sequence must not rely on the modes' function-local $TenantName).

    .PARAMETER ModuleSet
        The module set to assess (mode-specific).

    .PARAMETER RunHybridCorrelation
        Hybrid mode only: run the cloud↔on-prem correlation pass and
        stash $script:HybridCorrelationData for Export-AssessmentResult.

    .PARAMETER DoCompareWithLast
        Quick mode only (gated on -CompareWithLast): emit the delta report.

    .PARAMETER ErrorActionStop
        Scheduled mode only: run the sequence under
        $ErrorActionPreference='Stop' (the inline scheduled body set this
        before these same calls; preserved here so the refactor is
        behaviour-identical).
    #>
    param(
        [Parameter(Mandatory)][string]$TenantNameValue,
        [Parameter(Mandatory)][string[]]$ModuleSet,
        [switch]$RunHybridCorrelation,
        [switch]$DoCompareWithLast,
        [switch]$ErrorActionStop
    )

    if ($ErrorActionStop) { $ErrorActionPreference = "Stop" }

    $results = Invoke-ModuleAssessment -SelectedModules $ModuleSet -TenantName $TenantNameValue -OutputDir $OutputDirectory

    $hybridCorrelation = $null
    if ($RunHybridCorrelation) {
        # Correlation pass. Script:Findings was populated by the module dispatcher.
        $corrModule = Join-Path $script:ModulesPath "EntraChecks-HybridCorrelation.psm1"
        if (Test-Path $corrModule) {
            Import-Module $corrModule -Force
            try {
                $hybridCorrelation = Get-HybridIdentityCorrelation -Findings $script:Findings
                Write-Host "    [OK] Correlated $($hybridCorrelation.CorrelationCount) principals across cloud + on-prem." -ForegroundColor Green
                # PR 5 - push cross-surface findings back into the main pool so risk scoring,
                # HTML / Excel / CSV renderers, and delta reporting all see them alongside
                # standard findings. They carry Source='HybridCorrelation' so downstream code
                # can group / filter if needed.
                if ($hybridCorrelation.CrossSurfaceCount -gt 0) {
                    $script:Findings += $hybridCorrelation.CrossSurfaceFindings
                    Write-Host "    [OK] Emitted $($hybridCorrelation.CrossSurfaceCount) cross-surface finding(s)." -ForegroundColor Green
                }
            }
            catch {
                Write-Host "    [!] Correlation pass failed: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        # Stash correlation output on a script-scope variable so Export-AssessmentResult can pick it up.
        $script:HybridCorrelationData = $hybridCorrelation
    }

    $reportDir = Export-AssessmentResult -OutputDir $OutputDirectory -TenantName $TenantNameValue -IncludeUnified -GenerateComprehensiveReport:$GenerateComprehensiveReport -GenerateExecutiveSummary:$GenerateExecutiveSummary -GenerateExcelReport:$GenerateExcelReport -GenerateRemediationScripts:$GenerateRemediationScripts -HtmlReportSet $HtmlReportSet -HtmlDeepDiveDomains $HtmlDeepDiveDomains

    if ($SaveSnapshot) {
        $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
        Import-Module $deltaModule -Force
        Save-ComplianceSnapshot -OutputDirectory $script:SnapshotsPath -TenantName $TenantNameValue `
            -SecureScoreData $script:SecureScoreData `
            -DefenderComplianceData $script:DefenderComplianceData `
            -AzurePolicyData $script:AzurePolicyData `
            -PurviewComplianceData $script:PurviewComplianceData
    }

    # Auto-run SOC 2 readiness when SOC2.Enabled = true in config. Browser
    # open is suppressed in scripted modes (automation friendly).
    Invoke-SOC2ReadinessIfEnabled -TenantName $TenantNameValue -OutputDirectory $OutputDirectory -OpenBrowser $false

    if ($DoCompareWithLast) {
        $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
        Import-Module $deltaModule -Force

        # Get the two most recent snapshots and compare them
        $snapshots = Get-ComplianceSnapshots -SnapshotDirectory $script:SnapshotsPath
        if ($snapshots -and $snapshots.Count -ge 2) {
            $currentSnap = Import-ComplianceSnapshot -SnapshotPath $snapshots[0].FilePath
            $baselineSnap = Import-ComplianceSnapshot -SnapshotPath $snapshots[1].FilePath
            $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baselineSnap -CurrentSnapshot $currentSnap
            Export-DeltaReport -DeltaData $delta -OutputDirectory $OutputDirectory -TenantName $TenantNameValue
        }
        else {
            Write-Host "[!] Need at least 2 snapshots for comparison. Save a snapshot first." -ForegroundColor Yellow
        }
    }

    return [pscustomobject]@{
        Results = $results
        ReportDir = $reportDir
        HybridCorrelation = $hybridCorrelation
    }
}

function Start-QuickMode {
    Write-Host "`n[+] Quick Assessment Mode" -ForegroundColor Magenta

    if (-not $TenantName) {
        $TenantName = Read-Host "Enter tenant name"
    }

    if (-not $SkipAuthentication) {
        Connect-EntraCheck
    }

    $modulesToRun = if ($Modules -contains "All" -or -not $Modules) {
        @("Core", "IdentityProtection", "Devices", "SecureScore", "Defender", "AzurePolicy", "Purview")
    }
    else {
        $Modules
    }

    $seq = Invoke-EcfAssessmentSequence -TenantNameValue $TenantName -ModuleSet $modulesToRun -DoCompareWithLast:$CompareWithLast

    Write-Host "`n[+] Assessment Complete" -ForegroundColor Green
    Write-Host "    Duration: $($seq.Results.Duration.TotalMinutes.ToString('0.0')) minutes" -ForegroundColor Cyan
    Write-Host "    Reports: $($seq.ReportDir)" -ForegroundColor Cyan
}

function Start-HybridMode {
    <#
    .SYNOPSIS
        Cloud + Hybrid + On-Prem AD assessment with cross-plane correlation.
    .DESCRIPTION
        PR 2 of the AD integration roadmap. Runs the cloud module set plus
        the on-prem ActiveDirectory module, then correlates identity-bearing
        findings across the two planes via Get-HybridIdentityCorrelation.
        The unified report renders a new "Hybrid Correlation" section
        highlighting principals flagged in both planes.
    #>
    Write-Host "`n[+] Hybrid Analysis Mode" -ForegroundColor Magenta

    if (-not $TenantName) {
        $TenantName = Read-Host "Enter tenant name"
    }

    if (-not $SkipAuthentication) {
        Connect-EntraCheck
    }

    # Core cloud set + Hybrid (AD Connect health) + on-prem AD.
    $hybridModules = @('Core', 'IdentityProtection', 'Devices', 'SecureScore', 'Defender', 'AzurePolicy', 'Purview', 'ActiveDirectory')

    $seq = Invoke-EcfAssessmentSequence -TenantNameValue $TenantName -ModuleSet $hybridModules -RunHybridCorrelation

    Write-Host "`n[+] Hybrid Analysis Complete" -ForegroundColor Green
    Write-Host "    Duration: $($seq.Results.Duration.TotalMinutes.ToString('0.0')) minutes" -ForegroundColor Cyan
    Write-Host "    Reports: $($seq.ReportDir)" -ForegroundColor Cyan
    if ($seq.HybridCorrelation -and $seq.HybridCorrelation.CorrelationCount -gt 0) {
        Write-Host "    [!] $($seq.HybridCorrelation.CorrelationCount) principals are flagged in BOTH cloud and on-prem. See the Hybrid Correlation section of the report." -ForegroundColor Yellow
    }
}

function Start-ScheduledMode {
    # Silent mode for automation
    $ErrorActionPreference = "Stop"
    
    if (-not $TenantName) {
        throw "TenantName is required for scheduled mode"
    }
    
    if (-not $SkipAuthentication) {
        # In scheduled mode, use managed identity or service principal
        # This assumes pre-authenticated session
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        
        if (-not $graphContext -and -not $azContext) {
            throw "No active authentication session. Use -SkipAuthentication with pre-authenticated context."
        }
    }
    
    $modulesToRun = if ($Modules -contains "All" -or -not $Modules) {
        @("Core", "SecureScore")  # Default to core modules for scheduled runs
    }
    else {
        $Modules
    }

    $seq = Invoke-EcfAssessmentSequence -TenantNameValue $TenantName -ModuleSet $modulesToRun -ErrorActionStop

    # Return structured result for automation
    return @{
        Success = $seq.Results.Errors.Count -eq 0
        Duration = $seq.Results.Duration
        Modules = $seq.Results.Modules
        Errors = $seq.Results.Errors
    }
}

#endregion

#region ==================== MAIN EXECUTION ====================

# Main entry point
try {
    switch ($Mode) {
        "Interactive" {
            Start-InteractiveMode
        }
        "Quick" {
            Start-QuickMode
        }
        "Scheduled" {
            Start-ScheduledMode
        }
        "Hybrid" {
            Start-HybridMode
        }
    }
}
catch {
    Write-Log -Level CRITICAL -Message "Unhandled error in main execution" -Category "System" -ErrorRecord $_
    throw
}
finally {
    # Disconnect Graph and Azure sessions
    if (Get-Command Disconnect-EntraCheck -ErrorAction SilentlyContinue) {
        Disconnect-EntraCheck -Silent
    }

    # Cleanup and flush logs
    if (Get-Command Stop-Logging -ErrorAction SilentlyContinue) {
        Stop-Logging
    }
}

#endregion
