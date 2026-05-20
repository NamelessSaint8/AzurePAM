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
    [string[]]$HtmlDeepDiveDomains,

    # Native App Plan, Phase 1. When set, the non-interactive modes
    # (Quick/Scheduled/Hybrid) stream the runner's versioned NDJSON
    # event contract to stdout. Off by default: the run is silent
    # (the run-history manifest is still written). The Phase 2 console
    # renderer is what restores rich progress for interactive CLI use.
    [switch]$EmitEvents
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

# -- Module load helper -----------------------------------------------
#
# The original imports all used `-ErrorAction SilentlyContinue`. That
# made downstream "X is not recognized" cascades impossible to debug
# from the GUI (the actual import error was swallowed and never
# reached stderr). This helper surfaces the real Import-Module
# failure with the module path so the desktop's stderr capture and
# the TUI's console both show *why* loading failed.
$script:ModuleLoadFailures = New-Object System.Collections.Generic.List[string]
function script:Import-EcfModule {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ImportArgs = ''
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        $msg = "Module file not found: $Path"
        Write-Host "[X] $msg" -ForegroundColor Red
        $script:ModuleLoadFailures.Add($msg) | Out-Null
        return
    }
    try {
        if ($ImportArgs -eq 'DisableNameChecking') {
            Import-Module -Name $Path -Force -DisableNameChecking -ErrorAction Stop
        }
        else {
            Import-Module -Name $Path -Force -ErrorAction Stop
        }
    }
    catch {
        $msg = "Import-Module '$Path' failed: $($_.Exception.Message)"
        Write-Host "[X] $msg" -ForegroundColor Red
        $script:ModuleLoadFailures.Add($msg) | Out-Null
    }
}

# Import configuration module
$configModule = Join-Path $script:ModulesPath "EntraChecks-Configuration.psm1"
Import-EcfModule -Path $configModule

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
Import-EcfModule -Path $loggingModule

# Import data sources catalog so Add-Finding can tag each finding with its
# provenance source (auto-derived from the call stack, with optional override).
$dsModule = Join-Path $script:ModulesPath "EntraChecks-DataSources.psm1"
Import-EcfModule -Path $dsModule -ImportArgs 'DisableNameChecking'

# Import the v2 finding schema module (PR 2 of Central-Finding-Schema-GRC-Plan).
# Initialize-FindingsForReport runs at report-generation time to normalize
# every finding to schema v2 and merge optional analyst state. Loaded with
# -ErrorAction SilentlyContinue so legacy installs without the module still
# function — Initialize-FindingsForReport is invoked behind a Get-Command
# guard at the consumer sites.
$schemaModule = Join-Path $script:ModulesPath "EntraChecks-FindingSchema.psm1"
Import-EcfModule -Path $schemaModule

# Native App Plan, Phase 1 — the headless-runner contract. The
# non-interactive modes wrap Invoke-EcfAssessmentSequence with this
# module's NDJSON event lifecycle + run-history manifest. Loaded behind
# a Get-Command guard at the call site so a legacy install without the
# module still runs (events simply not emitted).
$runnerModule = Join-Path $script:ModulesPath "EntraChecks-Runner.psm1"
Import-EcfModule -Path $runnerModule

# HTML reporting module. The orchestration calls Get-HtmlReportPlan
# (from this module) early in its Report phase, but historically only
# Import-Module'd the file ~200 lines later in the same function —
# which on a packaged install meant "Get-HtmlReportPlan is not
# recognized" and the whole Report phase failed. Pre-load up front
# alongside the other engine modules; the lazy Import-Module deeper
# in the orchestration is still safe (idempotent with -Force).
$htmlModule = Join-Path $script:ModulesPath "EntraChecks-HTMLReporting.psm1"
Import-EcfModule -Path $htmlModule

# Initialize logging subsystem (from config or defaults)
if ($script:Config -and $script:Config.Logging) {
    $logConfig = $script:Config.Logging
    # $null = : Initialize-LoggingSubsystem returns $true; without this
    # the bare boolean leaks to stdout (the stray "True" after the
    # "Logging subsystem initialized" line on a real run).
    $null = Initialize-LoggingSubsystem `
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
    $null = Initialize-LoggingSubsystem -LogDirectory $script:LogsPath -MinimumLevel $logLevel -RetentionDays 90 -StructuredLogging
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


#region ==================== ORCHESTRATION (dot-sourced) ====================

# Native App Plan, Phase 1 (4/4): the orchestration function definitions
# live in EntraChecks.Orchestration.ps1 so both this menu entrypoint and
# the headless Invoke-EntraChecksRun.ps1 wrapper share one copy without
# relocating the $script: substrate. Dot-sourced into this scope, so
# behaviour is identical to when these were inline.
. (Join-Path $PSScriptRoot "EntraChecks.Orchestration.ps1")

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

