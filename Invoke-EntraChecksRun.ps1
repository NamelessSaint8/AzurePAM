<#
.SYNOPSIS
    Headless, non-interactive EntraChecks run — the contract entrypoint
    for automation and the Phase 4 Tauri sidecar.

.DESCRIPTION
    Native App Plan, Phase 1 (4/4b). A deliberately thin wrapper: it
    exposes the runner *contract* parameter surface (no -Mode, no menu
    baggage) and drives the already contract-wired non-interactive path
    (Start-EntraChecks.ps1's Quick mode -> Invoke-EcfAssessmentSequence
    -> EntraChecks-Runner). The orchestration + its cross-module
    $script: substrate are NOT relocated — they are reached via the
    dot-sourceable EntraChecks.Orchestration.ps1 include that the Quick
    path already uses (see 4/4a). Setup is reused, not duplicated, so it
    cannot drift from Start-EntraChecks.ps1.

    -EmitEvents streams the versioned NDJSON event contract to stdout
    (what the sidecar reads); the run-history manifest under
    <OutputDirectory>/.runs/<runId>.json is written regardless. There is
    no Read-Host on this path: -TenantName is required (a headless run
    must never prompt), and authentication is the existing coarse flow
    (device-code-as-events is Phase 3).

.PARAMETER TenantName
    Required. The tenant being assessed. A headless run never prompts,
    so this must be supplied explicitly.

.PARAMETER OutputDirectory
    Base directory for reports + the .runs/<runId>.json run history.

.PARAMETER Modules
    Module set (Core .. All). Defaults to the Quick cloud set.

.PARAMETER ExportFormat
    HTML | CSV | JSON | All.

.PARAMETER ConfigFile / -Environment
    Optional configuration file + environment override.

.PARAMETER SaveSnapshot / -CompareWithLast
    Snapshot save / delta-compare, as in the CLI.

.PARAMETER HtmlReportSet / -HtmlDeepDiveDomains
    HTML routing, as in the CLI.

.PARAMETER EmitPrivilegedRoster / -IdentityOverridesPath
    Privileged-roster emission + identity-equivalence overrides.

.PARAMETER SkipAuthentication
    Use an existing pre-authenticated Graph/Az session (automation).

.PARAMETER EmitEvents
    Stream the NDJSON event contract to stdout. Off = silent run; the
    run-history manifest is still written.

.EXAMPLE
    ./Invoke-EntraChecksRun.ps1 -TenantName Contoso -SkipAuthentication -EmitEvents
    # Headless run; NDJSON on stdout for a sidecar/CI to consume.

.NOTES
    plans/Native-App-Phase1-Headless-Core-Plan.md (4/4).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantName,

    [string]$OutputDirectory = ".\Reports",

    [ValidateSet("Core", "IdentityProtection", "Devices", "SecureScore", "Defender", "AzurePolicy", "Purview", "ActiveDirectory", "All")]
    [string[]]$Modules,

    [ValidateSet("HTML", "CSV", "JSON", "All")]
    [string]$ExportFormat = "All",

    [string]$ConfigFile,

    [string]$Environment,

    [switch]$SaveSnapshot,

    [switch]$CompareWithLast,

    [ValidateSet('Cockpit', 'CockpitAndDeepDives', 'DeepDivesOnly', 'LegacyAll')]
    [string]$HtmlReportSet,

    [ValidateSet('SecureScore', 'DefenderCompliance', 'AzurePolicy', 'PurviewCompliance', 'Delta', 'PrivilegedIdentity')]
    [string[]]$HtmlDeepDiveDomains,

    [switch]$EmitPrivilegedRoster,

    [string]$IdentityOverridesPath,

    [switch]$SkipAuthentication,

    [switch]$EmitEvents
)

$ErrorActionPreference = 'Stop'

# Headless contract: never prompt. (Belt-and-braces — the param is
# already Mandatory; this also rejects an empty/whitespace value that
# Mandatory would otherwise accept after a prompt in some hosts.)
if ([string]::IsNullOrWhiteSpace($TenantName)) {
    throw "Invoke-EntraChecksRun: -TenantName is required for a headless run (no interactive prompt)."
}

$startScript = Join-Path $PSScriptRoot 'Start-EntraChecks.ps1'
if (-not (Test-Path -LiteralPath $startScript)) {
    throw "Invoke-EntraChecksRun: Start-EntraChecks.ps1 not found next to this wrapper ($startScript)."
}

# Forward only the parameters the caller actually set, plus the fixed
# headless choices (Quick = full non-interactive assessment; the Quick
# path is already wired to the runner event lifecycle + manifest in
# Phase 1 step 3, so no orchestration logic is duplicated here).
$forward = @{
    Mode = 'Quick'
    TenantName = $TenantName
    OutputDirectory = $OutputDirectory
    EmitEvents = [bool]$EmitEvents
}
foreach ($name in @('Modules', 'ExportFormat', 'ConfigFile', 'Environment',
        'SaveSnapshot', 'CompareWithLast', 'HtmlReportSet', 'HtmlDeepDiveDomains',
        'EmitPrivilegedRoster', 'IdentityOverridesPath', 'SkipAuthentication')) {
    if ($PSBoundParameters.ContainsKey($name)) {
        $forward[$name] = $PSBoundParameters[$name]
    }
}

& $startScript @forward
