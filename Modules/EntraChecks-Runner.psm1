<#
.SYNOPSIS
    EntraChecks-Runner.psm1 — headless, observable assessment runner.
    Native App Plan, Phase 1 (the keystone contract).

.DESCRIPTION
    Provides the single non-interactive entry point Invoke-EntraChecksRun
    plus the contract primitives every UI (the re-platformed TUI in
    Phase 2, the Tauri GUI sidecar in Phase 4) and CI/automation drive
    the engine through:

      - a versioned NDJSON progress event stream (schemaVersion 1.0),
      - a structured run-result manifest, also written to run history,
      - parameter-driven invocation with no Read-Host and no decorative
        Write-Host (narration is emitted as events).

    The contract event/manifest shapes are frozen at v1.0 and are
    additive-only within major version 1 — see
    plans/Native-App-Phase1-Headless-Core-Plan.md §4/§5.

    Authored 5.1-safe (no PS7-only syntax) so the Phase 2 TUI can import
    it in-process under Windows PowerShell 5.1 as well as pwsh 7.

.NOTES
    Version: 1.0.0
    Author: EntraChecks Project
.LINK
    plans/Native-App-Phase1-Headless-Core-Plan.md
#>

#Requires -Version 5.1

$script:ModuleName = 'EntraChecks-Runner'
$script:ModuleVersion = '1.0.0'

# Frozen contract version. Bump the minor only for additive changes;
# never break a v1.x consumer.
$script:EcfSchemaVersion = '1.0'

# Canonical phase names (the only legal values of the `phase` field).
$script:EcfPhases = @('Prereqs', 'Auth', 'Core', 'Modules', 'Snapshot', 'SOC2', 'Report')

# Parameter keys allowed into the sanitized params echo. Anything not on
# this allowlist is dropped — secrets/tokens can never leak into the
# event stream or the run-history file because only these keys pass.
$script:EcfSafeParamKeys = @(
    'TenantName', 'OutputDirectory', 'Modules', 'ExportFormat', 'ConfigFile',
    'Environment', 'SaveSnapshot', 'CompareWithLast', 'HtmlReportSet',
    'HtmlDeepDiveDomains', 'EmitPrivilegedRoster', 'IdentityOverridesPath',
    'SkipAuthentication', 'AuthMethod', 'RunId', 'EmitEvents'
)

#region ==================== CONTRACT PRIMITIVES ====================

<#
.SYNOPSIS
    UTC timestamp in the contract's ISO-8601 form (yyyy-MM-ddTHH:mm:ssZ).
#>
function Get-EcfUtc {
    [CmdletBinding()]
    [OutputType([string])]
    param([datetime]$Time = (Get-Date))
    return $Time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

<#
.SYNOPSIS
    Projects a parameter hashtable onto the allowlist (§6 sanitization).
    Never returns disallowed keys; values are passed through as-is (the
    allowed set carries no secrets — auth material is resolved inside the
    engine, never a runner parameter).
#>
function ConvertTo-EcfSafeParams {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][AllowNull()]$Params)

    $safe = [ordered]@{}
    if ($null -eq $Params) { return $safe }

    foreach ($key in $script:EcfSafeParamKeys) {
        $has = $false
        $val = $null
        if ($Params -is [hashtable]) {
            if ($Params.ContainsKey($key)) { $has = $true; $val = $Params[$key] }
        }
        elseif ($Params.PSObject -and $Params.PSObject.Properties[$key]) {
            $has = $true; $val = $Params.$key
        }
        if ($has) {
            # Normalize switch/bool to plain bool for stable JSON.
            if ($val -is [System.Management.Automation.SwitchParameter]) {
                $val = [bool]$val
            }
            $safe[$key] = $val
        }
    }
    return $safe
}

<#
.SYNOPSIS
    Creates the in-process run context the driver threads through every
    emitter call. Holds the runId, the ordered event list (source of
    truth), and the artifact/error/warning accumulators.
#>
function New-EcfRunContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$RunId,
        [AllowNull()]$Params,
        [string]$OutputDirectory = '',
        [switch]$EmitEvents
    )

    if (-not $RunId) { $RunId = [guid]::NewGuid().ToString() }

    return [pscustomobject]@{
        RunId = $RunId
        SchemaVersion = $script:EcfSchemaVersion
        StartedUtc = Get-EcfUtc
        EndedUtc = ''
        OutputDirectory = $OutputDirectory
        EmitEvents = [bool]$EmitEvents
        SafeParams = (ConvertTo-EcfSafeParams -Params $Params)
        Events = (New-Object System.Collections.Generic.List[object])
        Artifacts = (New-Object System.Collections.Generic.List[object])
        Errors = (New-Object System.Collections.Generic.List[object])
        Warnings = (New-Object System.Collections.Generic.List[object])
        OpenPhases = (New-Object System.Collections.Generic.List[string])
        RunStarted = $false
        RunEnded = $false
    }
}

<#
.SYNOPSIS
    The single event emitter. Normalizes the event (schemaVersion / type
    / runId / utc always present), appends it to the context's ordered
    list (the source of truth used to assemble the manifest), and — when
    the context has EmitEvents — writes one compact JSON line to stdout
    (NDJSON). Engine modules never call this; only the orchestration
    layer narrates.
#>
function Write-EcfEvent {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Type,
        [hashtable]$Data
    )

    $evt = [ordered]@{
        schemaVersion = $script:EcfSchemaVersion
        type = $Type
        runId = $Context.RunId
        utc = Get-EcfUtc
    }
    if ($Data) {
        foreach ($k in $Data.Keys) {
            # schemaVersion/type/runId/utc are reserved and never overwritten.
            if ($k -in @('schemaVersion', 'type', 'runId', 'utc')) { continue }
            $evt[$k] = $Data[$k]
        }
    }

    $obj = [pscustomobject]$evt
    $Context.Events.Add($obj) | Out-Null

    if ($Context.EmitEvents) {
        $line = $obj | ConvertTo-Json -Depth 12 -Compress
        # Real stdout (not the PS pipeline) so the function stays
        # side-effect-only and a sidecar reads clean NDJSON.
        [Console]::Out.WriteLine($line)
    }
}

<#
.SYNOPSIS
    Emits run.started (must be the first event). Idempotent-guarded.
#>
function Start-EcfRun {
    [CmdletBinding()]
    [OutputType([void])]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    if ($Context.RunStarted) { return }
    $Context.RunStarted = $true
    Write-EcfEvent -Context $Context -Type 'run.started' -Data @{
        params = $Context.SafeParams
    }
}

function Assert-EcfPhase {
    param([string]$Phase)
    if ($Phase -notin $script:EcfPhases) {
        throw "Unknown phase '$Phase'. Legal phases: $($script:EcfPhases -join ', ')."
    }
}

<#
.SYNOPSIS
    Emits phase.started for a canonical phase.
#>
function Start-EcfPhase {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Phase
    )
    Assert-EcfPhase -Phase $Phase
    $Context.OpenPhases.Add($Phase) | Out-Null
    Write-EcfEvent -Context $Context -Type 'phase.started' -Data @{ phase = $Phase }
}

<#
.SYNOPSIS
    Emits phase.progress (only legal between a phase's start and complete).
#>
function Write-EcfProgress {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Phase,
        [int]$Current = 0,
        [int]$Total = 0,
        [string]$Message = ''
    )
    Assert-EcfPhase -Phase $Phase
    Write-EcfEvent -Context $Context -Type 'phase.progress' -Data @{
        phase = $Phase
        current = $Current
        total = $Total
        message = $Message
    }
}

<#
.SYNOPSIS
    Emits phase.completed with status ok|skipped|failed and pops the
    open-phase tracker.
#>
function Complete-EcfPhase {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Phase,
        [ValidateSet('ok', 'skipped', 'failed')][string]$Status = 'ok'
    )
    Assert-EcfPhase -Phase $Phase
    if ($Context.OpenPhases.Contains($Phase)) {
        $Context.OpenPhases.Remove($Phase) | Out-Null
    }
    Write-EcfEvent -Context $Context -Type 'phase.completed' -Data @{
        phase = $Phase
        status = $Status
    }
}

<#
.SYNOPSIS
    Narration replacement for orchestration Write-Host. level ∈ info|warn|error.
#>
function Write-EcfLog {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('info', 'warn', 'error')][string]$Level = 'info'
    )
    Write-EcfEvent -Context $Context -Type 'log' -Data @{
        level = $Level
        message = $Message
    }
}

<#
.SYNOPSIS
    Records a non-fatal warning (also surfaced in the manifest).
#>
function Write-EcfWarning {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Message,
        [string]$Code = 'warning'
    )
    $Context.Warnings.Add([pscustomobject]@{ code = $Code; message = $Message }) | Out-Null
    Write-EcfEvent -Context $Context -Type 'warning' -Data @{
        code = $Code
        message = $Message
    }
}

<#
.SYNOPSIS
    Records a structured error (also surfaced in the manifest). Fatal
    errors drive the terminal status to Failed.
#>
function Write-EcfError {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Message,
        [string]$Code = 'error',
        [switch]$Fatal
    )
    $Context.Errors.Add([pscustomobject]@{
            code = $Code
            message = $Message
            fatal = [bool]$Fatal
        }) | Out-Null
    Write-EcfEvent -Context $Context -Type 'log' -Data @{
        level = 'error'
        message = $Message
        code = $Code
        fatal = [bool]$Fatal
    }
}

<#
.SYNOPSIS
    Coarse auth narration (Phase 1). Device-code-as-events is Phase 3.
#>
function Write-EcfAuthInfo {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [string]$Method = '',
        [string]$Message = ''
    )
    Write-EcfEvent -Context $Context -Type 'auth.info' -Data @{
        method = $Method
        message = $Message
    }
}

<#
.SYNOPSIS
    Records a produced report artifact for the manifest's artifacts[].
    Path is resolved to absolute so GUI run-history can open it blind.
#>
function Add-EcfArtifact {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidateSet('cockpit-html', 'legacy-html', 'csv', 'json', 'excel', 'soc2-html', 'soc2-workbook', 'privileged-roster', 'snapshot', 'delta')]
        [string]$Kind,
        [Parameter(Mandatory)][string]$Path
    )
    $abs = $Path
    try {
        $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        $abs = $resolved.Path
    }
    catch {
        # Not yet on disk / glob — keep as given; still recorded.
        $abs = $Path
    }
    $Context.Artifacts.Add([pscustomobject]@{
            kind = $Kind
            path = $abs
            utc = Get-EcfUtc
        }) | Out-Null
}

<#
.SYNOPSIS
    Derives the terminal run status (§5 table).
      Failed             — a fatal error and no artifact produced.
      PartiallySucceeded — ≥1 artifact but ≥1 phase/module failed.
      Succeeded          — all requested phases ok.
      Cancelled          — reserved (not reachable in Phase 1).
#>
function Get-EcfRunStatus {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $hasFatal = @($Context.Errors | Where-Object { $_.fatal }).Count -gt 0
    $hasArtifact = $Context.Artifacts.Count -gt 0
    $hasFailedPhase = @($Context.Events | Where-Object {
            $_.type -eq 'phase.completed' -and $_.status -eq 'failed'
        }).Count -gt 0
    $hasAnyError = $Context.Errors.Count -gt 0

    if ($hasFatal -and -not $hasArtifact) { return 'Failed' }
    if (-not $hasArtifact -and $hasAnyError) { return 'Failed' }
    if ($hasArtifact -and ($hasFailedPhase -or $hasAnyError)) { return 'PartiallySucceeded' }
    return 'Succeeded'
}

<#
.SYNOPSIS
    Assembles the run.result manifest (§5). Pure over the context.
#>
function New-EcfRunManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [hashtable]$Summary
    )

    $sum = [ordered]@{
        findings = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        modulesRun = @()
        soc2 = [ordered]@{ ran = $false; verdict = $null }
    }
    if ($Summary) {
        foreach ($k in @('findings', 'critical', 'high', 'medium', 'low', 'modulesRun')) {
            if ($Summary.ContainsKey($k)) { $sum[$k] = $Summary[$k] }
        }
        if ($Summary.ContainsKey('soc2') -and $Summary['soc2']) {
            $s = $Summary['soc2']
            if ($s -is [hashtable]) {
                if ($s.ContainsKey('ran')) { $sum['soc2']['ran'] = [bool]$s['ran'] }
                if ($s.ContainsKey('verdict')) { $sum['soc2']['verdict'] = $s['verdict'] }
            }
        }
    }

    $status = Get-EcfRunStatus -Context $Context
    if (-not $Context.EndedUtc) { $Context.EndedUtc = Get-EcfUtc }

    return [pscustomobject]([ordered]@{
            schemaVersion = $script:EcfSchemaVersion
            type = 'run.result'
            runId = $Context.RunId
            status = $status
            startedUtc = $Context.StartedUtc
            endedUtc = $Context.EndedUtc
            params = $Context.SafeParams
            summary = $sum
            artifacts = @($Context.Artifacts.ToArray())
            errors = @($Context.Errors.ToArray())
            warnings = @($Context.Warnings.ToArray())
        })
}

<#
.SYNOPSIS
    Writes the manifest to <OutputDirectory>/.runs/<runId>.json (run
    history) and returns the file path.
#>
function Write-EcfRunHistory {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][pscustomobject]$Manifest,
        [string]$OutputDirectory
    )
    $dir = $OutputDirectory
    if (-not $dir) { $dir = $Context.OutputDirectory }
    if (-not $dir) { $dir = '.' }
    $runsDir = Join-Path $dir '.runs'
    if (-not (Test-Path -LiteralPath $runsDir)) {
        $null = New-Item -Path $runsDir -ItemType Directory -Force
    }
    $path = Join-Path $runsDir ("{0}.json" -f $Context.RunId)
    $Manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

<#
.SYNOPSIS
    Closes the run: assembles the manifest, emits run.result as the
    final event, writes run history, returns the manifest. Idempotent.
#>
function Complete-EcfRun {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [hashtable]$Summary
    )
    if ($Context.RunEnded) {
        return ($Context.Events | Where-Object { $_.type -eq 'run.result' } | Select-Object -Last 1)
    }
    $Context.RunEnded = $true
    $Context.EndedUtc = Get-EcfUtc

    $manifest = New-EcfRunManifest -Context $Context -Summary $Summary

    # Emit run.result as the final NDJSON line (mirror of the manifest).
    Write-EcfEvent -Context $Context -Type 'run.result' -Data @{
        status = $manifest.status
        startedUtc = $manifest.startedUtc
        endedUtc = $manifest.endedUtc
        params = $manifest.params
        summary = $manifest.summary
        artifacts = $manifest.artifacts
        errors = $manifest.errors
        warnings = $manifest.warnings
    }

    $historyPath = Write-EcfRunHistory -Context $Context -Manifest $manifest -OutputDirectory $Context.OutputDirectory
    Add-Member -InputObject $manifest -MemberType NoteProperty -Name 'historyPath' -Value $historyPath -Force
    return $manifest
}

#endregion

Export-ModuleMember -Function @(
    'Get-EcfUtc',
    'ConvertTo-EcfSafeParams',
    'New-EcfRunContext',
    'Write-EcfEvent',
    'Start-EcfRun',
    'Start-EcfPhase',
    'Write-EcfProgress',
    'Complete-EcfPhase',
    'Write-EcfLog',
    'Write-EcfWarning',
    'Write-EcfError',
    'Write-EcfAuthInfo',
    'Add-EcfArtifact',
    'Get-EcfRunStatus',
    'New-EcfRunManifest',
    'Write-EcfRunHistory',
    'Complete-EcfRun'
)
