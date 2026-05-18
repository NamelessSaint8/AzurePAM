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
        [switch]$EmitEvents,
        # Native App Plan, Phase 2 (2a). Optional in-process consumer.
        # When supplied, every emitted event object is also handed to
        # this scriptblock (same object as the in-memory list / NDJSON —
        # no serialization round-trip), so an in-process renderer (the
        # re-platformed TUI's Show-EcfRunStream) can react live without
        # parsing the runner's own stdout. Additive: the contract /
        # schema is unchanged; the sink only observes.
        [scriptblock]$EventSink,
        # Native App Plan, Phase 3 (3a). Optional in-process cancel
        # signal. The runner cancels if EITHER this ref is truthy OR the
        # filesystem sentinel <OutputDirectory>/.runs/<runId>.cancel
        # exists. The ref gives the in-process TUI zero-latency cancel;
        # the sentinel gives the Phase 4 Tauri sidecar a process-boundary
        # cancel. Cooperative + coarse (polled at phase boundaries).
        [AllowNull()]
        [ref]$CancelFlag
    )

    if (-not $RunId) { $RunId = [guid]::NewGuid().ToString() }

    return [pscustomobject]@{
        RunId = $RunId
        SchemaVersion = $script:EcfSchemaVersion
        StartedUtc = Get-EcfUtc
        EndedUtc = ''
        OutputDirectory = $OutputDirectory
        EmitEvents = [bool]$EmitEvents
        EventSink = $EventSink
        CancelFlag = $CancelFlag
        Cancelled = $false
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

    # In-process sink (Phase 2): hand the same object to a live consumer.
    # A presentation/renderer fault must never break the assessment, so
    # sink failures are swallowed (the event is still in the list + NDJSON).
    if ($Context.PSObject.Properties['EventSink'] -and $Context.EventSink) {
        try { & $Context.EventSink $obj }
        catch { Write-Verbose "EventSink threw (ignored): $_" }
    }

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
    # Clear any stale sentinel from a prior run so it can't cancel this
    # one (Phase 3a stale-sentinel guard).
    Clear-EcfCancelSentinel -Context $Context
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

# Phase 3b — the fixed error-code vocabulary. Each entry pins a default
# fatality and a human remediation hint a UI can show instead of raw
# exception text. Additive within v1 (the manifest errors[] gains a
# `remediation` field; the code set is documented + total — unknown
# codes degrade to `internal`, never throw).
$script:EcfErrorCatalog = [ordered]@{
    'auth.failed' = @{ Fatal = $true; Remediation = 'Authentication to Microsoft Graph/Azure failed. Re-run and sign in, or use -SkipAuthentication with a pre-authenticated session.' }
    'auth.cancelled' = @{ Fatal = $true; Remediation = 'Sign-in was cancelled or timed out. Re-run and complete the device-code / browser prompt.' }
    'auth.insufficientPrivileges' = @{ Fatal = $true; Remediation = 'The signed-in identity lacks the required read scopes. Sign in as Global Reader (or consent the requested scopes) and re-run.' }
    'prereq.moduleMissing' = @{ Fatal = $true; Remediation = 'A required PowerShell module is not installed. Install the Microsoft.Graph / Az modules (see Install-Prerequisites.ps1) and re-run.' }
    'prereq.azContextMissing' = @{ Fatal = $false; Remediation = 'No Azure context. Run Connect-AzAccount before the assessment to include the Azure-side checks; the Graph-only checks still ran.' }
    'engine.moduleFailed' = @{ Fatal = $false; Remediation = 'An assessment module failed. The run continued; review the module error and re-run that module to fill the gap.' }
    'report.writeFailed' = @{ Fatal = $true; Remediation = 'Writing the report output failed. Check the output directory exists and is writable, then re-run.' }
    'snapshot.failed' = @{ Fatal = $false; Remediation = 'Saving / comparing the compliance snapshot failed. The assessment itself completed; retry the snapshot step.' }
    'snapshot.insufficient' = @{ Fatal = $false; Remediation = 'At least two snapshots are required to compare. Save a snapshot now and compare on a later run.' }
    'cancelled' = @{ Fatal = $false; Remediation = 'The run was cancelled by request. Re-run to produce a complete assessment.' }
    'internal' = @{ Fatal = $false; Remediation = 'An unexpected error occurred. Re-run with -Verbose and report the message if it persists.' }
}

<#
.SYNOPSIS
    Pure, total mapper: a code → its catalogued { Code; Fatal;
    Remediation }. An unknown/unmapped code degrades to the `internal`
    entry (keeping the caller's code so it is still visible) and never
    throws. Used by Write-EcfError to auto-fill and by tests/consumers.
#>
function Get-EcfErrorInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Code)

    if ($script:EcfErrorCatalog.Contains($Code)) {
        $e = $script:EcfErrorCatalog[$Code]
        return [pscustomobject]@{ Code = $Code; Fatal = [bool]$e.Fatal; Remediation = [string]$e.Remediation }
    }
    $gen = $script:EcfErrorCatalog['internal']
    return [pscustomobject]@{ Code = $Code; Fatal = [bool]$gen.Fatal; Remediation = [string]$gen.Remediation }
}

<#
.SYNOPSIS
    Records a structured error (also surfaced in the manifest). Fatal
    errors drive the terminal status to Failed.

    Phase 3b: -Code is matched against the fixed vocabulary
    ($script:EcfErrorCatalog). When -Remediation is omitted it is
    auto-filled from the catalog; when -Fatal is not explicitly passed
    the catalog's default fatality applies (an unknown code → the
    `internal` defaults: non-fatal, generic hint — so pre-3b callers
    that passed an ad-hoc code without -Fatal keep their old non-fatal
    behaviour, now with a remediation string added).
#>
function Write-EcfError {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Message,
        [string]$Code = 'error',
        [string]$Remediation,
        [switch]$Fatal
    )
    $info = Get-EcfErrorInfo -Code $Code
    $isFatal = if ($PSBoundParameters.ContainsKey('Fatal')) { [bool]$Fatal } else { [bool]$info.Fatal }
    $remed = if ($PSBoundParameters.ContainsKey('Remediation')) { [string]$Remediation } else { [string]$info.Remediation }

    $Context.Errors.Add([pscustomobject]@{
            code = $Code
            message = $Message
            fatal = $isFatal
            remediation = $remed
        }) | Out-Null
    Write-EcfEvent -Context $Context -Type 'log' -Data @{
        level = 'error'
        message = $Message
        code = $Code
        fatal = $isFatal
        remediation = $remed
    }
}

<#
.SYNOPSIS
    Coarse auth narration (Phase 1). Still used for app-only / managed
    identity / "already connected" (no interactive prompt to surface).
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

# ---- Phase 3c: auth-as-events ---------------------------------------
# The Auth step runs inside an observed `Auth` phase; these surface the
# flow so a GUI/TUI renders it instead of relying on the Graph SDK's
# console output. Additive within v1 (new event types; the device-code
# event intentionally carries a nullable userCode + a `capture` field
# so a future real-code path is additive — see Phase 3 plan §5 / the
# 3c-spike decision).

<#
.SYNOPSIS
    Interactive-browser sign-in is starting (the system browser opens).
#>
function Write-EcfAuthBrowser {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [string]$Message = 'Opening the system browser to sign in...'
    )
    Write-EcfEvent -Context $Context -Type 'auth.browser' -Data @{ message = $Message }
}

<#
.SYNOPSIS
    Device-code sign-in is starting. Per the 3c-spike, the Graph SDK
    owns the code value, so by default userCode is $null and
    capture='sdk-console' (the code is on the sidecar's stdout /
    console). A future DeviceCodeCredential path can pass a real
    -UserCode without a contract break.
#>
function Write-EcfAuthDeviceCode {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [AllowNull()][string]$UserCode = $null,
        [string]$VerificationUri = 'https://microsoft.com/devicelogin',
        [ValidateSet('sdk-console', 'captured')][string]$Capture = 'sdk-console'
    )
    Write-EcfEvent -Context $Context -Type 'auth.devicecode' -Data @{
        userCode = $UserCode
        verificationUri = $VerificationUri
        capture = $Capture
    }
}

<#
.SYNOPSIS
    Sign-in succeeded.
#>
function Write-EcfAuthSucceeded {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [string]$Account = '',
        [string]$Method = ''
    )
    Write-EcfEvent -Context $Context -Type 'auth.succeeded' -Data @{
        account = $Account
        method = $Method
    }
}

<#
.SYNOPSIS
    Sign-in failed. Records a taxonomy'd error (this is where the 3b
    auth.* codes are wired now that auth is inside the observed run)
    AND emits the auth.failed event for live renderers. -Code defaults
    to auth.failed; pass auth.cancelled / auth.insufficientPrivileges
    when the cause is known.
#>
function Write-EcfAuthFailed {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('auth.failed', 'auth.cancelled', 'auth.insufficientPrivileges')]
        [string]$Code = 'auth.failed'
    )
    $info = Get-EcfErrorInfo -Code $Code
    Write-EcfError -Context $Context -Code $Code -Message $Message
    Write-EcfEvent -Context $Context -Type 'auth.failed' -Data @{
        code = $Code
        message = $Message
        remediation = $info.Remediation
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
    Path of this run's filesystem cancel sentinel:
    <OutputDirectory>/.runs/<runId>.cancel  (mirrors the run-history
    location so a sidecar that knows the run dir can cancel it).
#>
function Get-EcfCancelSentinelPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    $dir = $Context.OutputDirectory
    if (-not $dir) { $dir = '.' }
    return (Join-Path (Join-Path $dir '.runs') ("{0}.cancel" -f $Context.RunId))
}

<#
.SYNOPSIS
    Removes this run's cancel sentinel if present. Called at run start
    (so a stale sentinel from a prior run can't cancel this one) and at
    run completion (cleanup). Best-effort; never throws.
#>
function Clear-EcfCancelSentinel {
    [CmdletBinding()]
    [OutputType([void])]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    $p = Get-EcfCancelSentinelPath -Context $Context
    if (Test-Path -LiteralPath $p) {
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    }
}

<#
.SYNOPSIS
    Pure predicate — $true if cancellation has been requested: the run
    is already marked cancelled, OR the in-process -CancelFlag ref is
    truthy, OR the filesystem sentinel exists. No side effects (the
    sequence polls this at every phase boundary).
#>
function Test-EcfCancelled {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    if ($Context.PSObject.Properties['Cancelled'] -and $Context.Cancelled) { return $true }
    if ($Context.PSObject.Properties['CancelFlag'] -and $Context.CancelFlag) {
        try { if ($Context.CancelFlag.Value) { return $true } }
        catch { Write-Verbose "CancelFlag deref failed (ignored): $_" }
    }
    return (Test-Path -LiteralPath (Get-EcfCancelSentinelPath -Context $Context))
}

<#
.SYNOPSIS
    Marks the run cancelled and emits run.cancelled exactly once. The
    sequence calls this when a checkpoint observes cancellation; the
    terminal status then derives to Cancelled (highest precedence).
#>
function Set-EcfCancelled {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [string]$Reason = 'cancel requested'
    )
    if ($Context.Cancelled) { return }
    $Context.Cancelled = $true
    Write-EcfEvent -Context $Context -Type 'run.cancelled' -Data @{ reason = $Reason }
}

<#
.SYNOPSIS
    Derives the terminal run status (§5 table).
      Cancelled          — a cancel signal was honoured (Phase 3a).
                           Highest precedence: a cancelled run reports
                           Cancelled even if a fatal error also occurred,
                           and even though partial artifacts are retained.
      Failed             — a fatal error and no artifact produced.
      PartiallySucceeded — ≥1 artifact but ≥1 phase/module failed.
      Succeeded          — all requested phases ok.
#>
function Get-EcfRunStatus {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    if ($Context.PSObject.Properties['Cancelled'] -and $Context.Cancelled) {
        return 'Cancelled'
    }

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

    # Cleanup: a consumed sentinel must not linger to cancel a later run
    # that happens to reuse the run dir (Phase 3a).
    Clear-EcfCancelSentinel -Context $Context
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
    'Get-EcfErrorInfo',
    'Write-EcfAuthInfo',
    'Write-EcfAuthBrowser',
    'Write-EcfAuthDeviceCode',
    'Write-EcfAuthSucceeded',
    'Write-EcfAuthFailed',
    'Add-EcfArtifact',
    'Get-EcfRunStatus',
    'New-EcfRunManifest',
    'Write-EcfRunHistory',
    'Complete-EcfRun',
    # Phase 3a — cancellation primitives.
    'Get-EcfCancelSentinelPath',
    'Clear-EcfCancelSentinel',
    'Test-EcfCancelled',
    'Set-EcfCancelled'
)
