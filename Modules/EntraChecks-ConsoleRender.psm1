<#
.SYNOPSIS
    EntraChecks-ConsoleRender.psm1 — the console renderer for the
    headless-runner event stream. Native App Plan, Phase 2 (2b).

.DESCRIPTION
    Show-EcfRunStream maps one v1.0 runner event object (see
    EntraChecks-Runner.psm1 / Native-App-Phase1 §4) to the existing
    EntraChecks console vocabulary, so a user watching the re-platformed
    interactive menu sees what they saw before the runner refactor.

    This is the single place TUI run-progress formatting lives — the
    runner stays strictly UI-free; it only emits structured events. The
    menu wires this as the runner context's in-process -EventSink:

        $sink = { param($e) Show-EcfRunStream -Event $e }
        New-EcfRunContext ... -EventSink $sink

    Stateless per call (the sink delivers one event at a time); the
    run.result completion block derives duration from the event's own
    startedUtc/endedUtc, so no cross-call state is needed.

    5.1-safe (no PS7-only syntax): the TUI imports this in-process on
    whatever runtime the user launched. No dependency on the runner
    module — it only consumes the documented event shape.

.NOTES
    Version: 1.0.0
    Author: EntraChecks Project
.LINK
    plans/Native-App-Phase2-TUI-Replatform-Plan.md (§4)
#>

#Requires -Version 5.1

$script:ModuleName = 'EntraChecks-ConsoleRender'
$script:ModuleVersion = '1.0.0'

function script:Get-EcfDurationText {
    param([string]$StartUtc, [string]$EndUtc)
    $s = [datetime]::MinValue; $e = [datetime]::MinValue
    $okS = [datetime]::TryParse($StartUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$s)
    $okE = [datetime]::TryParse($EndUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$e)
    if (-not ($okS -and $okE)) { return 'n/a' }
    $mins = ($e - $s).TotalMinutes
    if ($mins -lt 0) { $mins = 0 }
    return ('{0:0.0} minutes' -f $mins)
}

<#
.SYNOPSIS
    Render a single runner event to the console (the §4 mapping).

.PARAMETER Event
    One v1.0 event object from the runner's event stream / -EventSink.

.OUTPUTS
    None. Writes to the host (Write-Host) only — pure presentation.
#>
function Show-EcfRunStream {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [pscustomobject]$Event
    )

    process {
        if ($null -eq $Event) { return }
        $type = [string]$Event.type

        switch ($type) {
            'run.started' {
                Write-Host ''
                Write-Host '[+] Starting assessment' -ForegroundColor Magenta
            }

            'phase.started' {
                Write-Host ("[+] {0}" -f [string]$Event.phase) -ForegroundColor Cyan
            }

            'phase.progress' {
                $cur = if ($Event.PSObject.Properties['current']) { [int]$Event.current } else { 0 }
                $tot = if ($Event.PSObject.Properties['total']) { [int]$Event.total } else { 0 }
                $msg = if ($Event.PSObject.Properties['message']) { [string]$Event.message } else { '' }
                $counter = if ($tot -gt 0) { " [$cur/$tot]" } else { '' }
                Write-Host ("   ->{0} {1}" -f $counter, $msg) -ForegroundColor Gray
            }

            'log' {
                $lvl = if ($Event.PSObject.Properties['level']) { [string]$Event.level } else { 'info' }
                $msg = if ($Event.PSObject.Properties['message']) { [string]$Event.message } else { '' }
                switch ($lvl) {
                    'error' { Write-Host ("    [!] {0}" -f $msg) -ForegroundColor Red }
                    'warn' { Write-Host ("    [!] {0}" -f $msg) -ForegroundColor Yellow }
                    default { Write-Host ("    [i] {0}" -f $msg) -ForegroundColor Gray }
                }
            }

            'warning' {
                $msg = if ($Event.PSObject.Properties['message']) { [string]$Event.message } else { '' }
                Write-Host ("    [!] {0}" -f $msg) -ForegroundColor Yellow
            }

            'auth.info' {
                $msg = if ($Event.PSObject.Properties['message']) { [string]$Event.message } else { '' }
                $method = if ($Event.PSObject.Properties['method']) { [string]$Event.method } else { '' }
                $text = if ($method) { "$method - $msg" } else { $msg }
                Write-Host ("    [i] {0}" -f $text) -ForegroundColor Gray
            }

            'phase.completed' {
                $status = if ($Event.PSObject.Properties['status']) { [string]$Event.status } else { 'ok' }
                $phase = [string]$Event.phase
                switch ($status) {
                    'failed' { Write-Host ("    [!] {0} failed" -f $phase) -ForegroundColor Red }
                    'skipped' { Write-Host ("    [skip] {0}" -f $phase) -ForegroundColor DarkGray }
                    default { Write-Host ("    [OK] {0}" -f $phase) -ForegroundColor Green }
                }
            }

            'run.cancelled' {
                $reason = if ($Event.PSObject.Properties['reason']) { [string]$Event.reason } else { 'cancel requested' }
                Write-Host ''
                Write-Host ("[!] Cancelling - {0} (finishing the current step)" -f $reason) -ForegroundColor Yellow
            }

            'run.result' {
                $status = if ($Event.PSObject.Properties['status']) { [string]$Event.status } else { '' }
                $startU = if ($Event.PSObject.Properties['startedUtc']) { [string]$Event.startedUtc } else { '' }
                $endU = if ($Event.PSObject.Properties['endedUtc']) { [string]$Event.endedUtc } else { '' }
                $dur = Get-EcfDurationText -StartUtc $startU -EndUtc $endU

                $color = switch ($status) {
                    'Succeeded' { 'Green' }
                    'PartiallySucceeded' { 'Yellow' }
                    'Failed' { 'Red' }
                    'Cancelled' { 'DarkGray' }
                    default { 'Green' }
                }
                Write-Host ''
                Write-Host ("[+] Assessment Complete - {0}" -f $status) -ForegroundColor $color
                Write-Host ("    Duration: {0}" -f $dur) -ForegroundColor Cyan
                if ($Event.PSObject.Properties['artifacts'] -and $Event.artifacts) {
                    foreach ($a in @($Event.artifacts)) {
                        Write-Host ("    Report ({0}): {1}" -f [string]$a.kind, [string]$a.path) -ForegroundColor Cyan
                    }
                }
                if ($Event.PSObject.Properties['errors'] -and $Event.errors) {
                    foreach ($er in @($Event.errors)) {
                        Write-Host ("    [!] {0}: {1}" -f [string]$er.code, [string]$er.message) -ForegroundColor Red
                    }
                }
            }

            default {
                # Unknown/future event type — forward-compat: ignore quietly
                # (the parent plan §5 forward-compat clause).
            }
        }
    }
}

Export-ModuleMember -Function @('Show-EcfRunStream')
