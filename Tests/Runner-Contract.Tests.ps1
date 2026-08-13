<#
.SYNOPSIS
    Pester 5 tests for the headless-runner contract
    (plans/Native-App-Phase1-Headless-Core-Plan.md §4/§5/§8).

.DESCRIPTION
    The NDJSON event stream and the run-result manifest are the public
    API every UI + automation depends on. They are frozen at v1.0 and
    tested here as data:

      1. Schema shape — every event carries schemaVersion/type/runId/utc.
      2. Ordering invariants — run.started first, run.result last,
         balanced phase.started/phase.completed, progress only in-phase.
      3. Manifest correctness — the §5 status-derivation table.
      4. No-Read-Host guard — the runner module is non-interactive.
      5. Sanitization — params echo is allowlisted; no secret leakage.
      6. NDJSON emission — -EmitEvents writes one compact JSON line per
         event to stdout; run history equals the final manifest.

    Driver/parity tests (Invoke-EntraChecksRun end-to-end vs. the legacy
    -Mode Quick path) are added with the driver in the same phase.

    Run: Invoke-Pester -Path Tests/Runner-Contract.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    if (-not $env:TEMP) {
        $env:TEMP = if ($env:TMPDIR) { $env:TMPDIR.TrimEnd('/') } else { '/tmp' }
    }
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $script:RunnerModulePath = Join-Path $repoRoot 'Modules/EntraChecks-Runner.psm1'
    Import-Module $script:RunnerModulePath -Force

    function script:New-FullRun {
        param([hashtable]$Params, [string]$OutDir, [switch]$EmitEvents)
        $ctx = New-EcfRunContext -RunId 'test-run' -Params $Params -OutputDirectory $OutDir -EmitEvents:$EmitEvents
        Start-EcfRun -Context $ctx
        Start-EcfPhase -Context $ctx -Phase 'Prereqs'
        Complete-EcfPhase -Context $ctx -Phase 'Prereqs' -Status ok
        Start-EcfPhase -Context $ctx -Phase 'Core'
        Write-EcfProgress -Context $ctx -Phase 'Core' -Current 1 -Total 25 -Message 'Conditional Access'
        Write-EcfLog -Context $ctx -Message 'narration' -Level info
        Complete-EcfPhase -Context $ctx -Phase 'Core' -Status ok
        return $ctx
    }
}

Describe 'Schema shape — every event' {

    BeforeAll {
        $script:Ctx = New-FullRun -Params @{ TenantName = 'Contoso' } -OutDir $env:TEMP
        $null = Complete-EcfRun -Context $script:Ctx -Summary @{ findings = 0 }
    }

    It 'every event carries schemaVersion=1.0, type, runId, utc' {
        foreach ($e in $script:Ctx.Events) {
            $e.schemaVersion | Should -BeExactly '1.0'
            [string]$e.type | Should -Not -BeNullOrEmpty
            $e.runId | Should -BeExactly 'test-run'
            ([string]$e.utc) | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        }
    }

    It 'only emits known v1.x event types' {
        # Additive within v1: run.cancelled (3a); auth.browser /
        # auth.devicecode / auth.succeeded / auth.failed (3c).
        $known = @('run.started', 'phase.started', 'phase.progress', 'phase.completed',
            'log', 'warning', 'auth.info', 'auth.browser', 'auth.devicecode',
            'auth.succeeded', 'auth.failed', 'run.cancelled', 'run.result')
        foreach ($e in $script:Ctx.Events) { $known | Should -Contain $e.type }
    }

    It 'reserved keys cannot be overwritten by event data' {
        $ctx = New-EcfRunContext -RunId 'x' -Params @{}
        Write-EcfEvent -Context $ctx -Type 'log' -Data @{ runId = 'HIJACK'; schemaVersion = '9.9'; message = 'm' }
        $ctx.Events[0].runId | Should -BeExactly 'x'
        $ctx.Events[0].schemaVersion | Should -BeExactly '1.0'
        $ctx.Events[0].message | Should -BeExactly 'm'
    }
}

Describe 'Ordering invariants' {

    BeforeAll {
        $script:Ctx = New-FullRun -Params @{ TenantName = 'Contoso' } -OutDir $env:TEMP
        $null = Complete-EcfRun -Context $script:Ctx -Summary @{ findings = 0 }
        $script:Types = @($script:Ctx.Events | ForEach-Object { $_.type })
    }

    It 'run.started is the first event' { $script:Types[0] | Should -BeExactly 'run.started' }
    It 'run.result is the last event' { $script:Types[-1] | Should -BeExactly 'run.result' }
    It 'exactly one run.started and one run.result' {
        @($script:Types | Where-Object { $_ -eq 'run.started' }).Count | Should -Be 1
        @($script:Types | Where-Object { $_ -eq 'run.result' }).Count | Should -Be 1
    }

    It 'phase.started / phase.completed are balanced per phase' {
        $started = $script:Ctx.Events | Where-Object { $_.type -eq 'phase.started' } | ForEach-Object { $_.phase }
        $completed = $script:Ctx.Events | Where-Object { $_.type -eq 'phase.completed' } | ForEach-Object { $_.phase }
        ($started | Sort-Object) | Should -Be ($completed | Sort-Object)
    }

    It 'phase.progress only appears inside an open phase' {
        $depth = 0
        foreach ($e in $script:Ctx.Events) {
            switch ($e.type) {
                'phase.started' { $depth++ }
                'phase.completed' { $depth-- }
                'phase.progress' { $depth | Should -BeGreaterThan 0 }
            }
        }
    }

    It 'Start-EcfRun is idempotent (no duplicate run.started)' {
        $ctx = New-EcfRunContext -RunId 'y' -Params @{}
        Start-EcfRun -Context $ctx
        Start-EcfRun -Context $ctx
        @($ctx.Events | Where-Object { $_.type -eq 'run.started' }).Count | Should -Be 1
    }

    It 'unknown phase names are rejected' {
        $ctx = New-EcfRunContext -RunId 'z' -Params @{}
        { Start-EcfPhase -Context $ctx -Phase 'Bogus' } | Should -Throw -ExpectedMessage '*Unknown phase*'
    }
}

Describe 'Manifest — §5 status derivation' {

    It 'all phases ok + an artifact = Succeeded' {
        $ctx = New-FullRun -Params @{} -OutDir $env:TEMP
        Add-EcfArtifact -Context $ctx -Kind 'cockpit-html' -Path $env:TEMP
        (New-EcfRunManifest -Context $ctx).status | Should -BeExactly 'Succeeded'
    }

    It 'artifact present but a phase failed = PartiallySucceeded' {
        $ctx = New-EcfRunContext -RunId 'p' -Params @{} -OutputDirectory $env:TEMP
        Start-EcfRun -Context $ctx
        Start-EcfPhase -Context $ctx -Phase 'Modules'
        Complete-EcfPhase -Context $ctx -Phase 'Modules' -Status failed
        Add-EcfArtifact -Context $ctx -Kind 'csv' -Path $env:TEMP
        (New-EcfRunManifest -Context $ctx).status | Should -BeExactly 'PartiallySucceeded'
    }

    It 'fatal error and no artifact = Failed' {
        $ctx = New-EcfRunContext -RunId 'f' -Params @{} -OutputDirectory $env:TEMP
        Start-EcfRun -Context $ctx
        Write-EcfError -Context $ctx -Message 'boom' -Code 'E1' -Fatal
        (New-EcfRunManifest -Context $ctx).status | Should -BeExactly 'Failed'
    }

    It 'non-fatal error with an artifact = PartiallySucceeded' {
        $ctx = New-EcfRunContext -RunId 'n' -Params @{} -OutputDirectory $env:TEMP
        Start-EcfRun -Context $ctx
        Write-EcfError -Context $ctx -Message 'soft' -Code 'E2'
        Add-EcfArtifact -Context $ctx -Kind 'json' -Path $env:TEMP
        (New-EcfRunManifest -Context $ctx).status | Should -BeExactly 'PartiallySucceeded'
    }

    It 'manifest carries summary, artifacts, errors, warnings, sanitized params' {
        $ctx = New-FullRun -Params @{ TenantName = 'Contoso'; SkipAuthentication = $true } -OutDir $env:TEMP
        Write-EcfWarning -Context $ctx -Message 'w' -Code 'W'
        Add-EcfArtifact -Context $ctx -Kind 'cockpit-html' -Path $env:TEMP
        $m = New-EcfRunManifest -Context $ctx -Summary @{ findings = 7; critical = 1; modulesRun = @('Core'); soc2 = @{ ran = $true; verdict = 'AUDIT-READY' } }
        $m.type | Should -BeExactly 'run.result'
        $m.summary.findings | Should -Be 7
        $m.summary.soc2.verdict | Should -BeExactly 'AUDIT-READY'
        @($m.artifacts).Count | Should -Be 1
        @($m.warnings).Count | Should -Be 1
        $m.params.Contains('TenantName') | Should -BeTrue
    }

    It 'artifact paths are resolved absolute' {
        $ctx = New-EcfRunContext -RunId 'abs' -Params @{}
        Add-EcfArtifact -Context $ctx -Kind 'cockpit-html' -Path $env:TEMP
        [System.IO.Path]::IsPathRooted($ctx.Artifacts[0].path) | Should -BeTrue
    }
}

Describe 'Sanitization — §6 allowlist' {

    It 'keeps allowlisted keys and drops everything else' {
        $safe = ConvertTo-EcfSafeParams -Params @{
            TenantName = 'Contoso'; OutputDirectory = 'C:\out'; Modules = @('Core')
            ClientSecret = 'topsecret'; AccessToken = 'eyJ...'; Password = 'p@ss'
        }
        $safe.Contains('TenantName') | Should -BeTrue
        $safe.Contains('OutputDirectory') | Should -BeTrue
        $safe.Contains('Modules') | Should -BeTrue
        $safe.Contains('ClientSecret') | Should -BeFalse
        $safe.Contains('AccessToken') | Should -BeFalse
        $safe.Contains('Password') | Should -BeFalse
    }

    It 'normalizes SwitchParameter to bool' {
        $safe = ConvertTo-EcfSafeParams -Params @{ SkipAuthentication = [switch]$true }
        $safe['SkipAuthentication'] | Should -BeOfType [bool]
        $safe['SkipAuthentication'] | Should -BeTrue
    }

    It 'tolerates null and pscustomobject input' {
        (ConvertTo-EcfSafeParams -Params $null).Count | Should -Be 0
        $safe = ConvertTo-EcfSafeParams -Params ([pscustomobject]@{ TenantName = 'X'; Secret = 'y' })
        $safe.Contains('TenantName') | Should -BeTrue
        $safe.Contains('Secret') | Should -BeFalse
    }
}

Describe 'No-Read-Host guard — runner is non-interactive' {

    It 'EntraChecks-Runner.psm1 contains no Read-Host' {
        $src = Get-Content -LiteralPath $script:RunnerModulePath -Raw
        # Strip block comments so doc prose can't trip the scan, then look
        # for an actual Read-Host invocation.
        $code = [regex]::Replace($src, '<#[\s\S]*?#>', '')
        $code | Should -Not -Match '(?im)(^|[^-\w])Read-Host\b'
    }
}

Describe 'NDJSON emission + run history' {

    BeforeEach {
        $script:Tmp = Join-Path $env:TEMP "rc-ndjson-$((Get-Random))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
    }
    AfterEach {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'with -EmitEvents writes one compact JSON line per event to stdout' {
        $out = Join-Path $script:Tmp 'stream.txt'
        $sb = {
            param($modPath, $dir)
            Import-Module $modPath -Force
            $ctx = New-EcfRunContext -RunId 'emit' -Params @{ TenantName = 'C' } -OutputDirectory $dir -EmitEvents
            Start-EcfRun -Context $ctx
            Start-EcfPhase -Context $ctx -Phase 'Core'
            Complete-EcfPhase -Context $ctx -Phase 'Core' -Status ok
            $null = Complete-EcfRun -Context $ctx -Summary @{ findings = 0 }
        }
        # Run in a child pwsh so [Console]::Out is a clean captured stream.
        & pwsh -NoProfile -Command "& { $($sb.ToString()) } '$script:RunnerModulePath' '$script:Tmp'" > $out
        $lines = @(Get-Content -LiteralPath $out | Where-Object { $_.Trim() })
        $lines.Count | Should -BeGreaterThan 0
        foreach ($l in $lines) {
            $obj = $l | ConvertFrom-Json   # each line must be valid standalone JSON
            $obj.schemaVersion | Should -BeExactly '1.0'
            $l | Should -Not -Match "`n"   # compact: single line
        }
        ($lines[0] | ConvertFrom-Json).type | Should -BeExactly 'run.started'
        ($lines[-1] | ConvertFrom-Json).type | Should -BeExactly 'run.result'
    }

    It 'writes run history to <out>/.runs/<runId>.json equal to the manifest' {
        $ctx = New-EcfRunContext -RunId 'hist1' -Params @{ TenantName = 'C' } -OutputDirectory $script:Tmp
        Start-EcfRun -Context $ctx
        Add-EcfArtifact -Context $ctx -Kind 'cockpit-html' -Path $script:Tmp
        $m = Complete-EcfRun -Context $ctx -Summary @{ findings = 3 }
        $histPath = Join-Path (Join-Path $script:Tmp '.runs') 'hist1.json'
        Test-Path $histPath | Should -BeTrue
        $fromDisk = Get-Content -LiteralPath $histPath -Raw | ConvertFrom-Json
        $fromDisk.runId | Should -BeExactly 'hist1'
        $fromDisk.status | Should -BeExactly $m.status
        $fromDisk.summary.findings | Should -Be 3
    }

    It 'Complete-EcfRun is idempotent' {
        $ctx = New-EcfRunContext -RunId 'idem' -Params @{} -OutputDirectory $script:Tmp
        Start-EcfRun -Context $ctx
        $null = Complete-EcfRun -Context $ctx -Summary @{}
        $null = Complete-EcfRun -Context $ctx -Summary @{}
        @($ctx.Events | Where-Object { $_.type -eq 'run.result' }).Count | Should -Be 1
    }
}

Describe 'In-process EventSink (Phase 2 2a)' {

    It 'receives every emitted event object, in order, same instances' {
        $seen = New-Object System.Collections.Generic.List[object]
        $sink = { param($e) $seen.Add($e) | Out-Null }
        $ctx = New-EcfRunContext -RunId 'sink1' -Params @{ TenantName = 'C' } -EventSink $sink
        Start-EcfRun -Context $ctx
        Start-EcfPhase -Context $ctx -Phase 'Core'
        Complete-EcfPhase -Context $ctx -Phase 'Core' -Status ok
        $null = Complete-EcfRun -Context $ctx -Summary @{ findings = 0 }

        @($seen | ForEach-Object { $_.type }) | Should -Be @($ctx.Events | ForEach-Object { $_.type })
        # Same object instances, not copies.
        [object]::ReferenceEquals($seen[0], $ctx.Events[0]) | Should -BeTrue
        $seen[0].type | Should -BeExactly 'run.started'
        $seen[-1].type | Should -BeExactly 'run.result'
    }

    It 'a throwing sink never breaks the run (event still recorded + manifest valid)' {
        $ctx = New-EcfRunContext -RunId 'sink2' -Params @{} -EventSink { param($e) throw 'renderer boom' }
        { Start-EcfRun -Context $ctx } | Should -Not -Throw
        $m = Complete-EcfRun -Context $ctx -Summary @{}
        $m.status | Should -BeExactly 'Succeeded'
        @($ctx.Events | Where-Object { $_.type -eq 'run.started' }).Count | Should -Be 1
    }

    It 'no sink is the default and changes nothing' {
        $ctx = New-EcfRunContext -RunId 'sink3' -Params @{}
        $ctx.EventSink | Should -BeNullOrEmpty
        Start-EcfRun -Context $ctx
        $ctx.Events[0].type | Should -BeExactly 'run.started'
    }
}

Describe 'Cancellation primitives (Phase 3a)' {

    BeforeEach {
        $script:Tmp = Join-Path $env:TEMP "rc-cancel-$([guid]::NewGuid().ToString('N'))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
    }
    AfterEach {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'sentinel path is <out>/.runs/<runId>.cancel' {
        $ctx = New-EcfRunContext -RunId 'cx1' -Params @{} -OutputDirectory $script:Tmp
        Get-EcfCancelSentinelPath -Context $ctx |
            Should -BeExactly (Join-Path (Join-Path $script:Tmp '.runs') 'cx1.cancel')
    }

    It 'Test-EcfCancelled is false by default and has no side effects' {
        $ctx = New-EcfRunContext -RunId 'cx2' -Params @{} -OutputDirectory $script:Tmp
        Test-EcfCancelled -Context $ctx | Should -BeFalse
        # side-effect-free: must not create the .runs dir or sentinel
        (Test-Path (Join-Path $script:Tmp '.runs')) | Should -BeFalse
    }

    It 'cancels via the in-process ref flag' {
        $flag = $false
        $ref = [ref]$flag
        $ctx = New-EcfRunContext -RunId 'cx3' -Params @{} -OutputDirectory $script:Tmp -CancelFlag $ref
        Test-EcfCancelled -Context $ctx | Should -BeFalse
        $ref.Value = $true
        Test-EcfCancelled -Context $ctx | Should -BeTrue
    }

    It 'cancels via the filesystem sentinel' {
        $ctx = New-EcfRunContext -RunId 'cx4' -Params @{} -OutputDirectory $script:Tmp
        $null = New-Item -Path (Join-Path $script:Tmp '.runs') -ItemType Directory -Force
        Set-Content -LiteralPath (Get-EcfCancelSentinelPath -Context $ctx) -Value '' -Encoding UTF8
        Test-EcfCancelled -Context $ctx | Should -BeTrue
    }

    It 'Set-EcfCancelled marks the run and emits run.cancelled exactly once' {
        $ctx = New-EcfRunContext -RunId 'cx5' -Params @{} -OutputDirectory $script:Tmp
        Start-EcfRun -Context $ctx
        Set-EcfCancelled -Context $ctx -Reason 'user requested'
        Set-EcfCancelled -Context $ctx
        $ctx.Cancelled | Should -BeTrue
        @($ctx.Events | Where-Object { $_.type -eq 'run.cancelled' }).Count | Should -Be 1
        ($ctx.Events | Where-Object { $_.type -eq 'run.cancelled' }).reason | Should -BeExactly 'user requested'
    }

    It 'Cancelled outranks a fatal error and retains partial artifacts' {
        $ctx = New-EcfRunContext -RunId 'cx6' -Params @{} -OutputDirectory $script:Tmp
        Start-EcfRun -Context $ctx
        Add-EcfArtifact -Context $ctx -Kind 'cockpit-html' -Path $script:Tmp
        Write-EcfError -Context $ctx -Message 'boom' -Code 'E1' -Fatal
        Set-EcfCancelled -Context $ctx
        $m = New-EcfRunManifest -Context $ctx
        $m.status | Should -BeExactly 'Cancelled'
        @($m.artifacts).Count | Should -BeGreaterThan 0
    }

    It 'Start-EcfRun clears a stale sentinel from a prior run' {
        $ctx = New-EcfRunContext -RunId 'cx7' -Params @{} -OutputDirectory $script:Tmp
        $null = New-Item -Path (Join-Path $script:Tmp '.runs') -ItemType Directory -Force
        Set-Content -LiteralPath (Get-EcfCancelSentinelPath -Context $ctx) -Value '' -Encoding UTF8
        Start-EcfRun -Context $ctx
        Test-EcfCancelled -Context $ctx | Should -BeFalse
        (Test-Path (Get-EcfCancelSentinelPath -Context $ctx)) | Should -BeFalse
    }

    It 'Complete-EcfRun clears the sentinel and derives Cancelled status' {
        $ctx = New-EcfRunContext -RunId 'cx8' -Params @{} -OutputDirectory $script:Tmp
        Start-EcfRun -Context $ctx
        Set-EcfCancelled -Context $ctx
        $m = Complete-EcfRun -Context $ctx -Summary @{}
        $m.status | Should -BeExactly 'Cancelled'
        (Test-Path (Get-EcfCancelSentinelPath -Context $ctx)) | Should -BeFalse
        $hist = Get-Content -LiteralPath $m.historyPath -Raw | ConvertFrom-Json
        $hist.status | Should -BeExactly 'Cancelled'
        # run.cancelled is part of the emitted stream / sink, not the
        # manifest shape — assert it on the context's recorded events.
        @($ctx.Events | Where-Object { $_.type -eq 'run.cancelled' }).Count | Should -BeGreaterThan 0
    }

    It 'no-cancel run is unaffected (status Succeeded, no sentinel created)' {
        $ctx = New-EcfRunContext -RunId 'cx9' -Params @{} -OutputDirectory $script:Tmp
        Start-EcfRun -Context $ctx
        Add-EcfArtifact -Context $ctx -Kind 'cockpit-html' -Path $script:Tmp
        $m = Complete-EcfRun -Context $ctx -Summary @{}
        $m.status | Should -BeExactly 'Succeeded'
        (Test-Path (Get-EcfCancelSentinelPath -Context $ctx)) | Should -BeFalse
    }
}

Describe 'Error taxonomy (Phase 3b)' {

    It 'Get-EcfErrorInfo is pure + total: every catalog code maps to {Code,Fatal,Remediation}' {
        foreach ($code in @('auth.failed', 'auth.cancelled', 'auth.insufficientPrivileges',
                'prereq.moduleMissing', 'prereq.azContextMissing', 'engine.moduleFailed',
                'report.writeFailed', 'snapshot.failed', 'snapshot.insufficient', 'cancelled', 'internal')) {
            $i = Get-EcfErrorInfo -Code $code
            $i.Code | Should -BeExactly $code
            $i.Remediation | Should -Not -BeNullOrEmpty
            $i.Fatal | Should -BeOfType [bool]
        }
    }

    It 'an unknown code degrades to internal (keeps the code, never throws)' {
        $i = Get-EcfErrorInfo -Code 'totally.made.up'
        $i.Code | Should -BeExactly 'totally.made.up'
        $i.Fatal | Should -BeFalse
        $i.Remediation | Should -BeExactly (Get-EcfErrorInfo -Code 'internal').Remediation
    }

    It 'fatal defaults come from the catalog (e.g. report.writeFailed is fatal)' {
        (Get-EcfErrorInfo -Code 'report.writeFailed').Fatal | Should -BeTrue
        (Get-EcfErrorInfo -Code 'prereq.azContextMissing').Fatal | Should -BeFalse
    }

    It 'Write-EcfError auto-fills remediation + fatality from the code' {
        $ctx = New-EcfRunContext -RunId 'et1' -Params @{} -OutputDirectory $env:TEMP
        Write-EcfError -Context $ctx -Code 'report.writeFailed' -Message 'disk full'
        $err = $ctx.Errors[0]
        $err.code | Should -BeExactly 'report.writeFailed'
        $err.fatal | Should -BeTrue
        $err.remediation | Should -Not -BeNullOrEmpty
        # surfaced on the emitted log event too
        $ev = $ctx.Events | Where-Object { $_.type -eq 'log' -and $_.code -eq 'report.writeFailed' } | Select-Object -Last 1
        $ev.remediation | Should -BeExactly $err.remediation
        $ev.fatal | Should -BeTrue
    }

    It 'explicit -Fatal / -Remediation override the catalog' {
        $ctx = New-EcfRunContext -RunId 'et2' -Params @{} -OutputDirectory $env:TEMP
        Write-EcfError -Context $ctx -Code 'prereq.azContextMissing' -Message 'no az' -Fatal -Remediation 'custom hint'
        $ctx.Errors[0].fatal | Should -BeTrue
        $ctx.Errors[0].remediation | Should -BeExactly 'custom hint'
    }

    It 'backward compat: an ad-hoc code with no -Fatal stays non-fatal (now with a hint)' {
        $ctx = New-EcfRunContext -RunId 'et3' -Params @{} -OutputDirectory $env:TEMP
        Write-EcfError -Context $ctx -Code 'E2' -Message 'soft'
        $ctx.Errors[0].fatal | Should -BeFalse
        $ctx.Errors[0].remediation | Should -Not -BeNullOrEmpty
    }

    It 'the manifest + run-history errors[] carry remediation' {
        $ctx = New-EcfRunContext -RunId 'et4' -Params @{} -OutputDirectory $env:TEMP
        Start-EcfRun -Context $ctx
        Write-EcfError -Context $ctx -Code 'engine.moduleFailed' -Message 'mod x failed'
        $m = New-EcfRunManifest -Context $ctx
        $m.errors[0].remediation | Should -Not -BeNullOrEmpty
        $m.errors[0].code | Should -BeExactly 'engine.moduleFailed'
    }
}

Describe 'Auth-as-events primitives (Phase 3c)' {

    It 'auth.browser carries a message' {
        $ctx = New-EcfRunContext -RunId 'ab1' -Params @{}
        Write-EcfAuthBrowser -Context $ctx
        $e = $ctx.Events[-1]
        $e.type | Should -BeExactly 'auth.browser'
        $e.message | Should -Not -BeNullOrEmpty
    }

    It 'auth.devicecode defaults to the spike Path-3 fallback shape' {
        $ctx = New-EcfRunContext -RunId 'ad1' -Params @{}
        Write-EcfAuthDeviceCode -Context $ctx
        $e = $ctx.Events[-1]
        $e.type | Should -BeExactly 'auth.devicecode'
        $e.userCode | Should -BeNullOrEmpty
        $e.verificationUri | Should -BeExactly 'https://microsoft.com/devicelogin'
        $e.capture | Should -BeExactly 'sdk-console'
    }

    It 'auth.devicecode can carry a real code (future DeviceCodeCredential path; additive)' {
        $ctx = New-EcfRunContext -RunId 'ad2' -Params @{}
        Write-EcfAuthDeviceCode -Context $ctx -UserCode 'ABCD-EFGH' -Capture 'captured'
        $e = $ctx.Events[-1]
        $e.userCode | Should -BeExactly 'ABCD-EFGH'
        $e.capture | Should -BeExactly 'captured'
    }

    It 'auth.succeeded carries account + method' {
        $ctx = New-EcfRunContext -RunId 'as1' -Params @{}
        Write-EcfAuthSucceeded -Context $ctx -Account 'admin@contoso.com' -Method 'Interactive'
        $e = $ctx.Events[-1]
        $e.type | Should -BeExactly 'auth.succeeded'
        $e.account | Should -BeExactly 'admin@contoso.com'
        $e.method | Should -BeExactly 'Interactive'
    }

    It 'auth.failed records a taxonomy error AND emits the event (3b auth wiring lands here)' {
        $ctx = New-EcfRunContext -RunId 'af1' -Params @{}
        Write-EcfAuthFailed -Context $ctx -Message 'AADSTS50058' -Code 'auth.cancelled'
        # taxonomy error recorded
        $err = @($ctx.Errors | Where-Object { $_.code -eq 'auth.cancelled' })
        $err.Count | Should -Be 1
        $err[0].fatal | Should -BeTrue
        $err[0].remediation | Should -Not -BeNullOrEmpty
        # auth.failed event emitted with the same code + remediation
        $e = $ctx.Events | Where-Object { $_.type -eq 'auth.failed' } | Select-Object -Last 1
        $e.code | Should -BeExactly 'auth.cancelled'
        $e.remediation | Should -BeExactly $err[0].remediation
    }

    It 'auth.failed defaults to the auth.failed code' {
        $ctx = New-EcfRunContext -RunId 'af2' -Params @{}
        Write-EcfAuthFailed -Context $ctx -Message 'unknown'
        ($ctx.Events | Where-Object { $_.type -eq 'auth.failed' } | Select-Object -Last 1).code | Should -BeExactly 'auth.failed'
        (Get-EcfErrorInfo -Code 'auth.failed').Fatal | Should -BeTrue
    }
}

Describe 'Run-context collections survive @() wrapping' {

    # New-Object System.Collections.Generic.List[object] hands back a
    # PSObject-wrapped list, and @() over one of those throws "Argument
    # types do not match" — on Windows PowerShell 5.1 and pwsh 7.x alike,
    # empty or not. The context lists cross into the orchestration, the
    # TUI renderer and the sidecar, so any consumer may reasonably wrap
    # them. ::new() in New-EcfRunContext is what keeps this passing.

    It 'wraps cleanly while empty' {
        $ctx = New-EcfRunContext -RunId 'wrap-empty' -Params @{} -OutputDirectory $env:TEMP
        foreach ($name in 'Events', 'Artifacts', 'Errors', 'Warnings', 'OpenPhases') {
            { @($ctx.$name) } | Should -Not -Throw -Because "@(`$ctx.$name) must not throw on the empty success path"
            @($ctx.$name).Count | Should -Be 0
        }
    }

    It 'wraps cleanly once populated' {
        # Emptiness is not the discriminator — a populated wrapped list
        # throws identically. Pin both so the fix cannot regress halfway.
        $ctx = New-EcfRunContext -RunId 'wrap-full' -Params @{} -OutputDirectory $env:TEMP
        Write-EcfWarning -Context $ctx -Code 'test.warn' -Message 'w'
        Write-EcfError -Context $ctx -Code 'internal' -Message 'e'
        Add-EcfArtifact -Context $ctx -Kind 'manifest' -Path (Join-Path $env:TEMP 'nope.json')
        Start-EcfPhase -Context $ctx -Phase 'Core'

        @($ctx.Warnings).Count | Should -Be 1
        @($ctx.Errors).Count | Should -Be 1
        @($ctx.Artifacts).Count | Should -Be 1
        @($ctx.OpenPhases).Count | Should -Be 1
        @($ctx.Events).Count | Should -BeGreaterThan 0
    }
}
