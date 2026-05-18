<#
.SYNOPSIS
    End-to-end parity test for the headless runner
    (plans/Native-App-Phase1-Headless-Core-Plan.md §8 item 6, the 4/4
    deliverable).

.DESCRIPTION
    Runner-Contract.Tests.ps1 proves the contract *primitives* in
    isolation. This proves the *integration*: the real
    Invoke-EcfAssessmentSequence (the orchestration seam, now dot-source
    -able from EntraChecks.Orchestration.ps1 after the 4/4a split),
    driven with the heavy orchestration mocked, produces a valid v1.0
    run-result manifest + run-history file with the right status,
    sanitized params, artifacts, and summary.

    The orchestration ($script: substrate, Invoke-ModuleAssessment,
    Export-AssessmentResult, SOC2) is mocked — a live tenant
    (Graph/Az) is still required for final behavioural sign-off; there
    is no CI substitute for that and this test does not claim to be one.

    Run: Invoke-Pester -Path Tests/Runner-Parity.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    if (-not $env:TEMP) {
        $env:TEMP = if ($env:TMPDIR) { $env:TMPDIR.TrimEnd('/') } else { '/tmp' }
    }
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Runner.psm1') -Force

    # Dot-source the orchestration include so Invoke-EcfAssessmentSequence
    # (and its siblings) are defined in this scope — mockable, callable —
    # without running Start-EntraChecks.ps1's setup or dispatch.
    $script:OrchPath = Join-Path $repoRoot 'EntraChecks.Orchestration.ps1'
    . $script:OrchPath

    # Minimal script-scope substrate the sequence reads on the happy path
    # (no SaveSnapshot / CompareWithLast / Hybrid -> the snapshot/delta/
    # correlation branches are not exercised, so ModulesPath etc. are not
    # needed).
    $GenerateComprehensiveReport = $false
    $GenerateExecutiveSummary = $false
    $GenerateExcelReport = $false
    $GenerateRemediationScripts = $false
    $HtmlReportSet = 'Cockpit'
    $HtmlDeepDiveDomains = @()
    # These are read by the dot-sourced Invoke-EcfAssessmentSequence via
    # dynamic scope (it passes them to the mocked Export-AssessmentResult).
    # Static analysis can't see the cross-dot-source use, so reference
    # them explicitly to keep PSScriptAnalyzer honest.
    $null = $GenerateComprehensiveReport, $GenerateExecutiveSummary,
    $GenerateExcelReport, $GenerateRemediationScripts, $HtmlReportSet, $HtmlDeepDiveDomains
}

Describe 'Runner parity — sequence drives the v1.0 contract end-to-end' {

    BeforeEach {
        $script:Tmp = Join-Path $env:TEMP "runner-parity-$([guid]::NewGuid().ToString('N'))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $OutputDirectory = $script:Tmp
        $null = $OutputDirectory   # read by the dot-sourced sequence (dynamic scope)

        # Seed the finding pool the sequence rolls into the summary.
        $script:Findings = @(
            [pscustomobject]@{ Severity = 'Critical'; Description = 'c' }
            [pscustomobject]@{ Severity = 'High'; Description = 'h' }
            [pscustomobject]@{ Severity = 'Low'; Description = 'l' }
        )

        # Mock the heavy orchestration. Export-AssessmentResult drops a
        # report file so the artifact-enumeration path is exercised.
        # Script-scoped (not a local named $reportDir): the sequence has
        # its own $reportDir local, so a same-named mock var would be
        # captured by dynamic scope instead of this one.
        $script:ParityReportDir = Join-Path $script:Tmp 'report'
        $null = New-Item -Path $script:ParityReportDir -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $script:ParityReportDir 'EntraChecks-cockpit.html') -Value '<html></html>' -Encoding UTF8

        Mock Invoke-ModuleAssessment {
            [pscustomobject]@{ Duration = [timespan]::FromMinutes(2); Errors = @(); Modules = @{ Core = 'ok' } }
        }
        Mock Export-AssessmentResult { $script:ParityReportDir }
        Mock Invoke-SOC2ReadinessIfEnabled { }
    }

    AfterEach {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'produces a v1.0 run-result manifest with status Succeeded' {
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp; ClientSecret = 'LEAK' } `
            -EmitEvents

        $seq.Manifest | Should -Not -BeNullOrEmpty
        $seq.Manifest.schemaVersion | Should -BeExactly '1.0'
        $seq.Manifest.type | Should -BeExactly 'run.result'
        $seq.Manifest.status | Should -BeExactly 'Succeeded'
        $seq.Manifest.runId | Should -Not -BeNullOrEmpty
    }

    It 'writes run history equal to the manifest under .runs/<runId>.json' {
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EmitEvents

        $histPath = Join-Path (Join-Path $script:Tmp '.runs') ("{0}.json" -f $seq.Manifest.runId)
        Test-Path $histPath | Should -BeTrue
        $fromDisk = Get-Content -LiteralPath $histPath -Raw | ConvertFrom-Json
        $fromDisk.runId | Should -BeExactly $seq.Manifest.runId
        $fromDisk.status | Should -BeExactly 'Succeeded'
        $fromDisk.schemaVersion | Should -BeExactly '1.0'
    }

    It 'rolls the finding pool into the manifest summary' {
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EmitEvents

        $seq.Manifest.summary.findings | Should -Be 3
        $seq.Manifest.summary.critical | Should -Be 1
        $seq.Manifest.summary.high | Should -Be 1
        $seq.Manifest.summary.low | Should -Be 1
        @($seq.Manifest.summary.modulesRun) | Should -Be @('Core')
    }

    It 'sanitizes the params echo (allowlist; secret dropped)' {
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp; ClientSecret = 'LEAK' } `
            -EmitEvents

        # params is the ordered hashtable from ConvertTo-EcfSafeParams
        # (in-process); assert via its keys, not PSObject members.
        @($seq.Manifest.params.Keys) | Should -Contain 'TenantName'
        @($seq.Manifest.params.Keys) | Should -Not -Contain 'ClientSecret'
        # And it round-trips through the run-history JSON the same way.
        $hist = Get-Content -LiteralPath (Join-Path (Join-Path $script:Tmp '.runs') ("{0}.json" -f $seq.Manifest.runId)) -Raw | ConvertFrom-Json
        $hist.params.PSObject.Properties.Name | Should -Contain 'TenantName'
        $hist.params.PSObject.Properties.Name | Should -Not -Contain 'ClientSecret'
    }

    It 'enumerates the report artifact produced by Export-AssessmentResult' {
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EmitEvents

        $arts = @($seq.Manifest.artifacts)
        $arts.Count | Should -BeGreaterThan 0
        ($arts | Where-Object { $_.kind -eq 'cockpit-html' }).Count | Should -BeGreaterThan 0
        foreach ($a in $arts) { [System.IO.Path]::IsPathRooted($a.path) | Should -BeTrue }
    }

    It 'calls the orchestration exactly once each (no duplicate driving)' {
        $null = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EmitEvents
        Should -Invoke Invoke-ModuleAssessment -Times 1 -Exactly
        Should -Invoke Export-AssessmentResult -Times 1 -Exactly
        Should -Invoke Invoke-SOC2ReadinessIfEnabled -Times 1 -Exactly
    }
}

Describe 'Runner parity — the seam is non-interactive' {

    It 'Invoke-EcfAssessmentSequence contains no Read-Host' {
        $src = Get-Content -LiteralPath $script:OrchPath -Raw
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        $fn = $ast.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-EcfAssessmentSequence' },
            $true) | Select-Object -First 1
        $fn | Should -Not -BeNullOrEmpty
        $fn.Extent.Text | Should -Not -Match '(?im)(^|[^-\w])Read-Host\b'
    }
}

Describe 'Invoke-EntraChecksRun.ps1 — headless wrapper guard' {

    It 'rejects an empty tenant (no prompt on the headless path)' {
        $wrapper = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-EntraChecksRun.ps1'
        Test-Path $wrapper | Should -BeTrue
        { & $wrapper -TenantName '   ' -SkipAuthentication } |
            Should -Throw -ExpectedMessage '*-TenantName is required for a headless run*'
    }

    It 'forwards to Start-EntraChecks.ps1 with Mode=Quick + the contract params' {
        # Static assertion — running it for real needs a tenant. Confirm
        # the wrapper hard-codes the non-interactive Quick path and
        # forwards EmitEvents (the sidecar contract).
        $wrapper = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-EntraChecksRun.ps1'
        $txt = Get-Content -LiteralPath $wrapper -Raw
        $txt | Should -Match "Mode\s*=\s*'Quick'"
        $txt | Should -Match 'EmitEvents\s*=\s*\[bool\]\$EmitEvents'
        $txt | Should -Match '& \$startScript @forward'
    }
}

Describe 'Runner parity — cooperative cancellation (Phase 3a)' {

    BeforeEach {
        $script:Tmp = Join-Path $env:TEMP "runner-cancel-$([guid]::NewGuid().ToString('N'))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $OutputDirectory = $script:Tmp
        $null = $OutputDirectory
        $script:Findings = @([pscustomobject]@{ Severity = 'High'; Description = 'h' })
        $script:ReportDir = Join-Path $script:Tmp 'report'
        $null = New-Item -Path $script:ReportDir -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $script:ReportDir 'EntraChecks-cockpit.html') -Value '<html></html>' -Encoding UTF8
        Mock Export-AssessmentResult { $script:ReportDir }
        Mock Invoke-SOC2ReadinessIfEnabled { }
    }
    AfterEach {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'pre-run cancel aborts before any module work; status Cancelled' {
        Mock Invoke-ModuleAssessment { [pscustomobject]@{ Duration = [timespan]::Zero; Errors = @(); Modules = @{} } }
        $flag = $true                                  # cancel requested before the run
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EmitEvents `
            -CancelFlag ([ref]$flag)
        $seq.Manifest.status | Should -BeExactly 'Cancelled'
        Should -Invoke Invoke-ModuleAssessment -Times 0 -Exactly
        Should -Invoke Export-AssessmentResult -Times 0 -Exactly
    }

    It 'mid-run cancel after Modules skips Report/SOC2; status Cancelled; run.cancelled emitted' {
        $flag = $false
        $ref = [ref]$flag
        # The engine "runs", then a cancel arrives before the next checkpoint.
        Mock Invoke-ModuleAssessment {
            $ref.Value = $true
            [pscustomobject]@{ Duration = [timespan]::FromMinutes(1); Errors = @(); Modules = @{ Core = 'ok' } }
        }
        $seen = New-Object System.Collections.Generic.List[object]
        $sink = { param($e) $seen.Add($e) | Out-Null }
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } `
            -EventSink $sink -CancelFlag $ref
        $seq.Manifest.status | Should -BeExactly 'Cancelled'
        Should -Invoke Invoke-ModuleAssessment -Times 1 -Exactly
        Should -Invoke Export-AssessmentResult -Times 0 -Exactly       # Report skipped post-Modules checkpoint
        @($seen | Where-Object { $_.type -eq 'run.cancelled' }).Count | Should -BeGreaterThan 0
        # Phases stay balanced even on the cancel path.
        $st = @($seen | Where-Object { $_.type -eq 'phase.started' } | ForEach-Object { $_.phase } | Sort-Object)
        $cp = @($seen | Where-Object { $_.type -eq 'phase.completed' } | ForEach-Object { $_.phase } | Sort-Object)
        $st | Should -Be $cp
    }

    It 'no cancel → unchanged: status Succeeded, Modules+Report invoked' {
        Mock Invoke-ModuleAssessment { [pscustomobject]@{ Duration = [timespan]::FromMinutes(1); Errors = @(); Modules = @{ Core = 'ok' } } }
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EmitEvents
        $seq.Manifest.status | Should -BeExactly 'Succeeded'
        Should -Invoke Invoke-ModuleAssessment -Times 1 -Exactly
        Should -Invoke Export-AssessmentResult -Times 1 -Exactly
    }
}
