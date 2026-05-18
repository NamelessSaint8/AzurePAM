<#
.SYNOPSIS
    Pester 5 tests for the Phase 2 TUI re-platform
    (plans/Native-App-Phase2-TUI-Replatform-Plan.md §8 items 2,4,6,9).

.DESCRIPTION
    The interactive menu's two assessment-run actions (main option 1 +
    the module-submenu run) now go through the single runner seam
    (Invoke-EcfAssessmentSequence) with the in-process console renderer
    as the -EventSink, instead of inline Invoke-ModuleAssessment +
    Export-AssessmentResult + completion Write-Host.

    Behavioural parity of the live menu needs a tenant (Graph/Az) — no
    CI substitute. These tests pin what CI *can* assert via AST/static
    analysis of EntraChecks.Orchestration.ps1:

      - the run actions call the seam with the renderer sink, and no
        longer call the orchestration primitives inline;
      - the interactive UX is preserved (tenant prompt, Connect
        preamble, post-run snapshot prompt, press-enter);
      - the auxiliary branches (AD-only, SOC 2 Type 2, snapshot/delta,
        auth status) are untouched;
      - the sequence's new params are additive (defaults = the old
        non-interactive behaviour).

    Run: Invoke-Pester -Path Tests/TUI-Replatform.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $script:OrchPath = Join-Path $repoRoot 'EntraChecks.Orchestration.ps1'
    $script:OrchText = Get-Content -LiteralPath $script:OrchPath -Raw
    $script:OrchAst = [System.Management.Automation.Language.Parser]::ParseInput($script:OrchText, [ref]$null, [ref]$null)

    function script:Get-FnText {
        param([string]$Name)
        $fn = $script:OrchAst.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name },
            $true) | Select-Object -First 1
        if ($fn) { return $fn.Extent.Text }
        return ''
    }
}

Describe 'Menu run actions route through the runner seam' {

    BeforeAll { $script:Menu = Get-FnText -Name 'Start-InteractiveMode' }

    It 'Start-InteractiveMode is present and non-empty' {
        $script:Menu | Should -Not -BeNullOrEmpty
    }

    It 'wires the console renderer as the in-process EventSink' {
        $script:Menu | Should -Match 'Show-EcfRunStream -Event \$e'
        $script:Menu | Should -Match '-EventSink \$renderSink'
    }

    It 'calls Invoke-EcfAssessmentSequence for the run actions (>=2 call sites)' {
        ([regex]::Matches($script:Menu, 'Invoke-EcfAssessmentSequence -TenantNameValue')).Count |
            Should -BeGreaterOrEqual 2
    }

    It 'the two run actions no longer drive the orchestration primitives inline' {
        # The seam owns Invoke-ModuleAssessment / Export-AssessmentResult
        # for the Quick + module-subset runs. (The AD-only auxiliary
        # branch keeps its own direct call by design — asserted below.)
        $script:Menu | Should -Not -Match 'Invoke-ModuleAssessment -SelectedModules \$allModules'
        $script:Menu | Should -Not -Match 'Invoke-ModuleAssessment -SelectedModules \$selectedModules'
        $script:Menu | Should -Not -Match 'Export-AssessmentResult -OutputDir'
    }

    It 'preserves the interactive UX: tenant prompt, Connect preamble, press-enter' {
        $script:Menu | Should -Match 'Enter tenant name'
        # Phase 3c relocated auth into the sequence's observed Auth
        # phase: the run actions no longer call Connect-EntraCheck
        # inline; they build an injected auth action gated by
        # -SkipAuthentication and pass it as -AuthAction. The Connect
        # preamble is preserved, now as that injected scriptblock.
        $script:Menu | Should -Match 'if \(-not \$SkipAuthentication\) \{ \$authAction = \{ \$null = Connect-EntraCheck \} \}'
        $script:Menu | Should -Match '-AuthAction \$authAction -AuthMethod ''Interactive'''
        $script:Menu | Should -Match 'Press Enter to continue'
    }

    It 'keeps the post-run snapshot prompt + save in the menu (timing preserved)' {
        $script:Menu | Should -Match 'Save snapshot for future comparison\? \(Y/N\)'
        $script:Menu | Should -Match 'Save-ComplianceSnapshot -OutputDirectory \$script:SnapshotsPath'
    }

    It 'tells the sequence to skip its own snapshot (no double save / timing kept)' {
        $script:Menu | Should -Match '-SkipSequenceSnapshot'
    }

    It 'preserves interactive SOC 2 browser-open via -OpenSoc2Browser' {
        $script:Menu | Should -Match '-OpenSoc2Browser'
    }
}

Describe 'Auxiliary menu branches are untouched (Phase 2 scope discipline)' {

    BeforeAll { $script:Menu = Get-FnText -Name 'Start-InteractiveMode' }

    It 'the AD-only assessment branch still calls Invoke-ModuleAssessment directly' {
        # Out of Phase 2 scope: only the Quick + module-subset run actions
        # re-platform. The AD-only branch keeps its direct call.
        $script:Menu | Should -Match "Invoke-ModuleAssessment -SelectedModules @\('ActiveDirectory'\)"
    }

    It 'SOC 2 Type 2 + snapshot/delta + auth-status helpers still exist as direct functions' {
        (Get-FnText -Name 'Invoke-SOC2TypeTwoFromMenu') | Should -Not -BeNullOrEmpty
        (Get-FnText -Name 'Show-AuthStatus') | Should -Not -BeNullOrEmpty
        (Get-FnText -Name 'Invoke-SOC2ReadinessIfEnabled') | Should -Not -BeNullOrEmpty
    }
}

Describe 'Sequence param additions are additive (non-interactive unchanged)' {

    BeforeAll { $script:Seq = Get-FnText -Name 'Invoke-EcfAssessmentSequence' }

    It 'exposes the Phase 2 params' {
        $script:Seq | Should -Match '\[switch\]\$SkipSequenceSnapshot'
        $script:Seq | Should -Match '\[switch\]\$OpenSoc2Browser'
        $script:Seq | Should -Match '\[scriptblock\]\$EventSink'
    }

    It 'snapshot gate defaults to the original behaviour (gated on $SaveSnapshot)' {
        # -SkipSequenceSnapshot defaults off, so non-interactive modes
        # still snapshot exactly when $SaveSnapshot is set. Phase 3a
        # additionally prefixes the cancel guard (-not $cancelled).
        $script:Seq | Should -Match '-not \$SkipSequenceSnapshot -and \$SaveSnapshot'
    }

    It 'SOC 2 browser-open defaults to $false (scripted-mode behaviour)' {
        $script:Seq | Should -Match 'Invoke-SOC2ReadinessIfEnabled .* -OpenBrowser \(\[bool\]\$OpenSoc2Browser\)'
    }

    It 'forwards the sink to New-EcfRunContext' {
        # Phase 3a switched the context creation to a splat
        # (@ctxArgs) so the cancel ref can be conditionally included;
        # the sink is still forwarded via that hashtable.
        $script:Seq | Should -Match "EventSink\s*=\s*\`$EventSink"
        $script:Seq | Should -Match 'New-EcfRunContext @ctxArgs'
    }

    It 'the three non-interactive modes do not pass the Phase 2 interactive switches' {
        foreach ($mode in @('Start-QuickMode', 'Start-ScheduledMode', 'Start-HybridMode')) {
            $txt = Get-FnText -Name $mode
            $txt | Should -Not -BeNullOrEmpty
            $txt | Should -Not -Match '-SkipSequenceSnapshot'
            $txt | Should -Not -Match '-OpenSoc2Browser'
            $txt | Should -Not -Match '-EventSink'
        }
    }
}
