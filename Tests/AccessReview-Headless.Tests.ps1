<#
.SYNOPSIS
    Pester 5 test suite for the headless Access Review path
    (PR 1 of plans/Access-Review-GUI-Implementation-Plan.md).

.DESCRIPTION
    Exercises Invoke-AccessReviewPhase and the AccessReview phase block in
    Invoke-EcfAssessmentSequence against fully-mocked Microsoft Graph.
    Covers:
    1. Open emits phase.started/phase.completed for 'AccessReview' and
       records the worksheet + manifest artifacts.
    2. A campaign-only run (-AccessReviewOnly) emits no Modules / Report /
       Snapshot / SOC2 phase events and never calls the assessment engine.
    3. Close against an incomplete worksheet -> non-fatal
       accessReview.failed error, phase status 'failed', campaign stays
       Open, and the run still reaches run.result.
    4. An invalid action is rejected by the ValidateSet before any Graph
       call.
    5. -AccessReviewDirectory overrides the config OutputDirectory.
    6. In concert: a normal run with -OpenAccessReviewCampaign emits the
       AccessReview phase between Modules and SOC2, reusing the privileged
       roster the run already built.
    7. PR 2 of plans/Access-Review-Remediation-Script-Plan.md — the
       Remediate action: phase + the two remediation artifacts, the
       missing-CampaignId refusal, a generator refusal as a non-fatal
       error, the action counts reaching the event path, and (the property
       most likely to regress) a Remediate run that authenticates not at
       all — and echoes that decision, not the Interactive default, into
       run.started.

    Run: Invoke-Pester -Path Tests/AccessReview-Headless.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    if (-not $env:TEMP) {
        $env:TEMP = if ($env:TMPDIR) { $env:TMPDIR.TrimEnd('/') } else { '/tmp' }
    }
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Runner.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AccessReview.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AccessReviewReport.psm1') -Force -DisableNameChecking
    # Imported here (not left to Invoke-AccessReviewPhase's lazy import) so
    # New-AccessReviewRemediationScript exists to be mocked, and so the
    # phase's `if (-not (Get-Module ...))` guard leaves the mock alone.
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AccessReviewRemediation.psm1') -Force -DisableNameChecking

    # Dot-source the orchestration include so Invoke-AccessReviewPhase /
    # Invoke-EcfAssessmentSequence are defined here — mockable, callable —
    # without running Start-EntraChecks.ps1's setup or dispatch.
    $script:OrchPath = Join-Path $repoRoot 'EntraChecks.Orchestration.ps1'
    . $script:OrchPath

    # Substrate the orchestration reads from script scope.
    $script:ModulesPath = Join-Path $repoRoot 'Modules'
    $script:RepoConfigPath = Join-Path $repoRoot 'config/entrachecks.config.json'

    function New-MockEnv {
        [pscustomobject]@{
            IsAvailable = $true
            FailureReason = $null
            TenantId = 'tenant-0'
            Account = 'auditor@contoso.onmicrosoft.com'
            AuthType = 'Delegated'
            Scopes = @('Directory.Read.All', 'RoleManagement.Read.Directory')
        }
    }
    $script:MakeEnv = ${function:New-MockEnv}

    function New-BetaUsersPage {
        @{
            value = @(
                @{
                    id = 'user-priv-1'; displayName = 'Priv User'; userPrincipalName = 'priv@contoso.com'
                    accountEnabled = $true; userType = 'Member'; createdDateTime = '2024-01-01T00:00:00Z'
                    signInActivity = @{ lastSignInDateTime = '2026-07-30T10:00:00Z' }
                },
                @{
                    id = 'user-2'; displayName = 'Normal User'; userPrincipalName = 'normal@contoso.com'
                    accountEnabled = $true; userType = 'Member'; createdDateTime = '2024-02-01T00:00:00Z'
                }
            )
        }
    }
    $script:MakeBetaPage = ${function:New-BetaUsersPage}

    function New-EntraRosterFixture {
        @{
            Available = $true
            FailureReason = $null
            Tenant = @{ TenantId = 'tenant-0'; Account = 'auditor@contoso.onmicrosoft.com'; AuthType = 'Delegated' }
            Roster = @(
                @{
                    ObjectId = 'user-priv-1'; PrincipalType = 'User'; Upn = 'priv@contoso.com'
                    DisplayName = 'Priv User'; Enabled = $true; LastSignIn = $null; HighestTier = 0
                    Privileges = @(@{ Key = 'Entra:GlobalAdministrator'; Path = @('Global Administrator (active)'); AssignmentType = 'Active' })
                    Sources = @('Active role assignment')
                },
                @{
                    ObjectId = 'sp-1'; PrincipalType = 'ServicePrincipal'; Upn = $null
                    DisplayName = 'Reused Roster SP'; Enabled = $true; LastSignIn = $null; HighestTier = 0
                    Privileges = @(@{ Key = 'MSGraph:Directory.ReadWrite.All'; Path = @('App-role: Directory.ReadWrite.All granted on Microsoft Graph'); AssignmentType = 'AppRole' })
                    Sources = @('MS Graph app-role grant')
                }
            )
            Statistics = @{ TotalPrincipals = 2; PimAvailable = $true }
        }
    }
    $script:MakeRoster = ${function:New-EntraRosterFixture}

    # Fresh run context + started run, so phase/artifact/error assertions
    # can read $ctx.Events in process (no NDJSON round-trip).
    function New-ArRunContext {
        param([string]$Id, [string]$OutDir)
        $c = New-EcfRunContext -RunId $Id -Params @{} -OutputDirectory $OutDir
        Start-EcfRun -Context $c
        return $c
    }
    $script:MakeCtx = ${function:New-ArRunContext}
}

Describe 'Invoke-AccessReviewPhase — Open' {

    BeforeEach {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeEnv
        }
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeBetaPage
        }
        $script:ArDir = Join-Path $TestDrive ("ar-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $script:Ctx = & $script:MakeCtx 'ar-open' $script:ArDir
    }

    It 'opens the phase and closes it ok' {
        $r = Invoke-AccessReviewPhase -Action 'Open' -TenantName 'Contoso' `
            -CampaignDirectory $script:ArDir -EntraRoster (& $script:MakeRoster) -Context $script:Ctx
        $r.Success | Should -BeTrue -Because ($r.FailureReason)

        @($script:Ctx.Events | Where-Object { $_.type -eq 'phase.started' -and $_.phase -eq 'AccessReview' }).Count |
            Should -Be 1
        $done = @($script:Ctx.Events | Where-Object { $_.type -eq 'phase.completed' -and $_.phase -eq 'AccessReview' })
        $done.Count | Should -Be 1
        $done[0].status | Should -BeExactly 'ok'
    }

    It 'records the worksheet and manifest as artifacts' {
        $r = Invoke-AccessReviewPhase -Action 'Open' -TenantName 'Contoso' `
            -CampaignDirectory $script:ArDir -EntraRoster (& $script:MakeRoster) -Context $script:Ctx
        $r.Success | Should -BeTrue -Because ($r.FailureReason)

        $kinds = @($script:Ctx.Artifacts | ForEach-Object { $_.kind })
        $kinds | Should -Contain 'worksheet'
        $kinds | Should -Contain 'manifest'
        # No report is rendered on open, so no HTML artifact yet.
        $kinds | Should -Not -Contain 'access-review-html'

        foreach ($a in $script:Ctx.Artifacts) {
            [System.IO.Path]::IsPathRooted($a.path) | Should -BeTrue
            Test-Path -LiteralPath $a.path | Should -BeTrue
        }
        ($script:Ctx.Artifacts | Where-Object { $_.kind -eq 'worksheet' }).path |
            Should -BeLike '*review-worksheet.csv'
    }

    It 'reuses a supplied roster instead of re-pulling it' {
        $r = Invoke-AccessReviewPhase -Action 'Open' -TenantName 'Contoso' `
            -CampaignDirectory $script:ArDir -EntraRoster (& $script:MakeRoster) -Context $script:Ctx
        $r.Success | Should -BeTrue -Because ($r.FailureReason)
        # The fixture SP exists only in the supplied roster (it is not a
        # user in the mocked Graph page), so its presence in the worksheet
        # proves the pre-built roster was used.
        $rows = Import-Csv -LiteralPath (Join-Path $r.Directory 'review-worksheet.csv')
        @($rows | Where-Object { $_.DisplayName -eq 'Reused Roster SP' }).Count | Should -Be 1
    }

    It 'runs without a context (interactive menu path) and emits nothing' {
        $r = Invoke-AccessReviewPhase -Action 'Open' -TenantName 'Contoso' -CampaignDirectory $script:ArDir `
            -EntraRoster (& $script:MakeRoster)
        $r.Success | Should -BeTrue -Because ($r.FailureReason)
        @($script:Ctx.Events | Where-Object { $_.phase -eq 'AccessReview' }).Count | Should -Be 0
    }
}

Describe 'Invoke-AccessReviewPhase — input validation' {

    BeforeEach {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeEnv
        }
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeBetaPage
        }
        $script:ArDir = Join-Path $TestDrive ("val-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }

    It 'rejects an invalid action before any Graph call' {
        { Invoke-AccessReviewPhase -Action 'Purge' -CampaignDirectory $script:ArDir } |
            Should -Throw
        Should -Invoke -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -Times 0 -Exactly
        Should -Invoke -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -Times 0 -Exactly
    }

    It 'Close without -CampaignId fails with a reason instead of crashing' {
        $r = Invoke-AccessReviewPhase -Action 'Close' -CampaignDirectory $script:ArDir
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'CampaignId'
        Should -Invoke -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -Times 0 -Exactly
    }

    It 'Start-EntraChecks.ps1 refuses -AccessReviewAction outside -Mode AccessReview' {
        # Static assertion (running the entrypoint for real needs a tenant
        # + full module load). Without this guard a Quick run silently
        # rewrote a requested Close into a brand-new Open campaign.
        $txt = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-EntraChecks.ps1') -Raw
        $txt | Should -Match "\`$AccessReviewAction -and \`$Mode -ne 'AccessReview'"
        $txt | Should -Match '-AccessReviewAction requires -Mode AccessReview'
    }

    It 'Report against an unknown campaign fails with a reason' {
        $r = Invoke-AccessReviewPhase -Action 'Report' -CampaignDirectory $script:ArDir -CampaignId 'nope'
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'not found'
    }
}

Describe 'Access review configuration — -AccessReviewDirectory overrides config' {

    BeforeEach {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeEnv
        }
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeBetaPage
        }
    }

    It 'Get-AccessReviewConfig reads the AccessReview block' {
        $cfgPath = Join-Path $TestDrive 'ar-config.json'
        @{
            AccessReview = @{
                Enabled = $true
                OutputDirectory = 'C:\Evidence\FromConfig'
                IncludeGuests = $false
                PeriodLabel = '2026-Q9'
            }
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $cfgPath -Encoding UTF8

        $cfg = Get-AccessReviewConfig -ConfigPath $cfgPath
        $cfg.Enabled | Should -BeTrue
        $cfg.Directory | Should -BeExactly 'C:\Evidence\FromConfig'
        $cfg.IncludeGuests | Should -BeFalse
        $cfg.PeriodLabel | Should -BeExactly '2026-Q9'
        $cfg.ParseError | Should -BeFalse
    }

    It 'falls back to defaults on a missing or unparseable file' {
        $missing = Get-AccessReviewConfig -ConfigPath (Join-Path $TestDrive 'no-such-config.json')
        $missing.Enabled | Should -BeFalse
        $missing.Directory | Should -BeExactly '.\Output\AccessReview'
        $missing.ParseError | Should -BeFalse

        $bad = Join-Path $TestDrive 'broken-config.json'
        Set-Content -LiteralPath $bad -Value '{ not json' -Encoding UTF8
        $broken = Get-AccessReviewConfig -ConfigPath $bad
        $broken.ParseError | Should -BeTrue
        $broken.Directory | Should -BeExactly '.\Output\AccessReview'
    }

    It 'the campaign lands under -AccessReviewDirectory, not the config directory' {
        $override = Join-Path $TestDrive ("override-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $r = Invoke-AccessReviewPhase -Action 'Open' -TenantName 'Contoso' `
            -CampaignDirectory $override -EntraRoster (& $script:MakeRoster)
        $r.Success | Should -BeTrue -Because ($r.FailureReason)
        $r.Directory | Should -BeLike "$override*"

        # And the configured directory is genuinely different, so the
        # assertion above is not vacuous.
        $configured = (Get-AccessReviewConfig -ConfigPath $script:RepoConfigPath).Directory
        $r.Directory | Should -Not -BeLike "*$configured*"
    }
}

Describe 'Access review configuration — the -Environment merge is honoured' {

    # Only Import-Configuration merges <base>.<env>.json over the base file,
    # and it leaves the result on $script:Config. Raw-parsing the -ConfigFile
    # therefore cannot see an AccessReview block that lives solely in an
    # environment override, so Get-AccessReviewConfig prefers $script:Config.

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Configuration.psm1') -Force

        # Schema-valid base with no AccessReview block; prod override adds one.
        $script:MergeBase = Join-Path $TestDrive 'merged.json'
        @{
            Version = '1.0.0'
            Assessment = @{
                Mode = 'Quick'
                Scope = @('Core')
                Output = @{ Directory = '.\Output'; Formats = @('HTML') }
            }
            Logging = @{ MinimumLevel = 'INFO'; Directory = '.\Logs' }
            ErrorHandling = @{ MaxRetries = 3 }
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:MergeBase -Encoding UTF8

        @{
            AccessReview = @{
                Enabled = $true
                OutputDirectory = 'C:\Evidence\ProdAR'
                IncludeGuests = $false
                PeriodLabel = '2026-Q4'
            }
        } | ConvertTo-Json -Depth 6 |
            Set-Content -LiteralPath (Join-Path $TestDrive 'merged.prod.json') -Encoding UTF8
    }

    AfterEach {
        # $script:Config is ambient — never let it leak into the suites that
        # assert the raw-file fallback.
        $script:Config = $null
    }

    It 'the base file alone yields the defaults (the pre-fix behaviour)' {
        $script:Config = $null
        $cfg = Get-AccessReviewConfig -ConfigPath $script:MergeBase
        $cfg.Enabled | Should -BeFalse
        $cfg.Directory | Should -BeExactly '.\Output\AccessReview'
    }

    It 'an AccessReview block that only exists in the -Environment override is honoured' {
        $script:Config = Import-Configuration -FilePath $script:MergeBase -Environment 'prod'

        $cfg = Get-AccessReviewConfig -ConfigPath $script:MergeBase
        $cfg.Enabled | Should -BeTrue
        $cfg.Directory | Should -BeExactly 'C:\Evidence\ProdAR'
        $cfg.IncludeGuests | Should -BeFalse
        $cfg.PeriodLabel | Should -BeExactly '2026-Q4'
        $cfg.ParseError | Should -BeFalse
    }

    It 'a merged config without an AccessReview block still falls back to the file' {
        $fromFile = Join-Path $TestDrive 'ar-only.json'
        @{ AccessReview = @{ Enabled = $true; OutputDirectory = 'C:\Evidence\FromFile' } } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $fromFile -Encoding UTF8

        $script:Config = Import-Configuration -FilePath $script:MergeBase

        $cfg = Get-AccessReviewConfig -ConfigPath $fromFile
        $cfg.Directory | Should -BeExactly 'C:\Evidence\FromFile' -Because 'the guard only wins when the merged config carries the block'
    }

    It 'Get-SOC2EnabledFromConfig honours the same merge' {
        $soc2Base = Join-Path $TestDrive 'soc2-merge.json'
        Copy-Item -LiteralPath $script:MergeBase -Destination $soc2Base
        @{ SOC2 = @{ Enabled = $true } } | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath (Join-Path $TestDrive 'soc2-merge.prod.json') -Encoding UTF8

        Get-SOC2EnabledFromConfig -ConfigPath $soc2Base | Should -BeFalse -Because 'the base file has no SOC2 block'

        $script:Config = Import-Configuration -FilePath $soc2Base -Environment 'prod'
        Get-SOC2EnabledFromConfig -ConfigPath $soc2Base | Should -BeTrue
    }
}

Describe 'Campaign-only run — the assessment pipeline is skipped' {

    BeforeEach {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeEnv
        }
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeBetaPage
        }
        Mock Invoke-ModuleAssessment { [pscustomobject]@{ Duration = [timespan]::Zero; Errors = @(); Modules = @{} } }
        Mock Export-AssessmentResult { $script:Tmp }
        Mock Invoke-SOC2ReadinessIfEnabled { }

        $script:Tmp = Join-Path $TestDrive ("only-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $script:Findings = @()
        $script:AccessReviewEntraRoster = & $script:MakeRoster

        # Read by the dot-sourced sequence through dynamic scope, exactly
        # as Start-EntraChecks.ps1's script-scope params are. $SaveSnapshot
        # is on so the Snapshot assertion below is real: with the
        # campaign-only gate removed, the save block would fire.
        $OutputDirectory = $script:Tmp
        $AccessReviewAction = 'Open'
        $AccessReviewDirectory = Join-Path $script:Tmp 'campaigns'
        $CampaignId = ''
        $OpenAccessReviewCampaign = $false
        $SaveSnapshot = $true
        $null = $OutputDirectory, $AccessReviewAction, $AccessReviewDirectory, $CampaignId,
        $OpenAccessReviewCampaign, $SaveSnapshot
    }

    It 'emits no Modules / Report / Snapshot / SOC2 phase events' {
        $seen = New-Object System.Collections.Generic.List[object]
        $sink = { param($e) $seen.Add($e) | Out-Null }
        # -DoCompareWithLast + $SaveSnapshot arm BOTH snapshot blocks; only
        # the campaign-only gate keeps them quiet.
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @() -AccessReviewOnly -DoCompareWithLast `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EventSink $sink

        foreach ($phase in 'Modules', 'Report', 'SOC2', 'Snapshot') {
            @($seen | Where-Object { $_.type -eq 'phase.started' -and $_.phase -eq $phase }).Count |
                Should -Be 0 -Because "a campaign-only run must not run the $phase phase"
        }
        @($seen | Where-Object { $_.type -eq 'phase.started' -and $_.phase -eq 'AccessReview' }).Count | Should -Be 1
        Should -Invoke Invoke-ModuleAssessment -Times 0 -Exactly
        Should -Invoke Export-AssessmentResult -Times 0 -Exactly
        Should -Invoke Invoke-SOC2ReadinessIfEnabled -Times 0 -Exactly
        $seq.Manifest | Should -Not -BeNullOrEmpty
    }

    It 'still produces a run.result with the campaign artifacts' {
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @() -AccessReviewOnly `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EmitEvents

        $seq.Manifest.type | Should -BeExactly 'run.result'
        $seq.Manifest.status | Should -BeExactly 'Succeeded'
        @($seq.Manifest.artifacts | ForEach-Object { $_.kind }) | Should -Contain 'worksheet'
        @($seq.Manifest.summary.modulesRun).Count | Should -Be 0
    }
}

Describe 'Campaign close — an incomplete worksheet is a non-fatal outcome' {

    BeforeEach {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeEnv
        }
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeBetaPage
        }
        Mock Invoke-ModuleAssessment { [pscustomobject]@{ Duration = [timespan]::Zero; Errors = @(); Modules = @{} } }
        Mock Export-AssessmentResult { $script:Tmp }
        Mock Invoke-SOC2ReadinessIfEnabled { }

        $script:Tmp = Join-Path $TestDrive ("close-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $script:Findings = @()
        $script:AccessReviewEntraRoster = $null
        $script:CampaignRoot = Join-Path $script:Tmp 'campaigns'

        # Open a campaign and leave the worksheet untouched (no decisions,
        # no sign-off) — the state a close must refuse.
        $script:Opened = Invoke-AccessReviewPhase -Action 'Open' -TenantName 'Contoso' `
            -CampaignDirectory $script:CampaignRoot -EntraRoster (& $script:MakeRoster)

        $OutputDirectory = $script:Tmp
        $AccessReviewAction = 'Close'
        $AccessReviewDirectory = $script:CampaignRoot
        $CampaignId = $script:Opened.CampaignId
        $OpenAccessReviewCampaign = $false
        # Remediation is opt-in; this test is about the GENERATOR's own
        # refusal, so opt in via the merged-config seam Get-AccessReviewConfig
        # consults first - this call drives the sequence directly, so there is
        # no -ConfigFile to thread.
        $script:Config = @{ AccessReview = @{ EnableRemediation = $true } }
        $ConfigFile = Join-Path $script:Tmp 'ar-enabled.config.json'
        @{ AccessReview = @{ EnableRemediation = $true } } | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $ConfigFile -Encoding UTF8
        $null = $OutputDirectory, $AccessReviewAction, $AccessReviewDirectory, $CampaignId,
        $OpenAccessReviewCampaign, $ConfigFile
    }

    AfterEach {
        # Do not leak the opt-in into other Describes.
        $script:Config = $null
    }

    It 'emits a non-fatal accessReview.failed, fails the phase, and still reaches run.result' {
        $script:Opened.Success | Should -BeTrue -Because ($script:Opened.FailureReason)

        $seen = New-Object System.Collections.Generic.List[object]
        $sink = { param($e) $seen.Add($e) | Out-Null }
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @() -AccessReviewOnly `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EventSink $sink

        $seq.Manifest | Should -Not -BeNullOrEmpty
        $seq.Manifest.type | Should -BeExactly 'run.result'

        $err = @($seq.Manifest.errors | Where-Object { $_.code -eq 'accessReview.failed' })
        $err.Count | Should -Be 1
        $err[0].fatal | Should -BeFalse
        $err[0].message | Should -Match 'Worksheet validation failed'
        $err[0].remediation | Should -Not -BeNullOrEmpty

        $done = @($seen | Where-Object { $_.type -eq 'phase.completed' -and $_.phase -eq 'AccessReview' })
        $done.Count | Should -Be 1
        $done[0].status | Should -BeExactly 'failed'

        # Phases stay balanced even on the refusal path.
        $started = @($seen | Where-Object { $_.type -eq 'phase.started' } | ForEach-Object { $_.phase } | Sort-Object)
        $completed = @($seen | Where-Object { $_.type -eq 'phase.completed' } | ForEach-Object { $_.phase } | Sort-Object)
        $started | Should -Be $completed
    }

    It 'leaves the campaign Open' {
        $null = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @() -AccessReviewOnly `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EmitEvents

        $meta = Get-Content -LiteralPath (Join-Path $script:Opened.Directory 'campaign.json') -Raw | ConvertFrom-Json
        $meta.Status | Should -BeExactly 'Open'
        Test-Path -LiteralPath (Join-Path $script:Opened.Directory 'roster-final.json') | Should -BeFalse
    }
}

Describe 'Campaign close — a report render fault does not invalidate the close' {

    BeforeEach {
        $script:Root = Join-Path $TestDrive ("render-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $script:Camp = Join-Path $script:Root 'camp-1'
        $null = New-Item -Path $script:Camp -ItemType Directory -Force
        # The evidence a completed close leaves behind — it must still ride
        # the artifact channel even when the HTML render blows up.
        Set-Content -LiteralPath (Join-Path $script:Camp 'review-worksheet.csv') -Value 'ObjectId' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $script:Camp 'manifest.json') -Value '{}' -Encoding UTF8

        Mock Complete-AccessReviewCampaign {
            @{ Success = $true; FailureReason = $null; CampaignId = 'camp-1'; Status = 'Closed'; Directory = $script:Camp }
        }
        Mock New-AccessReviewReport { throw 'Access to the path AccessReview-Report.html is denied.' }
    }

    It 'keeps Success, records the artifacts, and warns instead of failing the phase' {
        $ctx = & $script:MakeCtx 'ar-render-fault' $script:Root
        $r = Invoke-AccessReviewPhase -Action 'Close' -CampaignDirectory $script:Root -CampaignId 'camp-1' -Context $ctx

        $r.Success | Should -BeTrue -Because 'the campaign is already Closed on disk'
        $r.ReportError | Should -Match 'denied'

        @($ctx.Artifacts | ForEach-Object { $_.kind }) | Should -Contain 'worksheet'
        @($ctx.Artifacts | ForEach-Object { $_.kind }) | Should -Contain 'manifest'

        $done = @($ctx.Events | Where-Object { $_.type -eq 'phase.completed' -and $_.phase -eq 'AccessReview' })
        $done.Count | Should -Be 1
        $done[0].status | Should -BeExactly 'ok'
        # .Count direct: @() around an empty List[object] throws on pwsh 7.6.
        $ctx.Errors.Count | Should -Be 0
        @($ctx.Warnings | Where-Object { $_.code -eq 'accessReview.reportFailed' }).Count | Should -Be 1
    }
}

Describe 'Invoke-AccessReviewPhase — Remediate' {

    BeforeEach {
        $script:RemRoot = Join-Path $TestDrive ("rem-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $script:RemCamp = Join-Path $script:RemRoot 'camp-closed'
        $null = New-Item -Path $script:RemCamp -ItemType Directory -Force

        # What the generator produces: a SIBLING of the campaign folder, so
        # the sealed bundle still verifies against its own manifest.
        $remOut = Join-Path (Join-Path $script:RemRoot 'remediation') 'camp-closed'
        $null = New-Item -Path $remOut -ItemType Directory -Force
        $script:RemScript = Join-Path $remOut 'remediate-camp-closed.ps1'
        $script:RemPlan = Join-Path $remOut 'remediation-plan.md'
        Set-Content -LiteralPath $script:RemScript -Value '# generated' -Encoding UTF8
        Set-Content -LiteralPath $script:RemPlan -Value '# plan' -Encoding UTF8

        # The generator has its own 33-test suite; this file tests the wiring.
        # The mock still binds against the real signature, so a wrong
        # parameter name on the call site fails here.
        # Remediation ships disabled; these tests exercise the wiring behind
        # the opt-in, so they supply a config that turns it on. The gate
        # itself is covered separately below.
        $script:RemConfig = Join-Path $script:RemRoot 'ar-enabled.config.json'
        @{ AccessReview = @{ EnableRemediation = $true } } | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $script:RemConfig -Encoding UTF8

        Mock New-AccessReviewRemediationScript {
            @{ Success = $true; FailureReason = $null; ScriptPath = $script:RemScript; PlanPath = $script:RemPlan; ActionCount = 3; ManualCount = 1; SkippedCount = 2 }
        }
    }

    It 'refuses when remediation is not opted in, before loading the generator' {
        # The shipped default. A tenant turns this on knowingly - discovering
        # the button and having it emit a privileged-access removal script is
        # not a reasonable default.
        $off = Join-Path $script:RemRoot 'ar-disabled.config.json'
        @{ AccessReview = @{ EnableRemediation = $false } } | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $off -Encoding UTF8

        $ctx = & $script:MakeCtx 'ar-remediate-off' $script:RemRoot
        $r = Invoke-AccessReviewPhase -Action 'Remediate' -CampaignDirectory $script:RemRoot `
            -CampaignId 'camp-closed' -ConfigPath $off -Context $ctx

        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'EnableRemediation'
        # Refused before the generator is reached, not after it ran.
        Should -Invoke New-AccessReviewRemediationScript -Times 0 -Exactly
        @($ctx.Artifacts).Count | Should -Be 0
    }

    It 'ships disabled: the repo config does not opt in' {
        # Guards the shipped default itself, so enabling it in config/ has to
        # be a deliberate edit that fails this test loudly.
        (Get-AccessReviewConfig -ConfigPath $script:RepoConfigPath).EnableRemediation |
            Should -BeFalse
    }

    It 'runs the phase and records the script + plan artifacts' {
        $ctx = & $script:MakeCtx 'ar-remediate' $script:RemRoot
        $r = Invoke-AccessReviewPhase -Action 'Remediate' -CampaignDirectory $script:RemRoot `
            -CampaignId 'camp-closed' -ConfigPath $script:RemConfig -Context $ctx

        $r.Success | Should -BeTrue -Because ($r.FailureReason)
        $r.ActionCount | Should -Be 3
        $r.ManualCount | Should -Be 1
        Should -Invoke New-AccessReviewRemediationScript -Times 1 -Exactly `
            -ParameterFilter { $CampaignDirectory -eq $script:RemCamp }

        @($ctx.Events | Where-Object { $_.type -eq 'phase.started' -and $_.phase -eq 'AccessReview' }).Count |
            Should -Be 1
        $done = @($ctx.Events | Where-Object { $_.type -eq 'phase.completed' -and $_.phase -eq 'AccessReview' })
        $done.Count | Should -Be 1
        $done[0].status | Should -BeExactly 'ok'

        $kinds = @($ctx.Artifacts | ForEach-Object { $_.kind })
        $kinds | Should -Contain 'remediation-script'
        $kinds | Should -Contain 'remediation-plan'
        # Remediate produced neither of these — they belong to the campaign
        # itself, and claiming them here would misreport what the run did.
        $kinds | Should -Not -Contain 'worksheet'
        $kinds | Should -Not -Contain 'manifest'

        ($ctx.Artifacts | Where-Object { $_.kind -eq 'remediation-script' }).path |
            Should -BeLike '*remediate-camp-closed.ps1'
    }

    It 'puts the action counts on the event path, not just the console' {
        # A path alone does not say whether the script is a no-op or removes
        # ten role assignments. The console menu prints the three counts;
        # an event consumer (the GUI) must get them too.
        $ctx = & $script:MakeCtx 'ar-counts' $script:RemRoot
        $null = Invoke-AccessReviewPhase -Action 'Remediate' -CampaignDirectory $script:RemRoot `
            -CampaignId 'camp-closed' -ConfigPath $script:RemConfig -Context $ctx

        $counts = @($ctx.Events | Where-Object { $_.type -eq 'log' -and $_.message -match 'Actions=' })
        $counts.Count | Should -Be 1
        $counts[0].message | Should -Match 'Actions=3'
        $counts[0].message | Should -Match 'Manual=1'
        $counts[0].message | Should -Match 'Skipped=2'
    }

    It 'rejects a missing -CampaignId before calling the generator' {
        $r = Invoke-AccessReviewPhase -Action 'Remediate' -CampaignDirectory $script:RemRoot -ConfigPath $script:RemConfig
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'CampaignId'
        Should -Invoke New-AccessReviewRemediationScript -Times 0 -Exactly
    }

    It 'Add-EcfArtifact accepts both remediation kinds' {
        # i.e. the runner's ValidateSet was actually extended — without this
        # the phase throws at runtime the first time it emits an artifact.
        $ctx = & $script:MakeCtx 'ar-kinds' $script:RemRoot
        { Add-EcfArtifact -Context $ctx -Kind 'remediation-script' -Path $script:RemScript } | Should -Not -Throw
        { Add-EcfArtifact -Context $ctx -Kind 'remediation-plan' -Path $script:RemPlan } | Should -Not -Throw
        $ctx.Artifacts.Count | Should -Be 2
    }
}

Describe 'Remediate — a generator refusal is a non-fatal outcome' {

    BeforeEach {
        Mock Invoke-ModuleAssessment { [pscustomobject]@{ Duration = [timespan]::Zero; Errors = @(); Modules = @{} } }
        Mock Export-AssessmentResult { $script:Tmp }
        Mock Invoke-SOC2ReadinessIfEnabled { }
        Mock New-AccessReviewRemediationScript {
            @{ Success = $false; FailureReason = "Campaign 'camp-open' is Open, not Closed. Nothing generated." }
        }

        $script:Tmp = Join-Path $TestDrive ("remfail-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $script:CampaignRoot = Join-Path $script:Tmp 'campaigns'
        $null = New-Item -Path (Join-Path $script:CampaignRoot 'camp-open') -ItemType Directory -Force
        $script:Findings = @()
        $script:AccessReviewEntraRoster = $null

        $OutputDirectory = $script:Tmp
        $AccessReviewAction = 'Remediate'
        $AccessReviewDirectory = $script:CampaignRoot
        $CampaignId = 'camp-open'
        $OpenAccessReviewCampaign = $false
        $null = $OutputDirectory, $AccessReviewAction, $AccessReviewDirectory, $CampaignId, $OpenAccessReviewCampaign
    }

    It 'carries the reason verbatim, fails the phase, and still reaches run.result' {
        $seen = New-Object System.Collections.Generic.List[object]
        $sink = { param($e) $seen.Add($e) | Out-Null }
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @() -AccessReviewOnly `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EventSink $sink

        $seq.Manifest | Should -Not -BeNullOrEmpty
        $seq.Manifest.type | Should -BeExactly 'run.result'

        $err = @($seq.Manifest.errors | Where-Object { $_.code -eq 'accessReview.failed' })
        $err.Count | Should -Be 1
        $err[0].fatal | Should -BeFalse
        # Since remediation became opt-in, the gate refuses on this path
        # before the generator is reached, so this is the refusal that
        # surfaces here. The property under test is unchanged - a refusal is
        # non-fatal, reaches run.result, and carries its reason verbatim.
        # The generator's own "campaign is Open" refusal is covered by
        # Tests/AccessReview-Remediation.Tests.ps1 against the real module.
        $err[0].message | Should -Match 'EnableRemediation'
        $err[0].message | Should -Match 'never run by EntraChecks'

        $done = @($seen | Where-Object { $_.type -eq 'phase.completed' -and $_.phase -eq 'AccessReview' })
        $done.Count | Should -Be 1
        $done[0].status | Should -BeExactly 'failed'
        @($seq.Manifest.artifacts).Count | Should -Be 0
    }
}

Describe 'Remediate — the run never authenticates' {

    # The generator reads campaign files and touches no tenant, so producing
    # a script must not cost a sign-in. Two halves: the auth options a
    # Remediate run builds, and the run those options actually produce.

    BeforeEach {
        $script:Tmp = Join-Path $TestDrive ("noauth-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $script:CampaignRoot = Join-Path $script:Tmp 'campaigns'
        $null = New-Item -Path (Join-Path $script:CampaignRoot 'camp-closed') -ItemType Directory -Force
        $remOut = Join-Path (Join-Path $script:CampaignRoot 'remediation') 'camp-closed'
        $null = New-Item -Path $remOut -ItemType Directory -Force
        $script:RemScript = Join-Path $remOut 'remediate-camp-closed.ps1'
        Set-Content -LiteralPath $script:RemScript -Value '# generated' -Encoding UTF8

        Mock New-AccessReviewRemediationScript {
            @{ Success = $true; FailureReason = $null; ScriptPath = $script:RemScript; PlanPath = ''; ActionCount = 1; ManualCount = 0; SkippedCount = 0 }
        }
        Mock Connect-EntraCheck { throw 'a Remediate run must never sign in' }
        Mock Invoke-ModuleAssessment { [pscustomobject]@{ Duration = [timespan]::Zero; Errors = @(); Modules = @{} } }
        Mock Export-AssessmentResult { $script:Tmp }
        Mock Invoke-SOC2ReadinessIfEnabled { }
        $script:Findings = @()
        $script:AccessReviewEntraRoster = $null
    }

    It 'New-EcfAuthRunOptions hands back no auth action for Remediate' {
        $SkipAuthentication = $false
        $AuthMethod = 'Interactive'
        $AccessReviewAction = 'Remediate'
        $null = $SkipAuthentication, $AuthMethod, $AccessReviewAction

        $opts = New-EcfAuthRunOptions
        $opts.Action | Should -BeNullOrEmpty
        $opts.Method | Should -BeExactly 'Skip'
    }

    It 'the very same settings DO produce an auth action for Report' {
        # Keeps the assertion above honest: it is Remediate that suppresses
        # auth, not an unset ambient parameter.
        $SkipAuthentication = $false
        $AuthMethod = 'Interactive'
        $AccessReviewAction = 'Report'
        $null = $SkipAuthentication, $AuthMethod, $AccessReviewAction

        $opts = New-EcfAuthRunOptions
        $opts.Action | Should -Not -BeNullOrEmpty
        $opts.Method | Should -BeExactly 'Interactive'
    }

    It 'the echoed invocation params report the auth decision that ran' {
        # These params become run.started + the run-history manifest. This
        # is audit metadata about an auth decision, so it must not claim an
        # Interactive sign-in for a run that never signed in.
        $SkipAuthentication = $false
        $AuthMethod = 'Interactive'
        $AccessReviewAction = 'Remediate'
        $null = $SkipAuthentication, $AuthMethod, $AccessReviewAction

        $p = Get-EcfInvocationParams -ResolvedTenant 'Contoso'
        $p.AuthMethod | Should -BeExactly 'Skip'
        $p.SkipAuthentication | Should -BeTrue
    }

    It 'the same params still report Interactive for Report' {
        # Keeps the assertion above honest: it is Remediate that rewrites
        # the echoed pair, not a blanket 'Skip'.
        $SkipAuthentication = $false
        $AuthMethod = 'Interactive'
        $AccessReviewAction = 'Report'
        $null = $SkipAuthentication, $AuthMethod, $AccessReviewAction

        $p = Get-EcfInvocationParams -ResolvedTenant 'Contoso'
        $p.AuthMethod | Should -BeExactly 'Interactive'
        $p.SkipAuthentication | Should -BeFalse
    }

    It 'a full -Mode AccessReview Remediate run emits no auth.* events, no Auth phase, and records Skip' {
        $TenantName = 'Contoso'
        $SkipAuthentication = $false
        $AuthMethod = 'Interactive'
        $EmitEvents = $true
        $OutputDirectory = $script:Tmp
        $AccessReviewAction = 'Remediate'
        $AccessReviewDirectory = $script:CampaignRoot
        $CampaignId = 'camp-closed'
        $OpenAccessReviewCampaign = $false
        $ConfigFile = Join-Path $script:Tmp 'ar-enabled-e2e.config.json'
        @{ AccessReview = @{ EnableRemediation = $true } } | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $ConfigFile -Encoding UTF8
        $null = $TenantName, $SkipAuthentication, $AuthMethod, $EmitEvents, $OutputDirectory,
        $AccessReviewAction, $AccessReviewDirectory, $CampaignId, $OpenAccessReviewCampaign, $ConfigFile

        # The NDJSON contract is written to real stdout ([Console]::Out), not
        # the PowerShell pipeline, so the console is redirected for the call.
        $writer = New-Object System.IO.StringWriter
        $prev = [Console]::Out
        try {
            [Console]::SetOut($writer)
            Start-AccessReviewMode
        }
        finally {
            [Console]::SetOut($prev)
        }

        $events = @($writer.ToString() -split "`r?`n" |
                Where-Object { $_.Trim().StartsWith('{') } |
                ForEach-Object { $_ | ConvertFrom-Json })

        $events.Count | Should -BeGreaterThan 0
        @($events | Where-Object { ([string]$_.type).StartsWith('auth.') }).Count |
            Should -Be 0 -Because 'generating a script must not cost a sign-in'
        @($events | Where-Object { $_.phase -eq 'Auth' }).Count | Should -Be 0
        Should -Invoke Connect-EntraCheck -Times 0 -Exactly

        # The permanent record of that decision, as a consumer reads it.
        $started = @($events | Where-Object { $_.type -eq 'run.started' })
        $started.Count | Should -Be 1
        $started[0].params.AuthMethod | Should -BeExactly 'Skip'
        $started[0].params.SkipAuthentication | Should -BeTrue

        @($events | Where-Object { $_.type -eq 'phase.started' -and $_.phase -eq 'AccessReview' }).Count | Should -Be 1
        $result = @($events | Where-Object { $_.type -eq 'run.result' })
        $result.Count | Should -Be 1
        @($result[0].artifacts | ForEach-Object { $_.kind }) | Should -Contain 'remediation-script'
    }
}

Describe 'In concert — AccessReview runs between Modules and SOC2' {

    BeforeEach {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeEnv
        }
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeBetaPage
        }

        $script:Tmp = Join-Path $TestDrive ("concert-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $script:ReportDir = Join-Path $script:Tmp 'report'
        $null = New-Item -Path $script:ReportDir -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $script:ReportDir 'EntraChecks-cockpit.html') -Value '<html></html>' -Encoding UTF8

        Mock Invoke-ModuleAssessment { [pscustomobject]@{ Duration = [timespan]::FromMinutes(1); Errors = @(); Modules = @{ Core = 'ok' } } }
        Mock Export-AssessmentResult { $script:ReportDir }
        Mock Invoke-SOC2ReadinessIfEnabled { }

        $script:Findings = @([pscustomobject]@{ Severity = 'High'; Description = 'h' })
        # The roster the run "already built" (published by
        # Export-AssessmentResult on a real -EmitPrivilegedRoster run).
        $script:AccessReviewEntraRoster = & $script:MakeRoster

        $OutputDirectory = $script:Tmp
        $AccessReviewAction = ''
        $AccessReviewDirectory = Join-Path $script:Tmp 'campaigns'
        $CampaignId = ''
        $OpenAccessReviewCampaign = $true
        $GenerateComprehensiveReport = $false
        $GenerateExecutiveSummary = $false
        $GenerateExcelReport = $false
        $GenerateRemediationScripts = $false
        $HtmlReportSet = 'Cockpit'
        $HtmlDeepDiveDomains = @()
        $null = $OutputDirectory, $AccessReviewAction, $AccessReviewDirectory, $CampaignId,
        $OpenAccessReviewCampaign, $GenerateComprehensiveReport, $GenerateExecutiveSummary,
        $GenerateExcelReport, $GenerateRemediationScripts, $HtmlReportSet, $HtmlDeepDiveDomains
    }

    It 'orders the AccessReview phase after Modules and before SOC2' {
        $seen = New-Object System.Collections.Generic.List[object]
        $sink = { param($e) $seen.Add($e) | Out-Null }
        $null = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EventSink $sink

        $starts = @($seen | Where-Object { $_.type -eq 'phase.started' } | ForEach-Object { [string]$_.phase })
        $starts | Should -Contain 'AccessReview'
        $starts.IndexOf('Modules') | Should -BeLessThan $starts.IndexOf('AccessReview')
        $starts.IndexOf('AccessReview') | Should -BeLessThan $starts.IndexOf('SOC2')
    }

    It 'keeps the normal pipeline intact and creates the campaign from the run roster' {
        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EmitEvents

        Should -Invoke Invoke-ModuleAssessment -Times 1 -Exactly
        Should -Invoke Export-AssessmentResult -Times 1 -Exactly
        Should -Invoke Invoke-SOC2ReadinessIfEnabled -Times 1 -Exactly
        $seq.Manifest.status | Should -BeExactly 'Succeeded'

        $campaigns = @(Get-ChildItem -LiteralPath (Join-Path $script:Tmp 'campaigns') -Directory)
        $campaigns.Count | Should -Be 1
        $rows = Import-Csv -LiteralPath (Join-Path $campaigns[0].FullName 'review-worksheet.csv')
        @($rows | Where-Object { $_.DisplayName -eq 'Reused Roster SP' }).Count | Should -Be 1
    }

    It 'honours AccessReview.Enabled from the run -ConfigFile, not the repo default' {
        $cfgPath = Join-Path $script:Tmp 'run-config.json'
        $fromCfg = Join-Path $script:Tmp 'from-config'
        @{ AccessReview = @{ Enabled = $true; OutputDirectory = $fromCfg } } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $cfgPath -Encoding UTF8

        # Neither the switch nor the shipped config enables this — only the
        # -ConfigFile the run was launched with can.
        $OpenAccessReviewCampaign = $false
        $AccessReviewDirectory = ''
        $ConfigFile = $cfgPath
        $null = $OpenAccessReviewCampaign, $AccessReviewDirectory, $ConfigFile

        $seen = New-Object System.Collections.Generic.List[object]
        $sink = { param($e) $seen.Add($e) | Out-Null }
        $null = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EventSink $sink

        @($seen | Where-Object { $_.type -eq 'phase.started' -and $_.phase -eq 'AccessReview' }).Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $fromCfg -Directory).Count | Should -Be 1
    }

    It 'stays off when neither the switch nor config asks for it' {
        $OpenAccessReviewCampaign = $false
        $null = $OpenAccessReviewCampaign
        $seen = New-Object System.Collections.Generic.List[object]
        $sink = { param($e) $seen.Add($e) | Out-Null }
        $null = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } -EventSink $sink

        @($seen | Where-Object { $_.type -eq 'phase.started' -and $_.phase -eq 'AccessReview' }).Count |
            Should -Be 0 -Because 'AccessReview.Enabled is false in the shipped config'
    }
}
