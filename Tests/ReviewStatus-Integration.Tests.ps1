<#
.SYNOPSIS
    Pester 5 integration tests for Review-Status-Plan PR 4 — surfaces beyond
    the renderer that need to understand the REVIEW status.

.DESCRIPTION
    PR 4 wires REVIEW into three downstream surfaces:

    1. DeltaReporting (Compare-ComplianceSnapshots)
       - WARNING<->REVIEW transitions land in RecategorisedFindings, not in
         StatusChanges. Reason: PR 3 globally re-tagged 26 emissions, and we
         don't want every existing snapshot diff to look like 26 regressions
         (or improvements, depending on direction). Recategorisation is its
         own bucket.
       - New REVIEW findings land in NewReviewItems (not NewIssues).
       - Resolved REVIEW findings land in ResolvedReviewItems.

    2. ComplianceMapping (Get-ComplianceGapReport)
       - REVIEW findings count separately as ManualReviewFindings (not
         FailedFindings).
       - Per framework, REVIEW findings populate ManualReviewControls — so
         auditors can see which controls have manual-review items pending,
         distinct from controls with hard failures.

    3. SOC 2 (Get-SOC2Summary)
       - byFamily entries gain a Review counter alongside Pass/Fail/Warning/Info.

    Run: Invoke-Pester -Path Tests/ReviewStatus-Integration.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-DeltaReporting.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2.psm1') -Force

    function New-TestSnapshot {
        param(
            [string]$Id,
            [object[]]$Findings
        )
        return @{
            SnapshotId = $Id
            CreatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            TenantName = 'IntegrationTest'
            Scores = @{
                SecureScore = $null
                DefenderOverall = $null
                AzurePolicyOverall = $null
                PurviewOverall = $null
            }
            Sources = @{
                Findings = @{ Data = $Findings }
            }
        }
    }
}

# ============================================================================
# DeltaReporting — recategorisation
# ============================================================================

Describe 'Compare-ComplianceSnapshots — REVIEW recategorisation (PR 4)' {

    It 'classifies WARNING -> REVIEW as RecategorisedFindings, not a regression' {
        $baseline = New-TestSnapshot -Id 'B' -Findings @(
            [pscustomobject]@{ CheckName = 'OAuth Consent'; Object = 'app-1'; Status = 'WARNING'; Description = 'oauth grant' }
        )
        $current = New-TestSnapshot -Id 'C' -Findings @(
            [pscustomobject]@{ CheckName = 'OAuth Consent'; Object = 'app-1'; Status = 'REVIEW'; Description = 'oauth grant' }
        )

        $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baseline -CurrentSnapshot $current

        $delta.FindingChanges.RecategorisedFindings.Count | Should -Be 1
        $delta.Summary.RecategorisedCount | Should -Be 1
        $delta.FindingChanges.StatusChanges.Count | Should -Be 0
        $delta.Summary.RegressionCount | Should -Be 0
        $delta.Summary.ImprovementCount | Should -Be 0

        $entry = $delta.FindingChanges.RecategorisedFindings[0]
        $entry.OldStatus | Should -Be 'WARNING'
        $entry.NewStatus | Should -Be 'REVIEW'
    }

    It 'classifies REVIEW -> WARNING as RecategorisedFindings, not an improvement' {
        $baseline = New-TestSnapshot -Id 'B' -Findings @(
            [pscustomobject]@{ CheckName = 'OAuth Consent'; Object = 'app-1'; Status = 'REVIEW'; Description = 'oauth grant' }
        )
        $current = New-TestSnapshot -Id 'C' -Findings @(
            [pscustomobject]@{ CheckName = 'OAuth Consent'; Object = 'app-1'; Status = 'WARNING'; Description = 'oauth grant' }
        )

        $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baseline -CurrentSnapshot $current

        $delta.FindingChanges.RecategorisedFindings.Count | Should -Be 1
        $delta.Summary.RecategorisedCount | Should -Be 1
        $delta.Summary.ImprovementCount | Should -Be 0
        $delta.Summary.RegressionCount | Should -Be 0
    }

    It 'tracks new REVIEW findings under NewReviewItems, not NewIssues' {
        # Ballast finding shared by both snapshots so the comparator's data
        # guard passes. The interesting assertion is on the NEW finding only.
        $shared = [pscustomobject]@{ CheckName = 'Baseline Check'; Object = 'b'; Status = 'OK'; Description = 'shared' }
        $baseline = New-TestSnapshot -Id 'B' -Findings @($shared)
        $current = New-TestSnapshot -Id 'C' -Findings @(
            $shared,
            [pscustomobject]@{ CheckName = 'OAuth Consent'; Object = 'app-new'; Status = 'REVIEW'; Description = 'new oauth grant' }
        )

        $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baseline -CurrentSnapshot $current

        $delta.FindingChanges.NewReviewItems.Count | Should -Be 1
        $delta.Summary.NewReviewCount | Should -Be 1
        $delta.FindingChanges.NewIssues.Count | Should -Be 0
        $delta.Summary.NewIssueCount | Should -Be 0
    }

    It 'tracks disappeared REVIEW findings under ResolvedReviewItems, not ResolvedIssues' {
        $shared = [pscustomobject]@{ CheckName = 'Baseline Check'; Object = 'b'; Status = 'OK'; Description = 'shared' }
        $baseline = New-TestSnapshot -Id 'B' -Findings @(
            $shared,
            [pscustomobject]@{ CheckName = 'OAuth Consent'; Object = 'app-old'; Status = 'REVIEW'; Description = 'old oauth grant' }
        )
        $current = New-TestSnapshot -Id 'C' -Findings @($shared)

        $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baseline -CurrentSnapshot $current

        $delta.FindingChanges.ResolvedReviewItems.Count | Should -Be 1
        $delta.Summary.ResolvedReviewCount | Should -Be 1
        $delta.FindingChanges.ResolvedIssues.Count | Should -Be 0
        $delta.Summary.ResolvedIssueCount | Should -Be 0
    }

    It 'still classifies FAIL -> OK as a real improvement (no REVIEW regression)' {
        $baseline = New-TestSnapshot -Id 'B' -Findings @(
            [pscustomobject]@{ CheckName = 'MFA Admin'; Object = 'admin-1'; Status = 'FAIL'; Description = 'admin missing MFA' }
        )
        $current = New-TestSnapshot -Id 'C' -Findings @(
            [pscustomobject]@{ CheckName = 'MFA Admin'; Object = 'admin-1'; Status = 'OK'; Description = 'admin missing MFA' }
        )

        $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baseline -CurrentSnapshot $current

        $delta.Summary.ImprovementCount | Should -Be 1
        $delta.Summary.RecategorisedCount | Should -Be 0
    }
}

# ============================================================================
# ComplianceMapping — manual-review surface
# ============================================================================

Describe 'Get-ComplianceGapReport — ManualReviewFindings (PR 4)' {

    It 'counts REVIEW findings under ManualReviewFindings, not FailedFindings' {
        $findings = @(
            [pscustomobject]@{ Type = 'MFA_AdminDisabled'; Status = 'FAIL'; Object = 'a' }
            [pscustomobject]@{ Type = 'AppConsent_UserAllowed'; Status = 'REVIEW'; Object = 'b' }
            [pscustomobject]@{ Type = 'AppConsent_UserAllowed'; Status = 'REVIEW'; Object = 'c' }
            [pscustomobject]@{ Type = 'GuestUser_Excessive'; Status = 'WARNING'; Object = 'd' }
            [pscustomobject]@{ Type = 'Default'; Status = 'OK'; Object = 'e' }
        )

        $report = Get-ComplianceGapReport -Findings $findings -Framework 'All'

        $report.ManualReviewFindings | Should -Be 2
        # FAIL + WARNING continue to land in FailedFindings — REVIEW does not.
        $report.FailedFindings | Should -Be 2
    }

    It 'populates ManualReviewControls separately from Controls per framework' {
        $findings = @(
            [pscustomobject]@{ Type = 'AppConsent_UserAllowed'; Status = 'REVIEW'; Object = 'b' }
        )

        $report = Get-ComplianceGapReport -Findings $findings -Framework 'CIS'

        # FrameworkGaps.<fw> is a hashtable — use ContainsKey to introspect.
        $report.FrameworkGaps.CIS.ContainsKey('ManualReviewControls') | Should -Be $true
        $report.FrameworkGaps.CIS.ContainsKey('ManualReviewControlsCount') | Should -Be $true
        # Controls (failing bucket) stays empty when no FAIL/WARNING findings exist.
        $report.FrameworkGaps.CIS.ControlsAffected | Should -Be 0
    }
}

# ============================================================================
# SOC 2 — byFamily.Review counter
# ============================================================================

Describe 'Get-SOC2Summary — byFamily.Review counter (PR 4)' {

    It 'increments byFamily[X].Review when a REVIEW finding maps to family X' {
        # Minimal catalog: one CC control. The summary doesn't need the full
        # production catalog — we exercise byFamily counting via a finding
        # that references CC1.1 in its TSC mappings.
        $catalog = @(
            [pscustomobject]@{ Id = 'CC1.1'; Family = 'CC'; Automation = 'Automated' }
        )

        # Findings carrying a TSC reference. Get-FindingTSCReferences checks
        # explicit TSCReferences first, then falls back to
        # ComplianceMappings.SOC2.Criteria — the latter is the standard shape
        # populated by Add-ComplianceMapping during the assessment run.
        $findings = @(
            [pscustomobject]@{
                CheckName = 'OAuth Consent'
                Object = 'app-1'
                Status = 'REVIEW'
                Description = 'review me'
                ComplianceMappings = @{ SOC2 = @{ Criteria = @('CC1.1') } }
            }
        )

        $summary = Get-SOC2Summary -Findings $findings -Catalog $catalog
        $summary.ByFamily.CC.Review | Should -Be 1
        $summary.ByFamily.CC.Warning | Should -Be 0
        $summary.ByFamily.CC.Fail | Should -Be 0
    }

    It 'still routes FAIL/WARNING to their existing buckets (no regression)' {
        $catalog = @(
            [pscustomobject]@{ Id = 'CC1.1'; Family = 'CC'; Automation = 'Automated' }
        )
        $findings = @(
            [pscustomobject]@{
                Status = 'FAIL'
                ComplianceMappings = @{ SOC2 = @{ Criteria = @('CC1.1') } }
            }
            [pscustomobject]@{
                Status = 'WARNING'
                ComplianceMappings = @{ SOC2 = @{ Criteria = @('CC1.1') } }
            }
        )

        $summary = Get-SOC2Summary -Findings $findings -Catalog $catalog
        $summary.ByFamily.CC.Fail | Should -Be 1
        $summary.ByFamily.CC.Warning | Should -Be 1
        $summary.ByFamily.CC.Review | Should -Be 0
    }
}
