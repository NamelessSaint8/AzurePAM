<#
.SYNOPSIS
    Pester 5 test suite for the REVIEW finding status (PR 1 of Review-Status-Plan).

.DESCRIPTION
    Confirms that:
    1. Add-RiskScoring overrides RiskLevel to 'Review' when Status='REVIEW',
       regardless of underlying RiskScore.
    2. RiskScore is still computed normally (so the Review Queue can be sorted
       by underlying risk magnitude — that's the design choice).
    3. Get-RiskSummary returns ReviewCount and ReviewPercent.
    4. Get-PrioritizedFindings -GroupByPriority places REVIEW items in
       'Priority 6 - Review Queue', not in the severity-banded buckets.
    5. A WARNING-status finding with the same Type still gets its normal
       severity-band classification (no spillover).

    Run: Invoke-Pester -Path Tests/RiskScoring-Review.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-RiskScoring.psm1') -Force -DisableNameChecking

    function New-TestFinding {
        param(
            [string]$Status = 'WARNING',
            [string]$Type = 'AppConsent_UserAllowed',
            [string]$Description = 'synthetic finding',
            [string]$Object = 'subject'
        )
        # AppConsent_UserAllowed has BaseRiskScore = 70 -> Get-RiskLevel(70) = 'High'.
        # Choosing this Type intentionally so the override is clearly visible.
        [pscustomobject]@{
            Time = (Get-Date)
            Status = $Status
            Type = $Type
            Object = $Object
            Description = $Description
            Remediation = 'review or fix'
        }
    }
}

Describe 'Add-RiskScoring — REVIEW override' {

    It "overrides RiskLevel to 'Review' for REVIEW-status findings, regardless of score" {
        $f = New-TestFinding -Status 'REVIEW' -Type 'AppConsent_UserAllowed'
        $scored = $f | Add-RiskScoring
        $scored.RiskLevel | Should -BeExactly 'Review'
    }

    It 'leaves RiskScore intact (still computed) for REVIEW findings — sortable by underlying risk' {
        $f = New-TestFinding -Status 'REVIEW' -Type 'AppConsent_UserAllowed'
        $scored = $f | Add-RiskScoring
        # AppConsent_UserAllowed -> base 70. Allow some adjustment headroom.
        $scored.RiskScore | Should -BeGreaterThan 0
    }

    It 'does NOT affect a WARNING-status finding with the same Type' {
        $f = New-TestFinding -Status 'WARNING' -Type 'AppConsent_UserAllowed'
        $scored = $f | Add-RiskScoring
        # Base 70 * WARNING multiplier 0.7 = 49 -> Medium (40-60 band).
        # The point of this test is "no Review override leakage", not the
        # specific band — assert anything other than Review.
        $scored.RiskLevel | Should -Not -BeExactly 'Review'
        $scored.RiskLevel | Should -BeIn @('Critical', 'High', 'Medium', 'Low', 'Info')
    }

    It "preserves 'Critical' / 'High' / etc. for non-REVIEW findings" {
        $f = New-TestFinding -Status 'FAIL' -Type 'MFA_AdminDisabled'
        $scored = $f | Add-RiskScoring
        $scored.RiskLevel | Should -BeIn @('Critical', 'High')
    }
}

Describe 'Get-RiskSummary — Review counters' {

    It 'reports ReviewCount and ReviewPercent' {
        $findings = @(
            New-TestFinding -Status 'REVIEW' -Type 'AppConsent_UserAllowed'
            New-TestFinding -Status 'REVIEW' -Type 'AppConsent_UserAllowed'
            New-TestFinding -Status 'WARNING' -Type 'AppConsent_UserAllowed'
            New-TestFinding -Status 'FAIL' -Type 'MFA_AdminDisabled'
        )
        $summary = Get-RiskSummary -Findings $findings
        $summary.ReviewCount   | Should -Be 2
        $summary.ReviewPercent | Should -Be 50.0
    }

    It 'does not double-count REVIEW items into the severity-band counters' {
        $findings = @(
            New-TestFinding -Status 'REVIEW' -Type 'AppConsent_UserAllowed'  # would be High by score
            New-TestFinding -Status 'REVIEW' -Type 'AppConsent_UserAllowed'
        )
        $summary = Get-RiskSummary -Findings $findings
        $summary.HighCount   | Should -Be 0
        $summary.ReviewCount | Should -Be 2
    }
}

Describe 'Get-PrioritizedFindings — Review Queue bucket' {

    It "places REVIEW items in 'Priority 6 - Review Queue'" {
        $findings = @(
            New-TestFinding -Status 'REVIEW' -Type 'AppConsent_UserAllowed' -Object 'oauth-1'
            New-TestFinding -Status 'WARNING' -Type 'AppConsent_UserAllowed' -Object 'oauth-2'
            New-TestFinding -Status 'FAIL' -Type 'MFA_AdminDisabled' -Object 'admin-1'
        )
        $groups = Get-PrioritizedFindings -Findings $findings -GroupByPriority
        # Get-PrioritizedFindings returns a hashtable — use ContainsKey, not
        # PSObject.Properties (which doesn't enumerate hashtable keys).
        $groups.ContainsKey('Priority 6 - Review Queue') | Should -BeTrue
        @($groups['Priority 6 - Review Queue']).Count | Should -Be 1
        $groups['Priority 6 - Review Queue'][0].Object | Should -BeExactly 'oauth-1'
    }

    It 'does not leak REVIEW items into severity-band buckets' {
        $findings = @(
            New-TestFinding -Status 'REVIEW' -Type 'AppConsent_UserAllowed' -Object 'r1'
            New-TestFinding -Status 'REVIEW' -Type 'AppConsent_UserAllowed' -Object 'r2'
        )
        $groups = Get-PrioritizedFindings -Findings $findings -GroupByPriority
        @($groups['Priority 1 - Critical & Quick Wins']).Count | Should -Be 0
        @($groups['Priority 2 - High Risk']).Count             | Should -Be 0
        @($groups['Priority 6 - Review Queue']).Count          | Should -Be 2
    }
}
