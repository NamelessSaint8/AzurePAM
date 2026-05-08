<#
.SYNOPSIS
    Pester 5 test suite for the REVIEW renderer integration (PR 2 of
    Review-Status-Plan).

.DESCRIPTION
    Confirms the REVIEW status renders as a distinct visual category
    across the three presentation surfaces:

    1. Standalone HTML report (New-EnhancedHTMLReport):
       - .risk-badge.review CSS class is emitted in the head
       - .metric-card.review CSS class is emitted in the head
       - Executive Summary shows the "Items to Review" tile
       - Findings detail uses a Review badge for REVIEW-status rows

    2. Unified report (Export-UnifiedComplianceReport):
       - "To Review" framework-card tile renders alongside Failures /
         Warnings / Passed / Informational
       - The findings table uses a purple REVIEW badge for REVIEW rows

    3. Excel All Findings sheet:
       - Get-RiskSummary surfaces ReviewCount + ReviewPercent (used by
         the Executive Summary sheet's "Items to Review" row)

    Run: Invoke-Pester -Path Tests/Reporting-Review.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-RiskScoring.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-RemediationGuidance.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Compliance.psm1') -Force

    function New-MixedFindings {
        @(
            [pscustomobject]@{ Time = (Get-Date); Status = 'FAIL'; Type = 'MFA_AdminDisabled'; Object = 'admin@x'; Description = 'admin missing MFA'; Remediation = 'Enable MFA' }
            [pscustomobject]@{ Time = (Get-Date); Status = 'REVIEW'; Type = 'AppConsent_UserAllowed'; Object = 'consent-1'; Description = 'oauth grant'; Remediation = 'Review the grant' }
            [pscustomobject]@{ Time = (Get-Date); Status = 'REVIEW'; Type = 'AppConsent_UserAllowed'; Object = 'consent-2'; Description = 'oauth grant 2'; Remediation = 'Review the grant' }
            [pscustomobject]@{ Time = (Get-Date); Status = 'WARNING'; Type = 'PasswordExpiry_Disabled'; Object = 'tenant'; Description = 'pwd never expires'; Remediation = 'Enable expiry' }
            [pscustomobject]@{ Time = (Get-Date); Status = 'OK'; Type = 'Default'; Object = 'tenant'; Description = 'good thing'; Remediation = '' }
        )
    }
}

# ============================================================================
# Standalone HTML report
# ============================================================================

Describe 'New-EnhancedHTMLReport — REVIEW palette and tile' {

    BeforeAll {
        $script:OutputPath = Join-Path $TestDrive 'standalone-review-test.html'
        $tenantInfo = [pscustomobject]@{ TenantName = 'Test Tenant'; TenantId = '00000000-0000-0000-0000-000000000000' }
        New-EnhancedHTMLReport -Findings (New-MixedFindings) -OutputPath $script:OutputPath -TenantInfo $tenantInfo -IncludeIntegrityBadge:$false | Out-Null
        $script:Html = Get-Content $script:OutputPath -Raw
    }

    It 'emits the .risk-badge.review CSS class' {
        $script:Html | Should -Match '\.risk-badge\.review\s*\{'
    }

    It 'emits the .metric-card.review CSS class' {
        $script:Html | Should -Match '\.metric-card\.review\s*\{'
    }

    It 'renders the "Items to Review" tile in the Executive Summary' {
        $script:Html | Should -Match 'Items to Review'
    }

    It 'shows the Review count from the synthetic finding set (2)' {
        $script:Html | Should -Match 'class="metric-label">Items to Review</div>\s*<div class="metric-value">2'
    }
}

# ============================================================================
# Unified report (Compliance.psm1)
# ============================================================================

Describe 'Export-UnifiedComplianceReport — REVIEW tile and badge' {

    BeforeAll {
        $script:OutputDir = Join-Path $TestDrive 'unified-review'
        New-Item -ItemType Directory -Path $script:OutputDir -Force | Out-Null
        Export-UnifiedComplianceReport -OutputDirectory $script:OutputDir -TenantName 'Unit Test' -Findings (New-MixedFindings) | Out-Null
        $script:UnifiedHtml = Get-ChildItem $script:OutputDir -Filter 'UnifiedCompliance-Report-*.html' |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Raw
    }

    It 'renders a "To Review" framework-card tile' {
        $script:UnifiedHtml | Should -Match '<h3>To Review</h3>'
    }

    It 'shows the Review count of 2 in the tile' {
        $script:UnifiedHtml | Should -Match 'To Review</h3>\s*<div class="source">[^<]*</div>\s*<div[^>]*>2</div>'
    }

    It 'renders a purple REVIEW badge for REVIEW-status rows' {
        $script:UnifiedHtml | Should -Match 'background:var\(--purple\);color:white;">REVIEW'
    }

    It 'renders a dedicated "Review Queue" section heading (PR 4)' {
        $script:UnifiedHtml | Should -Match 'Review Queue \(2\)'
    }

    It 'renders REVIEW findings only inside the Review Queue, not in the main Findings table (PR 4)' {
        # Split the document at the Review Queue header. Anything before is the
        # main "All Assessment Findings" table; the REVIEW badge must not appear
        # there. Anything after must contain the REVIEW badge.
        $parts = $script:UnifiedHtml -split 'Review Queue \(2\)', 2
        $parts.Count | Should -Be 2
        $beforeQueue = $parts[0]
        $afterQueue = $parts[1]
        $beforeQueue | Should -Not -Match 'background:var\(--purple\);color:white;">REVIEW'
        $afterQueue | Should -Match 'background:var\(--purple\);color:white;">REVIEW'
    }

    It 'still renders failures/warnings normally (no regression)' {
        $script:UnifiedHtml | Should -Match '<h3>Failures</h3>'
        $script:UnifiedHtml | Should -Match '<h3>Warnings</h3>'
        $script:UnifiedHtml | Should -Match 'badge-danger">FAIL'
    }
}

# ============================================================================
# Get-RiskSummary surface used by Excel
# ============================================================================

Describe 'Get-RiskSummary — Review counters used by Excel exporter' {

    BeforeAll {
        # Re-import inside the Describe scope. Pester 5 occasionally loses
        # visibility of file-level imported functions in test scope when other
        # Describes have triggered nested module loads — this guarantees
        # Get-RiskSummary is callable from this test's It block.
        $repoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-RiskScoring.psm1') -Force -DisableNameChecking
    }

    It 'exposes ReviewCount that the Executive Summary sheet reads' {
        $summary = Get-RiskSummary -Findings (New-MixedFindings)
        $summary.ReviewCount   | Should -Be 2
        $summary.ReviewPercent | Should -BeOfType [double]
    }
}
