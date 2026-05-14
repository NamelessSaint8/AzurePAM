<#
.SYNOPSIS
    Pester 5 tests for Get-HtmlReportPlan (PR 4 of HTML-Reporting-Consolidation-Plan).

.DESCRIPTION
    Exercises the routing decision matrix that the orchestrator follows when
    deciding which HTML reports to emit:

      - Cockpit              → cockpit only
      - CockpitAndDeepDives  → cockpit + explicitly-listed available deep dives
      - DeepDivesOnly        → no cockpit; only the listed deep dives (warn if empty)
      - LegacyAll            → no cockpit; every available domain + comprehensive + unified

    Plus edge cases: invalid domain names, deep dives requested with no data,
    legacy mode ignoring HtmlDeepDiveDomains (it infers from AvailableSources).

    Run: Invoke-Pester -Path Tests/HtmlReportPlan.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force
}

# ============================================================================
# Cockpit mode
# ============================================================================

Describe 'Get-HtmlReportPlan — Cockpit mode' {

    It 'default mode is Cockpit and emits cockpit only' {
        $plan = Get-HtmlReportPlan
        $plan.GenerateCockpit | Should -BeTrue
        $plan.GenerateComprehensive | Should -BeFalse
        $plan.GenerateUnified | Should -BeFalse
        $plan.GenerateDomainReports.Count | Should -Be 0
    }

    It 'Cockpit mode emits cockpit only even when sources are available' {
        $plan = Get-HtmlReportPlan -HtmlReportSet 'Cockpit' -AvailableSources @{
            SecureScore = $true
            AzurePolicy = $true
            DefenderCompliance = $true
        }
        $plan.GenerateCockpit | Should -BeTrue
        $plan.GenerateDomainReports.Count | Should -Be 0
    }

    It 'Cockpit mode WARNS when HtmlDeepDiveDomains is supplied (which would be ignored)' {
        $plan = Get-HtmlReportPlan -HtmlReportSet 'Cockpit' -HtmlDeepDiveDomains @('AzurePolicy')
        $plan.GenerateCockpit | Should -BeTrue
        $plan.GenerateDomainReports.Count | Should -Be 0
        ($plan.Warnings -join ' ') | Should -Match 'deep dives ignored'
    }
}

# ============================================================================
# CockpitAndDeepDives mode
# ============================================================================

Describe 'Get-HtmlReportPlan — CockpitAndDeepDives mode' {

    It 'emits cockpit + the specifically requested available domain' {
        $plan = Get-HtmlReportPlan `
            -HtmlReportSet 'CockpitAndDeepDives' `
            -HtmlDeepDiveDomains @('AzurePolicy') `
            -AvailableSources @{ AzurePolicy = $true; SecureScore = $true }
        $plan.GenerateCockpit | Should -BeTrue
        $plan.GenerateDomainReports | Should -Contain 'AzurePolicy'
        # SecureScore data IS available but was not requested — must not emit.
        $plan.GenerateDomainReports | Should -Not -Contain 'SecureScore'
    }

    It 'warns when a requested domain has no collected data and skips it' {
        $plan = Get-HtmlReportPlan `
            -HtmlReportSet 'CockpitAndDeepDives' `
            -HtmlDeepDiveDomains @('SecureScore', 'AzurePolicy') `
            -AvailableSources @{ AzurePolicy = $true }
        $plan.GenerateCockpit | Should -BeTrue
        $plan.GenerateDomainReports | Should -Contain 'AzurePolicy'
        $plan.GenerateDomainReports | Should -Not -Contain 'SecureScore'
        ($plan.Warnings -join ' ') | Should -Match "Deep dive 'SecureScore' requested but no data was collected"
    }

    It 'with no -HtmlDeepDiveDomains, emits cockpit alone (no inference of all domains)' {
        # Plan §12 explicitly says: "If domains are omitted, do not infer all
        # domains." This guards against accidental expansion.
        $plan = Get-HtmlReportPlan `
            -HtmlReportSet 'CockpitAndDeepDives' `
            -AvailableSources @{ AzurePolicy = $true; SecureScore = $true }
        $plan.GenerateCockpit | Should -BeTrue
        $plan.GenerateDomainReports.Count | Should -Be 0
    }

    It 'warns on an invalid domain name but continues with the valid ones' {
        $plan = Get-HtmlReportPlan `
            -HtmlReportSet 'CockpitAndDeepDives' `
            -HtmlDeepDiveDomains @('Bogus', 'AzurePolicy') `
            -AvailableSources @{ AzurePolicy = $true }
        $plan.GenerateDomainReports | Should -Contain 'AzurePolicy'
        ($plan.Warnings -join ' ') | Should -Match "'Bogus' is not a recognised domain"
    }
}

# ============================================================================
# DeepDivesOnly mode
# ============================================================================

Describe 'Get-HtmlReportPlan — DeepDivesOnly mode' {

    It 'emits only the requested deep dives; no cockpit' {
        $plan = Get-HtmlReportPlan `
            -HtmlReportSet 'DeepDivesOnly' `
            -HtmlDeepDiveDomains @('AzurePolicy') `
            -AvailableSources @{ AzurePolicy = $true; SecureScore = $true }
        $plan.GenerateCockpit | Should -BeFalse
        $plan.GenerateComprehensive | Should -BeFalse
        $plan.GenerateUnified | Should -BeFalse
        $plan.GenerateDomainReports | Should -Contain 'AzurePolicy'
        $plan.GenerateDomainReports | Should -Not -Contain 'SecureScore'
    }

    It 'emits a warning + no HTML when -HtmlDeepDiveDomains is empty' {
        $plan = Get-HtmlReportPlan -HtmlReportSet 'DeepDivesOnly' `
            -AvailableSources @{ AzurePolicy = $true }
        $plan.GenerateCockpit | Should -BeFalse
        $plan.GenerateComprehensive | Should -BeFalse
        $plan.GenerateUnified | Should -BeFalse
        $plan.GenerateDomainReports.Count | Should -Be 0
        ($plan.Warnings -join ' ') | Should -Match 'no HTML will be generated'
    }
}

# ============================================================================
# LegacyAll mode
# ============================================================================

Describe 'Get-HtmlReportPlan — LegacyAll mode (compatibility)' {

    It 'preserves pre-PR-4 behavior: comprehensive + unified + every available domain' {
        $sources = @{
            SecureScore = $true
            DefenderCompliance = $true
            AzurePolicy = $true
            PurviewCompliance = $true
            Delta = $false
        }
        $plan = Get-HtmlReportPlan -HtmlReportSet 'LegacyAll' -AvailableSources $sources
        $plan.GenerateCockpit | Should -BeFalse
        $plan.GenerateComprehensive | Should -BeTrue
        $plan.GenerateUnified | Should -BeTrue
        $plan.GenerateDomainReports | Should -Contain 'SecureScore'
        $plan.GenerateDomainReports | Should -Contain 'DefenderCompliance'
        $plan.GenerateDomainReports | Should -Contain 'AzurePolicy'
        $plan.GenerateDomainReports | Should -Contain 'PurviewCompliance'
        # Delta is unavailable — must not be in the list.
        $plan.GenerateDomainReports | Should -Not -Contain 'Delta'
    }

    It 'LegacyAll IGNORES HtmlDeepDiveDomains (infers from AvailableSources)' {
        # Even with a narrow filter list, legacy mode emits every available source.
        $plan = Get-HtmlReportPlan `
            -HtmlReportSet 'LegacyAll' `
            -HtmlDeepDiveDomains @('AzurePolicy') `
            -AvailableSources @{ SecureScore = $true; AzurePolicy = $true }
        $plan.GenerateDomainReports | Should -Contain 'SecureScore'
        $plan.GenerateDomainReports | Should -Contain 'AzurePolicy'
    }
}
