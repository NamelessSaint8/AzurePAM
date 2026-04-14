<#
.SYNOPSIS
    Pester 5 test suite for SOC 2 Phase 3 PR 3 — licensing-gap dashboard tile.

.DESCRIPTION
    Validates the additive Get-SOC2Summary extension for licensing-gap
    aggregation, plus the HTML render delta (per-family tile + global panel).

    Three categories of tests:
    1. Get-SOC2Summary shape: LicensingGaps top-level + per-family field present
       and counts correctly classify SOC2_LicensingGap_* findings.
    2. Phase 2 byte-stable behavior: existing ByFamily.Info still counts
       licensing gaps (additive, not subtractive — locked decision #6).
    3. HTML render: tile and global panel appear when gaps exist; absent
       gracefully when none.

    Run: Invoke-Pester -Path Tests/SOC2-Phase3-LicensingTile.Tests.ps1

.NOTES
    Requires Pester 5.0+.
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-Branding.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-SOC2.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-SOC2Reporting.psm1') -Force

    function New-LicensingGapFinding {
        param(
            [string]$Feature,
            [string[]]$TSCRefs
        )
        $f = @{}
        $f['Type'] = "SOC2_LicensingGap_$Feature"
        $f['Status'] = 'INFO'
        $f['Severity'] = 'Low'
        $f['Object'] = "Licensing: $Feature"
        $f['Description'] = "License $Feature missing"
        $f['Remediation'] = 'Procure license'
        $f['CheckName'] = 'Get-SOC2LicensingCapabilities'
        $f['Category'] = 'SOC2'
        $f['ControlOwnerHint'] = 'Security'
        $f['TSCReferences'] = $TSCRefs
        return [pscustomobject]$f
    }

    function New-RegularFinding {
        param(
            [string]$Status = 'FAIL',
            [string]$Type = 'MFA_Disabled',
            [string[]]$TSCRefs = @('CC6.1')
        )
        $f = @{}
        $f['Type'] = $Type
        $f['Status'] = $Status
        $f['Severity'] = if ($Status -eq 'FAIL') { 'High' } else { 'Info' }
        $f['Object'] = 'tenant'
        $f['Description'] = "Synthetic $Type"
        $f['Remediation'] = 'Test'
        $f['CheckName'] = "Test-$Type"
        $f['Category'] = 'SOC2'
        $f['TSCReferences'] = $TSCRefs
        return [pscustomobject]$f
    }
}

Describe 'Get-SOC2Summary - LicensingGaps shape (additive extension)' {

    Context 'When no licensing-gap findings are present' {
        It 'returns LicensingGaps with Total=0 and zero per-feature counts' {
            $catalog = Get-SOC2TSCCatalog -Categories @('CC')
            $findings = @(New-RegularFinding -Status 'FAIL' -Type 'MFA_Disabled' -TSCRefs @('CC6.1'))
            $summary = Get-SOC2Summary -Findings $findings -Catalog $catalog
            $summary.LicensingGaps | Should -Not -BeNullOrEmpty
            $summary.LicensingGaps.Total | Should -Be 0
            $summary.LicensingGaps.ByFeature['IdentityProtection'] | Should -Be 0
            $summary.LicensingGaps.ByFeature['DefenderForCloud'] | Should -Be 0
        }
    }

    Context 'When licensing-gap findings span multiple features and TSC families' {
        It 'aggregates Total + ByFeature + ByFamily + per-family LicensingGaps correctly' {
            $catalog = Get-SOC2TSCCatalog -Categories @('CC', 'A', 'C')
            $findings = @(
                # Single-feature, single-family
                New-LicensingGapFinding -Feature 'IdentityProtection' -TSCRefs @('CC7.3')
                # Multi-family: PurviewE5 hits CC6.7, C1.1, C1.2 (CC + C)
                New-LicensingGapFinding -Feature 'PurviewE5' -TSCRefs @('CC6.7', 'C1.1', 'C1.2')
                # Defender hits CC4.2, CC6.7, CC6.8 (all CC)
                New-LicensingGapFinding -Feature 'DefenderForCloud' -TSCRefs @('CC4.2', 'CC6.7', 'CC6.8')
            )
            $summary = Get-SOC2Summary -Findings $findings -Catalog $catalog

            $summary.LicensingGaps.Total | Should -Be 3
            $summary.LicensingGaps.ByFeature['IdentityProtection'] | Should -Be 1
            $summary.LicensingGaps.ByFeature['PurviewE5'] | Should -Be 1
            $summary.LicensingGaps.ByFeature['DefenderForCloud'] | Should -Be 1

            # Per-family rollups (a single gap counted once per touched family)
            $summary.LicensingGaps.ByFamily['CC'] | Should -Be 3
            $summary.LicensingGaps.ByFamily['C']  | Should -Be 1
            $summary.LicensingGaps.ByFamily['A']  | Should -Be 0

            # Per-family ByFamily.LicensingGaps mirrors ByFamily rollup
            $summary.ByFamily['CC'].LicensingGaps | Should -Be 3
            $summary.ByFamily['C'].LicensingGaps | Should -Be 1
        }
    }

    Context 'Phase 2 byte-stable: existing Info count still includes licensing gaps' {
        It 'preserves Info counts unchanged (additive only — locked decision #6)' {
            $catalog = Get-SOC2TSCCatalog -Categories @('CC')
            $findings = @(
                New-LicensingGapFinding -Feature 'IdentityProtection' -TSCRefs @('CC7.3')
                New-RegularFinding -Status 'INFO' -Type 'TenantAndDomainInfo' -TSCRefs @('CC6.1')
            )
            $summary = Get-SOC2Summary -Findings $findings -Catalog $catalog
            # Both are INFO status; both should count toward CC.Info
            $summary.ByFamily['CC'].Info | Should -Be 2
            $summary.ByFamily['CC'].LicensingGaps | Should -Be 1
        }
    }

    Context 'When a licensing gap maps to a TSC the catalog does not include' {
        It 'does not crash; gap counted in Total but not in ByFamily for unmapped families' {
            $catalog = Get-SOC2TSCCatalog -Categories @('CC')  # Only CC in scope
            # Priva targets P1.1/P2.1/P3.1 — outside CC scope
            $findings = @(New-LicensingGapFinding -Feature 'Priva' -TSCRefs @('P1.1', 'P2.1'))
            $summary = Get-SOC2Summary -Findings $findings -Catalog $catalog
            $summary.LicensingGaps.Total | Should -Be 1
            $summary.LicensingGaps.ByFeature['Priva'] | Should -Be 1
            $summary.ByFamily['CC'].LicensingGaps | Should -Be 0
        }
    }
}

Describe 'New-SOC2AuditReport - HTML render with licensing-gap tile' {

    Context 'When the report has licensing gaps' {
        It 'renders the per-family Not Assessed (Licensing) row + global panel' {
            $catalog = Get-SOC2TSCCatalog -Categories @('CC')
            $findings = @(
                New-LicensingGapFinding -Feature 'IdentityProtection' -TSCRefs @('CC7.3')
                New-LicensingGapFinding -Feature 'DefenderForCloud' -TSCRefs @('CC6.7', 'CC6.8')
                New-RegularFinding -Status 'FAIL' -Type 'MFA_Disabled' -TSCRefs @('CC6.1')
            )
            $summary = Get-SOC2Summary -Findings $findings -Catalog $catalog

            $assessmentResult = [pscustomobject]@{
                Findings = $findings
                Catalog = $catalog
                Summary = $summary
                Evidence = $null
                IdentityMapPath = $null
                OutputDirectory = $env:TEMP
            }

            $branding = Get-ReportBrandingContext -Config $null -ReportTitle 'Test'
            $tmpHtml = Join-Path $env:TEMP "soc2-licensing-tile-$((Get-Random)).html"
            try {
                $null = New-SOC2AuditReport -AssessmentResult $assessmentResult -OutputPath $tmpHtml -Branding $branding
                $body = Get-Content -LiteralPath $tmpHtml -Raw

                # Per-family row appears
                $body | Should -BeLike '*Not Assessed (Licensing)*'

                # Global panel appears with correct total
                $body | Should -BeLike '*Licensing gaps:*2 control(s) not assessed*'

                # Feature breakdown present
                $body | Should -BeLike '*IdentityProtection*'
                $body | Should -BeLike '*DefenderForCloud*'
            } finally {
                if (Test-Path $tmpHtml) { Remove-Item -LiteralPath $tmpHtml -Force -ErrorAction SilentlyContinue }
            }
        }
    }

    Context 'When the report has zero licensing gaps' {
        It 'still renders per-family row (with 0) but suppresses the global panel' {
            $catalog = Get-SOC2TSCCatalog -Categories @('CC')
            $findings = @(New-RegularFinding -Status 'FAIL' -Type 'MFA_Disabled' -TSCRefs @('CC6.1'))
            $summary = Get-SOC2Summary -Findings $findings -Catalog $catalog

            $assessmentResult = [pscustomobject]@{
                Findings = $findings
                Catalog = $catalog
                Summary = $summary
                Evidence = $null
                IdentityMapPath = $null
                OutputDirectory = $env:TEMP
            }

            $branding = Get-ReportBrandingContext -Config $null -ReportTitle 'Test'
            $tmpHtml = Join-Path $env:TEMP "soc2-licensing-empty-$((Get-Random)).html"
            try {
                $null = New-SOC2AuditReport -AssessmentResult $assessmentResult -OutputPath $tmpHtml -Branding $branding
                $body = Get-Content -LiteralPath $tmpHtml -Raw

                # Per-family row still appears with count 0
                $body | Should -BeLike '*Not Assessed (Licensing): 0*'

                # Global panel absent
                $body | Should -Not -BeLike '*Licensing gaps:*not assessed due to missing*'
            } finally {
                if (Test-Path $tmpHtml) { Remove-Item -LiteralPath $tmpHtml -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}
