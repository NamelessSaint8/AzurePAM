<#
.SYNOPSIS
    Pester 5 tests for SOC 2 Licensing Gap Actionability
    (plans/SOC2-Audit-Readiness-Plan.md §11.3).

.DESCRIPTION
    Coverage:
      * Get-SOC2LicensingGapActionability — every shipped feature has a
        complete catalog entry; OverrideKey is the real config path;
        unknown features return a safe non-null generic record.
      * New-SOC2LicensingGapFindings — each emitted gap finding carries
        a structured LicensingGapDetail, and the actionable guidance is
        also folded into Description / Remediation so plain consumers
        still get it.
      * v2 normalization (ConvertTo-EntraFindingV2) preserves
        LicensingGapDetail.
      * End-to-end: New-SOC2AuditReport renders the
        #licensing-gap-actionability section with per-feature cards and
        the License/Evidence/Manual/Override/Risk rows; the section is
        omitted when there are no gaps.

    Run: Invoke-Pester -Path Tests/SOC2-LicensingGapActionability.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    if (-not $env:TEMP) {
        $env:TEMP = if ($env:TMPDIR) { $env:TMPDIR.TrimEnd('/') } else { '/tmp' }
    }
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Branding.psm1') -Force -WarningAction SilentlyContinue
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2.psm1') -Force -WarningAction SilentlyContinue
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2Reporting.psm1') -Force

    $script:Features = @('IdentityProtection', 'Intune', 'PurviewE5', 'DefenderForCloud', 'DefenderForEndpoint', 'Priva')

    # Capabilities with everything missing → every feature emits a gap.
    $script:AllMissing = @{
        HasP2 = $false; HasIntune = $false; HasPurviewE5 = $false
        HasDefenderForCloud = $false; HasDefenderForEndpoint = $false; HasPriva = $false
    }
}

Describe 'Get-SOC2LicensingGapActionability — catalog' {

    It 'returns a complete record for every shipped feature' {
        foreach ($f in $script:Features) {
            $a = Get-SOC2LicensingGapActionability -Feature $f
            $a | Should -Not -BeNullOrEmpty
            foreach ($prop in @('Feature', 'LicenseNeeded', 'EvidenceBlocked', 'ManualAlternative', 'OverrideKey', 'OverrideRecommendation', 'RiskIfUnassessed')) {
                $a.PSObject.Properties.Name | Should -Contain $prop -Because "$f must expose $prop"
                ([string]$a.$prop) | Should -Not -BeNullOrEmpty -Because "$f.$prop must be non-empty"
            }
            $a.Feature | Should -BeExactly $f
        }
    }

    It 'OverrideKey is the real config path for the feature' {
        (Get-SOC2LicensingGapActionability -Feature 'IdentityProtection').OverrideKey |
            Should -BeExactly 'SOC2.AzureReadiness.Licensing.Overrides.IdentityProtection'
    }

    It 'OverrideRecommendation names WARNING/FAIL escalation and the INFO/exclusion path' {
        $a = Get-SOC2LicensingGapActionability -Feature 'Intune'
        $a.OverrideRecommendation | Should -Match 'WARNING'
        $a.OverrideRecommendation | Should -Match 'INFO'
        $a.OverrideRecommendation | Should -Match ([regex]::Escape($a.OverrideKey))
    }

    It 'IdentityProtection names Entra ID P2 specifically' {
        (Get-SOC2LicensingGapActionability -Feature 'IdentityProtection').LicenseNeeded | Should -Match 'Entra ID P2'
    }

    It 'returns a safe non-null generic record for an unknown feature' {
        $a = Get-SOC2LicensingGapActionability -Feature 'TotallyBogusFeature'
        $a | Should -Not -BeNullOrEmpty
        $a.Feature | Should -BeExactly 'TotallyBogusFeature'
        $a.OverrideKey | Should -BeExactly 'SOC2.AzureReadiness.Licensing.Overrides.TotallyBogusFeature'
        ([string]$a.LicenseNeeded) | Should -Not -BeNullOrEmpty
        ([string]$a.RiskIfUnassessed) | Should -Not -BeNullOrEmpty
    }
}

Describe 'New-SOC2LicensingGapFindings — enrichment' {

    BeforeAll {
        $script:Gaps = @(New-SOC2LicensingGapFindings -Capabilities $script:AllMissing -Overrides @{})
    }

    It 'emits one finding per missing feature' {
        $script:Gaps.Count | Should -Be $script:Features.Count
    }

    It 'attaches a structured LicensingGapDetail to every gap finding' {
        foreach ($g in $script:Gaps) {
            $g.PSObject.Properties.Name | Should -Contain 'LicensingGapDetail'
            $d = $g.LicensingGapDetail
            foreach ($prop in @('Feature', 'LicenseNeeded', 'AffectedTSCs', 'EvidenceBlocked', 'ManualAlternative', 'OverrideKey', 'OverrideRecommendation', 'RiskIfUnassessed')) {
                $d.PSObject.Properties.Name | Should -Contain $prop
            }
            ([string]$d.AffectedTSCs) | Should -Not -BeNullOrEmpty
        }
    }

    It 'detail.AffectedTSCs matches the finding TSCReferences' {
        $idp = $script:Gaps | Where-Object { $_.Type -eq 'SOC2_LicensingGap_IdentityProtection' } | Select-Object -First 1
        $idp.LicensingGapDetail.AffectedTSCs | Should -BeExactly ((@($idp.TSCReferences)) -join ', ')
    }

    It 'folds the actionable guidance into Description and Remediation' {
        $idp = $script:Gaps | Where-Object { $_.Type -eq 'SOC2_LicensingGap_IdentityProtection' } | Select-Object -First 1
        $idp.Description | Should -Match 'License needed:'
        $idp.Remediation | Should -Match 'Manual alternative:'
        $idp.Remediation | Should -Match 'Audit risk if left unassessed:'
    }

    It 'honours the severity override (WARNING/FAIL) while keeping the detail' {
        $g = @(New-SOC2LicensingGapFindings -Capabilities $script:AllMissing -Overrides @{ Intune = 'FAIL' })
        $intune = $g | Where-Object { $_.Type -eq 'SOC2_LicensingGap_Intune' } | Select-Object -First 1
        $intune.Status | Should -BeExactly 'FAIL'
        $intune.LicensingGapDetail | Should -Not -BeNullOrEmpty
    }

    It 'v2 normalization preserves LicensingGapDetail' {
        $idp = $script:Gaps | Where-Object { $_.Type -eq 'SOC2_LicensingGap_IdentityProtection' } | Select-Object -First 1
        $v2 = $idp | ConvertTo-EntraFindingV2 -DefaultTenantId t -DefaultSource SOC2
        $v2.PSObject.Properties.Name | Should -Contain 'LicensingGapDetail'
        $v2.LicensingGapDetail.LicenseNeeded | Should -Match 'Entra ID P2'
    }
}

Describe 'End-to-end — HTML Licensing Gap Actionability section' {

    BeforeAll {
        $script:Tmp = Join-Path $env:TEMP "lga-e2e-$((Get-Random))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $raw = @([pscustomobject]@{ CheckName = 'Test-X'; Type = 'MFA_Disabled'; Status = 'FAIL'; Severity = 'High'; Object = 'tenant'; Description = 'd'; Remediation = 'r'; Category = 'Identity' })
        $script:Result = Invoke-SOC2Assessment -ExistingFindings $raw -TenantId 't1' `
            -Categories @('CC', 'C', 'P') -OutputDirectory $script:Tmp -WarningAction SilentlyContinue
        $htmlPath = Join-Path $script:Tmp 'r.html'
        $null = New-SOC2AuditReport -AssessmentResult $script:Result -OutputPath $htmlPath
        $script:Html = Get-Content -LiteralPath $htmlPath -Raw
        $script:Section = ($script:Html -split 'id="licensing-gap-actionability"', 2)[1]
        if ($script:Section) { $script:Section = ($script:Section -split '</section>', 2)[0] }
    }
    AfterAll {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'every emitted licensing-gap finding carries LicensingGapDetail' {
        $lic = @($script:Result.Findings | Where-Object { $_.Type -like 'SOC2_LicensingGap_*' })
        $lic.Count | Should -BeGreaterThan 0
        @($lic | Where-Object { $_.PSObject.Properties['LicensingGapDetail'] }).Count | Should -Be $lic.Count
    }

    It 'renders the actionability section with per-feature cards' {
        $script:Html | Should -Match 'id="licensing-gap-actionability"'
        $script:Section | Should -Match 'class="lga-card"'
    }

    It 'each card surfaces all five actionability rows' {
        $script:Section | Should -Match '<th>License needed</th>'
        $script:Section | Should -Match '<th>Evidence blocked</th>'
        $script:Section | Should -Match '<th>Manual alternative</th>'
        $script:Section | Should -Match '<th>Config override</th>'
        $script:Section | Should -Match '<th>Risk if unassessed</th>'
    }

    It 'surfaces the concrete override key for escalation' {
        $script:Section | Should -Match 'SOC2\.AzureReadiness\.Licensing\.Overrides'
    }

    It 'omits the section entirely when there are no licensing gaps' {
        # Build a summary whose findings contain no SOC2_LicensingGap_*.
        $catalog = Get-SOC2TSCCatalog -Categories @('CC')
        $findings = @([pscustomobject]@{ Type = 'MFA_Disabled'; Status = 'OK'; Severity = 'Info'; Object = 't'; Description = 'd'; Remediation = 'r'; CheckName = 'c'; Category = 'SOC2'; TSCReferences = @('CC6.1') })
        $summary = Get-SOC2Summary -Findings $findings -Catalog $catalog
        $result = [pscustomobject]@{ Findings = $findings; Catalog = $catalog; Summary = $summary; Evidence = $null }
        $htmlPath = Join-Path $script:Tmp 'no-gaps.html'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $htmlPath
        (Get-Content -LiteralPath $htmlPath -Raw) | Should -Not -Match 'id="licensing-gap-actionability"'
    }
}
