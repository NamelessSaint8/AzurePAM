<#
.SYNOPSIS
    Pester 5 test suite for SOC 2 reporting-enhancements PR.

.DESCRIPTION
    Covers four items added to EntraChecks-SOC2Reporting.psm1:
    1. CSV output parity with Excel (numbered files, all sheets mirrored)
    2. HTML executive summary + anchor links + print stylesheet
    3. Low-confidence check banner + per-finding tag
    4. Evidence-integrity "VERIFIED" badge

    Run: Invoke-Pester -Path Tests/SOC2-Reporting-Enhancements.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-Branding.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-SOC2.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-SOC2Reporting.psm1') -Force

    function New-TestFinding {
        param(
            [string]$Type = 'MFA_Disabled',
            [string]$Status = 'FAIL',
            [string]$CheckName = 'Test-MFA',
            [string[]]$TSCRefs = @('CC6.1'),
            [string]$Object = 'tenant'
        )
        [pscustomobject]@{
            Type = $Type
            Status = $Status
            Severity = if ($Status -eq 'FAIL') { 'High' } else { 'Info' }
            Object = $Object
            Description = "Synthetic $Type"
            Remediation = 'Test remediation'
            CheckName = $CheckName
            Category = 'SOC2'
            TSCReferences = $TSCRefs
        }
    }

    function New-TestAssessmentResult {
        param([object[]]$Findings, [string[]]$Categories = @('CC'))

        $catalog = Get-SOC2TSCCatalog -Categories $Categories
        $summary = Get-SOC2Summary -Findings $Findings -Catalog $catalog
        [pscustomobject]@{
            Findings = $Findings
            Catalog = $catalog
            Summary = $summary
            Evidence = $null
            IdentityMapPath = $null
            OutputDirectory = $env:TEMP
        }
    }

    function New-TestAssessmentResultWithEvidence {
        param([object[]]$Findings, [string[]]$Categories = @('CC'))
        $r = New-TestAssessmentResult -Findings $Findings -Categories $Categories
        # IMPORTANT: match the production shape. New-SOC2EvidenceBundle
        # returns a PSCustomObject (not a hashtable). Using a hashtable here
        # would hide PSCustomObject->Hashtable coercion bugs in row-builder
        # helpers — which is exactly the bug that slipped past the first
        # pass of reporting-enhancements tests.
        $r.Evidence = [pscustomobject]@{
            ManifestPath = ''
            BundleHash = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8'
            Directory = 'C:\tmp\evidence'
            FileCount = 0
            GeneratedAt = '2026-04-14T20:20:13Z'
        }
        $r
    }
}

Describe 'Regression: production PSCustomObject shapes flow through helpers' {
    # Reproduces a bug found only when running against a real tenant: the
    # production Evidence object is a PSCustomObject (from
    # New-SOC2EvidenceBundle's return), but the helper originally declared
    # [hashtable]. PowerShell does not auto-coerce PSCustomObject -> Hashtable,
    # so the workbook writer crashed mid-report.
    It 'New-SOC2AuditWorkbook end-to-end with PSCustomObject Evidence does not crash' {
        $findings = @(New-TestFinding -Status 'OK' -TSCRefs @('CC6.1'))
        $result = New-TestAssessmentResultWithEvidence -Findings $findings
        $tmpDir = Join-Path $env:TEMP "soc2-regress-$((Get-Random))"
        $null = New-Item -Path $tmpDir -ItemType Directory -Force
        $xlsxPath = Join-Path $tmpDir 'workbook.xlsx'
        try {
            { $null = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath $xlsxPath } | Should -Not -Throw
        } finally {
            if (Test-Path $tmpDir) { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'Item 1: CSV output parity with Excel' {

    BeforeEach {
        $script:CsvDir = Join-Path $env:TEMP "soc2-csv-parity-$((Get-Random))"
    }

    AfterEach {
        if (Test-Path $script:CsvDir) { Remove-Item -LiteralPath $script:CsvDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    Context 'When ImportExcel is available (Excel path)' {
        It 'still produces an .xlsx output without regression' -Skip:($null -eq (Get-Module -ListAvailable -Name ImportExcel)) {
            $findings = @(New-TestFinding)
            $result = New-TestAssessmentResult -Findings $findings
            $xlsxPath = Join-Path $script:CsvDir 'workbook.xlsx'
            $null = New-Item -Path $script:CsvDir -ItemType Directory -Force
            $null = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath $xlsxPath
            Test-Path $xlsxPath | Should -Be $true
        }
    }

    Context 'When ImportExcel is NOT available (CSV fallback path)' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2Reporting Get-Module {} -ParameterFilter { $Name -eq 'ImportExcel' -and $ListAvailable }
        }
        It 'produces Cover, Summary, Control Register, and flat Findings CSVs at minimum' {
            $findings = @(
                New-TestFinding -Status 'FAIL' -TSCRefs @('CC6.1')
                New-TestFinding -Type 'Other' -Status 'OK' -TSCRefs @('CC6.3')
            )
            $result = New-TestAssessmentResult -Findings $findings
            $xlsxPath = Join-Path $script:CsvDir 'workbook.xlsx'
            $outDir = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath $xlsxPath

            (Test-Path (Join-Path $outDir '01-Cover.csv')) | Should -Be $true
            (Test-Path (Join-Path $outDir '02-Summary-by-Category.csv')) | Should -Be $true
            (Test-Path (Join-Path $outDir '03-Control-Register.csv')) | Should -Be $true
        }

        It 'produces a per-family findings CSV (04-Findings-CC6.csv) when CC6 findings exist' {
            $findings = @(New-TestFinding -Status 'FAIL' -TSCRefs @('CC6.1'))
            $result = New-TestAssessmentResult -Findings $findings
            $xlsxPath = Join-Path $script:CsvDir 'workbook.xlsx'
            $outDir = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath $xlsxPath

            (Test-Path (Join-Path $outDir '04-Findings-CC6.csv')) | Should -Be $true
            $content = Import-Csv (Join-Path $outDir '04-Findings-CC6.csv')
            @($content).Count | Should -BeGreaterOrEqual 1
            $content[0].ControlId | Should -Be 'CC6.1'
        }

        It 'produces Licensing Gaps CSV (10) when gap findings exist' {
            $findings = @(
                [pscustomobject]@{
                    Type = 'SOC2_LicensingGap_IdentityProtection'
                    Status = 'INFO'
                    Severity = 'Low'
                    Object = 'Licensing: IdentityProtection'
                    Description = 'P2 missing'
                    Remediation = 'Procure P2'
                    CheckName = 'Get-SOC2LicensingCapabilities'
                    Category = 'SOC2'
                    ControlOwnerHint = 'Security'
                    TSCReferences = @('CC7.3')
                }
            )
            $result = New-TestAssessmentResult -Findings $findings
            $xlsxPath = Join-Path $script:CsvDir 'workbook.xlsx'
            $outDir = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath $xlsxPath

            (Test-Path (Join-Path $outDir '10-Findings-Licensing-Gaps.csv')) | Should -Be $true
            $content = Import-Csv (Join-Path $outDir '10-Findings-Licensing-Gaps.csv')
            $content[0].Feature | Should -Be 'IdentityProtection'
        }

        It 'produces Manual Attestation CSV (11) when manual stubs exist' {
            # Manual stubs come from the catalog. Broad category set ensures some
            # Manual TSCs (CC1.*, CC5.*, PI1.*, P*) are in the register. Dummy
            # finding is included because Get-SOC2Summary requires a non-empty
            # findings array.
            $findings = @(New-TestFinding -Status 'OK' -TSCRefs @('CC6.1'))
            $result = New-TestAssessmentResult -Findings $findings -Categories @('CC', 'A', 'C', 'PI', 'P')
            $xlsxPath = Join-Path $script:CsvDir 'workbook.xlsx'
            $outDir = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath $xlsxPath

            (Test-Path (Join-Path $outDir '11-Manual-Attestation.csv')) | Should -Be $true
        }

        It 'skips per-family CSV files when no findings in that family' {
            # Only CC6 findings — no Availability, no Confidentiality
            $findings = @(New-TestFinding -Status 'FAIL' -TSCRefs @('CC6.1'))
            $result = New-TestAssessmentResult -Findings $findings -Categories @('CC', 'A', 'C')
            $xlsxPath = Join-Path $script:CsvDir 'workbook.xlsx'
            $outDir = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath $xlsxPath

            (Test-Path (Join-Path $outDir '08-Findings-Availability.csv')) | Should -Be $false
            (Test-Path (Join-Path $outDir '09-Findings-Confidentiality.csv')) | Should -Be $false
        }
    }
}

Describe 'Item 2: HTML executive summary + anchor links + print stylesheet' {

    BeforeEach {
        $script:HtmlPath = Join-Path $env:TEMP "soc2-enhancements-$((Get-Random)).html"
    }
    AfterEach {
        if (Test-Path $script:HtmlPath) { Remove-Item -LiteralPath $script:HtmlPath -Force -ErrorAction SilentlyContinue }
    }

    It 'renders the Executive Summary section with verdict + headline stats + jump-to nav' {
        $findings = @(
            New-TestFinding -Status 'FAIL' -TSCRefs @('CC6.1')
            New-TestFinding -Type 'Other' -Status 'WARNING' -TSCRefs @('CC6.3')
        )
        $result = New-TestAssessmentResult -Findings $findings
        $branding = Get-ReportBrandingContext -Config $null -ReportTitle 'Enhancements Test'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $script:HtmlPath -Branding $branding
        $body = Get-Content -LiteralPath $script:HtmlPath -Raw

        $body | Should -BeLike '*Executive Summary*'
        $body | Should -BeLike '*Internal readiness: GAPS IDENTIFIED*'
        $body | Should -BeLike '*class=*headline-row*'
        $body | Should -BeLike '*Jump to*'
    }

    It 'verdict is STRONG when only PASS findings exist' {
        $findings = @(New-TestFinding -Status 'OK' -TSCRefs @('CC6.1'))
        $result = New-TestAssessmentResult -Findings $findings
        $branding = Get-ReportBrandingContext -Config $null -ReportTitle 'Enhancements Test'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $script:HtmlPath -Branding $branding
        (Get-Content $script:HtmlPath -Raw) | Should -BeLike '*Internal readiness: STRONG*'
    }

    It 'per-family sections have anchor IDs wired for quick-nav' {
        $findings = @(New-TestFinding -Status 'FAIL' -TSCRefs @('CC6.1'))
        $result = New-TestAssessmentResult -Findings $findings
        $branding = Get-ReportBrandingContext -Config $null -ReportTitle 'Enhancements Test'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $script:HtmlPath -Branding $branding
        $body = Get-Content -LiteralPath $script:HtmlPath -Raw

        $body | Should -BeLike "*id='family-CC'*"
        $body | Should -BeLike "*href='#family-CC'*"
    }

    It 'emits @media print stylesheet with color-adjust + page-break rules' {
        $findings = @(New-TestFinding -Status 'OK' -TSCRefs @('CC6.1'))
        $result = New-TestAssessmentResult -Findings $findings
        $branding = Get-ReportBrandingContext -Config $null -ReportTitle 'Enhancements Test'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $script:HtmlPath -Branding $branding
        $body = Get-Content -LiteralPath $script:HtmlPath -Raw

        $body | Should -BeLike '*@media print*'
        $body | Should -BeLike '*print-color-adjust: exact*'
        $body | Should -BeLike '*break-inside: avoid*'
    }
}

Describe 'Item 3: Low-confidence check banner + per-finding tag' {

    BeforeEach {
        $script:HtmlPath = Join-Path $env:TEMP "soc2-lowconf-$((Get-Random)).html"
    }
    AfterEach {
        if (Test-Path $script:HtmlPath) { Remove-Item -LiteralPath $script:HtmlPath -Force -ErrorAction SilentlyContinue }
    }

    It 'renders the banner when Test-SOC2DiagnosticSettingsExport is in findings' {
        $findings = @(
            [pscustomobject]@{
                Type = 'SOC2_DiagnosticSettingsGap'
                Status = 'FAIL'
                Severity = 'High'
                Object = 'Diag settings'
                Description = 'missing'
                Remediation = 'add'
                CheckName = 'Test-SOC2DiagnosticSettingsExport'
                Category = 'SOC2'
                TSCReferences = @('CC4.1', 'CC7.2')
            }
        )
        $result = New-TestAssessmentResult -Findings $findings
        $branding = Get-ReportBrandingContext -Config $null -ReportTitle 'Test'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $script:HtmlPath -Branding $branding
        $body = Get-Content -LiteralPath $script:HtmlPath -Raw

        $body | Should -BeLike '*low-confidence-banner*'
        $body | Should -BeLike '*fixture-verified only*'
        $body | Should -BeLike '*Test-SOC2DiagnosticSettingsExport*fixture-verified*'
    }

    It 'does not render the banner when no low-confidence checks are in findings' {
        $findings = @(New-TestFinding -Status 'FAIL' -TSCRefs @('CC6.1'))
        $result = New-TestAssessmentResult -Findings $findings
        $branding = Get-ReportBrandingContext -Config $null -ReportTitle 'Test'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $script:HtmlPath -Branding $branding
        $body = Get-Content -LiteralPath $script:HtmlPath -Raw

        # Pattern is deliberately specific: the CSS class definition always
        # appears in the <style> block, so we check for the banner DIV opener
        # and the banner copy (which never appears when the banner is absent).
        $body | Should -Not -BeLike '*<div class="low-confidence-banner">*'
        $body | Should -Not -BeLike '*Verification note:*'
    }

    It 'Test-SOC2IsLowConfidenceCheck helper returns true for known names' {
        $known = InModuleScope EntraChecks-SOC2Reporting { Test-SOC2IsLowConfidenceCheck -CheckName 'Test-SOC2DiagnosticSettingsExport' }
        $known | Should -Be $true

        $unknown = InModuleScope EntraChecks-SOC2Reporting { Test-SOC2IsLowConfidenceCheck -CheckName 'Test-MFA' }
        $unknown | Should -Be $false
    }
}

Describe 'Item 4: Evidence-integrity badge' {

    BeforeEach {
        $script:HtmlPath = Join-Path $env:TEMP "soc2-integrity-$((Get-Random)).html"
    }
    AfterEach {
        if (Test-Path $script:HtmlPath) { Remove-Item -LiteralPath $script:HtmlPath -Force -ErrorAction SilentlyContinue }
    }

    It 'renders Integrity-verifiable badge in the Cover panel when Evidence is populated' {
        $findings = @(New-TestFinding -Status 'OK' -TSCRefs @('CC6.1'))
        $result = New-TestAssessmentResultWithEvidence -Findings $findings
        $branding = Get-ReportBrandingContext -Config $null -ReportTitle 'Test'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $script:HtmlPath -Branding $branding
        $body = Get-Content -LiteralPath $script:HtmlPath -Raw

        $body | Should -BeLike '*badge-met*Integrity-verifiable*'
    }

    It 'renders No bundle neutral badge when Evidence is null' {
        $findings = @(New-TestFinding -Status 'OK' -TSCRefs @('CC6.1'))
        $result = New-TestAssessmentResult -Findings $findings  # no evidence
        $branding = Get-ReportBrandingContext -Config $null -ReportTitle 'Test'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $script:HtmlPath -Branding $branding
        $body = Get-Content -LiteralPath $script:HtmlPath -Raw

        $body | Should -BeLike '*badge-neutral*No bundle*'
        $body | Should -Not -BeLike '*badge-met*Integrity-verifiable*'
    }
}
