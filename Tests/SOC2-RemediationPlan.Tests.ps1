<#
.SYNOPSIS
    Pester 5 tests for the SOC 2 Remediation Plan
    (plans/SOC2-Audit-Readiness-Plan.md PR 2, §9).

.DESCRIPTION
    Get-SOC2RemediationPlan is a pure view over the Control Conclusion
    Register from PR 1. Tests cover:

      * Exclusion of Effective / Accepted Risk / Informational rows.
      * Priority derivation (1 Critical/High deficiency .. 5 no-evidence).
      * Deterministic sort: Priority asc, DueDate asc (blank last),
        ControlId asc.
      * Column completeness + owner / remediation pass-through from the
        register (which sources them from the v2 blocking finding).
      * HTML report emits <section id="remediation-plan"> with the
        priority badge markup.
      * CSV fallback writes 01b-Remediation-Plan.csv with the right
        columns, and the legacy 01a / 02 / 03 numbers stay stable.

    Run: Invoke-Pester -Path Tests/SOC2-RemediationPlan.Tests.ps1
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

    function script:New-RegRow {
        param(
            [string]$ControlId,
            [string]$Conclusion,
            [string]$DeficiencySeverity = '',
            [string]$Owner = 'Security',
            [string]$DueDate = '',
            [string]$TscFamily = 'CC',
            [string]$Reason = 'because',
            [string]$Remediation = 'do the thing',
            [string]$ValidationSteps = 're-run',
            [string]$EvidenceNeeded = 'screenshot'
        )
        [pscustomobject]@{
            ControlId = $ControlId
            TscFamily = $TscFamily
            FamilyName = 'Common Criteria'
            Automation = 'Automated'
            ControlDescription = "desc $ControlId"
            Conclusion = $Conclusion
            DeficiencySeverity = $DeficiencySeverity
            FindingCount = 1
            EvidenceCount = 0
            Owner = $Owner
            DueDate = $DueDate
            ExceptionStatus = 'None'
            ManagementResponse = ''
            ControlOwnerHint = 'Security'
            Reason = $Reason
            Remediation = $Remediation
            ValidationSteps = $ValidationSteps
            EvidenceNeeded = $EvidenceNeeded
        }
    }

    function script:New-SyntheticFinding {
        param(
            [string]$Type = 'SOC2_Synthetic',
            [string]$Status = 'OK',
            [string]$Severity = 'Info',
            [string]$Description = 'synthetic test',
            [string[]]$TSCReferences = @('CC6.1'),
            [string]$Remediation = 'Fix it'
        )
        [pscustomobject]@{
            Type = $Type
            Status = $Status
            Severity = $Severity
            Description = $Description
            Remediation = $Remediation
            Object = 'tenant'
            CheckName = "Test-$Type"
            Category = 'SOC2'
            TSCReferences = $TSCReferences
        }
    }

    # Get-SOC2RemediationPlan follows the module's comma-wrapped return
    # convention (see ConvertTo-ControlMappings): consume via direct
    # assignment, never @(call) — @() straight around the call double-wraps
    # a multi-element result. This helper does the documented direct-assign
    # then normalises to a plain array for the assertions.
    function script:Get-Plan {
        param($Register)
        $p = Get-SOC2RemediationPlan -Register $Register
        return @($p)
    }

    function script:Build-Result {
        param([object[]]$Findings, [string[]]$Categories = @('CC'))
        $catalog = Get-SOC2TSCCatalog -Categories $Categories
        $summary = Get-SOC2Summary -Findings $Findings -Catalog $catalog
        [pscustomobject]@{
            Findings = $Findings; Catalog = $catalog; Summary = $summary; Evidence = $null
        }
    }
}

Describe 'Get-SOC2RemediationPlan — exclusion rules' {

    It 'excludes Effective, Accepted Risk, and Informational rows' {
        $reg = @(
            New-RegRow -ControlId 'CC6.1' -Conclusion 'Effective'
            New-RegRow -ControlId 'CC6.2' -Conclusion 'Accepted Risk'
            New-RegRow -ControlId 'CC6.3' -Conclusion 'Informational'
            New-RegRow -ControlId 'CC6.4' -Conclusion 'Deficiency' -DeficiencySeverity 'High'
        )
        $plan = Get-Plan -Register $reg
        $plan.Count | Should -Be 1
        $plan[0].ControlId | Should -BeExactly 'CC6.4'
    }

    It 'returns an empty array (not null) when everything is excluded' {
        $reg = @(
            New-RegRow -ControlId 'CC6.1' -Conclusion 'Effective'
            New-RegRow -ControlId 'CC6.2' -Conclusion 'Accepted Risk'
        )
        $plan = Get-Plan -Register $reg
        $plan.Count | Should -Be 0
    }

    It 'accepts an empty register without throwing' {
        { Get-SOC2RemediationPlan -Register @() } | Should -Not -Throw
    }
}

Describe 'Get-SOC2RemediationPlan — priority derivation' {

    It 'High/Critical Deficiency is priority 1' {
        $p = Get-Plan -Register @(New-RegRow -ControlId 'X' -Conclusion 'Deficiency' -DeficiencySeverity 'Critical')
        $p[0].Priority | Should -Be 1
        $p2 = Get-Plan -Register @(New-RegRow -ControlId 'X' -Conclusion 'Deficiency' -DeficiencySeverity 'High')
        $p2[0].Priority | Should -Be 1
    }

    It 'Medium/Low Deficiency and Deficiency - Minor are priority 2' {
        $med = Get-Plan -Register @(New-RegRow -ControlId 'X' -Conclusion 'Deficiency' -DeficiencySeverity 'Medium')
        $med[0].Priority | Should -Be 2
        $minor = Get-Plan -Register @(New-RegRow -ControlId 'X' -Conclusion 'Deficiency - Minor')
        $minor[0].Priority | Should -Be 2
    }

    It 'Manual Pending is 3, Licensing is 4, No-Evidence is 5' {
        (Get-Plan -Register @(New-RegRow -ControlId 'X' -Conclusion 'Manual Pending'))[0].Priority | Should -Be 3
        (Get-Plan -Register @(New-RegRow -ControlId 'X' -Conclusion 'Not Assessed - Licensing'))[0].Priority | Should -Be 4
        (Get-Plan -Register @(New-RegRow -ControlId 'X' -Conclusion 'Not Assessed - No Evidence'))[0].Priority | Should -Be 5
    }
}

Describe 'Get-SOC2RemediationPlan — deterministic sort' {

    It 'orders by Priority asc, then DueDate asc (blank last), then ControlId' {
        $reg = @(
            New-RegRow -ControlId 'CC9.9' -Conclusion 'Not Assessed - No Evidence'
            New-RegRow -ControlId 'CC1.1' -Conclusion 'Deficiency' -DeficiencySeverity 'High' -DueDate ''
            New-RegRow -ControlId 'CC2.2' -Conclusion 'Deficiency' -DeficiencySeverity 'High' -DueDate '2026-06-01'
            New-RegRow -ControlId 'CC3.3' -Conclusion 'Deficiency' -DeficiencySeverity 'High' -DueDate '2026-05-20'
            New-RegRow -ControlId 'CC4.4' -Conclusion 'Deficiency - Minor'
        )
        $plan = Get-Plan -Register $reg
        # Priority 1 block first, dated before blank, earliest date first.
        $plan[0].ControlId | Should -BeExactly 'CC3.3'   # 2026-05-20
        $plan[1].ControlId | Should -BeExactly 'CC2.2'   # 2026-06-01
        $plan[2].ControlId | Should -BeExactly 'CC1.1'   # blank due, still P1
        $plan[3].ControlId | Should -BeExactly 'CC4.4'   # P2
        $plan[4].ControlId | Should -BeExactly 'CC9.9'   # P5
        @($plan.Priority) | Should -Be @(1, 1, 1, 2, 5)
    }

    It 'is stable across repeated calls (same input -> same order)' {
        $reg = @(
            New-RegRow -ControlId 'CC2.2' -Conclusion 'Manual Pending'
            New-RegRow -ControlId 'CC1.1' -Conclusion 'Manual Pending'
            New-RegRow -ControlId 'CC3.3' -Conclusion 'Manual Pending'
        )
        $a = (Get-Plan -Register $reg) | ForEach-Object ControlId
        $b = (Get-Plan -Register $reg) | ForEach-Object ControlId
        ($a -join ',') | Should -BeExactly ($b -join ',')
        ($a -join ',') | Should -BeExactly 'CC1.1,CC2.2,CC3.3'
    }
}

Describe 'Get-SOC2RemediationPlan — column completeness + pass-through' {

    It 'projects all PR 2 §9.1 columns' {
        $plan = Get-Plan -Register @(New-RegRow -ControlId 'CC6.1' -Conclusion 'Deficiency' -DeficiencySeverity 'High')
        foreach ($col in @('Priority', 'ControlId', 'TscFamily', 'Gap', 'Owner', 'DueDate', 'Remediation', 'ValidationSteps', 'EvidenceNeeded')) {
            $plan[0].PSObject.Properties.Name | Should -Contain $col
        }
    }

    It 'Gap combines Conclusion + Reason' {
        $plan = Get-Plan -Register @(New-RegRow -ControlId 'X' -Conclusion 'Deficiency' -DeficiencySeverity 'High' -Reason 'mfa off')
        $plan[0].Gap | Should -BeLike 'Deficiency*mfa off*'
    }

    It 'passes Owner/Remediation/Validation/Evidence through from the register row' {
        $reg = @(New-RegRow -ControlId 'X' -Conclusion 'Deficiency' -DeficiencySeverity 'High' -Owner 'Identity Team' -Remediation 'Turn on MFA' -ValidationSteps 'check portal' -EvidenceNeeded 'CA policy export')
        $plan = Get-Plan -Register $reg
        $plan[0].Owner | Should -BeExactly 'Identity Team'
        $plan[0].Remediation | Should -BeExactly 'Turn on MFA'
        $plan[0].ValidationSteps | Should -BeExactly 'check portal'
        $plan[0].EvidenceNeeded | Should -BeExactly 'CA policy export'
    }
}

Describe 'Get-SOC2ControlConclusionRegister — remediation source columns (PR 2 §9.1)' {

    It 'register rows now carry Remediation / ValidationSteps / EvidenceNeeded' {
        $findings = @(New-SyntheticFinding -Status 'FAIL' -Severity 'High' -TSCReferences @('CC6.1') -Remediation 'Enable MFA everywhere')
        $result = Build-Result -Findings $findings
        $reg = Get-SOC2ControlConclusionRegister -Catalog $result.Catalog -Summary $result.Summary
        $row = $reg | Where-Object ControlId -eq 'CC6.1' | Select-Object -First 1
        $row.PSObject.Properties.Name | Should -Contain 'Remediation'
        $row.PSObject.Properties.Name | Should -Contain 'ValidationSteps'
        $row.PSObject.Properties.Name | Should -Contain 'EvidenceNeeded'
        $row.Remediation | Should -BeExactly 'Enable MFA everywhere'
        $row.ValidationSteps | Should -Not -BeNullOrEmpty
        $row.EvidenceNeeded | Should -Not -BeNullOrEmpty
    }
}

Describe 'New-SOC2AuditReport — HTML remediation-plan section' {

    BeforeEach {
        $script:TmpDir = Join-Path $env:TEMP "soc2-rp-$((Get-Random))"
        $null = New-Item -Path $script:TmpDir -ItemType Directory -Force
    }
    AfterEach {
        if (Test-Path $script:TmpDir) { Remove-Item -LiteralPath $script:TmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'emits <section id="remediation-plan"> with priority badges when gaps exist' {
        $findings = @(New-SyntheticFinding -Status 'FAIL' -Severity 'High' -TSCReferences @('CC6.1'))
        $result = Build-Result -Findings $findings
        $htmlPath = Join-Path $script:TmpDir 'r.html'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $htmlPath
        $html = Get-Content -LiteralPath $htmlPath -Raw
        $html | Should -Match 'id="remediation-plan"'
        $section = ($html -split 'id="remediation-plan"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        $section | Should -Match '<th>Priority</th>'
        $section | Should -Match '<th>Validation</th>'
        $section | Should -Match "class='prio-badge prio-1'"
    }
}

Describe 'New-SOC2AuditWorkbook — CSV fallback writes 01b-Remediation-Plan.csv' {

    BeforeEach {
        $script:TmpDir = Join-Path $env:TEMP "soc2-rp-csv-$((Get-Random))"
        Mock -ModuleName EntraChecks-SOC2Reporting Get-Module {} -ParameterFilter { $Name -eq 'ImportExcel' -and $ListAvailable }
    }
    AfterEach {
        if (Test-Path $script:TmpDir) { Remove-Item -LiteralPath $script:TmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'writes 01b next to 01a, legacy 02/03 numbers unchanged' {
        $findings = @(New-SyntheticFinding -Status 'FAIL' -Severity 'High' -TSCReferences @('CC6.1'))
        $result = Build-Result -Findings $findings
        $xlsxPath = Join-Path $script:TmpDir 'wb.xlsx'
        $outDir = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath $xlsxPath
        (Test-Path (Join-Path $outDir '01a-Control-Conclusions.csv')) | Should -Be $true
        (Test-Path (Join-Path $outDir '01b-Remediation-Plan.csv')) | Should -Be $true
        (Test-Path (Join-Path $outDir '02-Summary-by-Category.csv')) | Should -Be $true
        (Test-Path (Join-Path $outDir '03-Control-Register.csv')) | Should -Be $true
    }

    It '01b columns match the Get-SOC2RemediationPlan projection' {
        $findings = @(New-SyntheticFinding -Status 'FAIL' -Severity 'High' -TSCReferences @('CC6.1'))
        $result = Build-Result -Findings $findings
        $xlsxPath = Join-Path $script:TmpDir 'wb.xlsx'
        $outDir = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath $xlsxPath
        $rows = Import-Csv (Join-Path $outDir '01b-Remediation-Plan.csv')
        $rows[0].PSObject.Properties.Name | Should -Contain 'Priority'
        $rows[0].PSObject.Properties.Name | Should -Contain 'Gap'
        $rows[0].PSObject.Properties.Name | Should -Contain 'EvidenceNeeded'
    }
}
