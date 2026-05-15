<#
.SYNOPSIS
    Pester 5 tests for Get-SOC2ControlConclusion (SOC 2 Audit-Readiness Plan
    PR 1) — exhaustive precedence matrix from plans/SOC2-Audit-Readiness-Plan.md §7.

.DESCRIPTION
    One Describe block per precedence row. Each test feeds a minimal v2-shaped
    finding (or no findings) into Get-SOC2ControlConclusion and asserts the
    resulting Conclusion + DeficiencySeverity + BlockingFinding identity.

    The precedence (top wins):

        FAIL (active)              -> Deficiency           (severity from highest FAIL)
        WARNING (active)           -> Deficiency - Minor
        REVIEW / MANUAL unattested -> Manual Pending
        Licensing Gap              -> Not Assessed - Licensing
        Accepted Risk only         -> Accepted Risk        (AcceptedRisk/CompensatingControl)
        INFO                       -> Informational
        OK + evidence              -> Effective
        OK without evidence        -> Effective            (audit-trail concern, not deficiency)
        Nothing                    -> Not Assessed - No Evidence

    Disposition in {FalsePositive, OutOfScope, Resolved, Suppressed} on FAIL
    or WARNING removes that finding from contention entirely.

    Run: Invoke-Pester -Path Tests/SOC2-ControlConclusion.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2.psm1') -Force -WarningAction SilentlyContinue
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2Reporting.psm1') -Force

    function script:New-TestFinding {
        param(
            [string]$Status,
            [string]$Severity = 'Info',
            [string]$Description = 'synthetic',
            [string]$Type = 'SOC2_Test',
            [string]$Disposition = '',
            [string[]]$Tags = @(),
            [hashtable]$ReviewStatus
        )
        $obj = [pscustomobject]@{
            Status = $Status
            Severity = $Severity
            Description = $Description
            Type = $Type
            Tags = $Tags
        }
        if ($Disposition) {
            Add-Member -InputObject $obj -MemberType NoteProperty -Name Disposition -Value $Disposition -Force
        }
        if ($ReviewStatus) {
            Add-Member -InputObject $obj -MemberType NoteProperty -Name ReviewStatus -Value ([pscustomobject]$ReviewStatus) -Force
        }
        return $obj
    }
}

Describe 'Get-SOC2ControlConclusion — row 1: FAIL drives Deficiency' {

    It 'returns Deficiency when a single FAIL is present' {
        $f = New-TestFinding -Status 'FAIL' -Severity 'High'
        $r = Get-SOC2ControlConclusion -ControlId 'CC6.1' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Deficiency'
        $r.DeficiencySeverity | Should -BeExactly 'High'
        $r.BlockingFinding | Should -Be $f
    }

    It 'picks the highest-severity FAIL when several are present' {
        $low = New-TestFinding -Status 'FAIL' -Severity 'Low' -Description 'low fail'
        $crit = New-TestFinding -Status 'FAIL' -Severity 'Critical' -Description 'critical fail'
        $r = Get-SOC2ControlConclusion -ControlId 'CC6.1' -Findings @($low, $crit) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Deficiency'
        $r.DeficiencySeverity | Should -BeExactly 'Critical'
        $r.BlockingFinding.Description | Should -BeExactly 'critical fail'
    }

    It 'beats WARNING + MANUAL + Licensing + Info even when all coexist' {
        $fail = New-TestFinding -Status 'FAIL' -Severity 'High'
        $warn = New-TestFinding -Status 'WARNING' -Severity 'Medium'
        $manual = New-TestFinding -Status 'MANUAL'
        $info = New-TestFinding -Status 'INFO'
        $gap = New-TestFinding -Status 'INFO' -Type 'SOC2_LicensingGap_Intune'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($warn, $manual, $info, $gap, $fail) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Deficiency'
    }
}

Describe 'Get-SOC2ControlConclusion — row 2: WARNING drives Deficiency - Minor' {

    It 'returns Deficiency - Minor when only WARNING is present' {
        $f = New-TestFinding -Status 'WARNING' -Severity 'Medium'
        $r = Get-SOC2ControlConclusion -ControlId 'A1.1' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Deficiency - Minor'
        $r.DeficiencySeverity | Should -BeExactly 'Medium'
    }

    It 'still wins over MANUAL / Licensing / INFO / OK' {
        $warn = New-TestFinding -Status 'WARNING'
        $manual = New-TestFinding -Status 'MANUAL'
        $info = New-TestFinding -Status 'INFO'
        $ok = New-TestFinding -Status 'OK'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($manual, $info, $ok, $warn) -EvidenceCount 1
        $r.Conclusion | Should -BeExactly 'Deficiency - Minor'
    }
}

Describe 'Get-SOC2ControlConclusion — row 3: REVIEW/MANUAL drive Manual Pending' {

    It 'returns Manual Pending for an unattested MANUAL finding' {
        $f = New-TestFinding -Status 'MANUAL'
        $r = Get-SOC2ControlConclusion -ControlId 'CC1.1' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Manual Pending'
    }

    It 'returns Manual Pending for an unattested REVIEW finding' {
        $f = New-TestFinding -Status 'REVIEW'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Manual Pending'
    }

    It 'treats ReviewStatus.State=Accepted as attested (not Pending)' {
        $f = New-TestFinding -Status 'MANUAL' -ReviewStatus @{ State = 'Accepted' }
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f) -EvidenceCount 1
        $r.Conclusion | Should -BeExactly 'Effective'
    }

    It 'treats ReviewStatus.State=Reviewed as attested' {
        $f = New-TestFinding -Status 'MANUAL' -ReviewStatus @{ State = 'Reviewed' }
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f) -EvidenceCount 1
        $r.Conclusion | Should -BeExactly 'Effective'
    }
}

Describe 'Get-SOC2ControlConclusion — row 4: Licensing Gap drives Not Assessed - Licensing' {

    It 'returns Not Assessed - Licensing for SOC2_LicensingGap_* Type' {
        $f = New-TestFinding -Status 'INFO' -Type 'SOC2_LicensingGap_IdentityProtection'
        $r = Get-SOC2ControlConclusion -ControlId 'CC4.1' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Not Assessed - Licensing'
    }

    It 'recognizes LicensingGap via Tags as well as Type' {
        $f = New-TestFinding -Status 'INFO' -Type 'Custom' -Tags @('LicensingGap')
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Not Assessed - Licensing'
    }

    It 'wins over INFO + OK but loses to active FAIL/WARNING/MANUAL' {
        $gap = New-TestFinding -Status 'INFO' -Type 'SOC2_LicensingGap_Intune'
        $info = New-TestFinding -Status 'INFO'
        $ok = New-TestFinding -Status 'OK'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($info, $ok, $gap) -EvidenceCount 1
        $r.Conclusion | Should -BeExactly 'Not Assessed - Licensing'

        $manual = New-TestFinding -Status 'MANUAL'
        $r2 = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($manual, $gap) -EvidenceCount 0
        $r2.Conclusion | Should -BeExactly 'Manual Pending'
    }
}

Describe 'Get-SOC2ControlConclusion — Accepted Risk override (row 1/2 override)' {

    It 'returns Accepted Risk when only blocker has Disposition=AcceptedRisk' {
        $f = New-TestFinding -Status 'FAIL' -Severity 'High' -Disposition 'AcceptedRisk'
        $r = Get-SOC2ControlConclusion -ControlId 'CC6.1' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Accepted Risk'
    }

    It 'CompensatingControl disposition also maps to Accepted Risk' {
        $f = New-TestFinding -Status 'FAIL' -Severity 'High' -Disposition 'CompensatingControl'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Accepted Risk'
    }

    It 'a separate unaccepted WARNING still drives Deficiency - Minor' {
        # Plan §7: AcceptedRisk overrides rows 1-2 only when it would be the
        # blocking finding. If another active blocker exists, that wins.
        $accepted = New-TestFinding -Status 'FAIL' -Severity 'High' -Disposition 'AcceptedRisk' -Description 'accepted'
        $warn = New-TestFinding -Status 'WARNING' -Severity 'Medium' -Description 'real warning'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($accepted, $warn) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Deficiency - Minor'
    }
}

Describe 'Get-SOC2ControlConclusion — excluded dispositions (do not block)' {

    It 'FAIL with FalsePositive disposition does not drive Deficiency' {
        $f = New-TestFinding -Status 'FAIL' -Severity 'High' -Disposition 'FalsePositive'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -Not -BeExactly 'Deficiency'
        $r.Conclusion | Should -Not -BeExactly 'Accepted Risk'
    }

    It 'FAIL with OutOfScope disposition does not drive Deficiency' {
        $f = New-TestFinding -Status 'FAIL' -Severity 'High' -Disposition 'OutOfScope'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -Not -BeExactly 'Deficiency'
    }

    It 'WARNING with Resolved disposition is ignored' {
        $f = New-TestFinding -Status 'WARNING' -Severity 'Medium' -Disposition 'Resolved'
        $ok = New-TestFinding -Status 'OK'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f, $ok) -EvidenceCount 1
        $r.Conclusion | Should -BeExactly 'Effective'
    }
}

Describe 'Get-SOC2ControlConclusion — row 5: INFO drives Informational' {

    It 'returns Informational when only INFO findings exist' {
        $f = New-TestFinding -Status 'INFO'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Informational'
    }

    It 'INFO beats OK (precedence: INFO > OK)' {
        $info = New-TestFinding -Status 'INFO'
        $ok = New-TestFinding -Status 'OK'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($ok, $info) -EvidenceCount 1
        $r.Conclusion | Should -BeExactly 'Informational'
    }
}

Describe 'Get-SOC2ControlConclusion — row 6: OK + evidence drives Effective' {

    It 'returns Effective when only OK findings exist and evidence is present' {
        $f = New-TestFinding -Status 'OK'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f) -EvidenceCount 1
        $r.Conclusion | Should -BeExactly 'Effective'
    }

    It 'returns Effective even without evidence (OK is OK)' {
        # Audit-trail concern handled separately by the Evidence Matrix PR.
        $f = New-TestFinding -Status 'OK'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($f) -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Effective'
    }
}

Describe 'Get-SOC2ControlConclusion — row 7: empty drives Not Assessed - No Evidence' {

    It 'returns Not Assessed - No Evidence when there are no findings and no evidence' {
        $r = Get-SOC2ControlConclusion -ControlId 'CC8.1' -Findings @() -EvidenceCount 0
        $r.Conclusion | Should -BeExactly 'Not Assessed - No Evidence'
        $r.BlockingFinding | Should -BeNullOrEmpty
    }
}

Describe 'Get-SOC2ControlConclusion — output shape' {

    It 'always echoes the ControlId back on the output' {
        $r = Get-SOC2ControlConclusion -ControlId 'MyControl.42' -Findings @() -EvidenceCount 0
        $r.ControlId | Should -BeExactly 'MyControl.42'
    }

    It 'always reports FindingCount + EvidenceCount on the output' {
        $a = New-TestFinding -Status 'OK'
        $b = New-TestFinding -Status 'OK'
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @($a, $b) -EvidenceCount 3
        $r.FindingCount | Should -Be 2
        $r.EvidenceCount | Should -Be 3
    }

    It 'always populates Reason with a non-empty string' {
        $r = Get-SOC2ControlConclusion -ControlId 'X' -Findings @() -EvidenceCount 0
        $r.Reason | Should -Not -BeNullOrEmpty
    }
}
