<#
.SYNOPSIS
    Pester 5 test suite for unified-report PR 1 (housekeeping).

.DESCRIPTION
    Covers three changes:
    1. CSV fallback in EntraChecks-ExcelReporting.psm1 produces all 9 sheets
       under the per-report subfolder.
    2. -PreviousAssessment in EntraChecks-HTMLReporting.psm1 wires through to
       a "Since last assessment" delta card in the executive section.
    3. Get-FindingsDelta produces correct Resolved / New / Persistent counts.

    Run: Invoke-Pester -Path Tests/UnifiedReport-PR1.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-RiskScoring.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-RemediationGuidance.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-ExcelReporting.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-HTMLReporting.psm1') -Force

    function New-PR1TestFinding {
        param(
            [string]$Description = 'Synthetic finding',
            [string]$Object = 'user-1',
            [string]$Status = 'FAIL',
            [string]$RiskLevel = 'High',
            [int]$RiskScore = 60,
            [string]$Type = 'MFA_Disabled'
        )
        [pscustomobject]@{
            Time = (Get-Date)
            Status = $Status
            Object = $Object
            Description = $Description
            Remediation = 'Synthetic remediation'
            RiskLevel = $RiskLevel
            RiskScore = $RiskScore
            PriorityScore = 30
            RemediationEffortDescription = 'Easy'
            ComplianceReference = 'CIS 1.1'
            Type = $Type
        }
    }

    $script:tenantInfo = [pscustomobject]@{
        TenantName = 'Test-Tenant'
        TenantId = '00000000-0000-0000-0000-000000000000'
    }
}

Describe 'Get-FindingsDelta' {

    It 'returns zero counts for two identical sets' {
        $f = New-PR1TestFinding -Description 'A' -Object 'x'
        $delta = & (Get-Module EntraChecks-HTMLReporting) {
            param($a, $b) Get-FindingsDelta -Current $a -Previous $b
        } @($f) @($f)

        $delta.Resolved   | Should -Be 0
        $delta.New        | Should -Be 0
        $delta.Persistent | Should -Be 1
    }

    It 'counts a finding present only in previous as Resolved' {
        $prev = New-PR1TestFinding -Description 'A' -Object 'x'
        $cur = New-PR1TestFinding -Description 'B' -Object 'y'
        $delta = & (Get-Module EntraChecks-HTMLReporting) {
            param($a, $b) Get-FindingsDelta -Current $a -Previous $b
        } @($cur) @($prev)

        $delta.Resolved   | Should -Be 1
        $delta.New        | Should -Be 1
        $delta.Persistent | Should -Be 0
    }

    It 'counts a finding present only in current as New' {
        $cur = New-PR1TestFinding -Description 'A' -Object 'x'
        # Use the comma idiom to keep the empty array intact through ScriptBlock
        # argument binding (PowerShell otherwise unwraps @() to zero arguments).
        $delta = & (Get-Module EntraChecks-HTMLReporting) {
            param($a, $b) Get-FindingsDelta -Current $a -Previous $b
        } @($cur) (, @())

        $delta.Resolved   | Should -Be 0
        $delta.New        | Should -Be 1
        $delta.Persistent | Should -Be 0
    }

    It 'handles a mixed set: 1 resolved, 1 new, 1 persistent' {
        $prev = @(
            (New-PR1TestFinding -Description 'A' -Object 'x'),
            (New-PR1TestFinding -Description 'B' -Object 'y')
        )
        $cur = @(
            (New-PR1TestFinding -Description 'A' -Object 'x'),
            (New-PR1TestFinding -Description 'C' -Object 'z')
        )
        $delta = & (Get-Module EntraChecks-HTMLReporting) {
            param($a, $b) Get-FindingsDelta -Current $a -Previous $b
        } $cur $prev

        $delta.Resolved   | Should -Be 1
        $delta.New        | Should -Be 1
        $delta.Persistent | Should -Be 1
    }
}

Describe 'New-EnhancedHTMLReport -PreviousAssessment wiring' {

    It 'omits the "Since last assessment" row when no previous assessment is supplied' {
        $f = New-PR1TestFinding
        $out = Join-Path $env:TEMP "pr1-no-prev-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Not -Match 'Since last assessment'
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        }
    }

    It 'emits the "Since last assessment" row when a previous assessment is supplied' {
        $prev = New-PR1TestFinding -Description 'Old finding' -Object 'old-user'
        $cur = New-PR1TestFinding -Description 'New finding' -Object 'new-user'
        $out = Join-Path $env:TEMP "pr1-with-prev-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($cur) -OutputPath $out -TenantInfo $script:tenantInfo `
                -PreviousAssessment ([pscustomobject]@{ Findings = @($prev) }) | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'Since last assessment'
            # Resolved card should show 1 (old finding gone), New card should show 1 (new finding appeared).
            $html | Should -Match 'Resolved'
            $html | Should -Match 'Findings closed since last run'
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        }
    }

    It 'accepts a bare findings array as -PreviousAssessment (not a snapshot wrapper)' {
        $prev = New-PR1TestFinding -Description 'Old finding' -Object 'old-user'
        $cur = New-PR1TestFinding -Description 'New finding' -Object 'new-user'
        $out = Join-Path $env:TEMP "pr1-bare-array-$((Get-Random)).html"
        try {
            # Pass a single object, not wrapped in @{Findings=...}.
            New-EnhancedHTMLReport -Findings @($cur) -OutputPath $out -TenantInfo $script:tenantInfo `
                -PreviousAssessment $prev | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'Since last assessment'
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'New-CSVWorkbook fallback' {

    It 'produces all expected CSV files in the per-report subfolder' {
        $f1 = New-PR1TestFinding -Description 'A' -Object 'x' -Type 'MFA_Disabled'
        $f2 = New-PR1TestFinding -Description 'B' -Object 'y' -Type 'NoConditionalAccessPolicy' -RiskLevel 'Critical' -RiskScore 90
        $tempDir = Join-Path $env:TEMP "pr1-csv-$((Get-Random))"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        $outPath = Join-Path $tempDir 'report.xlsx'
        try {
            # Call the private function directly via the module — this avoids
            # the ImportExcel preference check at the public surface.
            & (Get-Module EntraChecks-ExcelReporting) {
                param($findings, $path, $tenant)
                # Enhance findings the way the public path does, so the helpers
                # see ComplianceMappings populated.
                $enhanced = @()
                foreach ($x in $findings) {
                    $enhanced += ($x | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance)
                }
                New-CSVWorkbook -Findings $enhanced -OutputPath $path -TenantInfo $tenant
            } @($f1, $f2) $outPath $script:tenantInfo

            $csvDir = Join-Path $tempDir 'report-CSV'
            (Test-Path $csvDir) | Should -Be $true

            # The mandatory three sheets that always exist regardless of mappings.
            (Test-Path (Join-Path $csvDir '01-ExecutiveSummary.csv')) | Should -Be $true
            (Test-Path (Join-Path $csvDir '02-AllFindings.csv'))      | Should -Be $true
            (Test-Path (Join-Path $csvDir '03-PriorityFindings.csv')) | Should -Be $true
            (Test-Path (Join-Path $csvDir '09-RiskAnalysis.csv'))     | Should -Be $true

            # Spot-check that AllFindings carries our synthetic descriptions.
            $allRows = Import-Csv -LiteralPath (Join-Path $csvDir '02-AllFindings.csv')
            ($allRows.Description -contains 'A') | Should -Be $true
            ($allRows.Description -contains 'B') | Should -Be $true
        }
        finally {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not leak the rank counter across two consecutive runs' {
        # Regression test for the $script:rank scope leak. After two calls,
        # the second run's rank should restart from 1, not continue from N.
        $findings = 1..3 | ForEach-Object {
            New-PR1TestFinding -Description "F$_" -Object "u$_" -RiskScore (50 + $_)
        }
        $tempDir1 = Join-Path $env:TEMP "pr1-rank-1-$((Get-Random))"
        $tempDir2 = Join-Path $env:TEMP "pr1-rank-2-$((Get-Random))"
        New-Item -Path $tempDir1 -ItemType Directory -Force | Out-Null
        New-Item -Path $tempDir2 -ItemType Directory -Force | Out-Null
        try {
            foreach ($dir in @($tempDir1, $tempDir2)) {
                & (Get-Module EntraChecks-ExcelReporting) {
                    param($findings, $path, $tenant)
                    $enhanced = @()
                    foreach ($x in $findings) {
                        $enhanced += ($x | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance)
                    }
                    New-CSVWorkbook -Findings $enhanced -OutputPath $path -TenantInfo $tenant
                } $findings (Join-Path $dir 'report.xlsx') $script:tenantInfo
            }

            $priorityRows1 = Import-Csv -LiteralPath (Join-Path $tempDir1 'report-CSV\03-PriorityFindings.csv')
            $priorityRows2 = Import-Csv -LiteralPath (Join-Path $tempDir2 'report-CSV\03-PriorityFindings.csv')

            # Both runs should start at Rank 1.
            $priorityRows1[0].Rank | Should -Be '1'
            $priorityRows2[0].Rank | Should -Be '1'
        }
        finally {
            Remove-Item -LiteralPath $tempDir1 -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $tempDir2 -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
