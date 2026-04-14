<#
.SYNOPSIS
    Pester 5 test suite for SOC 2 Phase 3 PR 2 — Type 2 period coverage.

.DESCRIPTION
    Validates Get-SOC2PeriodCoverage, the consistency state machine,
    gap detection, and evidence-bundle integrity (including
    Test-SOC2TypeTwoBundle source-snapshot tamper detection).

    Fixtures are generated synthetically per test (no committed snapshot
    files) — the helpers below build a temp Snapshots/ directory with
    Snapshot-*.json files matching the schema written by
    EntraChecks-DeltaReporting.psm1's Save-ComplianceSnapshot.

    Run: Invoke-Pester -Path Tests/SOC2-Phase3-TypeTwo.Tests.ps1

.NOTES
    Requires Pester 5.0+.
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-SOC2.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-SOC2TypeTwo.psm1') -Force

    function New-TestSnapshotDirectory {
        param([string]$Name = 'soc2-typetwo-tests')
        $path = Join-Path $env:TEMP "$Name-$((Get-Random))"
        $null = New-Item -Path $path -ItemType Directory -Force
        return $path
    }

    function New-SyntheticSnapshot {
        param(
            [Parameter(Mandatory)] [string]$Directory,
            [Parameter(Mandatory)] [DateTime]$CreatedAtUtc,
            [Parameter(Mandatory)] [object[]]$Findings,
            [string]$TenantName = 'TestTenant'
        )
        $id = $CreatedAtUtc.ToString('yyyyMMdd-HHmmss')
        $snapshot = @{}
        $snapshot['SnapshotId'] = $id
        $snapshot['TenantName'] = $TenantName
        $snapshot['CreatedAt'] = $CreatedAtUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $snapshot['CreatedAtUtc'] = $CreatedAtUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $snapshot['Version'] = '1.7.0-test'

        $findingsContainer = @{}
        $findingsContainer['Available'] = ($Findings.Count -gt 0)
        $findingsContainer['Count'] = $Findings.Count
        $findingsContainer['Data'] = $Findings

        $sources = @{}
        $sources['Findings'] = $findingsContainer

        $snapshot['Sources'] = $sources

        $summary = @{}
        $summary['TotalFindings'] = $Findings.Count
        $summary['FailCount'] = @($Findings | Where-Object { $_.Status -eq 'FAIL' }).Count
        $summary['WarningCount'] = @($Findings | Where-Object { $_.Status -eq 'WARNING' }).Count
        $summary['OKCount'] = @($Findings | Where-Object { $_.Status -eq 'OK' }).Count
        $summary['InfoCount'] = @($Findings | Where-Object { $_.Status -eq 'INFO' }).Count
        $snapshot['Summary'] = $summary

        $path = Join-Path $Directory "Snapshot-$id.json"
        $snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }

    function New-SOC2Finding-Test {
        param(
            [string]$Type = 'MFA_Disabled',
            [string]$Status = 'OK',
            [string]$Object = 'tenant',
            [string[]]$TSCReferences = @('CC6.1')
        )
        $f = @{}
        $f['Type'] = $Type
        $f['Status'] = $Status
        $f['Object'] = $Object
        $f['Description'] = "Synthetic finding for $Type"
        $f['Remediation'] = 'Test'
        $f['CheckName'] = "Test-$Type"
        $f['Category'] = 'SOC2'
        $f['Severity'] = if ($Status -eq 'FAIL') { 'High' } elseif ($Status -eq 'WARNING') { 'Medium' } else { 'Info' }
        $f['TSCReferences'] = $TSCReferences
        return $f
    }

    function New-HealthyScenario {
        # 13 weekly snapshots over 90 days, all controls PASS
        $dir = New-TestSnapshotDirectory -Name 'soc2-healthy'
        $start = [DateTime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime()
        for ($i = 0; $i -lt 13; $i++) {
            $when = $start.AddDays($i * 7)
            $findings = @(
                New-SOC2Finding-Test -Type 'MFA_Disabled' -Status 'OK' -TSCReferences @('CC6.1')
                New-SOC2Finding-Test -Type 'GlobalAdmin_Multiple' -Status 'OK' -TSCReferences @('CC6.3')
            )
            $null = New-SyntheticSnapshot -Directory $dir -CreatedAtUtc $when -Findings $findings
        }
        return @{ Path = $dir; Start = $start; End = $start.AddDays(90) }
    }

    function New-SparseScenario {
        # Only 5 snapshots over 90 days — below threshold
        $dir = New-TestSnapshotDirectory -Name 'soc2-sparse'
        $start = [DateTime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime()
        @(0, 14, 35, 56, 80) | ForEach-Object {
            $when = $start.AddDays($_)
            $findings = @(New-SOC2Finding-Test -Type 'MFA_Disabled' -Status 'OK' -TSCReferences @('CC6.1'))
            $null = New-SyntheticSnapshot -Directory $dir -CreatedAtUtc $when -Findings $findings
        }
        return @{ Path = $dir; Start = $start; End = $start.AddDays(90) }
    }

    function New-MixedScenario {
        # 13 snapshots; CC6.3 fails in snapshots 5, 6, 7 (one-shot exception)
        $dir = New-TestSnapshotDirectory -Name 'soc2-mixed'
        $start = [DateTime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime()
        for ($i = 0; $i -lt 13; $i++) {
            $when = $start.AddDays($i * 7)
            $cc63Status = if ($i -in @(5, 6, 7)) { 'FAIL' } else { 'OK' }
            $findings = @(
                New-SOC2Finding-Test -Type 'MFA_Disabled' -Status 'OK' -TSCReferences @('CC6.1')
                New-SOC2Finding-Test -Type 'GlobalAdmin_Multiple' -Status $cc63Status -TSCReferences @('CC6.3')
            )
            $null = New-SyntheticSnapshot -Directory $dir -CreatedAtUtc $when -Findings $findings
        }
        return @{ Path = $dir; Start = $start; End = $start.AddDays(90) }
    }

    function New-GapScenario {
        # 13 snapshots BUT a 30-day gap mid-period
        $dir = New-TestSnapshotDirectory -Name 'soc2-gap'
        $start = [DateTime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime()
        # First 6 weekly, then 30-day gap, then 7 more weekly
        $offsets = @(0, 7, 14, 21, 28, 35, 65, 72, 79, 86, 93, 100, 107)
        foreach ($off in $offsets) {
            $when = $start.AddDays($off)
            $findings = @(New-SOC2Finding-Test -Type 'MFA_Disabled' -Status 'OK' -TSCReferences @('CC6.1'))
            $null = New-SyntheticSnapshot -Directory $dir -CreatedAtUtc $when -Findings $findings
        }
        return @{ Path = $dir; Start = $start; End = $start.AddDays(120) }
    }

    function Remove-Scenario {
        param([string]$Path)
        if (Test-Path $Path) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Get-SOC2ControlConsistencyState (state machine)' {
    Context 'All-PASS observations' {
        It 'returns ConsistentlyPassing' {
            $result = Get-SOC2ControlConsistencyState -WorstStatusPerSnapshot @('OK', 'OK', 'OK')
            $result.State | Should -Be 'ConsistentlyPassing'
        }
    }
    Context 'All-FAIL observations' {
        It 'returns ConsistentlyFailing' {
            $result = Get-SOC2ControlConsistencyState -WorstStatusPerSnapshot @('FAIL', 'FAIL', 'FAIL')
            $result.State | Should -Be 'ConsistentlyFailing'
        }
    }
    Context 'Single FAIL among PASSes' {
        It 'returns Inconsistent at strict 0 exceptions' {
            $result = Get-SOC2ControlConsistencyState -WorstStatusPerSnapshot @('OK', 'OK', 'FAIL', 'OK') -ExceptionsAllowed 0
            $result.State | Should -Be 'Inconsistent'
            $result.FailOccurrences | Should -Be 1
        }
        It 'demotes to DegradedButOperating when ExceptionsAllowed=1' {
            $result = Get-SOC2ControlConsistencyState -WorstStatusPerSnapshot @('OK', 'OK', 'FAIL', 'OK') -ExceptionsAllowed 1
            $result.State | Should -Not -Be 'Inconsistent'
        }
    }
    Context 'Mix of PASS + WARNING (no FAIL)' {
        It 'returns DegradedButOperating' {
            $result = Get-SOC2ControlConsistencyState -WorstStatusPerSnapshot @('OK', 'WARNING', 'OK', 'WARNING')
            $result.State | Should -Be 'DegradedButOperating'
        }
    }
    Context 'Manual control regardless of observations' {
        It 'returns ManualAttestationRequired' {
            $result = Get-SOC2ControlConsistencyState -WorstStatusPerSnapshot @('FAIL', 'FAIL') -Automation 'Manual'
            $result.State | Should -Be 'ManualAttestationRequired'
        }
    }
    Context 'No observations at all' {
        It 'returns Unobserved' {
            $result = Get-SOC2ControlConsistencyState -WorstStatusPerSnapshot @()
            $result.State | Should -Be 'Unobserved'
        }
    }
}

Describe 'Get-SOC2PeriodCoverage - Healthy scenario (13 weekly snapshots, all PASS)' {
    BeforeAll {
        $script:HealthyScenario = New-HealthyScenario
    }
    AfterAll {
        Remove-Scenario -Path $script:HealthyScenario.Path
    }
    It 'meets Type 2 threshold' {
        $coverage = Get-SOC2PeriodCoverage `
            -SnapshotDirectory $script:HealthyScenario.Path `
            -StartDate $script:HealthyScenario.Start `
            -EndDate $script:HealthyScenario.End
        $coverage.MeetsTypeTwoThreshold | Should -Be $true
        $coverage.SnapshotCount | Should -Be 13
        $coverage.LargestGapDays | Should -BeLessOrEqual 10
    }
    It 'classifies CC6.1 as ConsistentlyPassing' {
        $coverage = Get-SOC2PeriodCoverage `
            -SnapshotDirectory $script:HealthyScenario.Path `
            -StartDate $script:HealthyScenario.Start `
            -EndDate $script:HealthyScenario.End
        $coverage.ControlAnalysis['CC6.1'].State | Should -Be 'ConsistentlyPassing'
    }
}

Describe 'Get-SOC2PeriodCoverage - Sparse scenario (5 snapshots, below threshold)' {
    BeforeAll { $script:SparseScenario = New-SparseScenario }
    AfterAll { Remove-Scenario -Path $script:SparseScenario.Path }
    It 'fails MeetsTypeTwoThreshold with snapshot-count reason' {
        $coverage = Get-SOC2PeriodCoverage `
            -SnapshotDirectory $script:SparseScenario.Path `
            -StartDate $script:SparseScenario.Start `
            -EndDate $script:SparseScenario.End `
            -MinSnapshotsRequired 12
        $coverage.MeetsTypeTwoThreshold | Should -Be $false
        $coverage.SnapshotCount | Should -Be 5
        ($coverage.ThresholdDetail -join ' ') | Should -BeLike '*below minimum*'
    }
    It 'still computes per-control analysis over the 5 snapshots' {
        $coverage = Get-SOC2PeriodCoverage `
            -SnapshotDirectory $script:SparseScenario.Path `
            -StartDate $script:SparseScenario.Start `
            -EndDate $script:SparseScenario.End `
            -MinSnapshotsRequired 12
        $coverage.ControlAnalysis['CC6.1'].PassOccurrences | Should -Be 5
    }
}

Describe 'Get-SOC2PeriodCoverage - Mixed scenario (CC6.3 fails 3 times)' {
    BeforeAll { $script:MixedScenario = New-MixedScenario }
    AfterAll { Remove-Scenario -Path $script:MixedScenario.Path }
    It 'classifies CC6.3 as Inconsistent (strict)' {
        $coverage = Get-SOC2PeriodCoverage `
            -SnapshotDirectory $script:MixedScenario.Path `
            -StartDate $script:MixedScenario.Start `
            -EndDate $script:MixedScenario.End
        $coverage.ControlAnalysis['CC6.3'].State | Should -Be 'Inconsistent'
        $coverage.ControlAnalysis['CC6.3'].FailOccurrences | Should -Be 3
    }
    It 'still classifies CC6.1 as ConsistentlyPassing (other controls unaffected)' {
        $coverage = Get-SOC2PeriodCoverage `
            -SnapshotDirectory $script:MixedScenario.Path `
            -StartDate $script:MixedScenario.Start `
            -EndDate $script:MixedScenario.End
        $coverage.ControlAnalysis['CC6.1'].State | Should -Be 'ConsistentlyPassing'
    }
}

Describe 'Get-SOC2PeriodCoverage - Gap scenario (30-day gap mid-period)' {
    BeforeAll { $script:GapScenario = New-GapScenario }
    AfterAll { Remove-Scenario -Path $script:GapScenario.Path }
    It 'fails MeetsTypeTwoThreshold with cadence reason' {
        $coverage = Get-SOC2PeriodCoverage `
            -SnapshotDirectory $script:GapScenario.Path `
            -StartDate $script:GapScenario.Start `
            -EndDate $script:GapScenario.End `
            -MaxGapDays 10
        $coverage.MeetsTypeTwoThreshold | Should -Be $false
        $coverage.LargestGapDays | Should -BeGreaterOrEqual 29
        ($coverage.ThresholdDetail -join ' ') | Should -BeLike '*Largest snapshot gap*'
    }
}

Describe 'New-SOC2TypeTwoEvidenceBundle + Test-SOC2TypeTwoBundle' {
    BeforeAll { $script:HealthyScenario2 = New-HealthyScenario }
    AfterAll { Remove-Scenario -Path $script:HealthyScenario2.Path }
    It 'produces an integrity-verified bundle' {
        $coverage = Get-SOC2PeriodCoverage `
            -SnapshotDirectory $script:HealthyScenario2.Path `
            -StartDate $script:HealthyScenario2.Start `
            -EndDate $script:HealthyScenario2.End

        $bundleDir = Join-Path $env:TEMP "soc2-tt2-bundle-$((Get-Random))"
        try {
            $evidence = New-SOC2TypeTwoEvidenceBundle `
                -Coverage $coverage `
                -OutputDirectory $bundleDir `
                -TenantId 'test-tenant' `
                -TenantName 'TestTenant' `
                -Assessor 'pester'

            $verify = Test-SOC2TypeTwoBundle -ManifestPath $evidence.ManifestPath
            $verify.Valid | Should -Be $true
            $verify.Mismatches.Count | Should -Be 0
            $verify.TamperedSnapshots.Count | Should -Be 0
        } finally {
            if (Test-Path $bundleDir) { Remove-Item -LiteralPath $bundleDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'detects source-snapshot tampering (chain of custody)' {
        $coverage = Get-SOC2PeriodCoverage `
            -SnapshotDirectory $script:HealthyScenario2.Path `
            -StartDate $script:HealthyScenario2.Start `
            -EndDate $script:HealthyScenario2.End

        $bundleDir = Join-Path $env:TEMP "soc2-tt2-tamper-$((Get-Random))"
        try {
            $evidence = New-SOC2TypeTwoEvidenceBundle `
                -Coverage $coverage `
                -OutputDirectory $bundleDir `
                -TenantId 'test-tenant'

            # Tamper with one source snapshot
            $sourceFile = (Get-ChildItem -LiteralPath $script:HealthyScenario2.Path -Filter 'Snapshot-*.json' | Select-Object -First 1).FullName
            Add-Content -LiteralPath $sourceFile -Value ' '

            $verify = Test-SOC2TypeTwoBundle -ManifestPath $evidence.ManifestPath
            $verify.Valid | Should -Be $false
            $verify.TamperedSnapshots.Count | Should -BeGreaterOrEqual 1
        } finally {
            if (Test-Path $bundleDir) { Remove-Item -LiteralPath $bundleDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'New-SOC2TypeTwoReport' {
    BeforeAll { $script:HealthyScenario3 = New-HealthyScenario }
    AfterAll { Remove-Scenario -Path $script:HealthyScenario3.Path }
    It 'renders an HTML file' {
        $coverage = Get-SOC2PeriodCoverage `
            -SnapshotDirectory $script:HealthyScenario3.Path `
            -StartDate $script:HealthyScenario3.Start `
            -EndDate $script:HealthyScenario3.End
        $bundleDir = Join-Path $env:TEMP "soc2-tt2-report-$((Get-Random))"
        try {
            $evidence = New-SOC2TypeTwoEvidenceBundle -Coverage $coverage -OutputDirectory $bundleDir -TenantId 't'
            $htmlPath = Join-Path $bundleDir 'report.html'
            $null = New-SOC2TypeTwoReport -Coverage $coverage -Evidence $evidence -OutputPath $htmlPath
            Test-Path $htmlPath | Should -Be $true
            (Get-Item $htmlPath).Length | Should -BeGreaterThan 1000
            (Get-Content $htmlPath -Raw) | Should -BeLike '*Type 2 coverage MET*'
        } finally {
            if (Test-Path $bundleDir) { Remove-Item -LiteralPath $bundleDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}
