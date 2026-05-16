<#
.SYNOPSIS
    Pester 5 tests for the SOC 2 Type 2 Period Coverage Dashboard
    (plans/SOC2-Audit-Readiness-Plan.md §11.2).

.DESCRIPTION
    Coverage:
      * Get-SOC2TypeTwoFreshnessBucket boundary math (29/30/89/90 days,
        empty/unparseable, clock skew, tz-kind safety).
      * Get-SOC2PeriodCoverageDashboard pure aggregation:
          - snapshots expected vs collected + coverage %.
          - gap-within-threshold logic (largest/leading/trailing).
          - per-state consistency rollup.
          - flap detection (all-pass/all-fail = 0, pass/fail/pass = 2,
            WARNING is fail-ish, INFO ignored, single observation = 0).
          - freshness distribution by family, AsOf defaulting to the
            period end, Unknown for never-observed controls.
      * End-to-end: real snapshots → Get-SOC2PeriodCoverage →
        Get-SOC2PeriodCoverageDashboard → New-SOC2TypeTwoReport renders
        the #period-coverage section, tiles, flapping + freshness tables.

    Run: Invoke-Pester -Path Tests/SOC2-PeriodCoverageDashboard.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    if (-not $env:TEMP) {
        $env:TEMP = if ($env:TMPDIR) { $env:TMPDIR.TrimEnd('/') } else { '/tmp' }
    }
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2.psm1') -Force -WarningAction SilentlyContinue
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2TypeTwo.psm1') -Force -WarningAction SilentlyContinue

    $script:Now = [datetime]::SpecifyKind([datetime]'2026-05-15T00:00:00', [System.DateTimeKind]::Utc)

    function script:New-Coverage {
        param(
            [int]$MinSnapshotsRequired = 12,
            [int]$SnapshotCount = 9,
            [double]$LargestGapDays = 5,
            [double]$LeadingGapDays = 2,
            [double]$TrailingGapDays = 2,
            [double]$MaxGapDays = 10,
            [bool]$MeetsTypeTwoThreshold = $true,
            [hashtable]$ControlAnalysis = @{},
            [string]$EndUtc = '2026-05-15T00:00:00Z'
        )
        @{
            Period = @{ StartUtc = '2026-02-14T00:00:00Z'; EndUtc = $EndUtc; Days = 90 }
            MinSnapshotsRequired = $MinSnapshotsRequired
            SnapshotCount = $SnapshotCount
            LargestGapDays = $LargestGapDays
            LeadingGapDays = $LeadingGapDays
            TrailingGapDays = $TrailingGapDays
            MaxGapDays = $MaxGapDays
            MeetsTypeTwoThreshold = $MeetsTypeTwoThreshold
            ThresholdDetail = @()
            ControlAnalysis = $ControlAnalysis
        }
    }

    function script:New-ControlAnalysis {
        param(
            [string]$ControlId, [string]$Family = 'CC', [string]$State = 'ConsistentlyPassing',
            [string]$LastSeenUtc = '2026-05-14T00:00:00Z', [string[]]$TraceStatuses = @('OK')
        )
        $trace = foreach ($s in $TraceStatuses) { @{ WorstStatus = $s } }
        @{
            ControlId = $ControlId; Family = $Family; State = $State
            PassOccurrences = @($TraceStatuses | Where-Object { $_ -in @('OK', 'PASS') }).Count
            FailOccurrences = @($TraceStatuses | Where-Object { $_ -eq 'FAIL' }).Count
            WarningOccurrences = @($TraceStatuses | Where-Object { $_ -eq 'WARNING' }).Count
            LastSeenUtc = $LastSeenUtc
            Trace = @($trace)
        }
    }
}

Describe 'Get-SOC2TypeTwoFreshnessBucket — boundary math' {
    It 'Fresh below 30d' { Get-SOC2TypeTwoFreshnessBucket -IsoDate $script:Now.AddDays(-29).ToString('o') -AsOf $script:Now | Should -BeExactly 'Fresh' }
    It 'Aging at exactly 30d' { Get-SOC2TypeTwoFreshnessBucket -IsoDate $script:Now.AddDays(-30).ToString('o') -AsOf $script:Now | Should -BeExactly 'Aging' }
    It 'Aging at 89d' { Get-SOC2TypeTwoFreshnessBucket -IsoDate $script:Now.AddDays(-89).ToString('o') -AsOf $script:Now | Should -BeExactly 'Aging' }
    It 'Stale at exactly 90d' { Get-SOC2TypeTwoFreshnessBucket -IsoDate $script:Now.AddDays(-90).ToString('o') -AsOf $script:Now | Should -BeExactly 'Stale' }
    It 'Unknown for empty/unparseable/null' {
        Get-SOC2TypeTwoFreshnessBucket -IsoDate '' -AsOf $script:Now | Should -BeExactly 'Unknown'
        Get-SOC2TypeTwoFreshnessBucket -IsoDate 'nope' -AsOf $script:Now | Should -BeExactly 'Unknown'
        Get-SOC2TypeTwoFreshnessBucket -IsoDate $null -AsOf $script:Now | Should -BeExactly 'Unknown'
    }
    It 'clock skew (future) clamps to Fresh' {
        Get-SOC2TypeTwoFreshnessBucket -IsoDate $script:Now.AddDays(10).ToString('o') -AsOf $script:Now | Should -BeExactly 'Fresh'
    }
    It 'tz-kind safe (Local AsOf vs UTC stamp)' {
        $localAsOf = [datetime]::SpecifyKind([datetime]'2026-05-15T00:00:00', [System.DateTimeKind]::Local)
        Get-SOC2TypeTwoFreshnessBucket -IsoDate '2026-04-05T00:00:00Z' -AsOf $localAsOf | Should -BeExactly 'Aging'
    }
}

Describe 'Get-SOC2PeriodCoverageDashboard — snapshot coverage' {
    It 'computes expected/collected and a capped percentage' {
        $d = Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -MinSnapshotsRequired 12 -SnapshotCount 9)
        $d.SnapshotsExpected | Should -Be 12
        $d.SnapshotsCollected | Should -Be 9
        $d.CoveragePercent | Should -Be 75
    }
    It 'caps coverage at 100% when over-collected' {
        (Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -MinSnapshotsRequired 10 -SnapshotCount 25)).CoveragePercent | Should -Be 100
    }
    It 'handles a zero expected requirement' {
        (Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -MinSnapshotsRequired 0 -SnapshotCount 5)).CoveragePercent | Should -Be 100
        (Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -MinSnapshotsRequired 0 -SnapshotCount 0)).CoveragePercent | Should -Be 0
    }
}

Describe 'Get-SOC2PeriodCoverageDashboard — gap threshold' {
    It 'GapWithinThreshold true when every gap is within MaxGapDays' {
        (Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -LargestGapDays 9 -LeadingGapDays 4 -TrailingGapDays 4 -MaxGapDays 10)).GapWithinThreshold | Should -BeTrue
    }
    It 'GapWithinThreshold false when the largest gap exceeds MaxGapDays' {
        (Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -LargestGapDays 11 -MaxGapDays 10)).GapWithinThreshold | Should -BeFalse
    }
    It 'GapWithinThreshold false when only the leading gap exceeds' {
        (Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -LargestGapDays 5 -LeadingGapDays 30 -MaxGapDays 10)).GapWithinThreshold | Should -BeFalse
    }
}

Describe 'Get-SOC2PeriodCoverageDashboard — consistency rollup' {
    It 'tallies each control state and total' {
        $ca = @{
            'CC6.1' = New-ControlAnalysis -ControlId CC6.1 -State 'ConsistentlyPassing'
            'CC6.2' = New-ControlAnalysis -ControlId CC6.2 -State 'Inconsistent'
            'CC6.3' = New-ControlAnalysis -ControlId CC6.3 -State 'ConsistentlyFailing'
            'CC1.1' = New-ControlAnalysis -ControlId CC1.1 -State 'ManualAttestationRequired'
        }
        $d = Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -ControlAnalysis $ca)
        $d.TotalControls | Should -Be 4
        $d.ConsistencyCounts['ConsistentlyPassing'] | Should -Be 1
        $d.ConsistencyCounts['Inconsistent'] | Should -Be 1
        $d.ConsistencyCounts['ConsistentlyFailing'] | Should -Be 1
        $d.ConsistencyCounts['ManualAttestationRequired'] | Should -Be 1
    }
}

Describe 'Get-SOC2PeriodCoverageDashboard — flap detection' {
    It 'all-pass and all-fail have FlapCount 0 (not listed)' {
        $ca = @{
            'CC6.1' = New-ControlAnalysis -ControlId CC6.1 -TraceStatuses @('OK', 'OK', 'OK')
            'CC6.2' = New-ControlAnalysis -ControlId CC6.2 -TraceStatuses @('FAIL', 'FAIL')
        }
        (Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -ControlAnalysis $ca)).FlappingCount | Should -Be 0
    }
    It 'pass→fail→pass = 2 crossings' {
        $ca = @{ 'CC6.3' = New-ControlAnalysis -ControlId CC6.3 -TraceStatuses @('OK', 'FAIL', 'OK') }
        $d = Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -ControlAnalysis $ca)
        $d.FlappingCount | Should -Be 1
        ($d.FlappingControls | Where-Object ControlId -eq 'CC6.3').FlapCount | Should -Be 2
    }
    It 'WARNING counts as fail-ish' {
        $ca = @{ 'CC6.4' = New-ControlAnalysis -ControlId CC6.4 -TraceStatuses @('OK', 'WARNING', 'OK') }
        ($(Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -ControlAnalysis $ca)).FlappingControls | Where-Object ControlId -eq 'CC6.4').FlapCount | Should -Be 2
    }
    It 'INFO entries are skipped, not treated as a boundary' {
        # OK, INFO, OK collapses to OK,OK → no flap.
        $ca = @{ 'CC6.5' = New-ControlAnalysis -ControlId CC6.5 -TraceStatuses @('OK', 'INFO', 'OK') }
        (Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -ControlAnalysis $ca)).FlappingCount | Should -Be 0
    }
    It 'a single observation never flaps' {
        $ca = @{ 'CC6.6' = New-ControlAnalysis -ControlId CC6.6 -TraceStatuses @('FAIL') }
        (Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -ControlAnalysis $ca)).FlappingCount | Should -Be 0
    }
    It 'sorts flapping controls by FlapCount desc then ControlId' {
        $ca = @{
            'CC6.1' = New-ControlAnalysis -ControlId CC6.1 -TraceStatuses @('OK', 'FAIL', 'OK')          # 2
            'CC6.2' = New-ControlAnalysis -ControlId CC6.2 -TraceStatuses @('OK', 'FAIL', 'OK', 'FAIL')   # 3
            'CC6.3' = New-ControlAnalysis -ControlId CC6.3 -TraceStatuses @('FAIL', 'OK', 'FAIL')         # 2
        }
        $d = Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -ControlAnalysis $ca)
        @($d.FlappingControls | ForEach-Object ControlId) | Should -Be @('CC6.2', 'CC6.1', 'CC6.3')
    }
}

Describe 'Get-SOC2PeriodCoverageDashboard — freshness by family' {
    It 'buckets each control by last-seen age and groups by family' {
        $ca = @{
            'CC6.1' = New-ControlAnalysis -ControlId CC6.1 -Family CC -LastSeenUtc '2026-05-14T00:00:00Z' # ~1d Fresh
            'CC6.2' = New-ControlAnalysis -ControlId CC6.2 -Family CC -LastSeenUtc '2026-03-01T00:00:00Z' # ~75d Aging
            'A1.1' = New-ControlAnalysis -ControlId A1.1 -Family A -LastSeenUtc '' # Unknown
        }
        $d = Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -ControlAnalysis $ca -EndUtc '2026-05-15T00:00:00Z')
        $d.FreshnessByFamily['CC']['Fresh'] | Should -Be 1
        $d.FreshnessByFamily['CC']['Aging'] | Should -Be 1
        $d.FreshnessByFamily['A']['Unknown'] | Should -Be 1
    }
    It 'AsOf defaults to the period end' {
        $ca = @{ 'CC6.1' = New-ControlAnalysis -ControlId CC6.1 -LastSeenUtc '2026-01-01T00:00:00Z' }
        # Period end 2026-05-15 → ~134 days → Stale.
        $d = Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -ControlAnalysis $ca -EndUtc '2026-05-15T00:00:00Z')
        $d.FreshnessByFamily['CC']['Stale'] | Should -Be 1
        $d.AsOfUtc | Should -BeExactly '2026-05-15T00:00:00Z'
    }
    It 'an explicit -AsOf overrides the period end' {
        $ca = @{ 'CC6.1' = New-ControlAnalysis -ControlId CC6.1 -LastSeenUtc '2026-05-10T00:00:00Z' }
        $d = Get-SOC2PeriodCoverageDashboard -Coverage (New-Coverage -ControlAnalysis $ca) -AsOf ([datetime]::SpecifyKind([datetime]'2026-05-12T00:00:00', [System.DateTimeKind]::Utc))
        $d.FreshnessByFamily['CC']['Fresh'] | Should -Be 1
        $d.AsOfUtc | Should -BeExactly '2026-05-12T00:00:00Z'
    }
}

Describe 'End-to-end — report renders the Period Coverage section' {
    BeforeAll {
        $script:Dir = Join-Path $env:TEMP "t2dash-e2e-$((Get-Random))"
        $null = New-Item -Path $script:Dir -ItemType Directory -Force
        $start = [DateTime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime()
        for ($i = 0; $i -lt 13; $i++) {
            $when = $start.AddDays($i * 7)
            $cc63 = if ($i -in @(4, 8)) { 'FAIL' } else { 'OK' }  # CC6.3 flaps
            $snap = @{
                SnapshotId = $when.ToString('yyyyMMdd-HHmmss'); TenantName = 'T'
                CreatedAt = $when.ToString('yyyy-MM-dd HH:mm:ss'); CreatedAtUtc = $when.ToString('yyyy-MM-ddTHH:mm:ssZ')
                Version = 't'
                Sources = @{ Findings = @{ Available = $true; Count = 2; Data = @(
                            @{ Type = 'MFA_Disabled'; Status = 'OK'; Object = 't'; Description = 'd'; Remediation = 'r'; CheckName = 'c'; Category = 'SOC2'; Severity = 'Info'; TSCReferences = @('CC6.1') }
                            @{ Type = 'GA'; Status = $cc63; Object = 't'; Description = 'd'; Remediation = 'r'; CheckName = 'c'; Category = 'SOC2'; Severity = 'High'; TSCReferences = @('CC6.3') }
                        ) } }
                Summary = @{ TotalFindings = 2 }
            }
            $snap | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $script:Dir "Snapshot-$($snap.SnapshotId).json") -Encoding UTF8
        }
        $script:Coverage = Get-SOC2PeriodCoverage -SnapshotDirectory $script:Dir -StartDate $start -EndDate $start.AddDays(90) -Categories @('CC') -MinSnapshotsRequired 12
        $script:Html = Join-Path $script:Dir 'r.html'
        $null = New-SOC2TypeTwoReport -Coverage $script:Coverage -OutputPath $script:Html
        $script:Body = Get-Content -LiteralPath $script:Html -Raw
    }
    AfterAll {
        if (Test-Path $script:Dir) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'dashboard agrees the flapping control is CC6.3' {
        $d = Get-SOC2PeriodCoverageDashboard -Coverage $script:Coverage
        ($d.FlappingControls | Where-Object ControlId -eq 'CC6.3').FlapCount | Should -BeGreaterThan 0
    }

    It 'renders <section id="period-coverage"> with tiles' {
        $script:Body | Should -Match 'id="period-coverage"'
        $section = ($script:Body -split 'id="period-coverage"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        $section | Should -Match 'class="dash-tiles"'
        $section | Should -Match 'Snapshots collected'
        $section | Should -Match 'Largest evidence gap'
    }

    It 'renders the flapping-controls and freshness-by-family tables' {
        $section = ($script:Body -split 'id="period-coverage"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        $section | Should -Match 'Controls with intermittent failures'
        $section | Should -Match 'CC6\.3'
        $section | Should -Match 'Evidence freshness by TSC family'
    }
}
