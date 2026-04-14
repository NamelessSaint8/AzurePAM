<#
.SYNOPSIS
    EntraChecks-SOC2TypeTwo.psm1 - SOC 2 Type 2 period coverage reporting.

.DESCRIPTION
    Implements the Type 2 reporting workflow on top of the existing
    EntraChecks-DeltaReporting snapshot system. Consumes a series of
    point-in-time snapshots over a coverage period and produces:

    - Per-control consistency analysis (ConsistentlyPassing, Inconsistent,
      DegradedButOperating, ConsistentlyFailing, Unobserved, ManualAttestationRequired,
      InsufficientData)
    - Gap detection (largest gap between snapshots vs cadence threshold)
    - Standalone HTML + Excel report
    - Tamper-evident evidence bundle with SHA-256 manifest including
      source-snapshot hashes (chain-of-custody for the snapshot -> report flow)

    Type 2 is strictly historical analysis; an optional fresh Type 1 ribbon
    is available via -IncludeFreshAssessment.

.NOTES
    Version: 1.0.0
    Author: EntraChecks Project
    TSC revision: AICPA TSC 2017 (revised 2022)
    Read-only: This module never modifies tenant configuration.
    Phase 3 PR 2 deliverable (locked decisions in plans/SOC2-Phase3-Implementation-Plan.md).

.LINK
    SOC 2 Phase 3 plan: plans/SOC2-Phase3-Implementation-Plan.md
    SOC 2 Guide: docs/SOC2-Guide.md
#>

#Requires -Version 5.1

$script:ModuleName = 'EntraChecks-SOC2TypeTwo'
$script:ModuleVersion = '1.0.0'
$script:TSCRevision = 'AICPA TSC 2017 (revised 2022)'

#region ==================== STATE MACHINE ====================

<#
.SYNOPSIS
    Maps a per-snapshot status sequence for one control to a Type 2 consistency state.

.DESCRIPTION
    Implements the consistency state machine from the Phase 3 plan SS2.6:

    | Snapshot statuses observed                              | State                    |
    | All PASS / OK                                           | ConsistentlyPassing      |
    | All FAIL                                                | ConsistentlyFailing      |
    | Mix of PASS/OK + WARNING (no FAIL)                      | DegradedButOperating     |
    | Any single FAIL anywhere in period                      | Inconsistent             |
    | No findings reference this control in any snapshot      | Unobserved               |

    The 'Inconsistent' threshold is configurable via -ExceptionsAllowed:
    if FailOccurrences <= ExceptionsAllowed, the control demotes from
    Inconsistent to DegradedButOperating.

    ConsistentlyFailing is reported only when EVERY observed snapshot's
    worst-status for the control is FAIL — a single PASS/WARN/OK among
    fails moves it to Inconsistent.

.PARAMETER WorstStatusPerSnapshot
    Array of strings, one per observed snapshot, each containing the worst
    status of any finding mapped to the control in that snapshot.
    Empty/absent snapshots should be omitted (use 'Unobserved' state instead
    when the array is empty across all snapshots).

.PARAMETER Automation
    'Automated', 'Supporting', or 'Manual' — from the TSC catalog. When
    'Manual', returns 'ManualAttestationRequired' regardless of observations.

.PARAMETER ExceptionsAllowed
    Number of FAIL occurrences tolerated before classifying as Inconsistent.
    Default 0 (strict).

.OUTPUTS
    Hashtable with State (string), FailOccurrences (int), WarningOccurrences (int),
    PassOccurrences (int), InfoOccurrences (int).
#>
function Get-SOC2ControlConsistencyState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$WorstStatusPerSnapshot,

        [string]$Automation = 'Automated',

        [int]$ExceptionsAllowed = 0
    )

    if ($Automation -eq 'Manual') {
        return @{
            State = 'ManualAttestationRequired'
            FailOccurrences = 0
            WarningOccurrences = 0
            PassOccurrences = 0
            InfoOccurrences = 0
        }
    }

    if ($null -eq $WorstStatusPerSnapshot -or $WorstStatusPerSnapshot.Count -eq 0) {
        return @{
            State = 'Unobserved'
            FailOccurrences = 0
            WarningOccurrences = 0
            PassOccurrences = 0
            InfoOccurrences = 0
        }
    }

    $fail = 0
    $warn = 0
    $pass = 0
    $info = 0
    foreach ($s in $WorstStatusPerSnapshot) {
        switch ($s) {
            'FAIL' { $fail++ }
            'WARNING' { $warn++ }
            'OK' { $pass++ }
            'PASS' { $pass++ }
            'INFO' { $info++ }
            default { $info++ }
        }
    }

    $effectiveFail = $fail
    if ($fail -le $ExceptionsAllowed) {
        $effectiveFail = 0
    }

    $state = 'Unobserved'
    if ($pass -eq $WorstStatusPerSnapshot.Count) {
        $state = 'ConsistentlyPassing'
    } elseif ($fail -eq $WorstStatusPerSnapshot.Count) {
        $state = 'ConsistentlyFailing'
    } elseif ($effectiveFail -gt 0) {
        $state = 'Inconsistent'
    } elseif ($warn -gt 0) {
        $state = 'DegradedButOperating'
    } elseif ($pass -gt 0) {
        $state = 'ConsistentlyPassing'
    } else {
        # All info / unknown — treat as observed but unassessed
        $state = 'Unobserved'
    }

    return @{
        State = $state
        FailOccurrences = $fail
        WarningOccurrences = $warn
        PassOccurrences = $pass
        InfoOccurrences = $info
    }
}

#endregion

#region ==================== SNAPSHOT PARSING ====================

<#
.SYNOPSIS
    Parses a snapshot's UTC timestamp, falling back to local CreatedAt when
    CreatedAtUtc is missing (older snapshots from before that field was added).

.OUTPUTS
    DateTime in UTC, or $null on parse failure.
#>
function Get-SOC2SnapshotUtcTimestamp {
    [CmdletBinding()]
    [OutputType([Nullable[DateTime]])]
    param(
        [Parameter(Mandatory)]
        [object]$Snapshot
    )

    try {
        if ($Snapshot.PSObject.Properties['CreatedAtUtc'] -and $Snapshot.CreatedAtUtc) {
            return [DateTime]::Parse($Snapshot.CreatedAtUtc).ToUniversalTime()
        }
    } catch {
        # Fall through to local-time fallback below.
        Write-Debug "CreatedAtUtc parse failed: $($_.Exception.Message)"
    }

    try {
        if ($Snapshot.PSObject.Properties['CreatedAt'] -and $Snapshot.CreatedAt) {
            # Local-time fallback. Convert local to UTC.
            return [DateTime]::Parse($Snapshot.CreatedAt).ToUniversalTime()
        }
    } catch {
        # Both timestamp formats failed; caller treats $null as "skip snapshot".
        Write-Debug "CreatedAt parse failed: $($_.Exception.Message)"
    }

    return $null
}

<#
.SYNOPSIS
    Extracts TSC references for one finding inside a snapshot, with fallback
    to compliance mapping when the new-format snapshot fields are absent.

.DESCRIPTION
    New-format snapshots (Phase 3 PR 2+) include TSCReferences and Type per
    finding. Older snapshots only include CheckName / Category / Status /
    Description.

    For new-format findings: read TSCReferences directly. If only Type is
    present, look up via Get-ComplianceMapping.

    For legacy findings: derive Type from CheckName via the mapping module's
    fallback logic, then look up TSC criteria.

.PARAMETER Finding
    The finding object as captured in Sources.Findings.Data.

.OUTPUTS
    String[] of TSC control IDs (may be empty).
#>
function Get-SOC2FindingTSCFromSnapshot {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [object]$Finding
    )

    # New-format: explicit TSCReferences on the finding entry
    if ($Finding.PSObject.Properties['TSCReferences'] -and $Finding.TSCReferences) {
        return @($Finding.TSCReferences)
    }

    # Look up via Type if present
    $findingType = $null
    if ($Finding.PSObject.Properties['Type'] -and $Finding.Type) {
        $findingType = $Finding.Type
    } elseif ($Finding.PSObject.Properties['CheckName'] -and $Finding.CheckName) {
        # Legacy fallback: derive from CheckName via the mapping module's auto-capture pattern
        # (the Add-ComplianceMapping function uses Type | CheckType | Category as its lookup chain;
        # CheckName isn't in that chain, so we use the Category)
        if ($Finding.PSObject.Properties['Category'] -and $Finding.Category) {
            $findingType = $Finding.Category
        }
    }

    if (-not $findingType) { return @() }

    if (-not (Get-Command Get-ComplianceMapping -ErrorAction SilentlyContinue)) {
        return @()
    }

    $mapping = Get-ComplianceMapping -FindingType $findingType -Framework 'SOC2'
    if ($mapping -and $mapping.SOC2 -and $mapping.SOC2.Criteria) {
        return @($mapping.SOC2.Criteria)
    }
    return @()
}

#endregion

#region ==================== PERIOD COVERAGE ANALYSIS ====================

<#
.SYNOPSIS
    Computes Type 2 period coverage from a series of EntraChecks snapshots.

.DESCRIPTION
    The core analysis engine. Reads snapshots from $SnapshotDirectory whose
    CreatedAtUtc falls within [$StartDate, $EndDate], maps each snapshot's
    findings to TSC controls, computes per-control consistency state, and
    detects coverage gaps.

    Returns a structured object suitable for both report rendering
    (New-SOC2TypeTwoReport) and evidence-bundle generation.

.PARAMETER SnapshotDirectory
    Directory containing Snapshot-*.json files (typically .\Snapshots).

.PARAMETER StartDate
    UTC start of the coverage period (inclusive).

.PARAMETER EndDate
    UTC end of the coverage period (inclusive).

.PARAMETER MinSnapshotsRequired
    Minimum snapshot count for Type 2 threshold. Default 12.

.PARAMETER MaxGapDays
    Maximum allowed gap between consecutive snapshots (and at period edges).
    Default 10 (Weekly cadence with 3-day grace).

.PARAMETER ExceptionsAllowed
    Per-control FAIL tolerance before classifying as Inconsistent. Default 0.

.PARAMETER Categories
    TSC categories in scope. Default all five (CC, A, C, PI, P).

.OUTPUTS
    Hashtable with:
    - Period (StartUtc, EndUtc, Days)
    - Snapshots (array of snapshot metadata)
    - SkippedSnapshots (array of file paths skipped due to parse errors)
    - LargestGapDays (decimal)
    - LeadingGapDays (decimal — start of period to first snapshot)
    - TrailingGapDays (decimal — last snapshot to end of period)
    - MeetsTypeTwoThreshold (bool)
    - ThresholdDetail (string explaining why if false)
    - ControlAnalysis (hashtable: TSC ID -> consistency state + occurrences + per-snapshot trace)
    - Catalog (the TSC catalog used)
#>
function Get-SOC2PeriodCoverage {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$SnapshotDirectory,

        [Parameter(Mandatory)]
        [DateTime]$StartDate,

        [Parameter(Mandatory)]
        [DateTime]$EndDate,

        [int]$MinSnapshotsRequired = 12,

        [int]$MaxGapDays = 10,

        [int]$ExceptionsAllowed = 0,

        [ValidateSet('CC', 'A', 'C', 'PI', 'P')]
        [string[]]$Categories = @('CC', 'A', 'C', 'PI', 'P')
    )

    if (-not (Test-Path -LiteralPath $SnapshotDirectory)) {
        throw "Snapshot directory not found: $SnapshotDirectory"
    }
    if ($EndDate -lt $StartDate) {
        throw "EndDate ($EndDate) must be on or after StartDate ($StartDate)"
    }

    $startUtc = $StartDate.ToUniversalTime()
    $endUtc = $EndDate.ToUniversalTime()
    $periodDays = ($endUtc - $startUtc).TotalDays

    # Step 1: Enumerate + parse snapshot files in directory directly (avoid
    # cross-module dependency on Get-ComplianceSnapshots metadata, which
    # doesn't surface CreatedAtUtc).
    $snapshotFiles = Get-ChildItem -LiteralPath $SnapshotDirectory -Filter 'Snapshot-*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object Name

    $inPeriod = [System.Collections.Generic.List[hashtable]]::new()
    $skipped = [System.Collections.Generic.List[string]]::new()

    foreach ($file in $snapshotFiles) {
        try {
            $raw = Get-Content -LiteralPath $file.FullName -Raw
            $snap = $raw | ConvertFrom-Json
            $utc = Get-SOC2SnapshotUtcTimestamp -Snapshot $snap
            if ($null -eq $utc) {
                $skipped.Add("$($file.Name) (could not parse timestamp)") | Out-Null
                continue
            }
            if ($utc -lt $startUtc -or $utc -gt $endUtc) { continue }

            $entry = @{}
            $entry['SnapshotId'] = $snap.SnapshotId
            $entry['TenantName'] = $snap.TenantName
            $entry['CreatedAtUtc'] = $utc
            $entry['FilePath'] = $file.FullName
            $entry['SourceSHA256'] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLower()
            $entry['Snapshot'] = $snap

            $findingCount = 0
            if ($snap.Sources -and $snap.Sources.Findings -and $snap.Sources.Findings.Data) {
                $findingCount = @($snap.Sources.Findings.Data).Count
            }
            $entry['FindingCount'] = $findingCount

            $inPeriod.Add($entry) | Out-Null
        } catch {
            $skipped.Add("$($file.Name) ($($_.Exception.Message))") | Out-Null
        }
    }

    # Sort by timestamp ascending for gap analysis
    $sorted = @($inPeriod | Sort-Object { $_.CreatedAtUtc })

    # Step 2: Gap detection
    $largestGap = 0.0
    $leadingGap = 0.0
    $trailingGap = 0.0

    if ($sorted.Count -gt 0) {
        $leadingGap = ($sorted[0].CreatedAtUtc - $startUtc).TotalDays
        $trailingGap = ($endUtc - $sorted[-1].CreatedAtUtc).TotalDays

        for ($i = 1; $i -lt $sorted.Count; $i++) {
            $gap = ($sorted[$i].CreatedAtUtc - $sorted[$i - 1].CreatedAtUtc).TotalDays
            if ($gap -gt $largestGap) { $largestGap = $gap }
        }
    } else {
        # Zero snapshots in period: leading + trailing both equal full period
        $leadingGap = $periodDays
        $trailingGap = $periodDays
        $largestGap = $periodDays
    }

    # Step 3: Threshold check
    $thresholdMet = $true
    $thresholdReasons = [System.Collections.Generic.List[string]]::new()
    if ($sorted.Count -lt $MinSnapshotsRequired) {
        $thresholdMet = $false
        $thresholdReasons.Add("Snapshot count $($sorted.Count) below minimum $MinSnapshotsRequired") | Out-Null
    }
    if ($largestGap -gt $MaxGapDays) {
        $thresholdMet = $false
        $thresholdReasons.Add("Largest snapshot gap $([math]::Round($largestGap, 1)) days exceeds MaxGapDays $MaxGapDays") | Out-Null
    }
    if ($leadingGap -gt $MaxGapDays) {
        $thresholdMet = $false
        $thresholdReasons.Add("Leading gap $([math]::Round($leadingGap, 1)) days (start of period to first snapshot) exceeds MaxGapDays $MaxGapDays") | Out-Null
    }
    if ($trailingGap -gt $MaxGapDays) {
        $thresholdMet = $false
        $thresholdReasons.Add("Trailing gap $([math]::Round($trailingGap, 1)) days (last snapshot to end of period) exceeds MaxGapDays $MaxGapDays") | Out-Null
    }

    # Step 4: Per-control analysis
    $catalog = @()
    if (Get-Command Get-SOC2TSCCatalog -ErrorAction SilentlyContinue) {
        $catalog = @(Get-SOC2TSCCatalog -Categories $Categories)
    }

    $controlAnalysis = @{}

    foreach ($control in $catalog) {
        # For each snapshot, determine the worst status of any finding mapped to this control
        $perSnapshotStatus = [System.Collections.Generic.List[string]]::new()
        $perSnapshotTrace = [System.Collections.Generic.List[hashtable]]::new()
        $missingFromSnapshots = [System.Collections.Generic.List[string]]::new()

        foreach ($snapEntry in $sorted) {
            $worstStatus = $null
            $matchingFindings = [System.Collections.Generic.List[object]]::new()

            $data = @()
            if ($snapEntry.Snapshot.Sources -and $snapEntry.Snapshot.Sources.Findings -and $snapEntry.Snapshot.Sources.Findings.Data) {
                $data = @($snapEntry.Snapshot.Sources.Findings.Data)
            }

            foreach ($finding in $data) {
                $tsc = Get-SOC2FindingTSCFromSnapshot -Finding $finding
                if ($tsc -contains $control.Id) {
                    $matchingFindings.Add($finding) | Out-Null
                    $status = if ($finding.PSObject.Properties['Status']) { [string]$finding.Status } else { 'INFO' }
                    if ($null -eq $worstStatus -or (Get-SOC2StatusPriority $status) -gt (Get-SOC2StatusPriority $worstStatus)) {
                        $worstStatus = $status
                    }
                }
            }

            if ($null -eq $worstStatus) {
                $missingFromSnapshots.Add($snapEntry.SnapshotId) | Out-Null
            } else {
                $perSnapshotStatus.Add($worstStatus) | Out-Null
                $traceEntry = @{}
                $traceEntry['SnapshotId'] = $snapEntry.SnapshotId
                $traceEntry['CreatedAtUtc'] = $snapEntry.CreatedAtUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
                $traceEntry['WorstStatus'] = $worstStatus
                $traceEntry['MatchCount'] = $matchingFindings.Count
                $perSnapshotTrace.Add($traceEntry) | Out-Null
            }
        }

        $consistency = Get-SOC2ControlConsistencyState `
            -WorstStatusPerSnapshot $perSnapshotStatus.ToArray() `
            -Automation $control.Automation `
            -ExceptionsAllowed $ExceptionsAllowed

        $analysis = @{}
        $analysis['ControlId'] = $control.Id
        $analysis['Family'] = $control.Family
        $analysis['FamilyName'] = $control.FamilyName
        $analysis['Automation'] = $control.Automation
        $analysis['Description'] = $control.Description
        $analysis['ControlOwnerHint'] = $control.ControlOwnerHint
        $analysis['State'] = $consistency.State
        $analysis['FailOccurrences'] = $consistency.FailOccurrences
        $analysis['WarningOccurrences'] = $consistency.WarningOccurrences
        $analysis['PassOccurrences'] = $consistency.PassOccurrences
        $analysis['InfoOccurrences'] = $consistency.InfoOccurrences
        $analysis['ObservedSnapshotCount'] = $perSnapshotStatus.Count
        $analysis['MissingFromSnapshots'] = $missingFromSnapshots.ToArray()
        $analysis['Trace'] = $perSnapshotTrace.ToArray()

        if ($perSnapshotTrace.Count -gt 0) {
            $analysis['FirstSeenUtc'] = $perSnapshotTrace[0].CreatedAtUtc
            $analysis['LastSeenUtc'] = $perSnapshotTrace[-1].CreatedAtUtc
        } else {
            $analysis['FirstSeenUtc'] = ''
            $analysis['LastSeenUtc'] = ''
        }

        $controlAnalysis[$control.Id] = $analysis
    }

    return @{
        Period = @{
            StartUtc = $startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
            EndUtc = $endUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
            Days = [math]::Round($periodDays, 2)
        }
        Snapshots = $sorted
        SkippedSnapshots = $skipped.ToArray()
        SnapshotCount = $sorted.Count
        LargestGapDays = [math]::Round($largestGap, 2)
        LeadingGapDays = [math]::Round($leadingGap, 2)
        TrailingGapDays = [math]::Round($trailingGap, 2)
        MaxGapDays = $MaxGapDays
        MinSnapshotsRequired = $MinSnapshotsRequired
        ExceptionsAllowed = $ExceptionsAllowed
        MeetsTypeTwoThreshold = $thresholdMet
        ThresholdDetail = $thresholdReasons.ToArray()
        ControlAnalysis = $controlAnalysis
        Catalog = $catalog
        Categories = $Categories
    }
}

<#
.SYNOPSIS
    Internal helper: assigns a numeric priority to a finding status so we
    can compute "worst status" via comparison.
#>
function Get-SOC2StatusPriority {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Status
    )

    switch ($Status) {
        'FAIL' { return 4 }
        'WARNING' { return 3 }
        'INFO' { return 2 }
        'OK' { return 1 }
        'PASS' { return 1 }
        default { return 0 }
    }
}

#endregion

#region ==================== EVIDENCE BUNDLE ====================

<#
.SYNOPSIS
    Writes the Type 2 evidence bundle (manifest, per-control period coverage
    JSON, snapshots manifest) with a SHA-256 hash chain.

.DESCRIPTION
    Mirrors New-SOC2EvidenceBundle from Phase 1 but for period-coverage
    output. Differences:
    - manifest.json carries Type='Type2', Period.{StartUtc,EndUtc,Days},
      SourceSnapshots (with SHA256 of each), TypeTwoThresholdMet, LargestGapDays.
    - Per-control files live in period-coverage/<TSC-Id>.json (not controls/)
      so Type 1 and Type 2 bundles can coexist without collision.

.PARAMETER Coverage
    Output of Get-SOC2PeriodCoverage.

.PARAMETER OutputDirectory
    Where to write the evidence-bundle/ subtree.

.PARAMETER TenantId
    Tenant ID for the manifest.

.PARAMETER TenantName
    Tenant display name for the manifest.

.PARAMETER Assessor
    Assessor identity for the manifest.

.PARAMETER ServiceOrganization
    Org name for the manifest.

.OUTPUTS
    Hashtable with ManifestPath, BundleHash, Directory, FileCount, GeneratedAt.
#>
function New-SOC2TypeTwoEvidenceBundle {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][hashtable]$Coverage,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$TenantName = '',
        [string]$Assessor = '',
        [string]$ServiceOrganization = ''
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
    }

    $coverageDir = Join-Path $OutputDirectory 'period-coverage'
    $manualDir = Join-Path $OutputDirectory 'manual-attestation'
    $null = New-Item -Path $coverageDir -ItemType Directory -Force -ErrorAction SilentlyContinue
    $null = New-Item -Path $manualDir -ItemType Directory -Force -ErrorAction SilentlyContinue

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $writtenFiles = [System.Collections.Generic.List[string]]::new()

    # Per-control period coverage files
    foreach ($controlId in $Coverage.ControlAnalysis.Keys) {
        $analysis = $Coverage.ControlAnalysis[$controlId]
        $payload = [ordered]@{
            SchemaVersion = '1.0'
            TSCRevision = $script:TSCRevision
            ControlId = $analysis.ControlId
            ControlFamily = $analysis.Family
            ControlFamilyName = $analysis.FamilyName
            Automation = $analysis.Automation
            Description = $analysis.Description
            ControlOwnerHint = $analysis.ControlOwnerHint
            State = $analysis.State
            FirstSeenUtc = $analysis.FirstSeenUtc
            LastSeenUtc = $analysis.LastSeenUtc
            ObservedSnapshotCount = $analysis.ObservedSnapshotCount
            FailOccurrences = $analysis.FailOccurrences
            WarningOccurrences = $analysis.WarningOccurrences
            PassOccurrences = $analysis.PassOccurrences
            InfoOccurrences = $analysis.InfoOccurrences
            MissingFromSnapshots = $analysis.MissingFromSnapshots
            Trace = $analysis.Trace
            CapturedAt = $timestamp
            TenantId = $TenantId
        }
        $filePath = Join-Path $coverageDir "$($analysis.ControlId).json"
        $json = $payload | ConvertTo-Json -Depth 12
        Set-Content -LiteralPath $filePath -Value $json -Encoding UTF8
        $writtenFiles.Add($filePath) | Out-Null

        # Manual attestation template for Manual controls — pre-populated period
        if ($analysis.Automation -eq 'Manual') {
            $template = @"
# Manual Attestation - $($analysis.ControlId) (Period of Coverage)

**Control family:** $($analysis.FamilyName) ($($analysis.Family))
**Control owner hint:** $($analysis.ControlOwnerHint)
**TSC revision:** $($script:TSCRevision)
**Period of coverage:** $($Coverage.Period.StartUtc) through $($Coverage.Period.EndUtc) ($($Coverage.Period.Days) days)

## Description

$($analysis.Description)

## Attestation

| Field | Value |
|---|---|
| Control owner (name + title) |  |
| Description of how the control operated during the period |  |
| Frequency of operation |  |
| Evidence location |  |
| Period of coverage | $($Coverage.Period.StartUtc) -> $($Coverage.Period.EndUtc) |
| Attested by |  |
| Attested on (UTC) |  |

## Notes

"@
            $mdPath = Join-Path $manualDir "$($analysis.ControlId).md"
            Set-Content -LiteralPath $mdPath -Value $template -Encoding UTF8
            $writtenFiles.Add($mdPath) | Out-Null
        }
    }

    # Snapshots manifest (separate file so the main manifest stays compact)
    $snapRows = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $Coverage.Snapshots) {
        $row = [ordered]@{
            SnapshotId = $s.SnapshotId
            TenantName = $s.TenantName
            CreatedAtUtc = $s.CreatedAtUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
            Path = $s.FilePath
            SourceSHA256 = $s.SourceSHA256
            FindingCount = $s.FindingCount
        }
        $snapRows.Add($row) | Out-Null
    }
    $snapshotsManifestPayload = [ordered]@{
        SchemaVersion = '1.0'
        SourceCount = $Coverage.Snapshots.Count
        Snapshots = @($snapRows.ToArray())
    }
    $snapshotsManifestPath = Join-Path $OutputDirectory 'snapshots-manifest.json'
    Set-Content -LiteralPath $snapshotsManifestPath -Value ($snapshotsManifestPayload | ConvertTo-Json -Depth 8) -Encoding UTF8
    $writtenFiles.Add($snapshotsManifestPath) | Out-Null

    # Hash every written file, deterministically sorted
    $hashEntries = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($f in ($writtenFiles | Sort-Object)) {
        $hash = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower()
        $relative = $f.Substring($OutputDirectory.Length).TrimStart('\', '/')
        $entry = @{}
        $entry['RelativePath'] = $relative
        $entry['SHA256'] = $hash
        $hashEntries.Add($entry) | Out-Null
    }

    # Rolling bundle hash
    $concatSource = ($hashEntries | ForEach-Object { "$($_.RelativePath)|$($_.SHA256)" }) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bundleHashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concatSource))
    } finally {
        $sha.Dispose()
    }
    $bundleHash = -join ($bundleHashBytes | ForEach-Object { $_.ToString('x2') })

    $manifest = [ordered]@{
        SchemaVersion = '1.0'
        TSCRevision = $script:TSCRevision
        Type = 'Type2'
        GeneratedAt = $timestamp
        EntraChecksVersion = $script:ModuleVersion
        TenantId = $TenantId
        TenantName = $TenantName
        Assessor = $Assessor
        ServiceOrganization = $ServiceOrganization
        Categories = $Coverage.Categories
        Period = $Coverage.Period
        SnapshotCount = $Coverage.SnapshotCount
        MinSnapshotsRequired = $Coverage.MinSnapshotsRequired
        MaxGapDays = $Coverage.MaxGapDays
        ExceptionsAllowed = $Coverage.ExceptionsAllowed
        LargestGapDays = $Coverage.LargestGapDays
        LeadingGapDays = $Coverage.LeadingGapDays
        TrailingGapDays = $Coverage.TrailingGapDays
        TypeTwoThresholdMet = $Coverage.MeetsTypeTwoThreshold
        ThresholdDetail = $Coverage.ThresholdDetail
        DegradedTo = if ($Coverage.MeetsTypeTwoThreshold) { '' } else { 'Type1-Equivalent' }
        SkippedSnapshots = $Coverage.SkippedSnapshots
        HashAlgorithm = 'SHA256'
        BundleHash = $bundleHash
        Files = $hashEntries
    }

    $manifestPath = Join-Path $OutputDirectory 'manifest.json'
    Set-Content -LiteralPath $manifestPath -Value ($manifest | ConvertTo-Json -Depth 14) -Encoding UTF8

    return @{
        ManifestPath = $manifestPath
        BundleHash = $bundleHash
        Directory = $OutputDirectory
        FileCount = $writtenFiles.Count
        GeneratedAt = $timestamp
    }
}

<#
.SYNOPSIS
    Verifies the integrity of a Type 2 evidence bundle by recomputing every
    file hash and the rolling bundle hash, and additionally validates that
    every referenced source snapshot still hashes to its recorded SHA-256.

.OUTPUTS
    PSCustomObject with Valid (bool), Mismatches (string[]), TamperedSnapshots (string[]),
    ExpectedBundleHash, ComputedBundleHash, FileCount.
#>
function Test-SOC2TypeTwoBundle {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "Manifest not found: $ManifestPath"
    }

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $bundleDir = Split-Path -Parent $ManifestPath

    $mismatches = [System.Collections.Generic.List[string]]::new()
    $tamperedSnapshots = [System.Collections.Generic.List[string]]::new()
    $hashLines = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in $manifest.Files) {
        $fullPath = Join-Path $bundleDir $entry.RelativePath
        if (-not (Test-Path -LiteralPath $fullPath)) {
            $mismatches.Add("MISSING: $($entry.RelativePath)") | Out-Null
            continue
        }
        $actual = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $entry.SHA256) {
            $mismatches.Add("TAMPERED: $($entry.RelativePath) (expected $($entry.SHA256), got $actual)") | Out-Null
        }
        $hashLines.Add("$($entry.RelativePath)|$($entry.SHA256)") | Out-Null
    }

    # Recompute rolling bundle hash
    $concatSource = ($hashLines | Sort-Object) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $computed = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concatSource))
    } finally {
        $sha.Dispose()
    }
    $computedBundleHash = -join ($computed | ForEach-Object { $_.ToString('x2') })

    if ($computedBundleHash -ne $manifest.BundleHash) {
        $mismatches.Add("BUNDLE HASH MISMATCH: expected $($manifest.BundleHash), got $computedBundleHash") | Out-Null
    }

    # Source-snapshot tamper check (chain-of-custody)
    $snapshotsManifestPath = Join-Path $bundleDir 'snapshots-manifest.json'
    if (Test-Path -LiteralPath $snapshotsManifestPath) {
        $snapManifest = Get-Content -LiteralPath $snapshotsManifestPath -Raw | ConvertFrom-Json
        foreach ($snapEntry in $snapManifest.Snapshots) {
            if (-not (Test-Path -LiteralPath $snapEntry.Path)) {
                $tamperedSnapshots.Add("MISSING SOURCE: $($snapEntry.SnapshotId) at $($snapEntry.Path)") | Out-Null
                continue
            }
            $actualHash = (Get-FileHash -LiteralPath $snapEntry.Path -Algorithm SHA256).Hash.ToLower()
            if ($actualHash -ne $snapEntry.SourceSHA256) {
                $tamperedSnapshots.Add("SOURCE TAMPERED: $($snapEntry.SnapshotId) (expected $($snapEntry.SourceSHA256), got $actualHash)") | Out-Null
            }
        }
    }

    return [pscustomobject]@{
        Valid = ($mismatches.Count -eq 0 -and $tamperedSnapshots.Count -eq 0)
        Mismatches = $mismatches.ToArray()
        TamperedSnapshots = $tamperedSnapshots.ToArray()
        ExpectedBundleHash = $manifest.BundleHash
        ComputedBundleHash = $computedBundleHash
        FileCount = @($manifest.Files).Count
    }
}

#endregion

#region ==================== HTML REPORT ====================

<#
.SYNOPSIS
    Renders the SOC 2 Type 2 standalone HTML report.

.DESCRIPTION
    Produces a TSC-structured period-coverage report distinct from Phase 1's
    Type 1 standalone report. Sections: Cover, Period banner (when threshold
    not met), Summary by Category, Snapshot Timeline, Control Register with
    Period Consistency, Exceptions Detail, Manual Attestation, Evidence Register.

.PARAMETER Coverage
    Output of Get-SOC2PeriodCoverage.

.PARAMETER Evidence
    Output of New-SOC2TypeTwoEvidenceBundle (optional — when provided, bundle hash is rendered).

.PARAMETER OutputPath
    Path to write the .html file.

.PARAMETER Branding
    Optional branding context from Get-ReportBrandingContext.

.OUTPUTS
    Path to the rendered HTML.
#>
function New-SOC2TypeTwoReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][hashtable]$Coverage,
        [hashtable]$Evidence,
        [Parameter(Mandatory)][string]$OutputPath,
        [pscustomobject]$Branding
    )

    if (-not $Branding) {
        if (Get-Command Get-ReportBrandingContext -ErrorAction SilentlyContinue) {
            $Branding = Get-ReportBrandingContext -Config $null -ReportTitle 'SOC 2 Type 2 Period Coverage'
        } else {
            $Branding = [pscustomobject]@{
                WhiteLabel = $false
                ReportTitle = 'SOC 2 Type 2 Period Coverage'
                OrganizationName = 'EntraChecks'
                LogoDataUri = ''
                PrimaryColor = '#005A9E'
                Footer = ''
                Attribution = "Generated by EntraChecks-SOC2TypeTwo v$($script:ModuleVersion)"
                SuppressEntraChecksBranding = $false
            }
        }
    }

    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $primaryColor = $Branding.PrimaryColor
    $orgName = $Branding.OrganizationName
    $title = $Branding.ReportTitle

    $logoHtml = if ($Branding.LogoDataUri) {
        "<img src='$($Branding.LogoDataUri)' alt='Logo' class='org-logo' />"
    } else { '' }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="UTF-8">')
    [void]$sb.AppendLine("<title>$([System.Web.HttpUtility]::HtmlEncode($title))</title>")
    [void]$sb.AppendLine(@"
<style>
* { box-sizing: border-box; }
body { font-family: Segoe UI, Roboto, system-ui, sans-serif; margin: 0; color: #1a1a1a; background: #f4f6f8; }
header { background: $primaryColor; color: white; padding: 24px 32px; display: flex; align-items: center; gap: 16px; }
header .org-logo { max-height: 48px; max-width: 200px; background: white; padding: 4px; border-radius: 4px; }
header h1 { margin: 0; font-size: 1.6em; font-weight: 600; }
header .meta { margin-left: auto; text-align: right; font-size: 0.85em; opacity: 0.9; }
main { max-width: 1600px; margin: 0 auto; padding: 24px; }
section.report { background: white; border-radius: 6px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 24px; }
h2 { color: $primaryColor; border-bottom: 2px solid $primaryColor; padding-bottom: 8px; margin-top: 0; }
table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.9em; }
th { background: #f0f3f6; text-align: left; padding: 8px 12px; border-bottom: 2px solid #d0d5dc; }
td { padding: 8px 12px; border-bottom: 1px solid #e5e8ec; vertical-align: top; }
.banner-warning { background: #fff8e1; border-left: 6px solid #d89b00; padding: 16px; border-radius: 4px; margin-bottom: 16px; }
.badge { padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 0.85em; }
.badge-met { background: #2a8c3c; color: white; }
.badge-unmet { background: #c8102e; color: white; }
.state-ConsistentlyPassing { color: #2a8c3c; font-weight: 600; }
.state-ConsistentlyFailing { color: #c8102e; font-weight: 600; }
.state-DegradedButOperating { color: #d89b00; font-weight: 600; }
.state-Inconsistent { color: #c8102e; font-weight: 600; }
.state-Unobserved { color: #6c757d; }
.state-ManualAttestationRequired { color: #5b3fa9; font-weight: 600; }
.state-InsufficientData { color: #5a6c7d; }
.summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 16px 0; }
.summary-card { background: #f8f9fb; padding: 16px; border-left: 4px solid $primaryColor; border-radius: 4px; }
.summary-card .family { font-weight: 600; font-size: 1.1em; margin-bottom: 8px; }
.summary-card .row { font-size: 0.85em; color: #555; }
.evidence-hash { font-family: monospace; font-size: 0.85em; word-break: break-all; }
footer { background: #2a3441; color: #d0d5dc; text-align: center; padding: 16px; font-size: 0.85em; }
</style>
"@)
    [void]$sb.AppendLine('</head><body>')

    # Header
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine($logoHtml)
    [void]$sb.AppendLine("<h1>$([System.Web.HttpUtility]::HtmlEncode($title))</h1>")
    [void]$sb.AppendLine("<div class='meta'>")
    [void]$sb.AppendLine("<div>$([System.Web.HttpUtility]::HtmlEncode($orgName))</div>")
    [void]$sb.AppendLine("<div>Generated $((Get-Date).ToString('u'))</div>")
    [void]$sb.AppendLine('</div></header>')

    [void]$sb.AppendLine('<main>')

    # Cover
    $thresholdBadge = if ($Coverage.MeetsTypeTwoThreshold) {
        "<span class='badge badge-met'>Type 2 coverage MET</span>"
    } else {
        "<span class='badge badge-unmet'>Type 2 coverage NOT MET</span>"
    }

    [void]$sb.AppendLine('<section class="report"><h2>Period Cover</h2>')
    [void]$sb.AppendLine('<table>')
    [void]$sb.AppendLine("<tr><th>TSC Revision</th><td>$script:TSCRevision</td></tr>")
    [void]$sb.AppendLine("<tr><th>Type</th><td>Type 2 (period coverage)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Period (UTC)</th><td>$($Coverage.Period.StartUtc) - $($Coverage.Period.EndUtc) ($($Coverage.Period.Days) days)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Snapshots in period</th><td>$($Coverage.SnapshotCount) (minimum: $($Coverage.MinSnapshotsRequired))</td></tr>")
    [void]$sb.AppendLine("<tr><th>Largest gap</th><td>$($Coverage.LargestGapDays) days (max allowed: $($Coverage.MaxGapDays))</td></tr>")
    [void]$sb.AppendLine("<tr><th>Leading gap</th><td>$($Coverage.LeadingGapDays) days</td></tr>")
    [void]$sb.AppendLine("<tr><th>Trailing gap</th><td>$($Coverage.TrailingGapDays) days</td></tr>")
    [void]$sb.AppendLine("<tr><th>Threshold</th><td>$thresholdBadge</td></tr>")
    if ($Evidence) {
        [void]$sb.AppendLine("<tr><th>Bundle hash (SHA-256)</th><td class='evidence-hash'>$($Evidence.BundleHash)</td></tr>")
    }
    [void]$sb.AppendLine('</table></section>')

    # Threshold-not-met banner
    if (-not $Coverage.MeetsTypeTwoThreshold) {
        [void]$sb.AppendLine('<div class="banner-warning">')
        [void]$sb.AppendLine('<strong>Coverage insufficient for Type 2 claim:</strong><ul>')
        foreach ($reason in $Coverage.ThresholdDetail) {
            [void]$sb.AppendLine("<li>$([System.Web.HttpUtility]::HtmlEncode($reason))</li>")
        }
        [void]$sb.AppendLine('</ul>Per-control analysis still rendered below; treat as Type 1-equivalent evidence over the available snapshots.</div>')
    }

    # Summary by category
    [void]$sb.AppendLine('<section class="report"><h2>Summary by Trust Services Category</h2>')
    [void]$sb.AppendLine('<div class="summary-grid">')
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $controlsInFamily = @($Coverage.Catalog | Where-Object { $_.Family -eq $family })
        if ($controlsInFamily.Count -eq 0) { continue }

        $passing = 0; $failing = 0; $degraded = 0; $inconsistent = 0; $unobserved = 0; $manual = 0
        foreach ($c in $controlsInFamily) {
            $analysis = $Coverage.ControlAnalysis[$c.Id]
            if (-not $analysis) { continue }
            switch ($analysis.State) {
                'ConsistentlyPassing' { $passing++ }
                'ConsistentlyFailing' { $failing++ }
                'DegradedButOperating' { $degraded++ }
                'Inconsistent' { $inconsistent++ }
                'Unobserved' { $unobserved++ }
                'ManualAttestationRequired' { $manual++ }
            }
        }
        [void]$sb.AppendLine('<div class="summary-card">')
        [void]$sb.AppendLine("<div class='family'>$family</div>")
        [void]$sb.AppendLine("<div class='row'>Controls: $($controlsInFamily.Count)</div>")
        [void]$sb.AppendLine("<div class='row'><span class='state-ConsistentlyPassing'>Passing: $passing</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='state-Inconsistent'>Inconsistent: $inconsistent</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='state-DegradedButOperating'>Degraded: $degraded</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='state-ConsistentlyFailing'>Failing: $failing</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='state-Unobserved'>Unobserved: $unobserved</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='state-ManualAttestationRequired'>Manual: $manual</span></div>")
        [void]$sb.AppendLine('</div>')
    }
    [void]$sb.AppendLine('</div></section>')

    # Snapshot Timeline
    [void]$sb.AppendLine('<section class="report"><h2>Snapshot Timeline</h2>')
    [void]$sb.AppendLine('<table><thead><tr><th>Snapshot ID</th><th>Captured (UTC)</th><th>Tenant</th><th>Findings</th><th>Gap from previous (days)</th></tr></thead><tbody>')
    $previousUtc = $null
    foreach ($snap in $Coverage.Snapshots) {
        $gapText = if ($null -eq $previousUtc) { '-' } else { ([math]::Round(($snap.CreatedAtUtc - $previousUtc).TotalDays, 1)).ToString() }
        [void]$sb.AppendLine('<tr>')
        [void]$sb.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($snap.SnapshotId))</td>")
        [void]$sb.AppendLine("<td>$($snap.CreatedAtUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))</td>")
        [void]$sb.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($snap.TenantName))</td>")
        [void]$sb.AppendLine("<td>$($snap.FindingCount)</td>")
        [void]$sb.AppendLine("<td>$gapText</td>")
        [void]$sb.AppendLine('</tr>')
        $previousUtc = $snap.CreatedAtUtc
    }
    [void]$sb.AppendLine('</tbody></table></section>')

    # Control Register with Period Consistency
    [void]$sb.AppendLine('<section class="report"><h2>Control Register with Period Consistency</h2>')
    [void]$sb.AppendLine('<table><thead><tr><th>Control</th><th>Family</th><th>State</th><th>First Seen (UTC)</th><th>Last Seen (UTC)</th><th>Pass</th><th>Warn</th><th>Fail</th><th>Observed</th></tr></thead><tbody>')
    foreach ($controlId in ($Coverage.ControlAnalysis.Keys | Sort-Object)) {
        $a = $Coverage.ControlAnalysis[$controlId]
        $stateClass = "state-$($a.State)"
        [void]$sb.AppendLine('<tr>')
        [void]$sb.AppendLine("<td><strong>$($a.ControlId)</strong></td>")
        [void]$sb.AppendLine("<td>$($a.Family)</td>")
        [void]$sb.AppendLine("<td class='$stateClass'>$($a.State)</td>")
        [void]$sb.AppendLine("<td>$($a.FirstSeenUtc)</td>")
        [void]$sb.AppendLine("<td>$($a.LastSeenUtc)</td>")
        [void]$sb.AppendLine("<td>$($a.PassOccurrences)</td>")
        [void]$sb.AppendLine("<td>$($a.WarningOccurrences)</td>")
        [void]$sb.AppendLine("<td>$($a.FailOccurrences)</td>")
        [void]$sb.AppendLine("<td>$($a.ObservedSnapshotCount)</td>")
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table></section>')

    # Exceptions Detail
    $exceptions = @($Coverage.ControlAnalysis.Values | Where-Object { $_.State -in @('Inconsistent', 'ConsistentlyFailing') })
    if ($exceptions.Count -gt 0) {
        [void]$sb.AppendLine('<section class="report"><h2>Exceptions Detail</h2>')
        [void]$sb.AppendLine("<p>$($exceptions.Count) control(s) with at least one FAIL during the period:</p>")
        foreach ($exc in $exceptions) {
            [void]$sb.AppendLine("<h3>$($exc.ControlId) - <span class='state-$($exc.State)'>$($exc.State)</span></h3>")
            [void]$sb.AppendLine("<p>$([System.Web.HttpUtility]::HtmlEncode($exc.Description))</p>")
            [void]$sb.AppendLine('<table><thead><tr><th>Snapshot</th><th>Captured (UTC)</th><th>Worst Status</th><th>Findings matched</th></tr></thead><tbody>')
            foreach ($trace in $exc.Trace) {
                $statusClass = if ($trace.WorstStatus -eq 'FAIL') { "state-ConsistentlyFailing" } elseif ($trace.WorstStatus -eq 'WARNING') { "state-DegradedButOperating" } else { "state-ConsistentlyPassing" }
                [void]$sb.AppendLine("<tr><td>$($trace.SnapshotId)</td><td>$($trace.CreatedAtUtc)</td><td class='$statusClass'>$($trace.WorstStatus)</td><td>$($trace.MatchCount)</td></tr>")
            }
            [void]$sb.AppendLine('</tbody></table>')
        }
        [void]$sb.AppendLine('</section>')
    }

    # Skipped snapshots warning
    if ($Coverage.SkippedSnapshots.Count -gt 0) {
        [void]$sb.AppendLine('<section class="report"><h2>Data Integrity</h2>')
        [void]$sb.AppendLine("<p>$($Coverage.SkippedSnapshots.Count) snapshot file(s) could not be parsed and were excluded from the analysis:</p><ul>")
        foreach ($s in $Coverage.SkippedSnapshots) {
            [void]$sb.AppendLine("<li>$([System.Web.HttpUtility]::HtmlEncode($s))</li>")
        }
        [void]$sb.AppendLine('</ul></section>')
    }

    [void]$sb.AppendLine('</main>')

    [void]$sb.AppendLine('<footer>')
    if ($Branding.Footer) {
        [void]$sb.AppendLine([System.Web.HttpUtility]::HtmlEncode($Branding.Footer))
        [void]$sb.AppendLine('<br>')
    }
    if (-not $Branding.SuppressEntraChecksBranding) {
        [void]$sb.AppendLine($Branding.Attribution)
    }
    [void]$sb.AppendLine('</footer></body></html>')

    Set-Content -LiteralPath $OutputPath -Value $sb.ToString() -Encoding UTF8
    return $OutputPath
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-SOC2ControlConsistencyState',
    'Get-SOC2SnapshotUtcTimestamp',
    'Get-SOC2FindingTSCFromSnapshot',
    'Get-SOC2PeriodCoverage',
    'New-SOC2TypeTwoEvidenceBundle',
    'Test-SOC2TypeTwoBundle',
    'New-SOC2TypeTwoReport'
)

#endregion
