<#
.SYNOPSIS
    EntraChecks-SOC2Reporting.psm1 - SOC 2 standalone report builder
    (HTML + Excel/CSV) for internal readiness assessments.

.DESCRIPTION
    Renders the SOC 2 audit view as a TSC-structured report distinct from the
    severity-ranked unified EntraChecks report. The HTML report supports an
    optional local "identity lookup" side panel that resolves redacted hashes
    back to UPNs when the companion identity-resolution map is co-located.

    Excel output is provided when the optional ImportExcel module is available;
    otherwise a multi-CSV fallback is produced.

.NOTES
    Version: 1.0.0
    Author: EntraChecks Project

.LINK
    SOC 2 Implementation Plan: plans/SOC2-Implementation-Plan.md
#>

#Requires -Version 5.1

$script:ModuleName = 'EntraChecks-SOC2Reporting'
$script:ModuleVersion = '1.0.0'

# Phase 2 decision 1 (Path C): these check names ship fixture-verified only;
# the rendered HTML surfaces a caveat banner when results from these appear.
# Graduate to a config key if the list grows.
$script:LowConfidenceCheckNames = @(
    'Test-SOC2DiagnosticSettingsExport',
    'Test-SOC2BreakGlassAccountsConfigured'
)

#region ==================== CONTROL CONCLUSION (audit-readiness register) ====================

<#
.SYNOPSIS
    Returns the SOC 2 audit conclusion for a single control given its mapped
    findings and evidence count. Pure function — no I/O.

.DESCRIPTION
    Implements the precedence table from plans/SOC2-Audit-Readiness-Plan.md §7.
    Order of evaluation (first match wins):

        FAIL (active)        -> Deficiency           (severity from highest FAIL)
        WARNING (active)     -> Deficiency - Minor
        REVIEW / MANUAL      -> Manual Pending       (skipped if ReviewStatus.State is Accepted/Reviewed)
        Licensing Gap        -> Not Assessed - Licensing
        Accepted Risk only   -> Accepted Risk        (no other unaccepted blockers present)
        INFO                 -> Informational
        OK with evidence     -> Effective
        OK without evidence  -> Effective            (still effective; missing evidence is a separate audit-trail concern)
        Nothing              -> Not Assessed - No Evidence

    A finding with `Disposition` in {AcceptedRisk, CompensatingControl,
    FalsePositive, OutOfScope, Resolved, Suppressed} does not drive
    Deficiency. AcceptedRisk / CompensatingControl additionally surface as
    the Accepted Risk conclusion when they are the only blockers.

.PARAMETER ControlId
    The TSC control id (e.g. 'CC6.1') the conclusion is being computed for.
    Echoed back on the output object for caller convenience.

.PARAMETER Findings
    v2-shaped findings mapped to this control. Empty array is legal.

.PARAMETER EvidenceCount
    Number of evidence-bundle records that reference this control. 0 is
    legal; affects only the OK -> Effective vs No-Evidence boundary.

.OUTPUTS
    PSCustomObject with: ControlId, Conclusion, DeficiencySeverity,
    BlockingFinding (or $null), Reason, FindingCount, EvidenceCount.
#>
function Get-SOC2ControlConclusion {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [object[]]$Findings = @(),
        [int]$EvidenceCount = 0
    )

    # Dispositions that exclude a finding from driving a Deficiency.
    # AcceptedRisk and CompensatingControl additionally trigger the Accepted Risk
    # conclusion when no unaccepted blockers exist.
    $acceptedDispositions = @('AcceptedRisk', 'CompensatingControl')
    $excludedDispositions = @('FalsePositive', 'OutOfScope', 'Resolved', 'Suppressed')

    function script:Test-IsLicensingGapFinding {
        param($Finding)
        $t = if ($Finding.PSObject.Properties['Type']) { [string]$Finding.Type } else { '' }
        if ($t -match '^SOC2_LicensingGap') { return $true }
        if ($Finding.PSObject.Properties['Tags']) {
            foreach ($tag in @($Finding.Tags)) {
                if ([string]$tag -eq 'LicensingGap') { return $true }
            }
        }
        return $false
    }

    function script:Test-IsAttestedManual {
        param($Finding)
        if (-not $Finding.PSObject.Properties['ReviewStatus']) { return $false }
        $rs = $Finding.ReviewStatus
        if (-not $rs) { return $false }
        if (-not $rs.PSObject.Properties['State']) { return $false }
        return ([string]$rs.State -in @('Accepted', 'Reviewed'))
    }

    # Severity rank used to pick the worst FAIL as the "blocking" finding.
    $sevRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Info = 0 }

    $activeFails = New-Object System.Collections.Generic.List[object]
    $activeWarnings = New-Object System.Collections.Generic.List[object]
    $acceptedBlockers = New-Object System.Collections.Generic.List[object]
    $manualPending = New-Object System.Collections.Generic.List[object]
    $licensingGaps = New-Object System.Collections.Generic.List[object]
    $infoFindings = New-Object System.Collections.Generic.List[object]
    $okFindings = New-Object System.Collections.Generic.List[object]

    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $status = if ($f.PSObject.Properties['Status']) { [string]$f.Status } else { '' }
        $disposition = if ($f.PSObject.Properties['Disposition']) { [string]$f.Disposition } else { '' }

        # Licensing gaps short-circuit by Type/Tag regardless of Status, because
        # the production code emits them as INFO today. Plan §7 row 4 ranks
        # them above INFO so they have to win that race.
        if (Test-IsLicensingGapFinding $f) {
            $licensingGaps.Add($f) | Out-Null
            continue
        }

        switch ($status) {
            'FAIL' {
                if ($disposition -in $acceptedDispositions) {
                    $acceptedBlockers.Add($f) | Out-Null
                } elseif ($disposition -in $excludedDispositions) {
                    # Resolved / FalsePositive / OutOfScope / Suppressed don't block.
                } else {
                    $activeFails.Add($f) | Out-Null
                }
            }
            'WARNING' {
                if ($disposition -in $acceptedDispositions) {
                    $acceptedBlockers.Add($f) | Out-Null
                } elseif ($disposition -in $excludedDispositions) {
                    # ignore
                } else {
                    $activeWarnings.Add($f) | Out-Null
                }
            }
            'REVIEW' {
                if (Test-IsAttestedManual $f) { $okFindings.Add($f) | Out-Null }
                else { $manualPending.Add($f) | Out-Null }
            }
            'MANUAL' {
                if (Test-IsAttestedManual $f) { $okFindings.Add($f) | Out-Null }
                else { $manualPending.Add($f) | Out-Null }
            }
            'OK' { $okFindings.Add($f) | Out-Null }
            default { $infoFindings.Add($f) | Out-Null }
        }
    }

    $conclusion = ''
    $deficiencySeverity = ''
    $reason = ''
    $blockingFinding = $null

    if ($activeFails.Count -gt 0) {
        # Pick the worst FAIL by severity rank, stable on first-seen for ties.
        $worst = $null
        $worstRank = -1
        foreach ($f in $activeFails) {
            $sev = if ($f.PSObject.Properties['Severity']) { [string]$f.Severity } else { 'Info' }
            $rank = if ($sevRank.ContainsKey($sev)) { $sevRank[$sev] } else { 0 }
            if ($rank -gt $worstRank) { $worst = $f; $worstRank = $rank }
        }
        $blockingFinding = $worst
        $conclusion = 'Deficiency'
        $deficiencySeverity = if ($worst.PSObject.Properties['Severity']) { [string]$worst.Severity } else { 'High' }
        $reason = "FAIL ($deficiencySeverity): $([string]$worst.Description)"
    }
    elseif ($activeWarnings.Count -gt 0) {
        $blockingFinding = $activeWarnings[0]
        $conclusion = 'Deficiency - Minor'
        $deficiencySeverity = 'Medium'
        $reason = "WARNING: $([string]$blockingFinding.Description)"
    }
    elseif ($manualPending.Count -gt 0) {
        $blockingFinding = $manualPending[0]
        $conclusion = 'Manual Pending'
        $reason = "Manual attestation pending: $([string]$blockingFinding.Description)"
    }
    elseif ($licensingGaps.Count -gt 0) {
        $blockingFinding = $licensingGaps[0]
        $conclusion = 'Not Assessed - Licensing'
        $reason = "Licensing gap: $([string]$blockingFinding.Description)"
    }
    elseif ($acceptedBlockers.Count -gt 0) {
        $blockingFinding = $acceptedBlockers[0]
        $conclusion = 'Accepted Risk'
        $reason = "Risk accepted: $([string]$blockingFinding.Description)"
    }
    elseif ($infoFindings.Count -gt 0) {
        $blockingFinding = $infoFindings[0]
        $conclusion = 'Informational'
        $reason = 'Informational findings only'
    }
    elseif ($okFindings.Count -gt 0) {
        $blockingFinding = $okFindings[0]
        $conclusion = 'Effective'
        $reason = if ($EvidenceCount -gt 0) { 'All findings OK, evidence collected' } else { 'All findings OK (no evidence record present)' }
    }
    else {
        $conclusion = 'Not Assessed - No Evidence'
        $reason = 'No findings and no evidence for this control'
    }

    return [pscustomobject]@{
        ControlId = $ControlId
        Conclusion = $conclusion
        DeficiencySeverity = $deficiencySeverity
        BlockingFinding = $blockingFinding
        Reason = $reason
        FindingCount = @($Findings).Count
        EvidenceCount = $EvidenceCount
    }
}

<#
.SYNOPSIS
    Builds the Control Conclusion Register: one row per SOC 2 control, with
    conclusion, owner, due date, exception status, evidence count, and
    management response.

.DESCRIPTION
    Walks the TSC catalog. For each control:
      1. Pulls mapped findings from $Summary.ControlFindings[control.Id].
      2. Counts evidence records that reference this control (best-effort —
         falls back to bundle-wide count when per-control mapping is absent).
      3. Calls Get-SOC2ControlConclusion to compute the conclusion.
      4. Reads Owner / Exception / ManagementResponse from the v2 fields on
         the blocking finding (or the highest-severity finding for the
         control if no blocker was identified).

    Sort order: families in canonical order (CC, A, C, PI, P) and then by
    control id within family.

.PARAMETER Catalog
    Output of Get-SOC2TSCCatalog.

.PARAMETER Summary
    Output of Get-SOC2Summary (the .Summary property of the
    Invoke-SOC2Assessment result).

.PARAMETER EvidenceBundle
    Optional output of New-SOC2EvidenceBundle. When present (and its
    manifest is readable), per-control evidence counts are derived from
    the bundle manifest via Get-SOC2EvidenceMatrix; otherwise every
    control row reports EvidenceCount=0.

.OUTPUTS
    Array of PSCustomObject rows with:
      ControlId, TscFamily, FamilyName, Automation, ControlDescription,
      Conclusion, DeficiencySeverity, FindingCount, EvidenceCount, Owner,
      DueDate, ExceptionStatus, ManagementResponse, ControlOwnerHint,
      Reason, Remediation, ValidationSteps, EvidenceNeeded.
    The last three are PR 2 source columns consumed by
    Get-SOC2RemediationPlan.
#>
function Get-SOC2ControlConclusionRegister {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object[]]$Catalog,
        [Parameter(Mandatory)][pscustomobject]$Summary,
        [pscustomobject]$EvidenceBundle
    )

    # Per-control evidence counts. Derived from the bundle manifest via
    # Get-SOC2EvidenceMatrix (the canonical reader added in PR 3) so the
    # register's EvidenceCount and the Evidence Matrix never disagree on
    # what an "evidence artifact" is. One matrix row == one hashed
    # artifact in the manifest (a control's automated-capture JSON, plus
    # the manual-attestation template for Manual controls).
    #
    # The original PR 1 implementation read $EvidenceBundle.Findings,
    # which the production New-SOC2EvidenceBundle return object never
    # carries (it only exposes ManifestPath) — so this count was silently
    # 0 on every real run. Reading the manifest fixes that.
    $evidenceByControl = @{}
    $matrixRows = Get-SOC2EvidenceMatrix -EvidenceBundle $EvidenceBundle -ControlCatalog $Catalog
    foreach ($mr in @($matrixRows)) {
        if (-not $mr) { continue }
        $key = [string]$mr.ControlId
        if (-not $key) { continue }
        if (-not $evidenceByControl.ContainsKey($key)) { $evidenceByControl[$key] = 0 }
        $evidenceByControl[$key]++
    }

    $familyOrder = @{ CC = 0; A = 1; C = 2; PI = 3; P = 4 }
    $ordered = @($Catalog | Sort-Object @{
            Expression = { if ($familyOrder.ContainsKey([string]$_.Family)) { $familyOrder[[string]$_.Family] } else { 99 } }
        }, 'Id')

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($control in $ordered) {
        $controlId = [string]$control.Id
        $controlFindings = if ($Summary.ControlFindings.ContainsKey($controlId)) {
            @($Summary.ControlFindings[$controlId])
        } else { @() }
        $evidenceCount = if ($evidenceByControl.ContainsKey($controlId)) { $evidenceByControl[$controlId] } else { 0 }

        $conclusion = Get-SOC2ControlConclusion `
            -ControlId $controlId `
            -Findings $controlFindings `
            -EvidenceCount $evidenceCount

        # Pull owner/exception/management response off the blocking finding when
        # we have one. v2 normalization always populates the fields (with empty
        # objects when no real state exists), so the property checks below are
        # belt-and-braces against legacy or partial findings.
        $owner = ''
        $dueDate = ''
        $exceptionStatus = 'None'
        $managementResponse = ''
        $remediation = ''
        $validationSteps = ''

        $bf = $conclusion.BlockingFinding
        if ($bf) {
            if ($bf.PSObject.Properties['Owner'] -and $bf.Owner) {
                if ($bf.Owner.PSObject.Properties['DisplayName']) { $owner = [string]$bf.Owner.DisplayName }
                if ($bf.Owner.PSObject.Properties['DueDate']) { $dueDate = [string]$bf.Owner.DueDate }
            }
            if ($bf.PSObject.Properties['Exception'] -and $bf.Exception) {
                if ($bf.Exception.PSObject.Properties['Status']) {
                    $st = [string]$bf.Exception.Status
                    if ($st) { $exceptionStatus = $st }
                }
            }
            if ($bf.PSObject.Properties['ManagementResponse'] -and $bf.ManagementResponse) {
                $managementResponse = [string]$bf.ManagementResponse
            }
            if ($bf.PSObject.Properties['Remediation'] -and $bf.Remediation) {
                $remediation = [string]$bf.Remediation
            }
            # ValidationSteps: v2 RemediationGuidance carries a Verification
            # array (how to confirm the fix landed). PR 2 §9.1 surfaces it in
            # the Remediation Plan. Tolerate hashtable or pscustomobject.
            if ($bf.PSObject.Properties['RemediationGuidance'] -and $bf.RemediationGuidance) {
                $rg = $bf.RemediationGuidance
                $verification = if ($rg -is [hashtable] -and $rg.ContainsKey('Verification')) {
                    $rg['Verification']
                } elseif ($rg.PSObject -and $rg.PSObject.Properties['Verification']) {
                    $rg.Verification
                } else { $null }
                if ($verification) {
                    $validationSteps = (@($verification) | Where-Object { $_ }) -join ' | '
                }
            }
        }
        if (-not $owner -and $control.PSObject.Properties['ControlOwnerHint']) {
            # Fall back to the catalog's owner hint so the column is never empty.
            $owner = [string]$control.ControlOwnerHint
        }
        if (-not $validationSteps) {
            $validationSteps = 'Re-run Invoke-SOC2Assessment after remediation and confirm this control no longer reports a gap.'
        }

        # EvidenceNeeded: derived from the conclusion + control automation
        # type. Licensing gaps need a SKU/assignment proof; manual controls
        # need a signed attestation; automated controls need a fresh passing
        # run plus a config screenshot.
        $automation = if ($control.PSObject.Properties['Automation']) { [string]$control.Automation } else { '' }
        $evidenceNeeded = if ($conclusion.Conclusion -eq 'Not Assessed - Licensing') {
            'License / SKU assignment proof (invoice or admin-center screenshot showing the required plan is assigned).'
        } elseif ($automation -eq 'Manual') {
            "Signed management attestation in evidence-bundle/manual-attestation/$controlId.md (owner, operation, frequency, attested-by/date)."
        } else {
            'Re-run the SOC 2 assessment after remediation; capture the passing check output plus a configuration screenshot.'
        }

        $row = [pscustomobject]@{
            ControlId = $controlId
            TscFamily = [string]$control.Family
            FamilyName = if ($control.PSObject.Properties['FamilyName']) { [string]$control.FamilyName } else { '' }
            Automation = if ($control.PSObject.Properties['Automation']) { [string]$control.Automation } else { '' }
            ControlDescription = if ($control.PSObject.Properties['Description']) { [string]$control.Description } else { '' }
            Conclusion = $conclusion.Conclusion
            DeficiencySeverity = $conclusion.DeficiencySeverity
            FindingCount = $conclusion.FindingCount
            EvidenceCount = $conclusion.EvidenceCount
            Owner = $owner
            DueDate = $dueDate
            ExceptionStatus = $exceptionStatus
            ManagementResponse = $managementResponse
            ControlOwnerHint = if ($control.PSObject.Properties['ControlOwnerHint']) { [string]$control.ControlOwnerHint } else { '' }
            Reason = $conclusion.Reason
            # PR 2 §9.1 — remediation-plan source columns. Additive; the
            # Control Conclusion Register HTML table does not render these
            # (it picks columns explicitly), but the Excel/CSV gain them
            # and Get-SOC2RemediationPlan projects them into its view.
            Remediation = $remediation
            ValidationSteps = $validationSteps
            EvidenceNeeded = $evidenceNeeded
        }
        $rows.Add($row) | Out-Null
    }

    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds the Remediation Plan: the actionable subset of the Control
    Conclusion Register, prioritised and sorted for an owner to work
    top-down. SOC 2 Audit-Readiness Plan PR 2 §9.

.DESCRIPTION
    A pure view over the register produced by
    Get-SOC2ControlConclusionRegister — no finding walking, no new
    collection. Steps:

      1. Exclude rows whose Conclusion is Effective, Accepted Risk, or
         Informational (nothing to remediate).
      2. Derive Priority (1 = most urgent):
           1  Deficiency, severity Critical or High
           2  Deficiency (Medium/Low) or Deficiency - Minor
           3  Manual Pending
           4  Not Assessed - Licensing
           5  Not Assessed - No Evidence
         (Plan §9.1 wrote "5 = Warning"; PR 1 folded WARNING into
         Deficiency - Minor, so tier 5 is now the residual no-evidence
         gap — the closest analog. Decision recorded in the plan.)
      3. Sort Priority asc, then DueDate asc (blank dates last so dated
         work floats up), then ControlId asc — stable and deterministic.
      4. Project the auditor-facing columns.

.PARAMETER Register
    Output of Get-SOC2ControlConclusionRegister.

.OUTPUTS
    Array of PSCustomObject rows:
      Priority, ControlId, TscFamily, Gap, Owner, DueDate,
      Remediation, ValidationSteps, EvidenceNeeded.
#>
function Get-SOC2RemediationPlan {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Register
    )

    $excluded = @('Effective', 'Accepted Risk', 'Informational')

    $scored = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Register) {
        if ($null -eq $r) { continue }
        $conclusion = [string]$r.Conclusion
        if ($conclusion -in $excluded) { continue }

        $severity = if ($r.PSObject.Properties['DeficiencySeverity']) { [string]$r.DeficiencySeverity } else { '' }
        $priority = switch ($conclusion) {
            'Deficiency' { if ($severity -in @('Critical', 'High')) { 1 } else { 2 } }
            'Deficiency - Minor' { 2 }
            'Manual Pending' { 3 }
            'Not Assessed - Licensing' { 4 }
            'Not Assessed - No Evidence' { 5 }
            default { 6 }
        }

        $gap = if ($r.PSObject.Properties['Reason'] -and $r.Reason) {
            "$conclusion - $([string]$r.Reason)"
        } else {
            $conclusion
        }

        $row = [pscustomobject]@{
            Priority = $priority
            ControlId = [string]$r.ControlId
            TscFamily = if ($r.PSObject.Properties['TscFamily']) { [string]$r.TscFamily } else { '' }
            Gap = $gap
            Owner = if ($r.PSObject.Properties['Owner']) { [string]$r.Owner } else { '' }
            DueDate = if ($r.PSObject.Properties['DueDate']) { [string]$r.DueDate } else { '' }
            Remediation = if ($r.PSObject.Properties['Remediation']) { [string]$r.Remediation } else { '' }
            ValidationSteps = if ($r.PSObject.Properties['ValidationSteps']) { [string]$r.ValidationSteps } else { '' }
            EvidenceNeeded = if ($r.PSObject.Properties['EvidenceNeeded']) { [string]$r.EvidenceNeeded } else { '' }
        }
        $scored.Add($row) | Out-Null
    }

    # Sort key: Priority asc; then DueDate asc with blanks last (a blank
    # due date sorts AFTER any real date so committed/dated work rises);
    # then ControlId asc for a stable, deterministic order.
    $byPriority = @{ Expression = { [int]$_.Priority } }
    $byDue = @{ Expression = { if ([string]::IsNullOrWhiteSpace($_.DueDate)) { '9999-12-31' } else { [string]$_.DueDate } } }
    $byControl = @{ Expression = { [string]$_.ControlId } }
    $sorted = $scored.ToArray() | Sort-Object -Property $byPriority, $byDue, $byControl

    return , @($sorted)
}

<#
.SYNOPSIS
    Buckets an evidence artifact's age into Fresh / Aging / Stale.
    Pure boundary math — SOC 2 Audit-Readiness Plan PR 3 §10.1.

.DESCRIPTION
    Fresh  : age < 30 days
    Aging  : 30 <= age < 90 days
    Stale  : age >= 90 days
    Unknown: CollectionTime missing or unparseable.

    Boundaries are half-open so the day-30 and day-90 marks are
    deterministic (29d -> Fresh, 30d -> Aging, 89d -> Aging,
    90d -> Stale).

.PARAMETER CollectionTime
    ISO-8601 timestamp string (e.g. the manifest GeneratedAt).

.PARAMETER AsOf
    Reference "now" for the age calculation. Defaults to current UTC.
    Injectable so tests can pin the boundary math.

.OUTPUTS
    String: Fresh | Aging | Stale | Unknown.
#>
function Get-SOC2EvidenceFreshness {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()][string]$CollectionTime,
        [datetime]$AsOf = ([datetime]::UtcNow)
    )

    if ([string]::IsNullOrWhiteSpace($CollectionTime)) { return 'Unknown' }

    # DateTimeOffset carries the zone, so the age math is tz-kind safe even
    # when -AsOf is a Local/Unspecified [datetime] (e.g. a string literal)
    # and the timestamp is UTC. Mixing those as plain [datetime] would skew
    # the result by the local UTC offset.
    $parsed = [System.DateTimeOffset]::MinValue
    $ok = [System.DateTimeOffset]::TryParse(
        $CollectionTime,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$parsed)
    if (-not $ok) { return 'Unknown' }

    # Interpret AsOf's wall clock as UTC (matches AssumeUniversal above) so a
    # pinned [datetime] literal in tests and the UtcNow default behave the same.
    $asOfUtc = [datetime]::SpecifyKind($AsOf, [System.DateTimeKind]::Utc)
    $asOfOffset = [System.DateTimeOffset]::new($asOfUtc)
    $ageDays = ($asOfOffset - $parsed).TotalDays
    if ($ageDays -lt 0) { $ageDays = 0 }   # clock skew → treat as fresh
    if ($ageDays -lt 30) { return 'Fresh' }
    if ($ageDays -lt 90) { return 'Aging' }
    return 'Stale'
}

<#
.SYNOPSIS
    Pivots the evidence bundle manifest into one row per evidence
    artifact, keyed to its TSC control. SOC 2 Audit-Readiness Plan
    PR 3 §10.

.DESCRIPTION
    A pure view — reads the manifest JSON written by
    New-SOC2EvidenceBundle (the canonical record), maps each hashed
    file back to a control, and joins the catalog for TscFamily.

    Per-file ControlId is parsed from the manifest relative path
    (controls/<Id>.json or manual-attestation/<Id>.md). The bundle
    return object only carries ManifestPath, so this is the only
    reliable per-control evidence source.

    RedactionStatus is bundle-wide: redaction (Invoke-SOC2Redaction)
    runs over every finding before the bundle is written, so either
    all artifacts derive from redacted findings or none do. The signal
    is taken from -IdentityMapPath (set on the assessment result when
    redaction ran) and its salt-fingerprint metadata.

.PARAMETER EvidenceBundle
    The PSCustomObject returned by New-SOC2EvidenceBundle (needs
    .ManifestPath). $null → empty matrix.

.PARAMETER ControlCatalog
    Output of Get-SOC2TSCCatalog (for TscFamily lookup).

.PARAMETER IdentityMapPath
    Optional path to the identity-resolution map. When present, every
    row's RedactionStatus reflects the recorded hash algorithm;
    otherwise rows report "Not redacted".

.PARAMETER AsOf
    Reference time for Freshness. Defaults to current UTC.

.OUTPUTS
    Array of PSCustomObject rows:
      ControlId, TscFamily, EvidenceArtifact, Source, CollectionTime,
      Hash, RedactionStatus, Freshness, AnchorId.
#>
function Get-SOC2EvidenceMatrix {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()][pscustomobject]$EvidenceBundle,
        [Parameter(Mandatory)][object[]]$ControlCatalog,
        [AllowNull()][AllowEmptyString()][string]$IdentityMapPath,
        [datetime]$AsOf = ([datetime]::UtcNow)
    )

    $rows = New-Object System.Collections.Generic.List[object]

    if (-not $EvidenceBundle -or
        -not $EvidenceBundle.PSObject.Properties['ManifestPath'] -or
        -not $EvidenceBundle.ManifestPath -or
        -not (Test-Path -LiteralPath $EvidenceBundle.ManifestPath)) {
        return , $rows.ToArray()
    }

    try {
        $manifest = Get-Content -LiteralPath $EvidenceBundle.ManifestPath -Raw | ConvertFrom-Json
    } catch {
        return , $rows.ToArray()
    }

    $collectionTime = if ($manifest.PSObject.Properties['GeneratedAt']) { [string]$manifest.GeneratedAt } else { '' }
    $freshness = Get-SOC2EvidenceFreshness -CollectionTime $collectionTime -AsOf $AsOf

    # Bundle-wide redaction status from the identity-resolution map.
    $redactionStatus = 'Not redacted'
    if ($IdentityMapPath -and (Test-Path -LiteralPath $IdentityMapPath)) {
        try {
            $idMap = Get-Content -LiteralPath $IdentityMapPath -Raw | ConvertFrom-Json
            $algo = if ($idMap.PSObject.Properties['HashAlgorithm'] -and $idMap.HashAlgorithm) { [string]$idMap.HashAlgorithm } else { 'SHA256' }
            $redactionStatus = "Redacted ($algo, salted)"
        } catch {
            $redactionStatus = 'Redacted'
        }
    }

    # Family lookup from the catalog.
    $familyById = @{}
    foreach ($c in $ControlCatalog) {
        if ($c -and $c.PSObject.Properties['Id']) {
            $familyById[[string]$c.Id] = if ($c.PSObject.Properties['Family']) { [string]$c.Family } else { '' }
        }
    }

    $files = if ($manifest.PSObject.Properties['Files']) { @($manifest.Files) } else { @() }
    foreach ($entry in $files) {
        if (-not $entry) { continue }
        $rel = if ($entry.PSObject.Properties['RelativePath']) { [string]$entry.RelativePath } else { '' }
        if (-not $rel) { continue }
        # Skip the manifest itself if it ever appears in its own Files list.
        if ($rel -match '(^|[\\/])manifest\.json$') { continue }

        # ControlId is the file stem under controls/ or manual-attestation/.
        $leaf = [System.IO.Path]::GetFileNameWithoutExtension($rel)
        $controlId = $leaf
        $source = if ($rel -match '(^|[\\/])controls[\\/]') {
            'Automated control capture'
        } elseif ($rel -match '(^|[\\/])manual-attestation[\\/]') {
            'Manual attestation template'
        } else {
            'Bundle artifact'
        }

        $hash = if ($entry.PSObject.Properties['SHA256']) { [string]$entry.SHA256 } else { '' }
        # The SHA-256 is already ASCII hex, so a stable per-row anchor is
        # just the prefix + first 16 chars — no cross-module dependency on
        # New-SafeElementId (HTMLReporting) needed.
        $anchorId = if ($hash) { 'soc2-evidence-' + $hash.Substring(0, [Math]::Min(16, $hash.Length)) } else { 'soc2-evidence-empty' }

        $tscFamily = if ($familyById.ContainsKey($controlId)) { $familyById[$controlId] } else { '' }

        $row = [pscustomobject]@{
            ControlId = $controlId
            TscFamily = $tscFamily
            EvidenceArtifact = $rel
            Source = $source
            CollectionTime = $collectionTime
            Hash = $hash
            RedactionStatus = $redactionStatus
            Freshness = $freshness
            AnchorId = $anchorId
        }
        $rows.Add($row) | Out-Null
    }

    # Stable order: TscFamily, then ControlId, then artifact path.
    $byFamily = @{ Expression = { [string]$_.TscFamily } }
    $byControl = @{ Expression = { [string]$_.ControlId } }
    $byArtifact = @{ Expression = { [string]$_.EvidenceArtifact } }
    $sorted = $rows.ToArray() | Sort-Object -Property $byFamily, $byControl, $byArtifact

    return , @($sorted)
}

#endregion

#region ==================== INTERNAL HELPERS (row builders + digest) ====================

<#
.SYNOPSIS
    Builds summary-by-category rows once, consumed by both Excel and CSV branches.
#>
function Get-SOC2SummaryByCategoryRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][pscustomobject]$Summary)

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $f = $Summary.ByFamily[$family]
        if (-not $f) { continue }
        if (($f.Automated + $f.Manual) -eq 0) { continue }
        $licensingGapCount = if ($null -ne $f.LicensingGaps) { $f.LicensingGaps } else { 0 }
        $row = [pscustomobject]@{
            Family = $family
            Automated = $f.Automated
            Manual = $f.Manual
            Pass = $f.Pass
            Fail = $f.Fail
            Warning = $f.Warning
            Info = $f.Info
            LicensingGaps = $licensingGapCount
        }
        $rows.Add($row) | Out-Null
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds control-register rows for either report format.
#>
function Get-SOC2ControlRegisterRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object[]]$Catalog,
        [Parameter(Mandatory)][pscustomobject]$Summary
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($control in $Catalog) {
        $count = if ($Summary.ControlFindings.ContainsKey($control.Id)) {
            @($Summary.ControlFindings[$control.Id]).Count
        } else { 0 }
        $row = [pscustomobject]@{
            ControlId = $control.Id
            Family = $control.Family
            FamilyName = $control.FamilyName
            Automation = $control.Automation
            Description = $control.Description
            ControlOwnerHint = $control.ControlOwnerHint
            FindingCount = $count
        }
        $rows.Add($row) | Out-Null
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds finding rows for a given TSC-family predicate (e.g., "starts with CC6").
    Returns empty array when no findings match (callers skip empty sheets/files).
#>
function Get-SOC2FindingsByFamilyRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object[]]$Catalog,
        [Parameter(Mandatory)][pscustomobject]$Summary,
        [Parameter(Mandatory)][scriptblock]$Predicate
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($control in $Catalog) {
        if (-not (& $Predicate $control.Id)) { continue }
        $controlFindings = if ($Summary.ControlFindings.ContainsKey($control.Id)) {
            @($Summary.ControlFindings[$control.Id])
        } else { @() }
        foreach ($finding in $controlFindings) {
            $severity = if ($finding.PSObject.Properties['Severity']) { $finding.Severity } else { '' }
            $row = [pscustomobject]@{
                ControlId = $control.Id
                Status = $finding.Status
                Severity = $severity
                CheckName = $finding.CheckName
                Object = $finding.Object
                Description = $finding.Description
                Remediation = $finding.Remediation
            }
            $rows.Add($row) | Out-Null
        }
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds licensing-gap rows (de-duped by Type + Object).
#>
function Get-SOC2LicensingGapRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][pscustomobject]$Summary)

    $rows = [System.Collections.Generic.List[object]]::new()
    $allFindings = @()
    foreach ($controlId in $Summary.ControlFindings.Keys) {
        $allFindings += @($Summary.ControlFindings[$controlId])
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($finding in $allFindings) {
        if (-not ($finding.PSObject.Properties['Type'] -and $finding.Type -like 'SOC2_LicensingGap_*')) { continue }
        $key = "$($finding.Type)|$($finding.Object)"
        if (-not $seen.Add($key)) { continue }
        $feature = $finding.Type.Substring('SOC2_LicensingGap_'.Length)
        $tscList = ''
        if ($finding.PSObject.Properties['TSCReferences']) { $tscList = ($finding.TSCReferences -join ', ') }
        $severity = if ($finding.PSObject.Properties['Severity']) { $finding.Severity } else { '' }
        $owner = if ($finding.PSObject.Properties['ControlOwnerHint']) { $finding.ControlOwnerHint } else { '' }
        $row = [pscustomobject]@{
            Feature = $feature
            Status = $finding.Status
            Severity = $severity
            AffectedTSCs = $tscList
            Description = $finding.Description
            Remediation = $finding.Remediation
            ControlOwnerHint = $owner
        }
        $rows.Add($row) | Out-Null
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds manual-attestation register rows, populated from the tracked
    attestation state when supplied (Audit-Readiness Plan §11.1).

.DESCRIPTION
    Pre-§11.1 this returned all-empty placeholder cells. It now reflects
    the per-control lifecycle (State + owner + dates + reviewer + notes)
    from the attestation state, defaulting to 'NotStarted' for controls
    with no recorded attestation.

.PARAMETER Catalog
    Output of Get-SOC2TSCCatalog.

.PARAMETER AttestationState
    Hashtable from Import-SOC2AttestationState
    (@{ Attestations = @{ <ControlId> = <record> } }). Optional — when
    absent every manual control renders the NotStarted default.
#>
function Get-SOC2ManualAttestationRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object[]]$Catalog,
        [hashtable]$AttestationState
    )

    $bucket = @{}
    if ($AttestationState -and $AttestationState.ContainsKey('Attestations') -and $AttestationState['Attestations']) {
        $bucket = $AttestationState['Attestations']
    }

    $field = {
        param($Record, [string]$Name)
        if (-not $Record) { return '' }
        if ($Record -is [hashtable]) {
            if ($Record.ContainsKey($Name)) { return [string]$Record[$Name] }
            return ''
        }
        if ($Record.PSObject -and $Record.PSObject.Properties[$Name]) { return [string]$Record.$Name }
        return ''
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($control in $Catalog) {
        if ($control.Automation -ne 'Manual') { continue }

        $controlId = [string]$control.Id
        $record = $null
        if ($bucket -is [hashtable] -and $bucket.ContainsKey($controlId)) {
            $record = $bucket[$controlId]
        }
        elseif ($bucket.PSObject -and $bucket.PSObject.Properties[$controlId]) {
            $record = $bucket.$controlId
        }

        $state = & $field $record 'State'
        if (-not $state) { $state = 'NotStarted' }
        $owner = & $field $record 'ControlOwner'
        if (-not $owner -and $control.PSObject.Properties['ControlOwnerHint']) {
            $owner = [string]$control.ControlOwnerHint
        }

        $row = [pscustomobject]@{
            ControlId = $controlId
            Family = $control.Family
            State = $state
            ControlOwner = $owner
            RequestedDate = (& $field $record 'RequestedDate')
            ReceivedDate = (& $field $record 'ReceivedDate')
            EvidenceLocation = (& $field $record 'EvidenceLocation')
            Reviewer = (& $field $record 'Reviewer')
            NextReviewDate = (& $field $record 'NextReviewDate')
            Notes = (& $field $record 'Notes')
            Description = $control.Description
        }
        $rows.Add($row) | Out-Null
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds evidence-register rows from a manifest. Returns empty when no manifest.

.PARAMETER Evidence
    Evidence object returned by New-SOC2EvidenceBundle (a PSCustomObject with
    ManifestPath, BundleHash, Directory, FileCount, GeneratedAt). Accepts null.

    The parameter is typed as [object] rather than [hashtable] because the
    real production path returns a PSCustomObject; PowerShell does not
    auto-coerce PSCustomObject -> Hashtable. Tests may pass a hashtable
    fixture — both shapes expose the same dotted-property access this
    function uses.
#>
function Get-SOC2EvidenceRegisterRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object]$Evidence
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    if ($Evidence -and $Evidence.ManifestPath -and (Test-Path -LiteralPath $Evidence.ManifestPath)) {
        $manifest = Get-Content -LiteralPath $Evidence.ManifestPath -Raw | ConvertFrom-Json
        foreach ($file in $manifest.Files) {
            $row = [pscustomobject]@{
                RelativePath = $file.RelativePath
                SHA256 = $file.SHA256
            }
            $rows.Add($row) | Out-Null
        }
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Per-family predicate registry used by both Excel and CSV branches.
    Returns an ordered list of @{Name; Predicate} objects.
#>
function Get-SOC2FamilyPredicates {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return , @(
        [pscustomobject]@{ Name = 'CC6'; Predicate = { param($c) $c.StartsWith('CC6') } },
        [pscustomobject]@{ Name = 'CC7'; Predicate = { param($c) $c.StartsWith('CC7') } },
        [pscustomobject]@{ Name = 'CC8'; Predicate = { param($c) $c.StartsWith('CC8') } },
        [pscustomobject]@{ Name = 'Other-CC'; Predicate = { param($c) $c.StartsWith('CC') -and -not ($c.StartsWith('CC6') -or $c.StartsWith('CC7') -or $c.StartsWith('CC8')) } },
        [pscustomobject]@{ Name = 'Availability'; Predicate = { param($c) $c.StartsWith('A') } },
        [pscustomobject]@{ Name = 'Confidentiality'; Predicate = { param($c) $c.StartsWith('C') -and -not $c.StartsWith('CC') } }
    )
}

<#
.SYNOPSIS
    Computes the executive digest: readiness verdict + top failing TSCs + top
    licensing-gap features. Consumed by New-SOC2AuditReport for the Executive
    Summary section.
#>
function Get-SOC2ExecutiveDigest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object[]]$Catalog,
        [Parameter(Mandatory)][pscustomobject]$Summary,
        # Optional — if provided, the verdict is derived from control-level
        # conclusions rather than aggregate finding counts. See
        # plans/SOC2-Audit-Readiness-Plan.md §8.5.
        [pscustomobject]$EvidenceBundle
    )

    # Legacy finding-count rollup. Kept for backwards compat — external
    # consumers (CI badges, dashboards) read TotalPass / Fail / Warning.
    $totalFail = 0
    $totalWarn = 0
    $totalPass = 0
    $totalControls = 0
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $f = $Summary.ByFamily[$family]
        if (-not $f) { continue }
        $totalFail += $f.Fail
        $totalWarn += $f.Warning
        $totalPass += $f.Pass
        $totalControls += ($f.Automated + $f.Manual)
    }

    # PR 1: verdict from control conclusions. The plan's rationale is that
    # a single high-severity FAIL on one control should drive the verdict,
    # not get diluted by 50 OK findings on the same control. Build the
    # register once and tally.
    $register = Get-SOC2ControlConclusionRegister `
        -Catalog $Catalog `
        -Summary $Summary `
        -EvidenceBundle $EvidenceBundle

    $conclusionCounts = @{
        'Deficiency' = 0
        'Deficiency - Minor' = 0
        'Manual Pending' = 0
        'Not Assessed - Licensing' = 0
        'Accepted Risk' = 0
        'Informational' = 0
        'Effective' = 0
        'Not Assessed - No Evidence' = 0
    }
    $criticalDeficiencyCount = 0
    foreach ($row in $register) {
        if ($conclusionCounts.ContainsKey($row.Conclusion)) {
            $conclusionCounts[$row.Conclusion]++
        }
        if ($row.Conclusion -eq 'Deficiency' -and [string]$row.DeficiencySeverity -in @('Critical', 'High')) {
            $criticalDeficiencyCount++
        }
    }

    $verdict = 'INSUFFICIENT DATA'
    $verdictClass = 'state-Unobserved'
    if ($register.Count -gt 0) {
        # Plan §8.5 verdict rules:
        # - Audit-Ready: every control Effective or Accepted Risk.
        # - Potential Material Deficiency: any Critical/High Deficiency.
        #   Phrased as "potential" deliberately — this tool flags for
        #   analyst attention, it does not render the formal audit
        #   determination of a material deficiency.
        # - Gaps Identified: any Deficiency or Deficiency - Minor remaining.
        # - In Progress: any Manual Pending or Not Assessed.
        $auditReady = (
            $conclusionCounts['Deficiency'] -eq 0 -and
            $conclusionCounts['Deficiency - Minor'] -eq 0 -and
            $conclusionCounts['Manual Pending'] -eq 0 -and
            $conclusionCounts['Not Assessed - Licensing'] -eq 0 -and
            $conclusionCounts['Not Assessed - No Evidence'] -eq 0
        )
        if ($auditReady) {
            $verdict = 'AUDIT-READY'
            $verdictClass = 'state-ConsistentlyPassing'
        } elseif ($criticalDeficiencyCount -gt 0) {
            $verdict = 'POTENTIAL MATERIAL DEFICIENCY'
            $verdictClass = 'state-Inconsistent'
        } elseif ($conclusionCounts['Deficiency'] -gt 0 -or $conclusionCounts['Deficiency - Minor'] -gt 0) {
            $verdict = 'GAPS IDENTIFIED'
            $verdictClass = 'state-Inconsistent'
        } else {
            $verdict = 'IN PROGRESS'
            $verdictClass = 'state-DegradedButOperating'
        }
    }

    # Top failing TSCs: per control, count FAIL+WARNING findings, sort desc
    $tscFailCounts = [System.Collections.Generic.List[object]]::new()
    foreach ($control in $Catalog) {
        if (-not $Summary.ControlFindings.ContainsKey($control.Id)) { continue }
        $findings = @($Summary.ControlFindings[$control.Id])
        $fail = @($findings | Where-Object { $_.Status -eq 'FAIL' -or $_.Status -eq 'WARNING' }).Count
        if ($fail -gt 0) {
            $row = [pscustomobject]@{
                ControlId = $control.Id
                Family = $control.Family
                Description = $control.Description
                FailCount = $fail
            }
            $tscFailCounts.Add($row) | Out-Null
        }
    }
    $topFailingTscs = @($tscFailCounts | Sort-Object FailCount -Descending | Select-Object -First 3)

    # Top licensing gaps by affected TSC count (from ByFeature rollup if present)
    $topLicensingGaps = @()
    if ($Summary.PSObject.Properties['LicensingGaps'] -and $Summary.LicensingGaps -and $Summary.LicensingGaps.ByFeature) {
        $topLicensingGaps = @(
            $Summary.LicensingGaps.ByFeature.GetEnumerator() |
                Where-Object { $_.Value -gt 0 } |
                Sort-Object Value -Descending |
                Select-Object -First 3 |
                ForEach-Object { [pscustomobject]@{ Feature = $_.Key; Count = $_.Value } }
        )
    }

    return [pscustomobject]@{
        Verdict = $verdict
        VerdictClass = $verdictClass
        TotalControls = $totalControls
        TotalPass = $totalPass
        TotalFail = $totalFail
        TotalWarning = $totalWarn
        TotalFindings = $Summary.TotalFindings
        TopFailingTscs = $topFailingTscs
        TopLicensingGaps = $topLicensingGaps
        LicensingGapsTotal = if ($Summary.PSObject.Properties['LicensingGaps'] -and $Summary.LicensingGaps) { $Summary.LicensingGaps.Total } else { 0 }
        # PR 1: control-level conclusion rollup. Callers can render the
        # register without re-walking the catalog.
        ControlConclusions = $conclusionCounts
        CriticalDeficiencyCount = $criticalDeficiencyCount
        ConclusionRegister = $register
    }
}

<#
.SYNOPSIS
    Returns $true if the provided check name is on the fixture-verified-only list
    (Phase 2 Path C low-confidence checks).
#>
function Test-SOC2IsLowConfidenceCheck {
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$CheckName)

    if (-not $CheckName) { return $false }
    return ($script:LowConfidenceCheckNames -contains $CheckName)
}

#endregion

#region ==================== HTML REPORT ====================

function New-SOC2AuditReport {
    <#
    .SYNOPSIS
        Renders the SOC 2 standalone HTML audit report.

    .DESCRIPTION
        Produces a TSC-structured report including: cover panel, by-category
        summary, control register, per-control finding tables, manual
        attestation register, evidence summary. Supports white-label branding
        via Get-ReportBrandingContext and an optional identity-lookup side panel
        that loads the resolution map from a sibling local path (data is NOT
        embedded into the HTML).

    .PARAMETER AssessmentResult
        The PSCustomObject returned by Invoke-SOC2Assessment.

    .PARAMETER OutputPath
        Where to write the .html file.

    .PARAMETER Branding
        Optional branding context from Get-ReportBrandingContext.

    .PARAMETER IdentityResolutionMapPath
        Optional local file path to the identity-resolution-*.json. When
        provided, the report exposes an "Identity lookup" side panel.

    .OUTPUTS
        String path to the rendered HTML file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$AssessmentResult,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [pscustomobject]$Branding,

        [string]$IdentityResolutionMapPath
    )

    if (-not $Branding) {
        if (Get-Command Get-ReportBrandingContext -ErrorAction SilentlyContinue) {
            $Branding = Get-ReportBrandingContext -Config $null -ReportTitle 'SOC 2 Internal Readiness Assessment'
        } else {
            $Branding = [pscustomobject]@{
                WhiteLabel = $false
                ReportTitle = 'SOC 2 Internal Readiness Assessment'
                OrganizationName = 'EntraChecks'
                LogoDataUri = ''
                PrimaryColor = '#005A9E'
                Footer = ''
                Attribution = "Generated by EntraChecks v$($script:ModuleVersion)"
                SuppressEntraChecksBranding = $false
            }
        }
    }

    $catalog = $AssessmentResult.Catalog
    $summary = $AssessmentResult.Summary
    $evidence = $AssessmentResult.Evidence
    # §11.1 — per-control manual attestation state (may be absent on older
    # assessment results; Get-SOC2ManualAttestationRows tolerates $null).
    $attestationState = $null
    if ($AssessmentResult.PSObject.Properties['AttestationState']) {
        $attestationState = $AssessmentResult.AttestationState
    }

    # Ensure System.Web is loaded before HtmlEncode is called below.
    # In production (.NET Framework PowerShell 5.1) this is a no-op when the
    # assembly is already loaded; in Pester's clean runspace it's required.
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $primaryColor = $Branding.PrimaryColor
    $orgName = $Branding.OrganizationName
    $title = $Branding.ReportTitle
    $logoHtml = if ($Branding.LogoDataUri) {
        "<img src='$($Branding.LogoDataUri)' alt='Logo' class='org-logo' />"
    } else { '' }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en">')
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine("<meta charset='UTF-8'>")
    [void]$sb.AppendLine("<title>$([System.Web.HttpUtility]::HtmlEncode($title))</title>")
    [void]$sb.AppendLine(@"
<style>
* { box-sizing: border-box; }
body { font-family: Segoe UI, Roboto, system-ui, sans-serif; margin: 0; color: #1a1a1a; background: #f4f6f8; }
header { background: $primaryColor; color: white; padding: 24px 32px; display: flex; align-items: center; gap: 16px; }
header .org-logo { max-height: 48px; max-width: 200px; background: white; padding: 4px; border-radius: 4px; }
header h1 { margin: 0; font-size: 1.6em; font-weight: 600; }
header .meta { margin-left: auto; text-align: right; font-size: 0.85em; opacity: 0.9; }
main { display: grid; grid-template-columns: 1fr 320px; gap: 24px; max-width: 1600px; margin: 0 auto; padding: 24px; }
section.report { background: white; border-radius: 6px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 24px; }
aside { position: sticky; top: 24px; align-self: start; }
aside .panel { background: white; border-radius: 6px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 16px; }
h2 { color: $primaryColor; border-bottom: 2px solid $primaryColor; padding-bottom: 8px; margin-top: 0; }
h3 { color: #333; margin-top: 24px; }
table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.9em; }
th { background: #f0f3f6; text-align: left; padding: 8px 12px; border-bottom: 2px solid #d0d5dc; }
td { padding: 8px 12px; border-bottom: 1px solid #e5e8ec; vertical-align: top; }
tr:hover { background: #fafbfc; }
.status-ok { color: #2a8c3c; font-weight: 600; }
.status-fail { color: #c8102e; font-weight: 600; }
.status-warning { color: #d89b00; font-weight: 600; }
.status-info { color: #5a6c7d; }
.status-manual { color: #5b3fa9; font-weight: 600; }
.status-licensing { color: #6a5fb3; font-weight: 600; }
.licensing-panel { background: #f3f0fb; border-left: 4px solid #6a5fb3; padding: 12px 16px; margin: 16px 0; border-radius: 4px; }
.licensing-panel .title { font-weight: 600; color: #6a5fb3; margin-bottom: 8px; }
.licensing-panel .breakdown { font-size: 0.9em; color: #555; }
.licensing-panel .breakdown span { display: inline-block; margin-right: 14px; }
.severity-Critical { background: #c8102e; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.severity-High { background: #ff6f00; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.severity-Medium { background: #d89b00; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.severity-Low { background: #4a90d9; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.severity-Info { background: #6c757d; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 16px 0; }
.summary-card { background: #f8f9fb; padding: 16px; border-left: 4px solid $primaryColor; border-radius: 4px; }
.summary-card .family { font-weight: 600; font-size: 1.1em; margin-bottom: 8px; }
.summary-card .row { font-size: 0.85em; color: #555; }
.tsc-control { background: #f8f9fb; border-left: 4px solid $primaryColor; padding: 12px 16px; margin-bottom: 16px; border-radius: 4px; }
.tsc-control .id { font-weight: 700; font-size: 1.1em; color: $primaryColor; }
.tsc-control .meta { font-size: 0.85em; color: #666; margin-top: 4px; }
.tsc-control .desc { margin-top: 8px; }
footer { background: #2a3441; color: #d0d5dc; text-align: center; padding: 16px; font-size: 0.85em; }
.lookup-input { width: 100%; padding: 8px; border: 1px solid #d0d5dc; border-radius: 4px; font-family: monospace; }
.lookup-result { background: #f0f3f6; padding: 8px; margin-top: 8px; border-radius: 4px; font-family: monospace; font-size: 0.85em; word-break: break-all; }
.lookup-warning { background: #fff8e1; padding: 8px; margin-top: 8px; border-radius: 4px; font-size: 0.85em; color: #7b5e00; }
.lookup-picker { display: none; margin-top: 8px; padding: 8px; background: #eef4fb; border: 1px dashed #5b8fb9; border-radius: 4px; font-size: 0.85em; }
.lookup-picker label { display: block; margin-bottom: 6px; color: #1c3d5a; }
.evidence-hash { font-family: monospace; font-size: 0.85em; word-break: break-all; }
/* Phase-3-followup reporting enhancements */
.badge { display: inline-block; padding: 2px 10px; border-radius: 3px; font-size: 0.85em; font-weight: 600; }
.badge-met { background: #2a8c3c; color: white; }
.badge-unmet { background: #c8102e; color: white; }
.badge-neutral { background: #5a6c7d; color: white; }
.exec-summary { background: linear-gradient(135deg, #f8f9fb 0%, #eef1f6 100%); border-radius: 6px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.exec-summary h2 { border-bottom: none; margin-top: 0; }
.exec-summary .verdict { font-size: 1.4em; font-weight: 700; margin: 8px 0 20px 0; }
.exec-summary .headline-row { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 16px; }
.exec-summary .headline-stat { background: white; padding: 10px 16px; border-radius: 4px; min-width: 120px; }
.exec-summary .headline-stat .label { font-size: 0.75em; color: #666; text-transform: uppercase; letter-spacing: 0.05em; }
.exec-summary .headline-stat .value { font-size: 1.6em; font-weight: 700; color: $primaryColor; }
.exec-summary .section-title { font-weight: 600; margin-top: 16px; margin-bottom: 8px; color: #333; }
.exec-summary .top-list { list-style: none; padding-left: 0; }
.exec-summary .top-list li { background: white; padding: 8px 12px; margin-bottom: 4px; border-left: 3px solid $primaryColor; border-radius: 3px; font-size: 0.9em; }
.exec-summary .top-list .tsc-id { font-weight: 700; color: $primaryColor; margin-right: 8px; }
.exec-summary .top-list .count-chip { background: #f0f3f6; padding: 1px 8px; border-radius: 10px; font-size: 0.8em; margin-left: 6px; }
.exec-summary .nav-links { margin-top: 12px; }
.exec-summary .nav-links a { display: inline-block; background: white; padding: 4px 10px; margin: 2px 4px 2px 0; border-radius: 3px; text-decoration: none; color: $primaryColor; font-size: 0.85em; border: 1px solid #d0d5dc; }
.exec-summary .nav-links a:hover { background: $primaryColor; color: white; }
.low-confidence-banner { background: #fff8e1; border-left: 6px solid #d89b00; padding: 12px 16px; margin: 16px 0; border-radius: 4px; font-size: 0.9em; }
.low-confidence-banner strong { color: #7b5e00; }
.low-confidence-tag { display: inline-block; background: #fff8e1; color: #7b5e00; padding: 1px 6px; border-radius: 3px; font-size: 0.75em; margin-left: 6px; }
.summary-card a.family-link { color: inherit; text-decoration: none; }
.summary-card a.family-link:hover .family { text-decoration: underline; }
.integrity-icon { display: inline-block; vertical-align: middle; margin-right: 4px; }
/* SOC 2 Audit-Readiness Plan PR 1 — Control Conclusion Register */
.conclusion-counts { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0 18px; }
.conclusion-chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 12px; font-size: 0.82em; background: #eef1f5; color: #1a1a1a; border: 1px solid #d6dce5; }
.conclusion-chip .count { font-weight: 700; }
.conclusion-chip.state-ConsistentlyPassing { background: #e6f4ea; color: #1f6f3a; border-color: #b9dec5; }
.conclusion-chip.state-Inconsistent { background: #fde7e9; color: #8b1a23; border-color: #f3b7bd; }
.conclusion-chip.state-DegradedButOperating { background: #fff4ce; color: #7b5e00; border-color: #e8d791; }
.conclusion-chip.state-Manual { background: #ede4f5; color: #5c2d91; border-color: #c8b3e0; }
.conclusion-chip.state-Licensing { background: #f3f0fb; color: #6a5fb3; border-color: #cfc6ec; }
.conclusion-chip.state-AcceptedRisk { background: #fcefe1; color: #8a4b00; border-color: #e9cba2; }
.conclusion-chip.state-Info { background: #deecf9; color: #1d4d7f; border-color: #b8d3eb; }
.conclusion-chip.state-Unobserved { background: #e8eaee; color: #555; border-color: #c9ced4; }
table.conclusion-register { width: 100%; border-collapse: collapse; font-size: 0.9em; }
table.conclusion-register th { background: #f0f3f6; text-align: left; padding: 8px 10px; border-bottom: 2px solid #d0d5dc; }
table.conclusion-register td { padding: 8px 10px; border-bottom: 1px solid #e5e8ec; vertical-align: top; }
table.conclusion-register tr.row-deficiency td { background: #fdf2f3; }
table.conclusion-register tr.row-deficiency-minor td { background: #fffaf0; }
table.conclusion-register tr.row-manual td { background: #f6f1fb; }
table.conclusion-register tr.row-licensing td { background: #f5f2fa; }
table.conclusion-register tr.row-accepted-risk td { background: #fff5e8; }
table.conclusion-register tr.row-effective td { background: #f1f9f3; }
table.conclusion-register tr.row-no-evidence td { background: #f4f5f7; color: #555; }
table.conclusion-register tr.row-info td { color: #1a1a1a; }
table.conclusion-register tr:hover td { filter: brightness(0.97); }
table.conclusion-register a { color: inherit; }
/* PR 2 — Remediation Plan */
table.remediation-plan { width: 100%; border-collapse: collapse; font-size: 0.88em; }
table.remediation-plan th { background: #f0f3f6; text-align: left; padding: 8px 10px; border-bottom: 2px solid #d0d5dc; }
table.remediation-plan td { padding: 8px 10px; border-bottom: 1px solid #e5e8ec; vertical-align: top; }
table.remediation-plan tr.prio-1 td { background: #fdf2f3; }
table.remediation-plan tr.prio-2 td { background: #fff6ec; }
table.remediation-plan tr.prio-3 td { background: #f6f1fb; }
table.remediation-plan tr.prio-4 td { background: #f5f2fa; }
table.remediation-plan tr.prio-5 td { background: #f4f5f7; color: #555; }
table.remediation-plan tr:hover td { filter: brightness(0.97); }
table.remediation-plan a { color: inherit; }
.prio-badge { display: inline-block; min-width: 1.4em; text-align: center; padding: 2px 7px; border-radius: 10px; font-weight: 700; font-size: 0.85em; color: #fff; }
.prio-badge.prio-1 { background: #c8102e; }
.prio-badge.prio-2 { background: #e8893a; }
.prio-badge.prio-3 { background: #5c2d91; }
.prio-badge.prio-4 { background: #6a5fb3; }
.prio-badge.prio-5 { background: #6c757d; }
/* PR 3 — Evidence Matrix */
.em-filters { display: flex; flex-wrap: wrap; gap: 14px; margin: 12px 0 16px; font-size: 0.85em; }
.em-filters label { display: flex; align-items: center; gap: 6px; color: #555; }
.em-filters select { padding: 4px 8px; border: 1px solid #d0d5dc; border-radius: 4px; font-size: 0.95em; }
table.evidence-matrix { width: 100%; border-collapse: collapse; font-size: 0.85em; }
table.evidence-matrix th { background: #f0f3f6; text-align: left; padding: 8px 10px; border-bottom: 2px solid #d0d5dc; }
table.evidence-matrix td { padding: 7px 10px; border-bottom: 1px solid #e5e8ec; vertical-align: top; }
table.evidence-matrix td.evidence-hash { font-family: monospace; font-size: 0.78em; word-break: break-all; color: #555; }
table.evidence-matrix tr:hover td { background: #fafbfc; }
table.evidence-matrix a { color: inherit; }
.fresh-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; font-weight: 600; }
.fresh-badge.fresh-fresh { background: #dff6dd; color: #1f6f3a; }
.fresh-badge.fresh-aging { background: #fff4ce; color: #7b5e00; }
.fresh-badge.fresh-stale { background: #fde7e9; color: #8b1a23; }
.fresh-badge.fresh-unknown { background: #e8eaee; color: #555; }
/* §11.1 — Manual Attestation Register */
table.manual-attestation { width: 100%; border-collapse: collapse; font-size: 0.85em; }
table.manual-attestation th { background: #f0f3f6; text-align: left; padding: 8px 10px; border-bottom: 2px solid #d0d5dc; }
table.manual-attestation td { padding: 7px 10px; border-bottom: 1px solid #e5e8ec; vertical-align: top; }
table.manual-attestation tr:hover td { background: #fafbfc; }
table.manual-attestation a { color: inherit; }
.att-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; font-weight: 600; }
.att-badge.att-notstarted { background: #e8eaee; color: #555; }
.att-badge.att-requested { background: #deecf9; color: #1d4d7f; }
.att-badge.att-received { background: #e3f0fb; color: #16527e; }
.att-badge.att-reviewed { background: #fff4ce; color: #7b5e00; }
.att-badge.att-accepted { background: #dff6dd; color: #1f6f3a; }
.att-badge.att-rejected { background: #fde7e9; color: #8b1a23; }
/* Print stylesheet */
@media print {
    body { background: white; }
    aside { display: none; }
    main { display: block; max-width: none; padding: 0; }
    header { break-inside: avoid; }
    section.report, .exec-summary { break-inside: avoid; page-break-inside: avoid; box-shadow: none; border: 1px solid #d0d5dc; }
    .tsc-control { break-inside: avoid; page-break-inside: avoid; }
    .low-confidence-banner { break-inside: avoid; }
    * { -webkit-print-color-adjust: exact !important; color-adjust: exact !important; print-color-adjust: exact !important; }
    .exec-summary .nav-links { display: none; }
    .em-filters { display: none; }
    a[href^="#"] { text-decoration: none; color: inherit; }
}
</style>
"@)
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body>')

    # Header
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine($logoHtml)
    [void]$sb.AppendLine("<h1>$([System.Web.HttpUtility]::HtmlEncode($title))</h1>")
    [void]$sb.AppendLine("<div class='meta'>")
    [void]$sb.AppendLine("<div>$([System.Web.HttpUtility]::HtmlEncode($orgName))</div>")
    [void]$sb.AppendLine("<div>Generated $((Get-Date).ToString('u'))</div>")
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</header>')

    [void]$sb.AppendLine('<main>')
    [void]$sb.AppendLine('<div>')

    # Executive summary (reporting-enhancements PR) — pinned at the top for
    # a one-page readiness view before the reader scrolls into detail.
    $digest = Get-SOC2ExecutiveDigest -Catalog $catalog -Summary $summary -EvidenceBundle $evidence
    [void]$sb.AppendLine('<section class="exec-summary">')
    [void]$sb.AppendLine('<h2>Executive Summary</h2>')
    [void]$sb.AppendLine("<div class='verdict'><span class='$($digest.VerdictClass)'>Internal readiness: $($digest.Verdict)</span></div>")
    [void]$sb.AppendLine('<div class="headline-row">')
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Controls</div><div class='value'>$($digest.TotalControls)</div></div>")
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Passing</div><div class='value'>$($digest.TotalPass)</div></div>")
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Failing</div><div class='value'>$($digest.TotalFail)</div></div>")
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Warnings</div><div class='value'>$($digest.TotalWarning)</div></div>")
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Licensing gaps</div><div class='value'>$($digest.LicensingGapsTotal)</div></div>")
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Total findings</div><div class='value'>$($digest.TotalFindings)</div></div>")
    [void]$sb.AppendLine('</div>')

    if ($digest.TopFailingTscs.Count -gt 0) {
        [void]$sb.AppendLine("<div class='section-title'>Top gaps to address</div>")
        [void]$sb.AppendLine("<ul class='top-list'>")
        foreach ($top in $digest.TopFailingTscs) {
            $encDesc = [System.Web.HttpUtility]::HtmlEncode($top.Description)
            [void]$sb.AppendLine("<li><span class='tsc-id'>$($top.ControlId)</span> ($($top.Family)) - $encDesc <span class='count-chip'>$($top.FailCount) issue(s)</span></li>")
        }
        [void]$sb.AppendLine('</ul>')
    }

    if ($digest.TopLicensingGaps.Count -gt 0) {
        [void]$sb.AppendLine("<div class='section-title'>Top licensing gaps</div>")
        [void]$sb.AppendLine("<ul class='top-list'>")
        foreach ($gap in $digest.TopLicensingGaps) {
            [void]$sb.AppendLine("<li><span class='tsc-id'>$($gap.Feature)</span> <span class='count-chip'>$($gap.Count) TSC(s) affected</span></li>")
        }
        [void]$sb.AppendLine('</ul>')
    }

    # Quick-nav links to per-family detail
    [void]$sb.AppendLine("<div class='section-title'>Jump to</div>")
    [void]$sb.AppendLine("<div class='nav-links'>")
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $hasControls = @($catalog | Where-Object { $_.Family -eq $family }).Count -gt 0
        if ($hasControls) {
            [void]$sb.AppendLine("<a href='#family-$family'>$family</a>")
        }
    }
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</section>')

    # Low-confidence check banner (reporting-enhancements PR) — fires only
    # when at least one fixture-verified-only check surfaces in the findings.
    $lowConfidenceFound = $false
    foreach ($controlId in $summary.ControlFindings.Keys) {
        $findingsForControl = @($summary.ControlFindings[$controlId])
        foreach ($finding in $findingsForControl) {
            if (Test-SOC2IsLowConfidenceCheck -CheckName $finding.CheckName) {
                $lowConfidenceFound = $true
                break
            }
        }
        if ($lowConfidenceFound) { break }
    }
    if ($lowConfidenceFound) {
        [void]$sb.AppendLine('<div class="low-confidence-banner">')
        [void]$sb.AppendLine('<strong>Verification note:</strong> This report includes results from checks that ship <em>fixture-verified only</em> (<code>Test-SOC2DiagnosticSettingsExport</code>, <code>Test-SOC2BreakGlassAccountsConfigured</code>). Spot-check these against your live tenant before relying on the output for audit evidence. See <code>docs/SOC2-Guide.md</code> SS11 for the per-check confidence table.')
        [void]$sb.AppendLine('</div>')
    }

    # Cover panel
    [void]$sb.AppendLine('<section class="report">')
    [void]$sb.AppendLine('<h2>Assessment Cover</h2>')
    $integrityBadgeCover = if ($evidence) { "<span class='badge badge-met'>&check; Integrity-verifiable</span>" } else { "<span class='badge badge-neutral'>No bundle</span>" }
    [void]$sb.AppendLine('<table>')
    [void]$sb.AppendLine("<tr><th>TSC Revision</th><td>AICPA TSC 2017 (revised 2022)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Type</th><td>Type 1 (point-in-time)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Categories in scope</th><td>$(($catalog | Select-Object -ExpandProperty Family -Unique) -join ', ')</td></tr>")
    [void]$sb.AppendLine("<tr><th>Total controls</th><td>$($summary.TotalControls)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Total findings</th><td>$($summary.TotalFindings)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Evidence integrity</th><td>$integrityBadgeCover</td></tr>")
    if ($evidence) {
        [void]$sb.AppendLine("<tr><th>Evidence bundle hash (SHA-256)</th><td class='evidence-hash'>$($evidence.BundleHash)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Evidence bundle path</th><td>$([System.Web.HttpUtility]::HtmlEncode($evidence.Directory))</td></tr>")
    }
    [void]$sb.AppendLine('</table>')
    [void]$sb.AppendLine('</section>')

    # Summary grid by family
    [void]$sb.AppendLine('<section class="report">')
    [void]$sb.AppendLine('<h2>Summary by Trust Services Category</h2>')
    [void]$sb.AppendLine('<div class="summary-grid">')
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $f = $summary.ByFamily[$family]
        if (-not $f) { continue }
        $totalControls = $f.Automated + $f.Manual
        if ($totalControls -eq 0) { continue }
        $licensingGapCount = if ($null -ne $f.LicensingGaps) { $f.LicensingGaps } else { 0 }
        [void]$sb.AppendLine('<div class="summary-card">')
        [void]$sb.AppendLine("<a class='family-link' href='#family-$family'><div class='family'>$family</div></a>")
        [void]$sb.AppendLine("<div class='row'>Controls: $totalControls (auto: $($f.Automated), manual: $($f.Manual))</div>")
        [void]$sb.AppendLine("<div class='row'><span class='status-ok'>Pass: $($f.Pass)</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='status-fail'>Fail: $($f.Fail)</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='status-warning'>Warn: $($f.Warning)</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='status-info'>Info: $($f.Info)</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='status-licensing'>Not Assessed (Licensing): $licensingGapCount</span></div>")
        [void]$sb.AppendLine('</div>')
    }
    [void]$sb.AppendLine('</div>')

    # Phase 3 PR 3: Global licensing-gap callout panel
    if ($summary.PSObject.Properties['LicensingGaps'] -and $summary.LicensingGaps -and $summary.LicensingGaps.Total -gt 0) {
        [void]$sb.AppendLine('<div class="licensing-panel">')
        [void]$sb.AppendLine("<div class='title'>Licensing gaps: $($summary.LicensingGaps.Total) control(s) not assessed due to missing licensing</div>")
        $byFeatureBits = [System.Collections.Generic.List[string]]::new()
        foreach ($feature in @('IdentityProtection', 'Intune', 'PurviewE5', 'DefenderForCloud', 'DefenderForEndpoint', 'Priva')) {
            $count = $summary.LicensingGaps.ByFeature[$feature]
            if ($count -gt 0) {
                $byFeatureBits.Add("<span><strong>${feature}:</strong> $count</span>") | Out-Null
            }
        }
        if ($byFeatureBits.Count -gt 0) {
            [void]$sb.AppendLine("<div class='breakdown'>$([string]::Join(' ', $byFeatureBits.ToArray()))</div>")
        }
        [void]$sb.AppendLine('<div class="breakdown" style="margin-top:6px;font-size:0.85em;">If a feature should be in scope, set its override in <code>SOC2.AzureReadiness.Licensing.Overrides</code> to escalate from INFO to WARNING/FAIL.</div>')
        [void]$sb.AppendLine('</div>')
    }

    [void]$sb.AppendLine('</section>')

    # SOC 2 Audit-Readiness Plan PR 1 §8.3 — Control Conclusion Register.
    # The auditor-facing headline view: one row per control, with the
    # precedence-derived Conclusion, Owner, Due Date, and Exception Status.
    # The per-family TSC sections below are the legacy detail view; they
    # stay for one release behind data-soc2-legacy-findings="true" so
    # consumers can transition. Plan §14 rollout step 1.
    # Direct assignment (not @(...) around the call): the helper returns a
    # comma-wrapped array (file convention, see Get-SOC2SummaryByCategoryRows).
    # @() applied straight to that pipeline output double-wraps it; an
    # intermediate assignment unwraps cleanly first.
    if ($digest.PSObject.Properties['ConclusionRegister'] -and $digest.ConclusionRegister) {
        $registerRows = $digest.ConclusionRegister
    } else {
        $registerRows = Get-SOC2ControlConclusionRegister -Catalog $catalog -Summary $summary -EvidenceBundle $evidence
    }
    $registerRows = @($registerRows)
    if ($registerRows.Count -gt 0) {
        [void]$sb.AppendLine('<section class="report" id="control-conclusion-register">')
        [void]$sb.AppendLine('<h2>Control Conclusion Register</h2>')
        [void]$sb.AppendLine('<p style="color:#555;font-size:0.9em;margin:8px 0 16px;">One row per SOC 2 control. The <em>Conclusion</em> column is derived from the precedence rules in <code>plans/SOC2-Audit-Readiness-Plan.md</code> &sect;7: a single high-severity FAIL drives a Deficiency; warnings drive Deficiency&nbsp;-&nbsp;Minor; accepted-risk findings override deficiency conclusions; manual controls remain Pending until attested.</p>')
        # Conclusion counts strip — quick visual triage for leadership.
        $counts = $digest.ControlConclusions
        if ($counts) {
            [void]$sb.AppendLine('<div class="conclusion-counts">')
            foreach ($pair in @(
                    @{ Label = 'Deficiency'; Key = 'Deficiency'; Class = 'state-Inconsistent' }
                    @{ Label = 'Deficiency - Minor'; Key = 'Deficiency - Minor'; Class = 'state-DegradedButOperating' }
                    @{ Label = 'Manual Pending'; Key = 'Manual Pending'; Class = 'state-Manual' }
                    @{ Label = 'Not Assessed - Licensing'; Key = 'Not Assessed - Licensing'; Class = 'state-Licensing' }
                    @{ Label = 'Accepted Risk'; Key = 'Accepted Risk'; Class = 'state-AcceptedRisk' }
                    @{ Label = 'Informational'; Key = 'Informational'; Class = 'state-Info' }
                    @{ Label = 'Effective'; Key = 'Effective'; Class = 'state-ConsistentlyPassing' }
                    @{ Label = 'No Evidence'; Key = 'Not Assessed - No Evidence'; Class = 'state-Unobserved' }
                )) {
                $n = if ($counts.ContainsKey($pair.Key)) { [int]$counts[$pair.Key] } else { 0 }
                [void]$sb.AppendLine("<span class='conclusion-chip $($pair.Class)'><span class='count'>$n</span> $($pair.Label)</span>")
            }
            [void]$sb.AppendLine('</div>')
        }
        [void]$sb.AppendLine('<table class="conclusion-register">')
        [void]$sb.AppendLine('<thead><tr><th>Control</th><th>Family</th><th>Conclusion</th><th>Severity</th><th>Findings</th><th>Evidence</th><th>Owner</th><th>Due</th><th>Exception</th><th>Description</th></tr></thead>')
        [void]$sb.AppendLine('<tbody>')
        foreach ($r in $registerRows) {
            $cssClass = switch ($r.Conclusion) {
                'Deficiency' { 'row-deficiency' }
                'Deficiency - Minor' { 'row-deficiency-minor' }
                'Manual Pending' { 'row-manual' }
                'Not Assessed - Licensing' { 'row-licensing' }
                'Accepted Risk' { 'row-accepted-risk' }
                'Informational' { 'row-info' }
                'Effective' { 'row-effective' }
                'Not Assessed - No Evidence' { 'row-no-evidence' }
                default { '' }
            }
            $controlId = [System.Web.HttpUtility]::HtmlEncode([string]$r.ControlId)
            $family = [System.Web.HttpUtility]::HtmlEncode([string]$r.TscFamily)
            $conclusion = [System.Web.HttpUtility]::HtmlEncode([string]$r.Conclusion)
            $severity = [System.Web.HttpUtility]::HtmlEncode([string]$r.DeficiencySeverity)
            $owner = [System.Web.HttpUtility]::HtmlEncode([string]$r.Owner)
            $due = [System.Web.HttpUtility]::HtmlEncode([string]$r.DueDate)
            $exceptionStatus = [System.Web.HttpUtility]::HtmlEncode([string]$r.ExceptionStatus)
            $desc = [System.Web.HttpUtility]::HtmlEncode([string]$r.ControlDescription)
            [void]$sb.AppendLine("<tr class='$cssClass'><td><a href='#family-$family'>$controlId</a></td><td>$family</td><td>$conclusion</td><td>$severity</td><td>$($r.FindingCount)</td><td>$($r.EvidenceCount)</td><td>$owner</td><td>$due</td><td>$exceptionStatus</td><td>$desc</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
        [void]$sb.AppendLine('</section>')
    }

    # SOC 2 Audit-Readiness Plan PR 2 §9.2 — Remediation Plan. The
    # actionable subset of the register, prioritised. Renders after the
    # Control Conclusion Register, before the legacy per-family TSC
    # sections. Empty (everything Effective/Accepted Risk) → section omitted.
    $remediationRows = Get-SOC2RemediationPlan -Register $registerRows
    $remediationRows = @($remediationRows)
    if ($remediationRows.Count -gt 0) {
        [void]$sb.AppendLine('<section class="report" id="remediation-plan">')
        [void]$sb.AppendLine('<h2>Remediation Plan</h2>')
        [void]$sb.AppendLine('<p style="color:#555;font-size:0.9em;margin:8px 0 16px;">Every control with an open gap, ordered by priority (1&nbsp;=&nbsp;most urgent). Effective and Accepted-Risk controls are excluded. Priority: <strong>1</strong> Critical/High deficiency, <strong>2</strong> minor deficiency, <strong>3</strong> manual attestation pending, <strong>4</strong> not assessed (licensing), <strong>5</strong> not assessed (no evidence).</p>')
        [void]$sb.AppendLine('<table class="remediation-plan">')
        [void]$sb.AppendLine('<thead><tr><th>Priority</th><th>Control</th><th>Family</th><th>Gap</th><th>Owner</th><th>Due</th><th>Remediation</th><th>Validation</th><th>Evidence Needed</th></tr></thead>')
        [void]$sb.AppendLine('<tbody>')
        foreach ($rp in $remediationRows) {
            $pCss = "prio-$([int]$rp.Priority)"
            $cId = [System.Web.HttpUtility]::HtmlEncode([string]$rp.ControlId)
            $fam = [System.Web.HttpUtility]::HtmlEncode([string]$rp.TscFamily)
            $gap = [System.Web.HttpUtility]::HtmlEncode([string]$rp.Gap)
            $own = [System.Web.HttpUtility]::HtmlEncode([string]$rp.Owner)
            $due = [System.Web.HttpUtility]::HtmlEncode([string]$rp.DueDate)
            $rem = [System.Web.HttpUtility]::HtmlEncode([string]$rp.Remediation)
            $val = [System.Web.HttpUtility]::HtmlEncode([string]$rp.ValidationSteps)
            $evn = [System.Web.HttpUtility]::HtmlEncode([string]$rp.EvidenceNeeded)
            [void]$sb.AppendLine("<tr class='$pCss'><td><span class='prio-badge $pCss'>$([int]$rp.Priority)</span></td><td><a href='#family-$fam'>$cId</a></td><td>$fam</td><td>$gap</td><td>$own</td><td>$due</td><td>$rem</td><td>$val</td><td>$evn</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
        [void]$sb.AppendLine('</section>')
    }

    # SOC 2 Audit-Readiness Plan PR 3 §10.2 — Evidence Matrix. Per-artifact
    # rows pivoted from the bundle manifest, after the Remediation Plan and
    # before the legacy per-family TSC sections. Filters (TscFamily /
    # Freshness / RedactionStatus) use a small self-contained inline script
    # scoped to this section — the SOC 2 report is otherwise static and
    # importing the whole cockpit JS module would couple the two reports.
    $evidenceMatrixRows = Get-SOC2EvidenceMatrix -EvidenceBundle $evidence -ControlCatalog $catalog -IdentityMapPath $IdentityResolutionMapPath
    $evidenceMatrixRows = @($evidenceMatrixRows)
    if ($evidenceMatrixRows.Count -gt 0) {
        $emFamilies = @($evidenceMatrixRows | ForEach-Object { $_.TscFamily } | Where-Object { $_ } | Sort-Object -Unique)
        $emFresh = @($evidenceMatrixRows | ForEach-Object { $_.Freshness } | Sort-Object -Unique)
        $emRedaction = @($evidenceMatrixRows | ForEach-Object { $_.RedactionStatus } | Sort-Object -Unique)

        [void]$sb.AppendLine('<section class="report" id="evidence-matrix">')
        [void]$sb.AppendLine('<h2>Evidence Matrix</h2>')
        [void]$sb.AppendLine('<p style="color:#555;font-size:0.9em;margin:8px 0 16px;">Every evidence artifact in the bundle, pivoted to its control. <strong>Freshness</strong> is artifact age at render time: Fresh&nbsp;&lt;&nbsp;30d, Aging&nbsp;30&ndash;90d, Stale&nbsp;&ge;&nbsp;90d. Each artifact is hash-verifiable via the manifest.</p>')

        # Filter controls (plain selects + tiny scoped JS).
        [void]$sb.AppendLine('<div class="em-filters">')
        $famOpts = ($emFamilies | ForEach-Object { "<option value='$([System.Web.HttpUtility]::HtmlEncode($_))'>$([System.Web.HttpUtility]::HtmlEncode($_))</option>" }) -join ''
        $freshOpts = ($emFresh | ForEach-Object { "<option value='$([System.Web.HttpUtility]::HtmlEncode($_))'>$([System.Web.HttpUtility]::HtmlEncode($_))</option>" }) -join ''
        $redOpts = ($emRedaction | ForEach-Object { "<option value='$([System.Web.HttpUtility]::HtmlEncode($_))'>$([System.Web.HttpUtility]::HtmlEncode($_))</option>" }) -join ''
        [void]$sb.AppendLine("<label>Family <select data-em-filter='fam'><option value=''>All</option>$famOpts</select></label>")
        [void]$sb.AppendLine("<label>Freshness <select data-em-filter='fresh'><option value=''>All</option>$freshOpts</select></label>")
        [void]$sb.AppendLine("<label>Redaction <select data-em-filter='red'><option value=''>All</option>$redOpts</select></label>")
        [void]$sb.AppendLine('</div>')

        [void]$sb.AppendLine('<table class="evidence-matrix" id="evidence-matrix-table">')
        [void]$sb.AppendLine('<thead><tr><th>Control</th><th>Family</th><th>Evidence Artifact</th><th>Source</th><th>Collected</th><th>Freshness</th><th>Redaction</th><th>SHA-256</th></tr></thead>')
        [void]$sb.AppendLine('<tbody>')
        foreach ($em in $evidenceMatrixRows) {
            $fresh = [string]$em.Freshness
            $freshCss = "fresh-$($fresh.ToLowerInvariant())"
            $cId = [System.Web.HttpUtility]::HtmlEncode([string]$em.ControlId)
            $fam = [System.Web.HttpUtility]::HtmlEncode([string]$em.TscFamily)
            $art = [System.Web.HttpUtility]::HtmlEncode([string]$em.EvidenceArtifact)
            $src = [System.Web.HttpUtility]::HtmlEncode([string]$em.Source)
            $col = [System.Web.HttpUtility]::HtmlEncode([string]$em.CollectionTime)
            $red = [System.Web.HttpUtility]::HtmlEncode([string]$em.RedactionStatus)
            $hsh = [System.Web.HttpUtility]::HtmlEncode([string]$em.Hash)
            $anchor = [System.Web.HttpUtility]::HtmlEncode([string]$em.AnchorId)
            $famAttr = [System.Web.HttpUtility]::HtmlEncode([string]$em.TscFamily)
            $freshAttr = [System.Web.HttpUtility]::HtmlEncode($fresh)
            $redAttr = [System.Web.HttpUtility]::HtmlEncode([string]$em.RedactionStatus)
            [void]$sb.AppendLine("<tr id='$anchor' class='$freshCss' data-em-fam='$famAttr' data-em-fresh='$freshAttr' data-em-red='$redAttr'><td><a href='#family-$fam'>$cId</a></td><td>$fam</td><td>$art</td><td>$src</td><td>$col</td><td><span class='fresh-badge $freshCss'>$([System.Web.HttpUtility]::HtmlEncode($fresh))</span></td><td>$red</td><td class='evidence-hash'>$hsh</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
        [void]$sb.AppendLine(@'
<script>
(function () {
  var sect = document.getElementById('evidence-matrix');
  if (!sect) { return; }
  var selects = sect.querySelectorAll('select[data-em-filter]');
  var rows = sect.querySelectorAll('#evidence-matrix-table tbody tr');
  function apply() {
    var fam = '', fresh = '', red = '';
    selects.forEach(function (s) {
      var k = s.getAttribute('data-em-filter');
      if (k === 'fam') { fam = s.value; }
      else if (k === 'fresh') { fresh = s.value; }
      else if (k === 'red') { red = s.value; }
    });
    rows.forEach(function (r) {
      var ok = (!fam || r.getAttribute('data-em-fam') === fam) &&
               (!fresh || r.getAttribute('data-em-fresh') === fresh) &&
               (!red || r.getAttribute('data-em-red') === red);
      r.style.display = ok ? '' : 'none';
    });
  }
  selects.forEach(function (s) { s.addEventListener('change', apply); });
})();
</script>
'@)
        [void]$sb.AppendLine('</section>')
    }

    # §11.1 Manual Attestation Register — tracked lifecycle for manual
    # controls (NotStarted → Requested → Received → Reviewed →
    # Accepted/Rejected). Rendered after the Evidence Matrix, before the
    # legacy per-family TSC sections. Omitted when the catalog has no
    # manual controls in scope.
    $manualAttRows = Get-SOC2ManualAttestationRows -Catalog $catalog -AttestationState $attestationState
    $manualAttRows = @($manualAttRows)
    if ($manualAttRows.Count -gt 0) {
        [void]$sb.AppendLine('<section class="report" id="manual-attestation-register">')
        [void]$sb.AppendLine('<h2>Manual Attestation Register</h2>')
        [void]$sb.AppendLine('<p style="color:#555;font-size:0.9em;margin:8px 0 16px;">Controls that cannot be observed via Graph/Azure. Each is tracked through <strong>NotStarted &rarr; Requested &rarr; Received &rarr; Reviewed &rarr; Accepted</strong> (or Rejected). Non-accepted controls also surface in the analyst cockpit&rsquo;s Review Queue. State is held in a local, gitignored file (config <code>SOC2.AttestationStatePath</code>).</p>')
        [void]$sb.AppendLine('<table class="manual-attestation">')
        [void]$sb.AppendLine('<thead><tr><th>Control</th><th>Family</th><th>State</th><th>Owner</th><th>Requested</th><th>Received</th><th>Evidence Location</th><th>Reviewer</th><th>Next Review</th><th>Notes</th></tr></thead>')
        [void]$sb.AppendLine('<tbody>')
        foreach ($ma in $manualAttRows) {
            $st = [string]$ma.State
            $stCss = "att-$($st.ToLowerInvariant())"
            $cId = [System.Web.HttpUtility]::HtmlEncode([string]$ma.ControlId)
            $fam = [System.Web.HttpUtility]::HtmlEncode([string]$ma.Family)
            $own = [System.Web.HttpUtility]::HtmlEncode([string]$ma.ControlOwner)
            $req = [System.Web.HttpUtility]::HtmlEncode([string]$ma.RequestedDate)
            $rcv = [System.Web.HttpUtility]::HtmlEncode([string]$ma.ReceivedDate)
            $evl = [System.Web.HttpUtility]::HtmlEncode([string]$ma.EvidenceLocation)
            $rev = [System.Web.HttpUtility]::HtmlEncode([string]$ma.Reviewer)
            $nxt = [System.Web.HttpUtility]::HtmlEncode([string]$ma.NextReviewDate)
            $nts = [System.Web.HttpUtility]::HtmlEncode([string]$ma.Notes)
            [void]$sb.AppendLine("<tr class='$stCss'><td><a href='#family-$fam'>$cId</a></td><td>$fam</td><td><span class='att-badge $stCss'>$([System.Web.HttpUtility]::HtmlEncode($st))</span></td><td>$own</td><td>$req</td><td>$rcv</td><td>$evl</td><td>$rev</td><td>$nxt</td><td>$nts</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
        [void]$sb.AppendLine('</section>')
    }

    # Control register grouped by family (anchor IDs wired for quick-nav links)
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $controlsInFamily = @($catalog | Where-Object { $_.Family -eq $family })
        if ($controlsInFamily.Count -eq 0) { continue }

        [void]$sb.AppendLine("<section class='report' id='family-$family'>")
        $familyName = ($controlsInFamily | Select-Object -First 1 -ExpandProperty FamilyName)
        [void]$sb.AppendLine("<h2>$family - $([System.Web.HttpUtility]::HtmlEncode($familyName))</h2>")

        foreach ($control in $controlsInFamily) {
            $controlFindings = @()
            if ($summary.ControlFindings.ContainsKey($control.Id)) {
                $controlFindings = @($summary.ControlFindings[$control.Id])
            }

            [void]$sb.AppendLine('<div class="tsc-control">')
            [void]$sb.AppendLine("<div class='id'>$($control.Id)</div>")
            [void]$sb.AppendLine("<div class='meta'>Automation: $($control.Automation) | Owner hint: $([System.Web.HttpUtility]::HtmlEncode($control.ControlOwnerHint)) | Findings: $($controlFindings.Count)</div>")
            [void]$sb.AppendLine("<div class='desc'>$([System.Web.HttpUtility]::HtmlEncode($control.Description))</div>")

            if ($controlFindings.Count -gt 0) {
                [void]$sb.AppendLine('<table>')
                [void]$sb.AppendLine('<thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Object</th><th>Description</th><th>Remediation</th></tr></thead>')
                [void]$sb.AppendLine('<tbody>')
                foreach ($finding in $controlFindings) {
                    $statusClass = "status-$(($finding.Status -as [string]).ToLower())"
                    $severity = if ($finding.PSObject.Properties['Severity']) { $finding.Severity } else { 'Info' }
                    $checkName = if ($finding.PSObject.Properties['CheckName']) { $finding.CheckName } else { '' }
                    $checkTag = ''
                    if (Test-SOC2IsLowConfidenceCheck -CheckName $checkName) {
                        $checkTag = " <span class='low-confidence-tag' title='Fixture-verified only; see SOC2-Guide §11'>fixture-verified</span>"
                    }
                    [void]$sb.AppendLine('<tr>')
                    [void]$sb.AppendLine("<td class='$statusClass'>$($finding.Status)</td>")
                    [void]$sb.AppendLine("<td><span class='severity-$severity'>$severity</span></td>")
                    [void]$sb.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($checkName))$checkTag</td>")
                    [void]$sb.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Object))</td>")
                    [void]$sb.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Description))</td>")
                    [void]$sb.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Remediation))</td>")
                    [void]$sb.AppendLine('</tr>')
                }
                [void]$sb.AppendLine('</tbody>')
                [void]$sb.AppendLine('</table>')
            }

            [void]$sb.AppendLine('</div>')
        }
        [void]$sb.AppendLine('</section>')
    }

    [void]$sb.AppendLine('</div>')

    # Side panel
    [void]$sb.AppendLine('<aside>')
    [void]$sb.AppendLine('<div class="panel">')
    [void]$sb.AppendLine('<h3>Identity lookup</h3>')
    if ($IdentityResolutionMapPath) {
        $escapedPath = $IdentityResolutionMapPath -replace '\\', '\\\\'
        [void]$sb.AppendLine("<p style='font-size: 0.85em; color: #555;'>Resolves redacted hashes shown in this report to UPNs. Lookup data is loaded locally from the resolution map at:</p>")
        [void]$sb.AppendLine("<p style='font-family: monospace; font-size: 0.75em; word-break: break-all;'>$([System.Web.HttpUtility]::HtmlEncode($IdentityResolutionMapPath))</p>")
        [void]$sb.AppendLine("<input type='text' id='lookup-input' class='lookup-input' placeholder='Paste hash prefix (12+ chars)' />")
        [void]$sb.AppendLine("<div id='lookup-result' class='lookup-result'>Awaiting input...</div>")
        [void]$sb.AppendLine("<div id='lookup-picker' class='lookup-picker'>")
        [void]$sb.AppendLine("<label for='lookup-file'>Select the resolution map JSON shown above. Data stays in your browser tab and is never written back to this file.</label>")
        [void]$sb.AppendLine("<input type='file' id='lookup-file' accept='application/json,.json' />")
        [void]$sb.AppendLine("</div>")
        [void]$sb.AppendLine(@"
<script>
(function () {
  let resolutionData = null;

  function setResult(text, warn) {
    const el = document.getElementById('lookup-result');
    el.className = warn ? 'lookup-warning' : 'lookup-result';
    el.textContent = text;
  }

  function showPicker(reason) {
    document.getElementById('lookup-picker').style.display = 'block';
    setResult(reason + ' Use the picker below to load the resolution map manually.', true);
  }

  function applyData(data, source) {
    resolutionData = data;
    const count = (data && data.Entries) ? data.Entries.length : 0;
    setResult('Loaded ' + count + ' entries' + (source ? ' (' + source + ')' : '') + '. Paste a hash prefix above.', false);
    document.getElementById('lookup-picker').style.display = 'none';
  }

  async function tryFetch() {
    try {
      const r = await fetch('$escapedPath');
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const data = await r.json();
      applyData(data, 'auto-loaded');
    } catch (e) {
      // file:// fetch is blocked by the browser; fall back to the picker.
      showPicker('Auto-load blocked by the browser when this report is opened from the file system.');
    }
  }

  function handlePick(evt) {
    const file = evt.target.files && evt.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function (e) {
      try {
        const data = JSON.parse(e.target.result);
        if (!data || !Array.isArray(data.Entries)) {
          throw new Error('JSON does not look like a resolution map (missing Entries array).');
        }
        applyData(data, 'picker: ' + file.name);
      } catch (err) {
        setResult('Could not parse selected file: ' + err.message, true);
      }
    };
    reader.onerror = function () {
      setResult('Could not read selected file.', true);
    };
    reader.readAsText(file);
  }

  function handleQuery(evt) {
    if (evt.target.id !== 'lookup-input') return;
    if (!resolutionData) {
      setResult('No resolution map loaded yet — load one first.', true);
      return;
    }
    const q = (evt.target.value || '').toLowerCase().trim();
    if (q.length < 8) {
      setResult('Type at least 8 hex chars...', false);
      return;
    }
    const matches = resolutionData.Entries.filter(function (x) { return x.Hash && x.Hash.toLowerCase().startsWith(q); });
    const el = document.getElementById('lookup-result');
    el.className = 'lookup-result';
    if (matches.length === 0) {
      el.textContent = 'No match.';
    } else {
      el.innerHTML = matches.slice(0, 5).map(function (m) {
        return 'Hash: ' + m.Hash.substring(0, 16) + '...<br>UPN: ' + (m.UPN || '(none)') + '<br>Display: ' + (m.DisplayName || '(none)');
      }).join('<hr>');
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('lookup-file').addEventListener('change', handlePick);
    tryFetch();
  });
  document.addEventListener('input', handleQuery);
})();
</script>
"@)
    } else {
        [void]$sb.AppendLine("<p style='font-size: 0.85em; color: #555;'>No identity-resolution map is associated with this report (redaction was not enabled, or no PII was redacted).</p>")
    }
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div class="panel">')
    [void]$sb.AppendLine('<h3>Evidence integrity &mdash; verifiable</h3>')
    if ($evidence) {
        # Inline checkmark SVG (hash-chain evocation — no external asset dependency)
        $integrityIcon = "<svg class='integrity-icon' xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 16 16' fill='#2a8c3c'><path d='M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z'/></svg>"
        [void]$sb.AppendLine("<p style='font-size: 0.85em;'>${integrityIcon}<span class='badge badge-met'>Integrity-verifiable</span></p>")
        [void]$sb.AppendLine("<p style='font-size: 0.85em;'>Bundle hash (SHA-256):</p>")
        [void]$sb.AppendLine("<p class='evidence-hash' style='font-size: 0.7em;'>$($evidence.BundleHash)</p>")
        [void]$sb.AppendLine("<p style='font-size: 0.8em;'>To verify: <code>Test-SOC2EvidenceBundle -ManifestPath '$($evidence.ManifestPath)'</code></p>")
    } else {
        [void]$sb.AppendLine("<p style='font-size: 0.85em;'><span class='badge badge-neutral'>No bundle</span></p>")
        [void]$sb.AppendLine("<p style='font-size: 0.85em; color: #555;'>No evidence bundle was produced for this run.</p>")
    }
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('</aside>')
    [void]$sb.AppendLine('</main>')

    [void]$sb.AppendLine('<footer>')
    if ($Branding.Footer) {
        [void]$sb.AppendLine([System.Web.HttpUtility]::HtmlEncode($Branding.Footer))
        [void]$sb.AppendLine('<br>')
    }
    if (-not $Branding.SuppressEntraChecksBranding) {
        [void]$sb.AppendLine($Branding.Attribution)
    }
    [void]$sb.AppendLine('</footer>')

    [void]$sb.AppendLine('</body>')
    [void]$sb.AppendLine('</html>')

    Set-Content -LiteralPath $OutputPath -Value $sb.ToString() -Encoding UTF8

    return $OutputPath
}

#endregion

#region ==================== EXCEL / CSV REPORT ====================

function New-SOC2AuditWorkbook {
    <#
    .SYNOPSIS
        Renders the SOC 2 audit workbook (Excel via ImportExcel if available,
        else multi-CSV fallback).

    .DESCRIPTION
        Sheets / files emitted:
        - Cover
        - Summary by Category
        - Control Register
        - Findings - CC6, CC7, CC8, Other CC, Availability (A), Confidentiality (C)
        - Manual Attestation Register
        - Evidence Register

    .PARAMETER AssessmentResult
        The PSCustomObject returned by Invoke-SOC2Assessment.

    .PARAMETER OutputPath
        Where to write the .xlsx (or CSV directory if ImportExcel is unavailable).

    .OUTPUTS
        String path to the workbook (or directory of CSVs).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$AssessmentResult,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $catalog = $AssessmentResult.Catalog
    $summary = $AssessmentResult.Summary
    $evidence = $AssessmentResult.Evidence
    $identityMapPath = if ($AssessmentResult.PSObject.Properties['IdentityMapPath']) { [string]$AssessmentResult.IdentityMapPath } else { '' }
    $attestationState = if ($AssessmentResult.PSObject.Properties['AttestationState']) { $AssessmentResult.AttestationState } else { $null }

    # Row sets built once via private helpers; consumed by both Excel and CSV branches.
    $coverRows = @(
        [pscustomobject]@{ Field = 'TSC Revision'; Value = 'AICPA TSC 2017 (revised 2022)' }
        [pscustomobject]@{ Field = 'Type'; Value = 'Type 1' }
        [pscustomobject]@{ Field = 'Generated (UTC)'; Value = (Get-Date).ToUniversalTime().ToString('u') }
        [pscustomobject]@{ Field = 'Categories'; Value = (($catalog | Select-Object -ExpandProperty Family -Unique) -join ', ') }
        [pscustomobject]@{ Field = 'Total Controls'; Value = $summary.TotalControls }
        [pscustomobject]@{ Field = 'Total Findings'; Value = $summary.TotalFindings }
        [pscustomobject]@{ Field = 'Bundle Hash (SHA-256)'; Value = if ($evidence) { $evidence.BundleHash } else { '' } }
        [pscustomobject]@{ Field = 'Bundle Path'; Value = if ($evidence) { $evidence.Directory } else { '' } }
    )
    $summaryRows = Get-SOC2SummaryByCategoryRows -Summary $summary
    $registerRows = Get-SOC2ControlRegisterRows -Catalog $catalog -Summary $summary
    # SOC 2 Audit-Readiness Plan PR 1 §8.4 — first content sheet after Cover.
    # The Control Conclusion Register is the auditor's primary view; ship it
    # before the legacy per-family Findings sheets. Direct assignment then
    # @() — see the HTML render path for why @() around the call double-wraps.
    $conclusionRows = Get-SOC2ControlConclusionRegister -Catalog $catalog -Summary $summary -EvidenceBundle $evidence
    $conclusionRows = @($conclusionRows)
    # PR 2 §9.2 — prioritised remediation view over the register.
    $remediationRows = Get-SOC2RemediationPlan -Register $conclusionRows
    $remediationRows = @($remediationRows)
    # PR 3 §10.2 — per-control evidence pivot from the bundle manifest.
    $evidenceMatrixRows = Get-SOC2EvidenceMatrix -EvidenceBundle $evidence -ControlCatalog $catalog -IdentityMapPath $identityMapPath
    $evidenceMatrixRows = @($evidenceMatrixRows)
    $familyPreds = Get-SOC2FamilyPredicates
    $licensingRows = Get-SOC2LicensingGapRows -Summary $summary
    # §11.1 — manual-attestation rows now reflect tracked lifecycle state.
    $manualRows = Get-SOC2ManualAttestationRows -Catalog $catalog -AttestationState $attestationState
    $evidenceRows = Get-SOC2EvidenceRegisterRows -Evidence $evidence

    $useExcel = $null -ne (Get-Module -ListAvailable -Name ImportExcel)

    if ($useExcel) {
        Import-Module ImportExcel -ErrorAction Stop

        $coverRows | Export-Excel -Path $OutputPath -WorksheetName 'Cover' -AutoSize -ClearSheet
        if ($conclusionRows -and $conclusionRows.Count -gt 0) {
            # Conditional formatting on the Conclusion column. Column letter
            # picked by ImportExcel's auto-ordering; the column is the 6th
            # field (ControlId, TscFamily, FamilyName, Automation,
            # ControlDescription, Conclusion, ...) so 'F' is the address.
            $conditional = @(
                New-ConditionalText -Text 'Deficiency' -ConditionalTextColor White -BackgroundColor '#c8102e'
                New-ConditionalText -Text 'Deficiency - Minor' -ConditionalTextColor Black -BackgroundColor '#ffd166'
                New-ConditionalText -Text 'Manual Pending' -ConditionalTextColor White -BackgroundColor '#5c2d91'
                New-ConditionalText -Text 'Not Assessed - Licensing' -ConditionalTextColor White -BackgroundColor '#6a5fb3'
                New-ConditionalText -Text 'Effective' -ConditionalTextColor Black -BackgroundColor '#dff6dd'
                New-ConditionalText -Text 'Accepted Risk' -ConditionalTextColor Black -BackgroundColor '#fcefe1'
                New-ConditionalText -Text 'Not Assessed - No Evidence' -ConditionalTextColor Black -BackgroundColor '#e8eaee'
            )
            $conclusionRows | Export-Excel -Path $OutputPath -WorksheetName 'Control Conclusions' -AutoSize -TableName 'tblConclusions' -FreezeTopRow -ConditionalText $conditional
        }
        if ($remediationRows -and $remediationRows.Count -gt 0) {
            # Priority column is field 1 (Priority, ControlId, TscFamily,
            # Gap, ...). Red→grey gradient by priority tier mirrors the
            # HTML badge colours.
            $prioConditional = @(
                New-ConditionalText -Text '1' -ConditionalTextColor White -BackgroundColor '#c8102e'
                New-ConditionalText -Text '2' -ConditionalTextColor Black -BackgroundColor '#e8893a'
                New-ConditionalText -Text '3' -ConditionalTextColor White -BackgroundColor '#5c2d91'
                New-ConditionalText -Text '4' -ConditionalTextColor White -BackgroundColor '#6a5fb3'
                New-ConditionalText -Text '5' -ConditionalTextColor Black -BackgroundColor '#e8eaee'
            )
            $remediationRows | Export-Excel -Path $OutputPath -WorksheetName 'Remediation Plan' -AutoSize -TableName 'tblRemediation' -FreezeTopRow -ConditionalText $prioConditional
        }
        if ($evidenceMatrixRows -and $evidenceMatrixRows.Count -gt 0) {
            # Freshness is field 8 (ControlId, TscFamily, EvidenceArtifact,
            # Source, CollectionTime, Hash, RedactionStatus, Freshness,
            # AnchorId). Colour it Fresh→Stale to mirror the HTML badges.
            $freshConditional = @(
                New-ConditionalText -Text 'Fresh' -ConditionalTextColor Black -BackgroundColor '#dff6dd'
                New-ConditionalText -Text 'Aging' -ConditionalTextColor Black -BackgroundColor '#fff4ce'
                New-ConditionalText -Text 'Stale' -ConditionalTextColor White -BackgroundColor '#c8102e'
                New-ConditionalText -Text 'Unknown' -ConditionalTextColor Black -BackgroundColor '#e8eaee'
            )
            $evidenceMatrixRows | Export-Excel -Path $OutputPath -WorksheetName 'Evidence Matrix' -AutoSize -TableName 'tblEvidenceMatrix' -FreezeTopRow -ConditionalText $freshConditional
        }
        if ($summaryRows) { $summaryRows | Export-Excel -Path $OutputPath -WorksheetName 'Summary by Category' -AutoSize -TableName 'tblSummary' }
        if ($registerRows) { $registerRows | Export-Excel -Path $OutputPath -WorksheetName 'Control Register' -AutoSize -TableName 'tblRegister' }

        foreach ($fp in $familyPreds) {
            $rows = Get-SOC2FindingsByFamilyRows -Catalog $catalog -Summary $summary -Predicate $fp.Predicate
            if ($rows.Count -gt 0) {
                $sheetName = "Findings - $($fp.Name)"
                $rows | Export-Excel -Path $OutputPath -WorksheetName $sheetName -AutoSize
            }
        }

        if ($licensingRows.Count -gt 0) {
            $licensingRows | Export-Excel -Path $OutputPath -WorksheetName 'Findings - Licensing Gaps' -AutoSize -TableName 'tblLicensing'
        }
        if ($manualRows.Count -gt 0) {
            $manualRows | Export-Excel -Path $OutputPath -WorksheetName 'Manual Attestation' -AutoSize -TableName 'tblManual'
        }
        if ($evidenceRows.Count -gt 0) {
            $evidenceRows | Export-Excel -Path $OutputPath -WorksheetName 'Evidence Register' -AutoSize -TableName 'tblEvidence'
        }

        return $OutputPath
    }

    # CSV fallback — mirrors the Excel sheet structure with numbered filenames
    # so a CSV-only consumer gets the same data surface as an Excel consumer.
    $csvDir = if ($OutputPath -like '*.xlsx') { [System.IO.Path]::ChangeExtension($OutputPath, '') -replace '\.$', '' } else { $OutputPath }
    if (-not (Test-Path -LiteralPath $csvDir)) {
        $null = New-Item -Path $csvDir -ItemType Directory -Force
    }

    $coverRows | Export-Csv -Path (Join-Path $csvDir '01-Cover.csv') -NoTypeInformation -Encoding UTF8

    # PR 1 §8.4 — Control Conclusion Register. Existing numbers (02/03/04...)
    # are kept stable so downstream consumers and the
    # SOC2-Reporting-Enhancements tests don't break; we slot the new file at
    # 01a so it sorts right after the Cover but before the legacy Summary.
    if ($conclusionRows -and $conclusionRows.Count -gt 0) {
        $conclusionRows | Export-Csv -Path (Join-Path $csvDir '01a-Control-Conclusions.csv') -NoTypeInformation -Encoding UTF8
    }
    # PR 2 — Remediation Plan at 01b: sorts right after the conclusions,
    # still ahead of the legacy 02/03 files which keep their numbers.
    if ($remediationRows -and $remediationRows.Count -gt 0) {
        $remediationRows | Export-Csv -Path (Join-Path $csvDir '01b-Remediation-Plan.csv') -NoTypeInformation -Encoding UTF8
    }
    # PR 3 — Evidence Matrix at 01c; legacy 02/03 numbers stay stable.
    if ($evidenceMatrixRows -and $evidenceMatrixRows.Count -gt 0) {
        $evidenceMatrixRows | Export-Csv -Path (Join-Path $csvDir '01c-Evidence-Matrix.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($summaryRows) {
        $summaryRows | Export-Csv -Path (Join-Path $csvDir '02-Summary-by-Category.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($registerRows) {
        $registerRows | Export-Csv -Path (Join-Path $csvDir '03-Control-Register.csv') -NoTypeInformation -Encoding UTF8
    }

    # Per-family findings CSVs, numbered 04-09 (matches Excel sheet order)
    $csvIndex = 4
    foreach ($fp in $familyPreds) {
        $rows = Get-SOC2FindingsByFamilyRows -Catalog $catalog -Summary $summary -Predicate $fp.Predicate
        if ($rows.Count -gt 0) {
            $fileName = '{0:D2}-Findings-{1}.csv' -f $csvIndex, $fp.Name
            $rows | Export-Csv -Path (Join-Path $csvDir $fileName) -NoTypeInformation -Encoding UTF8
        }
        $csvIndex++
    }

    if ($licensingRows.Count -gt 0) {
        $licensingRows | Export-Csv -Path (Join-Path $csvDir '10-Findings-Licensing-Gaps.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($manualRows.Count -gt 0) {
        $manualRows | Export-Csv -Path (Join-Path $csvDir '11-Manual-Attestation.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($evidenceRows.Count -gt 0) {
        $evidenceRows | Export-Csv -Path (Join-Path $csvDir '12-Evidence-Register.csv') -NoTypeInformation -Encoding UTF8
    }

    return $csvDir
}

#endregion

Export-ModuleMember -Function @(
    'New-SOC2AuditReport',
    'New-SOC2AuditWorkbook',
    # SOC 2 Audit-Readiness Plan PR 1 — control-level conclusion engine.
    # Exported so consumers (Type 2 report, future remediation/evidence
    # PRs, and Pester tests) can call them directly.
    'Get-SOC2ControlConclusion',
    'Get-SOC2ControlConclusionRegister',
    # Was previously consumed only inside this module via New-SOC2AuditReport;
    # PR 1 needs to test it directly to lock the verdict logic.
    'Get-SOC2ExecutiveDigest',
    # SOC 2 Audit-Readiness Plan PR 2 — prioritised remediation view over
    # the register. Exported for the report renderers and Pester tests.
    'Get-SOC2RemediationPlan',
    # SOC 2 Audit-Readiness Plan PR 3 — per-control evidence pivot +
    # freshness bucketing. Exported for renderers and Pester tests.
    'Get-SOC2EvidenceMatrix',
    'Get-SOC2EvidenceFreshness',
    # §11.1 Manual Attestation Workflow — register rows now reflect
    # tracked state; exported for the Pester suite.
    'Get-SOC2ManualAttestationRows'
)
