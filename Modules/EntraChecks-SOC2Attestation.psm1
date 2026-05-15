<#
.SYNOPSIS
    EntraChecks-SOC2Attestation.psm1 — Manual Attestation Workflow for
    SOC 2 manual controls (Audit-Readiness Plan §11.1).

.DESCRIPTION
    SOC 2 has controls that cannot be observed via Graph/Azure (CC1
    control-environment items, etc.). Until now they shipped as static
    markdown templates with no tracked state. This module promotes them
    to a tracked lifecycle:

        NotStarted → Requested → Received → Reviewed → Accepted | Rejected

    with re-entry edges (Rejected → Requested for a re-request, Accepted
    → Requested for a new period's re-attestation).

    State is persisted in a local, gitignored JSON file (keyed by
    ControlId) — analogous to the v2 finding-state file but a separate
    artifact because attestation state is per-control, not per-finding.

    The workflow integrates with the v2 schema: each manual control's
    attestation state maps onto a finding's ReviewStatus.State so manual
    controls become first-class review items in both the SOC 2 report
    and the main analyst cockpit's Review Queue (no separate queue).

.NOTES
    Version: 1.0.0
    Author: EntraChecks Project

.LINK
    plans/SOC2-Audit-Readiness-Plan.md §11.1
#>

#Requires -Version 5.1

$script:ModuleName = 'EntraChecks-SOC2Attestation'
$script:ModuleVersion = '1.0.0'

# Lifecycle states in canonical order. NotStarted is the implicit default
# for any manual control with no recorded attestation.
$script:AttestationStates = @(
    'NotStarted', 'Requested', 'Received', 'Reviewed', 'Accepted', 'Rejected'
)

# Allowed transitions. Same-state is always allowed (idempotent re-apply).
# Re-entry edges let a control be re-requested after rejection and
# re-attested for a new Type 2 period after acceptance.
$script:AttestationTransitions = @{
    'NotStarted' = @('Requested')
    'Requested' = @('Received', 'Requested')
    'Received' = @('Reviewed', 'Requested')
    'Reviewed' = @('Accepted', 'Rejected', 'Received')
    'Accepted' = @('Requested')
    'Rejected' = @('Requested')
}

#region ==================== STATE MACHINE ====================

<#
.SYNOPSIS
    Returns the ordered list of valid attestation lifecycle states.
#>
function Get-SOC2AttestationStates {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return , ([string[]]$script:AttestationStates)
}

<#
.SYNOPSIS
    Returns a default attestation record for a control (State=NotStarted).

.PARAMETER ControlId
    The TSC control id this attestation tracks.

.PARAMETER ControlOwner
    Optional initial owner (typically the catalog's ControlOwnerHint).
#>
function Get-SOC2DefaultAttestation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [string]$ControlOwner = ''
    )
    return [pscustomobject]@{
        ControlId = $ControlId
        State = 'NotStarted'
        ControlOwner = $ControlOwner
        RequestedDate = ''
        ReceivedDate = ''
        EvidenceLocation = ''
        Reviewer = ''
        Notes = ''
        NextReviewDate = ''
    }
}

<#
.SYNOPSIS
    Returns $true if From → To is a permitted attestation transition.

.DESCRIPTION
    Same-state is always permitted (idempotent re-apply). Unknown states
    return $false. This is the single source of truth for the lifecycle
    graph — Set-SOC2AttestationRecord and any UI both gate on it.
#>
function Test-SOC2AttestationTransition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string]$To
    )
    if ($To -notin $script:AttestationStates) { return $false }
    if ($From -notin $script:AttestationStates) { return $false }
    if ($From -eq $To) { return $true }
    if (-not $script:AttestationTransitions.ContainsKey($From)) { return $false }
    return ($To -in $script:AttestationTransitions[$From])
}

<#
.SYNOPSIS
    Applies a validated state transition + field updates to an attestation
    record, returning a new record. Pure — the caller persists.

.DESCRIPTION
    Throws on an invalid transition (workflow integrity is not advisory —
    a caller asking for Received → Accepted has a bug). When entering a
    state, the corresponding timestamp is auto-stamped (UTC, ISO-8601) if
    the caller did not supply one:
      Requested → RequestedDate, Received → ReceivedDate.
    Any explicitly-passed field overrides the auto-stamp.

.PARAMETER Record
    The current record (from Import-SOC2AttestationState or
    Get-SOC2DefaultAttestation).

.PARAMETER State
    Target lifecycle state.

.PARAMETER ControlOwner / RequestedDate / ReceivedDate / EvidenceLocation
.PARAMETER Reviewer / Notes / NextReviewDate
    Optional field updates. Only supplied (non-$null) values are written.
#>
function Set-SOC2AttestationRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Record,
        [Parameter(Mandatory)][ValidateSet('NotStarted', 'Requested', 'Received', 'Reviewed', 'Accepted', 'Rejected')]
        [string]$State,
        [string]$ControlOwner,
        [string]$RequestedDate,
        [string]$ReceivedDate,
        [string]$EvidenceLocation,
        [string]$Reviewer,
        [string]$Notes,
        [string]$NextReviewDate
    )

    $from = [string]$Record.State
    if (-not (Test-SOC2AttestationTransition -From $from -To $State)) {
        throw "Invalid attestation transition: '$from' -> '$State' for control '$($Record.ControlId)'. Allowed from '$from': $(@($script:AttestationTransitions[$from]) -join ', ')."
    }

    $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

    # Clone so the input record is not mutated (pure contract).
    $new = [pscustomobject]@{
        ControlId = $Record.ControlId
        State = $State
        ControlOwner = $Record.ControlOwner
        RequestedDate = $Record.RequestedDate
        ReceivedDate = $Record.ReceivedDate
        EvidenceLocation = $Record.EvidenceLocation
        Reviewer = $Record.Reviewer
        Notes = $Record.Notes
        NextReviewDate = $Record.NextReviewDate
    }

    # Auto-stamp lifecycle timestamps on entry (only when not already set
    # and not explicitly overridden below).
    if ($State -eq 'Requested' -and -not $new.RequestedDate) { $new.RequestedDate = $now }
    if ($State -eq 'Received' -and -not $new.ReceivedDate) { $new.ReceivedDate = $now }

    if ($PSBoundParameters.ContainsKey('ControlOwner')) { $new.ControlOwner = $ControlOwner }
    if ($PSBoundParameters.ContainsKey('RequestedDate')) { $new.RequestedDate = $RequestedDate }
    if ($PSBoundParameters.ContainsKey('ReceivedDate')) { $new.ReceivedDate = $ReceivedDate }
    if ($PSBoundParameters.ContainsKey('EvidenceLocation')) { $new.EvidenceLocation = $EvidenceLocation }
    if ($PSBoundParameters.ContainsKey('Reviewer')) { $new.Reviewer = $Reviewer }
    if ($PSBoundParameters.ContainsKey('Notes')) { $new.Notes = $Notes }
    if ($PSBoundParameters.ContainsKey('NextReviewDate')) { $new.NextReviewDate = $NextReviewDate }

    return $new
}

#endregion

#region ==================== PERSISTENCE ====================

<#
.SYNOPSIS
    Resolves the attestation state file path.

.DESCRIPTION
    Precedence: explicit -Path always wins; otherwise the config block's
    SOC2.AttestationStatePath; otherwise '' (workflow disabled — manual
    controls render with NotStarted defaults). Mirrors the GRC
    finding-state resolution in Initialize-FindingsForReport.

.PARAMETER Path
    Explicit override.

.PARAMETER Config
    The SOC2 config block (hashtable or pscustomobject) — read
    .AttestationStatePath from it.
#>
function Get-SOC2AttestationStatePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Path = '',
        $Config
    )
    if ($Path) { return $Path }
    if ($Config) {
        $cfgPath = $null
        if ($Config -is [hashtable]) {
            if ($Config.ContainsKey('AttestationStatePath')) { $cfgPath = $Config['AttestationStatePath'] }
        }
        elseif ($Config.PSObject -and $Config.PSObject.Properties['AttestationStatePath']) {
            $cfgPath = $Config.AttestationStatePath
        }
        if ($cfgPath) { return [string]$cfgPath }
    }
    return ''
}

<#
.SYNOPSIS
    Loads the attestation state file into a hashtable keyed by ControlId.

.DESCRIPTION
    File JSON shape:
      { "Version": "1.0", "Attestations": { "<ControlId>": { State, ... } } }

    Returns @{ Attestations = @{} } when the path is empty or the file is
    missing (treated as "no state, NotStarted everywhere"). A malformed
    file logs a warning and also returns an empty bucket — attestation
    workflow is advisory and must never abort the assessment. Mirrors
    Import-FindingState.
#>
function Import-SOC2AttestationState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Path
    )

    $empty = @{ Attestations = @{} }
    if (-not $Path) { return $empty }
    if (-not (Test-Path -LiteralPath $Path)) { return $empty }

    try {
        $parsed = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Warning ("Failed to load SOC 2 attestation state '{0}': {1}" -f $Path, $_.Exception.Message)
        return $empty
    }

    $bucket = @{}
    if ($parsed.PSObject -and $parsed.PSObject.Properties['Attestations'] -and $parsed.Attestations) {
        foreach ($prop in $parsed.Attestations.PSObject.Properties) {
            $bucket[$prop.Name] = $prop.Value
        }
    }
    return @{ Attestations = $bucket }
}

<#
.SYNOPSIS
    Persists an attestation state hashtable to disk as JSON.

.PARAMETER State
    Hashtable @{ Attestations = @{ <ControlId> = <record> } }.

.PARAMETER Path
    Destination file. Parent directory is created if missing.
#>
function Save-SOC2AttestationState {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][hashtable]$State,
        [Parameter(Mandatory)][string]$Path
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -Path $dir -ItemType Directory -Force
    }

    $attestations = if ($State.ContainsKey('Attestations')) { $State['Attestations'] } else { @{} }
    # Emit an ordered object so the file is stable/diff-friendly.
    $ordered = [ordered]@{}
    foreach ($key in ($attestations.Keys | Sort-Object)) {
        $ordered[$key] = $attestations[$key]
    }
    $payload = [ordered]@{
        Version = '1.0'
        GeneratedAt = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Attestations = $ordered
    }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
    return $Path
}

#endregion

#region ==================== v2 INTEGRATION ====================

<#
.SYNOPSIS
    Maps an attestation record onto a v2 ReviewStatus object so manual
    controls flow through the existing cockpit Review Queue.

.DESCRIPTION
    The cockpit Review Queue (Get-CockpitReviewQueueSection) includes any
    finding whose ReviewStatus.State ∈ {NeedsReview, InReview,
    ActionRequired}. The attestation lifecycle maps as:

      NotStarted → NeedsReview     (request not yet sent)
      Requested  → InReview        (awaiting evidence from owner)
      Received   → InReview        (evidence in, awaiting reviewer)
      Reviewed   → ActionRequired  (needs an accept/reject decision)
      Accepted   → Accepted        (done — drops out of the queue)
      Rejected   → ActionRequired  (needs re-request / remediation)

    Reviewer / Notes / NextReviewDate pass through to the matching
    ReviewStatus fields so the queue row is actionable.

.OUTPUTS
    A v2 ReviewStatus pscustomobject (same shape as
    Get-EcfDefaultReviewStatus).
#>
function ConvertTo-SOC2ReviewStatusFromAttestation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Attestation
    )

    $state = [string]$Attestation.State
    $mapped = switch ($state) {
        'NotStarted' { 'NeedsReview' }
        'Requested' { 'InReview' }
        'Received' { 'InReview' }
        'Reviewed' { 'ActionRequired' }
        'Accepted' { 'Accepted' }
        'Rejected' { 'ActionRequired' }
        default { 'NeedsReview' }
    }

    $notesParts = New-Object System.Collections.Generic.List[string]
    $notesParts.Add("Attestation: $state") | Out-Null
    if ($Attestation.EvidenceLocation) { $notesParts.Add("Evidence: $($Attestation.EvidenceLocation)") | Out-Null }
    if ($Attestation.Notes) { $notesParts.Add([string]$Attestation.Notes) | Out-Null }

    return [pscustomobject]@{
        State = $mapped
        Reviewer = [string]$Attestation.Reviewer
        Notes = ($notesParts -join ' | ')
        FirstSeenUtc = ''
        LastSeenUtc = ''
        ReviewedAtUtc = ''
        NextReviewDate = [string]$Attestation.NextReviewDate
    }
}

<#
.SYNOPSIS
    Applies attestation state to the manual-attestation findings in a
    collection, in place, and returns the collection.

.DESCRIPTION
    For every finding that is a SOC 2 manual stub (Status='MANUAL'), looks
    up its control's attestation record (TSCReferences[0]) in the supplied
    state, defaults to NotStarted when absent, then:
      - sets the finding's ReviewStatus from the attestation
        (ConvertTo-SOC2ReviewStatusFromAttestation) so it surfaces in the
        cockpit Review Queue, and
      - stamps the finding's Owner.DisplayName with the attestation's
        ControlOwner when one is recorded.

    Findings that are not manual stubs are left untouched. Safe to call
    on legacy (pre-v2) findings — it only sets properties.

.PARAMETER Findings
    The findings collection (typically post-ConvertTo-EntraFindingV2).

.PARAMETER State
    Hashtable from Import-SOC2AttestationState.

.OUTPUTS
    The same findings array, with manual stubs enriched.
#>
function Add-SOC2AttestationToFindings {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory)][hashtable]$State
    )

    $bucket = if ($State.ContainsKey('Attestations')) { $State['Attestations'] } else { @{} }

    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }
        $status = if ($f.PSObject.Properties['Status']) { [string]$f.Status } else { '' }
        if ($status -ne 'MANUAL') { continue }

        # Control id from the first TSC reference.
        $controlId = ''
        if ($f.PSObject.Properties['TSCReferences'] -and $f.TSCReferences) {
            $controlId = [string](@($f.TSCReferences)[0])
        }
        if (-not $controlId) { continue }

        $ownerHint = if ($f.PSObject.Properties['ControlOwnerHint']) { [string]$f.ControlOwnerHint } else { '' }

        $record = $null
        if ($bucket -is [hashtable] -and $bucket.ContainsKey($controlId)) {
            $record = $bucket[$controlId]
        }
        elseif ($bucket.PSObject -and $bucket.PSObject.Properties[$controlId]) {
            $record = $bucket.$controlId
        }
        if (-not $record) {
            $record = Get-SOC2DefaultAttestation -ControlId $controlId -ControlOwner $ownerHint
        }
        # Normalize a JSON-roundtripped record to a pscustomobject with all
        # expected fields so ConvertTo-SOC2ReviewStatusFromAttestation is safe.
        $norm = Get-SOC2DefaultAttestation -ControlId $controlId -ControlOwner $ownerHint
        foreach ($p in $norm.PSObject.Properties.Name) {
            $val = $null
            if ($record -is [hashtable]) {
                if ($record.ContainsKey($p)) { $val = $record[$p] }
            }
            elseif ($record.PSObject -and $record.PSObject.Properties[$p]) {
                $val = $record.$p
            }
            if ($null -ne $val -and "$val" -ne '') { $norm.$p = $val }
        }

        $reviewStatus = ConvertTo-SOC2ReviewStatusFromAttestation -Attestation $norm
        if ($f.PSObject.Properties['ReviewStatus']) {
            $f.ReviewStatus = $reviewStatus
        }
        else {
            Add-Member -InputObject $f -MemberType NoteProperty -Name 'ReviewStatus' -Value $reviewStatus -Force
        }

        # Reflect the attestation owner onto the v2 Owner block when present.
        if ($norm.ControlOwner -and $f.PSObject.Properties['Owner'] -and $f.Owner) {
            if ($f.Owner.PSObject.Properties['DisplayName']) {
                $f.Owner.DisplayName = [string]$norm.ControlOwner
            }
            if ($f.Owner.PSObject.Properties['OwnerType'] -and -not [string]$f.Owner.OwnerType) {
                $f.Owner.OwnerType = 'Team'
            }
        }
    }

    return , $Findings
}

#endregion

Export-ModuleMember -Function @(
    'Get-SOC2AttestationStates',
    'Get-SOC2DefaultAttestation',
    'Test-SOC2AttestationTransition',
    'Set-SOC2AttestationRecord',
    'Get-SOC2AttestationStatePath',
    'Import-SOC2AttestationState',
    'Save-SOC2AttestationState',
    'ConvertTo-SOC2ReviewStatusFromAttestation',
    'Add-SOC2AttestationToFindings'
)
