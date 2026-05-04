<#
.SYNOPSIS
    EntraChecks-PrivilegedIdentityCorrelator.psm1
    Merges the AD privileged-identity roster (PR 2) and the Entra
    privileged-identity roster (PR 3) into a single unified roster keyed
    by canonical principal identity.

.DESCRIPTION
    The matching problem: a person typically appears as
        - AD user CONTOSO\jdoe (SID  S-1-5-21-...)
        - Entra user jdoe@contoso.onmicrosoft.com (Object ID GUID)
    There is no universal join key. This module combines four signals,
    in declining priority:
        1. OnPremisesSecurityIdentifier on the Entra user (set by Entra
           Connect for synced users) -> AD SID. *Strong* match.
        2. Mail attribute equality (AD user's mail == Entra user's mail).
           *Probable* match.
        3. UserPrincipalName substring match (AD samAccountName matches the
           local part of the Entra UPN). *Weak* match.
        4. Manual override map (-IdentityOverridesPath JSON file). Always
           treated as *Strong* — operator-asserted identity equivalence.

    The output is one row per canonical identity, with both AD and Entra
    privileges combined. Findings are emitted for the high-value crossover
    cases (Tier 0 cross-surface, AD-disabled-Entra-enabled, weak-match
    privileged identities).

.NOTES
    Override file schema (JSON array):
        [
          {
            "AdSid": "S-1-5-21-1-1-1001",
            "EntraObjectId": "aaaaaaaa-...",
            "CanonicalId": "jdoe@contoso.com",
            "Note": "Manually verified 2026-04-30"
          }
        ]

.LINK
    AD aggregator: Modules/EntraChecks-PrivilegedIdentityAD.psm1
    Entra aggregator: Modules/EntraChecks-PrivilegedIdentityEntra.psm1
    Plan: plans/Privileged-Identity-Roster-Plan.md (PR 4)
#>

#Requires -Version 5.1

$script:ModulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $script:ModulePath 'EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking

$script:ModuleVersion = '1.0.0'
$script:ModuleName = 'EntraChecks-PrivilegedIdentityCorrelator'

#region ==================== PRIVATE HELPERS ====================

function Read-IdentityOverrideMap {
    <#
    .SYNOPSIS
        Loads and validates the optional identity-override JSON file.
        Returns @() when the path is null or the file doesn't exist; throws
        when present but malformed (loud failure beats silent mismatch).
    #>
    [OutputType([object[]])]
    [CmdletBinding()]
    param([string]$Path)

    if (-not $Path) { return @() }
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Verbose "IdentityOverridesPath '$Path' not found — proceeding with no overrides."
        return @()
    }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        $entries = @($parsed)
        # Validate shape
        foreach ($e in $entries) {
            if (-not $e.CanonicalId) {
                throw "Override entry missing CanonicalId: $($e | ConvertTo-Json -Compress)"
            }
            if (-not ($e.AdSid -or $e.EntraObjectId)) {
                throw "Override entry must have at least one of AdSid or EntraObjectId: $($e | ConvertTo-Json -Compress)"
            }
        }
        return $entries
    }
    catch {
        throw "Failed to read identity overrides from '$Path': $($_.Exception.Message)"
    }
}

function New-UnifiedRow {
    <#
    .SYNOPSIS
        Constructs a unified roster row with the merged shape consumed by
        PR 5's renderer. Pure data — no enrichment side effects.
    #>
    param(
        [hashtable]$AdRow,
        [hashtable]$EntraRow,
        [string]$MatchConfidence,
        [string]$MatchedBy,
        [string]$CanonicalId
    )

    # Pick the most specific display name available
    $displayName = $null
    foreach ($candidate in @($EntraRow.DisplayName, $AdRow.DisplayName, $EntraRow.Upn, $AdRow.SamAccountName)) {
        if ($candidate) { $displayName = $candidate; break }
    }

    $privileges = @()
    if ($AdRow)    { $privileges += @($AdRow.Privileges) }
    if ($EntraRow) { $privileges += @($EntraRow.Privileges) }

    # HighestTier — minimum numeric tier across both sides
    $highestTier = 'Service'
    $tiers = @($AdRow.HighestTier, $EntraRow.HighestTier) | Where-Object { $_ -is [int] }
    if ($tiers.Count -gt 0) {
        $highestTier = ($tiers | Measure-Object -Minimum).Minimum
    }
    elseif ($AdRow.HighestTier -eq 'Unclassified' -or $EntraRow.HighestTier -eq 'Unclassified') {
        $highestTier = 'Unclassified'
    }

    @{
        CanonicalId = $CanonicalId
        DisplayName = $displayName
        AdSid = if ($AdRow) { $AdRow.Sid } else { $null }
        AdSamAccountName = if ($AdRow) { $AdRow.SamAccountName } else { $null }
        EntraObjectId = if ($EntraRow) { $EntraRow.ObjectId } else { $null }
        EntraUpn = if ($EntraRow) { $EntraRow.Upn } else { $null }
        PrincipalType = if ($EntraRow.PrincipalType) { $EntraRow.PrincipalType } else { $AdRow.PrincipalType }
        MatchConfidence = $MatchConfidence
        MatchedBy = $MatchedBy
        CrossSurface = ($AdRow -and $EntraRow)
        AdEnabled = if ($AdRow) { $AdRow.Enabled } else { $null }
        EntraEnabled = if ($EntraRow) { $EntraRow.Enabled } else { $null }
        AdLastLogonDays = if ($AdRow) { $AdRow.LastLogonDays } else { $null }
        EntraLastSignIn = if ($EntraRow) { $EntraRow.LastSignIn } else { $null }
        InProtectedUsers = if ($AdRow) { $AdRow.InProtectedUsers } else { $null }
        SmartCardRequired = if ($AdRow) { $AdRow.SmartCardRequired } else { $null }
        Privileges = $privileges
        HighestTier = $highestTier
        Sources = @(@($AdRow.Sources) + @($EntraRow.Sources) | Where-Object { $_ })
    }
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Merge-PrivilegedIdentityRosters {
    <#
    .SYNOPSIS
        Merges the AD and Entra rosters into a single unified roster.

    .PARAMETER AdRoster
        Hashtable returned by Get-PrivilegedIdentityRosterAD. May have
        Available=$false; in that case, no AD rows are included but the
        Entra rows are still emitted.

    .PARAMETER EntraRoster
        Hashtable returned by Get-PrivilegedIdentityRosterEntra. Same
        graceful handling as AdRoster.

    .PARAMETER IdentityOverridesPath
        Optional JSON file path with operator-asserted identity equivalences.
        Honored as Strong matches regardless of other signals.

    .OUTPUTS
        @{
            UnifiedRoster = @(@{ CanonicalId; AdSid; EntraObjectId; ... }, ...)
            Findings = @(@{ Severity; Description; Object }, ...)
            Statistics = @{ Total; CrossSurface; Tier0CrossSurface; ... }
        }
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$AdRoster,
        [Parameter(Mandatory)] [hashtable]$EntraRoster,
        [string]$IdentityOverridesPath
    )

    $overrides = Read-IdentityOverrideMap -Path $IdentityOverridesPath
    $unified = @{}              # CanonicalId -> unified row
    $consumedAdSids = @{}       # SID -> $true once matched
    $consumedEntraIds = @{}     # ObjectId -> $true once matched

    $adRows = if ($AdRoster -and $AdRoster.Available) { @($AdRoster.Roster) } else { @() }
    $entraRows = if ($EntraRoster -and $EntraRoster.Available) { @($EntraRoster.Roster) } else { @() }

    # Build SID lookup once for efficient matching
    $adBySid = @{}
    foreach ($r in $adRows) { if ($r.Sid) { $adBySid[$r.Sid] = $r } }

    $adByMail = @{}
    foreach ($r in $adRows) {
        # Some AD rows carry a Mail-equivalent via DistinguishedName resolution;
        # the AD aggregator doesn't currently capture mail — skip for now.
        # Mail-based matching primarily handles the Entra-side fallback below.
    }

    $adBySam = @{}
    foreach ($r in $adRows) { if ($r.SamAccountName) { $adBySam[$r.SamAccountName.ToLower()] = $r } }

    # ----- Pass 1: explicit overrides (Strong, operator-asserted) -----

    foreach ($ov in $overrides) {
        $canonical = $ov.CanonicalId
        $adRow = if ($ov.AdSid -and $adBySid.ContainsKey($ov.AdSid)) { $adBySid[$ov.AdSid] } else { $null }
        $entraRow = $null
        if ($ov.EntraObjectId) {
            $entraRow = $entraRows | Where-Object ObjectId -eq $ov.EntraObjectId | Select-Object -First 1
        }
        # Only emit a row if the override actually resolved to at least one side
        if (-not ($adRow -or $entraRow)) {
            Write-Verbose "Override '$canonical' resolved to neither AD nor Entra — skipping."
            continue
        }
        $unified[$canonical] = New-UnifiedRow -AdRow $adRow -EntraRow $entraRow `
            -MatchConfidence 'Strong' -MatchedBy 'IdentityOverride' -CanonicalId $canonical
        if ($adRow)    { $consumedAdSids[$adRow.Sid] = $true }
        if ($entraRow) { $consumedEntraIds[$entraRow.ObjectId] = $true }
    }

    # ----- Pass 2: OnPremisesSecurityIdentifier match (Strong) -----

    foreach ($entraRow in $entraRows) {
        if ($consumedEntraIds.ContainsKey($entraRow.ObjectId)) { continue }
        $opsSid = $entraRow.OnPremisesSecurityIdentifier
        if (-not $opsSid) { continue }
        if (-not $adBySid.ContainsKey($opsSid)) { continue }
        $adRow = $adBySid[$opsSid]
        if ($consumedAdSids.ContainsKey($adRow.Sid)) { continue }

        $canonical = if ($entraRow.Upn) { $entraRow.Upn } else { $adRow.SamAccountName }
        $unified[$canonical] = New-UnifiedRow -AdRow $adRow -EntraRow $entraRow `
            -MatchConfidence 'Strong' -MatchedBy 'OnPremisesSecurityIdentifier' -CanonicalId $canonical
        $consumedAdSids[$adRow.Sid] = $true
        $consumedEntraIds[$entraRow.ObjectId] = $true
    }

    # ----- Pass 3: Mail-attribute match (Probable) -----
    # AD rows don't currently expose Mail; this pass exists as a placeholder
    # so the confidence ladder is testable end-to-end. When the AD aggregator
    # adds Mail capture (or an LDAP join is wired), this kicks in automatically.

    foreach ($entraRow in $entraRows) {
        if ($consumedEntraIds.ContainsKey($entraRow.ObjectId)) { continue }
        $entraMail = $entraRow.Mail
        if (-not $entraMail) { continue }
        $adMatch = $adRows | Where-Object {
            $_.Mail -and ($_.Mail.ToLower() -eq $entraMail.ToLower()) -and
            (-not $consumedAdSids.ContainsKey($_.Sid))
        } | Select-Object -First 1
        if (-not $adMatch) { continue }

        $canonical = if ($entraRow.Upn) { $entraRow.Upn } else { $entraMail }
        $unified[$canonical] = New-UnifiedRow -AdRow $adMatch -EntraRow $entraRow `
            -MatchConfidence 'Probable' -MatchedBy 'Mail' -CanonicalId $canonical
        $consumedAdSids[$adMatch.Sid] = $true
        $consumedEntraIds[$entraRow.ObjectId] = $true
    }

    # ----- Pass 4: UPN local-part vs samAccountName match (Weak) -----

    foreach ($entraRow in $entraRows) {
        if ($consumedEntraIds.ContainsKey($entraRow.ObjectId)) { continue }
        if (-not $entraRow.Upn) { continue }
        if ($entraRow.PrincipalType -ne 'User') { continue }   # Only meaningful for users

        $localPart = ($entraRow.Upn -split '@', 2)[0].ToLower()
        if (-not $adBySam.ContainsKey($localPart)) { continue }
        $adRow = $adBySam[$localPart]
        if ($consumedAdSids.ContainsKey($adRow.Sid)) { continue }

        $unified[$entraRow.Upn] = New-UnifiedRow -AdRow $adRow -EntraRow $entraRow `
            -MatchConfidence 'Weak' -MatchedBy 'UpnLocalPart' -CanonicalId $entraRow.Upn
        $consumedAdSids[$adRow.Sid] = $true
        $consumedEntraIds[$entraRow.ObjectId] = $true
    }

    # ----- Pass 5: leftover Entra-only and AD-only rows -----

    foreach ($entraRow in $entraRows) {
        if ($consumedEntraIds.ContainsKey($entraRow.ObjectId)) { continue }
        $canonical = if ($entraRow.Upn) { $entraRow.Upn } else { "entra:$($entraRow.ObjectId)" }
        $unified[$canonical] = New-UnifiedRow -AdRow $null -EntraRow $entraRow `
            -MatchConfidence 'None' -MatchedBy 'EntraOnly' -CanonicalId $canonical
    }
    foreach ($adRow in $adRows) {
        if ($consumedAdSids.ContainsKey($adRow.Sid)) { continue }
        $canonical = if ($adRow.SamAccountName) { "ad:$($adRow.SamAccountName)" } else { "ad-sid:$($adRow.Sid)" }
        $unified[$canonical] = New-UnifiedRow -AdRow $adRow -EntraRow $null `
            -MatchConfidence 'None' -MatchedBy 'AdOnly' -CanonicalId $canonical
    }

    # ----- Findings — surface the high-value crossover cases -----

    $findings = @()

    foreach ($row in $unified.Values) {
        # Critical: cross-surface Tier 0 (DA <-> Global Admin breakaway-account scenario).
        if ($row.CrossSurface -and $row.HighestTier -eq 0) {
            $findings += @{
                Severity = 'Critical'
                Description = "Cross-surface Tier 0 admin: $($row.DisplayName) holds Tier 0 privileges in both Active Directory and Entra. Compromise of either side compromises the other; treat as a single Tier 0 identity with the strictest controls."
                Object = $row.CanonicalId
                CheckName = 'PrivilegedIdentityCorrelator-CrossSurfaceTier0'
            }
        }
        # High: AD-disabled but Entra-enabled (or vice versa) — orphaned cross-surface privilege.
        if ($row.CrossSurface -and ($row.AdEnabled -eq $false) -and ($row.EntraEnabled -eq $true)) {
            $findings += @{
                Severity = 'High'
                Description = "Account is disabled in AD but enabled in Entra: $($row.DisplayName). Disable on both surfaces or re-enable both — half-disabled accounts are a common source of stale privilege."
                Object = $row.CanonicalId
                CheckName = 'PrivilegedIdentityCorrelator-AdDisabledEntraEnabled'
            }
        }
        if ($row.CrossSurface -and ($row.AdEnabled -eq $true) -and ($row.EntraEnabled -eq $false)) {
            $findings += @{
                Severity = 'High'
                Description = "Account is enabled in AD but disabled in Entra: $($row.DisplayName). Disable on both surfaces or re-enable both — half-disabled accounts are a common source of stale privilege."
                Object = $row.CanonicalId
                CheckName = 'PrivilegedIdentityCorrelator-AdEnabledEntraDisabled'
            }
        }
        # High: privileged synced account (the AD identity is privileged AND it
        # syncs to a privileged Entra identity — the same person-object holds
        # both, which is the textbook "no separate cloud-only admin" pattern).
        if ($row.CrossSurface -and $row.HighestTier -in @(0, 1) -and $row.MatchedBy -eq 'OnPremisesSecurityIdentifier') {
            $findings += @{
                Severity = 'High'
                Description = "Privileged synced account: $($row.DisplayName). The on-prem identity is synced to Entra and holds privilege on both sides. Best practice is a separate cloud-only admin account that does not sync from AD; a sync-account compromise should not cascade to cloud admin."
                Object = $row.CanonicalId
                CheckName = 'PrivilegedIdentityCorrelator-PrivilegedSyncedAccount'
            }
        }
        # Medium: weak-confidence match on a privileged identity.
        if ($row.CrossSurface -and $row.MatchConfidence -in @('Probable', 'Weak') -and $row.HighestTier -in @(0, 1)) {
            $findings += @{
                Severity = 'Medium'
                Description = "Privileged identity matched with $($row.MatchConfidence) confidence ($($row.MatchedBy)): $($row.DisplayName). Verify manually and add to the IdentityOverrides JSON file to harden the match for future reports."
                Object = $row.CanonicalId
                CheckName = 'PrivilegedIdentityCorrelator-WeakMatchPrivileged'
            }
        }
    }

    # ----- Statistics -----

    $unifiedArray = @($unified.Values) | Sort-Object @{Expression = {
            if ($_.HighestTier -is [int]) { $_.HighestTier } else { 99 }
        }
    }, DisplayName

    $stats = @{
        Total = $unifiedArray.Count
        CrossSurface = @($unifiedArray | Where-Object { $_.CrossSurface }).Count
        AdOnly = @($unifiedArray | Where-Object { $_.MatchedBy -eq 'AdOnly' }).Count
        EntraOnly = @($unifiedArray | Where-Object { $_.MatchedBy -eq 'EntraOnly' }).Count
        Tier0 = @($unifiedArray | Where-Object { $_.HighestTier -eq 0 }).Count
        Tier0CrossSurface = @($unifiedArray | Where-Object { $_.HighestTier -eq 0 -and $_.CrossSurface }).Count
        StrongMatches = @($unifiedArray | Where-Object { $_.MatchConfidence -eq 'Strong' }).Count
        ProbableMatches = @($unifiedArray | Where-Object { $_.MatchConfidence -eq 'Probable' }).Count
        WeakMatches = @($unifiedArray | Where-Object { $_.MatchConfidence -eq 'Weak' }).Count
        OverrideCount = $overrides.Count
        ScannedAt = (Get-Date).ToUniversalTime().ToString('o')
    }

    return @{
        UnifiedRoster = $unifiedArray
        Findings = $findings
        Statistics = $stats
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Merge-PrivilegedIdentityRosters'
)

#endregion
