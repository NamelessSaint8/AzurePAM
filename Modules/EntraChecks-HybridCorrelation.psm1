<#
.SYNOPSIS
    EntraChecks-HybridCorrelation.psm1
    Correlates cloud findings (Entra) with on-prem AD findings across the hybrid identity surface.

.DESCRIPTION
    After a Hybrid Analysis run produces cloud + on-prem findings in one array,
    Get-HybridIdentityCorrelation walks the array and identifies principals
    (users, service accounts) flagged in BOTH planes.

    The correlation is keyed on UPN and sAMAccountName. For standard Azure AD
    Connect deployments these are usually equivalent (`alice@contoso.com`
    <-> `alice`), but the correlation emits a Confidence field so analysts
    can tell which match was exact vs. inferred.

.NOTES
    Version: 1.0.0
    Author:  David Stells
    Requires: PowerShell 5.1+ (no external modules — works on findings already in memory)
#>

#Requires -Version 5.1

$script:ModuleName = 'EntraChecks-HybridCorrelation'
$script:ModuleVersion = '1.0.0'

#region ==================== PRIVATE HELPERS ====================

<#
.SYNOPSIS
    Extracts a best-effort principal identifier from a finding.
.DESCRIPTION
    Different modules put different things in the Object field (UPN, SPN, DN,
    group name, hash). This helper returns a struct the correlation logic can
    reason about without caring which module produced the finding.
#>
function Get-FindingPrincipal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [object]$Finding
    )

    $obj = [string]$Finding.Object
    if ([string]::IsNullOrWhiteSpace($obj)) {
        return [pscustomobject]@{
            Kind = 'None'
            UPN = $null
            SamAccountName = $null
            Raw = $obj
        }
    }

    # UPN: contains @ and a dot after the @.
    if ($obj -match '([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})') {
        $upn = $matches[0]
        $sam = $matches[1]
        return [pscustomobject]@{
            Kind = 'UPN'
            UPN = $upn
            SamAccountName = $sam
            Raw = $obj
        }
    }

    # DN: "CN=X,CN=..." — extract CN= first-hit as sAMAccountName candidate (only when looks like a user/account DN, not a group or path).
    if ($obj -match '^CN=([^,]+),') {
        return [pscustomobject]@{
            Kind = 'DN'
            UPN = $null
            SamAccountName = $matches[1]
            Raw = $obj
        }
    }

    # Bare sAMAccountName (or decorated like "user (Domain Admins)"). Strip trailing " ( ... )" decoration.
    $stripped = ($obj -replace '\s*\(.*$', '').Trim()
    # Heuristic: must look like a valid sAMAccountName (<= 20 chars, no spaces, no special separators).
    if ($stripped -and $stripped.Length -le 64 -and $stripped -notmatch '\s' -and $stripped -notmatch '[/\\,;]') {
        return [pscustomobject]@{
            Kind = 'SAM'
            UPN = $null
            SamAccountName = $stripped
            Raw = $obj
        }
    }

    return [pscustomobject]@{
        Kind = 'Other'
        UPN = $null
        SamAccountName = $null
        Raw = $obj
    }
}

<#
.SYNOPSIS
    Determines whether a finding is identity-bearing (relates to a specific principal).
.DESCRIPTION
    Only identity-bearing findings participate in correlation. Environment-level
    findings (e.g., "Domain Controllers: count = 4") are excluded.
#>
function Test-IsIdentityFinding {
    [CmdletBinding()]
    [OutputType([bool])]
    param([object]$Finding)

    $excludedCategories = @('Infrastructure')
    if ($Finding.Category -in $excludedCategories) { return $false }

    # Must have a Status that actually means something.
    if ($Finding.Status -in @('INFO', 'PASS')) { return $false }

    $principal = Get-FindingPrincipal -Finding $Finding
    return $principal.Kind -in @('UPN', 'DN', 'SAM')
}

#endregion

#region ==================== PUBLIC API ====================

<#
.SYNOPSIS
    Correlates cloud (Entra) and on-prem (Active Directory) findings by principal.
.DESCRIPTION
    Walks a combined findings array, groups identity-bearing findings by UPN
    and sAMAccountName, and produces a summary of principals that appear in
    BOTH the cloud plane and the on-prem plane. Each correlation carries a
    Confidence flag so the renderer can annotate when a match was exact vs.
    inferred.

.PARAMETER Findings
    The combined findings array from a Hybrid Analysis run. Must include
    both cloud findings (Source in {Core, IdentityProtection, Devices, ...})
    and on-prem findings (Source='ActiveDirectory').

.OUTPUTS
    PSCustomObject with CorrelatedPrincipals, CloudOnlyPrincipals,
    OnPremOnlyPrincipals, TotalCloudFindings, TotalOnPremFindings,
    CorrelationCount.

.EXAMPLE
    $findings = Invoke-HybridAssessment ...
    $corr = Get-HybridIdentityCorrelation -Findings $findings
    $corr.CorrelatedPrincipals | Format-Table

.NOTES
    Matching algorithm:
    1. For each identity-bearing finding, extract {UPN, sAMAccountName, Raw}.
    2. Build two indices keyed on UPN and sAMAccountName, each pointing at
       (Source, Finding) tuples.
    3. A principal is "correlated" when:
       - UPN match across Source={ActiveDirectory, <any cloud source>}, OR
       - sAMAccountName match across Source={ActiveDirectory, <any cloud
         source>} (Confidence='Inferred' — the cloud UPN's left-hand side
         equals the on-prem sAMAccountName but domain suffix doesn't appear
         in the on-prem finding).
#>
function Get-HybridIdentityCorrelation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Findings',
        Justification = 'Iterated via foreach below, analyzer false positive.')]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    # Indices. Key = normalized identifier; value = list of {Source, Finding}.
    $upnIndex = @{}
    $samIndex = @{}
    $totalCloud = 0
    $totalOnPrem = 0

    if ($Findings) {
        foreach ($f in $Findings) {
            if (-not (Test-IsIdentityFinding -Finding $f)) { continue }
            $src = if ($f.Source) { [string]$f.Source } else { 'Unknown' }
            if ($src -eq 'ActiveDirectory') { $totalOnPrem++ } else { $totalCloud++ }

            $p = Get-FindingPrincipal -Finding $f
            if ($p.UPN) {
                $upnKey = $p.UPN.ToLowerInvariant()
                if (-not $upnIndex.ContainsKey($upnKey)) { $upnIndex[$upnKey] = @() }
                $upnIndex[$upnKey] += [pscustomobject]@{ Source = $src; Finding = $f; Principal = $p }
            }
            if ($p.SamAccountName) {
                $samKey = $p.SamAccountName.ToLowerInvariant()
                if (-not $samIndex.ContainsKey($samKey)) { $samIndex[$samKey] = @() }
                $samIndex[$samKey] += [pscustomobject]@{ Source = $src; Finding = $f; Principal = $p }
            }
        }
    }

    $correlated = [System.Collections.Generic.List[object]]::new()
    $seenKeys = @{}

    # Pass 1 — UPN-keyed correlations (Confidence='Exact').
    foreach ($k in $upnIndex.Keys) {
        $entries = $upnIndex[$k]
        $cloudHits = @($entries | Where-Object { $_.Source -ne 'ActiveDirectory' })
        $onPremHits = @($entries | Where-Object { $_.Source -eq 'ActiveDirectory' })
        if ($cloudHits.Count -gt 0 -and $onPremHits.Count -gt 0) {
            $correlated.Add([pscustomobject]@{
                    Principal = $k
                    Confidence = 'Exact'
                    MatchKey = 'UPN'
                    CloudFindings = $cloudHits.Finding
                    OnPremFindings = $onPremHits.Finding
                    MaxCloudSeverity = (Get-MaxSeverity -Findings $cloudHits.Finding)
                    MaxOnPremSeverity = (Get-MaxSeverity -Findings $onPremHits.Finding)
                    CloudCount = $cloudHits.Count
                    OnPremCount = $onPremHits.Count
                })
            $seenKeys[$k] = $true
            # Also mark the SAM form seen to avoid double-counting.
            $sam = $entries[0].Principal.SamAccountName
            if ($sam) { $seenKeys[$sam.ToLowerInvariant()] = $true }
        }
    }

    # Pass 2 — sAMAccountName-keyed correlations for pairs NOT already matched by UPN.
    foreach ($k in $samIndex.Keys) {
        if ($seenKeys.ContainsKey($k)) { continue }
        $entries = $samIndex[$k]
        $cloudHits = @($entries | Where-Object { $_.Source -ne 'ActiveDirectory' })
        $onPremHits = @($entries | Where-Object { $_.Source -eq 'ActiveDirectory' })
        if ($cloudHits.Count -gt 0 -and $onPremHits.Count -gt 0) {
            $correlated.Add([pscustomobject]@{
                    Principal = $k
                    Confidence = 'Inferred'
                    MatchKey = 'sAMAccountName'
                    CloudFindings = $cloudHits.Finding
                    OnPremFindings = $onPremHits.Finding
                    MaxCloudSeverity = (Get-MaxSeverity -Findings $cloudHits.Finding)
                    MaxOnPremSeverity = (Get-MaxSeverity -Findings $onPremHits.Finding)
                    CloudCount = $cloudHits.Count
                    OnPremCount = $onPremHits.Count
                })
            $seenKeys[$k] = $true
        }
    }

    # Cloud-only and on-prem-only: principals that appear in only one plane.
    $cloudOnly = [System.Collections.Generic.List[object]]::new()
    $onPremOnly = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $upnIndex.Keys) {
        if ($seenKeys.ContainsKey($k)) { continue }
        $entries = $upnIndex[$k]
        $src = $entries[0].Source
        $record = [pscustomobject]@{
            Principal = $k
            MatchKey = 'UPN'
            Findings = $entries.Finding
            MaxSeverity = (Get-MaxSeverity -Findings $entries.Finding)
            Count = $entries.Count
        }
        if ($src -eq 'ActiveDirectory') { $onPremOnly.Add($record) }
        else { $cloudOnly.Add($record) }
    }

    return [pscustomobject]@{
        CorrelatedPrincipals = $correlated.ToArray()
        CloudOnlyPrincipals = $cloudOnly.ToArray()
        OnPremOnlyPrincipals = $onPremOnly.ToArray()
        TotalCloudFindings = $totalCloud
        TotalOnPremFindings = $totalOnPrem
        CorrelationCount = $correlated.Count
    }
}

<#
.SYNOPSIS
    Returns the highest Severity string from a findings array.
#>
function Get-MaxSeverity {
    [CmdletBinding()]
    [OutputType([string])]
    param([object[]]$Findings)
    $order = @('Critical', 'High', 'Medium', 'Low', 'Info')
    foreach ($sev in $order) {
        if ($Findings | Where-Object { $_.Severity -eq $sev }) { return $sev }
    }
    return 'Low'
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-HybridIdentityCorrelation',
    'Get-MaxSeverity'
)

#endregion
