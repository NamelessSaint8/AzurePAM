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
$script:ModuleVersion = '1.1.0'  # PR 5: cross-surface correlators

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

    # PR 5 - Cross-surface correlators. Build a lightweight principal index
    # keyed on both UPN and SamAccountName so the correlators can do O(1)
    # lookups without re-scanning the findings list.
    $principalIndex = New-PrincipalIndex -Findings $Findings

    $crossSurface = [System.Collections.Generic.List[object]]::new()
    foreach ($corr in @(
            'Find-DAExposureToCloudAdmin',
            'Find-DnsAdminsWithCloudPrivilege',
            'Find-ShadowCredentialsOnCloudSyncedAdmin',
            'Find-RBCDOnPrivilegedTier0Targeting',
            'Find-RiskyUserWithOnPremPrivilege'
        )) {
        try {
            $results = & $corr -Findings $Findings -PrincipalIndex $principalIndex
            foreach ($r in @($results)) { if ($r) { $crossSurface.Add($r) } }
        }
        catch {
            Write-Verbose "Correlator '$corr' failed: $($_.Exception.Message)"
        }
    }

    return [pscustomobject]@{
        CorrelatedPrincipals = $correlated.ToArray()
        CloudOnlyPrincipals = $cloudOnly.ToArray()
        OnPremOnlyPrincipals = $onPremOnly.ToArray()
        TotalCloudFindings = $totalCloud
        TotalOnPremFindings = $totalOnPrem
        CorrelationCount = $correlated.Count
        CrossSurfaceFindings = $crossSurface.ToArray()
        CrossSurfaceCount = $crossSurface.Count
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

#region ==================== PR 5 - CROSS-SURFACE CORRELATORS ====================

<#
.SYNOPSIS
    Builds a principal index from the findings list for O(1) correlator lookups.
.DESCRIPTION
    Walks findings once. Extracts UPN + SamAccountName via Get-FindingPrincipal.
    Emits a hashtable keyed on the lower-cased identifier, value is a record
    with CloudFindings / OnPremFindings arrays for that principal plus the
    privileged cloud roles they hold (extracted from PrivilegedRoleMember
    findings emitted by Check-DirectoryRolesAndMembers).

    Correlators consume this index rather than re-scanning the findings array,
    keeping the extension's runtime proportional to O(findings + correlators).
#>
function New-PrincipalIndex {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    $index = @{}
    if (-not $Findings) { return $index }

    foreach ($f in $Findings) {
        $p = Get-FindingPrincipal -Finding $f
        $keys = @()
        if ($p.UPN) { $keys += $p.UPN.ToLowerInvariant() }
        if ($p.SamAccountName) { $keys += $p.SamAccountName.ToLowerInvariant() }
        if ($keys.Count -eq 0) { continue }

        $src = if ($f.Source) { [string]$f.Source } else { 'Cloud' }

        foreach ($k in ($keys | Select-Object -Unique)) {
            if (-not $index.ContainsKey($k)) {
                $index[$k] = [pscustomobject]@{
                    Key = $k
                    UPN = $p.UPN
                    SamAccountName = $p.SamAccountName
                    CloudFindings = [System.Collections.Generic.List[object]]::new()
                    OnPremFindings = [System.Collections.Generic.List[object]]::new()
                    PrivilegedRoles = [System.Collections.Generic.List[string]]::new()
                }
            }
            $record = $index[$k]
            if ($src -eq 'ActiveDirectory') { $record.OnPremFindings.Add($f) }
            else { $record.CloudFindings.Add($f) }

            # Extract privileged role name from the PrivilegedRoleMember marker.
            # Emitted by Check-DirectoryRolesAndMembers as INFO with Description
            # starting "PrivilegedRoleMember:" and Object "upn (RoleName)".
            if ($f.CheckName -eq 'Check-DirectoryRolesAndMembers' -and
                $f.Status -eq 'INFO' -and
                [string]$f.Description -match '^PrivilegedRoleMember:' -and
                [string]$f.Object -match '\(([^)]+)\)$') {
                $role = $matches[1]
                if (-not $record.PrivilegedRoles.Contains($role)) {
                    $record.PrivilegedRoles.Add($role)
                }
            }
        }
    }

    return $index
}

<#
.SYNOPSIS
    Emits a standard CrossSurfaceFinding record consumed by the renderers.
#>
function New-CrossSurfaceFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$Type,
        [Parameter(Mandatory)] [ValidateSet('Critical', 'High', 'Medium', 'Low')] [string]$Severity,
        [Parameter(Mandatory)] [string]$Principal,
        [string]$OnPremCheck,
        [string]$CloudContext,
        [Parameter(Mandatory)] [string]$Description,
        [Parameter(Mandatory)] [string]$Remediation
    )
    [pscustomobject]@{
        Time = (Get-Date)
        CheckName = $Type
        Type = $Type
        Status = 'FAIL'
        Severity = $Severity
        Category = 'Hybrid'
        Source = 'HybridCorrelation'
        Object = $Principal
        Principal = $Principal
        OnPremCheck = $OnPremCheck
        CloudContext = $CloudContext
        Description = $Description
        Remediation = $Remediation
        ComplianceFrameworks = @('MCSB-IM', 'NIST-AC-6', 'SOC2-CC6.1')
        ComplianceReference = 'MCSB-IM;NIST-AC-6;SOC2-CC6.1'
        RiskScore = switch ($Severity) { 'Critical' { 90 } 'High' { 70 } 'Medium' { 40 } 'Low' { 10 } }
    }
}

<#
.SYNOPSIS
    Correlator 1 - on-prem DACL reach (direct exposure) ∩ cloud admin role.
.DESCRIPTION
    Scans for Critical/High FAIL findings from Test-AuthenticatedUsersDACLReach
    (direct-reach variant only - two-hop is too weak to escalate) and
    Test-WritablePrivilegedACLs. For each, extracts the TARGET principal (the
    privileged user under attack) and checks whether that principal holds any
    cloud privileged role. If yes, emits a Critical cross-surface finding:
    a single on-prem ACE modification grants cloud tenant admin.
#>
function Find-DAExposureToCloudAdmin {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [object[]]$Findings,
        [Parameter(Mandatory)] [hashtable]$PrincipalIndex
    )

    if (-not $Findings) { return @() }
    $results = [System.Collections.Generic.List[object]]::new()

    $candidates = @($Findings | Where-Object {
            $_.Source -eq 'ActiveDirectory' -and
            $_.Status -eq 'FAIL' -and
            $_.CheckName -in @('Test-AuthenticatedUsersDACLReach', 'Test-WritablePrivilegedACLs') -and
            [string]$_.Description -match 'DIRECT reach|GenericAll|GenericWrite|WriteDacl|WriteOwner'
        })

    foreach ($onPrem in $candidates) {
        $p = Get-FindingPrincipal -Finding $onPrem
        $key = if ($p.UPN) { $p.UPN.ToLowerInvariant() } elseif ($p.SamAccountName) { $p.SamAccountName.ToLowerInvariant() } else { $null }
        if (-not $key -or -not $PrincipalIndex.ContainsKey($key)) { continue }

        $record = $PrincipalIndex[$key]
        if (@($record.PrivilegedRoles).Count -eq 0) { continue }

        $roles = ($record.PrivilegedRoles -join ', ')
        $results.Add((New-CrossSurfaceFinding `
                    -Type 'HybridCrossSurface_DAExposureToCloudAdmin' `
                    -Severity 'Critical' `
                    -Principal $key `
                    -OnPremCheck $onPrem.CheckName `
                    -CloudContext "PrivilegedRoles: $roles" `
                    -Description "Principal '$key' has DIRECT on-prem ACL exposure ($($onPrem.CheckName)) AND holds cloud privileged role(s): $roles. A single AD ACE modification grants cloud tenant admin - one-step hybrid takeover path." `
                    -Remediation "Fix the underlying on-prem ACE (see the AD finding). Audit AD ACLs on every synced cloud admin. Strongly consider making cloud admins cloud-only accounts (no on-prem source) so on-prem compromise cannot pivot to the tenant."))
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
    Correlator 2 - DnsAdmins membership ∩ cloud privileged role.
.DESCRIPTION
    If any DnsAdmins member also holds a privileged cloud role, compromise
    of either side leads to the other. Severity inherits the on-prem
    tiering: Critical on legacy DC OS (CVE-2021-40469-class), High on modern.
#>
function Find-DnsAdminsWithCloudPrivilege {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [object[]]$Findings,
        [Parameter(Mandatory)] [hashtable]$PrincipalIndex
    )

    if (-not $Findings) { return @() }
    $results = [System.Collections.Generic.List[object]]::new()

    $dnsAdmin = @($Findings | Where-Object {
            $_.Source -eq 'ActiveDirectory' -and
            $_.CheckName -eq 'Test-DNSAdminsPrivilege' -and
            $_.Status -in @('FAIL', 'WARNING')
        })
    if ($dnsAdmin.Count -eq 0) { return @() }

    # Detect legacy severity from the description of any DnsAdmins finding.
    $legacy = $dnsAdmin | Where-Object { [string]$_.Description -match 'legacy DC|Server 2016|Server 2012|Server 2008' }
    $severity = if ($legacy) { 'Critical' } else { 'High' }

    # Extract member names from the description: "DnsAdmins has N member(s): name [class]; name [class]".
    foreach ($finding in $dnsAdmin) {
        $desc = [string]$finding.Description
        if ($desc -notmatch 'member\(s\):\s*(.+?)\.\s') { continue }
        $memberBlob = $matches[1]
        # Split by "; " and strip " [class]" decoration.
        $memberNames = @($memberBlob -split ';\s*' | ForEach-Object { ($_ -replace '\s*\[[^\]]+\]', '').Trim() } | Where-Object { $_ })

        foreach ($name in $memberNames) {
            $key = $name.ToLowerInvariant()
            if (-not $PrincipalIndex.ContainsKey($key)) { continue }
            $record = $PrincipalIndex[$key]
            if (@($record.PrivilegedRoles).Count -eq 0) { continue }

            $roles = ($record.PrivilegedRoles -join ', ')
            $context = if ($severity -eq 'Critical') { 'legacy DC OS present - CVE-2021-40469 class' } else { 'modern DCs only - zone-tampering vector' }
            $results.Add((New-CrossSurfaceFinding `
                        -Type 'HybridCrossSurface_DnsAdminsWithCloudPrivilege' `
                        -Severity $severity `
                        -Principal $name `
                        -OnPremCheck 'Test-DNSAdminsPrivilege' `
                        -CloudContext "PrivilegedRoles: $roles" `
                        -Description "Principal '$name' is a member of DnsAdmins on-prem ($context) AND holds cloud privileged role(s): $roles. Compromise on either plane pivots to the other." `
                        -Remediation "Remove '$name' from DnsAdmins if not business-critical. Upgrade all DCs to Server 2019+ for ServerLevelPluginDll hardening. Treat DnsAdmins membership as Tier 0 and subject it to PIM / conditional access on the cloud side."))
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
    Correlator 3 - Shadow Credentials target ∩ cloud-synced admin.
.DESCRIPTION
    If a Shadow Credentials finding names a user whose cloud identity also
    holds a privileged role, writing msDS-KeyCredentialLink yields a PKINIT
    cert authenticating as that user - and via sync, their cloud session.
#>
function Find-ShadowCredentialsOnCloudSyncedAdmin {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [object[]]$Findings,
        [Parameter(Mandatory)] [hashtable]$PrincipalIndex
    )

    if (-not $Findings) { return @() }
    $results = [System.Collections.Generic.List[object]]::new()

    $candidates = @($Findings | Where-Object {
            $_.Source -eq 'ActiveDirectory' -and
            $_.CheckName -eq 'Test-ShadowCredentialsVulnerable' -and
            $_.Status -eq 'FAIL'
        })

    foreach ($onPrem in $candidates) {
        $p = Get-FindingPrincipal -Finding $onPrem
        $key = if ($p.UPN) { $p.UPN.ToLowerInvariant() } elseif ($p.SamAccountName) { $p.SamAccountName.ToLowerInvariant() } else { $null }
        if (-not $key -or -not $PrincipalIndex.ContainsKey($key)) { continue }

        $record = $PrincipalIndex[$key]
        if (@($record.PrivilegedRoles).Count -eq 0) { continue }

        $roles = ($record.PrivilegedRoles -join ', ')
        $results.Add((New-CrossSurfaceFinding `
                    -Type 'HybridCrossSurface_ShadowCredentialsOnCloudSyncedAdmin' `
                    -Severity 'Critical' `
                    -Principal $key `
                    -OnPremCheck 'Test-ShadowCredentialsVulnerable' `
                    -CloudContext "PrivilegedRoles: $roles" `
                    -Description "Principal '$key' is writable via msDS-KeyCredentialLink on-prem (Shadow Credentials) AND holds cloud privileged role(s): $roles. Attacker can write a key credential, PKINIT-authenticate as the user, and pivot to cloud admin via the synced identity." `
                    -Remediation "Remove the non-admin write ACE on msDS-KeyCredentialLink for this account. Consider Protected Users membership (blocks NTLM + restricts Kerberos). For synced cloud admins specifically, migrate to cloud-only admin accounts."))
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
    Correlator 4 - RBCD source principal ∩ cloud-privileged identity.
.DESCRIPTION
    Test-RBCDConfigured findings on DC / Tier 0 computers list the RBCD
    SOURCE principal in the description. If that source is also a cloud-
    privileged principal, cloud compromise yields on-prem impersonation.
    Scoped to FAIL severity only (DCs and Tier 0); non-Tier-0 RBCD is INFO
    in the on-prem check and not escalated here.
#>
function Find-RBCDOnPrivilegedTier0Targeting {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [object[]]$Findings,
        [Parameter(Mandatory)] [hashtable]$PrincipalIndex
    )

    if (-not $Findings) { return @() }
    $results = [System.Collections.Generic.List[object]]::new()

    $candidates = @($Findings | Where-Object {
            $_.Source -eq 'ActiveDirectory' -and
            $_.CheckName -eq 'Test-RBCDConfigured' -and
            $_.Status -eq 'FAIL'
        })

    foreach ($onPrem in $candidates) {
        $desc = [string]$onPrem.Description
        # PR 4a Test-RBCDConfigured description pattern includes "allowing impersonation by: <principals>".
        # Capture non-greedy up to a sentence terminator ("." followed by whitespace, or end-of-string)
        # so UPNs with internal dots (foo@bar.com) survive.
        if ($desc -notmatch 'allow(?:ing|s)?\s+impersonation\s+by:?\s*(.+?)(?:\.\s|$)') {
            Write-Verbose "RBCD source principal not extractable from: $($onPrem.Object)"
            continue
        }
        $sourceBlob = $matches[1]
        $sourceNames = @($sourceBlob -split ',\s*|;\s*' | ForEach-Object { ($_ -replace '\s*\([^)]+\)', '').Trim() } | Where-Object { $_ -and $_ -notmatch '^\s*$' })

        foreach ($name in $sourceNames) {
            $key = $name.ToLowerInvariant()
            if (-not $PrincipalIndex.ContainsKey($key)) { continue }
            $record = $PrincipalIndex[$key]
            if (@($record.PrivilegedRoles).Count -eq 0) { continue }

            $roles = ($record.PrivilegedRoles -join ', ')
            $results.Add((New-CrossSurfaceFinding `
                        -Type 'HybridCrossSurface_RBCDOnPrivilegedTier0Targeting' `
                        -Severity 'High' `
                        -Principal $name `
                        -OnPremCheck 'Test-RBCDConfigured' `
                        -CloudContext "PrivilegedRoles: $roles ; RBCDTarget: $($onPrem.Object)" `
                        -Description "RBCD is configured on Tier 0 target '$($onPrem.Object)' permitting impersonation by '$name', who holds cloud privileged role(s): $roles. Cloud-side compromise of '$name' would yield on-prem Tier 0 impersonation; on-prem Tier 0 compromise pivots to cloud admin." `
                        -Remediation "Remove the RBCD entry on '$($onPrem.Object)' (clear msDS-AllowedToActOnBehalfOfOtherIdentity) unless explicitly required. Treat '$name' as Tier 0 and enforce PIM + conditional access. Review why a cloud-privileged principal has RBCD to on-prem infrastructure."))
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
    Correlator 5 - IdentityProtection risky user ∩ on-prem privileged group.
.DESCRIPTION
    An IdentityProtection FAIL finding names a risky user; if that user is
    also a member of an on-prem privileged group (Test-PrivilegedGroupMembership
    emits per-member findings), the cloud-detected risk directly endangers AD.
    Inherits severity from the cloud side; floors at High when the on-prem
    finding implicates DA / EA / SA.
#>
function Find-RiskyUserWithOnPremPrivilege {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [object[]]$Findings,
        [Parameter(Mandatory)] [hashtable]$PrincipalIndex
    )

    if (-not $Findings) { return @() }
    $results = [System.Collections.Generic.List[object]]::new()

    $riskyFindings = @($Findings | Where-Object {
            $_.CheckName -like '*Risky*' -and
            $_.Status -eq 'FAIL'
        })

    foreach ($risky in $riskyFindings) {
        $p = Get-FindingPrincipal -Finding $risky
        $key = if ($p.UPN) { $p.UPN.ToLowerInvariant() } elseif ($p.SamAccountName) { $p.SamAccountName.ToLowerInvariant() } else { $null }
        if (-not $key -or -not $PrincipalIndex.ContainsKey($key)) { continue }

        $record = $PrincipalIndex[$key]
        $onPremPriv = @($record.OnPremFindings | Where-Object {
                $_.CheckName -in @('Test-PrivilegedGroupMembership', 'Test-PrivilegedGroupCreep', 'Test-RecentPrivilegedAccounts') -and
                $_.Status -in @('FAIL', 'WARNING')
            })
        if ($onPremPriv.Count -eq 0) { continue }

        $tier0 = $onPremPriv | Where-Object { [string]$_.Description -match 'Domain Admins|Enterprise Admins|Schema Admins|Administrators' }
        $cloudSev = if ($risky.Severity) { [string]$risky.Severity } else { 'High' }
        $severity = if ($tier0) {
            if ($cloudSev -in @('Critical')) { 'Critical' } else { 'High' }
        }
        else {
            if ($cloudSev -in @('Critical', 'High')) { $cloudSev } else { 'Medium' }
        }

        $onPremSummary = ($onPremPriv | Select-Object -First 3 | ForEach-Object { $_.CheckName }) -join ', '
        $results.Add((New-CrossSurfaceFinding `
                    -Type 'HybridCrossSurface_RiskyUserWithOnPremPrivilege' `
                    -Severity $severity `
                    -Principal $key `
                    -OnPremCheck $onPremSummary `
                    -CloudContext "RiskyUser: $($risky.CheckName) [$cloudSev]" `
                    -Description "Principal '$key' is flagged risky by IdentityProtection AND holds on-prem privileged group membership ($onPremSummary). Cloud-side compromise indicators directly threaten AD." `
                    -Remediation "Investigate the IdentityProtection risk event immediately. If the account is synced, consider temporary disablement or password reset. Long-term: migrate privileged on-prem accounts behind PIM + MFA + conditional access."))
    }

    return $results.ToArray()
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-HybridIdentityCorrelation',
    'Get-MaxSeverity',
    # PR 5 - cross-surface correlators
    'New-PrincipalIndex',
    'New-CrossSurfaceFinding',
    'Find-DAExposureToCloudAdmin',
    'Find-DnsAdminsWithCloudPrivilege',
    'Find-ShadowCredentialsOnCloudSyncedAdmin',
    'Find-RBCDOnPrivilegedTier0Targeting',
    'Find-RiskyUserWithOnPremPrivilege'
)

#endregion
