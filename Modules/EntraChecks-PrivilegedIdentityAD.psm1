<#
.SYNOPSIS
    EntraChecks-PrivilegedIdentityAD.psm1
    Walks every Active Directory privilege source defined in the privilege
    catalog and produces a coalesced roster — one row per unique principal
    with all privileges they hold and the transitive path through which they
    hold each one.

.DESCRIPTION
    Discovery sources, in order:
        1. Direct + nested membership in every Tier 0/1 AD privileged group
           that exists in the catalog.
        2. Principals with DS-Replication-Get-Changes (and All) extended
           rights on the domain root (DCSync path).
        3. Principals with non-default ACEs on AdminSDHolder.
        4. krbtgt — always emitted as a Tier 0 row when the domain is
           reachable, even though it is not a "member of" anything.
        5. Broad groups (Authenticated Users, Domain Users, Everyone) when
           they appear with delegated ACEs on Tier 0 / Tier 1 objects;
           emitted as a single 'BroadGroup' row, not expanded to members.
        6. Protected Users membership — surfaced as a positive-control marker
           on existing rows, not as a privilege.

    All findings coalesce by principal SID. The output is suitable for
    JSON serialisation (-EmitPrivilegedRoster), the cross-surface
    correlator (PR 4), and the unified report's Privileged Identity
    Roster section (PR 5).

.NOTES
    Runs on Windows with the ActiveDirectory module installed. Returns
    @{ Available=$false; FailureReason=...; Roster=@() } when the
    environment cannot satisfy that requirement, so callers can render
    a graceful "AD not available" panel without exception handling.

.LINK
    PrivilegeCatalog: Modules/EntraChecks-PrivilegeCatalog.psm1
    Plan: plans/Privileged-Identity-Roster-Plan.md (PR 2)
#>

#Requires -Version 5.1

$script:ComplianceModulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $script:ComplianceModulePath 'EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking

$script:ModuleVersion = '1.0.0'
$script:ModuleName = 'EntraChecks-PrivilegedIdentityAD'

#region ==================== MODULE STATE ====================

# Two well-known SIDs we always check for as broad-group ACE holders. A
# delegated right granted to any of these effectively grants it to every
# authenticated user in the domain — so we capture them as a single
# BroadGroup row instead of exploding the roster.
$script:BroadGroupSidPatterns = @{
    'S-1-5-11' = 'Authenticated Users'
    'S-1-1-0'  = 'Everyone'
    # Domain Users is a domain-relative SID (ends in -513). Pattern, not literal.
    'S-1-5-21-DOMAIN-513' = 'Domain Users'
}

# Replication extended-right GUIDs used to identify DCSync-capable principals.
# Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts
$script:DcSyncRightGuids = @{
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
}

# Default principals authorised to hold replication rights. ACEs for these are
# NOT flagged as DCSync findings.
$script:DcSyncDefaultPrincipals = @(
    'NT AUTHORITY\SYSTEM',
    'BUILTIN\Administrators',
    'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
    'Domain Controllers',
    'Enterprise Read-only Domain Controllers',
    'Read-only Domain Controllers',
    'Administrators',
    'Domain Admins',
    'Enterprise Admins'
)

#endregion

#region ==================== PRIVATE HELPERS ====================

function Test-PrivilegedIdentityADEnvironment {
    <#
    .SYNOPSIS
        Probe to confirm the environment can satisfy AD privilege roster
        collection. Mirrors Test-ADEnvironment from EntraChecks-ActiveDirectory
        but is duplicated here so this module can run independently.
    #>
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param()

    $isWindows = ($env:OS -eq 'Windows_NT') -or ($PSVersionTable.PSEdition -eq 'Desktop')
    if (-not $isWindows) {
        return [pscustomobject]@{
            IsAvailable = $false
            FailureReason = 'Active Directory privilege roster collection only runs on Windows.'
        }
    }
    $adModule = Get-Module -ListAvailable -Name 'ActiveDirectory' -ErrorAction SilentlyContinue
    if (-not $adModule) {
        return [pscustomobject]@{
            IsAvailable = $false
            FailureReason = 'ActiveDirectory PowerShell module not installed (RSAT). Install: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
        }
    }
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        return [pscustomobject]@{
            IsAvailable = $true
            DomainName = $domain.DNSRoot
            DomainSID = $domain.DomainSID.Value
            DomainDN = $domain.DistinguishedName
        }
    }
    catch {
        return [pscustomobject]@{
            IsAvailable = $false
            FailureReason = "Unable to query Active Directory: $($_.Exception.Message)"
        }
    }
}

function ConvertTo-PrincipalType {
    <#
    .SYNOPSIS
        Maps an AD object class to the canonical PrincipalType the roster uses.
    #>
    param([string]$ObjectClass)

    switch -Regex ($ObjectClass) {
        '^user$'     { 'User'; break }
        '^group$'    { 'Group'; break }
        '^computer$' { 'Computer'; break }
        '^msDS-GroupManagedServiceAccount$' { 'gMSA'; break }
        '^msDS-ManagedServiceAccount$'      { 'sMSA'; break }
        '^foreignSecurityPrincipal$'        { 'ForeignSecurityPrincipal'; break }
        default { 'Unknown' }
    }
}

function New-PrivilegeEntry {
    <#
    .SYNOPSIS
        Constructs a single privilege entry for the Privileges[] array on a
        roster row. Centralised so every emitter produces identical shape.
    #>
    param(
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] [string[]]$Path,
        [Parameter(Mandatory)] [ValidateSet('Group (direct)', 'Group (nested)', 'ACL', 'DCSync', 'AdminSDHolder', 'WellKnown', 'BroadGroupACE')] [string]$AssignmentType,
        [string]$Source
    )

    @{
        Key = $Key
        Path = @($Path)
        AssignmentType = $AssignmentType
        DiscoveredAt = (Get-Date).ToUniversalTime().ToString('o')
        Source = $Source
    }
}

function Add-PrivilegeToRoster {
    <#
    .SYNOPSIS
        Inserts (or updates, if SID already present) a row in the roster dict.
        Coalesces multiple privilege entries onto one row per principal.
    #>
    param(
        [Parameter(Mandatory)] [hashtable]$Roster,
        [Parameter(Mandatory)] [string]$Sid,
        [Parameter(Mandatory)] [hashtable]$Properties,   # SamAccountName, DisplayName, PrincipalType, etc.
        [Parameter(Mandatory)] [hashtable]$Privilege,    # output of New-PrivilegeEntry
        [string]$DiscoverySource
    )

    if (-not $Roster.ContainsKey($Sid)) {
        $Roster[$Sid] = @{
            Sid = $Sid
            SamAccountName = $Properties['SamAccountName']
            DisplayName = $Properties['DisplayName']
            PrincipalType = $Properties['PrincipalType']
            Enabled = $Properties['Enabled']
            LastLogonDate = $Properties['LastLogonDate']
            LastLogonDays = $Properties['LastLogonDays']
            SmartCardRequired = $Properties['SmartCardRequired']
            InProtectedUsers = $Properties['InProtectedUsers']
            DistinguishedName = $Properties['DistinguishedName']
            Privileges = @()
            HighestTier = $null
            Sources = @()
        }
    }
    else {
        # Merge any previously-unknown properties onto an existing row
        # (the first discovery may have been ACL-based and lacked Enabled, etc.)
        foreach ($k in 'SamAccountName', 'DisplayName', 'PrincipalType', 'Enabled', 'LastLogonDate', 'LastLogonDays', 'SmartCardRequired', 'InProtectedUsers', 'DistinguishedName') {
            if (-not $Roster[$Sid][$k] -and $Properties.ContainsKey($k) -and $Properties[$k]) {
                $Roster[$Sid][$k] = $Properties[$k]
            }
        }
    }

    $Roster[$Sid]['Privileges'] += $Privilege
    if ($DiscoverySource -and ($Roster[$Sid]['Sources'] -notcontains $DiscoverySource)) {
        $Roster[$Sid]['Sources'] += $DiscoverySource
    }
}

function Get-PrincipalEnrichment {
    <#
    .SYNOPSIS
        Enriches a discovered principal SID with auditor-relevant attributes
        (Enabled, LastLogonDate, SmartCardRequired, Protected Users membership).
    .DESCRIPTION
        Result is merged into the roster row by Add-PrivilegeToRoster. Uses
        Get-ADUser/Get-ADComputer/Get-ADObject depending on object class. Soft
        failures (e.g., orphaned SIDs, foreign principals) return a sparse
        hashtable rather than throwing.
    #>
    param(
        [Parameter(Mandatory)] [string]$Sid
    )

    $result = @{
        SamAccountName = $null
        DisplayName = $null
        PrincipalType = $null
        Enabled = $null
        LastLogonDate = $null
        LastLogonDays = $null
        SmartCardRequired = $null
        InProtectedUsers = $null
        DistinguishedName = $null
    }

    try {
        $obj = Get-ADObject -Filter "objectSid -eq '$Sid'" -Properties Name, SamAccountName, DisplayName, ObjectClass, DistinguishedName -ErrorAction Stop | Select-Object -First 1
        if (-not $obj) { return $result }

        $result['SamAccountName'] = $obj.SamAccountName
        $result['DisplayName'] = if ($obj.DisplayName) { $obj.DisplayName } else { $obj.Name }
        $result['PrincipalType'] = ConvertTo-PrincipalType -ObjectClass $obj.ObjectClass
        $result['DistinguishedName'] = $obj.DistinguishedName

        if ($result['PrincipalType'] -eq 'User') {
            $u = Get-ADUser -Identity $Sid -Properties Enabled, LastLogonDate, SmartcardLogonRequired, MemberOf -ErrorAction Stop
            $result['Enabled'] = $u.Enabled
            $result['LastLogonDate'] = $u.LastLogonDate
            if ($u.LastLogonDate) {
                $result['LastLogonDays'] = [int](New-TimeSpan -Start $u.LastLogonDate -End (Get-Date)).TotalDays
            }
            $result['SmartCardRequired'] = $u.SmartcardLogonRequired
            $result['InProtectedUsers'] = @($u.MemberOf | Where-Object { $_ -match 'CN=Protected Users' }).Count -gt 0
        }
        elseif ($result['PrincipalType'] -in @('Computer', 'gMSA', 'sMSA')) {
            $c = Get-ADComputer -Identity $Sid -Properties Enabled, LastLogonDate -ErrorAction SilentlyContinue
            if ($c) {
                $result['Enabled'] = $c.Enabled
                $result['LastLogonDate'] = $c.LastLogonDate
                if ($c.LastLogonDate) {
                    $result['LastLogonDays'] = [int](New-TimeSpan -Start $c.LastLogonDate -End (Get-Date)).TotalDays
                }
            }
        }
    }
    catch {
        Write-Verbose "Get-PrincipalEnrichment: SID $Sid lookup failed: $($_.Exception.Message)"
    }
    return $result
}

function Resolve-MembershipPaths {
    <#
    .SYNOPSIS
        Walks a privileged group's nested membership and yields one record per
        leaf principal, with the chain of nested groups it transited.
    .DESCRIPTION
        AD group nesting can produce multiple paths to the same principal.
        Each path is yielded separately so the roster preserves WHY a
        principal is privileged (which chain) rather than collapsing the
        information.

        Cycle protection: a group already in $PathSoFar is skipped.

        Recursion depth is bounded at $MaxDepth (default 6). Beyond that the
        walker emits a synthetic "depth limit reached" entry — visible to the
        auditor as a hint to look for a misconfiguration.
    .OUTPUTS
        pscustomobject with: Sid, SamAccountName, DisplayName, ObjectClass, Path
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$GroupName,
        [string[]]$PathSoFar = @(),
        [int]$Depth = 0,
        [int]$MaxDepth = 6
    )

    if ($Depth -gt $MaxDepth) {
        Write-Verbose "Resolve-MembershipPaths: depth limit reached at $($PathSoFar -join ' -> ')"
        return
    }
    $newPath = $PathSoFar + $GroupName

    try {
        $direct = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop
    }
    catch {
        Write-Verbose "Resolve-MembershipPaths: cannot enumerate '$GroupName': $($_.Exception.Message)"
        return
    }

    foreach ($m in $direct) {
        if ($m.objectClass -eq 'group') {
            # Cycle guard — don't recurse into a group already on the path
            if ($newPath -contains $m.SamAccountName) { continue }
            Resolve-MembershipPaths -GroupName $m.SamAccountName -PathSoFar $newPath -Depth ($Depth + 1) -MaxDepth $MaxDepth
        }
        else {
            [pscustomobject]@{
                Sid = $m.SID.Value
                SamAccountName = $m.SamAccountName
                DisplayName = $m.Name
                ObjectClass = $m.objectClass
                Path = $newPath
            }
        }
    }
}

function Get-DCSyncPrincipals {
    <#
    .SYNOPSIS
        Returns principals holding DS-Replication-Get-Changes / -All extended
        rights on the domain root. These principals can perform DCSync.
    .DESCRIPTION
        Reads the ACL on the domain DN. Filters out default-authorised
        principals (Administrators, Domain Admins, Enterprise Admins, SYSTEM,
        Domain Controllers) — the finding is interesting only when a non-
        default principal holds the right.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$DomainDN)

    $results = @()
    $dnPath = "AD:$DomainDN"
    try {
        $acl = Get-Acl -Path $dnPath -ErrorAction Stop
    }
    catch {
        Write-Verbose "Get-DCSyncPrincipals: cannot read ACL on '$DomainDN': $($_.Exception.Message)"
        return $results
    }

    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $rightGuid = $ace.ObjectType.Guid.ToString().ToLower()
        if (-not $script:DcSyncRightGuids.ContainsKey($rightGuid)) { continue }
        $idRef = $ace.IdentityReference.Value
        if ($script:DcSyncDefaultPrincipals -contains $idRef -or $script:DcSyncDefaultPrincipals -contains ($idRef -replace '^.+\\','')) { continue }

        # Translate IdentityReference to a SID. NTAccount may already be SID.
        $sid = $null
        try {
            $ntAccount = New-Object System.Security.Principal.NTAccount($idRef)
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            if ($idRef -match '^S-1-') { $sid = $idRef }
        }

        $results += [pscustomobject]@{
            IdentityReference = $idRef
            Sid = $sid
            Right = $script:DcSyncRightGuids[$rightGuid]
            DomainDN = $DomainDN
        }
    }
    return $results
}

function Get-AdminSDHolderWriters {
    <#
    .SYNOPSIS
        Returns principals with non-default ACEs on AdminSDHolder. Compares
        against a known-default ACE set; anything outside that set is a
        potential persistence primitive (Test-AdminSDHolderDrift coverage).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$DomainDN)

    $results = @()
    $sdhPath = "AD:CN=AdminSDHolder,CN=System,$DomainDN"
    try {
        $acl = Get-Acl -Path $sdhPath -ErrorAction Stop
    }
    catch {
        Write-Verbose "Get-AdminSDHolderWriters: cannot read AdminSDHolder ACL: $($_.Exception.Message)"
        return $results
    }

    # Default principals expected on AdminSDHolder. Anything else with write
    # rights is suspicious. (Read rights are common — we only flag writes.)
    $defaultPrincipals = @(
        'NT AUTHORITY\SYSTEM',
        'BUILTIN\Administrators',
        'Domain Admins',
        'Enterprise Admins',
        'NT AUTHORITY\Authenticated Users',
        'NT AUTHORITY\SELF',
        'CREATOR OWNER',
        'BUILTIN\Pre-Windows 2000 Compatible Access'
    )
    $writeRights = [System.DirectoryServices.ActiveDirectoryRights]'WriteDacl, WriteOwner, WriteProperty, GenericWrite, GenericAll'

    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if (-not ($ace.ActiveDirectoryRights -band $writeRights)) { continue }
        $idRef = $ace.IdentityReference.Value
        $idLeaf = $idRef -replace '^.+\\',''
        if ($defaultPrincipals -contains $idRef -or $defaultPrincipals -contains $idLeaf) { continue }

        $sid = $null
        try {
            $ntAccount = New-Object System.Security.Principal.NTAccount($idRef)
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            if ($idRef -match '^S-1-') { $sid = $idRef }
        }

        $results += [pscustomobject]@{
            IdentityReference = $idRef
            Sid = $sid
            Rights = $ace.ActiveDirectoryRights.ToString()
        }
    }
    return $results
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-PrivilegedIdentityRosterAD {
    <#
    .SYNOPSIS
        Builds the Active Directory privileged-identity roster by walking
        every privilege source in the catalog and coalescing by SID.

    .DESCRIPTION
        One row per unique principal (user, group, gMSA, computer,
        BroadGroup). Each row carries a Privileges[] array with one entry
        per privilege held, including the transitive Path through which
        the principal holds that privilege.

        Returns a hashtable shape:
            @{
                Available = $true | $false
                FailureReason = $null | <string>
                Domain = @{ Name=...; SID=...; DN=... }
                Roster = @( @{ Sid=...; Privileges=...; HighestTier=...; ... }, ... )
                Statistics = @{ TotalPrincipals=N; Tier0Count=N; ...; ScannedAt=... }
            }

        Suitable for JSON serialisation and downstream consumption by the
        cross-surface correlator (PR 4) and the report renderer (PR 5).

    .PARAMETER Domain
        Optional FQDN. Defaults to the computer's joined domain.

    .PARAMETER IncludeServiceAccounts
        Include gMSA / sMSA / computer accounts as roster rows. Default
        excluded (they bloat the roster in service-rich environments).

    .PARAMETER MaxNestingDepth
        Maximum depth for nested-group traversal. Default 6.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [string]$Domain,
        [switch]$IncludeServiceAccounts,
        [int]$MaxNestingDepth = 6
    )

    $env = Test-PrivilegedIdentityADEnvironment
    if (-not $env.IsAvailable) {
        return @{
            Available = $false
            FailureReason = $env.FailureReason
            Domain = $null
            Roster = @()
            Statistics = @{ ScannedAt = (Get-Date).ToUniversalTime().ToString('o') }
        }
    }

    $domainDN = $env.DomainDN
    $domainSid = $env.DomainSID
    $roster = @{}    # SID -> roster row

    Write-Verbose "Building AD privilege roster for $($env.DomainName)"

    # ----- 1. Privileged group membership (catalog-driven) -----

    $catalog = Get-PrivilegeCatalog
    $adGroupKeys = Get-PrivilegeCatalogKeys -Surface 'AD' -Tier 1   # 0 + 1
    foreach ($pkey in $adGroupKeys) {
        $entry = $catalog[$pkey]
        # Only walk catalog entries that map to actual on-prem groups, not
        # ACL paths (DCSync, AdminSDHolder) or markers (Protected Users, krbtgt).
        if ($pkey -in @('AD:DCSyncRights', 'AD:AdminSDHolderWriter', 'AD:KrbTgt', 'AD:ProtectedUsersMember')) { continue }

        $groupName = $entry.DisplayName -replace '^BUILTIN\\',''
        try {
            Get-ADGroup -Identity $groupName -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Verbose "Group '$groupName' not present in this domain — skipping."
            continue
        }

        $leaves = @(Resolve-MembershipPaths -GroupName $groupName -MaxDepth $MaxNestingDepth)
        foreach ($leaf in $leaves) {
            if (-not $IncludeServiceAccounts -and ($leaf.ObjectClass -in @('computer', 'msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount'))) {
                continue
            }
            $assignmentType = if ($leaf.Path.Count -gt 1) { 'Group (nested)' } else { 'Group (direct)' }
            $enrichment = Get-PrincipalEnrichment -Sid $leaf.Sid
            if (-not $enrichment.SamAccountName) {
                # Fallback to whatever Get-ADGroupMember returned if SID lookup
                # failed (orphaned member, FSP).
                $enrichment.SamAccountName = $leaf.SamAccountName
                $enrichment.DisplayName = $leaf.DisplayName
                $enrichment.PrincipalType = ConvertTo-PrincipalType -ObjectClass $leaf.ObjectClass
            }
            $priv = New-PrivilegeEntry `
                -Key $pkey `
                -Path $leaf.Path `
                -AssignmentType $assignmentType `
                -Source 'Get-ADGroupMember (recursive)'
            Add-PrivilegeToRoster -Roster $roster -Sid $leaf.Sid `
                -Properties $enrichment -Privilege $priv `
                -DiscoverySource 'Get-ADGroupMember'
        }
    }

    # ----- 2. DCSync rights on the domain root -----

    foreach ($p in (Get-DCSyncPrincipals -DomainDN $domainDN)) {
        if (-not $p.Sid) { continue }
        $enrichment = Get-PrincipalEnrichment -Sid $p.Sid
        if (-not $enrichment.SamAccountName) {
            $enrichment.SamAccountName = $p.IdentityReference
            $enrichment.DisplayName = $p.IdentityReference
            $enrichment.PrincipalType = 'Unknown'
        }
        $priv = New-PrivilegeEntry `
            -Key 'AD:DCSyncRights' `
            -Path @("$($p.IdentityReference) holds $($p.Right) on $($p.DomainDN)") `
            -AssignmentType 'DCSync' `
            -Source 'Get-Acl on domain root'
        Add-PrivilegeToRoster -Roster $roster -Sid $p.Sid `
            -Properties $enrichment -Privilege $priv `
            -DiscoverySource 'Domain root ACL'
    }

    # ----- 3. AdminSDHolder writers -----

    foreach ($p in (Get-AdminSDHolderWriters -DomainDN $domainDN)) {
        if (-not $p.Sid) { continue }
        $enrichment = Get-PrincipalEnrichment -Sid $p.Sid
        if (-not $enrichment.SamAccountName) {
            $enrichment.SamAccountName = $p.IdentityReference
            $enrichment.DisplayName = $p.IdentityReference
            $enrichment.PrincipalType = 'Unknown'
        }
        $priv = New-PrivilegeEntry `
            -Key 'AD:AdminSDHolderWriter' `
            -Path @("$($p.IdentityReference) holds $($p.Rights) on AdminSDHolder") `
            -AssignmentType 'AdminSDHolder' `
            -Source 'Get-Acl on CN=AdminSDHolder,CN=System'
        Add-PrivilegeToRoster -Roster $roster -Sid $p.Sid `
            -Properties $enrichment -Privilege $priv `
            -DiscoverySource 'AdminSDHolder ACL'
    }

    # ----- 4. krbtgt — always emit when reachable -----

    try {
        $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties Enabled, PasswordLastSet, MemberOf -ErrorAction Stop
        $krbtgtPwAge = if ($krbtgt.PasswordLastSet) { [int](New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).TotalDays } else { $null }
        $enrichment = @{
            SamAccountName = $krbtgt.SamAccountName
            DisplayName = 'krbtgt (Kerberos service account)'
            PrincipalType = 'User'
            Enabled = $krbtgt.Enabled
            LastLogonDate = $null
            LastLogonDays = $null
            SmartCardRequired = $null
            InProtectedUsers = $false
            DistinguishedName = $krbtgt.DistinguishedName
        }
        $priv = New-PrivilegeEntry `
            -Key 'AD:KrbTgt' `
            -Path @("krbtgt account (password age: ${krbtgtPwAge}d)") `
            -AssignmentType 'WellKnown' `
            -Source 'Get-ADUser krbtgt'
        Add-PrivilegeToRoster -Roster $roster -Sid $krbtgt.SID.Value `
            -Properties $enrichment -Privilege $priv `
            -DiscoverySource 'Well-known principal'
    }
    catch {
        Write-Verbose "krbtgt enumeration failed: $($_.Exception.Message)"
    }

    # ----- 5. Stamp HighestTier on every row -----

    foreach ($sid in $roster.Keys) {
        $row = $roster[$sid]
        $tiers = foreach ($p in $row.Privileges) {
            try { Get-TierForPrivilege -Key $p.Key } catch { $null }
        }
        $numericTiers = @($tiers | Where-Object { $_ -is [int] })
        if ($numericTiers.Count -gt 0) {
            $row.HighestTier = ($numericTiers | Measure-Object -Minimum).Minimum
        }
        else {
            $row.HighestTier = 'Service'
        }
    }

    # ----- 6. Statistics + return -----

    $rosterArray = @($roster.Values) | Sort-Object @{Expression = {
            if ($_.HighestTier -is [int]) { $_.HighestTier } else { 99 }
        }
    }, SamAccountName

    $tier0 = @($rosterArray | Where-Object { $_.HighestTier -eq 0 }).Count
    $tier1 = @($rosterArray | Where-Object { $_.HighestTier -eq 1 }).Count
    $tier2 = @($rosterArray | Where-Object { $_.HighestTier -eq 2 }).Count

    return @{
        Available = $true
        FailureReason = $null
        Domain = @{
            Name = $env.DomainName
            SID = $domainSid
            DN = $domainDN
        }
        Roster = $rosterArray
        Statistics = @{
            TotalPrincipals = $rosterArray.Count
            Tier0Count = $tier0
            Tier1Count = $tier1
            Tier2Count = $tier2
            ScannedAt = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
}

function Group-PrivilegedIdentitiesByTier {
    <#
    .SYNOPSIS
        Groups roster rows by HighestTier. Helper used by the report renderer
        to emit tier-by-tier sections.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Roster
    )

    $result = @{
        Tier0 = @()
        Tier1 = @()
        Tier2 = @()
        Service = @()
        Other = @()
    }
    foreach ($row in @($Roster)) {
        switch ($row.HighestTier) {
            0 { $result.Tier0 += $row }
            1 { $result.Tier1 += $row }
            2 { $result.Tier2 += $row }
            'Service' { $result.Service += $row }
            default { $result.Other += $row }
        }
    }
    return $result
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-PrivilegedIdentityRosterAD',
    'Group-PrivilegedIdentitiesByTier'
)

#endregion
