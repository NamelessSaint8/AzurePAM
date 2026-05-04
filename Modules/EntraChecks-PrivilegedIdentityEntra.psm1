<#
.SYNOPSIS
    EntraChecks-PrivilegedIdentityEntra.psm1
    Walks every Entra ID privilege source defined in the privilege catalog
    and produces a coalesced roster — one row per unique principal
    (user, group, service principal) with all privileges held.

.DESCRIPTION
    Discovery sources, in order:
        1. Active directory-role assignments — every catalog Tier 0/1/2
           Entra role, filtered to the principals actually assigned today.
        2. PIM-eligible directory-role assignments — same scope, gated by
           Entra ID Premium P2. When the API returns 403/license-required,
           the module degrades gracefully and sets PimAvailable=$false.
        3. Service principals with high-risk Microsoft Graph app-role
           assignments — uses the curated MSGraph permissions catalog
           (Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory,
           etc.). Found via Get-MgServicePrincipalAppRoleAssignedTo on the
           MS Graph resource SP, which returns every grant in the tenant
           in one paginated query rather than one per SP.
        4. Owners of any service principal or app on the roster that holds
           a Tier 0 or Tier 1 privilege. Owners can mint credentials and
           impersonate the SP, so they inherit the privilege transitively.

    All discoveries coalesce by principal Object ID. Output shape mirrors
    EntraChecks-PrivilegedIdentityAD.psm1 so the cross-surface correlator
    (PR 4) can merge the two rosters with identical field names.

    Returns @{ Available; FailureReason; Tenant; Roster; Statistics } so
    callers can render a graceful "Entra not available" panel without
    exception handling.

.NOTES
    Required Microsoft Graph scopes:
        - RoleManagement.Read.Directory       (active role assignments)
        - RoleEligibilitySchedule.Read.Directory  (PIM-eligible — P2 license)
        - Application.Read.All                (SP catalog + app role mapping)
        - User.Read.All                       (principal enrichment for users)
        - Group.Read.All                      (principal enrichment for groups)
        - Directory.Read.All                  (broad fallback)

.LINK
    PrivilegeCatalog: Modules/EntraChecks-PrivilegeCatalog.psm1
    Plan: plans/Privileged-Identity-Roster-Plan.md (PR 3)
#>

#Requires -Version 5.1

$script:ModulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $script:ModulePath 'EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking

$script:ModuleVersion = '1.0.0'
$script:ModuleName = 'EntraChecks-PrivilegedIdentityEntra'

#region ==================== MODULE STATE ====================

# Microsoft Graph resource SP — stable across all tenants. Used to resolve
# AppRoleId GUIDs (e.g., 19dbc75e-c2e2-444c-a770-ec69d8559fc7) into permission
# names (e.g., 'Directory.ReadWrite.All').
$script:MicrosoftGraphAppId = '00000003-0000-0000-c000-000000000000'

# Cache populated once per Get-PrivilegedIdentityRosterEntra call:
#   AppRoleId GUID (lowercase) -> permission Value (e.g., 'Directory.ReadWrite.All')
$script:MgAppRoleNameCache = @{}

#endregion

#region ==================== PRIVATE HELPERS ====================

function Test-PrivilegedIdentityEntraEnvironment {
    <#
    .SYNOPSIS
        Probe to confirm Microsoft.Graph is available and a Graph context is
        already established. Returns Available=$false with a concrete
        FailureReason rather than throwing.
    #>
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param()

    $mgModule = Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' -ErrorAction SilentlyContinue
    if (-not $mgModule) {
        return [pscustomobject]@{
            IsAvailable = $false
            FailureReason = 'Microsoft.Graph module not installed. Install: Install-Module Microsoft.Graph -Scope CurrentUser'
        }
    }
    if (-not (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            IsAvailable = $false
            FailureReason = 'Get-MgContext not available — Microsoft.Graph.Authentication is not loaded.'
        }
    }
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        return [pscustomobject]@{
            IsAvailable = $false
            FailureReason = 'No Microsoft Graph context. Run Connect-MgGraph -Scopes RoleManagement.Read.Directory,Application.Read.All,Directory.Read.All before invoking the roster.'
        }
    }
    return [pscustomobject]@{
        IsAvailable = $true
        TenantId = $ctx.TenantId
        Account = $ctx.Account
        AuthType = $ctx.AuthType
        Scopes = @($ctx.Scopes)
    }
}

function ConvertTo-EntraPrincipalType {
    <#
    .SYNOPSIS
        Normalises Microsoft Graph principal type strings to the canonical
        roster value.
    #>
    param([string]$Type)
    switch -Regex ($Type) {
        '^User$'             { 'User'; break }
        '^ServicePrincipal$' { 'ServicePrincipal'; break }
        '^Group$'            { 'Group'; break }
        default              { if ($Type) { $Type } else { 'Unknown' } }
    }
}

function New-EntraPrivilegeEntry {
    <#
    .SYNOPSIS
        Constructs a privilege entry for the Privileges[] array on a roster row.
        Centralised so every emitter produces identical shape.
    #>
    param(
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] [string[]]$Path,
        [Parameter(Mandatory)] [ValidateSet('Active', 'Eligible (PIM)', 'AppRole', 'Owner', 'Unclassified')] [string]$AssignmentType,
        [string]$Source,
        [string]$RoleDefinitionId,
        [datetime]$AssignedDateTime
    )

    $entry = @{
        Key = $Key
        Path = @($Path)
        AssignmentType = $AssignmentType
        DiscoveredAt = (Get-Date).ToUniversalTime().ToString('o')
        Source = $Source
    }
    if ($RoleDefinitionId) { $entry['RoleDefinitionId'] = $RoleDefinitionId }
    if ($AssignedDateTime) { $entry['AssignedDateTime'] = $AssignedDateTime.ToUniversalTime().ToString('o') }
    return $entry
}

function Add-EntraPrivilegeToRoster {
    <#
    .SYNOPSIS
        Inserts (or updates) a row in the roster dict, keyed by Object ID.
    #>
    param(
        [Parameter(Mandatory)] [hashtable]$Roster,
        [Parameter(Mandatory)] [string]$ObjectId,
        [Parameter(Mandatory)] [hashtable]$Properties,
        [Parameter(Mandatory)] [hashtable]$Privilege,
        [string]$DiscoverySource
    )

    if (-not $Roster.ContainsKey($ObjectId)) {
        $Roster[$ObjectId] = @{
            ObjectId = $ObjectId
            PrincipalType = $Properties['PrincipalType']
            Upn = $Properties['Upn']
            DisplayName = $Properties['DisplayName']
            Enabled = $Properties['Enabled']
            LastSignIn = $Properties['LastSignIn']
            AppId = $Properties['AppId']
            ServicePrincipalType = $Properties['ServicePrincipalType']
            OnPremisesSecurityIdentifier = $Properties['OnPremisesSecurityIdentifier']
            Mail = $Properties['Mail']
            Privileges = @()
            HighestTier = $null
            Sources = @()
        }
    }
    else {
        # Merge any newly-known properties onto an existing row
        foreach ($k in 'PrincipalType', 'Upn', 'DisplayName', 'Enabled', 'LastSignIn', 'AppId', 'ServicePrincipalType', 'OnPremisesSecurityIdentifier', 'Mail') {
            if (-not $Roster[$ObjectId][$k] -and $Properties.ContainsKey($k) -and $Properties[$k]) {
                $Roster[$ObjectId][$k] = $Properties[$k]
            }
        }
    }

    $Roster[$ObjectId]['Privileges'] += $Privilege
    if ($DiscoverySource -and ($Roster[$ObjectId]['Sources'] -notcontains $DiscoverySource)) {
        $Roster[$ObjectId]['Sources'] += $DiscoverySource
    }
}

function Get-EntraPrincipalEnrichment {
    <#
    .SYNOPSIS
        Looks up auditor-relevant properties for a principal Object ID.
    .DESCRIPTION
        Tries Get-MgUser / Get-MgServicePrincipal / Get-MgGroup in that order.
        Sign-in activity (LastSignIn) requires P1 — degrades to $null when
        unavailable. Soft failures return a sparse hashtable rather than
        throwing so the roster keeps building.
    #>
    param(
        [Parameter(Mandatory)] [string]$ObjectId,
        [string]$HintedType
    )

    $result = @{
        PrincipalType = $null
        Upn = $null
        DisplayName = $null
        Enabled = $null
        LastSignIn = $null
        AppId = $null
        ServicePrincipalType = $null
        # Match signals consumed by the cross-surface correlator (PR 4).
        OnPremisesSecurityIdentifier = $null
        Mail = $null
    }

    # Try the hinted type first, then fall through.
    $tryUser = $tryGroup = $trySp = $true
    if ($HintedType -eq 'User')             { $tryGroup = $trySp = $false }
    if ($HintedType -eq 'Group')            { $tryUser = $trySp = $false }
    if ($HintedType -eq 'ServicePrincipal') { $tryUser = $tryGroup = $false }

    if ($tryUser) {
        try {
            $u = Get-MgUser -UserId $ObjectId -Property Id, DisplayName, UserPrincipalName, AccountEnabled, SignInActivity, OnPremisesSecurityIdentifier, Mail -ErrorAction Stop
            if ($u) {
                $result['PrincipalType'] = 'User'
                $result['Upn'] = $u.UserPrincipalName
                $result['DisplayName'] = $u.DisplayName
                $result['Enabled'] = $u.AccountEnabled
                if ($u.SignInActivity -and $u.SignInActivity.LastSignInDateTime) {
                    $result['LastSignIn'] = $u.SignInActivity.LastSignInDateTime
                }
                $result['OnPremisesSecurityIdentifier'] = $u.OnPremisesSecurityIdentifier
                $result['Mail'] = $u.Mail
                return $result
            }
        }
        catch {
            Write-Verbose "Get-MgUser miss for $ObjectId — trying SP"
        }
    }

    if ($trySp) {
        try {
            $sp = Get-MgServicePrincipal -ServicePrincipalId $ObjectId -ErrorAction Stop
            if ($sp) {
                $result['PrincipalType'] = 'ServicePrincipal'
                $result['DisplayName'] = $sp.DisplayName
                $result['Enabled'] = $sp.AccountEnabled
                $result['AppId'] = $sp.AppId
                $result['ServicePrincipalType'] = $sp.ServicePrincipalType
                return $result
            }
        }
        catch {
            Write-Verbose "Get-MgServicePrincipal miss for $ObjectId — trying Group"
        }
    }

    if ($tryGroup) {
        try {
            $g = Get-MgGroup -GroupId $ObjectId -ErrorAction Stop
            if ($g) {
                $result['PrincipalType'] = 'Group'
                $result['DisplayName'] = $g.DisplayName
                return $result
            }
        }
        catch {
            Write-Verbose "Get-MgGroup miss for $ObjectId"
        }
    }
    return $result
}

function Get-RoleDefinitionMap {
    <#
    .SYNOPSIS
        Builds a map of role definition ID -> display name (e.g.,
        '62e90394-69f5-4237-9190-012177145e10' -> 'Global Administrator').
    .DESCRIPTION
        One paginated call returns the active directory-role definitions
        in the tenant. Cached for the duration of one roster build.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()

    $map = @{}
    try {
        $defs = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
        foreach ($d in $defs) {
            $map[$d.Id] = $d.DisplayName
        }
    }
    catch {
        Write-Verbose "Get-RoleDefinitionMap failed: $($_.Exception.Message)"
    }
    return $map
}

function Get-MicrosoftGraphAppRoleNames {
    <#
    .SYNOPSIS
        Returns a map of Microsoft Graph AppRoleId GUID -> permission name
        (e.g., 'Directory.ReadWrite.All'). Used to translate app role
        assignments into catalog keys.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()

    if ($script:MgAppRoleNameCache.Count -gt 0) { return $script:MgAppRoleNameCache }

    try {
        $msSp = Get-MgServicePrincipal -Filter "appId eq '$($script:MicrosoftGraphAppId)'" -ErrorAction Stop | Select-Object -First 1
        if (-not $msSp) {
            Write-Verbose 'Microsoft Graph SP not found in tenant.'
            return @{}
        }
        $map = @{}
        foreach ($role in @($msSp.AppRoles)) {
            $map[$role.Id.ToString().ToLower()] = $role.Value
        }
        $script:MgAppRoleNameCache = $map
        return $map
    }
    catch {
        Write-Verbose "Get-MicrosoftGraphAppRoleNames failed: $($_.Exception.Message)"
        return @{}
    }
}

function Resolve-EntraRolePrivilegeKey {
    <#
    .SYNOPSIS
        Resolves a directory-role display name to a catalog key. Falls back
        to a synthetic 'Entra:Other:<Name>' key for non-catalogued roles so
        nothing slips through the roster — the auditor can decide whether
        to add the role to the catalog later.
    #>
    param([Parameter(Mandatory)] [string]$DisplayName)
    $key = Resolve-PrivilegeKey -Surface 'Entra' -Name $DisplayName
    if ($key) { return $key }
    return "Entra:Other:$DisplayName"
}

function Resolve-MsGraphPermissionPrivilegeKey {
    <#
    .SYNOPSIS
        Resolves an MS Graph permission name (e.g., 'Directory.ReadWrite.All')
        to a catalog key. Returns $null when the permission is not in the
        curated high-risk catalog — caller skips it (low-risk grants are
        intentionally out of roster scope).
    #>
    param([Parameter(Mandatory)] [string]$PermissionValue)
    return Resolve-PrivilegeKey -Surface 'MSGraph' -Name $PermissionValue
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-PrivilegedIdentityRosterEntra {
    <#
    .SYNOPSIS
        Builds the Entra ID privileged-identity roster by walking every
        privilege source in the catalog and coalescing by Object ID.

    .PARAMETER ActiveOnly
        Skip the PIM-eligible discovery pass. Default: include eligible
        assignments, marked AssignmentType='Eligible (PIM)'.

    .PARAMETER IncludeAppOwners
        Discover and emit owners of catalogued-privileged service principals
        and applications. Default: included (off only when explicitly disabled).

    .PARAMETER IncludeNonCatalogedRoles
        Include directory roles not in the curated catalog as roster rows
        with key 'Entra:Other:<RoleName>' and HighestTier='Unclassified'.
        Default: included.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [switch]$ActiveOnly,
        [switch]$IncludeAppOwners = $true,
        [switch]$IncludeNonCatalogedRoles = $true
    )

    $env = Test-PrivilegedIdentityEntraEnvironment
    if (-not $env.IsAvailable) {
        return @{
            Available = $false
            FailureReason = $env.FailureReason
            Tenant = $null
            Roster = @()
            Statistics = @{
                ScannedAt = (Get-Date).ToUniversalTime().ToString('o')
                PimAvailable = $null
            }
        }
    }

    # Reset per-call cache
    $script:MgAppRoleNameCache = @{}

    $roster = @{}        # ObjectId -> roster row
    $pimAvailable = $true

    # ----- 1. Active directory-role assignments -----

    Write-Verbose 'Enumerating active directory-role assignments...'
    $roleDefMap = Get-RoleDefinitionMap

    try {
        $activeAssignments = @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop)
    }
    catch {
        Write-Verbose "Active assignments query failed: $($_.Exception.Message)"
        $activeAssignments = @()
    }

    foreach ($a in $activeAssignments) {
        $roleName = if ($roleDefMap.ContainsKey($a.RoleDefinitionId)) { $roleDefMap[$a.RoleDefinitionId] } else { $a.RoleDefinitionId }
        $key = Resolve-EntraRolePrivilegeKey -DisplayName $roleName
        if ((-not $IncludeNonCatalogedRoles) -and $key.StartsWith('Entra:Other:')) { continue }

        $enrichment = Get-EntraPrincipalEnrichment -ObjectId $a.PrincipalId
        $priv = New-EntraPrivilegeEntry `
            -Key $key `
            -Path @("$roleName (active)") `
            -AssignmentType 'Active' `
            -Source 'Get-MgRoleManagementDirectoryRoleAssignment' `
            -RoleDefinitionId $a.RoleDefinitionId
        Add-EntraPrivilegeToRoster -Roster $roster -ObjectId $a.PrincipalId `
            -Properties $enrichment -Privilege $priv -DiscoverySource 'Active role assignment'
    }

    # ----- 2. PIM-eligible directory-role assignments -----

    if (-not $ActiveOnly) {
        Write-Verbose 'Enumerating PIM-eligible directory-role assignments...'
        try {
            $eligible = @(Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop)
        }
        catch {
            $msg = $_.Exception.Message
            # P2 license / 403 — degrade gracefully.
            if ($msg -match '403|Forbidden|License|Premium|requires.*Premium|RoleEligibilitySchedule') {
                Write-Verbose "PIM eligibility query returned: $msg — assuming P2 license is not available."
                $pimAvailable = $false
            }
            else {
                Write-Verbose "PIM eligibility query failed: $msg"
                $pimAvailable = $false
            }
            $eligible = @()
        }

        foreach ($e in $eligible) {
            $roleName = if ($roleDefMap.ContainsKey($e.RoleDefinitionId)) { $roleDefMap[$e.RoleDefinitionId] } else { $e.RoleDefinitionId }
            $key = Resolve-EntraRolePrivilegeKey -DisplayName $roleName
            if ((-not $IncludeNonCatalogedRoles) -and $key.StartsWith('Entra:Other:')) { continue }

            $enrichment = Get-EntraPrincipalEnrichment -ObjectId $e.PrincipalId
            $priv = New-EntraPrivilegeEntry `
                -Key $key `
                -Path @("$roleName (PIM-eligible)") `
                -AssignmentType 'Eligible (PIM)' `
                -Source 'Get-MgRoleManagementDirectoryRoleEligibilitySchedule' `
                -RoleDefinitionId $e.RoleDefinitionId
            Add-EntraPrivilegeToRoster -Roster $roster -ObjectId $e.PrincipalId `
                -Properties $enrichment -Privilege $priv -DiscoverySource 'PIM-eligible assignment'
        }
    }

    # ----- 3. Service principals with high-risk MS Graph app permissions -----

    Write-Verbose 'Enumerating SPs with curated high-risk MS Graph permissions...'
    $msGraphRoleMap = Get-MicrosoftGraphAppRoleNames
    if ($msGraphRoleMap.Count -gt 0) {
        try {
            $msGraphSp = Get-MgServicePrincipal -Filter "appId eq '$($script:MicrosoftGraphAppId)'" -ErrorAction Stop | Select-Object -First 1
            if ($msGraphSp) {
                $appRoleAssignments = @(Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $msGraphSp.Id -All -ErrorAction Stop)
                foreach ($ara in $appRoleAssignments) {
                    $appRoleId = $ara.AppRoleId.ToString().ToLower()
                    if (-not $msGraphRoleMap.ContainsKey($appRoleId)) { continue }
                    $permName = $msGraphRoleMap[$appRoleId]
                    $catalogKey = Resolve-MsGraphPermissionPrivilegeKey -PermissionValue $permName
                    # Only emit grants whose permission appears in the curated catalog
                    if (-not $catalogKey) { continue }

                    $enrichment = Get-EntraPrincipalEnrichment -ObjectId $ara.PrincipalId -HintedType 'ServicePrincipal'
                    $priv = New-EntraPrivilegeEntry `
                        -Key $catalogKey `
                        -Path @("App-role: $permName granted on Microsoft Graph") `
                        -AssignmentType 'AppRole' `
                        -Source 'Get-MgServicePrincipalAppRoleAssignedTo (Microsoft Graph)' `
                        -AssignedDateTime $ara.CreatedDateTime
                    Add-EntraPrivilegeToRoster -Roster $roster -ObjectId $ara.PrincipalId `
                        -Properties $enrichment -Privilege $priv -DiscoverySource 'MS Graph app-role grant'
                }
            }
        }
        catch {
            Write-Verbose "App-role-assignment query failed: $($_.Exception.Message)"
        }
    }

    # ----- 4. Owners of privileged service principals / apps -----

    if ($IncludeAppOwners) {
        Write-Verbose 'Resolving owners of catalogued-privileged service principals...'
        $catalog = Get-PrivilegeCatalog
        # Identify SP rows already on the roster that hold a Tier 0 / Tier 1 privilege.
        $privSpIds = @($roster.Keys | Where-Object {
                $row = $roster[$_]
                if ($row.PrincipalType -ne 'ServicePrincipal') { return $false }
                foreach ($p in $row.Privileges) {
                    $tier = $null
                    if ($catalog.ContainsKey($p.Key)) { $tier = $catalog[$p.Key].Tier }
                    if ($tier -in @(0, 1)) { return $true }
                }
                return $false
            })

        foreach ($spId in $privSpIds) {
            try {
                $owners = @(Get-MgServicePrincipalOwner -ServicePrincipalId $spId -All -ErrorAction Stop)
                $appName = $roster[$spId].DisplayName
                foreach ($o in $owners) {
                    $hint = ConvertTo-EntraPrincipalType -Type $o.AdditionalProperties['@odata.type']
                    $enrichment = Get-EntraPrincipalEnrichment -ObjectId $o.Id -HintedType $hint
                    $priv = New-EntraPrivilegeEntry `
                        -Key 'Entra:OwnerOfPrivilegedApp' `
                        -Path @("Owner of '$appName' which holds privileged role/permission") `
                        -AssignmentType 'Owner' `
                        -Source 'Get-MgServicePrincipalOwner'
                    Add-EntraPrivilegeToRoster -Roster $roster -ObjectId $o.Id `
                        -Properties $enrichment -Privilege $priv -DiscoverySource 'App ownership'
                }
            }
            catch {
                Write-Verbose "Owner query failed for SP $spId : $($_.Exception.Message)"
            }
        }
    }

    # ----- 5. Stamp HighestTier on every row -----

    foreach ($oid in $roster.Keys) {
        $row = $roster[$oid]
        $tiers = foreach ($p in $row.Privileges) {
            try { Get-TierForPrivilege -Key $p.Key } catch { $null }
        }
        $numericTiers = @($tiers | Where-Object { $_ -is [int] })
        if ($numericTiers.Count -gt 0) {
            $row.HighestTier = ($numericTiers | Measure-Object -Minimum).Minimum
        }
        elseif ($row.Privileges | Where-Object { $_.Key -like 'Entra:Other:*' }) {
            $row.HighestTier = 'Unclassified'
        }
        else {
            $row.HighestTier = 'Service'
        }
    }

    # ----- 6. Statistics + return -----

    $rosterArray = @($roster.Values) | Sort-Object @{Expression = {
            if ($_.HighestTier -is [int]) { $_.HighestTier } else { 99 }
        }
    }, DisplayName

    $tier0 = @($rosterArray | Where-Object { $_.HighestTier -eq 0 }).Count
    $tier1 = @($rosterArray | Where-Object { $_.HighestTier -eq 1 }).Count
    $tier2 = @($rosterArray | Where-Object { $_.HighestTier -eq 2 }).Count
    $unclassified = @($rosterArray | Where-Object { $_.HighestTier -eq 'Unclassified' }).Count
    $spCount = @($rosterArray | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' }).Count

    return @{
        Available = $true
        FailureReason = $null
        Tenant = @{
            TenantId = $env.TenantId
            Account = $env.Account
            AuthType = $env.AuthType
        }
        Roster = $rosterArray
        Statistics = @{
            TotalPrincipals = $rosterArray.Count
            Tier0Count = $tier0
            Tier1Count = $tier1
            Tier2Count = $tier2
            UnclassifiedCount = $unclassified
            ServicePrincipalCount = $spCount
            PimAvailable = $pimAvailable
            ScannedAt = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-PrivilegedIdentityRosterEntra'
)

#endregion
