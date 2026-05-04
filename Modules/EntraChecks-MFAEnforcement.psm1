<#
.SYNOPSIS
    EntraChecks-MFAEnforcement.psm1
    Tenant-level MFA enforcement probe (PR 2 of MFA Detection).

.DESCRIPTION
    Captures every tenant-wide MFA enforcement mechanism so the per-user
    resolver (PR 3) has a complete picture in one upfront pass:

        1. Security Defaults state
            (/policies/identitySecurityDefaultsEnforcementPolicy)
        2. Per-user MFA reachability note — the per-user state itself is a
           per-user attribute (no tenant-wide list endpoint exists), so PR 3
           captures it during its all-users walk. PR 2 records that the
           probe will run.
        3. Conditional Access policy enumeration + materialisation into a
           structured cache PR 3 can apply per-user without re-fetching.

    Returns a hashtable with Available / FailureReason at the top so callers
    render a graceful "MFA enforcement not visible" panel without exception
    handling.

.NOTES
    Required Microsoft Graph scopes:
        - Policy.Read.All                        (Security Defaults + CA policies)
        - PrivilegedAccess.Read.AzureAD          (PIM-aware role enumeration)
        - Directory.Read.All                     (broad fallback)

    All graceful degradation is by design: a 403 on Security Defaults does
    not fail the probe. Each section reports its own Available flag.

.LINK
    Plan: plans/MFA-Detection-Plan.md (PR 2)
    Catalog: Modules/EntraChecks-AuthMethodCatalog.psm1 (PR 1)
#>

#Requires -Version 5.1

$script:ModulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $script:ModulePath 'EntraChecks-AuthMethodCatalog.psm1') -Force -DisableNameChecking -ErrorAction SilentlyContinue

$script:ModuleVersion = '1.0.0'
$script:ModuleName = 'EntraChecks-MFAEnforcement'

#region ==================== PRIVATE HELPERS ====================

function Test-MFAEnforcementEnvironment {
    <#
    .SYNOPSIS
        Probe to confirm a Microsoft Graph context is reachable. Returns
        Available=$false with a concrete FailureReason rather than throwing.
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
            FailureReason = 'Microsoft.Graph.Authentication is not loaded.'
        }
    }
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        return [pscustomobject]@{
            IsAvailable = $false
            FailureReason = 'No Microsoft Graph context. Run Connect-MgGraph -Scopes Policy.Read.All,Directory.Read.All before invoking the MFA enforcement probe.'
        }
    }
    return [pscustomobject]@{
        IsAvailable = $true
        TenantId = $ctx.TenantId
        Account = $ctx.Account
        AuthType = $ctx.AuthType
    }
}

function Get-SecurityDefaultsState {
    <#
    .SYNOPSIS
        Reads /policies/identitySecurityDefaultsEnforcementPolicy and
        returns a normalised state hashtable.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()

    $result = @{
        Available = $false
        Enabled = $null
        Source = '/policies/identitySecurityDefaultsEnforcementPolicy'
        DisplayName = $null
        FailureReason = $null
        Note = 'Security Defaults provide tenant-wide baseline MFA enforcement (Authenticator app required, blocks legacy auth). Adequate for small tenants; supplant with Conditional Access at scale for granular control.'
    }

    try {
        $policy = $null
        if (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
            $policy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -ErrorAction Stop
        }
        elseif (Get-Command -Name Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue) {
            $policy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        }

        if ($policy) {
            $result.Available = $true
            $result.Enabled = [bool]$policy.isEnabled
            $result.DisplayName = $policy.displayName
        }
    }
    catch {
        $result.FailureReason = $_.Exception.Message
        Write-Verbose "Get-SecurityDefaultsState failed: $($_.Exception.Message)"
    }

    return $result
}

function Get-PerUserMfaReachability {
    <#
    .SYNOPSIS
        Records that the per-user MFA state will be probed in PR 3.

    .DESCRIPTION
        Per-user MFA on Graph is exposed at /users/{id}/authentication/requirements
        — a per-user endpoint with no tenant-wide list. Confirming the API works
        requires a sample call against an actual user, which PR 3 will do during
        its enrollment-status walk. This stub records the design choice so the
        result hashtable shape stays consistent across versions.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()

    @{
        Available = 'DeferredToResolver'
        Note = 'Per-user MFA state is per-user, not tenant-wide. The MFA Resolver (PR 3) reads /users/{id}/authentication/requirements for each user during its pass and aggregates the count back into the unified roster. PR 2 only records that the probe will happen; the actual EnforcedUserCount / EnabledUserCount come from PR 3.'
        EnforcedUserCount = $null
        EnabledUserCount = $null
    }
}

function ConvertTo-MaterialisedCaPolicy {
    <#
    .SYNOPSIS
        Materialises a raw Conditional Access policy into the structured
        cache shape PR 3's resolver consumes. Centralised so PR 3 doesn't
        re-walk Graph properties.

    .DESCRIPTION
        Captures the access decision boundary explicitly:
          - Includes / Excludes for users, groups, roles
          - Application filter (which apps does the policy gate)
          - Client app type filter (legacy vs modern)
          - Conditions that NARROW the policy (locations, platforms,
            sign-in / user risk levels) — IsConditional is set $true when
            any narrowing condition is present, signalling to PR 3 that
            the policy does not unconditionally require MFA.
          - Grant controls — operator (AND/OR), built-in controls,
            RequiresMfa boolean, Blocks boolean.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$RawPolicy)

    $cond = $RawPolicy.conditions
    $grant = $RawPolicy.grantControls

    # --- Includes / Excludes ---
    $includeUsers = if ($cond.users.includeUsers) { @($cond.users.includeUsers) } else { @() }
    $excludeUsers = if ($cond.users.excludeUsers) { @($cond.users.excludeUsers) } else { @() }
    $includeGroups = if ($cond.users.includeGroups) { @($cond.users.includeGroups) } else { @() }
    $excludeGroups = if ($cond.users.excludeGroups) { @($cond.users.excludeGroups) } else { @() }
    $includeRoles = if ($cond.users.includeRoles) { @($cond.users.includeRoles) } else { @() }
    $excludeRoles = if ($cond.users.excludeRoles) { @($cond.users.excludeRoles) } else { @() }

    # --- Conditions that narrow applicability ---
    $clientAppTypes = if ($cond.clientAppTypes) { @($cond.clientAppTypes) } else { @() }
    $platforms = $cond.platforms
    $locations = $cond.locations
    $signInRiskLevels = if ($cond.signInRiskLevels) { @($cond.signInRiskLevels) } else { @() }
    $userRiskLevels = if ($cond.userRiskLevels) { @($cond.userRiskLevels) } else { @() }
    $appsInclude = if ($cond.applications.includeApplications) { @($cond.applications.includeApplications) } else { @() }
    $appsExclude = if ($cond.applications.excludeApplications) { @($cond.applications.excludeApplications) } else { @() }

    # A policy is "conditional" if narrowing conditions are present beyond
    # the universal defaults. clientAppTypes=['all'] / applications=['All']
    # are the universal defaults.
    $isConditional = $false
    if (@($clientAppTypes).Count -gt 0 -and ($clientAppTypes -notcontains 'all')) { $isConditional = $true }
    if ($platforms -and ($platforms.includePlatforms -or $platforms.excludePlatforms)) { $isConditional = $true }
    if ($locations -and ($locations.includeLocations -or $locations.excludeLocations)) { $isConditional = $true }
    if (@($signInRiskLevels).Count -gt 0) { $isConditional = $true }
    if (@($userRiskLevels).Count -gt 0) { $isConditional = $true }
    if (@($appsInclude).Count -gt 0 -and ($appsInclude -notcontains 'All') -and ($appsInclude -notcontains 'none')) { $isConditional = $true }

    # --- Grant controls ---
    $builtIn = if ($grant.builtInControls) { @($grant.builtInControls) } else { @() }
    $requiresMfa = $builtIn -contains 'mfa'
    $blocks = $builtIn -contains 'block'
    $requiresCompliantDevice = $builtIn -contains 'compliantDevice'
    $requiresDomainJoinedDevice = $builtIn -contains 'domainJoinedDevice'

    @{
        Id = $RawPolicy.id
        DisplayName = $RawPolicy.displayName
        State = $RawPolicy.state
        ReportOnly = ($RawPolicy.state -eq 'enabledForReportingButNotEnforced')
        Enabled = ($RawPolicy.state -eq 'enabled')

        Includes = @{
            Users = $includeUsers
            Groups = $includeGroups
            Roles = $includeRoles
        }
        Excludes = @{
            Users = $excludeUsers
            Groups = $excludeGroups
            Roles = $excludeRoles
        }

        Conditions = @{
            ApplicationsInclude = $appsInclude
            ApplicationsExclude = $appsExclude
            ClientAppTypes = $clientAppTypes
            SignInRiskLevels = $signInRiskLevels
            UserRiskLevels = $userRiskLevels
            HasPlatformConstraint = [bool]($platforms -and ($platforms.includePlatforms -or $platforms.excludePlatforms))
            HasLocationConstraint = [bool]($locations -and ($locations.includeLocations -or $locations.excludeLocations))
            IsConditional = $isConditional
        }

        GrantControls = @{
            Operator = if ($grant.'operator') { $grant.'operator' } else { 'AND' }
            BuiltInControls = $builtIn
            RequiresMfa = $requiresMfa
            Blocks = $blocks
            RequiresCompliantDevice = $requiresCompliantDevice
            RequiresDomainJoinedDevice = $requiresDomainJoinedDevice
        }
    }
}

function Get-CaPoliciesMaterialised {
    <#
    .SYNOPSIS
        Fetches every Conditional Access policy and materialises into the
        structured cache PR 3 will apply per-user.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()

    $result = @{
        Available = $false
        Policies = @()
        FailureReason = $null
    }

    try {
        $raw = $null
        if (Get-Command -Name Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue) {
            $raw = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        elseif (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
            $response = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -ErrorAction Stop
            $raw = @($response.value)
        }
        else {
            $result.FailureReason = 'Neither Get-MgIdentityConditionalAccessPolicy nor Invoke-MgGraphRequest is available.'
            return $result
        }

        $materialised = foreach ($p in $raw) {
            try {
                ConvertTo-MaterialisedCaPolicy -RawPolicy $p
            }
            catch {
                Write-Verbose "ConvertTo-MaterialisedCaPolicy failed for policy '$($p.displayName)': $($_.Exception.Message)"
            }
        }

        $result.Available = $true
        $result.Policies = @($materialised)
    }
    catch {
        $result.FailureReason = $_.Exception.Message
        Write-Verbose "Get-CaPoliciesMaterialised failed: $($_.Exception.Message)"
    }

    return $result
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-TenantMfaEnforcement {
    <#
    .SYNOPSIS
        Builds the tenant-level MFA enforcement summary the per-user resolver
        (PR 3) consumes.

    .OUTPUTS
        @{
            Available; FailureReason; Tenant
            SecurityDefaults = @{ Available; Enabled; Source; DisplayName; FailureReason; Note }
            PerUserMfa       = @{ Available; Note; EnforcedUserCount; EnabledUserCount }
            ConditionalAccess = @{ Available; Policies = @(<materialised>); FailureReason }
            Findings = @( @{ Severity; Object; Description; CheckName; Remediation } )
            Statistics = @{ ... }
        }
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()

    $env = Test-MFAEnforcementEnvironment
    if (-not $env.IsAvailable) {
        return @{
            Available = $false
            FailureReason = $env.FailureReason
            Tenant = $null
            SecurityDefaults = @{ Available = $false }
            PerUserMfa = @{ Available = $false }
            ConditionalAccess = @{ Available = $false; Policies = @() }
            Findings = @()
            Statistics = @{
                ScannedAt = (Get-Date).ToUniversalTime().ToString('o')
            }
        }
    }

    Write-Verbose 'Probing tenant-level MFA enforcement...'

    $securityDefaults = Get-SecurityDefaultsState
    $perUserMfa = Get-PerUserMfaReachability
    $caPolicies = Get-CaPoliciesMaterialised

    # --- Findings ---
    $findings = @()

    # Security Defaults
    if ($securityDefaults.Available) {
        if ($securityDefaults.Enabled) {
            $findings += @{
                Severity = 'Info'
                Object = 'Security Defaults'
                CheckName = 'MFAEnforcement-SecurityDefaultsEnabled'
                Description = 'Security Defaults are enabled tenant-wide. Every user is required to register Microsoft Authenticator and gets MFA-challenged on risky sign-ins. Adequate baseline; consider Conditional Access at scale for granular control.'
                Remediation = 'No immediate action. If the tenant has Azure AD P1 or higher, migrate to Conditional Access for per-user / per-app MFA targeting.'
            }
        }
        else {
            $findings += @{
                Severity = 'High'
                Object = 'Security Defaults'
                CheckName = 'MFAEnforcement-SecurityDefaultsDisabled'
                Description = 'Security Defaults are DISABLED. Without Conditional Access policies that require MFA, users have no enforced second factor.'
                Remediation = 'Enable Security Defaults at https://entra.microsoft.com/ -> Identity -> Properties, OR implement Conditional Access policies that require MFA for all users (preferred for P1+ tenants).'
            }
        }
    }

    # CA policy coverage
    if ($caPolicies.Available) {
        $enabled = @($caPolicies.Policies | Where-Object { $_.Enabled })
        $reportOnly = @($caPolicies.Policies | Where-Object { $_.ReportOnly })
        $disabled = @($caPolicies.Policies | Where-Object { $_.State -eq 'disabled' })

        $enabledMfaPolicies = @($enabled | Where-Object { $_.GrantControls.RequiresMfa })
        $reportOnlyMfaPolicies = @($reportOnly | Where-Object { $_.GrantControls.RequiresMfa })

        # Does at least one ENABLED policy require MFA for the universal scope?
        $hasUniversalEnabledMfa = @($enabledMfaPolicies | Where-Object {
                ($_.Includes.Users -contains 'All') -and -not $_.Conditions.IsConditional
            }).Count -gt 0

        if (-not $hasUniversalEnabledMfa -and $enabledMfaPolicies.Count -eq 0 -and $reportOnlyMfaPolicies.Count -gt 0) {
            $findings += @{
                Severity = 'High'
                Object = 'Conditional Access'
                CheckName = 'MFAEnforcement-OnlyReportOnlyMfa'
                Description = "$($reportOnlyMfaPolicies.Count) Conditional Access polic(ies) require MFA but ALL of them are in report-only state. Report-only policies log without enforcing — users are not actually being challenged for MFA."
                Remediation = 'Move at least one MFA-grant policy out of report-only into "On" state. Validate impact via the report-only logs first.'
            }
        }
        elseif (-not $hasUniversalEnabledMfa) {
            $findings += @{
                Severity = 'Medium'
                Object = 'Conditional Access'
                CheckName = 'MFAEnforcement-NoUniversalMfaPolicy'
                Description = 'No enabled Conditional Access policy unconditionally requires MFA for all users. The MFA Resolver will determine per-user effective coverage from the policies that DO exist; this is informational.'
                Remediation = 'Consider adding a baseline policy: Users=All, Apps=All Cloud Apps, Grant=Require MFA, no narrowing conditions. Exclude only break-glass accounts.'
            }
        }
    }

    # --- Statistics ---
    $stats = @{
        ScannedAt = (Get-Date).ToUniversalTime().ToString('o')
        SecurityDefaultsEnabled = $securityDefaults.Enabled
        TotalCaPolicies = @($caPolicies.Policies).Count
        EnabledCaPolicies = @($caPolicies.Policies | Where-Object { $_.Enabled }).Count
        ReportOnlyCaPolicies = @($caPolicies.Policies | Where-Object { $_.ReportOnly }).Count
        DisabledCaPolicies = @($caPolicies.Policies | Where-Object { $_.State -eq 'disabled' }).Count
        EnabledMfaPolicies = @($caPolicies.Policies | Where-Object { $_.Enabled -and $_.GrantControls.RequiresMfa }).Count
        UnconditionalMfaForAllPolicies = @($caPolicies.Policies | Where-Object { $_.Enabled -and $_.GrantControls.RequiresMfa -and ($_.Includes.Users -contains 'All') -and -not $_.Conditions.IsConditional }).Count
    }

    return @{
        Available = $true
        FailureReason = $null
        Tenant = @{
            TenantId = $env.TenantId
            Account = $env.Account
            AuthType = $env.AuthType
        }
        SecurityDefaults = $securityDefaults
        PerUserMfa = $perUserMfa
        ConditionalAccess = $caPolicies
        Findings = $findings
        Statistics = $stats
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-TenantMfaEnforcement'
)

#endregion
