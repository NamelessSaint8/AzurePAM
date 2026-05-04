<#
.SYNOPSIS
    EntraChecks-MFAResolver.psm1
    Per-user effective-MFA verdict engine (PR 3 of MFA Detection).

.DESCRIPTION
    Consumes the Auth Method Catalog (PR 1) + Tenant Enforcement probe (PR 2)
    and returns a deterministic verdict for every active user in the tenant:

        EnforcedStrong       — covered by an enabled enforcement signal AND
                               has phishing-resistant or strong methods
        EnforcedWeak         — covered by enforcement but only weak methods
                               (SMS / voice / email)
        RegisteredUnenforced — has methods but no policy actually enforces MFA
        NotRegistered        — no MFA methods at all
        NeedsReview          — strict mode: any ambiguity collapses here

    Strict mode is non-negotiable. The point of the resolver is that it never
    reports "Enforced (Strong)" when it cannot prove enforcement. Ambiguous
    coverage paths (conditional-only CA, mixed per-user-MFA vs CA signals,
    guests, missing membership data) become NeedsReview deliberately.

.NOTES
    Performance note: this module makes per-user Graph calls to resolve
    transitiveMemberOf and (optionally) per-user MFA state. At 10k+ users,
    runtime is dominated by network latency. Mitigations:
      - userRegistrationDetails bulk fetch is preferred; per-user fallback
        is used only when the bulk endpoint is unavailable (P1 license gap).
      - -SkipPerUserMfaProbe disables the /authentication/requirements probe
        (the most expensive per-user call) for tenants that don't use legacy
        per-user MFA.
      - Membership and methods are cached per user for the duration of one
        Get-UserMfaCoverage run.

    Required Microsoft Graph scopes:
        - User.Read.All
        - UserAuthenticationMethod.Read.All
        - Policy.Read.All
        - Directory.Read.All
        - AuditLog.Read.All        (for userRegistrationDetails)

.LINK
    Plan: plans/MFA-Detection-Plan.md (PR 3)
    Catalog: Modules/EntraChecks-AuthMethodCatalog.psm1 (PR 1)
    Tenant probe: Modules/EntraChecks-MFAEnforcement.psm1 (PR 2)
#>

#Requires -Version 5.1

$script:ModulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $script:ModulePath 'EntraChecks-AuthMethodCatalog.psm1') -Force -DisableNameChecking -ErrorAction SilentlyContinue
Import-Module (Join-Path $script:ModulePath 'EntraChecks-MFAEnforcement.psm1') -Force -DisableNameChecking -ErrorAction SilentlyContinue
Import-Module (Join-Path $script:ModulePath 'EntraChecks-MFASignInEvidence.psm1') -Force -DisableNameChecking -ErrorAction SilentlyContinue

$script:ModuleVersion = '1.0.0'
$script:ModuleName = 'EntraChecks-MFAResolver'

#region ==================== MODULE STATE ====================

# Microsoft directory-role template IDs we treat as "privileged" for the
# -PrivilegedOnly fast-scan switch. Not used for verdict logic — the catalog
# from the Privileged Identity Roster work is the authoritative privilege
# source. This list is just the fast-scan filter.
$script:WellKnownAdminRoleTemplateIds = @(
    '62e90394-69f5-4237-9190-012177145e10'   # Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814'   # Privileged Role Administrator
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'   # Privileged Authentication Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d'   # Security Administrator
    'fe930be7-5e62-47db-91af-98c3a49a38b1'   # User Administrator
    '29232cdf-9323-42fd-ade2-1d097af3e4de'   # Exchange Administrator
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'   # SharePoint Administrator
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'   # Application Administrator
    '158c047a-c907-4556-b7ef-446551a6b5f7'   # Cloud Application Administrator
    'c4e39bd9-1100-46d3-8c65-fb160da0071f'   # Authentication Administrator
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'   # Hybrid Identity Administrator
)

# Service-account UPN heuristics — case-insensitive substring / prefix match.
$script:ServiceAccountUpnPatterns = @(
    '^svc-', '^svc_', '^service-', '^service_', '^automation-', '^sync-',
    '^noreply', '^no-reply', '^donotreply',
    '@.*-svc\.', '-svc@', 'service@', 'automation@', 'sync@'
)

# Service-account display-name heuristics.
$script:ServiceAccountDisplayNamePatterns = @(
    '^service\s', '\sservice$', 'automation', 'sync\saccount', 'integration\saccount',
    'ldap\sbind', 'monitoring\saccount', 'backup\saccount'
)

#endregion

#region ==================== PRIVATE HELPERS ====================

function Test-MFAResolverEnvironment {
    <#
    .SYNOPSIS
        Confirms a Microsoft Graph context is reachable. Returns
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
            FailureReason = 'No Microsoft Graph context. Connect-MgGraph required before invoking the MFA resolver.'
        }
    }
    return [pscustomobject]@{
        IsAvailable = $true
        TenantId = $ctx.TenantId
        Account = $ctx.Account
    }
}

function Test-IsServiceAccount {
    <#
    .SYNOPSIS
        Heuristic check for whether a user looks like a service account.
        Returns $null when no signals matched, or a list of fired signals.
    #>
    [OutputType([string[]])]
    [CmdletBinding()]
    param(
        [string]$Upn,
        [string]$DisplayName
    )

    $signals = @()
    if ($Upn) {
        foreach ($pattern in $script:ServiceAccountUpnPatterns) {
            if ($Upn -imatch $pattern) {
                $signals += "upn-pattern:$pattern"
            }
        }
    }
    if ($DisplayName) {
        foreach ($pattern in $script:ServiceAccountDisplayNamePatterns) {
            if ($DisplayName -imatch $pattern) {
                $signals += "displayname-pattern:$pattern"
            }
        }
    }
    if ($signals.Count -eq 0) { return $null }
    return [string[]]$signals
}

function Get-UserTransitiveMembership {
    <#
    .SYNOPSIS
        Returns the user's transitive group + role memberships. Cached per user
        for the duration of the resolver run.
    .DESCRIPTION
        Group IDs and role-template IDs are returned (not directoryRole IDs)
        because Conditional Access policies reference role-template IDs, not
        the per-tenant directoryRole instance IDs.

        Returns @{ Groups; Roles; Available; FailureReason }. When Available=$false,
        the resolver collapses to NeedsReview (cannot prove or disprove
        coverage without membership data).
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$UserId,
        [Parameter(Mandatory)] [hashtable]$Cache
    )

    if ($Cache.ContainsKey($UserId)) { return $Cache[$UserId] }

    $result = @{ Groups = @(); Roles = @(); Available = $true; FailureReason = $null }

    try {
        $members = $null
        if (Get-Command -Name Get-MgUserTransitiveMemberOf -ErrorAction SilentlyContinue) {
            $members = @(Get-MgUserTransitiveMemberOf -UserId $UserId -All -ErrorAction Stop)
        }
        else {
            $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserId/transitiveMemberOf" -ErrorAction Stop
            $members = @($resp.value)
        }

        foreach ($m in $members) {
            $type = $null
            if ($m.AdditionalProperties -and $m.AdditionalProperties['@odata.type']) {
                $type = $m.AdditionalProperties['@odata.type']
            }
            elseif ($m.'@odata.type') {
                $type = $m.'@odata.type'
            }

            switch -Wildcard ($type) {
                '*microsoft.graph.group*' {
                    $result.Groups += $m.Id
                }
                '*microsoft.graph.directoryRole*' {
                    # CA policies reference role-template IDs, not the per-tenant
                    # directoryRole instance IDs. Pull the templateId.
                    $tmpl = $null
                    if ($m.AdditionalProperties -and $m.AdditionalProperties.roleTemplateId) {
                        $tmpl = $m.AdditionalProperties.roleTemplateId
                    }
                    elseif ($m.RoleTemplateId) {
                        $tmpl = $m.RoleTemplateId
                    }
                    if ($tmpl) { $result.Roles += $tmpl }
                }
                default { }
            }
        }
    }
    catch {
        $result.Available = $false
        $result.FailureReason = $_.Exception.Message
    }

    $Cache[$UserId] = $result
    return $result
}

function Get-UserRegisteredMethods {
    <#
    .SYNOPSIS
        Returns canonical method keys for a user's registered authentication
        methods. Prefers the registrationDetails bulk lookup (passed in as
        a pre-loaded map); falls back to the per-user endpoint.
    #>
    [OutputType([string[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$UserId,
        [hashtable]$BulkRegistrationMap,    # UserId -> @{ methodsRegistered }; pre-loaded
        [Parameter(Mandatory)] [hashtable]$Cache
    )

    if ($Cache.ContainsKey($UserId)) { return $Cache[$UserId] }

    $methods = @()

    # Path 1: bulk registrationDetails map (preferred)
    if ($BulkRegistrationMap -and $BulkRegistrationMap.ContainsKey($UserId)) {
        $entry = $BulkRegistrationMap[$UserId]
        foreach ($m in @($entry.methodsRegistered)) {
            $key = Resolve-AuthMethodKey -Identifier $m -ErrorAction SilentlyContinue
            if ($key) { $methods += $key }
        }
        $Cache[$UserId] = [string[]]$methods
        return [string[]]$methods
    }

    # Path 2: per-user fallback
    try {
        $resp = $null
        if (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
            $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserId/authentication/methods" -ErrorAction Stop
        }
        if ($resp -and $resp.value) {
            foreach ($m in @($resp.value)) {
                $type = $m.'@odata.type'
                # phoneAuthenticationMethod requires phoneType disambiguation
                if ($type -imatch 'phoneAuthenticationMethod') {
                    $phoneType = if ($m.phoneType) { $m.phoneType } else { 'mobile' }
                    $key = Resolve-AuthMethodKey -Identifier $type -PhoneType $phoneType -ErrorAction SilentlyContinue
                }
                else {
                    $key = Resolve-AuthMethodKey -Identifier $type -ErrorAction SilentlyContinue
                }
                if ($key) { $methods += $key }
            }
        }
    }
    catch {
        Write-Verbose "Get-UserRegisteredMethods: per-user fallback failed for $UserId : $($_.Exception.Message)"
    }

    $Cache[$UserId] = [string[]]$methods
    return [string[]]$methods
}

function Get-UserPerUserMfaState {
    <#
    .SYNOPSIS
        Reads /users/{id}/authentication/requirements (beta) for a single
        user. Returns 'Enforced' | 'Enabled' | 'Disabled' | 'Unknown'.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$UserId)

    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$UserId/authentication/requirements" -ErrorAction Stop
        if ($resp.perUserMfaState) {
            switch ($resp.perUserMfaState.ToString().ToLower()) {
                'enforced' { return 'Enforced' }
                'enabled' { return 'Enabled' }
                'disabled' { return 'Disabled' }
                default { return 'Unknown' }
            }
        }
    }
    catch {
        Write-Verbose "Get-UserPerUserMfaState failed for $UserId : $($_.Exception.Message)"
    }
    return 'Unknown'
}

function Test-CaPolicyAppliesTo {
    <#
    .SYNOPSIS
        Determines whether a single materialised CA policy applies to a single
        user, based on Includes/Excludes resolution.

    .OUTPUTS
        @{
            Applies     = $true | $false
            Conditional = $true | $false   # narrowing conditions present
            Reason      = '<plain English why or why not>'
        }
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$User,    # @{ Id; UserType; Groups; Roles }
        [Parameter(Mandatory)] [hashtable]$Policy   # materialised PR 2 shape
    )

    # Excludes always win
    if ($Policy.Excludes.Users -contains $User.Id) {
        return @{ Applies = $false; Conditional = $false; Reason = 'User is in policy excludeUsers' }
    }
    foreach ($g in @($User.Groups)) {
        if ($Policy.Excludes.Groups -contains $g) {
            return @{ Applies = $false; Conditional = $false; Reason = "User is in excluded group $g" }
        }
    }
    foreach ($r in @($User.Roles)) {
        if ($Policy.Excludes.Roles -contains $r) {
            return @{ Applies = $false; Conditional = $false; Reason = "User is in excluded role $r" }
        }
    }

    # Includes — at least one match required
    $matched = $false
    $matchReason = ''

    if ($Policy.Includes.Users -contains 'All') {
        $matched = $true
        $matchReason = "Policy includes 'All' users"
    }
    elseif ($Policy.Includes.Users -contains $User.Id) {
        $matched = $true
        $matchReason = 'User explicitly included'
    }
    elseif (($Policy.Includes.Users -contains 'GuestsOrExternalUsers') -and ($User.UserType -eq 'Guest')) {
        $matched = $true
        $matchReason = "Policy includes guests; user is a $($User.UserType)"
    }

    if (-not $matched) {
        foreach ($g in @($User.Groups)) {
            if ($Policy.Includes.Groups -contains $g) {
                $matched = $true
                $matchReason = "User is in included group $g"
                break
            }
        }
    }
    if (-not $matched) {
        foreach ($r in @($User.Roles)) {
            if ($Policy.Includes.Roles -contains $r) {
                $matched = $true
                $matchReason = "User is in included role $r"
                break
            }
        }
    }

    if (-not $matched) {
        return @{ Applies = $false; Conditional = $false; Reason = 'User does not match any include' }
    }

    return @{
        Applies = $true
        Conditional = [bool]$Policy.Conditions.IsConditional
        Reason = $matchReason
    }
}

function Resolve-MfaVerdict {
    <#
    .SYNOPSIS
        The deterministic verdict logic. Pure data-in / data-out — no Graph
        calls. Trivially testable.
    .DESCRIPTION
        Strict mode is the only mode (per resolved decision #2). Any
        ambiguity collapses to NeedsReview. The conservatism is the
        bulletproof guarantee.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$StrongestRegistered,    # PhishingResistant|Strong|Weak|None|Unknown
        [Parameter(Mandatory)] [bool]$SecurityDefaultsApplies,
        [Parameter(Mandatory)] [string]$PerUserMfaState,        # Enforced|Enabled|Disabled|Unknown
        [Parameter()]
        [AllowEmptyCollection()]
        [array]$ApplicableCaPolicies = @(),                     # @( @{ Policy; Applies; Conditional; Reason } )
        [Parameter(Mandatory)] [string]$UserType,               # Member|Guest
        [bool]$MembershipResolved = $true
    )

    # When membership couldn't be resolved, we cannot reason about CA — NeedsReview.
    if (-not $MembershipResolved) {
        return @{
            Verdict = 'NeedsReview'
            Reason = "Cannot determine effective MFA enforcement: transitive group/role membership query failed (likely a Graph permission gap on Directory.Read.All). Without membership data, no CA policy can be evaluated."
            NeedsReviewBecause = 'MembershipResolutionFailed'
        }
    }

    # Determine effective enforcement signals
    $applicableEnabledMfa = @($ApplicableCaPolicies | Where-Object { $_.Applies -and $_.Policy.Enabled -and $_.Policy.GrantControls.RequiresMfa })
    $applicableConditional = @($applicableEnabledMfa | Where-Object { $_.Conditional })
    $applicableUnconditional = @($applicableEnabledMfa | Where-Object { -not $_.Conditional })
    $applicableReportOnly = @($ApplicableCaPolicies | Where-Object { $_.Applies -and $_.Policy.ReportOnly -and $_.Policy.GrantControls.RequiresMfa })

    # Grant controls with OR — if mfa is OR'd with compliantDevice or domainJoinedDevice,
    # the user might satisfy the policy with the alternative path. We can't verify
    # device compliance from here, so OR'd MFA grants are conditional for our purposes.
    $applicableOrMfa = @($applicableUnconditional | Where-Object {
            $_.Policy.GrantControls.Operator -eq 'OR' -and
            (@($_.Policy.GrantControls.BuiltInControls).Count -gt 1) -and
            ($_.Policy.GrantControls.RequiresCompliantDevice -or $_.Policy.GrantControls.RequiresDomainJoinedDevice)
        })

    $sources = @()
    $unconditionallyEnforced = $false

    if ($SecurityDefaultsApplies) {
        $sources += 'Security Defaults'
        $unconditionallyEnforced = $true
    }
    if ($PerUserMfaState -eq 'Enforced') {
        $sources += 'Per-user MFA (legacy)'
        $unconditionallyEnforced = $true
    }
    # An unconditional CA policy with MFA AND'd in counts as enforcement.
    # An OR'd grant is more nuanced and is treated as conditional.
    $strictlyUnconditional = @($applicableUnconditional | Where-Object { $_ -notin $applicableOrMfa })
    if ($strictlyUnconditional.Count -gt 0) {
        $sources += "Conditional Access ($($strictlyUnconditional.Count) policy/policies)"
        $unconditionallyEnforced = $true
    }

    # ---- NeedsReview cases (strict; checked first) ----

    # Mixed signals: per-user MFA says Disabled but CA enforces
    if ($PerUserMfaState -eq 'Disabled' -and $unconditionallyEnforced) {
        return @{
            Verdict = 'NeedsReview'
            Reason = "Per-user MFA state is 'Disabled' but Conditional Access enforces MFA via $($sources -join ', '). Resolve the contradiction — usually by removing the legacy per-user setting."
            NeedsReviewBecause = 'MixedSignals_PerUserDisabledButCaEnforced'
        }
    }

    # OR'd grants where MFA is one option among others — can't prove MFA path was taken
    if ($applicableOrMfa.Count -gt 0 -and $strictlyUnconditional.Count -eq 0) {
        return @{
            Verdict = 'NeedsReview'
            Reason = "MFA is required by an OR'd grant (mfa OR compliantDevice/domainJoinedDevice). The user could satisfy the policy without MFA via the device path; cannot prove MFA was actually used."
            NeedsReviewBecause = 'OrGrantWithDeviceAlternative'
        }
    }

    # Conditional-only enforcement: only narrowing CA policies match
    if (-not $unconditionallyEnforced -and $applicableConditional.Count -gt 0) {
        return @{
            Verdict = 'NeedsReview'
            Reason = "MFA is required only by conditional CA polic(ies) (location/risk/platform-narrowed). User is not always challenged for MFA — every sign-in path that bypasses the conditions skips MFA."
            NeedsReviewBecause = 'ConditionalOnlyCoverage'
        }
    }

    # Report-only-only coverage
    if (-not $unconditionallyEnforced -and $applicableConditional.Count -eq 0 -and $applicableReportOnly.Count -gt 0) {
        return @{
            Verdict = 'NeedsReview'
            Reason = "$($applicableReportOnly.Count) Conditional Access polic(ies) target this user with MFA but ALL of them are in report-only state. The user is not actually challenged for MFA."
            NeedsReviewBecause = 'ReportOnlyMfaCoverage'
        }
    }

    # Guest with no enforcement: home tenant may enforce, but we can't verify
    if ($UserType -eq 'Guest' -and -not $unconditionallyEnforced) {
        return @{
            Verdict = 'NeedsReview'
            Reason = "Guest user with no visible MFA enforcement in this tenant. The home tenant may enforce MFA, but that cannot be verified from here. Confirm via cross-tenant access settings or B2B Conditional Access policies."
            NeedsReviewBecause = 'GuestWithUnverifiableHomeEnforcement'
        }
    }

    # ---- Deterministic verdicts ----

    if ($StrongestRegistered -eq 'None') {
        return @{
            Verdict = 'NotRegistered'
            Reason = 'User has no MFA methods registered. Block sign-in or force registration.'
        }
    }

    if ($unconditionallyEnforced -and $StrongestRegistered -in @('PhishingResistant', 'Strong')) {
        return @{
            Verdict = 'EnforcedStrong'
            Reason = "MFA is enforced via $($sources -join ', '). User has $StrongestRegistered methods registered."
        }
    }

    if ($unconditionallyEnforced -and $StrongestRegistered -eq 'Weak') {
        return @{
            Verdict = 'EnforcedWeak'
            Reason = "MFA is enforced via $($sources -join ', ') but the user only has Weak methods (SMS / voice / email) registered. Add a phishing-resistant or strong method."
        }
    }

    if (-not $unconditionallyEnforced -and $StrongestRegistered -ne 'None') {
        return @{
            Verdict = 'RegisteredUnenforced'
            Reason = "User has $StrongestRegistered methods registered but no policy enforces MFA. They can sign in without MFA today."
        }
    }

    # Fallback (shouldn't reach here in a well-formed input set)
    return @{
        Verdict = 'NeedsReview'
        Reason = 'Could not derive verdict from available signals (resolver fell through).'
        NeedsReviewBecause = 'ResolverFallthrough'
    }
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-UserMfaCoverage {
    <#
    .SYNOPSIS
        Builds the per-user effective-MFA roster.

    .PARAMETER UserIds
        Optional list of user IDs. When omitted, the resolver enumerates every
        enabled Member user (Guest users excluded unless -IncludeGuests is set).

    .PARAMETER TenantEnforcement
        Output of Get-TenantMfaEnforcement (PR 2). When omitted, the resolver
        invokes it itself, which adds one Graph round-trip pass.

    .PARAMETER IncludeGuests
        Include B2B guest users. They surface as NeedsReview unless an explicit
        guest-targeting CA policy applies.

    .PARAMETER PrivilegedOnly
        Fast-scan switch: only resolve users whose role memberships contain a
        well-known admin role. Reduces Graph load by 100x in mid-size tenants.

    .PARAMETER SkipPerUserMfaProbe
        Skip the per-user /authentication/requirements call. Use when legacy
        per-user MFA is known to be unused — saves one Graph call per user.

    .PARAMETER SkipSignInEvidence
        Skip the bulk /auditLogs/signIns fetch (PR 4). Default OFF — sign-in
        evidence runs by default per the design decision. Use this switch
        for fast scans or when AuditLog.Read.All is unavailable.

    .PARAMETER SignInLookbackDays
        How many days back to query sign-in logs. Default 30.

    .OUTPUTS
        @{
            Available; FailureReason; Tenant
            Coverage = @( @{ UserId; Upn; DisplayName; UserType; Enabled;
                              IsServiceAccountSuspected; ServiceAccountSignals;
                              RegisteredMethods; StrongestRegistered;
                              SecurityDefaultsApplies; PerUserMfaState;
                              AppliedCaPolicies; EffectiveCaMfaRequired;
                              Verdict; VerdictReason; NeedsReviewBecause } )
            Statistics = @{ Counts per verdict, ScannedAt, etc. }
        }
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [string[]]$UserIds,
        [hashtable]$TenantEnforcement,
        [switch]$IncludeGuests,
        [switch]$PrivilegedOnly,
        [switch]$SkipPerUserMfaProbe,
        [switch]$SkipSignInEvidence,
        [int]$SignInLookbackDays = 30
    )

    $env = Test-MFAResolverEnvironment
    if (-not $env.IsAvailable) {
        return @{
            Available = $false
            FailureReason = $env.FailureReason
            Tenant = $null
            Coverage = @()
            Statistics = @{ ScannedAt = (Get-Date).ToUniversalTime().ToString('o') }
        }
    }

    # 0. Tenant enforcement (PR 2). Either passed in or fetched here.
    if (-not $TenantEnforcement) {
        $TenantEnforcement = Get-TenantMfaEnforcement
    }
    $securityDefaultsApplies = [bool]($TenantEnforcement.SecurityDefaults -and $TenantEnforcement.SecurityDefaults.Enabled)
    $caPolicies = if ($TenantEnforcement.ConditionalAccess.Available) { @($TenantEnforcement.ConditionalAccess.Policies) } else { @() }

    # 1. User enumeration
    if (-not $UserIds -or $UserIds.Count -eq 0) {
        Write-Verbose 'Enumerating users (no UserIds passed)...'
        try {
            $filter = if ($IncludeGuests) {
                "accountEnabled eq true"
            }
            else {
                "accountEnabled eq true and userType eq 'Member'"
            }
            $allUsers = @(Get-MgUser -Filter $filter -Property 'Id,DisplayName,UserPrincipalName,AccountEnabled,UserType' -All -ErrorAction Stop)
            $UserIds = @($allUsers | ForEach-Object { $_.Id })
            $script:UserPropertyCache = @{}
            foreach ($u in $allUsers) {
                $script:UserPropertyCache[$u.Id] = @{
                    DisplayName = $u.DisplayName
                    Upn = $u.UserPrincipalName
                    UserType = $u.UserType
                    Enabled = $u.AccountEnabled
                }
            }
        }
        catch {
            return @{
                Available = $false
                FailureReason = "User enumeration failed: $($_.Exception.Message)"
                Tenant = $null
                Coverage = @()
                Statistics = @{ ScannedAt = (Get-Date).ToUniversalTime().ToString('o') }
            }
        }
    }
    else {
        $script:UserPropertyCache = @{}
    }

    # 2. Bulk registrationDetails fetch (preferred; one paginated call)
    $bulkRegistrationMap = @{}
    try {
        if (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
            $regResp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999' -ErrorAction Stop
            $regs = @($regResp.value)
            # follow @odata.nextLink
            while ($regResp.'@odata.nextLink') {
                $regResp = Invoke-MgGraphRequest -Method GET -Uri $regResp.'@odata.nextLink' -ErrorAction Stop
                $regs += @($regResp.value)
            }
            foreach ($r in $regs) {
                if ($r.id) { $bulkRegistrationMap[$r.id] = $r }
            }
            Write-Verbose "Loaded $($bulkRegistrationMap.Count) registration entries from bulk endpoint."
        }
    }
    catch {
        Write-Verbose "Bulk registrationDetails fetch failed: $($_.Exception.Message). Will use per-user fallback."
        $bulkRegistrationMap = $null
    }

    # 3. Sign-in evidence bulk fetch (PR 4) — one paginated call against
    #    /auditLogs/signIns over the lookback window. Per-user lookup is then
    #    a hashtable index; no further Graph calls in the per-user loop.
    $signInEvidence = $null
    if (-not $SkipSignInEvidence -and (Get-Command -Name Get-MfaSignInEvidence -ErrorAction SilentlyContinue)) {
        Write-Verbose "Fetching sign-in evidence (last $SignInLookbackDays days)..."
        try {
            $signInEvidence = Get-MfaSignInEvidence -LookbackDays $SignInLookbackDays -UserIds $UserIds
            if (-not $signInEvidence.Available) {
                Write-Verbose "Sign-in evidence unavailable: $($signInEvidence.FailureReason)"
            }
        }
        catch {
            Write-Verbose "Get-MfaSignInEvidence threw: $($_.Exception.Message)"
            $signInEvidence = $null
        }
    }

    # 4. Per-user resolver loop
    $coverage = [System.Collections.Generic.List[object]]::new()
    $membershipCache = @{}
    $methodsCache = @{}

    foreach ($userId in $UserIds) {
        $userProp = $script:UserPropertyCache[$userId]
        if (-not $userProp -and $bulkRegistrationMap.ContainsKey($userId)) {
            # Synthesise from registration entry
            $r = $bulkRegistrationMap[$userId]
            $userProp = @{
                DisplayName = $r.userDisplayName
                Upn = $r.userPrincipalName
                UserType = if ($r.userType) { $r.userType } else { 'Member' }
                Enabled = $true
            }
        }
        if (-not $userProp) {
            # Fallback: minimal Get-MgUser
            try {
                $u = Get-MgUser -UserId $userId -Property 'Id,DisplayName,UserPrincipalName,AccountEnabled,UserType' -ErrorAction Stop
                $userProp = @{
                    DisplayName = $u.DisplayName
                    Upn = $u.UserPrincipalName
                    UserType = $u.UserType
                    Enabled = $u.AccountEnabled
                }
            }
            catch {
                $userProp = @{ DisplayName = $userId; Upn = $userId; UserType = 'Unknown'; Enabled = $null }
            }
        }

        # Membership
        $membership = Get-UserTransitiveMembership -UserId $userId -Cache $membershipCache
        $membershipResolved = $membership.Available

        # PrivilegedOnly fast filter
        if ($PrivilegedOnly) {
            $isPrivileged = @($membership.Roles | Where-Object { $script:WellKnownAdminRoleTemplateIds -contains $_ }).Count -gt 0
            if (-not $isPrivileged) { continue }
        }

        # Methods
        $methods = Get-UserRegisteredMethods -UserId $userId -BulkRegistrationMap $bulkRegistrationMap -Cache $methodsCache
        $strongest = Get-StrongestMethod -Methods $methods

        # Per-user MFA state
        $perUserMfa = if ($SkipPerUserMfaProbe) { 'Unknown' } else { Get-UserPerUserMfaState -UserId $userId }

        # CA applicability
        $userForResolver = @{
            Id = $userId
            UserType = $userProp.UserType
            Groups = @($membership.Groups)
            Roles = @($membership.Roles)
        }
        $applicable = foreach ($pol in $caPolicies) {
            $check = Test-CaPolicyAppliesTo -User $userForResolver -Policy $pol
            @{ Policy = $pol; Applies = $check.Applies; Conditional = $check.Conditional; Reason = $check.Reason }
        }
        $applicableMatched = @($applicable | Where-Object { $_.Applies })

        # Verdict
        $verdict = Resolve-MfaVerdict `
            -StrongestRegistered $strongest `
            -SecurityDefaultsApplies $securityDefaultsApplies `
            -PerUserMfaState $perUserMfa `
            -ApplicableCaPolicies @($applicableMatched) `
            -UserType $userProp.UserType `
            -MembershipResolved $membershipResolved

        # Service-account heuristic
        $svcSignals = Test-IsServiceAccount -Upn $userProp.Upn -DisplayName $userProp.DisplayName

        # Compose row
        $row = @{
            UserId = $userId
            Upn = $userProp.Upn
            DisplayName = $userProp.DisplayName
            UserType = $userProp.UserType
            Enabled = $userProp.Enabled
            IsServiceAccountSuspected = ($null -ne $svcSignals)
            ServiceAccountSignals = if ($svcSignals) { $svcSignals } else { @() }
            RegisteredMethods = $methods
            StrongestRegistered = $strongest
            SecurityDefaultsApplies = $securityDefaultsApplies
            PerUserMfaState = $perUserMfa
            MembershipResolved = $membershipResolved
            AppliedCaPolicies = @($applicableMatched | ForEach-Object {
                    @{
                        Id = $_.Policy.Id
                        DisplayName = $_.Policy.DisplayName
                        State = $_.Policy.State
                        ReportOnly = $_.Policy.ReportOnly
                        RequiresMfa = $_.Policy.GrantControls.RequiresMfa
                        Conditional = $_.Conditional
                        MatchReason = $_.Reason
                    }
                })
            EffectiveCaMfaRequired = (@($applicableMatched | Where-Object { $_.Policy.Enabled -and $_.Policy.GrantControls.RequiresMfa -and -not $_.Conditional }).Count -gt 0)
            Verdict = $verdict.Verdict
            VerdictReason = $verdict.Reason
            NeedsReviewBecause = $verdict.NeedsReviewBecause

            # PR 4 — sign-in evidence + drift
            SignInEvidenceAvailable = [bool]($signInEvidence -and $signInEvidence.Available)
            LastMfaMethodUsed = $null
            LastSignInAt = $null
            SignInsLastNDays = $null
            MfaChallengeOccurred = $null
            MethodsObserved = @()
            DriftFinding = $null
        }

        if ($signInEvidence -and $signInEvidence.Available) {
            $row.SignInsLastNDays = 0
            $userEv = $signInEvidence.Evidence[$userId]
            if ($userEv) {
                $row.LastMfaMethodUsed = $userEv.LastMfaMethodUsed
                $row.LastSignInAt = if ($userEv.LastSignInAt) { $userEv.LastSignInAt.ToString('o') } else { $null }
                $row.SignInsLastNDays = $userEv.SignInsCount
                $row.MfaChallengeOccurred = $userEv.MfaChallengeOccurred
                $row.MethodsObserved = @($userEv.MethodsObserved)
            }
            if (Get-Command -Name Resolve-MfaDrift -ErrorAction SilentlyContinue) {
                $row.DriftFinding = Resolve-MfaDrift -RegisteredMethods $methods -Evidence $userEv
            }
        }

        [void]$coverage.Add($row)
    }

    # Statistics
    $stats = @{
        ScannedAt = (Get-Date).ToUniversalTime().ToString('o')
        TotalUsers = $coverage.Count
        EnforcedStrong = @($coverage | Where-Object { $_.Verdict -eq 'EnforcedStrong' }).Count
        EnforcedWeak = @($coverage | Where-Object { $_.Verdict -eq 'EnforcedWeak' }).Count
        RegisteredUnenforced = @($coverage | Where-Object { $_.Verdict -eq 'RegisteredUnenforced' }).Count
        NotRegistered = @($coverage | Where-Object { $_.Verdict -eq 'NotRegistered' }).Count
        NeedsReview = @($coverage | Where-Object { $_.Verdict -eq 'NeedsReview' }).Count
        DriftFindings = @($coverage | Where-Object { $_.DriftFinding }).Count
        SignInEvidenceAvailable = [bool]($signInEvidence -and $signInEvidence.Available)
        SignInLookbackDays = if ($signInEvidence) { $signInEvidence.LookbackDays } else { $null }
        ServiceAccountsSuspected = @($coverage | Where-Object { $_.IsServiceAccountSuspected }).Count
    }

    return @{
        Available = $true
        FailureReason = $null
        Tenant = @{ TenantId = $env.TenantId; Account = $env.Account }
        Coverage = @($coverage)
        Statistics = $stats
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-UserMfaCoverage'
)

#endregion
