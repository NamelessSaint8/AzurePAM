<#
.SYNOPSIS
    EntraChecks-MFASignInEvidence.psm1
    Sign-in evidence layer for the MFA resolver (PR 4 of MFA Detection).

.DESCRIPTION
    Cross-references what's REGISTERED (PR 1 catalog + PR 3 resolver) with
    what's ACTUALLY USED (Graph audit-log /auditLogs/signIns over a 30-day
    lookback window). Surfaces three drift cases an auditor cares about:

      1. Registered phishing-resistant method but every recent sign-in used
         a Strong or Weak method instead — the strong method exists but
         isn't the path actually being walked.
      2. Registered any MFA but no MFA challenge in the lookback window —
         user might be hitting an excluded path that bypasses MFA entirely.
      3. Registered Strong methods but recent sign-ins used Weak methods —
         opportunity to remove the weak method.

    Bulk fetch strategy: one paginated call against /auditLogs/signIns with
    a createdDateTime filter. Users are aggregated locally. This trades one
    large fetch for N per-user fetches; at 10k+ users the bulk path is
    dramatically faster.

.NOTES
    Required Microsoft Graph scopes:
        - AuditLog.Read.All
        - Directory.Read.All

    License gating:
        Sign-in audit logs require Azure AD P1 or higher. When the API
        returns 403, the layer degrades gracefully — Available=$false plus
        a FailureReason note — instead of failing the resolver run.

    Lookback window default = 30 days. Larger windows (90 days) are common
    in audit contexts but cost more API time.

.LINK
    Plan: plans/MFA-Detection-Plan.md (PR 4)
    Catalog: Modules/EntraChecks-AuthMethodCatalog.psm1 (PR 1)
    Resolver: Modules/EntraChecks-MFAResolver.psm1 (PR 3)
#>

#Requires -Version 5.1

$script:ModulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $script:ModulePath 'EntraChecks-AuthMethodCatalog.psm1') -Force -DisableNameChecking -ErrorAction SilentlyContinue

$script:ModuleVersion = '1.0.0'
$script:ModuleName = 'EntraChecks-MFASignInEvidence'

#region ==================== MODULE STATE ====================

# Heuristic mapping from Graph sign-in authenticationMethod display strings
# back to canonical catalog keys. The audit-log API returns friendly names
# rather than @odata.type values, so we cannot reuse Resolve-AuthMethodKey
# directly.
$script:SignInMethodDisplayMap = @{
    'mobile app notification'              = 'microsoftAuthenticatorPush'
    'mobile app verification code'         = 'microsoftAuthenticatorPush'
    'authenticator app notification'       = 'microsoftAuthenticatorPush'
    'phone app notification'               = 'microsoftAuthenticatorPush'
    'authenticator app oath token'         = 'softwareOath'
    'oath verification code'               = 'softwareOath'
    'oath software token'                  = 'softwareOath'
    'sms'                                  = 'mobilePhone'
    'text message'                         = 'mobilePhone'
    'phone call'                           = 'voiceCall'
    'voice call'                           = 'voiceCall'
    'email'                                = 'email'
    'fido2 security key'                   = 'fido2'
    'fido2'                                = 'fido2'
    'windows hello for business'           = 'windowsHelloForBusiness'
    'windows hello'                        = 'windowsHelloForBusiness'
    'temporary access pass'                = 'temporaryAccessPass'
    'certificate'                          = 'certificateBasedAuth'
    'x509 certificate'                     = 'certificateBasedAuth'
    'password'                             = 'password'
    'security question'                    = 'securityQuestions'
}

#endregion

#region ==================== PRIVATE HELPERS ====================

function ConvertTo-CanonicalSignInMethod {
    <#
    .SYNOPSIS
        Maps a Graph sign-in authenticationMethod display string to a
        canonical catalog key. Returns $null on no match.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param([string]$DisplayName)

    if (-not $DisplayName) { return $null }
    $key = $DisplayName.Trim().ToLower()
    if ($script:SignInMethodDisplayMap.ContainsKey($key)) {
        return $script:SignInMethodDisplayMap[$key]
    }
    # Token-fall-through: try matching on substring
    foreach ($k in $script:SignInMethodDisplayMap.Keys) {
        if ($key -like "*$k*") { return $script:SignInMethodDisplayMap[$k] }
    }
    return $null
}

function Test-MFASignInEvidenceEnvironment {
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param()

    $mgModule = Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' -ErrorAction SilentlyContinue
    if (-not $mgModule) {
        return [pscustomobject]@{
            IsAvailable = $false
            FailureReason = 'Microsoft.Graph module not installed.'
        }
    }
    if (-not (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ IsAvailable = $false; FailureReason = 'Microsoft.Graph.Authentication is not loaded.' }
    }
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        return [pscustomobject]@{ IsAvailable = $false; FailureReason = 'No Microsoft Graph context. Connect-MgGraph first.' }
    }
    return [pscustomobject]@{ IsAvailable = $true; TenantId = $ctx.TenantId }
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-MfaSignInEvidence {
    <#
    .SYNOPSIS
        Returns per-user sign-in evidence over the lookback window.

    .PARAMETER LookbackDays
        Number of days back to query. Default 30.

    .PARAMETER UserIds
        Optional restriction list. When supplied, the bulk fetch is still
        used but only matching users appear in the output map (avoids
        returning evidence for users PR 3 didn't resolve).

    .OUTPUTS
        @{
            Available        = $true | $false
            FailureReason    = $null | <string>
            LookbackDays     = N
            CutoffDateTime   = '<ISO-8601>'
            Evidence         = @{ <userId> -> @{
                                    UserId
                                    SignInsCount
                                    LastSignInAt
                                    LastMfaMethodUsed   # canonical key or $null
                                    MethodsObserved     # @() of canonical keys seen
                                    MfaChallengeOccurred = $true | $false
                                  } }
            Statistics       = @{ TotalSignIns; UsersWithEvidence; ScannedAt }
        }
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [int]$LookbackDays = 30,
        [string[]]$UserIds
    )

    $env = Test-MFASignInEvidenceEnvironment
    if (-not $env.IsAvailable) {
        return @{
            Available = $false
            FailureReason = $env.FailureReason
            LookbackDays = $LookbackDays
            CutoffDateTime = $null
            Evidence = @{}
            Statistics = @{ ScannedAt = (Get-Date).ToUniversalTime().ToString('o') }
        }
    }

    $cutoff = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays)
    $cutoffIso = $cutoff.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $userIdSet = if ($UserIds) { @{} } else { $null }
    if ($userIdSet -ne $null) { foreach ($u in $UserIds) { $userIdSet[$u] = $true } }

    $evidence = @{}
    $totalSignIns = 0

    try {
        # Bulk fetch with paging — single-pass over /auditLogs/signIns.
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $cutoffIso&`$top=999"
        $page = $null

        while ($true) {
            if (-not $page) {
                $page = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            }
            else {
                if (-not $page.'@odata.nextLink') { break }
                $page = Invoke-MgGraphRequest -Method GET -Uri $page.'@odata.nextLink' -ErrorAction Stop
            }
            foreach ($s in @($page.value)) {
                $totalSignIns++
                $userId = $s.userId
                if (-not $userId) { continue }
                if ($userIdSet -and -not $userIdSet.ContainsKey($userId)) { continue }

                if (-not $evidence.ContainsKey($userId)) {
                    $evidence[$userId] = @{
                        UserId = $userId
                        SignInsCount = 0
                        LastSignInAt = $null
                        LastMfaMethodUsed = $null
                        MethodsObserved = @{}
                        MfaChallengeOccurred = $false
                    }
                }
                $row = $evidence[$userId]
                $row.SignInsCount += 1

                # Track last-sign-in-at
                if ($s.createdDateTime) {
                    $dt = if ($s.createdDateTime -is [datetime]) { $s.createdDateTime } else { [datetime]::Parse([string]$s.createdDateTime) }
                    if (-not $row.LastSignInAt -or ($dt -gt $row.LastSignInAt)) {
                        $row.LastSignInAt = $dt
                    }
                }

                # Inspect authenticationDetails for MFA evidence
                $authDetails = @($s.authenticationDetails)
                $thisSignInMfaMethod = $null
                $thisSignInIsMfa = $false
                foreach ($d in $authDetails) {
                    $methodDisplay = $d.authenticationMethod
                    $key = ConvertTo-CanonicalSignInMethod -DisplayName $methodDisplay
                    if (-not $key) { continue }
                    if ($key -in @('password', 'securityQuestions')) { continue }
                    $row.MethodsObserved[$key] = $true
                    # Counts as an MFA challenge if the step succeeded
                    if ($d.succeeded -eq $true -or $d.authenticationStepResultDetail -in @('Success', 'MFA completed in Azure AD')) {
                        $thisSignInIsMfa = $true
                        $thisSignInMfaMethod = $key
                    }
                }
                if ($thisSignInIsMfa) {
                    $row.MfaChallengeOccurred = $true
                    if ($thisSignInMfaMethod -and ($null -eq $row.LastMfaMethodUsed -or ($row.LastSignInAt -eq $dt))) {
                        $row.LastMfaMethodUsed = $thisSignInMfaMethod
                    }
                }
            }
            if (-not $page.'@odata.nextLink') { break }
        }
    }
    catch {
        return @{
            Available = $false
            FailureReason = "Sign-in evidence query failed (likely missing AuditLog.Read.All scope or P1 license): $($_.Exception.Message)"
            LookbackDays = $LookbackDays
            CutoffDateTime = $cutoffIso
            Evidence = @{}
            Statistics = @{ ScannedAt = (Get-Date).ToUniversalTime().ToString('o') }
        }
    }

    # Convert per-user MethodsObserved hash to array
    foreach ($u in @($evidence.Keys)) {
        $evidence[$u].MethodsObserved = @($evidence[$u].MethodsObserved.Keys | Sort-Object)
    }

    return @{
        Available = $true
        FailureReason = $null
        LookbackDays = $LookbackDays
        CutoffDateTime = $cutoffIso
        Evidence = $evidence
        Statistics = @{
            TotalSignIns = $totalSignIns
            UsersWithEvidence = $evidence.Count
            ScannedAt = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
}

function Resolve-MfaDrift {
    <#
    .SYNOPSIS
        Pure-logic drift detector. Compares registered methods to the
        per-user evidence and emits a finding when a notable mismatch is
        present. Returns $null when no drift.

    .PARAMETER RegisteredMethods
        Array of canonical method keys (PR 1 catalog).

    .PARAMETER Evidence
        Per-user evidence row from Get-MfaSignInEvidence.Evidence[$userId].
        $null when the user had no sign-ins or evidence is unavailable.

    .OUTPUTS
        $null OR @{ Severity; Reason; Code }
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [string[]]$RegisteredMethods,
        [hashtable]$Evidence
    )

    if (-not $RegisteredMethods -or @($RegisteredMethods).Count -eq 0) {
        # No registered methods is its own verdict (NotRegistered) — drift
        # detection has nothing to compare against.
        return $null
    }

    if (-not $Evidence) {
        # No sign-in activity in the lookback window. Could mean:
        #   - dormant account (informational)
        #   - service account that uses a different auth path
        #   - genuinely off-radar
        # We don't emit a drift finding here; the resolver's verdict
        # (NotRegistered / RegisteredUnenforced) is more meaningful.
        return $null
    }

    if ($Evidence.SignInsCount -eq 0) { return $null }

    $registeredStrongest = Get-StrongestMethod -Methods $RegisteredMethods
    $observed = @($Evidence.MethodsObserved)

    # Case 1: registered MFA but no MFA challenge ever
    if (-not $Evidence.MfaChallengeOccurred -and $registeredStrongest -ne 'None') {
        return @{
            Severity = 'Medium'
            Code = 'NoMfaChallengeDespiteRegistration'
            Reason = "User has registered MFA methods ($($RegisteredMethods -join ', ')) but no sign-in in the last $($Evidence.SignInsCount) recorded sign-ins challenged for MFA. Likely hitting an excluded path or persistent-token reuse."
        }
    }

    # Case 2: registered phishing-resistant but never used
    $hasPhishingResistantRegistered = @($RegisteredMethods | Where-Object { (Get-AuthMethodStrength -Key $_) -eq 'PhishingResistant' }).Count -gt 0
    if ($hasPhishingResistantRegistered -and @($observed).Count -gt 0) {
        $observedStrongest = Get-StrongestMethod -Methods $observed
        if ($observedStrongest -ne 'PhishingResistant') {
            return @{
                Severity = 'Medium'
                Code = 'PhishingResistantRegisteredButUnused'
                Reason = "User has phishing-resistant methods registered (FIDO2 / Windows Hello / passkey / CBA) but every observed sign-in used $observedStrongest methods ($($observed -join ', ')). Investigate why the strong method isn't the one being used."
            }
        }
    }

    # Case 3: registered Strong + Weak; only Weak observed
    $hasStrongRegistered = @($RegisteredMethods | Where-Object { (Get-AuthMethodStrength -Key $_) -in @('PhishingResistant', 'Strong') }).Count -gt 0
    if ($hasStrongRegistered -and @($observed).Count -gt 0) {
        $observedStrongest = Get-StrongestMethod -Methods $observed
        if ($observedStrongest -eq 'Weak') {
            return @{
                Severity = 'Medium'
                Code = 'StrongRegisteredButOnlyWeakUsed'
                Reason = "User has a Strong or Phishing-Resistant method registered but every observed sign-in used Weak methods (SMS / voice / email): $($observed -join ', '). Consider removing the weak methods."
            }
        }
    }

    return $null
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-MfaSignInEvidence',
    'Resolve-MfaDrift'
)

#endregion
