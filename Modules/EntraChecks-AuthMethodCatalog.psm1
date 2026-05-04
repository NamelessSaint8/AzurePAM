<#
.SYNOPSIS
    EntraChecks-AuthMethodCatalog.psm1
    Authoritative catalog of every Entra authentication method, classified by
    strength tier with auditor-grade explanations.

.DESCRIPTION
    Answers two questions for the MFA Resolver (PR 3) and reporting layer
    (PR 5):
        1. What is the strength of this method?
           -> 'PhishingResistant' | 'Strong' | 'Weak' | 'None'
        2. Why is it classified that way?
           -> WhyClassified paragraph + ReferenceUrl

    Resolves both naming conventions Microsoft Graph returns:
      - @odata.type values from /users/{id}/authentication/methods
        (e.g., '#microsoft.graph.fido2AuthenticationMethod')
      - methodsRegistered values from /reports/authenticationMethods/userRegistrationDetails
        (e.g., 'fido2', 'softwareOneTimePasscode')

    Adding a new method = one new entry in $script:AuthMethodCatalog plus
    optional aliases.

.NOTES
    Strength tiers (canonical):
        PhishingResistant — origin-bound asymmetric crypto (FIDO2, WHfB,
            passkeys, certificate-based auth). Cannot be replayed against a
            phishing site. Required for Tier 0 admins by current Microsoft
            guidance.
        Strong            — multifactor, but a real-time phishing proxy can
            still capture and replay (TOTP, Authenticator push with number
            matching, hardware OATH, TAP). Acceptable for general users.
        Weak              — phishable trivially (SMS, voice call, email OTP).
            NIST SP 800-63B downgraded SMS in 2017; Microsoft considers it the
            lowest-tier MFA.
        None              — single factor or knowledge-only (password,
            security questions). Listed for completeness so the resolver can
            identify "no MFA registered".

.LINK
    Plan: plans/MFA-Detection-Plan.md (PR 1)
#>

#Requires -Version 5.1

$script:ModuleVersion = '1.0.0'
$script:ModuleName = 'EntraChecks-AuthMethodCatalog'

#region ==================== CATALOG ====================

# Canonical key naming follows the registrationDetails endpoint where
# possible (more granular than @odata.type). The resolver maps the cruder
# @odata.type values onto these canonical keys.

$script:AuthMethodCatalog = @{

    #region ---- PhishingResistant tier ----

    'fido2' = @{
        Key = 'fido2'
        DisplayName = 'FIDO2 security key'
        Strength = 'PhishingResistant'
        Aliases = @('fido2', 'fido2AuthenticationMethod')
        WhyClassified = 'Hardware-bound asymmetric key with origin binding (WebAuthn). The key signs only when the relying-party origin matches the registered one, so a phishing site cannot induce a valid signature even with a tricked user. Microsoft and NIST SP 800-63B both classify FIDO2 as phishing-resistant. The required posture for Tier 0 admins.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless#fido2-security-keys'
    }

    'windowsHelloForBusiness' = @{
        Key = 'windowsHelloForBusiness'
        DisplayName = 'Windows Hello for Business'
        Strength = 'PhishingResistant'
        Aliases = @('windowsHelloForBusiness', 'windowsHelloForBusinessAuthenticationMethod', 'whfb')
        WhyClassified = 'Device-bound asymmetric key tied to a TPM and gated by a local biometric or PIN. Like FIDO2, the credential is origin-bound and cannot be replayed across sites. Considered phishing-resistant by Microsoft.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/'
    }

    'passKeyDeviceBound' = @{
        Key = 'passKeyDeviceBound'
        DisplayName = 'Microsoft Authenticator passkey (device-bound)'
        Strength = 'PhishingResistant'
        Aliases = @('passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'microsoftAuthenticatorPasskey')
        WhyClassified = 'WebAuthn passkey stored in the Microsoft Authenticator app, bound to the registering device. Same phishing resistance as FIDO2 — origin-checked at signing time. Distinct from synced/iCloud-Keychain passkeys, which Microsoft does not yet treat as enterprise phishing-resistant.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless'
    }

    'certificateBasedAuth' = @{
        Key = 'certificateBasedAuth'
        DisplayName = 'Certificate-based authentication (CBA)'
        Strength = 'PhishingResistant'
        Aliases = @('certificateBasedAuth', 'certificateBasedAuthConfiguration', 'x509Certificate', 'x509CertificateAuthenticationMethod')
        WhyClassified = 'X.509 client certificate authentication. When the certificate is on a smart card or HSM (high-assurance), it is phishing-resistant — the private key never leaves the hardware. Lower-assurance CBA (soft-cert in user store) is closer to Strong than PhishingResistant; the catalog assumes the high-assurance posture and reports the low-assurance edge as a NeedsReview signal at the resolver level.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication'
    }

    #endregion

    #region ---- Strong tier ----

    'microsoftAuthenticatorPush' = @{
        Key = 'microsoftAuthenticatorPush'
        DisplayName = 'Microsoft Authenticator (push notification)'
        Strength = 'Strong'
        Aliases = @('microsoftAuthenticatorPush', 'microsoftAuthenticatorAuthenticationMethod', 'microsoftAuthenticator')
        WhyClassified = 'Push approval with number matching (mandatory globally since Feb 2023). Number matching defeats MFA-fatigue / push-bombing attacks because the user must transcribe a number from the sign-in screen into the app. NOT phishing-resistant — a real-time relayed sign-in can still capture a matching number from a tricked user. Acceptable for general users; insufficient for Tier 0/1 admins.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match'
    }

    'microsoftAuthenticatorPasswordless' = @{
        Key = 'microsoftAuthenticatorPasswordless'
        DisplayName = 'Microsoft Authenticator (passwordless sign-in)'
        Strength = 'Strong'
        Aliases = @('microsoftAuthenticatorPasswordless', 'microsoftAuthenticatorPasswordlessSignIn')
        WhyClassified = 'Passwordless phone sign-in via Authenticator. Stronger than push because there is no password phase, but the approval gesture is similar — a phishing proxy can still ask the user to approve a relayed sign-in. Microsoft recommends combining with conditional access for additional gating.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-phone'
    }

    'softwareOath' = @{
        Key = 'softwareOath'
        DisplayName = 'Software OATH (TOTP)'
        Strength = 'Strong'
        Aliases = @('softwareOath', 'softwareOathAuthenticationMethod', 'softwareOneTimePasscode', 'totp')
        WhyClassified = 'Time-based one-time password (RFC 6238) generated by an authenticator app from a shared secret. Resists generic password phishing. NOT phishing-resistant in the FIDO2/WebAuthn sense — an attacker proxying the sign-in flow can capture the 30-second code in real time and use it before it expires. Acceptable for general users; insufficient for Tier 0/1 admins.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-oath-tokens'
    }

    'hardwareOath' = @{
        Key = 'hardwareOath'
        DisplayName = 'Hardware OATH token'
        Strength = 'Strong'
        Aliases = @('hardwareOath', 'hardwareOneTimePasscode', 'hardwareOathAuthenticationMethod')
        WhyClassified = 'Hardware token (typically YubiKey OTP, Feitian) generating TOTP codes. Same phishing-resistance properties as software OATH — the code can be relayed in real time by a phishing proxy. Stronger than software OATH only in that the secret never lived on a phone. Strong, not phishing-resistant.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-oath-tokens'
    }

    'temporaryAccessPass' = @{
        Key = 'temporaryAccessPass'
        DisplayName = 'Temporary Access Pass (TAP)'
        Strength = 'Strong'
        Aliases = @('temporaryAccessPass', 'temporaryAccessPassAuthenticationMethod', 'tap')
        WhyClassified = 'Time-limited passcode issued by an admin for onboarding or recovery. Treated as MFA for the duration of its validity window (default 1 hour, max 30 days). Should be short-lived and one-time; long-lived TAPs are a finding because they degrade to a shared-password failure mode.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass'
    }

    #endregion

    #region ---- Weak tier ----

    'mobilePhone' = @{
        Key = 'mobilePhone'
        DisplayName = 'SMS to mobile phone'
        Strength = 'Weak'
        Aliases = @('mobilePhone', 'sms', 'phoneAuthenticationMethod-mobile')
        WhyClassified = 'One-time code delivered via SMS. Vulnerable to SIM-swap, port-out fraud, SS7 interception, and mobile-malware capture. NIST SP 800-63B downgraded SMS as a restricted authenticator in 2017. Microsoft classifies SMS as the lowest-tier MFA method — useful only when the alternative is single-factor.'
        ReferenceUrl = 'https://pages.nist.gov/800-63-3/sp800-63b.html'
    }

    'alternateMobilePhone' = @{
        Key = 'alternateMobilePhone'
        DisplayName = 'SMS to alternate mobile phone'
        Strength = 'Weak'
        Aliases = @('alternateMobilePhone')
        WhyClassified = 'Same SMS substrate as the primary mobile phone, just registered as a backup number. Same SIM-swap and SS7 attack surface. Often a forgotten registration that survives the user changing carriers — auditors should review whether the alternate number is still owned by the user.'
        ReferenceUrl = 'https://pages.nist.gov/800-63-3/sp800-63b.html'
    }

    'voiceCall' = @{
        Key = 'voiceCall'
        DisplayName = 'Voice call (office or landline)'
        Strength = 'Weak'
        Aliases = @('voiceCall', 'office', 'phoneAuthenticationMethod-office', 'phoneAuthenticationMethod-alternateMobile')
        WhyClassified = 'Phone call delivers a code or asks the user to press # to approve. Same telephony substrate as SMS — vulnerable to call forwarding, voicemail interception, and PBX compromise. Often configured against a desk phone that any office visitor can answer.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-phone-options'
    }

    'email' = @{
        Key = 'email'
        DisplayName = 'Email one-time code'
        Strength = 'Weak'
        Aliases = @('email', 'emailAuthenticationMethod')
        WhyClassified = 'OTP delivered via email. Reduces to single-factor if the email account itself is compromised — and email is often the recovery surface for every other account. Microsoft restricts email OTP primarily to Self-Service Password Reset and B2B guest sign-in flows; auditors should treat its presence on enterprise users as a misconfiguration.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods'
    }

    #endregion

    #region ---- None tier ----

    'securityQuestions' = @{
        Key = 'securityQuestions'
        DisplayName = 'Security questions'
        Strength = 'None'
        Aliases = @('securityQuestions', 'securityQuestion')
        WhyClassified = 'Knowledge-only factor. Not multi-factor. Microsoft restricts security questions to Self-Service Password Reset and explicitly does NOT count them as MFA. Listed in the catalog so the resolver can correctly identify "no MFA registered" when this is the only method.'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-security-questions'
    }

    'password' = @{
        Key = 'password'
        DisplayName = 'Password'
        Strength = 'None'
        Aliases = @('password', 'passwordAuthenticationMethod')
        WhyClassified = 'Single factor. Not MFA. Listed for completeness so the resolver can distinguish "user has only a password" from "user has password + something else".'
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods'
    }

    #endregion
}

# Strength ordering used by Get-StrongestMethod. Lower number = stronger.
$script:StrengthOrder = @{
    'PhishingResistant' = 0
    'Strong'            = 1
    'Weak'              = 2
    'None'              = 3
    'Unknown'           = 4
}

#endregion

#region ==================== PRIVATE HELPERS ====================

function ConvertTo-AuthMethodClone {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable]$Descriptor)

    $clone = @{}
    foreach ($k in $Descriptor.Keys) {
        $v = $Descriptor[$k]
        if ($v -is [array]) { $clone[$k] = @($v) } else { $clone[$k] = $v }
    }
    return $clone
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-AuthMethodCatalog {
    <#
    .SYNOPSIS
        Returns a fresh clone of the full auth method catalog.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()

    $result = @{}
    foreach ($k in $script:AuthMethodCatalog.Keys) {
        $result[$k] = ConvertTo-AuthMethodClone -Descriptor $script:AuthMethodCatalog[$k]
    }
    return $result
}

function Get-AuthMethodDescriptor {
    <#
    .SYNOPSIS
        Returns a clone of one named descriptor.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Key)

    if (-not $script:AuthMethodCatalog.ContainsKey($Key)) {
        throw "Unknown auth method key: '$Key'. Use Get-AuthMethodKeys to list valid keys."
    }
    return ConvertTo-AuthMethodClone -Descriptor $script:AuthMethodCatalog[$Key]
}

function Get-AuthMethodKeys {
    <#
    .SYNOPSIS
        Returns the sorted list of auth-method catalog keys, optionally
        filtered by strength tier.
    #>
    [OutputType([string[]])]
    [CmdletBinding()]
    param(
        [ValidateSet('PhishingResistant', 'Strong', 'Weak', 'None')]
        [string]$Strength
    )

    $keys = $script:AuthMethodCatalog.Keys
    if ($Strength) {
        $keys = $keys | Where-Object { $script:AuthMethodCatalog[$_].Strength -eq $Strength }
    }
    return [string[]]@($keys | Sort-Object)
}

function Get-AuthMethodStrength {
    <#
    .SYNOPSIS
        Returns the strength tier for a canonical auth method key.
    .OUTPUTS
        'PhishingResistant' | 'Strong' | 'Weak' | 'None' | 'Unknown'
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Key)

    if ($script:AuthMethodCatalog.ContainsKey($Key)) {
        return $script:AuthMethodCatalog[$Key].Strength
    }
    return 'Unknown'
}

function Resolve-AuthMethodKey {
    <#
    .SYNOPSIS
        Maps a Graph-side identifier to a canonical catalog key.

    .DESCRIPTION
        Microsoft Graph returns auth-method identifiers in two flavors:
        - @odata.type values from /users/{id}/authentication/methods
          (e.g., '#microsoft.graph.fido2AuthenticationMethod')
        - methodsRegistered values from
          /reports/authenticationMethods/userRegistrationDetails
          (e.g., 'fido2', 'softwareOneTimePasscode')

        This resolver handles both. It also handles the phoneAuthenticationMethod
        case where the @odata.type alone is ambiguous and the caller must pass
        -PhoneType.

    .PARAMETER Identifier
        The Graph-side identifier (case-insensitive). Strips the
        '#microsoft.graph.' prefix and the 'AuthenticationMethod' suffix
        before matching aliases.

    .PARAMETER PhoneType
        Required when resolving phoneAuthenticationMethod entries. Values:
        'mobile' | 'alternateMobile' | 'office'.

    .OUTPUTS
        Canonical key (string) or $null when no match.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Identifier,
        [ValidateSet('mobile', 'alternateMobile', 'office')]
        [string]$PhoneType
    )

    $needle = $Identifier.Trim()
    # Normalise the @odata.type form
    $needle = $needle -replace '^#microsoft\.graph\.', ''

    # Special-case phone auth — disambiguate via PhoneType
    if ($needle -ieq 'phoneAuthenticationMethod' -or $needle -ieq 'phone') {
        switch ($PhoneType) {
            'mobile'          { return 'mobilePhone' }
            'alternateMobile' { return 'alternateMobilePhone' }
            'office'          { return 'voiceCall' }
            default {
                Write-Verbose "Resolve-AuthMethodKey: phoneAuthenticationMethod requires -PhoneType to disambiguate."
                return $null
            }
        }
    }

    foreach ($key in $script:AuthMethodCatalog.Keys) {
        $entry = $script:AuthMethodCatalog[$key]
        if ($entry.Key -ieq $needle) { return $key }
        foreach ($alias in @($entry.Aliases)) {
            if ($alias -ieq $needle) { return $key }
        }
    }
    return $null
}

function Get-StrongestMethod {
    <#
    .SYNOPSIS
        Returns the strongest tier present in a list of canonical method keys.

    .DESCRIPTION
        Tier ordering: PhishingResistant > Strong > Weak > None.
        Methods not in the catalog are treated as 'Unknown' and ignored when
        a recognized method is also present; if ALL methods are unknown, the
        function returns 'Unknown'.

    .PARAMETER Methods
        Array of canonical keys (post-Resolve-AuthMethodKey).

    .OUTPUTS
        'PhishingResistant' | 'Strong' | 'Weak' | 'None' | 'Unknown'
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param([string[]]$Methods)

    if (-not $Methods -or @($Methods).Count -eq 0) { return 'None' }

    $best = 'Unknown'
    $bestRank = $script:StrengthOrder['Unknown']
    foreach ($m in @($Methods)) {
        $tier = Get-AuthMethodStrength -Key $m
        $rank = if ($script:StrengthOrder.ContainsKey($tier)) { $script:StrengthOrder[$tier] } else { $script:StrengthOrder['Unknown'] }
        if ($rank -lt $bestRank) {
            $best = $tier
            $bestRank = $rank
        }
    }
    return $best
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-AuthMethodCatalog',
    'Get-AuthMethodDescriptor',
    'Get-AuthMethodKeys',
    'Get-AuthMethodStrength',
    'Resolve-AuthMethodKey',
    'Get-StrongestMethod'
)

#endregion
