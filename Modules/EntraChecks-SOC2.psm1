<#
.SYNOPSIS
    EntraChecks-SOC2.psm1 - SOC 2 orchestration, TSC catalog, synthetic checks,
    evidence bundle, PII redaction, and identity resolution for EntraChecks.

.DESCRIPTION
    Implements SOC 2 (AICPA TSC 2017, revised 2022) assessment workflow on top
    of the existing EntraChecks assessment engine. Primary use case is an
    internal readiness check for Microsoft 365 / Azure environments.

    Core responsibilities:
    - Define the authoritative Trust Services Criteria catalog (all 5 categories:
      CC, A, C, PI, P) including automation status and control-owner hints.
    - Ingest findings produced by the unified EntraChecks run and map them to
      TSC controls via EntraChecks-ComplianceMapping.
    - Emit synthetic findings for TSC controls that need SOC-2-specific probes
      (admin contacts, security alerting readiness, incident response readiness).
    - Emit MANUAL-attestation findings for non-automatable TSC controls so the
      internal team sees the complete TSC landscape.
    - Produce a tamper-evident evidence bundle (SHA-256 hashes per file + rolling
      bundle hash) suitable for internal retention.
    - Redact PII by default (SHA-256 salted hashing) while emitting a companion
      identity-resolution map so internal remediation teams can resolve hashes
      back to UPNs.

.NOTES
    Version: 1.0.0
    Author: EntraChecks Project
    TSC revision: AICPA TSC 2017 (revised 2022)
    Read-only: This module never modifies tenant configuration.

.LINK
    SOC 2 Implementation Plan: plans/SOC2-Implementation-Plan.md
    SOC 2 Guide: docs/SOC2-Guide.md
#>

#Requires -Version 5.1

$script:ModuleName = 'EntraChecks-SOC2'
$script:ModuleVersion = '1.0.0'
$script:TSCRevision = 'AICPA TSC 2017 (revised 2022)'

#region ==================== TSC CATALOG ====================

<#
.SYNOPSIS
    Builds the authoritative Trust Services Criteria catalog used by the SOC 2
    assessment. Uses individual assignments (not hashtable literal) to avoid
    the PSScriptAnalyzer CheckHashtable alignment conflict documented in
    the project memory.
#>
function Get-SOC2TSCCatalog {
    <#
    .SYNOPSIS
        Returns the authoritative catalog of SOC 2 Trust Services Criteria.

    .DESCRIPTION
        Returns an ordered catalog of TSC controls with their family, automation
        status (Automated / Supporting / Manual), description, control-owner hint,
        and the EntraChecks finding types that map to each control.

        Filter by category to return only a subset (e.g., "CC" for Common Criteria).

    .PARAMETER Categories
        Optional array of TSC categories to include. Valid values:
        CC, A, C, PI, P. Defaults to all categories.

    .OUTPUTS
        Array of hashtables, one per TSC control.

    .EXAMPLE
        Get-SOC2TSCCatalog
        Returns the full catalog.

    .EXAMPLE
        Get-SOC2TSCCatalog -Categories @('CC', 'A')
        Returns only Common Criteria and Availability controls.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [ValidateSet('CC', 'A', 'C', 'PI', 'P')]
        [string[]]$Categories = @('CC', 'A', 'C', 'PI', 'P')
    )

    $catalog = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $script:TSCCatalog) {
        if ($entry.Family -in $Categories) {
            $catalog.Add([pscustomobject]$entry) | Out-Null
        }
    }

    return $catalog.ToArray()
}

function Initialize-SOC2Catalog {
    <#
    .SYNOPSIS
        Initializes the module-scoped TSC catalog. Idempotent.
    .DESCRIPTION
        Called once on module import. Populates $script:TSCCatalog with every
        TSC control in scope, including its family, automation status, description,
        control-owner hint, and mapped EntraChecks finding types.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    if ($script:TSCCatalogInitialized) { return }

    $catalog = [System.Collections.Generic.List[hashtable]]::new()

    # CC1 - Control Environment (all manual)
    foreach ($id in @('CC1.1', 'CC1.2', 'CC1.3', 'CC1.4', 'CC1.5')) {
        $entry = @{}
        $entry['Id'] = $id
        $entry['Family'] = 'CC'
        $entry['FamilyName'] = 'Control Environment'
        $entry['Automation'] = 'Manual'
        $entry['Description'] = "CC1 Control Environment - $id establishes the foundation of the organization's internal control system (integrity, ethics, org structure, HR). Not observable via Graph/Azure."
        $entry['ControlOwnerHint'] = 'HR / Executive'
        $entry['MappedFindingTypes'] = @()
        $catalog.Add($entry) | Out-Null
    }

    # CC2 - Communication & Information
    $e = @{}
    $e['Id'] = 'CC2.1'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Communication & Information'
    $e['Automation'] = 'Supporting'
    $e['Description'] = 'Relevant information is identified and communicated to support internal control (admin contact presence, communication channels).'
    $e['ControlOwnerHint'] = 'Security / IT Ops'
    $e['MappedFindingTypes'] = @('SOC2_AdminContactsMissing', 'SOC2_SecurityContactsMissing')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC2.2'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Communication & Information'
    $e['Automation'] = 'Manual'
    $e['Description'] = 'Internal communication supports the functioning of internal control (policy distribution, training records). Organizational.'
    $e['ControlOwnerHint'] = 'Compliance / HR'
    $e['MappedFindingTypes'] = @()
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC2.3'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Communication & Information'
    $e['Automation'] = 'Supporting'
    $e['Description'] = 'External communication channels for incidents and security notifications.'
    $e['ControlOwnerHint'] = 'Security / IT Ops'
    $e['MappedFindingTypes'] = @('SOC2_AdminContactsMissing')
    $catalog.Add($e) | Out-Null

    # CC3 - Risk Assessment (manual with supporting signals)
    foreach ($id in @('CC3.1', 'CC3.2', 'CC3.3', 'CC3.4')) {
        $e = @{}
        $e['Id'] = $id
        $e['Family'] = 'CC'
        $e['FamilyName'] = 'Risk Assessment'
        $e['Automation'] = 'Supporting'
        $e['Description'] = "CC3 Risk Assessment - $id specifies objectives, identifies risks, considers fraud, and identifies change. Supporting evidence: Secure Score, Defender Secure Score, Purview Compliance Manager."
        $e['ControlOwnerHint'] = 'Security / Compliance'
        $e['MappedFindingTypes'] = @()
        $catalog.Add($e) | Out-Null
    }

    # CC4 - Monitoring Activities
    $e = @{}
    $e['Id'] = 'CC4.1'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Monitoring Activities'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Ongoing and/or separate evaluations of components of internal control (audit log retention, diagnostic settings).'
    $e['ControlOwnerHint'] = 'Security / IT Ops'
    $e['MappedFindingTypes'] = @('AuditLog_NotEnabled', 'AuditLog_RetentionShort')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC4.2'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Monitoring Activities'
    $e['Automation'] = 'Supporting'
    $e['Description'] = 'Evaluates and communicates internal control deficiencies (alerting infrastructure, Defender for Cloud, Sentinel).'
    $e['ControlOwnerHint'] = 'Security'
    $e['MappedFindingTypes'] = @('SOC2_SecurityAlertingUnconfigured')
    $catalog.Add($e) | Out-Null

    # CC5 - Control Activities (manual)
    foreach ($id in @('CC5.1', 'CC5.2', 'CC5.3')) {
        $e = @{}
        $e['Id'] = $id
        $e['Family'] = 'CC'
        $e['FamilyName'] = 'Control Activities'
        $e['Automation'] = 'Manual'
        $e['Description'] = "CC5 Control Activities - $id selects and develops control activities, technology controls, and policies/procedures. Organizational."
        $e['ControlOwnerHint'] = 'Compliance / Security'
        $e['MappedFindingTypes'] = @()
        $catalog.Add($e) | Out-Null
    }

    # CC6 - Logical & Physical Access (fully automated, primary coverage)
    $e = @{}
    $e['Id'] = 'CC6.1'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Logical & Physical Access'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Implements logical access security software, infrastructure, and architectures (MFA, Conditional Access, least privilege, legacy auth blocked).'
    $e['ControlOwnerHint'] = 'Identity / Security'
    $e['MappedFindingTypes'] = @('MFA_Disabled', 'MFA_AdminDisabled', 'ConditionalAccess_Missing', 'LegacyAuth_Enabled', 'AdminRoles_Excessive', 'GlobalAdmin_Multiple', 'GuestAccess_Unrestricted', 'AppPermissions_Excessive', 'AppConsent_UserAllowed', 'SecurityDefaults_Disabled', 'PasswordExpiry_Disabled', 'SelfServicePasswordReset_Disabled')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC6.2'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Logical & Physical Access'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Prior to issuing credentials, registers and authorizes new internal and external users (user provisioning, authorization policy, guest controls).'
    $e['ControlOwnerHint'] = 'Identity'
    $e['MappedFindingTypes'] = @('MFA_Disabled', 'GuestAccess_Unrestricted', 'AuthorizationPolicy_Permissive', 'PasswordExpiry_Disabled', 'SelfServicePasswordReset_Disabled')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC6.3'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Logical & Physical Access'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Authorizes, modifies, or removes access based on roles, responsibilities, or system design (privileged access, PIM, role creep).'
    $e['ControlOwnerHint'] = 'Identity / Security'
    $e['MappedFindingTypes'] = @('MFA_AdminDisabled', 'AdminRoles_Excessive', 'GlobalAdmin_Multiple', 'PrivilegedRoleCreep', 'PIM_NotConfigured', 'AppPermissions_Excessive', 'AppConsent_UserAllowed')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC6.4'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Logical & Physical Access'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Restricts physical access to facilities and protected information assets (device compliance, encrypted devices via Intune).'
    $e['ControlOwnerHint'] = 'IT Ops / Security'
    $e['MappedFindingTypes'] = @('DeviceCompliance_NonCompliant', 'BitLocker_NotEnforced', 'StaleDevices_Present')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC6.6'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Logical & Physical Access'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Implements logical access security measures to protect against threats from outside system boundaries (named locations, cross-tenant controls).'
    $e['ControlOwnerHint'] = 'Security / Identity'
    $e['MappedFindingTypes'] = @('ConditionalAccess_Missing', 'LegacyAuth_Enabled', 'NamedLocation_Missing', 'CrossTenant_Permissive', 'GuestAccess_Unrestricted')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC6.7'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Logical & Physical Access'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Restricts the transmission, movement, and removal of information (DLP, encryption posture).'
    $e['ControlOwnerHint'] = 'Security / Compliance'
    $e['MappedFindingTypes'] = @('DLP_NotConfigured', 'SOC2_EncryptionPostureGaps')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC6.8'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Logical & Physical Access'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software (Defender posture).'
    $e['ControlOwnerHint'] = 'Security'
    $e['MappedFindingTypes'] = @('SOC2_MalwareProtectionGaps')
    $catalog.Add($e) | Out-Null

    # CC7 - System Operations
    $e = @{}
    $e['Id'] = 'CC7.1'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'System Operations'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Identifies configuration standards and monitors for anomalies (Security Defaults, CA baseline).'
    $e['ControlOwnerHint'] = 'Security'
    $e['MappedFindingTypes'] = @('ConditionalAccess_Missing', 'SecurityDefaults_Disabled')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC7.2'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'System Operations'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Monitors system components for anomalies indicative of security events (audit log, sign-in log, diagnostic settings).'
    $e['ControlOwnerHint'] = 'Security / IT Ops'
    $e['MappedFindingTypes'] = @('AuditLog_NotEnabled', 'AuditLog_RetentionShort', 'LegacyAuth_Enabled', 'MailboxAudit_Disabled')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC7.3'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'System Operations'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Evaluates security events to determine whether they represent incidents (Identity Protection policies).'
    $e['ControlOwnerHint'] = 'Security'
    $e['MappedFindingTypes'] = @('RiskySignIn_NoPolicy', 'UserRisk_NoPolicy', 'AuditLog_NotEnabled', 'MailboxAudit_Disabled')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC7.4'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'System Operations'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Responds to identified security incidents using an established incident response program (alert routing, notification emails, IR runbook availability).'
    $e['ControlOwnerHint'] = 'Security'
    $e['MappedFindingTypes'] = @('SOC2_IncidentResponseGap')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'CC7.5'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'System Operations'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Identifies, develops, and implements activities to recover from security incidents (break-glass accounts, backup admin path).'
    $e['ControlOwnerHint'] = 'Security / Identity'
    $e['MappedFindingTypes'] = @('SOC2_BreakGlassMissing', 'ConditionalAccess_Missing')
    $catalog.Add($e) | Out-Null

    # CC8 - Change Management
    $e = @{}
    $e['Id'] = 'CC8.1'
    $e['Family'] = 'CC'
    $e['FamilyName'] = 'Change Management'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Authorizes, designs, develops, configures, documents, tests, approves, and implements changes (app consent restrictions, SP credential rotation, policy drift detection).'
    $e['ControlOwnerHint'] = 'Security / IT Ops'
    $e['MappedFindingTypes'] = @('AuthorizationPolicy_Permissive', 'AppConsent_UserAllowed', 'AppRoleAssignment_Overprivileged', 'ApplicationCredential_Expired', 'AzurePolicy_Noncompliant')
    $catalog.Add($e) | Out-Null

    # CC9 - Risk Mitigation (manual with supporting signal)
    foreach ($id in @('CC9.1', 'CC9.2')) {
        $e = @{}
        $e['Id'] = $id
        $e['Family'] = 'CC'
        $e['FamilyName'] = 'Risk Mitigation'
        $e['Automation'] = 'Supporting'
        $e['Description'] = "CC9 Risk Mitigation - $id identifies, selects, and develops risk mitigation activities for risks arising from potential disruptions and vendor relationships."
        $e['ControlOwnerHint'] = 'Compliance / Vendor Mgmt'
        $e['MappedFindingTypes'] = @('GuestAccess_Unrestricted', 'CrossTenant_Permissive')
        $catalog.Add($e) | Out-Null
    }

    # A - Availability
    $e = @{}
    $e['Id'] = 'A1.1'
    $e['Family'] = 'A'
    $e['FamilyName'] = 'Availability'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Maintains current processing capacity and usage (service health, resource capacity).'
    $e['ControlOwnerHint'] = 'IT Ops'
    $e['MappedFindingTypes'] = @('SOC2_ServiceHealthGap')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'A1.2'
    $e['Family'] = 'A'
    $e['FamilyName'] = 'Availability'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Authorizes, designs, develops, implements, operates, approves, maintains, and monitors environmental protections, software, data back-up processes, and recovery infrastructure.'
    $e['ControlOwnerHint'] = 'IT Ops'
    $e['MappedFindingTypes'] = @('SOC2_BackupConfigurationGap')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'A1.3'
    $e['Family'] = 'A'
    $e['FamilyName'] = 'Availability'
    $e['Automation'] = 'Manual'
    $e['Description'] = 'Tests recovery plan procedures supporting system recovery. Requires attestation of recovery test execution.'
    $e['ControlOwnerHint'] = 'IT Ops / Compliance'
    $e['MappedFindingTypes'] = @()
    $catalog.Add($e) | Out-Null

    # C - Confidentiality
    $e = @{}
    $e['Id'] = 'C1.1'
    $e['Family'] = 'C'
    $e['FamilyName'] = 'Confidentiality'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Identifies and maintains confidential information to meet the entity''s objectives (sensitivity labels, data classification).'
    $e['ControlOwnerHint'] = 'Compliance / Security'
    $e['MappedFindingTypes'] = @('DLP_NotConfigured', 'SensitivityLabels_Missing')
    $catalog.Add($e) | Out-Null

    $e = @{}
    $e['Id'] = 'C1.2'
    $e['Family'] = 'C'
    $e['FamilyName'] = 'Confidentiality'
    $e['Automation'] = 'Automated'
    $e['Description'] = 'Disposes of confidential information to meet the entity''s objectives (retention policies, data lifecycle).'
    $e['ControlOwnerHint'] = 'Compliance'
    $e['MappedFindingTypes'] = @('RetentionPolicies_Missing')
    $catalog.Add($e) | Out-Null

    # PI - Processing Integrity (manual)
    foreach ($id in @('PI1.1', 'PI1.2', 'PI1.3', 'PI1.4', 'PI1.5')) {
        $e = @{}
        $e['Id'] = $id
        $e['Family'] = 'PI'
        $e['FamilyName'] = 'Processing Integrity'
        $e['Automation'] = 'Manual'
        $e['Description'] = "PI Processing Integrity - $id addresses input, processing, and output validation at the application layer. Outside EntraChecks scope (IAM-focused tool)."
        $e['ControlOwnerHint'] = 'Application / Product'
        $e['MappedFindingTypes'] = @()
        $catalog.Add($e) | Out-Null
    }

    # P - Privacy (manual, optional Priva signals)
    $privacyControls = @(
        'P1.1',
        'P2.1',
        'P3.1', 'P3.2',
        'P4.1', 'P4.2', 'P4.3',
        'P5.1', 'P5.2',
        'P6.1', 'P6.2', 'P6.3', 'P6.4', 'P6.5', 'P6.6', 'P6.7',
        'P7.1',
        'P8.1'
    )
    foreach ($id in $privacyControls) {
        $e = @{}
        $e['Id'] = $id
        $e['Family'] = 'P'
        $e['FamilyName'] = 'Privacy'
        $e['Automation'] = 'Manual'
        $e['Description'] = "Privacy - $id covers notice, consent, collection, use, retention, disclosure, access, and monitoring of personal information. Automatable signals require Microsoft Priva licensing and are planned for Phase 4."
        $e['ControlOwnerHint'] = 'Privacy / Compliance'
        $e['MappedFindingTypes'] = @()
        $catalog.Add($e) | Out-Null
    }

    $script:TSCCatalog = $catalog.ToArray()
    $script:TSCCatalogInitialized = $true
}

# Initialize on module import (idempotent)
Initialize-SOC2Catalog

#endregion

#region ==================== IDENTITY REDACTION ====================

<#
.SYNOPSIS
    Generates or retrieves a stable per-tenant salt used for UPN and device-name
    hashing. The salt is stable across assessment runs so hashes remain
    referentially consistent across snapshots (enabling Type 2 period coverage).
#>
function Get-SOC2TenantSalt {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$SaltDirectory
    )

    if (-not (Test-Path -LiteralPath $SaltDirectory)) {
        $null = New-Item -Path $SaltDirectory -ItemType Directory -Force
    }

    $saltFile = Join-Path $SaltDirectory "$TenantId.salt"

    if (Test-Path -LiteralPath $saltFile) {
        return (Get-Content -LiteralPath $saltFile -Raw).Trim()
    }

    $bytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    $salt = [System.Convert]::ToBase64String($bytes)
    Set-Content -LiteralPath $saltFile -Value $salt -NoNewline -Encoding ASCII

    # Best-effort ACL lockdown on Windows. On non-Windows hosts, skip quietly.
    try {
        $acl = Get-Acl -LiteralPath $saltFile
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser, 'FullControl', 'Allow'
        )
        $acl.AddAccessRule($rule)
        $adminsRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'Allow'
        )
        $acl.AddAccessRule($adminsRule)
        Set-Acl -LiteralPath $saltFile -AclObject $acl
    } catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level WARN -Message "Could not lock down salt file ACL: $($_.Exception.Message)" -Category 'SOC2'
        }
    }

    return $salt
}

function Get-SOC2IdentityHash {
    <#
    .SYNOPSIS
        Returns a salted SHA-256 hash of an identifier (UPN, device name).

    .DESCRIPTION
        Produces a stable, tenant-scoped hash that can be used in redacted reports
        while allowing referential integrity across snapshots when the same salt
        is reused.

    .PARAMETER Value
        The raw identifier to hash. Normalized to lowercase before hashing.

    .PARAMETER Salt
        The tenant-scoped salt from Get-SOC2TenantSalt.

    .OUTPUTS
        Lowercase hex SHA-256 digest.

    .EXAMPLE
        Get-SOC2IdentityHash -Value "alice@contoso.com" -Salt $salt
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory)]
        [string]$Salt
    )

    if ([string]::IsNullOrEmpty($Value)) { return '' }

    $normalized = $Value.ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Salt + $normalized)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($bytes)
    } finally {
        $sha.Dispose()
    }
    return -join ($digest | ForEach-Object { $_.ToString('x2') })
}

function Invoke-SOC2Redaction {
    <#
    .SYNOPSIS
        Applies PII redaction to a findings collection and emits an identity
        resolution map so internal remediation teams can resolve hashes back
        to UPNs.

    .DESCRIPTION
        Walks each finding, replacing UPNs/display names/device names in the
        Object and Description fields with salted SHA-256 hashes. Collects all
        observed identities into a resolution map that is written separately.

    .PARAMETER Findings
        The array of finding objects to redact (modified in place where possible,
        else returned as new objects).

    .PARAMETER TenantId
        The tenant ID (used to derive the per-tenant salt file).

    .PARAMETER SaltDirectory
        Directory containing the persisted salt file.

    .PARAMETER RedactUsers
        When set, redact user UPNs and display names.

    .PARAMETER RedactDevices
        When set, redact device names.

    .OUTPUTS
        PSCustomObject with Findings (redacted array) and IdentityMap (hashtable
        of hash -> { UPN, ObjectId, DisplayName }).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$SaltDirectory,

        [switch]$RedactUsers,

        [switch]$RedactDevices
    )

    if (-not $RedactUsers -and -not $RedactDevices) {
        return [pscustomobject]@{
            Findings = $Findings
            IdentityMap = @{}
            Salt = $null
        }
    }

    $salt = Get-SOC2TenantSalt -TenantId $TenantId -SaltDirectory $SaltDirectory
    $identityMap = @{}

    # Regexes capture UPN-like tokens; device-name redaction is scoped to known
    # structured fields (DeviceName, DisplayName). For generic free-text device
    # names we fall back to tokenization on whitespace/punctuation to minimize
    # collateral redaction of legitimate words.
    $upnPattern = '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'

    $redacted = foreach ($finding in $Findings) {
        $cloned = $finding.PSObject.Copy()

        if ($RedactUsers) {
            foreach ($field in @('Object', 'Description', 'Remediation')) {
                $val = $cloned.$field
                if ([string]::IsNullOrEmpty($val)) { continue }

                # Iterate matches manually rather than using MatchEvaluator so
                # PSScriptAnalyzer PSUseConsistentIndentation is happy and the
                # code reads linearly.
                $matches = [regex]::Matches($val, $upnPattern)
                if ($matches.Count -eq 0) { continue }

                $sb = [System.Text.StringBuilder]::new()
                $cursor = 0
                foreach ($m in $matches) {
                    [void]$sb.Append($val.Substring($cursor, $m.Index - $cursor))
                    $upn = $m.Value
                    $hash = Get-SOC2IdentityHash -Value $upn -Salt $salt
                    if (-not $identityMap.ContainsKey($hash)) {
                        $entry = @{}
                        $entry['Hash'] = $hash
                        $entry['UPN'] = $upn
                        $entry['ObjectId'] = ''
                        $entry['DisplayName'] = ''
                        $identityMap[$hash] = $entry
                    }
                    [void]$sb.Append("user:$($hash.Substring(0, 12))")
                    $cursor = $m.Index + $m.Length
                }
                [void]$sb.Append($val.Substring($cursor))
                $cloned.$field = $sb.ToString()
            }
        }

        # Structured fields: if the finding carries an explicit DeviceName / ObjectId / UPN
        # property (which happens for device / identity checks), hash those too.
        if ($RedactDevices -and $cloned.PSObject.Properties['DeviceName']) {
            $dn = $cloned.DeviceName
            if (-not [string]::IsNullOrEmpty($dn)) {
                $hash = Get-SOC2IdentityHash -Value $dn -Salt $salt
                if (-not $identityMap.ContainsKey($hash)) {
                    $entry = @{}
                    $entry['Hash'] = $hash
                    $entry['UPN'] = ''
                    $entry['ObjectId'] = ''
                    $entry['DisplayName'] = $dn
                    $identityMap[$hash] = $entry
                }
                $cloned.DeviceName = "device:$($hash.Substring(0, 12))"
            }
        }

        $cloned
    }

    return [pscustomobject]@{
        Findings = @($redacted)
        IdentityMap = $identityMap
        Salt = $salt
    }
}

function Write-SOC2IdentityResolutionMap {
    <#
    .SYNOPSIS
        Writes the identity resolution map to disk with restrictive ACLs.

    .DESCRIPTION
        Persists the hash-to-identity mapping so internal remediation teams can
        resolve redacted hashes back to real accounts. The output directory is
        locked down to the running user and BUILTIN\Administrators on Windows.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$IdentityMap,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$OutputDirectory,

        [string]$HashAlgorithm = 'SHA256',

        [string]$Salt
    )

    if ($IdentityMap.Count -eq 0) { return $null }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
    }

    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $fileName = "identity-resolution-$TenantId-$timestamp.json"
    $filePath = Join-Path $OutputDirectory $fileName

    $payload = [ordered]@{
        SchemaVersion = '1.0'
        HashAlgorithm = $HashAlgorithm
        TenantId = $TenantId
        GeneratedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        SaltReference = if ($Salt) { "Stored in $SaltDirectory\$TenantId.salt" } else { '' }
        Entries = @($IdentityMap.Values | Sort-Object Hash)
    }

    $json = $payload | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $filePath -Value $json -Encoding UTF8

    # Lock down ACLs (best effort)
    try {
        $acl = Get-Acl -LiteralPath $filePath
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser, 'FullControl', 'Allow'
        )
        $acl.AddAccessRule($rule)
        $adminsRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'Allow'
        )
        $acl.AddAccessRule($adminsRule)
        Set-Acl -LiteralPath $filePath -AclObject $acl
    } catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level WARN -Message "Could not lock down identity-resolution ACL: $($_.Exception.Message)" -Category 'SOC2'
        }
    }

    return $filePath
}

function Resolve-SOC2Identity {
    <#
    .SYNOPSIS
        Looks up a UPN / device name from a redaction hash using the most recent
        identity-resolution map for a tenant.

    .DESCRIPTION
        Operator helper for internal remediation: given a redacted hash displayed
        in a SOC 2 report, returns the underlying UPN, ObjectId, and DisplayName.

    .PARAMETER Hash
        The full SHA-256 hex hash (or the 12-char prefix shown in reports).

    .PARAMETER ResolutionMapDirectory
        Directory containing one or more identity-resolution-*.json files.

    .PARAMETER TenantId
        Optional tenant ID filter when multiple tenants' maps live in the same dir.

    .OUTPUTS
        PSCustomObject with Hash, UPN, ObjectId, DisplayName (empty strings when
        not found).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Hash,

        [Parameter(Mandatory)]
        [string]$ResolutionMapDirectory,

        [string]$TenantId
    )

    if (-not (Test-Path -LiteralPath $ResolutionMapDirectory)) {
        throw "Resolution map directory not found: $ResolutionMapDirectory"
    }

    $pattern = if ($TenantId) { "identity-resolution-$TenantId-*.json" } else { 'identity-resolution-*.json' }
    $files = Get-ChildItem -LiteralPath $ResolutionMapDirectory -Filter $pattern -File |
        Sort-Object LastWriteTime -Descending

    foreach ($file in $files) {
        $map = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        foreach ($entry in $map.Entries) {
            if ($entry.Hash -eq $Hash -or $entry.Hash.StartsWith($Hash)) {
                return [pscustomobject]@{
                    Hash = $entry.Hash
                    UPN = $entry.UPN
                    ObjectId = $entry.ObjectId
                    DisplayName = $entry.DisplayName
                    SourceFile = $file.FullName
                }
            }
        }
    }

    return [pscustomobject]@{
        Hash = $Hash
        UPN = ''
        ObjectId = ''
        DisplayName = ''
        SourceFile = $null
    }
}

#endregion

#region ==================== FINDING FACTORY ====================

function Get-SOC2Finding {
    <#
    .SYNOPSIS
        Standardized finding factory for SOC 2 synthetic checks and manual
        attestation records.

    .DESCRIPTION
        Produces a finding object that matches the EntraChecks findings schema
        (Time, CheckName, Type, Status, Object, Description, Remediation) plus
        SOC-2-specific metadata (TSCReferences, Category='SOC2',
        ControlOwnerHint).

    .PARAMETER CheckName
        The name of the synthetic check (e.g., 'Test-SOC2_AdminContacts').

    .PARAMETER Type
        The finding type key used for compliance mapping lookup.

    .PARAMETER Status
        OK | INFO | WARNING | FAIL | MANUAL.

    .PARAMETER Object
        Short identifier for the affected object.

    .PARAMETER Description
        What was found.

    .PARAMETER Remediation
        How to address the finding (or attestation guidance for MANUAL).

    .PARAMETER TSCReferences
        Array of TSC control IDs this finding applies to.

    .PARAMETER ControlOwnerHint
        Team hint for remediation routing.

    .PARAMETER Severity
        Critical | High | Medium | Low | Info. Defaults based on Status.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$CheckName,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)]
        [ValidateSet('OK', 'INFO', 'WARNING', 'FAIL', 'MANUAL')]
        [string]$Status,
        [Parameter(Mandatory)][string]$Object,
        [Parameter(Mandatory)][string]$Description,
        [string]$Remediation = 'See SOC 2 Guide for remediation guidance.',
        [string[]]$TSCReferences = @(),
        [string]$ControlOwnerHint = 'Security',
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity
    )

    if (-not $Severity) {
        $Severity = switch ($Status) {
            'FAIL' { 'High' }
            'WARNING' { 'Medium' }
            'MANUAL' { 'Info' }
            'INFO' { 'Info' }
            'OK' { 'Info' }
            default { 'Info' }
        }
    }

    return [pscustomobject]@{
        Time = (Get-Date)
        CheckName = $CheckName
        Type = $Type
        Status = $Status
        Severity = $Severity
        Category = 'SOC2'
        Object = $Object
        Description = $Description
        Remediation = $Remediation
        TSCReferences = $TSCReferences
        ControlOwnerHint = $ControlOwnerHint
        ComplianceFrameworks = @('SOC2')
    }
}

#endregion

#region ==================== AZURE HELPERS (Phase 2) ====================

<#
.SYNOPSIS
    Thin Azure REST wrapper used by Phase 2 SOC 2 checks.

.DESCRIPTION
    Wraps Invoke-AzRestMethod to inject an api-version query parameter and
    normalize error handling. Returns the parsed JSON body on HTTP 200,
    $null on 403/404, and logs a warning for other non-success codes.

    Kept as a local helper rather than reusing the one in
    EntraChecks-DefenderCompliance.psm1 because that function is not exported.

.PARAMETER Uri
    Full https://management.azure.com/... URI. api-version will be appended
    automatically if not already present.

.PARAMETER ApiVersion
    Default '2022-01-01'. Override per-call for APIs that require specific
    versions (e.g. microsoft.aadiam preview).

.OUTPUTS
    Deserialized JSON response body, or $null.
#>
function Invoke-SOC2AzureRestRequest {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$ApiVersion = '2022-01-01'
    )

    try {
        if ($Uri -notmatch 'api-version=') {
            $separator = if ($Uri -match '\?') { '&' } else { '?' }
            $Uri = "$Uri${separator}api-version=$ApiVersion"
        }

        $response = Invoke-AzRestMethod -Uri $Uri -Method GET -ErrorAction Stop

        if ($response.StatusCode -eq 200) {
            if ($response.Content) {
                return $response.Content | ConvertFrom-Json
            }
            return $null
        }

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level DEBUG -Message "Azure REST returned $($response.StatusCode) for $Uri" -Category 'SOC2-Phase2'
        }
        return $null
    } catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level WARN -Message "Azure REST failed for ${Uri}: $($_.Exception.Message)" -Category 'SOC2-Phase2'
        }
        return $null
    }
}

<#
.SYNOPSIS
    Resolves the in-scope Azure subscriptions for Phase 2 checks.

.DESCRIPTION
    Wraps Get-AzSubscription with an optional filter. Returns only Enabled
    subscriptions. Matches user-supplied filter values against either the
    subscription ID or Name (case-insensitive). Returns empty array on error.

.PARAMETER Filter
    Optional array of subscription IDs or names. Empty/null means all
    accessible subscriptions.

.OUTPUTS
    Array of subscription objects (with Id, Name, TenantId properties).
#>
function Get-SOC2TargetSubscriptions {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [string[]]$Filter = @()
    )

    try {
        $subs = Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' }

        if ($Filter -and $Filter.Count -gt 0) {
            $filterSet = @($Filter | ForEach-Object { $_.ToLowerInvariant() })
            $subs = $subs | Where-Object {
                ($_.Id.ToLowerInvariant() -in $filterSet) -or ($_.Name.ToLowerInvariant() -in $filterSet)
            }
        }

        return @($subs)
    } catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level WARN -Message "Could not enumerate subscriptions: $($_.Exception.Message)" -Category 'SOC2-Phase2'
        }
        return @()
    }
}

#endregion

#region ==================== LICENSING CAPABILITIES (Phase 2) ====================

# Cache across assessment runs (per user decision #5 — module-lifetime cache
# with -Refresh escape hatch)
$script:SOC2LicensingCache = $null

<#
.SYNOPSIS
    Probes tenant licensing capabilities that gate Phase 2 checks.

.DESCRIPTION
    Runs cheap read-only probes against Graph and Azure REST to determine
    which licensed features are available. Each probe is wrapped in try/catch
    so one failure does not poison the rest.

    Results are cached for the lifetime of the module import; pass -Refresh
    to force a new probe run.

    Returned keys (all boolean): HasP2, HasIntune, HasPurviewE5,
    HasDefenderForCloud, HasDefenderForEndpoint, HasPriva, HasAzContext.

.PARAMETER Refresh
    Ignore any cached result and probe fresh.

.OUTPUTS
    Hashtable of capability flags.
#>
function Get-SOC2LicensingCapabilities {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [switch]$Refresh
    )

    if (-not $Refresh -and $null -ne $script:SOC2LicensingCache) {
        return $script:SOC2LicensingCache
    }

    $caps = @{}
    $caps['HasP2'] = $false
    $caps['HasIntune'] = $false
    $caps['HasPurviewE5'] = $false
    $caps['HasDefenderForCloud'] = $false
    $caps['HasDefenderForEndpoint'] = $false
    $caps['HasPriva'] = $false
    $caps['HasAzContext'] = $false

    # P2 probe: role eligibility endpoint only exists with P2 / PIM
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$top=1' -ErrorAction Stop
        if ($null -ne $resp) { $caps['HasP2'] = $true }
    } catch { $caps['HasP2'] = $false }

    # Intune probe: deviceManagement endpoint requires Intune license
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1' -ErrorAction Stop
        if ($null -ne $resp) { $caps['HasIntune'] = $true }
    } catch { $caps['HasIntune'] = $false }

    # Purview E5 probe: informationProtection requires E5 Compliance
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels?$top=1' -ErrorAction Stop
        if ($null -ne $resp) { $caps['HasPurviewE5'] = $true }
    } catch { $caps['HasPurviewE5'] = $false }

    # Priva probe: subjectRightsRequests endpoint requires Priva
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/privacy/subjectRightsRequests?$top=1' -ErrorAction Stop
        if ($null -ne $resp) { $caps['HasPriva'] = $true }
    } catch { $caps['HasPriva'] = $false }

    # Az context + Defender probes (only if Az.Accounts module is loaded + context present)
    try {
        if (Get-Command Get-AzContext -ErrorAction SilentlyContinue) {
            $ctx = Get-AzContext -ErrorAction SilentlyContinue
            if ($ctx) {
                $caps['HasAzContext'] = $true

                # Defender for Cloud: any subscription with Security pricings tier > Free
                $subs = Get-SOC2TargetSubscriptions
                foreach ($sub in $subs) {
                    $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue
                    $uri = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.Security/pricings"
                    $pricings = Invoke-SOC2AzureRestRequest -Uri $uri -ApiVersion '2023-01-01'
                    if ($pricings -and $pricings.value) {
                        $paidPlans = @($pricings.value | Where-Object { $_.properties.pricingTier -and $_.properties.pricingTier -ne 'Free' })
                        if ($paidPlans.Count -gt 0) {
                            $caps['HasDefenderForCloud'] = $true

                            # Defender for Endpoint (WDATP): check settings endpoint
                            $wdatpUri = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.Security/settings/WDATP"
                            $wdatp = Invoke-SOC2AzureRestRequest -Uri $wdatpUri -ApiVersion '2022-05-01'
                            if ($wdatp -and $wdatp.properties -and $wdatp.properties.enabled) {
                                $caps['HasDefenderForEndpoint'] = $true
                            }
                            break
                        }
                    }
                }
            }
        }
    } catch {
        # Capability probes are best-effort; swallow exceptions so one failing
        # probe doesn't poison the rest. Surface via debug stream.
        Write-Debug "Licensing capability probe failed: $($_.Exception.Message)"
    }

    $script:SOC2LicensingCache = $caps
    return $caps
}

<#
.SYNOPSIS
    Emits SOC2_LicensingGap_* INFO findings for each missing capability.

.DESCRIPTION
    Walks the capability hashtable; for each capability that is $false, emits
    a finding that surfaces the affected TSC controls as "not assessed due
    to licensing." The default Status/Severity is INFO/Low, overridable via
    the Overrides hashtable (config key SOC2.Phase2.Licensing.Overrides).

.PARAMETER Capabilities
    Output of Get-SOC2LicensingCapabilities.

.PARAMETER Overrides
    Hashtable keyed by feature name (IdentityProtection, Intune, etc.) with
    value 'INFO' | 'WARNING' | 'FAIL'. Missing keys use default INFO.

.OUTPUTS
    Array of finding objects (may be empty).
#>
function New-SOC2LicensingGapFindings {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Capabilities,

        [hashtable]$Overrides = @{}
    )

    $gaps = [System.Collections.Generic.List[object]]::new()

    # Map: capability flag -> (feature name, Type, default TSCReferences, control owner)
    $gapMap = [System.Collections.Generic.List[hashtable]]::new()

    $e = @{}
    $e['Flag'] = 'HasP2'
    $e['Feature'] = 'IdentityProtection'
    $e['Type'] = 'SOC2_LicensingGap_IdentityProtection'
    $e['TSC'] = @('CC7.3')
    $e['Owner'] = 'Identity / Security'
    $e['Reason'] = 'Azure AD Premium P2 required to assess risk-based user/sign-in policies'
    $gapMap.Add($e) | Out-Null

    $e = @{}
    $e['Flag'] = 'HasIntune'
    $e['Feature'] = 'Intune'
    $e['Type'] = 'SOC2_LicensingGap_Intune'
    $e['TSC'] = @('CC6.4')
    $e['Owner'] = 'IT Ops'
    $e['Reason'] = 'Intune / EMS E3+ required to assess device compliance and management'
    $gapMap.Add($e) | Out-Null

    $e = @{}
    $e['Flag'] = 'HasPurviewE5'
    $e['Feature'] = 'PurviewE5'
    $e['Type'] = 'SOC2_LicensingGap_PurviewE5'
    $e['TSC'] = @('CC6.7', 'C1.1', 'C1.2')
    $e['Owner'] = 'Compliance'
    $e['Reason'] = 'Microsoft Purview (E5 / Compliance add-on) required for DLP, sensitivity labels, retention policies'
    $gapMap.Add($e) | Out-Null

    $e = @{}
    $e['Flag'] = 'HasDefenderForCloud'
    $e['Feature'] = 'DefenderForCloud'
    $e['Type'] = 'SOC2_LicensingGap_DefenderForCloud'
    $e['TSC'] = @('CC4.2', 'CC6.7', 'CC6.8')
    $e['Owner'] = 'Security'
    $e['Reason'] = 'Defender for Cloud paid plan required to assess regulatory compliance and security alerting'
    $gapMap.Add($e) | Out-Null

    $e = @{}
    $e['Flag'] = 'HasDefenderForEndpoint'
    $e['Feature'] = 'DefenderForEndpoint'
    $e['Type'] = 'SOC2_LicensingGap_DefenderForEndpoint'
    $e['TSC'] = @('CC6.8')
    $e['Owner'] = 'Security'
    $e['Reason'] = 'Defender for Endpoint connector required to assess EDR / anti-malware posture'
    $gapMap.Add($e) | Out-Null

    $e = @{}
    $e['Flag'] = 'HasPriva'
    $e['Feature'] = 'Priva'
    $e['Type'] = 'SOC2_LicensingGap_Priva'
    $e['TSC'] = @('P1.1', 'P2.1', 'P3.1')
    $e['Owner'] = 'Privacy / Compliance'
    $e['Reason'] = 'Microsoft Priva license required to assess privacy program signals'
    $gapMap.Add($e) | Out-Null

    foreach ($gap in $gapMap) {
        if ($Capabilities[$gap.Flag]) { continue }

        # Apply override if present
        $severity = 'Low'
        $status = 'INFO'
        if ($Overrides.ContainsKey($gap.Feature)) {
            $override = $Overrides[$gap.Feature]
            if ($override -in @('WARNING', 'FAIL')) {
                $status = $override
                $severity = if ($override -eq 'FAIL') { 'High' } else { 'Medium' }
            }
        }

        $params = @{
            CheckName = 'Get-SOC2LicensingCapabilities'
            Type = $gap.Type
            Status = $status
            Severity = $severity
            Object = "Licensing: $($gap.Feature)"
            Description = $gap.Reason + '. Affected TSCs are not assessed.'
            Remediation = "If this feature is in scope for your SOC 2 readiness, procure the required licensing. Otherwise, document exclusion scope and leave this finding as INFO to acknowledge the gap."
            TSCReferences = $gap.TSC
            ControlOwnerHint = $gap.Owner
        }
        $gaps.Add((Get-SOC2Finding @params)) | Out-Null
    }

    return $gaps.ToArray()
}

#endregion

#region ==================== SYNTHETIC CHECKS ====================

<#
.SYNOPSIS
    Probes /organization for security/technical notification email addresses
    required under CC2.1 and CC2.3 (board/mgmt informed of security matters,
    external communication channels for incidents).
#>
function Test-SOC2AdminContacts {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $findings = [System.Collections.Generic.List[pscustomobject]]::new()

    try {
        $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization'
        $tenant = $org.value[0]

        $technical = @($tenant.technicalNotificationMails)
        $security = @($tenant.securityComplianceNotificationMails)

        if ($technical.Count -eq 0) {
            $params = @{
                CheckName = 'Test-SOC2_AdminContacts'
                Type = 'SOC2_AdminContactsMissing'
                Status = 'FAIL'
                Severity = 'Medium'
                Object = 'Tenant technical notification contacts'
                Description = 'No technical notification email addresses are configured on /organization. Microsoft cannot reach technical contacts for urgent tenant notifications.'
                Remediation = 'In the Microsoft 365 admin center, set at least one technical notification email. Verify monthly and rotate as staff changes.'
                TSCReferences = @('CC2.1', 'CC2.3')
                ControlOwnerHint = 'IT Ops'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
        } else {
            $params = @{
                CheckName = 'Test-SOC2_AdminContacts'
                Type = 'SOC2_AdminContactsConfigured'
                Status = 'OK'
                Object = 'Tenant technical notification contacts'
                Description = "Technical notification emails configured: $($technical.Count) address(es)."
                Remediation = 'No action needed. Review quarterly as part of control evidence refresh.'
                TSCReferences = @('CC2.1', 'CC2.3')
                ControlOwnerHint = 'IT Ops'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
        }

        if ($security.Count -eq 0) {
            $params = @{
                CheckName = 'Test-SOC2_AdminContacts'
                Type = 'SOC2_SecurityContactsMissing'
                Status = 'FAIL'
                Severity = 'High'
                Object = 'Tenant security/compliance notification contacts'
                Description = 'No security/compliance notification email addresses are configured on /organization. Microsoft cannot reach security contacts for incident notifications.'
                Remediation = 'In the Microsoft 365 admin center, set at least one security/compliance notification email (Settings > Org settings > Security & privacy).'
                TSCReferences = @('CC2.1', 'CC2.3', 'CC7.4')
                ControlOwnerHint = 'Security'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
        } else {
            $params = @{
                CheckName = 'Test-SOC2_AdminContacts'
                Type = 'SOC2_SecurityContactsConfigured'
                Status = 'OK'
                Object = 'Tenant security/compliance notification contacts'
                Description = "Security/compliance notification emails configured: $($security.Count) address(es)."
                Remediation = 'No action needed. Review quarterly as part of control evidence refresh.'
                TSCReferences = @('CC2.1', 'CC2.3', 'CC7.4')
                ControlOwnerHint = 'Security'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
        }
    } catch {
        $params = @{
            CheckName = 'Test-SOC2_AdminContacts'
            Type = 'SOC2_AdminContactsMissing'
            Status = 'WARNING'
            Severity = 'Low'
            Object = 'Tenant notification contacts'
            Description = "Unable to read tenant notification contacts: $($_.Exception.Message)"
            Remediation = 'Verify the running identity has Organization.Read.All or Directory.Read.All Graph scope.'
            TSCReferences = @('CC2.1', 'CC2.3')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
    }

    return $findings.ToArray()
}

<#
.SYNOPSIS
    Probes for the presence of security alerting infrastructure (Defender for
    Cloud connector enabled, Sentinel workspaces reachable, security portal
    reachable). Supports CC4.2 and CC7.4.
#>
function Test-SOC2SecurityAlertingConfigured {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $findings = [System.Collections.Generic.List[pscustomobject]]::new()

    # Defender for Cloud presence is tracked in a separate module. Here we do a
    # lightweight probe: can we list subscriptions and does any expose a Security
    # pricing tier above Free? A richer check lives in EntraChecks-DefenderCompliance.
    $defenderSignal = $false
    try {
        if (Get-Command Get-AzContext -ErrorAction SilentlyContinue) {
            $ctx = Get-AzContext -ErrorAction SilentlyContinue
            if ($ctx) {
                $defenderSignal = $true
            }
        }
    } catch {
        $defenderSignal = $false
    }

    if ($defenderSignal) {
        $params = @{
            CheckName = 'Test-SOC2_SecurityAlertingConfigured'
            Type = 'SOC2_SecurityAlertingPresent'
            Status = 'INFO'
            Object = 'Security alerting infrastructure'
            Description = 'Azure context present. Detailed Defender-for-Cloud posture is assessed by EntraChecks-DefenderCompliance; see those findings for CC4.2 evidence.'
            Remediation = 'Cross-reference Defender for Cloud posture findings; confirm at least one subscription has Defender plans enabled and action groups route to security contacts.'
            TSCReferences = @('CC4.2', 'CC7.4')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
    } else {
        $params = @{
            CheckName = 'Test-SOC2_SecurityAlertingConfigured'
            Type = 'SOC2_SecurityAlertingUnconfigured'
            Status = 'WARNING'
            Severity = 'Medium'
            Object = 'Security alerting infrastructure'
            Description = 'No Azure context is available to assess Defender for Cloud alerting. Without Azure Reader + Security Reader roles, alerting posture cannot be verified.'
            Remediation = 'Connect to Azure (Connect-AzAccount) with a Security Reader role and re-run to collect Defender/Sentinel alerting evidence.'
            TSCReferences = @('CC4.2', 'CC7.4')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
    }

    return $findings.ToArray()
}

<#
.SYNOPSIS
    Probes tenant-level incident response readiness signals (security
    notification emails, privileged identity monitoring, audit log retention).
    Supports CC7.4.
#>
function Test-SOC2IncidentResponseReadiness {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $findings = [System.Collections.Generic.List[pscustomobject]]::new()

    $readinessSignals = @()
    $missingSignals = @()

    # Signal 1: security contact emails configured
    try {
        $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization'
        $tenant = $org.value[0]
        if (@($tenant.securityComplianceNotificationMails).Count -gt 0) {
            $readinessSignals += 'security notification emails configured'
        } else {
            $missingSignals += 'security notification emails'
        }
    } catch {
        $missingSignals += 'security notification emails (could not read)'
    }

    # Signal 2: PIM detected (best-effort; Graph returns 404 if not in use)
    try {
        $pim = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$top=1' -ErrorAction SilentlyContinue
        if ($pim -and $pim.value) {
            $readinessSignals += 'PIM eligible assignments present'
        } else {
            $missingSignals += 'PIM (no eligible assignments found)'
        }
    } catch {
        $missingSignals += 'PIM (unavailable or not queryable)'
    }

    $status = if ($missingSignals.Count -eq 0) {
        'OK'
    } elseif ($readinessSignals.Count -eq 0) {
        'FAIL'
    } else {
        'WARNING'
    }

    $descriptionLines = @(
        "Readiness signals present: $(($readinessSignals -join '; '))",
        "Readiness signals missing: $(($missingSignals -join '; '))"
    )

    $severity = if ($status -eq 'FAIL') { 'High' } elseif ($status -eq 'WARNING') { 'Medium' } else { 'Info' }
    $params = @{
        CheckName = 'Test-SOC2_IncidentResponseReadiness'
        Type = 'SOC2_IncidentResponseGap'
        Status = $status
        Severity = $severity
        Object = 'Incident response readiness'
        Description = ($descriptionLines -join "`n")
        Remediation = 'Ensure (1) security notification emails are set on /organization, (2) PIM is configured for privileged roles, (3) audit log retention meets the period of coverage, and (4) an incident response runbook references these controls.'
        TSCReferences = @('CC7.4')
        ControlOwnerHint = 'Security'
    }
    $findings.Add((Get-SOC2Finding @params)) | Out-Null

    return $findings.ToArray()
}

# ---------- Phase 2 synthetic checks ----------

<#
.SYNOPSIS
    Evaluates Azure Recovery Services backup posture for A1.2 (availability
    commitment: environmental protections, backup processes, recovery
    infrastructure).

.DESCRIPTION
    Enumerates Recovery Services vaults across in-scope subscriptions and
    validates: presence of vaults, presence of protected items, minimum
    redundancy tier. Graceful degradation when Az.RecoveryServices module,
    Az context, or Backup Reader role is missing.

.PARAMETER Subscriptions
    Optional subscription filter (ID or name) passed to Get-SOC2TargetSubscriptions.

.PARAMETER MinRedundancyTier
    Minimum acceptable redundancy tier. One of LRS, ZRS, GRS, RA-GRS.
    Default GRS — below this produces a WARNING.

.OUTPUTS
    Array of finding objects.
#>
function Test-SOC2BackupConfiguration {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [string[]]$Subscriptions = @(),

        [ValidateSet('LRS', 'ZRS', 'GRS', 'RA-GRS')]
        [string]$MinRedundancyTier = 'GRS'
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    # Prerequisite: Az.RecoveryServices module
    if (-not (Get-Module -ListAvailable -Name Az.RecoveryServices)) {
        $params = @{
            CheckName = 'Test-SOC2BackupConfiguration'
            Type = 'SOC2_Phase2_PrereqMissing'
            Status = 'INFO'
            Severity = 'Low'
            Object = 'Module: Az.RecoveryServices'
            Description = 'Az.RecoveryServices PowerShell module is not installed; backup posture cannot be evaluated.'
            Remediation = 'Run Install-Prerequisites.ps1 (adds Az.RecoveryServices) or install manually: Install-Module Az.RecoveryServices -MinimumVersion 6.0.0 -Scope CurrentUser.'
            TSCReferences = @('A1.2')
            ControlOwnerHint = 'IT Ops'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    $targetSubs = Get-SOC2TargetSubscriptions -Filter $Subscriptions
    if ($targetSubs.Count -eq 0) {
        $params = @{
            CheckName = 'Test-SOC2BackupConfiguration'
            Type = 'SOC2_Phase2_AzContextMissing'
            Status = 'INFO'
            Severity = 'Low'
            Object = 'Azure subscriptions'
            Description = 'No accessible subscriptions. Backup posture cannot be assessed.'
            Remediation = 'Run Connect-AzAccount with a principal that has Reader on at least one subscription in scope.'
            TSCReferences = @('A1.2')
            ControlOwnerHint = 'IT Ops'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    # Redundancy tier ranking for comparison
    $tierRank = @{}
    $tierRank['LRS'] = 1
    $tierRank['ZRS'] = 2
    $tierRank['GRS'] = 3
    $tierRank['RA-GRS'] = 4
    $minRank = $tierRank[$MinRedundancyTier]

    $allVaults = [System.Collections.Generic.List[object]]::new()
    $vaultsWithItems = 0
    $vaultsMeetingRedundancy = 0

    foreach ($sub in $targetSubs) {
        $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue

        $vaultsUri = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.RecoveryServices/vaults"
        $vaultsResp = Invoke-SOC2AzureRestRequest -Uri $vaultsUri -ApiVersion '2023-04-01'

        if ($null -eq $vaultsResp -or $null -eq $vaultsResp.value) { continue }

        foreach ($vault in $vaultsResp.value) {
            $allVaults.Add($vault) | Out-Null

            # Redundancy tier check (property path varies by vault version; defensive)
            $tier = $null
            if ($vault.properties -and $vault.properties.redundancySettings -and $vault.properties.redundancySettings.standardTierStorageRedundancy) {
                $tier = $vault.properties.redundancySettings.standardTierStorageRedundancy
            }
            if ($tier -and $tierRank.ContainsKey($tier) -and $tierRank[$tier] -ge $minRank) {
                $vaultsMeetingRedundancy++
            }

            # Protected items presence
            $itemsUri = "$($vault.id)/backupProtectedItems"
            $itemsResp = Invoke-SOC2AzureRestRequest -Uri $itemsUri -ApiVersion '2023-04-01'
            if ($itemsResp -and $itemsResp.value -and @($itemsResp.value).Count -gt 0) {
                $vaultsWithItems++
            }
        }
    }

    if ($allVaults.Count -eq 0) {
        $params = @{
            CheckName = 'Test-SOC2BackupConfiguration'
            Type = 'SOC2_BackupConfigurationGap'
            Status = 'FAIL'
            Severity = 'High'
            Object = 'Recovery Services vaults'
            Description = 'No Recovery Services vaults found in in-scope subscriptions. Availability commitment A1.2 (backup / environmental protection) unmet.'
            Remediation = 'Create at least one Recovery Services vault, configure backup policies for in-scope workloads, and attach protected items. Prefer geo-redundant (GRS/RA-GRS) storage.'
            TSCReferences = @('A1.2')
            ControlOwnerHint = 'IT Ops'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    if ($vaultsWithItems -eq 0) {
        $params = @{
            CheckName = 'Test-SOC2BackupConfiguration'
            Type = 'SOC2_BackupConfigurationGap'
            Status = 'FAIL'
            Severity = 'High'
            Object = "Recovery Services vaults ($($allVaults.Count))"
            Description = "Found $($allVaults.Count) Recovery Services vault(s) but none have protected items. Backup coverage for availability commitment A1.2 is nil."
            Remediation = 'Configure backup policies on the existing vault(s) and attach in-scope resources (VMs, SQL, file shares, etc.) as protected items.'
            TSCReferences = @('A1.2')
            ControlOwnerHint = 'IT Ops'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    if ($vaultsMeetingRedundancy -eq 0) {
        $params = @{
            CheckName = 'Test-SOC2BackupConfiguration'
            Type = 'SOC2_BackupConfigurationGap'
            Status = 'WARNING'
            Severity = 'Medium'
            Object = "Recovery Services vaults ($($allVaults.Count))"
            Description = "Vaults exist with protected items, but none meet minimum redundancy tier '$MinRedundancyTier'. Single-region failure would cause backup data loss."
            Remediation = "Re-create or reconfigure at least one vault with $MinRedundancyTier or higher redundancy. Note: redundancy tier cannot be changed after vault creation with items protected; may require data migration."
            TSCReferences = @('A1.2')
            ControlOwnerHint = 'IT Ops'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    # Healthy PASS
    $params = @{
        CheckName = 'Test-SOC2BackupConfiguration'
        Type = 'SOC2_BackupConfigurationHealthy'
        Status = 'OK'
        Severity = 'Info'
        Object = "Recovery Services vaults ($($allVaults.Count))"
        Description = "$($allVaults.Count) vault(s) configured; $vaultsWithItems with protected items; $vaultsMeetingRedundancy meeting minimum redundancy '$MinRedundancyTier'. Availability commitment A1.2 evidence present."
        Remediation = 'No action required. Re-verify quarterly as part of control-operation evidence.'
        TSCReferences = @('A1.2')
        ControlOwnerHint = 'IT Ops'
    }
    $findings.Add((Get-SOC2Finding @params)) | Out-Null

    return $findings.ToArray()
}

<#
.SYNOPSIS
    Assesses Azure Resource Health availability baseline for A1.1 (availability
    commitment: maintain current processing capacity and usage).

.DESCRIPTION
    Queries Azure Resource Health across in-scope subscriptions and computes
    the percentage of resources reporting "Available". Below the threshold
    emits a WARNING; missing Resource Health telemetry emits INFO.

.PARAMETER Subscriptions
    Optional subscription filter.

.PARAMETER AvailabilityThresholdPercent
    Minimum acceptable percent of resources reporting Available. Default 98.

.OUTPUTS
    Array of finding objects.
#>
function Test-SOC2ServiceHealthBaseline {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [string[]]$Subscriptions = @(),

        [int]$AvailabilityThresholdPercent = 98
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    $targetSubs = Get-SOC2TargetSubscriptions -Filter $Subscriptions
    if ($targetSubs.Count -eq 0) {
        $params = @{
            CheckName = 'Test-SOC2ServiceHealthBaseline'
            Type = 'SOC2_Phase2_AzContextMissing'
            Status = 'INFO'
            Severity = 'Low'
            Object = 'Azure subscriptions'
            Description = 'No accessible subscriptions. Resource health baseline cannot be assessed.'
            Remediation = 'Run Connect-AzAccount with Reader on at least one subscription in scope.'
            TSCReferences = @('A1.1')
            ControlOwnerHint = 'IT Ops'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    $totalCount = 0
    $availableCount = 0
    $unavailableCount = 0
    $degradedCount = 0

    foreach ($sub in $targetSubs) {
        $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue
        $uri = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.ResourceHealth/availabilityStatuses"
        $resp = Invoke-SOC2AzureRestRequest -Uri $uri -ApiVersion '2022-10-01'

        if ($null -eq $resp -or $null -eq $resp.value) { continue }

        foreach ($status in $resp.value) {
            if (-not $status.properties) { continue }
            $totalCount++
            switch ($status.properties.availabilityState) {
                'Available' { $availableCount++ }
                'Unavailable' { $unavailableCount++ }
                'Degraded' { $degradedCount++ }
            }
        }
    }

    if ($totalCount -eq 0) {
        $params = @{
            CheckName = 'Test-SOC2ServiceHealthBaseline'
            Type = 'SOC2_ServiceHealthGap'
            Status = 'INFO'
            Severity = 'Low'
            Object = 'Resource Health telemetry'
            Description = 'No resources returned health status. A1.1 cannot be assessed from telemetry alone.'
            Remediation = 'Confirm Reader role on in-scope subscriptions and that at least one resource is reporting to Resource Health.'
            TSCReferences = @('A1.1')
            ControlOwnerHint = 'IT Ops'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    $percentAvailable = [math]::Round(($availableCount / $totalCount) * 100, 2)

    if ($percentAvailable -lt $AvailabilityThresholdPercent) {
        $params = @{
            CheckName = 'Test-SOC2ServiceHealthBaseline'
            Type = 'SOC2_ServiceHealthGap'
            Status = 'WARNING'
            Severity = 'Medium'
            Object = "Resource Health ($totalCount resources)"
            Description = "Resource health $percentAvailable% Available (threshold $AvailabilityThresholdPercent%); $unavailableCount Unavailable, $degradedCount Degraded. Investigate whether SOC 2 in-scope services are affected."
            Remediation = 'Triage unavailable/degraded resources in the Azure portal Resource Health blade. If in SOC 2 scope, ensure incident response procedures capture the outage.'
            TSCReferences = @('A1.1')
            ControlOwnerHint = 'IT Ops'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    $params = @{
        CheckName = 'Test-SOC2ServiceHealthBaseline'
        Type = 'SOC2_ServiceHealthHealthy'
        Status = 'OK'
        Severity = 'Info'
        Object = "Resource Health ($totalCount resources)"
        Description = "Resource health $percentAvailable% Available (threshold $AvailabilityThresholdPercent%); baseline healthy."
        Remediation = 'No action required. Re-verify periodically as part of availability monitoring.'
        TSCReferences = @('A1.1')
        ControlOwnerHint = 'IT Ops'
    }
    $findings.Add((Get-SOC2Finding @params)) | Out-Null

    return $findings.ToArray()
}

<#
.SYNOPSIS
    Evaluates Entra tenant-level diagnostic settings export for CC4.1 and CC7.2
    (monitoring controls, system monitoring via log retention and forwarding).

.DESCRIPTION
    Reads Entra ID tenant-level diagnostic settings via the preview API
    `microsoft.aadiam` and verifies required log categories (AuditLogs,
    SignInLogs at minimum) are exported to a reachable Log Analytics workspace.
    Optionally enforces a specific required workspace when configured.

.PARAMETER RequiredCategories
    Log categories that must appear in at least one setting. Default
    AuditLogs + SignInLogs.

.PARAMETER RequiredWorkspaceId
    Optional full Log Analytics workspace resource ID. When set, an enabled
    setting must target this specific workspace to PASS.

.OUTPUTS
    Array of finding objects.
#>
function Test-SOC2DiagnosticSettingsExport {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [string[]]$RequiredCategories = @('AuditLogs', 'SignInLogs'),

        [string]$RequiredWorkspaceId = ''
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    if (-not (Get-Command Get-AzContext -ErrorAction SilentlyContinue) -or -not (Get-AzContext -ErrorAction SilentlyContinue)) {
        $params = @{
            CheckName = 'Test-SOC2DiagnosticSettingsExport'
            Type = 'SOC2_Phase2_AzContextMissing'
            Status = 'INFO'
            Severity = 'Low'
            Object = 'Azure context'
            Description = 'Azure context required to query Entra tenant diagnostic settings (microsoft.aadiam). Check cannot run.'
            Remediation = 'Run Connect-AzAccount with a principal granted Monitoring Reader at the tenant root scope.'
            TSCReferences = @('CC4.1', 'CC7.2')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    # Entra tenant-level diag settings live under a tenant-scoped resource provider,
    # not under a subscription. Requires Monitoring Reader at /providers/microsoft.aadiam.
    $uri = 'https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings'
    $resp = Invoke-SOC2AzureRestRequest -Uri $uri -ApiVersion '2017-04-01-preview'

    if ($null -eq $resp) {
        # Could be 403 (missing role) or API hiccup — surface as WARNING so auditors see
        # "we could not confirm", not a false PASS.
        $params = @{
            CheckName = 'Test-SOC2DiagnosticSettingsExport'
            Type = 'SOC2_DiagnosticSettingsGap'
            Status = 'WARNING'
            Severity = 'Medium'
            Object = 'Entra tenant diagnostic settings'
            Description = 'Could not read tenant diagnostic settings (microsoft.aadiam). Likely cause: Monitoring Reader role missing at tenant scope.'
            Remediation = 'Grant Monitoring Reader at the tenant root (/providers/microsoft.aadiam) to the assessment identity and re-run. See docs/SOC2-Guide.md Phase 2 permissions.'
            TSCReferences = @('CC4.1', 'CC7.2')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    $settings = @()
    if ($resp.value) { $settings = @($resp.value) }

    if ($settings.Count -eq 0) {
        $params = @{
            CheckName = 'Test-SOC2DiagnosticSettingsExport'
            Type = 'SOC2_DiagnosticSettingsGap'
            Status = 'FAIL'
            Severity = 'High'
            Object = 'Entra tenant diagnostic settings'
            Description = 'No diagnostic settings configured for the Entra tenant. Audit and sign-in logs are not being exported, so monitoring coverage under CC4.1/CC7.2 cannot be demonstrated.'
            Remediation = 'In Entra ID -> Monitoring -> Diagnostic settings, add a setting that exports at minimum AuditLogs and SignInLogs to a Log Analytics workspace or storage account.'
            TSCReferences = @('CC4.1', 'CC7.2')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    # Aggregate exported categories across all enabled settings
    $exportedCategories = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $workspaceTargets = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($setting in $settings) {
        if (-not $setting.properties) { continue }
        if ($setting.properties.workspaceId) { $null = $workspaceTargets.Add($setting.properties.workspaceId) }
        if ($setting.properties.logs) {
            foreach ($log in $setting.properties.logs) {
                if ($log.enabled -and $log.category) { $null = $exportedCategories.Add($log.category) }
            }
        }
    }

    $missingCategories = @($RequiredCategories | Where-Object { -not $exportedCategories.Contains($_) })

    if ($missingCategories.Count -gt 0) {
        $params = @{
            CheckName = 'Test-SOC2DiagnosticSettingsExport'
            Type = 'SOC2_DiagnosticSettingsGap'
            Status = 'FAIL'
            Severity = 'High'
            Object = 'Entra diagnostic settings - missing categories'
            Description = "Tenant diagnostic settings exist but required log categories are not exported: $(($missingCategories) -join ', '). Monitoring coverage for CC4.1/CC7.2 is incomplete."
            Remediation = "Enable the following log categories in an existing diagnostic setting: $(($missingCategories) -join ', ')."
            TSCReferences = @('CC4.1', 'CC7.2')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    if ($RequiredWorkspaceId) {
        $matchFound = $workspaceTargets | Where-Object { $_ -eq $RequiredWorkspaceId }
        if (-not $matchFound) {
            $params = @{
                CheckName = 'Test-SOC2DiagnosticSettingsExport'
                Type = 'SOC2_DiagnosticSettingsGap'
                Status = 'FAIL'
                Severity = 'High'
                Object = 'Entra diagnostic settings - wrong workspace'
                Description = "Required SOC 2 evidence workspace is not configured as a diagnostic setting target. Found $($workspaceTargets.Count) distinct target(s); required: $RequiredWorkspaceId"
                Remediation = 'Update at least one diagnostic setting to target the required workspace, or update SOC2.Phase2.DiagnosticSettings.RequiredWorkspaceId if the evidence workspace has moved.'
                TSCReferences = @('CC4.1', 'CC7.2')
                ControlOwnerHint = 'Security'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
            return $findings.ToArray()
        }
    }

    $params = @{
        CheckName = 'Test-SOC2DiagnosticSettingsExport'
        Type = 'SOC2_DiagnosticSettingsHealthy'
        Status = 'OK'
        Severity = 'Info'
        Object = "Entra diagnostic settings ($($settings.Count))"
        Description = "$($settings.Count) diagnostic setting(s) configured; all required categories ($(($RequiredCategories) -join ', ')) exported. Monitoring coverage for CC4.1/CC7.2 evidenced."
        Remediation = 'No action required. Spot-check workspace reachability and retention quarterly.'
        TSCReferences = @('CC4.1', 'CC7.2')
        ControlOwnerHint = 'Security'
    }
    $findings.Add((Get-SOC2Finding @params)) | Out-Null

    return $findings.ToArray()
}

<#
.SYNOPSIS
    Evaluates encryption-at-rest and encryption-in-transit posture for CC6.7
    using Defender for Cloud assessments.

.DESCRIPTION
    Uses Get-DefenderComplianceAssessments (from the Defender module) filtered
    to encryption-related assessment keywords. Graceful degradation when
    Defender plans are not enabled.

.PARAMETER Subscriptions
    Optional subscription filter.

.OUTPUTS
    Array of finding objects.
#>
function Test-SOC2EncryptionPosture {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [string[]]$Subscriptions = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    if (-not (Get-Command Get-DefenderComplianceAssessments -ErrorAction SilentlyContinue)) {
        $params = @{
            CheckName = 'Test-SOC2EncryptionPosture'
            Type = 'SOC2_Phase2_PrereqMissing'
            Status = 'INFO'
            Severity = 'Low'
            Object = 'Module: EntraChecks-DefenderCompliance'
            Description = 'Defender compliance module is not loaded. Encryption posture (CC6.7) cannot be evaluated.'
            Remediation = 'Import EntraChecks-DefenderCompliance before running SOC 2 assessment.'
            TSCReferences = @('CC6.7')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    $targetSubs = Get-SOC2TargetSubscriptions -Filter $Subscriptions
    if ($targetSubs.Count -eq 0) {
        $params = @{
            CheckName = 'Test-SOC2EncryptionPosture'
            Type = 'SOC2_Phase2_AzContextMissing'
            Status = 'INFO'
            Severity = 'Low'
            Object = 'Azure subscriptions'
            Description = 'No accessible subscriptions to query Defender encryption assessments.'
            Remediation = 'Connect-AzAccount with Security Reader and re-run.'
            TSCReferences = @('CC6.7')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    $encryptionKeywords = @('encryption', 'encrypt', 'tls', 'https', 'diskencryption', 'bitlocker', 'transparentdataencryption', 'ssl', 'cmk', 'customer-managed')
    $assessments = @()
    try {
        $subIds = @($targetSubs | ForEach-Object { $_.Id })
        $assessments = Get-DefenderComplianceAssessments -Subscriptions $subIds -ErrorAction Stop
    } catch {
        $params = @{
            CheckName = 'Test-SOC2EncryptionPosture'
            Type = 'SOC2_LicensingGap_DefenderForCloud'
            Status = 'INFO'
            Severity = 'Low'
            Object = 'Defender for Cloud regulatory compliance'
            Description = 'Could not query Defender compliance assessments. Likely cause: no paid Defender for Cloud plan on any subscription.'
            Remediation = 'Enable a Defender for Cloud plan on at least one in-scope subscription and assign a regulatory standard (e.g., Azure Security Benchmark).'
            TSCReferences = @('CC6.7')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    $encryption = [System.Collections.Generic.List[object]]::new()
    foreach ($assessment in $assessments) {
        $text = ($assessment.displayName + ' ' + $assessment.description).ToLowerInvariant()
        foreach ($kw in $encryptionKeywords) {
            if ($text -like "*$kw*") {
                $encryption.Add($assessment) | Out-Null
                break
            }
        }
    }

    if ($encryption.Count -eq 0) {
        $params = @{
            CheckName = 'Test-SOC2EncryptionPosture'
            Type = 'SOC2_EncryptionPostureGaps'
            Status = 'INFO'
            Severity = 'Low'
            Object = 'Defender encryption assessments'
            Description = 'No encryption-related assessments returned. Defender regulatory compliance may not have standards assigned, or encryption assessments are out of scope.'
            Remediation = 'Assign Azure Security Benchmark or CIS standard in Defender for Cloud and re-run.'
            TSCReferences = @('CC6.7')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    $failed = @($encryption | Where-Object { $_.status -eq 'Failed' -or $_.status -eq 'Unhealthy' })

    if ($failed.Count -gt 0) {
        foreach ($f in $failed) {
            $params = @{
                CheckName = 'Test-SOC2EncryptionPosture'
                Type = 'SOC2_EncryptionPostureGaps'
                Status = 'FAIL'
                Severity = 'High'
                Object = "Encryption: $($f.displayName)"
                Description = "Defender assessment failing: $($f.displayName). $($f.description)"
                Remediation = 'Follow Defender for Cloud remediation guidance in Azure portal for this assessment.'
                TSCReferences = @('CC6.7')
                ControlOwnerHint = 'Security'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
        }
        return $findings.ToArray()
    }

    $params = @{
        CheckName = 'Test-SOC2EncryptionPosture'
        Type = 'SOC2_EncryptionPostureHealthy'
        Status = 'OK'
        Severity = 'Info'
        Object = "Defender encryption assessments ($($encryption.Count))"
        Description = "All $($encryption.Count) encryption-related assessment(s) passing. CC6.7 (data in transit/at rest) evidence present."
        Remediation = 'No action required. Re-verify periodically.'
        TSCReferences = @('CC6.7')
        ControlOwnerHint = 'Security'
    }
    $findings.Add((Get-SOC2Finding @params)) | Out-Null

    return $findings.ToArray()
}

<#
.SYNOPSIS
    Evaluates anti-malware / EDR posture for CC6.8 (controls to prevent or
    detect unauthorized or malicious software).

.DESCRIPTION
    Checks whether Defender for Endpoint connector (WDATP setting) is enabled
    on at least one in-scope subscription, and cross-checks endpoint-protection
    assessments from Defender for Cloud where available.

.PARAMETER Subscriptions
    Optional subscription filter.

.OUTPUTS
    Array of finding objects.
#>
function Test-SOC2MalwareProtection {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [string[]]$Subscriptions = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    $targetSubs = Get-SOC2TargetSubscriptions -Filter $Subscriptions
    if ($targetSubs.Count -eq 0) {
        $params = @{
            CheckName = 'Test-SOC2MalwareProtection'
            Type = 'SOC2_Phase2_AzContextMissing'
            Status = 'INFO'
            Severity = 'Low'
            Object = 'Azure subscriptions'
            Description = 'No accessible subscriptions to query Defender for Endpoint connector state.'
            Remediation = 'Connect-AzAccount with Security Reader.'
            TSCReferences = @('CC6.8')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    $wdatpEnabledAnywhere = $false
    foreach ($sub in $targetSubs) {
        $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue
        $uri = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.Security/settings/WDATP"
        $wdatp = Invoke-SOC2AzureRestRequest -Uri $uri -ApiVersion '2022-05-01'
        if ($wdatp -and $wdatp.properties -and $wdatp.properties.enabled) {
            $wdatpEnabledAnywhere = $true
            break
        }
    }

    if (-not $wdatpEnabledAnywhere) {
        $params = @{
            CheckName = 'Test-SOC2MalwareProtection'
            Type = 'SOC2_MalwareProtectionGaps'
            Status = 'FAIL'
            Severity = 'High'
            Object = 'Defender for Endpoint connector'
            Description = 'Defender for Endpoint connector (WDATP) is not enabled on any in-scope subscription. EDR coverage for CC6.8 cannot be verified via Azure.'
            Remediation = 'Enable the Defender for Endpoint integration in Defender for Cloud on at least one subscription covering in-scope workloads.'
            TSCReferences = @('CC6.8')
            ControlOwnerHint = 'Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
        return $findings.ToArray()
    }

    # Secondary check: Defender malware assessments, if available
    if (Get-Command Get-DefenderComplianceAssessments -ErrorAction SilentlyContinue) {
        try {
            $subIds = @($targetSubs | ForEach-Object { $_.Id })
            $assessments = Get-DefenderComplianceAssessments -Subscriptions $subIds -ErrorAction Stop
            $malwareKeywords = @('*malware*', '*antimalware*', '*endpoint protection*', '*edr*')
            $malware = [System.Collections.Generic.List[object]]::new()
            foreach ($assessment in $assessments) {
                $text = ($assessment.displayName + ' ' + $assessment.description).ToLowerInvariant()
                foreach ($pattern in $malwareKeywords) {
                    if ($text -like $pattern) {
                        $malware.Add($assessment) | Out-Null
                        break
                    }
                }
            }
            $failedMalware = @($malware | Where-Object { $_.status -eq 'Failed' -or $_.status -eq 'Unhealthy' })
            if ($failedMalware.Count -gt 0) {
                foreach ($f in $failedMalware) {
                    $params = @{
                        CheckName = 'Test-SOC2MalwareProtection'
                        Type = 'SOC2_MalwareProtectionGaps'
                        Status = 'FAIL'
                        Severity = 'High'
                        Object = "Malware: $($f.displayName)"
                        Description = "Defender assessment failing: $($f.displayName). $($f.description)"
                        Remediation = 'Follow Defender for Cloud remediation guidance for this assessment.'
                        TSCReferences = @('CC6.8')
                        ControlOwnerHint = 'Security'
                    }
                    $findings.Add((Get-SOC2Finding @params)) | Out-Null
                }
                return $findings.ToArray()
            }
        } catch {
            # Defender assessment secondary-check is best-effort; primary
            # WDATP-connector check already passed when we got here.
            Write-Debug "Malware assessment secondary-check failed: $($_.Exception.Message)"
        }
    }

    $params = @{
        CheckName = 'Test-SOC2MalwareProtection'
        Type = 'SOC2_MalwareProtectionHealthy'
        Status = 'OK'
        Severity = 'Info'
        Object = 'Defender for Endpoint'
        Description = 'Defender for Endpoint connector enabled and no failing anti-malware assessments detected. CC6.8 signal present. Note: connector-enabled does not confirm per-endpoint coverage; complement with Intune device-compliance evidence where available.'
        Remediation = 'No action required. Spot-check per-device EDR coverage via the Defender portal.'
        TSCReferences = @('CC6.8')
        ControlOwnerHint = 'Security'
    }
    $findings.Add((Get-SOC2Finding @params)) | Out-Null

    return $findings.ToArray()
}

<#
.SYNOPSIS
    Verifies break-glass / emergency-access accounts are configured per CC7.5
    (ability to recover from security incidents).

.DESCRIPTION
    Enumerates Global Administrator members and Conditional Access policies,
    then identifies GA members whose ObjectId appears in EVERY enabled CA
    policy's excludeUsers list (user-level exclusion) OR via
    transitively-resolved excludeGroups membership. PASS requires at least
    MinimumAccounts such accounts.

.PARAMETER MinimumAccounts
    Minimum break-glass account count. Default 2.

.PARAMETER AccountUpnPatterns
    Optional array of glob patterns (e.g., 'breakglass-*@*') that qualifying
    accounts' UPNs should match. When set, accounts not matching any pattern
    produce a WARNING.

.OUTPUTS
    Array of finding objects.
#>
function Test-SOC2BreakGlassAccountsConfigured {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [int]$MinimumAccounts = 2,

        [string[]]$AccountUpnPatterns = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    # Global Administrator role template ID
    $gaRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'

    try {
        # Fetch GA role object and its members
        $rolesResp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/directoryRoles' -ErrorAction Stop
        $gaRole = $null
        if ($rolesResp.value) {
            $gaRole = $rolesResp.value | Where-Object { $_.roleTemplateId -eq $gaRoleTemplateId } | Select-Object -First 1
        }
        if (-not $gaRole) {
            $params = @{
                CheckName = 'Test-SOC2BreakGlassAccountsConfigured'
                Type = 'SOC2_BreakGlassMissing'
                Status = 'INFO'
                Severity = 'Low'
                Object = 'Global Administrator role'
                Description = 'Global Administrator role not found as activated directory role. In most tenants this means no GAs are assigned (PIM eligible-only) — verify manually.'
                Remediation = 'Review directory role assignments. Break-glass accounts are typically permanent GA members, not eligible.'
                TSCReferences = @('CC7.5')
                ControlOwnerHint = 'Identity / Security'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
            return $findings.ToArray()
        }

        $membersResp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($gaRole.id)/members" -ErrorAction Stop
        $gaMembers = @()
        if ($membersResp.value) {
            $gaMembers = @($membersResp.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' })
        }

        if ($gaMembers.Count -eq 0) {
            $params = @{
                CheckName = 'Test-SOC2BreakGlassAccountsConfigured'
                Type = 'SOC2_BreakGlassMissing'
                Status = 'FAIL'
                Severity = 'High'
                Object = 'Global Administrators'
                Description = 'Zero active Global Administrator users. No break-glass recovery path exists.'
                Remediation = 'Create at least 2 break-glass Global Administrator accounts with strong authentication and exclude them from all Conditional Access policies.'
                TSCReferences = @('CC7.5')
                ControlOwnerHint = 'Identity / Security'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
            return $findings.ToArray()
        }

        if ($gaMembers.Count -eq 1) {
            $params = @{
                CheckName = 'Test-SOC2BreakGlassAccountsConfigured'
                Type = 'SOC2_BreakGlassMissing'
                Status = 'FAIL'
                Severity = 'Critical'
                Object = 'Global Administrators'
                Description = 'Only one Global Administrator exists. Single point of failure for tenant recovery.'
                Remediation = 'Add at least one more permanent Global Administrator as a break-glass account, excluded from all Conditional Access policies.'
                TSCReferences = @('CC7.5')
                ControlOwnerHint = 'Identity / Security'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
            return $findings.ToArray()
        }

        # Fetch enabled CA policies
        $caResp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -ErrorAction Stop
        $enabledPolicies = @()
        if ($caResp.value) {
            $enabledPolicies = @($caResp.value | Where-Object { $_.state -eq 'enabled' })
        }

        if ($enabledPolicies.Count -eq 0) {
            $params = @{
                CheckName = 'Test-SOC2BreakGlassAccountsConfigured'
                Type = 'SOC2_BreakGlassMissing'
                Status = 'WARNING'
                Severity = 'Medium'
                Object = 'Conditional Access policies'
                Description = 'No enabled Conditional Access policies exist. Break-glass exclusion pattern cannot be verified. All GAs are effectively unrestricted — but CC6.1 is also failing since no CA policies protect any access paths.'
                Remediation = 'Implement Conditional Access policies for privileged access, then re-verify break-glass exclusions.'
                TSCReferences = @('CC6.1', 'CC7.5')
                ControlOwnerHint = 'Identity / Security'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
            return $findings.ToArray()
        }

        # Determine break-glass accounts: GA members whose ObjectId is in excludeUsers
        # of every enabled policy (or via excludeGroups membership).
        $breakGlassIds = [System.Collections.Generic.List[string]]::new()

        foreach ($ga in $gaMembers) {
            $excludedFromAll = $true
            foreach ($policy in $enabledPolicies) {
                $excluded = $false
                if ($policy.conditions.users.excludeUsers -and $ga.id -in $policy.conditions.users.excludeUsers) {
                    $excluded = $true
                }
                if (-not $excluded -and $policy.conditions.users.excludeGroups) {
                    # Check group membership (transitive)
                    foreach ($groupId in $policy.conditions.users.excludeGroups) {
                        try {
                            $memberCheck = Invoke-MgGraphRequest -Method POST `
                                -Uri "https://graph.microsoft.com/v1.0/users/$($ga.id)/checkMemberGroups" `
                                -Body (@{ groupIds = @($groupId) } | ConvertTo-Json) `
                                -ContentType 'application/json' `
                                -ErrorAction Stop
                            if ($memberCheck.value -and $memberCheck.value -contains $groupId) {
                                $excluded = $true
                                break
                            }
                        } catch {
                            # Transitive membership lookup can 404 for deleted groups
                            # or fail on rate limits; treat as "not a member" and continue.
                            Write-Debug "Group membership check failed for group $groupId : $($_.Exception.Message)"
                        }
                    }
                }
                if (-not $excluded) { $excludedFromAll = $false; break }
            }
            if ($excludedFromAll) { $breakGlassIds.Add($ga.id) | Out-Null }
        }

        if ($breakGlassIds.Count -lt $MinimumAccounts) {
            $params = @{
                CheckName = 'Test-SOC2BreakGlassAccountsConfigured'
                Type = 'SOC2_BreakGlassMissing'
                Status = 'FAIL'
                Severity = 'High'
                Object = 'Break-glass Global Administrators'
                Description = "Only $($breakGlassIds.Count) GA account(s) are excluded from all $($enabledPolicies.Count) enabled CA policies; SOC 2 CC7.5 recovery control requires at least $MinimumAccounts."
                Remediation = "Designate at least $MinimumAccounts break-glass Global Administrator accounts and exclude them from every enabled Conditional Access policy (either by user ID or by membership in a break-glass group)."
                TSCReferences = @('CC7.5')
                ControlOwnerHint = 'Identity / Security'
            }
            $findings.Add((Get-SOC2Finding @params)) | Out-Null
            return $findings.ToArray()
        }

        # Optional UPN pattern check
        if ($AccountUpnPatterns.Count -gt 0) {
            $nonMatchingCount = 0
            foreach ($bgId in $breakGlassIds) {
                $ga = $gaMembers | Where-Object { $_.id -eq $bgId } | Select-Object -First 1
                $upn = $ga.userPrincipalName
                $matchesAny = $false
                foreach ($pattern in $AccountUpnPatterns) {
                    if ($upn -like $pattern) { $matchesAny = $true; break }
                }
                if (-not $matchesAny) { $nonMatchingCount++ }
            }
            if ($nonMatchingCount -gt 0) {
                $params = @{
                    CheckName = 'Test-SOC2BreakGlassAccountsConfigured'
                    Type = 'SOC2_BreakGlassMissing'
                    Status = 'WARNING'
                    Severity = 'Low'
                    Object = "Break-glass UPN naming ($nonMatchingCount mismatched)"
                    Description = "$nonMatchingCount of $($breakGlassIds.Count) break-glass account(s) do not match configured UPN patterns ($(($AccountUpnPatterns) -join ', ')). Accounts are functional but naming convention is inconsistent."
                    Remediation = 'Either update UPN patterns in SOC2.Phase2.BreakGlass.AccountUpnPatterns to match actual naming, or rename accounts to match the convention.'
                    TSCReferences = @('CC7.5')
                    ControlOwnerHint = 'Identity / Security'
                }
                $findings.Add((Get-SOC2Finding @params)) | Out-Null
            }
        }

        # Healthy PASS
        $params = @{
            CheckName = 'Test-SOC2BreakGlassAccountsConfigured'
            Type = 'SOC2_BreakGlassConfigured'
            Status = 'OK'
            Severity = 'Info'
            Object = "Break-glass Global Administrators ($($breakGlassIds.Count))"
            Description = "$($breakGlassIds.Count) break-glass GA account(s) excluded from all $($enabledPolicies.Count) enabled CA policies. CC7.5 recovery control satisfied."
            Remediation = 'No action required. Verify sign-in capability quarterly via a documented runbook and rotate credentials annually.'
            TSCReferences = @('CC7.5')
            ControlOwnerHint = 'Identity / Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null

    } catch {
        $params = @{
            CheckName = 'Test-SOC2BreakGlassAccountsConfigured'
            Type = 'SOC2_BreakGlassMissing'
            Status = 'WARNING'
            Severity = 'Low'
            Object = 'Break-glass verification'
            Description = "Could not verify break-glass configuration: $($_.Exception.Message)"
            Remediation = 'Ensure Graph scopes Directory.Read.All, Policy.Read.All, RoleManagement.Read.Directory are granted.'
            TSCReferences = @('CC7.5')
            ControlOwnerHint = 'Identity / Security'
        }
        $findings.Add((Get-SOC2Finding @params)) | Out-Null
    }

    return $findings.ToArray()
}

#endregion

#region ==================== ORCHESTRATION ====================

<#
.SYNOPSIS
    Combines mapped EntraChecks findings with SOC-2-specific synthetic findings
    and manual-attestation stubs into a complete SOC 2 findings collection.
#>
function Get-SOC2ManualAttestationStubs {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [object[]]$Catalog
    )

    $stubs = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($control in $Catalog) {
        if ($control.Automation -eq 'Manual') {
            $params = @{
                CheckName = "Manual-$($control.Id)"
                Type = "SOC2_Manual_$($control.Id)"
                Status = 'MANUAL'
                Object = "$($control.Id) - $($control.FamilyName)"
                Description = "Manual attestation required for $($control.Id). $($control.Description)"
                Remediation = "Record attestation in evidence-bundle/manual-attestation/$($control.Id).md covering: control owner, description of operation, frequency of operation, evidence location, attested-by, attested-date."
                TSCReferences = @($control.Id)
                ControlOwnerHint = $control.ControlOwnerHint
            }
            $stubs.Add((Get-SOC2Finding @params)) | Out-Null
        }
    }
    return $stubs.ToArray()
}

function Invoke-SOC2Assessment {
    <#
    .SYNOPSIS
        Orchestrates a SOC 2 Type 1 assessment over a pre-collected set of
        EntraChecks findings, producing TSC-mapped findings, synthetic findings,
        manual-attestation stubs, and an evidence bundle.

    .DESCRIPTION
        This function assumes the caller has already run the EntraChecks core
        assessment and passes in the resulting findings via -ExistingFindings.
        It then:
          1. Maps each existing finding to TSC controls via ComplianceMapping.
          2. Runs SOC-2-specific synthetic checks (admin contacts, alerting,
             incident response readiness).
          3. Emits manual-attestation stubs for non-automatable TSC controls.
          4. Optionally redacts user PII (default ON per project decision).
          5. Writes the evidence bundle with a SHA-256 manifest.

    .PARAMETER ExistingFindings
        Findings from the unified EntraChecks run to be mapped to SOC 2 TSCs.

    .PARAMETER TenantId
        Tenant ID (for evidence manifest and tenant-scoped salt).

    .PARAMETER TenantName
        Human-readable tenant name for the evidence manifest.

    .PARAMETER Categories
        TSC categories in scope (default: all).

    .PARAMETER OutputDirectory
        Root directory for SOC 2 output (HTML/Excel/evidence bundle).

    .PARAMETER SaltDirectory
        Directory where the tenant-scoped salt file is persisted.

    .PARAMETER IdentityResolutionDirectory
        Where to write the identity-resolution map (separate from output dir).

    .PARAMETER RedactUsers
        Apply user-PII redaction (default via caller; module default: ON).

    .PARAMETER RedactDevices
        Apply device-name redaction.

    .PARAMETER IncludeManualAttestation
        Emit MANUAL findings for non-automatable TSC controls.

    .PARAMETER Assessor
        Name / identity of the person running the assessment (for manifest).

    .PARAMETER ServiceOrganization
        Organization name for the manifest (used only if not white-labeled).

    .OUTPUTS
        PSCustomObject with Findings, Catalog, Evidence, Summary.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object[]]$ExistingFindings,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [string]$TenantName = '',

        [ValidateSet('CC', 'A', 'C', 'PI', 'P')]
        [string[]]$Categories = @('CC', 'A', 'C', 'PI', 'P'),

        [Parameter(Mandatory)]
        [string]$OutputDirectory,

        [string]$SaltDirectory,

        [string]$IdentityResolutionDirectory,

        [switch]$RedactUsers,

        [switch]$RedactDevices,

        [bool]$IncludeManualAttestation = $true,

        [string]$Assessor = '',

        [string]$ServiceOrganization = '',

        # --- Phase 2 parameters ---
        [string[]]$SubscriptionFilter = @(),

        [hashtable]$LicensingOverrides = @{},

        [int]$BreakGlassMinimumAccounts = 2,

        [string[]]$BreakGlassUpnPatterns = @(),

        [string]$BackupMinRedundancyTier = 'GRS',

        [int]$ServiceHealthThreshold = 98,

        [string[]]$DiagnosticSettingsRequiredCategories = @('AuditLogs', 'SignInLogs'),

        [string]$DiagnosticSettingsRequiredWorkspaceId = '',

        # Audit-Readiness Plan §11.1 — Manual Attestation Workflow. Path to
        # the per-control attestation state file. Empty disables the
        # workflow (manual controls render NotStarted).
        [string]$AttestationStatePath = ''
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
    }
    if (-not $SaltDirectory) { $SaltDirectory = Join-Path $OutputDirectory 'salt' }
    if (-not $IdentityResolutionDirectory) {
        $IdentityResolutionDirectory = Join-Path $OutputDirectory 'identity-resolution'
    }

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level INFO -Message "Starting SOC 2 assessment for tenant $TenantId" -Category 'SOC2' -Properties @{
            Categories = ($Categories -join ',')
            InputFindings = $ExistingFindings.Count
        }
    }

    # Step 1: Filter catalog by categories in scope
    $catalog = Get-SOC2TSCCatalog -Categories $Categories

    # Step 2a: Probe licensing capabilities once per assessment
    $caps = Get-SOC2LicensingCapabilities
    $azContext = $null
    if (Get-Command Get-AzContext -ErrorAction SilentlyContinue) {
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
    }

    # Step 2b: Run synthetic checks (Phase 1 + Phase 2), capability-gated
    $syntheticFindings = [System.Collections.Generic.List[object]]::new()

    if ('CC' -in $Categories) {
        # Phase 1 CC checks
        foreach ($f in @(Test-SOC2AdminContacts)) { $syntheticFindings.Add($f) | Out-Null }
        foreach ($f in @(Test-SOC2SecurityAlertingConfigured)) { $syntheticFindings.Add($f) | Out-Null }
        foreach ($f in @(Test-SOC2IncidentResponseReadiness)) { $syntheticFindings.Add($f) | Out-Null }

        # Phase 2 CC checks (Graph-only -> run unconditionally)
        $bgParams = @{}
        if ($BreakGlassMinimumAccounts -gt 0) { $bgParams['MinimumAccounts'] = $BreakGlassMinimumAccounts }
        if ($BreakGlassUpnPatterns -and $BreakGlassUpnPatterns.Count -gt 0) {
            $bgParams['AccountUpnPatterns'] = $BreakGlassUpnPatterns
        }
        foreach ($f in @(Test-SOC2BreakGlassAccountsConfigured @bgParams)) { $syntheticFindings.Add($f) | Out-Null }

        # Phase 2 CC checks that need Az context
        if ($azContext) {
            $dsParams = @{}
            if ($DiagnosticSettingsRequiredCategories -and $DiagnosticSettingsRequiredCategories.Count -gt 0) {
                $dsParams['RequiredCategories'] = $DiagnosticSettingsRequiredCategories
            }
            if ($DiagnosticSettingsRequiredWorkspaceId) {
                $dsParams['RequiredWorkspaceId'] = $DiagnosticSettingsRequiredWorkspaceId
            }
            foreach ($f in @(Test-SOC2DiagnosticSettingsExport @dsParams)) { $syntheticFindings.Add($f) | Out-Null }

            foreach ($f in @(Test-SOC2EncryptionPosture -Subscriptions $SubscriptionFilter)) { $syntheticFindings.Add($f) | Out-Null }
            foreach ($f in @(Test-SOC2MalwareProtection -Subscriptions $SubscriptionFilter)) { $syntheticFindings.Add($f) | Out-Null }
        } else {
            $umbrella = @{}
            $umbrella['CheckName'] = 'Invoke-SOC2Assessment'
            $umbrella['Type'] = 'SOC2_Phase2_AzContextMissing'
            $umbrella['Status'] = 'INFO'
            $umbrella['Severity'] = 'Low'
            $umbrella['Object'] = 'Azure context'
            $umbrella['Description'] = 'No Azure context available; CC4.1/CC6.7/CC6.8/CC7.2 Azure-side checks will be reported as unassessed.'
            $umbrella['Remediation'] = 'Run Connect-AzAccount before invoking SOC 2 assessment to enable Phase 2 Azure-side checks.'
            $umbrella['TSCReferences'] = @('CC4.1', 'CC6.7', 'CC6.8', 'CC7.2')
            $umbrella['ControlOwnerHint'] = 'Security'
            $syntheticFindings.Add((Get-SOC2Finding @umbrella)) | Out-Null
        }
    }

    if ('A' -in $Categories -and $azContext) {
        $bkParams = @{}
        if ($SubscriptionFilter -and $SubscriptionFilter.Count -gt 0) {
            $bkParams['Subscriptions'] = $SubscriptionFilter
        }
        if ($BackupMinRedundancyTier) { $bkParams['MinRedundancyTier'] = $BackupMinRedundancyTier }
        foreach ($f in @(Test-SOC2BackupConfiguration @bkParams)) { $syntheticFindings.Add($f) | Out-Null }

        $shParams = @{}
        if ($SubscriptionFilter -and $SubscriptionFilter.Count -gt 0) {
            $shParams['Subscriptions'] = $SubscriptionFilter
        }
        if ($ServiceHealthThreshold -gt 0) { $shParams['AvailabilityThresholdPercent'] = $ServiceHealthThreshold }
        foreach ($f in @(Test-SOC2ServiceHealthBaseline @shParams)) { $syntheticFindings.Add($f) | Out-Null }
    }

    # Step 2c: Seed licensing-gap findings
    foreach ($f in @(New-SOC2LicensingGapFindings -Capabilities $caps -Overrides $LicensingOverrides)) {
        $syntheticFindings.Add($f) | Out-Null
    }

    # Step 3: Annotate existing findings with TSC mappings (via ComplianceMapping)
    $annotatedFindings = [System.Collections.Generic.List[pscustomobject]]::new()
    if (Get-Command Add-ComplianceMapping -ErrorAction SilentlyContinue) {
        foreach ($finding in $ExistingFindings) {
            $annotated = $finding | Add-ComplianceMapping
            $annotatedFindings.Add($annotated) | Out-Null
        }
    } else {
        foreach ($finding in $ExistingFindings) { $annotatedFindings.Add($finding) | Out-Null }
    }

    # Step 4: Emit manual-attestation stubs if requested
    $manualStubs = @()
    if ($IncludeManualAttestation) {
        $manualStubs = Get-SOC2ManualAttestationStubs -Catalog $catalog
    }

    # Step 5: Combine all findings
    $allFindings = @()
    $allFindings += $annotatedFindings.ToArray()
    $allFindings += $syntheticFindings.ToArray()
    $allFindings += $manualStubs

    # Step 5b: Normalize to schema v2 BEFORE redaction so every downstream
    # consumer (redaction → bundle → summary → digest → renderers) sees the
    # same shape. ConvertTo-EntraFindingV2 is idempotent; existing v2 fields
    # are preserved, missing ones added (FindingId, Disposition, Owner,
    # Exception, ReviewStatus, ControlMappings, Evidence, SchemaVersion).
    # Source defaults to 'SOC2' so the deterministic FindingId is stable
    # across runs of the SOC 2 pipeline.
    # See: plans/SOC2-Audit-Readiness-Plan.md §8.1 (PR 1 sub-step 1).
    if (Get-Command ConvertTo-EntraFindingV2 -ErrorAction SilentlyContinue) {
        $normalized = @()
        foreach ($f in $allFindings) {
            $normalized += (ConvertTo-EntraFindingV2 -Finding $f -DefaultTenantId $TenantId -DefaultSource 'SOC2')
        }
        $allFindings = $normalized
    }

    # Step 5c: Manual Attestation Workflow (Audit-Readiness Plan §11.1).
    # Load the per-control attestation state and map it onto each manual
    # stub's v2 ReviewStatus so non-accepted manual controls surface in
    # the cockpit Review Queue and the SOC 2 report shows tracked state.
    # Advisory: a missing/disabled path just leaves everything NotStarted.
    $attestationState = @{ Attestations = @{} }
    if ((Get-Command Import-SOC2AttestationState -ErrorAction SilentlyContinue) -and
        (Get-Command Add-SOC2AttestationToFindings -ErrorAction SilentlyContinue)) {
        $attestationState = Import-SOC2AttestationState -Path $AttestationStatePath
        # Direct-assign (NOT @(...)): Add-SOC2AttestationToFindings returns a
        # comma-wrapped array (module convention); @() around the call
        # double-wraps it into a single element. It also mutates in place,
        # so this is belt-and-braces.
        $allFindings = Add-SOC2AttestationToFindings -Findings $allFindings -State $attestationState
    }

    # Step 6: Redact if requested
    $identityMap = @{}
    $redactionResult = $null
    if ($RedactUsers -or $RedactDevices) {
        $redactionResult = Invoke-SOC2Redaction `
            -Findings $allFindings `
            -TenantId $TenantId `
            -SaltDirectory $SaltDirectory `
            -RedactUsers:$RedactUsers `
            -RedactDevices:$RedactDevices
        $allFindings = $redactionResult.Findings
        $identityMap = $redactionResult.IdentityMap
    }

    # Step 7: Build summary
    $summary = Get-SOC2Summary -Findings $allFindings -Catalog $catalog

    # Step 8: Write evidence bundle
    $evidenceDir = Join-Path $OutputDirectory 'evidence-bundle'
    $evidence = New-SOC2EvidenceBundle `
        -Findings $allFindings `
        -Catalog $catalog `
        -TenantId $TenantId `
        -TenantName $TenantName `
        -Assessor $Assessor `
        -ServiceOrganization $ServiceOrganization `
        -Categories $Categories `
        -Summary $summary `
        -OutputDirectory $evidenceDir

    # Step 9: Persist identity-resolution map (if redacted)
    $resolutionMapPath = $null
    if ($identityMap.Count -gt 0) {
        $resolutionMapPath = Write-SOC2IdentityResolutionMap `
            -IdentityMap $identityMap `
            -TenantId $TenantId `
            -OutputDirectory $IdentityResolutionDirectory
    }

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level INFO -Message "SOC 2 assessment complete" -Category 'SOC2' -Properties @{
            TotalFindings = $allFindings.Count
            BundleHash = $evidence.BundleHash
            IdentityMapPath = $resolutionMapPath
        }
    }

    return [pscustomobject]@{
        Findings = $allFindings
        Catalog = $catalog
        Evidence = $evidence
        Summary = $summary
        IdentityMapPath = $resolutionMapPath
        OutputDirectory = $OutputDirectory
        # §11.1 — per-control attestation state (loaded above) so the SOC 2
        # report renderer can show tracked owner/dates/reviewer per control.
        AttestationState = $attestationState
    }
}

function Get-SOC2Summary {
    <#
    .SYNOPSIS
        Aggregates SOC 2 findings by TSC category and control.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [object[]]$Catalog
    )

    $byFamily = @{}
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $entry = @{}
        $entry['Automated'] = 0
        $entry['Manual'] = 0
        $entry['Pass'] = 0
        $entry['Fail'] = 0
        $entry['Warning'] = 0
        $entry['Review'] = 0
        $entry['Info'] = 0
        # Phase 3 PR 3: per-family count of SOC2_LicensingGap_* findings.
        # Additive — gaps continue to also count toward Info for byte-stable
        # Phase 2 behavior (locked decision #6).
        $entry['LicensingGaps'] = 0
        $byFamily[$family] = $entry
    }

    # Phase 3 PR 3: licensing-gap rollup for the executive dashboard tile
    $licensingGapRollup = @{}
    $licensingGapRollup['Total'] = 0
    $licensingGapByFeature = @{}
    foreach ($feature in @('IdentityProtection', 'Intune', 'PurviewE5', 'DefenderForCloud', 'DefenderForEndpoint', 'Priva', 'Sentinel')) {
        $licensingGapByFeature[$feature] = 0
    }
    $licensingGapByFamily = @{}
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $licensingGapByFamily[$family] = 0
    }

    $controlFindings = @{}

    foreach ($control in $Catalog) {
        $family = $control.Family
        if ($control.Automation -eq 'Manual') {
            $byFamily[$family]['Manual']++
        } else {
            $byFamily[$family]['Automated']++
        }
        $controlFindings[$control.Id] = @()
    }

    foreach ($finding in $Findings) {
        $tscRefs = Get-FindingTSCReferences -Finding $finding
        $isLicensingGap = $false
        if ($finding.PSObject.Properties['Type'] -and $finding.Type -and $finding.Type -like 'SOC2_LicensingGap_*') {
            $isLicensingGap = $true
            $licensingGapRollup['Total']++
            $featureName = $finding.Type.Substring('SOC2_LicensingGap_'.Length)
            if ($licensingGapByFeature.ContainsKey($featureName)) {
                $licensingGapByFeature[$featureName]++
            } else {
                # Future-proof for unknown features (not pre-seeded above)
                $licensingGapByFeature[$featureName] = 1
            }
        }

        foreach ($tsc in $tscRefs) {
            if ($controlFindings.ContainsKey($tsc)) {
                $controlFindings[$tsc] += $finding
            }
        }

        # Track per-family licensing-gap counts across ALL referenced TSCs
        # (a single gap finding can affect multiple families, e.g. PurviewE5 hits CC and C).
        if ($isLicensingGap) {
            $touchedFamilies = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($tsc in $tscRefs) {
                $fam = $null
                if ($tsc -match '^CC') { $fam = 'CC' }
                elseif ($tsc -match '^A') { $fam = 'A' }
                elseif ($tsc -match '^PI') { $fam = 'PI' }
                elseif ($tsc -match '^P') { $fam = 'P' }
                elseif ($tsc -match '^C') { $fam = 'C' }
                if ($fam -and $licensingGapByFamily.ContainsKey($fam)) {
                    $null = $touchedFamilies.Add($fam)
                }
            }
            foreach ($fam in $touchedFamilies) {
                $licensingGapByFamily[$fam]++
                $byFamily[$fam]['LicensingGaps']++
            }
        }

        $family = $null
        if ($tscRefs.Count -gt 0) {
            $family = ($tscRefs[0] -split '\.', 2)[0]
            # Normalize CC1..CC9 -> CC, A1.. -> A, C1.. -> C, PI1.. -> PI, P... -> P
            if ($family -match '^CC') { $family = 'CC' }
            elseif ($family -match '^A') { $family = 'A' }
            elseif ($family -match '^C') { $family = 'C' }
            elseif ($family -match '^PI') { $family = 'PI' }
            elseif ($family -match '^P') { $family = 'P' }
        }

        if ($family -and $byFamily.ContainsKey($family)) {
            switch ($finding.Status) {
                'OK' { $byFamily[$family]['Pass']++ }
                'FAIL' { $byFamily[$family]['Fail']++ }
                'WARNING' { $byFamily[$family]['Warning']++ }
                'REVIEW' { $byFamily[$family]['Review']++ }
                default { $byFamily[$family]['Info']++ }
            }
        }
    }

    $licensingGapRollup['ByFeature'] = $licensingGapByFeature
    $licensingGapRollup['ByFamily'] = $licensingGapByFamily

    return [pscustomobject]@{
        ByFamily = $byFamily
        ControlFindings = $controlFindings
        TotalFindings = $Findings.Count
        TotalControls = $Catalog.Count
        LicensingGaps = $licensingGapRollup
    }
}

#endregion

#region ==================== EVIDENCE BUNDLE ====================

function Get-FindingTSCReferences {
    <#
    .SYNOPSIS
        Extracts TSC control IDs from a finding.
    .DESCRIPTION
        Internal helper used by the evidence-bundle generator. Checks the
        explicit TSCReferences property first, then falls back to the
        ComplianceMappings.SOC2.Criteria list populated by Add-ComplianceMapping.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [object]$Finding
    )

    # Leading-comma return prevents PowerShell from unwrapping single-element
    # arrays to scalars — callers rely on .Count and [int]-indexing on the
    # result, which behave very differently on a string vs string[].
    if ($Finding.PSObject.Properties['TSCReferences'] -and $Finding.TSCReferences) {
        return , @($Finding.TSCReferences)
    }
    if ($Finding.PSObject.Properties['ComplianceMappings'] -and $Finding.ComplianceMappings -and $Finding.ComplianceMappings.SOC2) {
        return , @($Finding.ComplianceMappings.SOC2.Criteria)
    }
    return , @()
}

function New-SOC2EvidenceBundle {
    <#
    .SYNOPSIS
        Writes the SOC 2 evidence bundle (manifest, per-control JSON, manual
        attestation templates) with a SHA-256 hash chain for tamper detection.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][object[]]$Catalog,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$TenantName = '',
        [string]$Assessor = '',
        [string]$ServiceOrganization = '',
        [Parameter(Mandatory)][string[]]$Categories,
        [Parameter(Mandatory)][pscustomobject]$Summary,
        [Parameter(Mandatory)][string]$OutputDirectory
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
    }

    $controlsDir = Join-Path $OutputDirectory 'controls'
    $manualDir = Join-Path $OutputDirectory 'manual-attestation'
    $null = New-Item -Path $controlsDir -ItemType Directory -Force -ErrorAction SilentlyContinue
    $null = New-Item -Path $manualDir -ItemType Directory -Force -ErrorAction SilentlyContinue

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $writtenFiles = [System.Collections.Generic.List[string]]::new()

    # Per-TSC evidence files
    foreach ($control in $Catalog) {
        $mapped = [System.Collections.Generic.List[object]]::new()
        foreach ($finding in $Findings) {
            $refs = Get-FindingTSCReferences -Finding $finding
            if ($refs -contains $control.Id) { $mapped.Add($finding) | Out-Null }
        }

        $findingRows = [System.Collections.Generic.List[object]]::new()
        foreach ($f in $mapped) {
            $severity = if ($f.PSObject.Properties['Severity']) { $f.Severity } else { '' }
            $row = [ordered]@{
                CheckName = $f.CheckName
                Type = $f.Type
                Status = $f.Status
                Severity = $severity
                Object = $f.Object
                Description = $f.Description
                Remediation = $f.Remediation
            }
            $findingRows.Add($row) | Out-Null
        }

        $payload = [ordered]@{
            SchemaVersion = '1.0'
            TSCRevision = $script:TSCRevision
            ControlId = $control.Id
            ControlFamily = $control.Family
            ControlFamilyName = $control.FamilyName
            Automation = $control.Automation
            Description = $control.Description
            ControlOwnerHint = $control.ControlOwnerHint
            CapturedAt = $timestamp
            TenantId = $TenantId
            Findings = @($findingRows.ToArray())
        }

        $filePath = Join-Path $controlsDir "$($control.Id).json"
        $json = $payload | ConvertTo-Json -Depth 10
        Set-Content -LiteralPath $filePath -Value $json -Encoding UTF8
        $writtenFiles.Add($filePath) | Out-Null

        # Manual attestation template
        if ($control.Automation -eq 'Manual') {
            $template = @"
# Manual Attestation - $($control.Id)

**Control family:** $($control.FamilyName) ($($control.Family))
**Control owner hint:** $($control.ControlOwnerHint)
**TSC revision:** $($script:TSCRevision)

## Description

$($control.Description)

## Attestation

| Field | Value |
|---|---|
| Control owner (name + title) |  |
| Description of how the control operates |  |
| Frequency of operation |  |
| Evidence location |  |
| Period of coverage |  |
| Attested by |  |
| Attested on (UTC) |  |

## Notes

"@
            $mdPath = Join-Path $manualDir "$($control.Id).md"
            Set-Content -LiteralPath $mdPath -Value $template -Encoding UTF8
            $writtenFiles.Add($mdPath) | Out-Null
        }
    }

    # Hash every written file deterministically
    $hashEntries = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($f in ($writtenFiles | Sort-Object)) {
        $hash = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower()
        $relative = $f.Substring($OutputDirectory.Length).TrimStart('\', '/')
        $entry = @{}
        $entry['RelativePath'] = $relative
        $entry['SHA256'] = $hash
        $hashEntries.Add($entry) | Out-Null
    }

    # Rolling bundle hash: SHA-256 over the concatenation of "relative|hash\n" sorted
    $concatSource = ($hashEntries | ForEach-Object { "$($_.RelativePath)|$($_.SHA256)" }) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bundleHashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concatSource))
    } finally {
        $sha.Dispose()
    }
    $bundleHash = -join ($bundleHashBytes | ForEach-Object { $_.ToString('x2') })

    $manifest = [ordered]@{
        SchemaVersion = '1.0'
        TSCRevision = $script:TSCRevision
        GeneratedAt = $timestamp
        EntraChecksVersion = $script:ModuleVersion
        TenantId = $TenantId
        TenantName = $TenantName
        Assessor = $Assessor
        ServiceOrganization = $ServiceOrganization
        Categories = $Categories
        Type = 'Type1'
        HashAlgorithm = 'SHA256'
        BundleHash = $bundleHash
        Files = $hashEntries
        Summary = @{
            TotalFindings = $Summary.TotalFindings
            TotalControls = $Summary.TotalControls
            ByFamily = $Summary.ByFamily
        }
    }

    $manifestPath = Join-Path $OutputDirectory 'manifest.json'
    $manifestJson = $manifest | ConvertTo-Json -Depth 12
    Set-Content -LiteralPath $manifestPath -Value $manifestJson -Encoding UTF8

    return [pscustomobject]@{
        ManifestPath = $manifestPath
        BundleHash = $bundleHash
        Directory = $OutputDirectory
        FileCount = $writtenFiles.Count
        GeneratedAt = $timestamp
    }
}

function Test-SOC2EvidenceBundle {
    <#
    .SYNOPSIS
        Recomputes the SHA-256 hashes listed in a SOC 2 evidence manifest and
        returns $true only if every file matches its recorded hash and the
        rolling bundle hash still matches.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "Manifest not found: $ManifestPath"
    }

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $bundleDir = Split-Path -Parent $ManifestPath

    $mismatches = [System.Collections.Generic.List[string]]::new()
    $hashLines = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in $manifest.Files) {
        $fullPath = Join-Path $bundleDir $entry.RelativePath
        if (-not (Test-Path -LiteralPath $fullPath)) {
            $mismatches.Add("MISSING: $($entry.RelativePath)") | Out-Null
            continue
        }
        $actual = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $entry.SHA256) {
            $mismatches.Add("TAMPERED: $($entry.RelativePath) (expected $($entry.SHA256), got $actual)") | Out-Null
        }
        $hashLines.Add("$($entry.RelativePath)|$($entry.SHA256)") | Out-Null
    }

    # Recompute rolling bundle hash
    $concatSource = ($hashLines | Sort-Object) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $computed = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concatSource))
    } finally {
        $sha.Dispose()
    }
    $computedBundleHash = -join ($computed | ForEach-Object { $_.ToString('x2') })
    $bundleHashMatches = ($computedBundleHash -eq $manifest.BundleHash)
    if (-not $bundleHashMatches) {
        $mismatches.Add("BUNDLE HASH MISMATCH: expected $($manifest.BundleHash), got $computedBundleHash") | Out-Null
    }

    return [pscustomobject]@{
        Valid = ($mismatches.Count -eq 0)
        Mismatches = $mismatches.ToArray()
        ExpectedBundleHash = $manifest.BundleHash
        ComputedBundleHash = $computedBundleHash
        FileCount = @($manifest.Files).Count
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    # Phase 1
    'Get-SOC2TSCCatalog',
    'Get-SOC2Finding',
    'Get-SOC2TenantSalt',
    'Get-SOC2IdentityHash',
    'Invoke-SOC2Redaction',
    'Write-SOC2IdentityResolutionMap',
    'Resolve-SOC2Identity',
    'Test-SOC2AdminContacts',
    'Test-SOC2SecurityAlertingConfigured',
    'Test-SOC2IncidentResponseReadiness',
    'Get-SOC2ManualAttestationStubs',
    'Invoke-SOC2Assessment',
    'Get-SOC2Summary',
    'New-SOC2EvidenceBundle',
    'Test-SOC2EvidenceBundle',
    # Phase 2 - Azure helpers + licensing
    'Get-SOC2LicensingCapabilities',
    'New-SOC2LicensingGapFindings',
    # Phase 2 - synthetic checks
    'Test-SOC2BackupConfiguration',
    'Test-SOC2ServiceHealthBaseline',
    'Test-SOC2DiagnosticSettingsExport',
    'Test-SOC2EncryptionPosture',
    'Test-SOC2MalwareProtection',
    'Test-SOC2BreakGlassAccountsConfigured'
)

#endregion
