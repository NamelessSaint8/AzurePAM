# EntraChecks Compliance Framework Mapping Module
# Maps security findings to compliance framework controls

<#
.SYNOPSIS
    Provides compliance framework mapping for EntraChecks findings.

.DESCRIPTION
    This module maps EntraChecks security findings to controls in multiple compliance frameworks:
    - CIS Microsoft 365 Foundations Benchmark
    - NIST Cybersecurity Framework (CSF)
    - SOC 2 Trust Services Criteria
    - PCI-DSS v4.0.1

.NOTES
    Author: David Stells
    Version: 1.0.0
#>

#region Framework Data Structures

# CIS Microsoft 365 Foundations Benchmark mappings
$Script:CISMicrosoft365Mapping = @{
    # Identity and Access Management
    'MFA_Disabled' = @{
        Controls = @('1.1.3', '1.3.1')
        Title = 'Ensure multifactor authentication is enabled for all users'
        Description = 'MFA provides additional security for user accounts'
    }
    'MFA_AdminDisabled' = @{
        Controls = @('1.1.1', '1.1.3')
        Title = 'Ensure multifactor authentication is enabled for all admin users'
        Description = 'Administrative accounts require MFA protection'
    }
    'ConditionalAccess_Missing' = @{
        Controls = @('1.1.1', '1.1.3', '2.1.1')
        Title = 'Ensure Conditional Access policies are configured'
        Description = 'Conditional Access provides risk-based access control'
    }
    'LegacyAuth_Enabled' = @{
        Controls = @('1.1.4')
        Title = 'Ensure legacy authentication protocols are blocked'
        Description = 'Legacy protocols do not support MFA'
    }
    'PasswordExpiry_Disabled' = @{
        Controls = @('1.1.5')
        Title = 'Ensure password expiration is appropriately configured'
        Description = 'Password policies should align with modern guidance'
    }
    'SelfServicePasswordReset_Disabled' = @{
        Controls = @('1.1.7')
        Title = 'Ensure self-service password reset is enabled'
        Description = 'SSPR reduces helpdesk burden and improves security'
    }
    'AdminRoles_Excessive' = @{
        Controls = @('1.2.1', '1.2.2')
        Title = 'Ensure administrative roles are assigned to fewer than 5 users'
        Description = 'Limit administrative access to minimum necessary users'
    }
    'GlobalAdmin_Multiple' = @{
        Controls = @('1.2.1')
        Title = 'Ensure the global admin role is assigned to fewer than 5 users'
        Description = 'Global admins have unrestricted access'
    }
    'GuestAccess_Unrestricted' = @{
        Controls = @('1.3.1', '1.3.3')
        Title = 'Ensure guest users are reviewed regularly'
        Description = 'Guest access should be monitored and controlled'
    }

    # Application Permissions
    'AppPermissions_Excessive' = @{
        Controls = @('3.1.1', '3.1.2')
        Title = 'Ensure application permissions are reviewed regularly'
        Description = 'Applications should have minimum required permissions'
    }
    'AppConsent_UserAllowed' = @{
        Controls = @('3.1.4')
        Title = 'Ensure user consent for applications is restricted'
        Description = 'Prevent users from consenting to risky applications'
    }

    # Data Protection
    'DLP_NotConfigured' = @{
        Controls = @('2.1.6')
        Title = 'Ensure DLP policies are enabled'
        Description = 'Data Loss Prevention protects sensitive information'
    }
    'AuditLog_NotEnabled' = @{
        Controls = @('2.1.1', '6.1.1')
        Title = 'Ensure audit logging is enabled'
        Description = 'Audit logs are critical for security monitoring'
    }
    'MailboxAudit_Disabled' = @{
        Controls = @('2.1.2')
        Title = 'Ensure mailbox auditing is enabled'
        Description = 'Mailbox audit logs track access and changes'
    }

    # Security Defaults
    'SecurityDefaults_Disabled' = @{
        Controls = @('1.1.1')
        Title = 'Ensure Security Defaults is enabled if Conditional Access is not used'
        Description = 'Security Defaults provide baseline protection'
    }
    'RiskySignIn_NoPolicy' = @{
        Controls = @('1.1.2')
        Title = 'Ensure sign-in risk policy is configured'
        Description = 'Risk-based policies respond to suspicious activity'
    }
}

# NIST Cybersecurity Framework mappings
$Script:NISTCSFMapping = @{
    # Identify
    'MFA_Disabled' = @{
        Functions = @('PR.AC-1', 'PR.AC-7')
        Description = 'Identities and credentials are managed (PR.AC-1); Users, devices, and assets are authenticated (PR.AC-7)'
    }
    'MFA_AdminDisabled' = @{
        Functions = @('PR.AC-1', 'PR.AC-4', 'PR.AC-7')
        Description = 'Identities and credentials are managed; Access permissions are managed; Authentication and authorization'
    }
    'ConditionalAccess_Missing' = @{
        Functions = @('PR.AC-3', 'PR.AC-4', 'PR.AC-6')
        Description = 'Remote access is managed; Access permissions are managed; Identity is proofed and bound'
    }
    'LegacyAuth_Enabled' = @{
        Functions = @('PR.AC-7', 'DE.CM-7')
        Description = 'Authentication and authorization; Monitoring for unauthorized activity'
    }
    'AdminRoles_Excessive' = @{
        Functions = @('PR.AC-4', 'PR.AC-1')
        Description = 'Access permissions and authorizations are managed and enforced'
    }
    'GlobalAdmin_Multiple' = @{
        Functions = @('PR.AC-4', 'PR.AC-1')
        Description = 'Access permissions are managed, incorporating principles of least privilege'
    }
    'GuestAccess_Unrestricted' = @{
        Functions = @('PR.AC-3', 'PR.AC-4', 'ID.AM-5')
        Description = 'Remote access managed; Access permissions managed; Resources prioritized'
    }
    'AppPermissions_Excessive' = @{
        Functions = @('PR.AC-4', 'ID.AM-2')
        Description = 'Access permissions and authorizations are managed; Software platforms identified'
    }
    'AppConsent_UserAllowed' = @{
        Functions = @('PR.AC-4', 'PR.PT-3')
        Description = 'Access permissions managed; Principle of least functionality'
    }
    'DLP_NotConfigured' = @{
        Functions = @('PR.DS-5', 'DE.CM-7')
        Description = 'Protections against data leaks; Monitoring for unauthorized activity'
    }
    'AuditLog_NotEnabled' = @{
        Functions = @('DE.AE-3', 'DE.CM-1', 'PR.PT-1')
        Description = 'Event data aggregated and correlated; Network monitored; Audit/log records determined'
    }
    'MailboxAudit_Disabled' = @{
        Functions = @('DE.AE-3', 'DE.CM-1')
        Description = 'Event data aggregated; Network and environment monitored'
    }
    'SecurityDefaults_Disabled' = @{
        Functions = @('PR.AC-1', 'PR.AC-7', 'PR.IP-1')
        Description = 'Identity management; Authentication; Baseline configuration established'
    }
    'RiskySignIn_NoPolicy' = @{
        Functions = @('DE.CM-7', 'RS.AN-1', 'PR.AC-7')
        Description = 'Monitoring for unauthorized activity; Notifications analyzed; Authentication'
    }
    'PasswordExpiry_Disabled' = @{
        Functions = @('PR.AC-1')
        Description = 'Identities and credentials are issued, managed, verified, revoked'
    }
    'SelfServicePasswordReset_Disabled' = @{
        Functions = @('PR.AC-1')
        Description = 'Identities and credentials are managed for authorized users'
    }
}

# SOC 2 Trust Services Criteria mappings (AICPA TSC 2017, revised 2022)
# Expanded in EntraChecks v1.5+ to cover CC1-CC9, A, C, PI, P as part of
# the SOC 2 internal readiness feature. See docs/SOC2-Guide.md.
$Script:SOC2Mapping = @{
    # --- Common Criteria CC6 Logical & Physical Access ---
    'MFA_Disabled' = @{
        Criteria = @('CC6.1', 'CC6.2')
        Description = 'Logical and physical access controls; prior to issuing credentials, registration and authorization completed'
    }
    'MFA_AdminDisabled' = @{
        Criteria = @('CC6.1', 'CC6.2', 'CC6.3')
        Description = 'Access controls; credential management; privileged access management'
    }
    'ConditionalAccess_Missing' = @{
        Criteria = @('CC6.1', 'CC6.6', 'CC7.1', 'CC7.5')
        Description = 'Logical access controls; boundary protection; security configuration baseline; recovery from incidents via exclusion policies'
    }
    'LegacyAuth_Enabled' = @{
        Criteria = @('CC6.1', 'CC6.6', 'CC7.2')
        Description = 'Access controls; boundary protection; system monitoring'
    }
    'AdminRoles_Excessive' = @{
        Criteria = @('CC6.1', 'CC6.3')
        Description = 'Access controls restricted to authorized users; privileged access management'
    }
    'GlobalAdmin_Multiple' = @{
        Criteria = @('CC6.3')
        Description = 'Users with administrative privileges are restricted and managed'
    }
    'GuestAccess_Unrestricted' = @{
        Criteria = @('CC6.1', 'CC6.2', 'CC6.6', 'CC9.2')
        Description = 'Access controls; credential issuance; boundary protection; vendor risk'
    }
    'AppPermissions_Excessive' = @{
        Criteria = @('CC6.1', 'CC6.3')
        Description = 'Logical access controls; system authorizations appropriate for user roles'
    }
    'AppConsent_UserAllowed' = @{
        Criteria = @('CC6.1', 'CC6.3', 'CC8.1')
        Description = 'Access controls; authorization management; change authorization for new applications'
    }
    'SecurityDefaults_Disabled' = @{
        Criteria = @('CC6.1', 'CC7.1')
        Description = 'Access controls; security baseline configuration'
    }
    'PasswordExpiry_Disabled' = @{
        Criteria = @('CC6.1', 'CC6.2')
        Description = 'Access controls; credential management'
    }
    'SelfServicePasswordReset_Disabled' = @{
        Criteria = @('CC6.1', 'CC6.2')
        Description = 'Access controls; credential management and recovery'
    }
    'AuthorizationPolicy_Permissive' = @{
        Criteria = @('CC6.2', 'CC8.1')
        Description = 'Credential issuance authorization; change authorization'
    }
    'PrivilegedRoleCreep' = @{
        Criteria = @('CC6.3')
        Description = 'Privileged access management; role-based access reviewed'
    }
    'PIM_NotConfigured' = @{
        Criteria = @('CC6.3')
        Description = 'Privileged access management via just-in-time activation'
    }
    'NamedLocation_Missing' = @{
        Criteria = @('CC6.6')
        Description = 'Boundary protection; named locations enforce network context for access'
    }
    'CrossTenant_Permissive' = @{
        Criteria = @('CC6.6', 'CC9.2')
        Description = 'Boundary protection for external tenant relationships; vendor/partner risk'
    }

    # --- Device & Endpoint (CC6.4) ---
    'DeviceCompliance_NonCompliant' = @{
        Criteria = @('CC6.4')
        Description = 'Managed device compliance policies enforce baseline protections'
    }
    'BitLocker_NotEnforced' = @{
        Criteria = @('CC6.4', 'CC6.7')
        Description = 'Device encryption protects data at rest on endpoints'
    }
    'StaleDevices_Present' = @{
        Criteria = @('CC6.4')
        Description = 'Stale managed devices represent access-control hygiene gaps'
    }

    # --- DLP / Encryption (CC6.7) ---
    'DLP_NotConfigured' = @{
        Criteria = @('CC6.1', 'CC6.7', 'C1.1')
        Description = 'Data classification and protection; access to sensitive data restricted; confidentiality'
    }
    'SOC2_EncryptionPostureGaps' = @{
        Criteria = @('CC6.7')
        Description = 'Encryption-in-transit and encryption-at-rest posture across tenant assets'
    }
    'SensitivityLabels_Missing' = @{
        Criteria = @('CC6.7', 'C1.1')
        Description = 'Sensitivity labels classify confidential information'
    }
    'RetentionPolicies_Missing' = @{
        Criteria = @('C1.2')
        Description = 'Retention/disposal of confidential information'
    }

    # --- Malware (CC6.8) ---
    'SOC2_MalwareProtectionGaps' = @{
        Criteria = @('CC6.8')
        Description = 'Controls to prevent or detect unauthorized or malicious software'
    }

    # --- System Operations (CC7) ---
    'AuditLog_NotEnabled' = @{
        Criteria = @('CC4.1', 'CC7.2', 'CC7.3')
        Description = 'Monitoring coverage; system monitoring; security event evaluation'
    }
    'AuditLog_RetentionShort' = @{
        Criteria = @('CC4.1', 'CC7.2')
        Description = 'Sufficient log retention for detection and investigation'
    }
    'MailboxAudit_Disabled' = @{
        Criteria = @('CC7.2', 'CC7.3')
        Description = 'Audit logging for security-relevant events'
    }
    'RiskySignIn_NoPolicy' = @{
        Criteria = @('CC7.2', 'CC7.3')
        Description = 'System monitoring; evaluation of security events'
    }
    'UserRisk_NoPolicy' = @{
        Criteria = @('CC7.3')
        Description = 'Identity Protection user-risk response policies'
    }
    'SOC2_IncidentResponseGap' = @{
        Criteria = @('CC7.4')
        Description = 'Incident response program readiness (contacts, PIM, runbooks)'
    }
    'SOC2_BreakGlassMissing' = @{
        Criteria = @('CC7.5')
        Description = 'Break-glass accounts and recovery access paths'
    }

    # --- Change Management (CC8) ---
    'AppRoleAssignment_Overprivileged' = @{
        Criteria = @('CC8.1')
        Description = 'Change authorization; least-privilege for application role assignments'
    }
    'ApplicationCredential_Expired' = @{
        Criteria = @('CC8.1')
        Description = 'Change management: service principal credential rotation hygiene'
    }
    'AzurePolicy_Noncompliant' = @{
        Criteria = @('CC8.1')
        Description = 'Change management: Azure Policy drift from approved baseline'
    }

    # --- SOC 2 synthetic checks (CC2 / CC4 / CC7) ---
    'SOC2_AdminContactsMissing' = @{
        Criteria = @('CC2.1', 'CC2.3')
        Description = 'Tenant notification contacts enable external communication of security matters'
    }
    'SOC2_AdminContactsConfigured' = @{
        Criteria = @('CC2.1', 'CC2.3')
        Description = 'Tenant notification contacts enable external communication of security matters'
    }
    'SOC2_SecurityContactsMissing' = @{
        Criteria = @('CC2.1', 'CC2.3', 'CC7.4')
        Description = 'Security/compliance notification contacts; incident response readiness'
    }
    'SOC2_SecurityContactsConfigured' = @{
        Criteria = @('CC2.1', 'CC2.3', 'CC7.4')
        Description = 'Security/compliance notification contacts; incident response readiness'
    }
    'SOC2_SecurityAlertingPresent' = @{
        Criteria = @('CC4.2', 'CC7.4')
        Description = 'Security alerting infrastructure presence'
    }
    'SOC2_SecurityAlertingUnconfigured' = @{
        Criteria = @('CC4.2', 'CC7.4')
        Description = 'Security alerting infrastructure coverage'
    }

    # --- Availability (Phase 2 synthetic checks; mapping ready) ---
    'SOC2_ServiceHealthGap' = @{
        Criteria = @('A1.1')
        Description = 'Capacity/performance monitoring for availability'
    }
    'SOC2_BackupConfigurationGap' = @{
        Criteria = @('A1.2')
        Description = 'Backup / environmental protection for availability'
    }
}

# PCI-DSS v4.0.1 mappings
$Script:PCIDSS4Mapping = @{
    'MFA_Disabled' = @{
        Requirements = @('8.4.2', '8.5.1')
        Description = 'MFA implemented for access; Authentication factors validated'
    }
    'MFA_AdminDisabled' = @{
        Requirements = @('8.4.2', '8.4.3', '7.2.2')
        Description = 'MFA for all access; MFA for administrative access; Privileged access management'
    }
    'ConditionalAccess_Missing' = @{
        Requirements = @('8.2.1', '8.3.1')
        Description = 'User identity verified; Authentication factors unique; Risk-based controls'
    }
    'LegacyAuth_Enabled' = @{
        Requirements = @('8.4.2', '8.3.8')
        Description = 'Strong authentication required; Security policies enforced'
    }
    'AdminRoles_Excessive' = @{
        Requirements = @('7.2.2', '7.2.3')
        Description = 'Privileged access assigned based on job function; Access limited to least privilege'
    }
    'GlobalAdmin_Multiple' = @{
        Requirements = @('7.2.2', '7.2.4')
        Description = 'Privileged access managed; Access reviewed regularly'
    }
    'GuestAccess_Unrestricted' = @{
        Requirements = @('7.2.1', '7.2.4', '8.2.2')
        Description = 'Access control system configured; Access reviewed; User accounts managed'
    }
    'AppPermissions_Excessive' = @{
        Requirements = @('7.2.2', '7.2.5')
        Description = 'Access privileges assigned; Application and system accounts managed'
    }
    'AppConsent_UserAllowed' = @{
        Requirements = @('7.2.2', '6.4.2')
        Description = 'Access privileges validated; Applications meet security requirements'
    }
    'DLP_NotConfigured' = @{
        Requirements = @('3.5.1', '4.2.1')
        Description = 'Primary Account Number rendered unreadable; Strong cryptography and security protocols'
    }
    'AuditLog_NotEnabled' = @{
        Requirements = @('10.2.1', '10.2.2', '10.3.1')
        Description = 'Audit logs implemented; Audit trail for all access; Audit log entries recorded'
    }
    'MailboxAudit_Disabled' = @{
        Requirements = @('10.2.1', '10.2.2')
        Description = 'Audit logs capture all access; User activities logged'
    }
    'SecurityDefaults_Disabled' = @{
        Requirements = @('8.4.2', '2.2.1')
        Description = 'Multi-factor authentication; Security configuration standards'
    }
    'RiskySignIn_NoPolicy' = @{
        Requirements = @('10.4.1', '11.5.1')
        Description = 'Audit logs reviewed; Security monitoring implemented'
    }
    'PasswordExpiry_Disabled' = @{
        Requirements = @('8.3.6', '8.3.9')
        Description = 'Password parameters configured; Passwords changed upon suspicion of compromise'
    }
    'SelfServicePasswordReset_Disabled' = @{
        Requirements = @('8.6.1', '8.6.2')
        Description = 'Password reset process secure; Identity verified before password reset'
    }
}

#endregion

#region Public Functions

function Get-ComplianceMapping {
    <#
    .SYNOPSIS
        Retrieves compliance framework mappings for a finding type.

    .DESCRIPTION
        Returns compliance control mappings across all configured frameworks for a specific finding type.

    .PARAMETER FindingType
        The type of finding to retrieve mappings for (e.g., 'MFA_Disabled')

    .PARAMETER Framework
        Optional. Specific framework to retrieve mappings for (CIS, NIST, SOC2, PCIDSS)

    .EXAMPLE
        Get-ComplianceMapping -FindingType "MFA_Disabled"
        Returns all framework mappings for MFA_Disabled finding

    .EXAMPLE
        Get-ComplianceMapping -FindingType "MFA_Disabled" -Framework "CIS"
        Returns only CIS framework mapping
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FindingType,

        [ValidateSet('CIS', 'NIST', 'SOC2', 'PCIDSS', 'All')]
        [string]$Framework = 'All'
    )

    $mappings = @{}

    if ($Framework -eq 'All' -or $Framework -eq 'CIS') {
        if ($Script:CISMicrosoft365Mapping.ContainsKey($FindingType)) {
            $mappings['CIS_M365'] = $Script:CISMicrosoft365Mapping[$FindingType]
        }
    }

    if ($Framework -eq 'All' -or $Framework -eq 'NIST') {
        if ($Script:NISTCSFMapping.ContainsKey($FindingType)) {
            $mappings['NIST_CSF'] = $Script:NISTCSFMapping[$FindingType]
        }
    }

    if ($Framework -eq 'All' -or $Framework -eq 'SOC2') {
        if ($Script:SOC2Mapping.ContainsKey($FindingType)) {
            $mappings['SOC2'] = $Script:SOC2Mapping[$FindingType]
        }
    }

    if ($Framework -eq 'All' -or $Framework -eq 'PCIDSS') {
        if ($Script:PCIDSS4Mapping.ContainsKey($FindingType)) {
            $mappings['PCI_DSS_4'] = $Script:PCIDSS4Mapping[$FindingType]
        }
    }

    return $mappings
}

function Get-AllComplianceMappings {
    <#
    .SYNOPSIS
        Retrieves all compliance framework mappings.

    .DESCRIPTION
        Returns the complete compliance mapping data structure for all frameworks.

    .PARAMETER Framework
        Optional. Specific framework to retrieve (CIS, NIST, SOC2, PCIDSS)

    .EXAMPLE
        Get-AllComplianceMappings
        Returns all framework mappings
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [ValidateSet('CIS', 'NIST', 'SOC2', 'PCIDSS', 'All')]
        [string]$Framework = 'All'
    )

    $allMappings = @{}

    if ($Framework -eq 'All' -or $Framework -eq 'CIS') {
        $allMappings['CIS_M365'] = $Script:CISMicrosoft365Mapping
    }

    if ($Framework -eq 'All' -or $Framework -eq 'NIST') {
        $allMappings['NIST_CSF'] = $Script:NISTCSFMapping
    }

    if ($Framework -eq 'All' -or $Framework -eq 'SOC2') {
        $allMappings['SOC2'] = $Script:SOC2Mapping
    }

    if ($Framework -eq 'All' -or $Framework -eq 'PCIDSS') {
        $allMappings['PCI_DSS_4'] = $Script:PCIDSS4Mapping
    }

    return $allMappings
}

function Get-FindingsForControl {
    <#
    .SYNOPSIS
        Retrieves finding types that map to a specific control.

    .DESCRIPTION
        Returns all finding types that relate to a specific framework control.
        Useful for generating compliance reports organized by control.

    .PARAMETER Framework
        The framework to search (CIS, NIST, SOC2, PCIDSS)

    .PARAMETER ControlId
        The control identifier (e.g., '1.1.3' for CIS, 'PR.AC-1' for NIST)

    .EXAMPLE
        Get-FindingsForControl -Framework "CIS" -ControlId "1.1.3"
        Returns all findings that map to CIS control 1.1.3
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('CIS', 'NIST', 'SOC2', 'PCIDSS')]
        [string]$Framework,

        [Parameter(Mandatory)]
        [string]$ControlId
    )

    $findings = @()
    $mappingTable = $null
    $controlKey = $null

    switch ($Framework) {
        'CIS' {
            $mappingTable = $Script:CISMicrosoft365Mapping
            $controlKey = 'Controls'
        }
        'NIST' {
            $mappingTable = $Script:NISTCSFMapping
            $controlKey = 'Functions'
        }
        'SOC2' {
            $mappingTable = $Script:SOC2Mapping
            $controlKey = 'Criteria'
        }
        'PCIDSS' {
            $mappingTable = $Script:PCIDSS4Mapping
            $controlKey = 'Requirements'
        }
    }

    foreach ($findingType in $mappingTable.Keys) {
        $controls = $mappingTable[$findingType][$controlKey]
        if ($controls -contains $ControlId) {
            $findings += @{
                FindingType = $findingType
                Mapping = $mappingTable[$findingType]
            }
        }
    }

    return $findings
}

function Format-ComplianceReference {
    <#
    .SYNOPSIS
        Formats compliance mappings for display in reports.

    .DESCRIPTION
        Converts compliance mapping data into formatted strings for HTML/CSV reports.

    .PARAMETER FindingType
        The type of finding to format mappings for

    .PARAMETER Format
        Output format: 'Short' (control IDs only), 'Long' (with descriptions), 'HTML' (with formatting)

    .EXAMPLE
        Format-ComplianceReference -FindingType "MFA_Disabled" -Format "Short"
        Returns: "CIS M365: 1.1.3, 1.3.1 | NIST CSF: PR.AC-1, PR.AC-7 | SOC2: CC6.1, CC6.2 | PCI-DSS: 8.4.2, 8.5.1"
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FindingType,

        [ValidateSet('Short', 'Long', 'HTML')]
        [string]$Format = 'Short'
    )

    $mappings = Get-ComplianceMapping -FindingType $FindingType

    if ($mappings.Count -eq 0) {
        return "No compliance mappings available"
    }

    $output = @()

    foreach ($framework in $mappings.Keys) {
        $data = $mappings[$framework]

        switch ($Format) {
            'Short' {
                $controls = switch ($framework) {
                    'CIS_M365' { $data.Controls -join ', ' }
                    'NIST_CSF' { $data.Functions -join ', ' }
                    'SOC2' { $data.Criteria -join ', ' }
                    'PCI_DSS_4' { $data.Requirements -join ', ' }
                }
                $frameworkName = $framework -replace '_', ' '
                $output += "${frameworkName}: $controls"
            }
            'Long' {
                $controls = switch ($framework) {
                    'CIS_M365' { $data.Controls -join ', ' }
                    'NIST_CSF' { $data.Functions -join ', ' }
                    'SOC2' { $data.Criteria -join ', ' }
                    'PCI_DSS_4' { $data.Requirements -join ', ' }
                }
                $frameworkName = $framework -replace '_', ' '
                $output += "$frameworkName [$controls]: $($data.Description)"
            }
            'HTML' {
                $controls = switch ($framework) {
                    'CIS_M365' { $data.Controls -join ', ' }
                    'NIST_CSF' { $data.Functions -join ', ' }
                    'SOC2' { $data.Criteria -join ', ' }
                    'PCI_DSS_4' { $data.Requirements -join ', ' }
                }
                $frameworkName = $framework -replace '_', ' '
                $output += "<strong>$frameworkName</strong> [$controls]: $($data.Description)"
            }
        }
    }

    $separator = if ($Format -eq 'HTML') { '<br>' } else { ' | ' }
    return ($output -join $separator)
}

function Add-ComplianceMapping {
    <#
    .SYNOPSIS
        Adds compliance mapping information to a findings object.

    .DESCRIPTION
        Enhances a findings object with compliance framework references.

    .PARAMETER Finding
        The finding object to enhance

    .EXAMPLE
        $finding | Add-ComplianceMapping
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Finding
    )

    process {
        # Determine finding type from various possible properties
        $findingType = $null
        if ($Finding.Type) { $findingType = $Finding.Type }
        elseif ($Finding.CheckType) { $findingType = $Finding.CheckType }
        elseif ($Finding.Category) { $findingType = $Finding.Category }

        if ($findingType) {
            $mappings = Get-ComplianceMapping -FindingType $findingType

            if ($mappings.Count -gt 0) {
                $Finding | Add-Member -NotePropertyName 'ComplianceMappings' -NotePropertyValue $mappings -Force
                $Finding | Add-Member -NotePropertyName 'ComplianceReference' -NotePropertyValue (Format-ComplianceReference -FindingType $findingType -Format 'Short') -Force
            }
        }

        return $Finding
    }
}

function Get-ComplianceGapReport {
    <#
    .SYNOPSIS
        Generates a compliance gap analysis report.

    .DESCRIPTION
        Analyzes findings to show which controls are failing and compliance gaps.

    .PARAMETER Findings
        Array of finding objects to analyze

    .PARAMETER Framework
        Framework to analyze against (CIS, NIST, SOC2, PCIDSS, All)

    .EXAMPLE
        Get-ComplianceGapReport -Findings $allFindings -Framework "CIS"
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [ValidateSet('CIS', 'NIST', 'SOC2', 'PCIDSS', 'All')]
        [string]$Framework = 'All'
    )

    $gapReport = @{
        TotalFindings = $Findings.Count
        FailedFindings = @($Findings | Where-Object { $_.Status -eq 'FAIL' -or $_.Status -eq 'WARNING' }).Count
        FrameworkGaps = @{}
    }

    # Analyze by framework
    $frameworks = if ($Framework -eq 'All') { @('CIS', 'NIST', 'SOC2', 'PCIDSS') } else { @($Framework) }

    foreach ($fw in $frameworks) {
        $controlsAffected = @{}

        foreach ($finding in $Findings) {
            if ($finding.Status -eq 'FAIL' -or $finding.Status -eq 'WARNING') {
                $findingType = if ($null -ne $finding.Type) { $finding.Type } elseif ($null -ne $finding.CheckType) { $finding.CheckType } else { $finding.Category }
                if ($findingType) {
                    $mapping = Get-ComplianceMapping -FindingType $findingType -Framework $fw

                    if ($mapping.Count -gt 0) {
                        $controlKey = switch ($fw) {
                            'CIS' { 'Controls' }
                            'NIST' { 'Functions' }
                            'SOC2' { 'Criteria' }
                            'PCIDSS' { 'Requirements' }
                        }

                        $frameworkKey = switch ($fw) {
                            'CIS' { 'CIS_M365' }
                            'NIST' { 'NIST_CSF' }
                            'SOC2' { 'SOC2' }
                            'PCIDSS' { 'PCI_DSS_4' }
                        }

                        if ($mapping[$frameworkKey]) {
                            $controls = $mapping[$frameworkKey][$controlKey]
                            foreach ($control in $controls) {
                                if (-not $controlsAffected.ContainsKey($control)) {
                                    $controlsAffected[$control] = @()
                                }
                                $controlsAffected[$control] += $finding
                            }
                        }
                    }
                }
            }
        }

        $gapReport.FrameworkGaps[$fw] = @{
            ControlsAffected = $controlsAffected.Count
            Controls = $controlsAffected
        }
    }

    return $gapReport
}

#endregion

#region Export Module Members

Export-ModuleMember -Function @(
    'Get-ComplianceMapping',
    'Get-AllComplianceMappings',
    'Get-FindingsForControl',
    'Format-ComplianceReference',
    'Add-ComplianceMapping',
    'Get-ComplianceGapReport'
)

#endregion
