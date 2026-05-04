<#
.SYNOPSIS
    EntraChecks-Compliance.psm1
    Optional module for compliance framework mapping and reporting

.DESCRIPTION
    This module maps security findings from Invoke-EntraChecks.ps1 and its modules
    to compliance frameworks (CIS Microsoft 365, NIST 800-53) and generates
    compliance-focused reports.
    
    Features:
    - Map findings to CIS Microsoft 365 Foundations Benchmark v3.0
    - Map findings to NIST 800-53 Rev 5 controls
    - Calculate compliance scores
    - Identify compliance gaps
    - Export HTML and CSV compliance reports
    
.NOTES
    Version: 1.0.0
    Author: David Stells
    Requires: Findings from Invoke-EntraChecks.ps1 or modules
    
    No additional licenses required - uses existing findings.
    
.LINK
    Main Script: Invoke-EntraChecks.ps1
    CIS Benchmark: https://www.cisecurity.org/benchmark/microsoft_365
    NIST 800-53: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
#>

#Requires -Version 5.1

# Import dependent modules
$script:ComplianceModulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $script:ComplianceModulePath "EntraChecks-DataSources.psm1") -Force -DisableNameChecking
Import-Module (Join-Path $script:ComplianceModulePath "EntraChecks-RemediationGuidance.psm1") -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $script:ComplianceModulePath "EntraChecks-PrivilegedIdentityRender.psm1") -Force -DisableNameChecking -ErrorAction SilentlyContinue

# Module version
$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-Compliance"

#region ==================== FRAMEWORK DEFINITIONS ====================

# CIS Microsoft 365 Foundations Benchmark v3.0 - Entra ID Controls
$script:CISControls = @(
    # 1.1 - Identity and Access Management
    @{
        ControlId = "1.1.1"
        Title = "Ensure Administrative accounts are separate and cloud-only"
        Section = "Identity and Access Management"
        Description = "Administrative accounts should be cloud-only to prevent on-premises compromise from affecting cloud administration."
        MappedChecks = @("Check-DirectoryRolesAndMembers", "Check-PrivilegedRoleCreep")
        Severity = "High"
        DefaultRemediation = "Create dedicated cloud-only admin accounts. Do not sync admin accounts from on-premises AD."
    },
    @{
        ControlId = "1.1.3"
        Title = "Ensure that between two and four global admins are designated"
        Section = "Identity and Access Management"
        Description = "Having 2-4 global admins ensures redundancy while limiting risk exposure."
        MappedChecks = @("Check-DirectoryRolesAndMembers")
        Severity = "High"
        DefaultRemediation = "Maintain 2-4 Global Administrators. Use less privileged roles where possible."
    },
    @{
        ControlId = "1.1.4"
        Title = "Ensure multifactor authentication is enabled for all users in administrative roles"
        Section = "Identity and Access Management"
        Description = "MFA for admins prevents unauthorized access even if credentials are compromised."
        MappedChecks = @("Check-PrivilegedUserMFACoverage", "Check-ConditionalAccessPolicies")
        Severity = "Critical"
        DefaultRemediation = "Enable MFA for all administrative accounts via Conditional Access or Security Defaults."
    },
    @{
        ControlId = "1.1.5"
        Title = "Ensure multifactor authentication is enabled for all users"
        Section = "Identity and Access Management"
        Description = "MFA significantly reduces the risk of account compromise for all users."
        MappedChecks = @("Check-ConditionalAccessPolicies", "Check-AuthenticationMethodsPolicy")
        Severity = "High"
        DefaultRemediation = "Create a Conditional Access policy requiring MFA for all users accessing cloud apps."
    },
    @{
        ControlId = "1.1.6"
        Title = "Ensure Privileged Identity Management is used to manage roles"
        Section = "Identity and Access Management"
        Description = "PIM provides just-in-time privileged access to reduce standing permissions."
        MappedChecks = @("Check-PIMConfiguration", "Check-PrivilegedRoleCreep")
        Severity = "High"
        DefaultRemediation = "Enable Azure AD PIM and convert permanent role assignments to eligible assignments."
    },
    @{
        ControlId = "1.1.7"
        Title = "Ensure that password hash sync is enabled for hybrid deployments"
        Section = "Identity and Access Management"
        Description = "Password hash sync enables leaked credential detection and provides authentication backup."
        MappedChecks = @("Check-DirectorySyncStatus", "Check-PasswordHashSync")
        Severity = "Medium"
        DefaultRemediation = "Enable Password Hash Synchronization in Azure AD Connect."
    },
    
    # 1.2 - Conditional Access
    @{
        ControlId = "1.2.1"
        Title = "Ensure Security Defaults is disabled when using Conditional Access"
        Section = "Conditional Access"
        Description = "Security Defaults should be disabled when custom Conditional Access policies are in use."
        MappedChecks = @("Check-ConditionalAccessPolicies")
        Severity = "Medium"
        DefaultRemediation = "Disable Security Defaults and implement comprehensive Conditional Access policies."
    },
    @{
        ControlId = "1.2.2"
        Title = "Ensure that an emergency access admin account is excluded from Conditional Access policies"
        Section = "Conditional Access"
        Description = "Break-glass accounts must be excluded from CA policies to ensure emergency access."
        MappedChecks = @("Check-ConditionalAccessPolicies", "Check-DirectoryRolesAndMembers")
        Severity = "High"
        DefaultRemediation = "Create break-glass accounts and exclude them from all Conditional Access policies."
    },
    @{
        ControlId = "1.2.3"
        Title = "Ensure legacy authentication is blocked"
        Section = "Conditional Access"
        Description = "Legacy authentication protocols cannot enforce MFA and should be blocked."
        MappedChecks = @("Check-ConditionalAccessPolicies")
        Severity = "High"
        DefaultRemediation = "Create a Conditional Access policy to block legacy authentication for all users."
    },
    @{
        ControlId = "1.2.4"
        Title = "Ensure sign-in frequency is enabled and browser sessions are not persistent for administrative users"
        Section = "Conditional Access"
        Description = "Limiting session duration reduces the window of opportunity for session hijacking."
        MappedChecks = @("Check-ConditionalAccessPolicies")
        Severity = "Medium"
        DefaultRemediation = "Configure Conditional Access session controls to limit sign-in frequency for admins."
    },
    
    # 1.3 - Password Management
    @{
        ControlId = "1.3.1"
        Title = "Ensure password protection is enabled for on-premises Active Directory"
        Section = "Password Management"
        Description = "Azure AD Password Protection blocks weak passwords in on-premises AD."
        MappedChecks = @("Check-PasswordProtectionSettings")
        Severity = "Medium"
        DefaultRemediation = "Deploy Azure AD Password Protection agents to domain controllers."
    },
    @{
        ControlId = "1.3.2"
        Title = "Ensure the self-service password reset activity report is reviewed at least weekly"
        Section = "Password Management"
        Description = "Regular review of SSPR activity helps identify potential account compromise."
        MappedChecks = @("Check-AuditLogRetention", "Check-SelfServicePasswordReset")
        Severity = "Low"
        DefaultRemediation = "Enable SSPR reporting and review activity weekly."
    },
    @{
        ControlId = "1.3.3"
        Title = "Ensure password hash sync is enabled for resiliency"
        Section = "Password Management"
        Description = "Password hash sync provides authentication backup if federation fails."
        MappedChecks = @("Check-PasswordHashSync")
        Severity = "Medium"
        DefaultRemediation = "Enable Password Hash Synchronization in Azure AD Connect."
    },
    
    # 2.1 - Identity Protection
    @{
        ControlId = "2.1.1"
        Title = "Ensure user risk policy is configured and enabled"
        Section = "Identity Protection"
        Description = "User risk policies automatically respond to compromised user accounts."
        MappedChecks = @("Check-UserRiskPolicy")
        Severity = "High"
        DefaultRemediation = "Configure a user risk policy requiring password change for high/medium risk users."
    },
    @{
        ControlId = "2.1.2"
        Title = "Ensure sign-in risk policy is configured and enabled"
        Section = "Identity Protection"
        Description = "Sign-in risk policies block or challenge risky authentication attempts."
        MappedChecks = @("Check-SignInRiskPolicy")
        Severity = "High"
        DefaultRemediation = "Configure a sign-in risk policy requiring MFA for high/medium risk sign-ins."
    },
    @{
        ControlId = "2.1.3"
        Title = "Ensure risky users are remediated within 24 hours"
        Section = "Identity Protection"
        Description = "Prompt remediation of risky users prevents ongoing unauthorized access."
        MappedChecks = @("Check-RiskyUsers")
        Severity = "High"
        DefaultRemediation = "Establish a process to review and remediate risky users within 24 hours."
    },
    
    # 5.1 - Logging and Auditing
    @{
        ControlId = "5.1.1"
        Title = "Ensure Microsoft 365 audit log search is enabled"
        Section = "Logging"
        Description = "Audit logging must be enabled to track security events."
        MappedChecks = @("Check-AuditLogRetention")
        Severity = "High"
        DefaultRemediation = "Enable unified audit logging in the Microsoft 365 compliance center."
    },
    @{
        ControlId = "5.1.2"
        Title = "Ensure audit log retention policies are configured"
        Section = "Logging"
        Description = "Adequate log retention enables forensic investigation of security incidents."
        MappedChecks = @("Check-AuditLogRetention")
        Severity = "Medium"
        DefaultRemediation = "Configure audit log retention for at least 90 days (1 year recommended)."
    },
    
    # Device-related controls
    @{
        ControlId = "1.4.1"
        Title = "Ensure device registration requires MFA"
        Section = "Device Management"
        Description = "Requiring MFA for device registration prevents unauthorized device enrollment."
        MappedChecks = @("Check-DeviceRegistrationPolicy")
        Severity = "Medium"
        DefaultRemediation = "Enable MFA requirement for device join in Azure AD Device Settings."
    },
    @{
        ControlId = "1.4.2"
        Title = "Ensure Conditional Access policies require compliant devices"
        Section = "Device Management"
        Description = "Requiring device compliance ensures only secure devices access resources."
        MappedChecks = @("Check-ConditionalAccessDeviceControls")
        Severity = "High"
        DefaultRemediation = "Create Conditional Access policy requiring compliant or hybrid joined device."
    }
)

# NIST 800-53 Rev 5 Controls mapped to Entra ID checks
$script:NISTControls = @(
    # AC - Access Control
    @{
        ControlId = "AC-2"
        Title = "Account Management"
        Family = "Access Control"
        Description = "Manage system accounts including creating, enabling, modifying, disabling, and removing accounts."
        MappedChecks = @("Check-UserAccountsAndInactivity", "Check-GuestAccounts", "Check-DirectoryRolesAndMembers")
        Severity = "High"
        DefaultRemediation = "Implement account lifecycle management processes. Review inactive accounts regularly."
    },
    @{
        ControlId = "AC-2(1)"
        Title = "Account Management | Automated System Account Management"
        Family = "Access Control"
        Description = "Employ automated mechanisms to support management of system accounts."
        MappedChecks = @("Check-UserAccountsAndInactivity", "Check-PIMConfiguration")
        Severity = "Medium"
        DefaultRemediation = "Implement automated account provisioning and access reviews."
    },
    @{
        ControlId = "AC-2(3)"
        Title = "Account Management | Disable Accounts"
        Family = "Access Control"
        Description = "Disable accounts when no longer required or after defined period of inactivity."
        MappedChecks = @("Check-UserAccountsAndInactivity", "Check-StaleDevices")
        Severity = "Medium"
        DefaultRemediation = "Disable accounts after 90 days of inactivity. Delete after 180 days."
    },
    @{
        ControlId = "AC-2(4)"
        Title = "Account Management | Automated Audit Actions"
        Family = "Access Control"
        Description = "Automatically audit account creation, modification, enabling, disabling, and removal."
        MappedChecks = @("Check-AuditLogRetention")
        Severity = "Medium"
        DefaultRemediation = "Ensure Azure AD audit logs are enabled and retained appropriately."
    },
    @{
        ControlId = "AC-2(7)"
        Title = "Account Management | Privileged User Accounts"
        Family = "Access Control"
        Description = "Establish and administer privileged user accounts in accordance with role-based access."
        MappedChecks = @("Check-DirectoryRolesAndMembers", "Check-PrivilegedRoleCreep", "Check-PIMConfiguration")
        Severity = "High"
        DefaultRemediation = "Implement PIM for just-in-time privileged access. Review role assignments regularly."
    },
    @{
        ControlId = "AC-3"
        Title = "Access Enforcement"
        Family = "Access Control"
        Description = "Enforce approved authorizations for logical access to information and system resources."
        MappedChecks = @("Check-ConditionalAccessPolicies", "Check-AuthorizationPolicy")
        Severity = "High"
        DefaultRemediation = "Implement Conditional Access policies to enforce access controls."
    },
    @{
        ControlId = "AC-6"
        Title = "Least Privilege"
        Family = "Access Control"
        Description = "Employ the principle of least privilege, allowing only authorized accesses."
        MappedChecks = @("Check-PrivilegedRoleCreep", "Check-DirectoryRolesAndMembers", "Check-AppPermissionsAnalysis")
        Severity = "High"
        DefaultRemediation = "Review and minimize privileged role assignments. Use PIM for just-in-time access."
    },
    @{
        ControlId = "AC-6(1)"
        Title = "Least Privilege | Authorize Access to Security Functions"
        Family = "Access Control"
        Description = "Authorize access for users and processes acting on behalf of users to security functions."
        MappedChecks = @("Check-DirectoryRolesAndMembers", "Check-PIMConfiguration")
        Severity = "High"
        DefaultRemediation = "Limit security function access to designated administrators only."
    },
    @{
        ControlId = "AC-6(5)"
        Title = "Least Privilege | Privileged Accounts"
        Family = "Access Control"
        Description = "Restrict privileged accounts on the system to specific personnel or roles."
        MappedChecks = @("Check-DirectoryRolesAndMembers", "Check-PrivilegedRoleCreep", "Check-PIMConfiguration")
        Severity = "High"
        DefaultRemediation = "Minimize Global Admin count. Use PIM for privileged access."
    },
    @{
        ControlId = "AC-7"
        Title = "Unsuccessful Logon Attempts"
        Family = "Access Control"
        Description = "Enforce a limit of consecutive invalid logon attempts and lock account when exceeded."
        MappedChecks = @("Check-ConditionalAccessPolicies", "Check-SignInRiskPolicy")
        Severity = "Medium"
        DefaultRemediation = "Configure smart lockout settings in Azure AD. Enable sign-in risk policies."
    },
    @{
        ControlId = "AC-11"
        Title = "Device Lock"
        Family = "Access Control"
        Description = "Prevent access to the system via device lock after period of inactivity."
        MappedChecks = @("Check-DeviceCompliancePolicies", "Check-ConditionalAccessPolicies")
        Severity = "Medium"
        DefaultRemediation = "Configure device compliance policies requiring screen lock timeout."
    },
    @{
        ControlId = "AC-17"
        Title = "Remote Access"
        Family = "Access Control"
        Description = "Establish usage restrictions and implementation guidance for remote access."
        MappedChecks = @("Check-ConditionalAccessPolicies", "Check-ConditionalAccessDeviceControls")
        Severity = "High"
        DefaultRemediation = "Implement Conditional Access policies for remote access with MFA and device requirements."
    },
    
    # AU - Audit and Accountability
    @{
        ControlId = "AU-2"
        Title = "Event Logging"
        Family = "Audit and Accountability"
        Description = "Identify event types that the system is capable of logging."
        MappedChecks = @("Check-AuditLogRetention")
        Severity = "High"
        DefaultRemediation = "Enable comprehensive audit logging in Azure AD and Microsoft 365."
    },
    @{
        ControlId = "AU-3"
        Title = "Content of Audit Records"
        Family = "Audit and Accountability"
        Description = "Ensure audit records contain required information."
        MappedChecks = @("Check-AuditLogRetention")
        Severity = "Medium"
        DefaultRemediation = "Azure AD audit logs automatically include required content fields."
    },
    @{
        ControlId = "AU-6"
        Title = "Audit Record Review, Analysis, and Reporting"
        Family = "Audit and Accountability"
        Description = "Review and analyze audit records for indications of inappropriate or unusual activity."
        MappedChecks = @("Check-RiskDetections", "Check-RiskySignIns", "Check-RiskyUsers")
        Severity = "High"
        DefaultRemediation = "Review Identity Protection reports regularly. Configure alerts for high-risk events."
    },
    @{
        ControlId = "AU-11"
        Title = "Audit Record Retention"
        Family = "Audit and Accountability"
        Description = "Retain audit records for defined period to support after-the-fact investigations."
        MappedChecks = @("Check-AuditLogRetention")
        Severity = "Medium"
        DefaultRemediation = "Configure audit log retention for at least 90 days (1 year recommended)."
    },
    
    # CM - Configuration Management
    @{
        ControlId = "CM-5"
        Title = "Access Restrictions for Change"
        Family = "Configuration Management"
        Description = "Define and enforce access restrictions for change to the system."
        MappedChecks = @("Check-DirectoryRolesAndMembers", "Check-PIMConfiguration")
        Severity = "High"
        DefaultRemediation = "Limit configuration change access to designated administrators."
    },
    @{
        ControlId = "CM-7"
        Title = "Least Functionality"
        Family = "Configuration Management"
        Description = "Configure the system to provide only mission-essential capabilities."
        MappedChecks = @("Check-AuthorizationPolicy", "Check-ConsentPolicy")
        Severity = "Medium"
        DefaultRemediation = "Disable unnecessary features. Restrict user consent for applications."
    },
    @{
        ControlId = "CM-8"
        Title = "System Component Inventory"
        Family = "Configuration Management"
        Description = "Develop and maintain an inventory of system components."
        MappedChecks = @("Check-DeviceOverview", "Check-ApplicationInventory")
        Severity = "Medium"
        DefaultRemediation = "Maintain device and application inventories in Azure AD and Intune."
    },
    
    # IA - Identification and Authentication
    @{
        ControlId = "IA-2"
        Title = "Identification and Authentication (Organizational Users)"
        Family = "Identification and Authentication"
        Description = "Uniquely identify and authenticate organizational users."
        MappedChecks = @("Check-UserAccountsAndInactivity", "Check-AuthenticationMethodsPolicy")
        Severity = "High"
        DefaultRemediation = "Ensure all users have unique identities. Implement strong authentication."
    },
    @{
        ControlId = "IA-2(1)"
        Title = "Identification and Authentication | Multi-Factor Authentication"
        Family = "Identification and Authentication"
        Description = "Implement multi-factor authentication for access to privileged accounts."
        MappedChecks = @("Check-PrivilegedUserMFACoverage", "Check-ConditionalAccessPolicies")
        Severity = "Critical"
        DefaultRemediation = "Enable MFA for all privileged accounts via Conditional Access."
    },
    @{
        ControlId = "IA-2(2)"
        Title = "Identification and Authentication | Multi-Factor Authentication for Non-Privileged Accounts"
        Family = "Identification and Authentication"
        Description = "Implement multi-factor authentication for access to non-privileged accounts."
        MappedChecks = @("Check-ConditionalAccessPolicies", "Check-AuthenticationMethodsPolicy")
        Severity = "High"
        DefaultRemediation = "Enable MFA for all users via Conditional Access."
    },
    @{
        ControlId = "IA-2(6)"
        Title = "Identification and Authentication | Access to Accounts - Separate Device"
        Family = "Identification and Authentication"
        Description = "Implement multi-factor authentication using a separate device."
        MappedChecks = @("Check-AuthenticationMethodsPolicy")
        Severity = "Medium"
        DefaultRemediation = "Require hardware tokens or authenticator apps on separate devices."
    },
    @{
        ControlId = "IA-4"
        Title = "Identifier Management"
        Family = "Identification and Authentication"
        Description = "Manage system identifiers by receiving authorization and disabling after inactivity."
        MappedChecks = @("Check-UserAccountsAndInactivity", "Check-GuestAccounts")
        Severity = "Medium"
        DefaultRemediation = "Implement identity lifecycle management. Disable inactive identities."
    },
    @{
        ControlId = "IA-5"
        Title = "Authenticator Management"
        Family = "Identification and Authentication"
        Description = "Manage system authenticators including passwords and certificates."
        MappedChecks = @("Check-AuthenticationMethodsPolicy", "Check-PasswordNeverExpires", "Check-SelfServicePasswordReset")
        Severity = "High"
        DefaultRemediation = "Configure strong authentication methods. Enable SSPR with appropriate controls."
    },
    @{
        ControlId = "IA-5(1)"
        Title = "Authenticator Management | Password-Based Authentication"
        Family = "Identification and Authentication"
        Description = "Enforce password complexity and change requirements."
        MappedChecks = @("Check-PasswordProtectionSettings", "Check-PasswordNeverExpires")
        Severity = "Medium"
        DefaultRemediation = "Enable Azure AD Password Protection. Use banned password lists."
    },
    @{
        ControlId = "IA-8"
        Title = "Identification and Authentication (Non-Organizational Users)"
        Family = "Identification and Authentication"
        Description = "Uniquely identify and authenticate non-organizational users."
        MappedChecks = @("Check-GuestAccounts", "Check-ExternalCollaborationSettings")
        Severity = "Medium"
        DefaultRemediation = "Configure B2B collaboration settings. Review guest accounts regularly."
    },
    
    # SC - System and Communications Protection
    @{
        ControlId = "SC-8"
        Title = "Transmission Confidentiality and Integrity"
        Family = "System and Communications Protection"
        Description = "Protect the confidentiality and integrity of transmitted information."
        MappedChecks = @("Check-ConditionalAccessPolicies")
        Severity = "High"
        DefaultRemediation = "Enforce TLS for all communications. Block legacy protocols."
    },
    @{
        ControlId = "SC-28"
        Title = "Protection of Information at Rest"
        Family = "System and Communications Protection"
        Description = "Protect the confidentiality and integrity of information at rest."
        MappedChecks = @("Check-BitLockerRecoveryKeys", "Check-DeviceCompliancePolicies")
        Severity = "High"
        DefaultRemediation = "Require device encryption via Intune compliance policies."
    },
    
    # SI - System and Information Integrity
    @{
        ControlId = "SI-4"
        Title = "System Monitoring"
        Family = "System and Information Integrity"
        Description = "Monitor the system to detect attacks and indicators of potential attacks."
        MappedChecks = @("Check-RiskDetections", "Check-RiskySignIns", "Check-AuditLogRetention")
        Severity = "High"
        DefaultRemediation = "Enable Identity Protection. Configure security alerts."
    }
)

#endregion

#region ==================== MODULE INITIALIZATION ====================

<#
.SYNOPSIS
    Initializes the compliance module and verifies the findings collection is available.
#>
function Initialize-ComplianceModule {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Loading module: $script:ModuleName v$script:ModuleVersion" -ForegroundColor Magenta
    
    # Verify findings collection exists
    if (-not (Get-Variable -Name "Findings" -Scope Script -ErrorAction SilentlyContinue)) {
        $script:Findings = @()
        Write-Host "    [!] No findings loaded. Run security checks first or provide findings." -ForegroundColor Yellow
    }
    else {
        Write-Host "    [i] Found $($script:Findings.Count) existing findings" -ForegroundColor Gray
    }
    
    Write-Host "    [OK] Module loaded successfully" -ForegroundColor Green
    Write-Host "    [i] CIS Controls: $($script:CISControls.Count) | NIST Controls: $($script:NISTControls.Count)" -ForegroundColor Gray
    
    return @{
        Name = $script:ModuleName
        Version = $script:ModuleVersion
        CISControlCount = $script:CISControls.Count
        NISTControlCount = $script:NISTControls.Count
        SupportedFrameworks = @("CIS-M365-v3", "NIST-800-53-r5")
    }
}

#endregion

#region ==================== COMPLIANCE MAPPING FUNCTIONS ====================

<#
.SYNOPSIS
    Maps findings to CIS Microsoft 365 Benchmark controls.

.DESCRIPTION
    Evaluates the findings collection against CIS controls and determines
    compliance status for each control.

.PARAMETER Findings
    Array of findings from security checks. Uses $script:Findings if not provided.

.OUTPUTS
    Hashtable with control mappings and compliance summary.
#>
function Get-CISComplianceMapping {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter()]
        [array]$Findings = $script:Findings
    )
    
    Write-Host "`n[+] Mapping findings to CIS Microsoft 365 Benchmark v3.0..." -ForegroundColor Cyan

    # Filter to only actual finding objects with required properties
    $validFindings = @($Findings | Where-Object {
            $null -ne $_ -and $_.PSObject -and $_.PSObject.Properties.Name -contains 'CheckName'
        })

    if ($validFindings.Count -eq 0) {
        Write-Host "    [!] No findings available to map (received $($Findings.Count) objects, 0 valid findings)" -ForegroundColor Yellow
        return $null
    }

    Write-Host "    [i] Mapping $($validFindings.Count) findings against $($script:CISControls.Count) controls..." -ForegroundColor Gray

    # Build a lookup table: CheckName -> array of findings for fast matching
    $findingsByCheckName = @{}
    foreach ($f in $validFindings) {
        $cn = $f.CheckName
        if ($cn) {
            if (-not $findingsByCheckName.ContainsKey($cn)) {
                $findingsByCheckName[$cn] = [System.Collections.ArrayList]::new()
            }
            $findingsByCheckName[$cn].Add($f) | Out-Null
        }
    }

    $controlResults = @()

    foreach ($control in $script:CISControls) {
        $result = @{
            ControlId = $control.ControlId
            Title = $control.Title
            Section = $control.Section
            Description = $control.Description
            Severity = $control.Severity
            MappedChecks = $control.MappedChecks
            Status = "NOT_ASSESSED"
            Findings = @()
            Evidence = ""
            Remediation = $control.DefaultRemediation
        }

        # Find related findings using the lookup table (primary) and regex fallback
        $relatedFindings = [System.Collections.ArrayList]::new()
        foreach ($checkName in $control.MappedChecks) {
            # Primary: exact CheckName match via lookup table
            if ($findingsByCheckName.ContainsKey($checkName)) {
                foreach ($f in $findingsByCheckName[$checkName]) {
                    if (-not $relatedFindings.Contains($f)) {
                        $relatedFindings.Add($f) | Out-Null
                    }
                }
            }

            # Fallback: regex match on Object/Description fields
            $checkPattern = $checkName -replace "Check-", ""
            $regexMatches = @($validFindings | Where-Object {
                    $_.Object -match $checkPattern -or
                    $_.Description -match $checkPattern
                })
            foreach ($f in $regexMatches) {
                if ($null -ne $f -and -not $relatedFindings.Contains($f)) {
                    $relatedFindings.Add($f) | Out-Null
                }
            }
        }

        $result.Findings = @($relatedFindings)

        if ($relatedFindings.Count -eq 0) {
            $result.Status = "NOT_ASSESSED"
            $result.Evidence = "No check data available for this control. Run relevant security checks."
        }
        else {
            # Determine status based on findings
            $failCount = ($relatedFindings | Where-Object { $_.Status -eq "FAIL" }).Count
            $warnCount = ($relatedFindings | Where-Object { $_.Status -eq "WARNING" }).Count
            $okCount = ($relatedFindings | Where-Object { $_.Status -eq "OK" }).Count
            
            if ($failCount -gt 0) {
                $result.Status = "FAIL"
                $failFindings = $relatedFindings | Where-Object { $_.Status -eq "FAIL" }
                $result.Evidence = ($failFindings | ForEach-Object { $_.Description }) -join " | "
                # Use finding remediation if available
                $findingRemediation = ($failFindings | Where-Object { $_.Remediation } | Select-Object -First 1).Remediation
                if ($findingRemediation) { $result.Remediation = $findingRemediation }
            }
            elseif ($warnCount -gt 0) {
                $result.Status = "PARTIAL"
                $warnFindings = $relatedFindings | Where-Object { $_.Status -eq "WARNING" }
                $result.Evidence = ($warnFindings | ForEach-Object { $_.Description }) -join " | "
                $findingRemediation = ($warnFindings | Where-Object { $_.Remediation } | Select-Object -First 1).Remediation
                if ($findingRemediation) { $result.Remediation = $findingRemediation }
            }
            elseif ($okCount -gt 0) {
                $result.Status = "PASS"
                $result.Evidence = "Control requirements satisfied based on security check results."
                $result.Remediation = "Continue monitoring. No action required."
            }
            else {
                $result.Status = "NOT_ASSESSED"
                $result.Evidence = "Only informational findings available. Manual review recommended."
            }
        }
        
        $controlResults += [PSCustomObject]$result
    }
    
    # Calculate summary
    $summary = @{
        Framework = "CIS Microsoft 365 Foundations Benchmark v3.0"
        AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalControls = $controlResults.Count
        Pass = ($controlResults | Where-Object { $_.Status -eq "PASS" }).Count
        Fail = ($controlResults | Where-Object { $_.Status -eq "FAIL" }).Count
        Partial = ($controlResults | Where-Object { $_.Status -eq "PARTIAL" }).Count
        NotAssessed = ($controlResults | Where-Object { $_.Status -eq "NOT_ASSESSED" }).Count
    }
    
    $assessedControls = $summary.TotalControls - $summary.NotAssessed
    $summary.ComplianceScore = if ($assessedControls -gt 0) {
        [math]::Round((($summary.Pass / $assessedControls) * 100), 1)
    } else { 0 }
    
    # Diagnostic: show CheckName values found in findings for troubleshooting
    $uniqueCheckNames = $findingsByCheckName.Keys | Sort-Object
    Write-Host "    [i] Unique CheckNames in findings: $($uniqueCheckNames.Count) ($($uniqueCheckNames -join ', '))" -ForegroundColor Gray
    Write-Host "    [i] Assessed: $($summary.TotalControls - $summary.NotAssessed)/$($summary.TotalControls) controls" -ForegroundColor Gray

    Write-Host "    [i] Compliance Score: $($summary.ComplianceScore)% ($($summary.Pass) pass, $($summary.Fail) fail, $($summary.Partial) partial)" -ForegroundColor $(
        if ($summary.ComplianceScore -ge 80) { "Green" } elseif ($summary.ComplianceScore -ge 60) { "Yellow" } else { "Red" }
    )

    return @{
        Controls = $controlResults
        Summary = $summary
    }
}

<#
.SYNOPSIS
    Maps findings to NIST 800-53 Rev 5 controls.

.DESCRIPTION
    Evaluates the findings collection against NIST controls and determines
    compliance status for each control.

.PARAMETER Findings
    Array of findings from security checks. Uses $script:Findings if not provided.

.OUTPUTS
    Hashtable with control mappings and compliance summary.
#>
function Get-NISTComplianceMapping {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter()]
        [array]$Findings = $script:Findings
    )
    
    Write-Host "`n[+] Mapping findings to NIST 800-53 Rev 5..." -ForegroundColor Cyan

    # Filter to only actual finding objects with required properties
    $validFindings = @($Findings | Where-Object {
            $null -ne $_ -and $_.PSObject -and $_.PSObject.Properties.Name -contains 'CheckName'
        })

    if ($validFindings.Count -eq 0) {
        Write-Host "    [!] No findings available to map (received $($Findings.Count) objects, 0 valid findings)" -ForegroundColor Yellow
        return $null
    }

    Write-Host "    [i] Mapping $($validFindings.Count) findings against $($script:NISTControls.Count) controls..." -ForegroundColor Gray

    # Build a lookup table: CheckName -> array of findings for fast matching
    $findingsByCheckName = @{}
    foreach ($f in $validFindings) {
        $cn = $f.CheckName
        if ($cn) {
            if (-not $findingsByCheckName.ContainsKey($cn)) {
                $findingsByCheckName[$cn] = [System.Collections.ArrayList]::new()
            }
            $findingsByCheckName[$cn].Add($f) | Out-Null
        }
    }

    $controlResults = @()

    foreach ($control in $script:NISTControls) {
        $result = @{
            ControlId = $control.ControlId
            Title = $control.Title
            Family = $control.Family
            Description = $control.Description
            Severity = $control.Severity
            MappedChecks = $control.MappedChecks
            Status = "NOT_ASSESSED"
            Findings = @()
            Evidence = ""
            Remediation = $control.DefaultRemediation
        }

        # Find related findings using the lookup table (primary) and regex fallback
        $relatedFindings = [System.Collections.ArrayList]::new()
        foreach ($checkName in $control.MappedChecks) {
            # Primary: exact CheckName match via lookup table
            if ($findingsByCheckName.ContainsKey($checkName)) {
                foreach ($f in $findingsByCheckName[$checkName]) {
                    if (-not $relatedFindings.Contains($f)) {
                        $relatedFindings.Add($f) | Out-Null
                    }
                }
            }

            # Fallback: regex match on Object/Description fields
            $checkPattern = $checkName -replace "Check-", ""
            $regexMatches = @($validFindings | Where-Object {
                    $_.Object -match $checkPattern -or
                    $_.Description -match $checkPattern
                })
            foreach ($f in $regexMatches) {
                if ($null -ne $f -and -not $relatedFindings.Contains($f)) {
                    $relatedFindings.Add($f) | Out-Null
                }
            }
        }

        $result.Findings = @($relatedFindings)

        if ($relatedFindings.Count -eq 0) {
            $result.Status = "NOT_ASSESSED"
            $result.Evidence = "No check data available for this control."
        }
        else {
            $failCount = ($relatedFindings | Where-Object { $_.Status -eq "FAIL" }).Count
            $warnCount = ($relatedFindings | Where-Object { $_.Status -eq "WARNING" }).Count
            $okCount = ($relatedFindings | Where-Object { $_.Status -eq "OK" }).Count
            
            if ($failCount -gt 0) {
                $result.Status = "FAIL"
                $failFindings = $relatedFindings | Where-Object { $_.Status -eq "FAIL" }
                $result.Evidence = ($failFindings | ForEach-Object { $_.Description }) -join " | "
                $findingRemediation = ($failFindings | Where-Object { $_.Remediation } | Select-Object -First 1).Remediation
                if ($findingRemediation) { $result.Remediation = $findingRemediation }
            }
            elseif ($warnCount -gt 0) {
                $result.Status = "PARTIAL"
                $warnFindings = $relatedFindings | Where-Object { $_.Status -eq "WARNING" }
                $result.Evidence = ($warnFindings | ForEach-Object { $_.Description }) -join " | "
                $findingRemediation = ($warnFindings | Where-Object { $_.Remediation } | Select-Object -First 1).Remediation
                if ($findingRemediation) { $result.Remediation = $findingRemediation }
            }
            elseif ($okCount -gt 0) {
                $result.Status = "PASS"
                $result.Evidence = "Control requirements satisfied."
                $result.Remediation = "Continue monitoring. No action required."
            }
            else {
                $result.Status = "NOT_ASSESSED"
                $result.Evidence = "Only informational findings available."
            }
        }
        
        $controlResults += [PSCustomObject]$result
    }
    
    # Calculate summary by family
    $familySummary = $controlResults | Group-Object Family | ForEach-Object {
        @{
            Family = $_.Name
            Total = $_.Count
            Pass = ($_.Group | Where-Object { $_.Status -eq "PASS" }).Count
            Fail = ($_.Group | Where-Object { $_.Status -eq "FAIL" }).Count
            Partial = ($_.Group | Where-Object { $_.Status -eq "PARTIAL" }).Count
        }
    }
    
    $summary = @{
        Framework = "NIST 800-53 Rev 5"
        AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalControls = $controlResults.Count
        Pass = ($controlResults | Where-Object { $_.Status -eq "PASS" }).Count
        Fail = ($controlResults | Where-Object { $_.Status -eq "FAIL" }).Count
        Partial = ($controlResults | Where-Object { $_.Status -eq "PARTIAL" }).Count
        NotAssessed = ($controlResults | Where-Object { $_.Status -eq "NOT_ASSESSED" }).Count
        ByFamily = $familySummary
    }
    
    $assessedControls = $summary.TotalControls - $summary.NotAssessed
    $summary.ComplianceScore = if ($assessedControls -gt 0) {
        [math]::Round((($summary.Pass / $assessedControls) * 100), 1)
    } else { 0 }
    
    # Diagnostic: show match stats
    Write-Host "    [i] Assessed: $($summary.TotalControls - $summary.NotAssessed)/$($summary.TotalControls) controls" -ForegroundColor Gray

    Write-Host "    [i] Compliance Score: $($summary.ComplianceScore)% ($($summary.Pass) pass, $($summary.Fail) fail, $($summary.Partial) partial)" -ForegroundColor $(
        if ($summary.ComplianceScore -ge 80) { "Green" } elseif ($summary.ComplianceScore -ge 60) { "Yellow" } else { "Red" }
    )

    return @{
        Controls = $controlResults
        Summary = $summary
    }
}

<#
.SYNOPSIS
    Identifies compliance gaps across frameworks.

.DESCRIPTION
    Analyzes mapped controls to identify gaps that need attention.

.PARAMETER CISMapping
    CIS compliance mapping results.

.PARAMETER NISTMapping
    NIST compliance mapping results.

.OUTPUTS
    Array of compliance gaps with prioritization.
#>
function Get-ComplianceGaps {
    [CmdletBinding()]
    param(
        [Parameter()]
        $CISMapping,
        
        [Parameter()]
        $NISTMapping
    )
    
    Write-Host "`n[+] Analyzing compliance gaps..." -ForegroundColor Cyan
    
    $gaps = @()
    
    # Analyze CIS gaps
    if ($CISMapping) {
        $cisFailures = $CISMapping.Controls | Where-Object { $_.Status -in @("FAIL", "PARTIAL") }
        foreach ($control in $cisFailures) {
            $gaps += [PSCustomObject]@{
                Framework = "CIS M365 v3.0"
                ControlId = $control.ControlId
                Title = $control.Title
                Status = $control.Status
                Severity = $control.Severity
                Priority = switch ($control.Severity) {
                    "Critical" { 1 }
                    "High" { 2 }
                    "Medium" { 3 }
                    "Low" { 4 }
                    default { 5 }
                }
                Evidence = $control.Evidence
                Remediation = $control.Remediation
            }
        }
    }
    
    # Analyze NIST gaps
    if ($NISTMapping) {
        $nistFailures = $NISTMapping.Controls | Where-Object { $_.Status -in @("FAIL", "PARTIAL") }
        foreach ($control in $nistFailures) {
            $gaps += [PSCustomObject]@{
                Framework = "NIST 800-53 r5"
                ControlId = $control.ControlId
                Title = $control.Title
                Status = $control.Status
                Severity = $control.Severity
                Priority = switch ($control.Severity) {
                    "Critical" { 1 }
                    "High" { 2 }
                    "Medium" { 3 }
                    "Low" { 4 }
                    default { 5 }
                }
                Evidence = $control.Evidence
                Remediation = $control.Remediation
            }
        }
    }
    
    # Sort by priority
    $gaps = $gaps | Sort-Object Priority, Framework, ControlId
    
    $criticalCount = ($gaps | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = ($gaps | Where-Object { $_.Severity -eq "High" }).Count
    
    Write-Host "    [i] Found $($gaps.Count) compliance gaps (Critical: $criticalCount, High: $highCount)" -ForegroundColor $(
        if ($criticalCount -gt 0) { "Red" } elseif ($highCount -gt 0) { "Yellow" } else { "Cyan" }
    )
    
    return $gaps
}

<#
.SYNOPSIS
    Calculates overall compliance scores.

.DESCRIPTION
    Provides a summary of compliance scores across frameworks.

.PARAMETER CISMapping
    CIS compliance mapping results.

.PARAMETER NISTMapping
    NIST compliance mapping results.

.OUTPUTS
    Hashtable with compliance scores.
#>
function Get-ComplianceScore {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter()]
        $CISMapping,
        
        [Parameter()]
        $NISTMapping
    )
    
    $scores = @{
        AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Frameworks = @()
    }
    
    if ($CISMapping) {
        $scores.Frameworks += @{
            Name = "CIS Microsoft 365 v3.0"
            Score = $CISMapping.Summary.ComplianceScore
            Pass = $CISMapping.Summary.Pass
            Fail = $CISMapping.Summary.Fail
            Partial = $CISMapping.Summary.Partial
            NotAssessed = $CISMapping.Summary.NotAssessed
            Total = $CISMapping.Summary.TotalControls
        }
    }
    
    if ($NISTMapping) {
        $scores.Frameworks += @{
            Name = "NIST 800-53 Rev 5"
            Score = $NISTMapping.Summary.ComplianceScore
            Pass = $NISTMapping.Summary.Pass
            Fail = $NISTMapping.Summary.Fail
            Partial = $NISTMapping.Summary.Partial
            NotAssessed = $NISTMapping.Summary.NotAssessed
            Total = $NISTMapping.Summary.TotalControls
        }
    }
    
    # Calculate overall score (average of frameworks)
    if ($scores.Frameworks.Count -gt 0) {
        $scores.OverallScore = [math]::Round(
            (($scores.Frameworks | ForEach-Object { $_.Score }) | Measure-Object -Average).Average, 1
        )
    }
    
    return $scores
}

#endregion

#region ==================== REPORT GENERATION ====================

<#
.SYNOPSIS
    Exports compliance report in HTML format.

.DESCRIPTION
    Generates a professional HTML compliance report with executive summary,
    framework details, and remediation guidance.

.PARAMETER CISMapping
    CIS compliance mapping results.

.PARAMETER NISTMapping
    NIST compliance mapping results.

.PARAMETER Gaps
    Array of compliance gaps.

.PARAMETER OutputPath
    Path for the output HTML file.

.PARAMETER TenantName
    Name of the tenant being assessed.
#>
function Export-ComplianceReportHTML {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter()]
        $CISMapping,
        
        [Parameter()]
        $NISTMapping,
        
        [Parameter()]
        $Gaps,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [Parameter()]
        [string]$TenantName = "Unknown Tenant"
    )
    
    Write-Host "`n[+] Generating HTML compliance report..." -ForegroundColor Cyan
    
    $scores = Get-ComplianceScore -CISMapping $CISMapping -NISTMapping $NISTMapping
    $assessmentDate = Get-Date -Format "MMMM dd, yyyy HH:mm"
    
    # Generate HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra ID Compliance Assessment Report</title>
    <style>
        :root {
            --primary-color: #0078d4;
            --success-color: #107c10;
            --warning-color: #ff8c00;
            --danger-color: #d13438;
            --info-color: #00bcf2;
            --gray-100: #f3f2f1;
            --gray-200: #e1dfdd;
            --gray-600: #605e5c;
            --gray-800: #323130;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--gray-800);
            background: var(--gray-100);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, var(--primary-color), #106ebe);
            color: white;
            padding: 40px;
            margin-bottom: 30px;
            border-radius: 8px;
        }
        
        header h1 { font-size: 2rem; margin-bottom: 10px; }
        header p { opacity: 0.9; }
        
        .meta-info {
            display: flex;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .meta-item {
            background: rgba(255,255,255,0.15);
            padding: 10px 20px;
            border-radius: 4px;
        }
        
        .meta-item label {
            font-size: 0.75rem;
            text-transform: uppercase;
            opacity: 0.8;
        }
        
        .meta-item span { font-size: 1.1rem; font-weight: 600; }
        
        .card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .card-header {
            background: var(--gray-100);
            padding: 15px 20px;
            border-bottom: 1px solid var(--gray-200);
            font-weight: 600;
            font-size: 1.1rem;
        }
        
        .card-body { padding: 20px; }
        
        .score-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .score-card {
            background: white;
            border-radius: 8px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .score-card h3 {
            font-size: 0.9rem;
            color: var(--gray-600);
            margin-bottom: 10px;
        }
        
        .score-value {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 10px;
        }
        
        .score-value.high { color: var(--success-color); }
        .score-value.medium { color: var(--warning-color); }
        .score-value.low { color: var(--danger-color); }
        
        .score-breakdown {
            display: flex;
            justify-content: center;
            gap: 15px;
            font-size: 0.85rem;
        }
        
        .score-breakdown span { display: flex; align-items: center; gap: 5px; }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-pass { background: #dff6dd; color: var(--success-color); }
        .badge-fail { background: #fde7e9; color: var(--danger-color); }
        .badge-partial { background: #fff4ce; color: var(--warning-color); }
        .badge-notassessed { background: var(--gray-200); color: var(--gray-600); }
        
        .severity-critical { color: #a4262c; font-weight: 700; }
        .severity-high { color: var(--danger-color); font-weight: 600; }
        .severity-medium { color: var(--warning-color); }
        .severity-low { color: var(--gray-600); }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--gray-200);
        }
        
        th {
            background: var(--gray-100);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            color: var(--gray-600);
        }
        
        tr:hover { background: var(--gray-100); }
        
        .gap-item {
            border-left: 4px solid var(--danger-color);
            padding: 15px 20px;
            margin-bottom: 15px;
            background: white;
            border-radius: 0 8px 8px 0;
        }
        
        .gap-item.partial { border-left-color: var(--warning-color); }
        
        .gap-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
        }
        
        .gap-title { font-weight: 600; }
        .gap-control { font-size: 0.85rem; color: var(--gray-600); }
        
        .gap-evidence {
            background: var(--gray-100);
            padding: 10px 15px;
            border-radius: 4px;
            margin: 10px 0;
            font-size: 0.9rem;
        }
        
        .gap-remediation {
            background: #e8f4fd;
            padding: 10px 15px;
            border-radius: 4px;
            font-size: 0.9rem;
            border-left: 3px solid var(--primary-color);
        }
        
        .gap-remediation strong {
            color: var(--primary-color);
        }
        
        .section-title {
            font-size: 1.3rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--primary-color);
        }
        
        .control-table td:first-child { width: 100px; font-weight: 600; }
        .control-table td:nth-child(2) { width: 35%; }
        .control-table td:nth-child(3) { width: 100px; }
        .control-table td:nth-child(4) { width: 100px; }
        
        .executive-summary {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .summary-list { list-style: none; }
        .summary-list li {
            padding: 8px 0;
            border-bottom: 1px solid var(--gray-200);
            display: flex;
            justify-content: space-between;
        }
        
        .summary-list li:last-child { border-bottom: none; }
        
        footer {
            text-align: center;
            padding: 20px;
            color: var(--gray-600);
            font-size: 0.85rem;
        }
        
        @media print {
            body { background: white; }
            .container { max-width: 100%; }
            .card { break-inside: avoid; }
            header { background: var(--primary-color) !important; -webkit-print-color-adjust: exact; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Entra ID Compliance Assessment Report</h1>
            <p>Security posture evaluation against industry compliance frameworks</p>
            <div class="meta-info">
                <div class="meta-item">
                    <label>Tenant</label><br>
                    <span>$TenantName</span>
                </div>
                <div class="meta-item">
                    <label>Assessment Date</label><br>
                    <span>$assessmentDate</span>
                </div>
                <div class="meta-item">
                    <label>Overall Score</label><br>
                    <span>$($scores.OverallScore)%</span>
                </div>
            </div>
        </header>

        <!-- Executive Summary -->
        <h2 class="section-title">Executive Summary</h2>
        <div class="score-grid">
"@

    # Add score cards for each framework
    foreach ($framework in $scores.Frameworks) {
        $scoreClass = if ($framework.Score -ge 80) { "high" } elseif ($framework.Score -ge 60) { "medium" } else { "low" }
        $html += @"
            <div class="score-card">
                <h3>$($framework.Name)</h3>
                <div class="score-value $scoreClass">$($framework.Score)%</div>
                <div class="score-breakdown">
                    <span><span class="badge badge-pass">$($framework.Pass) Pass</span></span>
                    <span><span class="badge badge-fail">$($framework.Fail) Fail</span></span>
                    <span><span class="badge badge-partial">$($framework.Partial) Partial</span></span>
                </div>
            </div>
"@
    }

    $html += @"
        </div>

        <!-- Priority Gaps -->
        <h2 class="section-title">Priority Remediation Items</h2>
        <div class="card">
            <div class="card-header">Critical and High Severity Gaps Requiring Immediate Attention</div>
            <div class="card-body">
"@

    # Add priority gaps
    $priorityGaps = $Gaps | Where-Object { $_.Severity -in @("Critical", "High") } | Select-Object -First 10
    
    if ($priorityGaps.Count -eq 0) {
        $html += "<p style='color: var(--success-color); font-weight: 600;'>&check; No critical or high severity gaps identified. Great work!</p>"
    }
    else {
        foreach ($gap in $priorityGaps) {
            $gapClass = if ($gap.Status -eq "FAIL") { "" } else { "partial" }
            $severityClass = "severity-$($gap.Severity.ToLower())"
            
            $html += @"
                <div class="gap-item $gapClass">
                    <div class="gap-header">
                        <div>
                            <div class="gap-title">$($gap.Title)</div>
                            <div class="gap-control">$($gap.Framework) - $($gap.ControlId)</div>
                        </div>
                        <span class="$severityClass">$($gap.Severity)</span>
                    </div>
                    <div class="gap-evidence">
                        <strong>Issue:</strong> $($gap.Evidence)
                    </div>
                    <div class="gap-remediation">
                        <strong>Remediation:</strong> $($gap.Remediation)
                    </div>
                </div>
"@
        }
    }

    $html += @"
            </div>
        </div>
"@

    # CIS Controls Detail
    if ($CISMapping) {
        $html += @"
        <h2 class="section-title">CIS Microsoft 365 Benchmark v3.0 Details</h2>
        <div class="card">
            <div class="card-body">
                <table class="control-table">
                    <thead>
                        <tr>
                            <th>Control</th>
                            <th>Title</th>
                            <th>Status</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($control in $CISMapping.Controls | Sort-Object ControlId) {
            $statusClass = switch ($control.Status) {
                "PASS" { "badge-pass" }
                "FAIL" { "badge-fail" }
                "PARTIAL" { "badge-partial" }
                default { "badge-notassessed" }
            }
            $severityClass = "severity-$($control.Severity.ToLower())"
            
            $html += @"
                        <tr>
                            <td>$($control.ControlId)</td>
                            <td>$($control.Title)</td>
                            <td><span class="badge $statusClass">$($control.Status)</span></td>
                            <td class="$severityClass">$($control.Severity)</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
"@
    }

    # NIST Controls Detail
    if ($NISTMapping) {
        $html += @"
        <h2 class="section-title">NIST 800-53 Rev 5 Details</h2>
        <div class="card">
            <div class="card-body">
                <table class="control-table">
                    <thead>
                        <tr>
                            <th>Control</th>
                            <th>Title</th>
                            <th>Family</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($control in $NISTMapping.Controls | Sort-Object ControlId) {
            $statusClass = switch ($control.Status) {
                "PASS" { "badge-pass" }
                "FAIL" { "badge-fail" }
                "PARTIAL" { "badge-partial" }
                default { "badge-notassessed" }
            }
            
            $html += @"
                        <tr>
                            <td>$($control.ControlId)</td>
                            <td>$($control.Title)</td>
                            <td>$($control.Family)</td>
                            <td><span class="badge $statusClass">$($control.Status)</span></td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
"@
    }

    # Footer
    $html += @"
        <footer>
            <p>Generated by EntraChecks Compliance Module v$script:ModuleVersion</p>
            <p>&copy; $(Get-Date -Format "yyyy") SolveGRC - Security Assessment Report</p>
        </footer>
    </div>
</body>
</html>
"@

    # Write file
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    
    Write-Host "    [OK] HTML report saved to: $OutputPath" -ForegroundColor Green
    
    return $OutputPath
}

<#
.SYNOPSIS
    Exports compliance report in CSV format.

.DESCRIPTION
    Generates detailed CSV reports for compliance controls and gaps.

.PARAMETER CISMapping
    CIS compliance mapping results.

.PARAMETER NISTMapping
    NIST compliance mapping results.

.PARAMETER Gaps
    Array of compliance gaps.

.PARAMETER OutputPath
    Base path for output files (will create multiple CSVs).
#>
function Export-ComplianceReportCSV {
    [CmdletBinding()]
    param(
        [Parameter()]
        $CISMapping,
        
        [Parameter()]
        $NISTMapping,
        
        [Parameter()]
        $Gaps,
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    Write-Host "`n[+] Generating CSV compliance reports..." -ForegroundColor Cyan
    
    $basePath = [System.IO.Path]::GetDirectoryName($OutputPath)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
    
    $outputFiles = @()
    
    # Export CIS controls
    if ($CISMapping) {
        $cisPath = Join-Path $basePath "$baseName-CIS-Controls.csv"
        $CISMapping.Controls | Select-Object ControlId, Title, Section, Status, Severity, Evidence, Remediation |
            Export-Csv -Path $cisPath -NoTypeInformation -Encoding UTF8
        $outputFiles += $cisPath
        Write-Host "    [OK] CIS controls: $cisPath" -ForegroundColor Green
    }
    
    # Export NIST controls
    if ($NISTMapping) {
        $nistPath = Join-Path $basePath "$baseName-NIST-Controls.csv"
        $NISTMapping.Controls | Select-Object ControlId, Title, Family, Status, Severity, Evidence, Remediation |
            Export-Csv -Path $nistPath -NoTypeInformation -Encoding UTF8
        $outputFiles += $nistPath
        Write-Host "    [OK] NIST controls: $nistPath" -ForegroundColor Green
    }
    
    # Export gaps
    if ($Gaps -and $Gaps.Count -gt 0) {
        $gapsPath = Join-Path $basePath "$baseName-Compliance-Gaps.csv"
        $Gaps | Select-Object Framework, ControlId, Title, Status, Severity, Priority, Evidence, Remediation |
            Export-Csv -Path $gapsPath -NoTypeInformation -Encoding UTF8
        $outputFiles += $gapsPath
        Write-Host "    [OK] Compliance gaps: $gapsPath" -ForegroundColor Green
    }
    
    # Export summary
    $summaryPath = Join-Path $basePath "$baseName-Summary.csv"
    $summaryData = @()
    
    if ($CISMapping) {
        $summaryData += [PSCustomObject]@{
            Framework = "CIS Microsoft 365 v3.0"
            ComplianceScore = "$($CISMapping.Summary.ComplianceScore)%"
            TotalControls = $CISMapping.Summary.TotalControls
            Pass = $CISMapping.Summary.Pass
            Fail = $CISMapping.Summary.Fail
            Partial = $CISMapping.Summary.Partial
            NotAssessed = $CISMapping.Summary.NotAssessed
            AssessmentDate = $CISMapping.Summary.AssessmentDate
        }
    }
    
    if ($NISTMapping) {
        $summaryData += [PSCustomObject]@{
            Framework = "NIST 800-53 Rev 5"
            ComplianceScore = "$($NISTMapping.Summary.ComplianceScore)%"
            TotalControls = $NISTMapping.Summary.TotalControls
            Pass = $NISTMapping.Summary.Pass
            Fail = $NISTMapping.Summary.Fail
            Partial = $NISTMapping.Summary.Partial
            NotAssessed = $NISTMapping.Summary.NotAssessed
            AssessmentDate = $NISTMapping.Summary.AssessmentDate
        }
    }
    
    $summaryData | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
    $outputFiles += $summaryPath
    Write-Host "    [OK] Summary: $summaryPath" -ForegroundColor Green
    
    return $outputFiles
}

<#
.SYNOPSIS
    Generates full compliance report in both HTML and CSV formats.

.DESCRIPTION
    Main function to generate comprehensive compliance reports.

.PARAMETER Findings
    Array of findings from security checks.

.PARAMETER OutputDirectory
    Directory for output files.

.PARAMETER TenantName
    Name of the tenant being assessed.

.PARAMETER Frameworks
    Array of frameworks to include. Default: @("CIS", "NIST")
#>
function Export-ComplianceReport {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter()]
        [array]$Findings = $script:Findings,
        
        [Parameter(Mandatory)]
        [string]$OutputDirectory,
        
        [Parameter()]
        [string]$TenantName = "Unknown Tenant",
        
        [Parameter()]
        [string[]]$Frameworks = @("CIS", "NIST")
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host " Compliance Report Generation" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Magenta
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $baseFileName = "EntraID-Compliance-$timestamp"
    
    # Generate mappings
    $cisMapping = $null
    $nistMapping = $null
    
    if ($Frameworks -contains "CIS") {
        $cisMapping = Get-CISComplianceMapping -Findings $Findings
    }
    
    if ($Frameworks -contains "NIST") {
        $nistMapping = Get-NISTComplianceMapping -Findings $Findings
    }
    
    # Get gaps
    $gaps = Get-ComplianceGaps -CISMapping $cisMapping -NISTMapping $nistMapping
    
    # Generate reports
    $htmlPath = Join-Path $OutputDirectory "$baseFileName.html"
    Export-ComplianceReportHTML -CISMapping $cisMapping -NISTMapping $nistMapping -Gaps $gaps -OutputPath $htmlPath -TenantName $TenantName
    
    $csvBasePath = Join-Path $OutputDirectory $baseFileName
    Export-ComplianceReportCSV -CISMapping $cisMapping -NISTMapping $nistMapping -Gaps $gaps -OutputPath $csvBasePath
    
    # Display summary
    Write-Host "`n[+] Compliance Assessment Complete" -ForegroundColor Magenta
    Write-Host "    Reports saved to: $OutputDirectory" -ForegroundColor Cyan
    
    return @{
        CISMapping = $cisMapping
        NISTMapping = $nistMapping
        Gaps = $gaps
        HTMLReport = $htmlPath
        OutputDirectory = $OutputDirectory
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

<#
.SYNOPSIS
    Runs compliance assessment and generates reports.

.DESCRIPTION
    Convenience function to run full compliance assessment.
#>
function Invoke-ComplianceAssessment {
    [CmdletBinding()]
    param(
        [Parameter()]
        [array]$Findings = $script:Findings,
        
        [Parameter()]
        [string]$OutputDirectory = ".",
        
        [Parameter()]
        [string]$TenantName = "Unknown Tenant"
    )
    
    return Export-ComplianceReport -Findings $Findings -OutputDirectory $OutputDirectory -TenantName $TenantName
}

# Export module members
Export-ModuleMember -Function @(
    'Initialize-ComplianceModule',
    'Get-CISComplianceMapping',
    'Get-NISTComplianceMapping',
    'Get-ComplianceGaps',
    'Get-ComplianceScore',
    'Export-ComplianceReportHTML',
    'Export-ComplianceReportCSV',
    'Export-ComplianceReport',
    'Invoke-ComplianceAssessment'
)

#endregion

#region ==================== UNIFIED COMPLIANCE REPORTING ====================

<#
.SYNOPSIS
    Generates unified compliance report from all available sources.

.DESCRIPTION
    Aggregates compliance data from:
    - Internal findings (EntraChecks)
    - Microsoft Secure Score
    - Defender for Cloud regulatory compliance
    
    Produces a consolidated report showing compliance posture across all frameworks.

.PARAMETER OutputDirectory
    Directory for output files.

.PARAMETER TenantName
    Name of the tenant being assessed.

.PARAMETER Findings
    EntraChecks findings array.

.PARAMETER IncludeSecureScore
    Include Microsoft Secure Score data.

.PARAMETER IncludeDefenderCompliance
    Include Defender for Cloud compliance data.

.PARAMETER SecureScoreData
    Pre-loaded Secure Score data. If not provided, will attempt to retrieve.

.PARAMETER DefenderComplianceData
    Pre-loaded Defender compliance data. If not provided, will attempt to retrieve.
#>
function Export-UnifiedComplianceReport {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputDirectory,
        
        [Parameter()]
        [string]$TenantName = "Unknown Tenant",
        
        [Parameter()]
        [array]$Findings = $script:Findings,
        
        [switch]$IncludeSecureScore,
        
        [switch]$IncludeDefenderCompliance,
        
        [switch]$IncludeAzurePolicy,
        
        [switch]$IncludePurviewCompliance,
        
        [Parameter()]
        $SecureScoreData,
        
        [Parameter()]
        $DefenderComplianceData,
        
        [Parameter()]
        $AzurePolicyData,

        [Parameter()]
        $PurviewComplianceData,

        # Output of Merge-PrivilegedIdentityRosters (unified AD <-> Entra
        # privileged-identity roster). When supplied, the report renders the
        # Privileged Identity Roster section + dashboard tile.
        [Parameter()]
        $PrivilegedIdentityRoster
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "==========================================================" -ForegroundColor Magenta
    Write-Host " UNIFIED COMPLIANCE REPORT - All Sources" -ForegroundColor Magenta
    Write-Host "==========================================================" -ForegroundColor Magenta
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $assessmentDate = Get-Date -Format "MMMM dd, yyyy HH:mm"
    
    # Gather data from all sources. Catalog provides static provenance
    # (Provider, Endpoints, Cmdlets, Scopes, ReferenceUrl); we extend each entry
    # with Available/Data and stamp runtime context via Update-DataSourceContext.
    $dataSources = Get-DataSourceCatalog
    foreach ($dsKey in @($dataSources.Keys)) {
        $dataSources[$dsKey]['Available'] = $false
        $dataSources[$dsKey]['Data'] = $null
    }

    # Internal findings (CIS/NIST mapping)
    Write-Host "`n[1/5] Processing internal findings..." -ForegroundColor Cyan
    $cisMapping = $null
    $nistMapping = $null

    if ($Findings -and $Findings.Count -gt 0) {
        $cisMapping = Get-CISComplianceMapping -Findings $Findings
        $nistMapping = Get-NISTComplianceMapping -Findings $Findings
        $dataSources.Internal.Available = $true
        $dataSources.Internal.Data = @{
            CIS = $cisMapping
            NIST = $nistMapping
            FindingsCount = $Findings.Count
        }
        Update-DataSourceContext -Descriptor $dataSources.Internal
    }
    else {
        Write-Host "    [!] No internal findings available" -ForegroundColor Yellow
    }

    # Secure Score
    Write-Host "`n[2/5] Processing Secure Score data..." -ForegroundColor Cyan
    if ($IncludeSecureScore) {
        if ($SecureScoreData) {
            $dataSources.SecureScore.Available = $true
            $dataSources.SecureScore.Data = $SecureScoreData
            Update-DataSourceContext -Descriptor $dataSources.SecureScore
            Write-Host "    [OK] Using provided Secure Score data" -ForegroundColor Green
        }
        elseif ($script:SecureScoreData) {
            $dataSources.SecureScore.Available = $true
            $dataSources.SecureScore.Data = $script:SecureScoreData
            Update-DataSourceContext -Descriptor $dataSources.SecureScore
            Write-Host "    [OK] Using cached Secure Score data" -ForegroundColor Green
        }
        else {
            Write-Host "    [!] No Secure Score data. Import EntraChecks-SecureScore module and run Get-SecureScore." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "    [i] Secure Score not requested (use -IncludeSecureScore)" -ForegroundColor Gray
    }

    # Defender for Cloud
    Write-Host "`n[3/5] Processing Defender for Cloud data..." -ForegroundColor Cyan
    if ($IncludeDefenderCompliance) {
        $dcData = if ($DefenderComplianceData) { $DefenderComplianceData } elseif ($script:DefenderComplianceData) { $script:DefenderComplianceData } else { $null }
        if ($dcData) {
            $dataSources.DefenderCompliance.Available = $true
            $dataSources.DefenderCompliance.Data = $dcData
            $dcSubs = @()
            if ($dcData.Summary -and $dcData.Summary.Subscriptions) { $dcSubs = @($dcData.Summary.Subscriptions) }
            elseif ($dcData.Subscriptions) { $dcSubs = @($dcData.Subscriptions | ForEach-Object { if ($_.Name) { $_.Name } else { $_ } }) }
            Update-DataSourceContext -Descriptor $dataSources.DefenderCompliance -Subscriptions $dcSubs
            Write-Host "    [OK] Using Defender compliance data" -ForegroundColor Green
        }
        else {
            Write-Host "    [!] No Defender data. Import EntraChecks-DefenderCompliance module and run Get-DefenderComplianceAssessment." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "    [i] Defender compliance not requested (use -IncludeDefenderCompliance)" -ForegroundColor Gray
    }

    # Azure Policy
    Write-Host "`n[4/5] Processing Azure Policy data..." -ForegroundColor Cyan
    if ($IncludeAzurePolicy) {
        $apData = if ($AzurePolicyData) { $AzurePolicyData } elseif ($script:AzurePolicyData) { $script:AzurePolicyData } else { $null }
        if ($apData) {
            $dataSources.AzurePolicy.Available = $true
            $dataSources.AzurePolicy.Data = $apData
            $apSubs = @()
            if ($apData.Summary -and $apData.Summary.Subscriptions) { $apSubs = @($apData.Summary.Subscriptions) }
            elseif ($apData.Subscriptions) { $apSubs = @($apData.Subscriptions | ForEach-Object { if ($_.Name) { $_.Name } else { $_ } }) }
            Update-DataSourceContext -Descriptor $dataSources.AzurePolicy -Subscriptions $apSubs
            Write-Host "    [OK] Using Azure Policy data" -ForegroundColor Green
        }
        else {
            Write-Host "    [!] No Azure Policy data. Import EntraChecks-AzurePolicy module and run Get-AzurePolicyComplianceAssessment." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "    [i] Azure Policy not requested (use -IncludeAzurePolicy)" -ForegroundColor Gray
    }

    # Purview Compliance Manager
    Write-Host "`n[5/5] Processing Purview Compliance Manager data..." -ForegroundColor Cyan
    if ($IncludePurviewCompliance) {
        if ($PurviewComplianceData) {
            $dataSources.PurviewCompliance.Available = $true
            $dataSources.PurviewCompliance.Data = $PurviewComplianceData
            Update-DataSourceContext -Descriptor $dataSources.PurviewCompliance
            Write-Host "    [OK] Using provided Purview compliance data" -ForegroundColor Green
        }
        elseif ($script:PurviewComplianceData) {
            $dataSources.PurviewCompliance.Available = $true
            $dataSources.PurviewCompliance.Data = $script:PurviewComplianceData
            Update-DataSourceContext -Descriptor $dataSources.PurviewCompliance
            Write-Host "    [OK] Using cached Purview compliance data" -ForegroundColor Green
        }
        else {
            Write-Host "    [!] No Purview data. Import EntraChecks-PurviewCompliance module and run Get-PurviewComplianceAssessment." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "    [i] Purview compliance not requested (use -IncludePurviewCompliance)" -ForegroundColor Gray
    }
    
    # Build unified data structure
    $unifiedData = @{
        AssessmentDate = $assessmentDate
        TenantName = $TenantName
        DataSources = $dataSources
        Frameworks = @()
        AllGaps = @()
    }
    
    # Add internal frameworks
    if ($cisMapping) {
        $unifiedData.Frameworks += @{
            Name = "CIS Microsoft 365 v3.0"
            ShortName = "CIS-M365"
            Source = "Internal"
            Score = $cisMapping.Summary.ComplianceScore
            Pass = $cisMapping.Summary.Pass
            Fail = $cisMapping.Summary.Fail
            Partial = $cisMapping.Summary.Partial
            Total = $cisMapping.Summary.TotalControls
        }
    }
    
    if ($nistMapping) {
        $unifiedData.Frameworks += @{
            Name = "NIST 800-53 Rev 5"
            ShortName = "NIST-800-53"
            Source = "Internal"
            Score = $nistMapping.Summary.ComplianceScore
            Pass = $nistMapping.Summary.Pass
            Fail = $nistMapping.Summary.Fail
            Partial = $nistMapping.Summary.Partial
            Total = $nistMapping.Summary.TotalControls
        }
    }
    
    # Add Secure Score
    if ($dataSources.SecureScore.Available) {
        $ssData = $dataSources.SecureScore.Data
        $unifiedData.Frameworks += @{
            Name = "Microsoft Secure Score"
            ShortName = "SecureScore"
            Source = "SecureScore"
            Score = $ssData.ScorePercent
            Current = $ssData.CurrentScore
            Max = $ssData.MaxScore
            Total = ($ssData.ControlScores | Measure-Object).Count
        }
    }
    
    # Add Defender frameworks
    if ($dataSources.DefenderCompliance.Available) {
        $defData = $dataSources.DefenderCompliance.Data
        foreach ($standardId in $defData.Standards.Keys) {
            $standard = $defData.Standards[$standardId]
            $avgScore = if ($standard.Subscriptions.Count -gt 0) {
                [math]::Round(($standard.Subscriptions | Measure-Object -Property CompliancePercent -Average).Average, 1)
            } else { 0 }
            
            $totalPassed = ($standard.Subscriptions | Measure-Object -Property Passed -Sum).Sum
            $totalFailed = ($standard.Subscriptions | Measure-Object -Property Failed -Sum).Sum
            
            $unifiedData.Frameworks += @{
                Name = $standard.Name
                ShortName = $standard.ShortName
                Source = "DefenderForCloud"
                Score = $avgScore
                Pass = $totalPassed
                Fail = $totalFailed
                Subscriptions = $standard.Subscriptions.Count
                Total = $totalPassed + $totalFailed
            }
        }
    }
    
    # Add Azure Policy data
    if ($dataSources.AzurePolicy.Available) {
        $apData = $dataSources.AzurePolicy.Data
        $apCompliance = if ($apData.Summary.TotalPolicies -gt 0) {
            [math]::Round(($apData.Summary.CompliantPolicies / $apData.Summary.TotalPolicies) * 100, 1)
        } else { 0 }
        
        $unifiedData.Frameworks += @{
            Name = "Azure Policy Compliance"
            ShortName = "AzurePolicy"
            Source = "AzurePolicy"
            Score = $apCompliance
            Pass = $apData.Summary.CompliantPolicies
            Fail = $apData.Summary.NonCompliantPolicies
            Subscriptions = $apData.Summary.TotalSubscriptions
            Total = $apData.Summary.TotalPolicies
            NonCompliantResources = $apData.Summary.NonCompliantResources
        }
        
        # Add individual initiative frameworks if present
        foreach ($initName in $apData.Initiatives.Keys) {
            $init = $apData.Initiatives[$initName]
            if ($init.Framework -ne "Custom") {
                $unifiedData.Frameworks += @{
                    Name = $init.DisplayName
                    ShortName = $init.ShortName
                    Source = "AzurePolicy"
                    Score = $null  # Initiative-level scores require additional API calls
                    Framework = $init.Framework
                    Type = $init.Type
                    Subscriptions = $init.Subscriptions.Count
                }
            }
        }
    }
    
    # Add Purview Compliance Manager data
    if ($dataSources.PurviewCompliance.Available) {
        $pvData = $dataSources.PurviewCompliance.Data
        
        # Add overall Compliance Manager score
        if ($pvData.Summary.ComplianceScore) {
            $unifiedData.Frameworks += @{
                Name = "Purview Compliance Manager"
                ShortName = "ComplianceManager"
                Source = "PurviewCompliance"
                Score = $pvData.Summary.ComplianceScore
                Total = $pvData.Summary.TotalAssessments
                Actions = $pvData.Summary.TotalActions
                CompletedActions = $pvData.Summary.CompletedActions
            }
        }
        
        # Add individual assessments as frameworks
        if ($pvData.ComplianceManager.Assessments) {
            foreach ($assessment in $pvData.ComplianceManager.Assessments) {
                $unifiedData.Frameworks += @{
                    Name = $assessment.DisplayName
                    ShortName = $assessment.ShortName
                    Source = "PurviewCompliance"
                    Score = $assessment.ScorePercent
                    Framework = $assessment.Framework
                    Category = $assessment.Category
                }
            }
        }
        
        # Add data protection summary
        $dpSummary = @()
        if ($pvData.DataProtection.DLPPolicies.Count -gt 0) { $dpSummary += "DLP: $($pvData.DataProtection.DLPPolicies.Count)" }
        if ($pvData.DataProtection.SensitivityLabels.Count -gt 0) { $dpSummary += "Labels: $($pvData.DataProtection.SensitivityLabels.Count)" }
        if ($pvData.DataProtection.RetentionPolicies.Count -gt 0) { $dpSummary += "Retention: $($pvData.DataProtection.RetentionPolicies.Count)" }
        
        if ($dpSummary.Count -gt 0) {
            $unifiedData.Frameworks += @{
                Name = "Purview Data Protection"
                ShortName = "DataProtection"
                Source = "PurviewCompliance"
                Score = $null
                Details = $dpSummary -join ", "
            }
        }
    }
    
    # Consolidate gaps from all sources
    $allGaps = @()
    
    # Internal gaps
    if ($cisMapping -or $nistMapping) {
        $internalGaps = Get-ComplianceGaps -CISMapping $cisMapping -NISTMapping $nistMapping
        if ($internalGaps) { $allGaps += $internalGaps }
    }
    
    # Defender gaps
    if ($dataSources.DefenderCompliance.Available) {
        $defData = $dataSources.DefenderCompliance.Data
        $defenderGaps = $defData.Controls | Where-Object { $_.Status -eq "Failed" } | ForEach-Object {
            [PSCustomObject]@{
                Framework = $_.Framework
                ControlId = $_.ControlId
                Title = $_.ControlTitle
                Status = "FAIL"
                Severity = "High"
                Priority = 2
                Evidence = "Failed in subscription: $($_.SubscriptionName)"
                Remediation = $_.Remediation
                Source = "DefenderForCloud"
            }
        }
        if ($defenderGaps) { $allGaps += $defenderGaps }
    }
    
    # Azure Policy gaps
    if ($dataSources.AzurePolicy.Available) {
        $apData = $dataSources.AzurePolicy.Data
        $policyGaps = $apData.Policies | Where-Object { $_.Status -eq "Failed" } | ForEach-Object {
            [PSCustomObject]@{
                Framework = "Azure Policy"
                ControlId = $_.ControlId
                Title = $_.ControlTitle
                Status = "FAIL"
                Severity = $_.Severity
                Priority = switch ($_.Severity) { "High" { 2 } "Medium" { 3 } default { 4 } }
                Evidence = "Non-compliant: $($_.FailedResources) resources in $($_.SubscriptionName)"
                Remediation = $_.Remediation
                Source = "AzurePolicy"
            }
        }
        if ($policyGaps) { $allGaps += $policyGaps }
    }
    
    # Purview Compliance Manager gaps
    if ($dataSources.PurviewCompliance.Available) {
        $pvData = $dataSources.PurviewCompliance.Data
        
        # Add gaps from controls (assessments with low scores)
        if ($pvData.Controls) {
            $purviewGaps = $pvData.Controls | Where-Object { $_.Status -eq "Failed" } | ForEach-Object {
                [PSCustomObject]@{
                    Framework = $_.Framework
                    ControlId = $_.ControlId
                    Title = $_.ControlTitle
                    Status = "FAIL"
                    Severity = $_.Severity
                    Priority = switch ($_.Severity) { "High" { 2 } "Medium" { 3 } default { 4 } }
                    Evidence = "Compliance score: $($_.CompliancePercent)%"
                    Remediation = $_.Remediation
                    Source = "PurviewCompliance"
                }
            }
            if ($purviewGaps) { $allGaps += $purviewGaps }
        }
        
        # Add gaps from incomplete improvement actions
        if ($pvData.ComplianceManager.Actions) {
            $actionGaps = $pvData.ComplianceManager.Actions |
                Where-Object { $_.Status -notin @("Passed", "NotApplicable") } |
                ForEach-Object {
                    [PSCustomObject]@{
                        Framework = "Compliance Manager"
                        ControlId = $_.Id
                        Title = $_.DisplayName
                        Status = "FAIL"
                        Severity = if ($_.Points -gt 5) { "High" } elseif ($_.Points -gt 2) { "Medium" } else { "Low" }
                        Priority = 3
                        Evidence = "Status: $($_.Status), Points: $($_.Points)"
                        Remediation = "Complete improvement action in Compliance Manager"
                        Source = "PurviewCompliance"
                    }
                }
            if ($actionGaps) { $allGaps += $actionGaps }
        }
    }
    
    $unifiedData.AllGaps = $allGaps | Sort-Object Priority, Framework
    
    # Generate unified HTML report
    $htmlPath = Join-Path $OutputDirectory "UnifiedCompliance-Report-$timestamp.html"
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified Compliance Report</title>
    <style>
        :root {
            --primary: #0078d4;
            --success: #107c10;
            --warning: #ff8c00;
            --danger: #d13438;
            --purple: #5c2d91;
            --gray-100: #f3f2f1;
            --gray-200: #e1dfdd;
            --gray-600: #605e5c;
            --gray-800: #323130;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', Tahoma, sans-serif;
            line-height: 1.6;
            color: var(--gray-800);
            background: var(--gray-100);
        }
        
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        
        header {
            background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460);
            color: white;
            padding: 40px;
            margin-bottom: 30px;
            border-radius: 8px;
        }
        
        header h1 { font-size: 2rem; margin-bottom: 10px; }
        
        .meta-grid {
            display: flex;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .meta-item {
            background: rgba(255,255,255,0.1);
            padding: 15px 20px;
            border-radius: 6px;
        }
        
        .meta-item label { font-size: 0.75rem; text-transform: uppercase; opacity: 0.8; }
        .meta-item span { font-size: 1.2rem; font-weight: 600; display: block; margin-top: 5px; }
        
        .source-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            margin-left: 8px;
        }
        
        .source-internal { background: var(--primary); color: white; }
        .source-securescore { background: #00bcf2; color: white; }
        .source-defender { background: var(--purple); color: white; }
        .source-azurepolicy { background: #0089d6; color: white; }
        .source-purview { background: #742774; color: white; }
        
        .section-title {
            font-size: 1.4rem;
            margin: 30px 0 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid var(--primary);
        }
        
        .framework-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .framework-card {
            background: white;
            border-radius: 8px;
            padding: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-top: 4px solid var(--primary);
        }
        
        .framework-card.defender { border-top-color: var(--purple); }
        .framework-card.securescore { border-top-color: #00bcf2; }
        .framework-card.azurepolicy { border-top-color: #0089d6; }
        .framework-card.purview { border-top-color: #742774; }
        
        .framework-card h3 { font-size: 1rem; margin-bottom: 5px; }
        .framework-card .source { font-size: 0.75rem; color: var(--gray-600); margin-bottom: 15px; }
        
        .framework-score {
            font-size: 2.5rem;
            font-weight: 700;
            margin: 10px 0;
        }
        
        .framework-score.good { color: var(--success); }
        .framework-score.warn { color: var(--warning); }
        .framework-score.bad { color: var(--danger); }
        
        .framework-stats {
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            color: var(--gray-600);
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid var(--gray-200);
        }
        
        .card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .card-header {
            background: var(--gray-100);
            padding: 15px 20px;
            border-bottom: 1px solid var(--gray-200);
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .card-body { padding: 20px; }
        
        table { width: 100%; border-collapse: collapse; table-layout: fixed; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--gray-200); word-wrap: break-word; overflow-wrap: break-word; }
        th { background: var(--gray-100); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }
        tr:hover { background: var(--gray-100); }
        .col-check { width: 14%; }
        .col-status { width: 7%; }
        .col-category { width: 9%; }
        .col-object { width: 15%; }
        .col-desc { width: 30%; }
        .col-remediation { width: 25%; }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .badge-success { background: #dff6dd; color: var(--success); }
        .badge-warning { background: #fff4ce; color: var(--warning); }
        .badge-danger { background: #fde7e9; color: var(--danger); }
        
        .severity-critical { color: #a4262c; font-weight: 700; }
        .severity-high { color: var(--danger); font-weight: 600; }
        .severity-medium { color: var(--warning); }
        
        .gap-item {
            border-left: 4px solid var(--danger);
            padding: 15px 20px;
            margin-bottom: 15px;
            background: white;
            border-radius: 0 8px 8px 0;
        }
        
        .gap-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        
        .gap-title { font-weight: 600; }
        .gap-meta { font-size: 0.85rem; color: var(--gray-600); }
        
        .gap-remediation {
            background: var(--gray-100);
            padding: 10px 15px;
            border-radius: 4px;
            font-size: 0.9rem;
            margin-top: 10px;
        }

        /* Data Sources — provenance cards + accordion reference table */
        .ds-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }
        .ds-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-top: 4px solid var(--primary);
            padding: 20px 22px;
            scroll-margin-top: 16px;
        }
        .ds-card.ds-securescore { border-top-color: #00bcf2; }
        .ds-card.ds-defender    { border-top-color: var(--purple); }
        .ds-card.ds-azurepolicy { border-top-color: #0089d6; }
        .ds-card.ds-purview     { border-top-color: #742774; }
        .ds-card.ds-internal    { border-top-color: var(--primary); }
        .ds-card-head {
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            margin-bottom: 4px;
        }
        .ds-card-head h3 { font-size: 1.05rem; }
        .ds-card-provider {
            font-size: 0.78rem;
            color: var(--gray-600);
            margin-bottom: 14px;
        }
        .ds-fields {
            display: grid;
            grid-template-columns: 110px 1fr;
            row-gap: 6px;
            column-gap: 12px;
            font-size: 0.85rem;
        }
        .ds-fields dt {
            color: var(--gray-600);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 0.03em;
            padding-top: 2px;
        }
        .ds-fields dd {
            margin: 0;
            color: var(--gray-800);
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        .ds-fields dd ul {
            margin: 0;
            padding-left: 18px;
        }
        .ds-fields dd ul li { margin-bottom: 2px; }
        .ds-fields dd code {
            background: var(--gray-100);
            padding: 1px 5px;
            border-radius: 3px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.78rem;
        }
        .ds-card-footer {
            margin-top: 14px;
            padding-top: 12px;
            border-top: 1px solid var(--gray-200);
            font-size: 0.82rem;
            color: var(--gray-600);
        }
        .ds-card-footer a { color: var(--primary); text-decoration: none; }
        .ds-card-footer a:hover { text-decoration: underline; }
        .ds-table-flyout {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 0;
            margin-top: 10px;
        }
        .ds-table-flyout summary {
            padding: 14px 22px;
            cursor: pointer;
            font-weight: 600;
            color: var(--gray-800);
            user-select: none;
        }
        .ds-table-flyout summary::marker { color: var(--primary); }
        .ds-table-flyout[open] summary {
            border-bottom: 1px solid var(--gray-200);
        }
        .ds-table-flyout-body {
            max-height: 520px;
            overflow: auto;
        }
        .ds-table-flyout-body table {
            table-layout: auto;
            min-width: 100%;
        }
        .ds-table-flyout-body th {
            position: sticky;
            top: 0;
            z-index: 1;
        }
        .ds-table-flyout-body td {
            font-size: 0.82rem;
            vertical-align: top;
        }
        a.ds-tile-link {
            color: inherit;
            text-decoration: none;
            display: block;
        }
        a.ds-tile-link:hover { background: rgba(255,255,255,0.18); }

        /* Findings — expandable rows ported from the standalone HTML report */
        .uf-findings-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .uf-finding {
            background: white;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            overflow: hidden;
        }
        .uf-finding > summary {
            padding: 12px 18px;
            cursor: pointer;
            list-style: none;
            display: grid;
            grid-template-columns: 90px 1fr 220px 110px 1.6fr 1fr 22px;
            gap: 14px;
            align-items: center;
            font-size: 0.88rem;
            user-select: none;
        }
        .uf-finding > summary::-webkit-details-marker { display: none; }
        .uf-finding > summary::marker { display: none; }
        .uf-finding > summary:hover { background: var(--gray-100); }
        .uf-finding[open] > summary { border-bottom: 1px solid var(--gray-200); }
        .uf-finding > summary .uf-caret {
            text-align: right;
            color: var(--gray-600);
            transition: transform 0.15s ease-in-out;
        }
        .uf-finding[open] > summary .uf-caret { transform: rotate(180deg); }
        .uf-finding-static > summary {
            cursor: default;
        }
        .uf-finding-static > summary:hover { background: transparent; }
        .uf-finding-static > summary .uf-caret { visibility: hidden; }
        .uf-headers {
            display: grid;
            grid-template-columns: 90px 1fr 220px 110px 1.6fr 1fr 22px;
            gap: 14px;
            padding: 10px 18px;
            background: var(--gray-100);
            font-weight: 600;
            font-size: 0.72rem;
            text-transform: uppercase;
            color: var(--gray-600);
            border-radius: 6px;
            margin-bottom: 8px;
            letter-spacing: 0.04em;
        }
        .uf-finding-body {
            padding: 16px 22px 20px;
            font-size: 0.9rem;
        }
        .uf-finding-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px 24px;
            margin-bottom: 12px;
            padding: 12px 14px;
            background: var(--gray-100);
            border-radius: 4px;
            font-size: 0.85rem;
        }
        .uf-remediation-steps {
            background: #e7f3ff;
            padding: 14px 18px;
            border-radius: 4px;
            margin-top: 12px;
        }
        .uf-remediation-steps h4 {
            color: var(--primary);
            margin-bottom: 8px;
            font-size: 0.95rem;
        }
        .uf-remediation-steps ol {
            margin-left: 20px;
            margin-bottom: 8px;
        }
        .uf-remediation-steps li { margin-bottom: 6px; }
        .uf-code-block {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 12px 14px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.82rem;
            margin: 8px 0;
            white-space: pre-wrap;
        }
        .uf-source-link {
            text-decoration: none;
        }
        .uf-source-link .source-badge {
            cursor: pointer;
        }
        .uf-source-link:hover .source-badge {
            filter: brightness(1.1);
        }

        footer {
            text-align: center;
            padding: 30px;
            color: var(--gray-600);
            font-size: 0.85rem;
        }
        
        @media print {
            body { background: white; }
            .card { break-inside: avoid; }
        }

$(if (Get-Command Get-PrivilegedIdentityRosterCss -ErrorAction SilentlyContinue) { Get-PrivilegedIdentityRosterCss } else { '' })
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Assessment Report</h1>
            <p>Comprehensive security findings, discovery, and compliance posture</p>
            <div class="meta-grid">
                <div class="meta-item">
                    <label>Organization</label>
                    <span>$TenantName</span>
                </div>
                <div class="meta-item">
                    <label>Assessment Date</label>
                    <span>$assessmentDate</span>
                </div>
                <div class="meta-item">
                    <label>Total Findings</label>
                    <span>$($Findings.Count)</span>
                </div>
                <a class="ds-tile-link" href="#data-sources" title="Jump to Data Sources">
                <div class="meta-item">
                    <label>Data Sources</label>
                    <span>$(($dataSources.GetEnumerator() | Where-Object { $_.Value.Available }).Count) Active &rarr;</span>
                </div>
                </a>
                $(if ($PrivilegedIdentityRoster -and (Get-Command Get-PrivilegedIdentityDashboardTile -ErrorAction SilentlyContinue)) { Get-PrivilegedIdentityDashboardTile -RosterInput $PrivilegedIdentityRoster } else { '' })
            </div>
        </header>
"@

    # Findings Summary Dashboard
    $fFailCount = @($Findings | Where-Object { $_.Status -eq 'FAIL' }).Count
    $fWarnCount = @($Findings | Where-Object { $_.Status -eq 'WARNING' }).Count
    $fOkCount = @($Findings | Where-Object { $_.Status -eq 'OK' }).Count
    $fInfoCount = @($Findings | Where-Object { $_.Status -eq 'INFO' }).Count

    $html += @"
        <h2 class="section-title">Security Findings Overview</h2>
        <div class="framework-grid">
            <div class="framework-card" style="border-top-color: var(--danger);">
                <h3>Failures</h3>
                <div class="source">Require immediate attention</div>
                <div class="framework-score bad">$fFailCount</div>
            </div>
            <div class="framework-card" style="border-top-color: var(--warning);">
                <h3>Warnings</h3>
                <div class="source">Recommended improvements</div>
                <div class="framework-score warn">$fWarnCount</div>
            </div>
            <div class="framework-card" style="border-top-color: var(--success);">
                <h3>Passed</h3>
                <div class="source">Correctly configured</div>
                <div class="framework-score good">$fOkCount</div>
            </div>
            <div class="framework-card" style="border-top-color: #0078d4;">
                <h3>Informational</h3>
                <div class="source">Discovery and inventory</div>
                <div class="framework-score" style="color: #0078d4;">$fInfoCount</div>
            </div>
        </div>
"@

    # All Assessment Findings — expandable rows. FAIL/WARNING findings expand
    # to show portal/PowerShell remediation pulled from EntraChecks-RemediationGuidance.
    if ($Findings -and $Findings.Count -gt 0) {
        # Enrich findings with detailed remediation guidance when the module is
        # available. Add-RemediationGuidance is idempotent — if a finding
        # already carries .RemediationGuidance, it's left untouched.
        $enrichedFindings = if (Get-Command Add-RemediationGuidance -ErrorAction SilentlyContinue) {
            @($Findings | ForEach-Object { $_ | Add-RemediationGuidance })
        }
        else { @($Findings) }

        $sourceClassMap = @{
            'Internal' = 'source-internal'
            'SecureScore' = 'source-securescore'
            'DefenderCompliance' = 'source-defender'
            'AzurePolicy' = 'source-azurepolicy'
            'PurviewCompliance' = 'source-purview'
        }
        $sourceLabelMap = @{
            'Internal' = 'EntraChecks'
            'SecureScore' = 'Secure Score'
            'DefenderCompliance' = 'Defender'
            'AzurePolicy' = 'Azure Policy'
            'PurviewCompliance' = 'Purview'
        }

        $html += @"

        <h2 class="section-title">All Assessment Findings ($($enrichedFindings.Count))</h2>
        <div class="uf-headers">
            <div>Status</div>
            <div>Check</div>
            <div>Object</div>
            <div>Source</div>
            <div>Description</div>
            <div>Remediation</div>
            <div></div>
        </div>
        <div class="uf-findings-list">
"@

        $sortedFindings = $enrichedFindings | Sort-Object @{Expression = {
                switch ($_.Status) { 'FAIL' { 0 } 'WARNING' { 1 } 'INFO' { 2 } 'OK' { 3 } default { 4 } }
            }
        }

        foreach ($f in $sortedFindings) {
            $fStatusBadge = switch ($f.Status) {
                'FAIL' { '<span class="badge badge-danger">FAIL</span>' }
                'WARNING' { '<span class="badge badge-warning">WARNING</span>' }
                'OK' { '<span class="badge badge-success">OK</span>' }
                default { '<span class="badge" style="background:#e0e0e0;color:#333;">INFO</span>' }
            }
            $fCheckName = [System.Net.WebUtility]::HtmlEncode($f.Check)
            if (-not $fCheckName) { $fCheckName = [System.Net.WebUtility]::HtmlEncode($f.CheckName) }
            $fObj = [System.Net.WebUtility]::HtmlEncode($f.Object)
            $fDesc = [System.Net.WebUtility]::HtmlEncode($f.Description)
            $fRem = [System.Net.WebUtility]::HtmlEncode($f.Remediation)

            $sourceKey = if ($f.Source) { [string]$f.Source } else { 'Internal' }
            $sourceCss = if ($sourceClassMap.ContainsKey($sourceKey)) { $sourceClassMap[$sourceKey] } else { 'source-internal' }
            $sourceLbl = if ($sourceLabelMap.ContainsKey($sourceKey)) { $sourceLabelMap[$sourceKey] } else { $sourceKey }
            $sourceBadgeHtml = "<a class=`"uf-source-link`" href=`"#data-source-$sourceKey`" title=`"Jump to $sourceLbl provenance card`"><span class=`"source-badge $sourceCss`">$sourceLbl</span></a>"

            # Body is meaningful only for FAIL/WARNING; OK/INFO render a static
            # row with no expand affordance to keep the list scannable.
            $hasFlyout = ($f.Status -in @('FAIL', 'WARNING'))
            $caret = if ($hasFlyout) { '&#9660;' } else { '' }
            $finOpen = '<details class="uf-finding">'
            if (-not $hasFlyout) {
                $finOpen = '<details class="uf-finding uf-finding-static">'
            }

            $bodyHtml = ''
            if ($hasFlyout) {
                $rg = $f.RemediationGuidance
                $portalSteps = ''
                $psSteps = ''
                $impactBlock = ''
                if ($rg) {
                    if ($rg.StepsPortal) {
                        $stepLis = ($rg.StepsPortal | ForEach-Object {
                                $line = ($_ -replace '^\d+\.\s*', '')
                                "<li>$([System.Net.WebUtility]::HtmlEncode($line))</li>"
                            }) -join ''
                        $portalSteps = @"
                <h4>&#128273; Remediation Steps (Azure Portal)</h4>
                <ol>$stepLis</ol>
"@
                    }
                    if ($rg.StepsPowerShell) {
                        $codeSafe = [System.Net.WebUtility]::HtmlEncode([string]$rg.StepsPowerShell)
                        $psSteps = @"
                <h4 style="margin-top: 12px;">&#128187; PowerShell Remediation</h4>
                <pre class="uf-code-block">$codeSafe</pre>
"@
                    }
                    if ($rg.Impact) {
                        $posSafe = [System.Net.WebUtility]::HtmlEncode([string]$rg.Impact.Positive)
                        $negSafe = [System.Net.WebUtility]::HtmlEncode([string]$rg.Impact.Negative)
                        $impactBlock = @"
                <p style="margin-top: 10px;"><strong>Impact:</strong> $posSafe</p>
                <p><strong>Considerations:</strong> $negSafe</p>
"@
                    }
                }

                $remediationBlock = if ($portalSteps -or $psSteps -or $impactBlock) {
                    @"
            <div class="uf-remediation-steps">
                $portalSteps
                $psSteps
                $impactBlock
            </div>
"@
                }
                else { '' }

                $bodyHtml = @"
        <div class="uf-finding-body">
            <div class="uf-finding-meta">
                <div><strong>Object:</strong> $fObj</div>
                <div><strong>Source:</strong> $sourceLbl</div>
                <div><strong>Status:</strong> $($f.Status)</div>
            </div>
            <p><strong>Description:</strong> $fDesc</p>
            <p><strong>Quick remediation:</strong> $fRem</p>
            $remediationBlock
        </div>
"@
            }

            $html += @"
        $finOpen
            <summary>
                <div>$fStatusBadge</div>
                <div><strong>$fCheckName</strong></div>
                <div>$fObj</div>
                <div>$sourceBadgeHtml</div>
                <div>$fDesc</div>
                <div style="font-size:0.82rem;">$fRem</div>
                <div class="uf-caret">$caret</div>
            </summary>
            $bodyHtml
        </details>
"@
        }
        $html += @"
        </div>
"@
    }

    # Privileged Identity Roster — rendered between Findings and Compliance Overview.
    # Skipped silently if no roster supplied OR the render module isn't loaded.
    if ($PrivilegedIdentityRoster -and (Get-Command Get-PrivilegedIdentityHtmlSection -ErrorAction SilentlyContinue)) {
        $matchSummary = if ($PrivilegedIdentityRoster -is [hashtable] -and $PrivilegedIdentityRoster.ContainsKey('Statistics')) { $PrivilegedIdentityRoster.Statistics } else { $null }
        $html += Get-PrivilegedIdentityHtmlSection -RosterInput $PrivilegedIdentityRoster -MatchSummary $matchSummary
    }

    $html += @"

        <h2 class="section-title">Compliance Overview by Framework</h2>
        <div class="framework-grid">
"@

    foreach ($framework in $unifiedData.Frameworks) {
        $scoreClass = if ($framework.Score -ge 80) { "good" } elseif ($framework.Score -ge 60) { "warn" } else { "bad" }
        $cardClass = switch ($framework.Source) {
            "DefenderForCloud" { "defender" }
            "SecureScore" { "securescore" }
            "AzurePolicy" { "azurepolicy" }
            "PurviewCompliance" { "purview" }
            default { "" }
        }
        $sourceLabel = switch ($framework.Source) {
            "Internal" { "EntraChecks" }
            "SecureScore" { "Microsoft Secure Score" }
            "DefenderForCloud" { "Defender for Cloud" }
            "AzurePolicy" { "Azure Policy" }
            "PurviewCompliance" { "Purview Compliance" }
            default { $framework.Source }
        }
        
        $html += @"
            <div class="framework-card $cardClass">
                <h3>$($framework.Name)</h3>
                <div class="source">Source: $sourceLabel</div>
                <div class="framework-score $scoreClass">$($framework.Score)%</div>
"@
        
        if ($null -ne $framework.Pass) {
            $html += @"
                <div class="framework-stats">
                    <span>Pass: $($framework.Pass)</span>
                    <span>Fail: $($framework.Fail)</span>
                    <span>Total: $($framework.Total)</span>
                </div>
"@
        }
        elseif ($null -ne $framework.Current) {
            $html += @"
                <div class="framework-stats">
                    <span>Score: $($framework.Current)/$($framework.Max)</span>
                </div>
"@
        }
        
        $html += @"
            </div>
"@
    }

    $html += @"
        </div>
"@

    # Top gaps section
    $topGaps = $unifiedData.AllGaps
    
    if ($topGaps.Count -gt 0) {
        $html += @"
        
        <h2 class="section-title">Priority Compliance Gaps</h2>
        <p style="margin-bottom: 20px; color: var(--gray-600);">All compliance gaps across frameworks and sources ($($topGaps.Count) total)</p>
"@

        foreach ($gap in $topGaps) {
            $sourceClass = switch ($gap.Source) {
                "DefenderForCloud" { "source-defender" }
                "SecureScore" { "source-securescore" }
                "AzurePolicy" { "source-azurepolicy" }
                "PurviewCompliance" { "source-purview" }
                default { "source-internal" }
            }
            $sourceLabel = switch ($gap.Source) {
                "DefenderForCloud" { "Defender" }
                "SecureScore" { "Secure Score" }
                "AzurePolicy" { "Azure Policy" }
                "PurviewCompliance" { "Purview" }
                default { "EntraChecks" }
            }
            
            $html += @"
        <div class="gap-item">
            <div class="gap-header">
                <div>
                    <div class="gap-title">$($gap.Title)</div>
                    <div class="gap-meta">$($gap.Framework) - $($gap.ControlId) <span class="source-badge $sourceClass">$sourceLabel</span></div>
                </div>
                <span class="severity-$($gap.Severity.ToLower())">$($gap.Severity)</span>
            </div>
            <div class="gap-remediation">
                <strong>Remediation:</strong> $($gap.Remediation)
            </div>
        </div>
"@
        }
    }

    # Data Sources — provenance cards + collapsed accordion reference table.
    # Cards give the rich per-source view; the table flyout below is the flat
    # "paste into evidence binder" view auditors want.
    $html += @"

        <h2 class="section-title" id="data-sources">Data Sources</h2>
        <p style="margin-bottom: 18px; color: var(--gray-600); font-size: 0.9rem;">
            Each card documents the API, cmdlet, scope, and runtime context that produced the data in this report.
            Expand the reference table below for a flat one-row-per-source view.
        </p>
        <div class="ds-grid">
"@

    $orderedKeys = @('Internal', 'SecureScore', 'DefenderCompliance', 'AzurePolicy', 'PurviewCompliance')
    $cardClassMap = @{
        'Internal' = 'ds-internal'
        'SecureScore' = 'ds-securescore'
        'DefenderCompliance' = 'ds-defender'
        'AzurePolicy' = 'ds-azurepolicy'
        'PurviewCompliance' = 'ds-purview'
    }
    $titleMap = @{
        'Internal' = 'EntraChecks Internal'
        'SecureScore' = 'Microsoft Secure Score'
        'DefenderCompliance' = 'Defender for Cloud Compliance'
        'AzurePolicy' = 'Azure Policy'
        'PurviewCompliance' = 'Purview Compliance Manager'
    }

    # Per-source "Result" line — preserves the existing at-a-glance details
    # (count of findings, score, subscription/standard counts) so we keep the
    # information density of the old table.
    function Get-DataSourceResultLine {
        param([string]$Key, [hashtable]$Source)
        if (-not $Source.Available) { return $null }
        switch ($Key) {
            'Internal' { return "$($Source.Data.FindingsCount) findings processed" }
            'SecureScore' { return "Score: $($Source.Data.ScorePercent)%" }
            'DefenderCompliance' { return "$($Source.Data.Summary.TotalSubscriptions) subscriptions, $($Source.Data.Summary.TotalStandards) standards" }
            'AzurePolicy' { return "$($Source.Data.Summary.TotalSubscriptions) subscriptions, $($Source.Data.Summary.TotalPolicies) policies" }
            'PurviewCompliance' {
                $pvSummary = @()
                if ($Source.Data.Summary.ComplianceScore) { $pvSummary += "Score: $($Source.Data.Summary.ComplianceScore)%" }
                if ($Source.Data.Summary.TotalAssessments) { $pvSummary += "$($Source.Data.Summary.TotalAssessments) assessments" }
                if ($pvSummary.Count -gt 0) { return ($pvSummary -join ', ') } else { return 'Data available' }
            }
        }
        return $null
    }

    function Format-DataSourceList {
        param([object]$Items, [switch]$AsCode)
        if (-not $Items -or @($Items).Count -eq 0) { return '<em style="color:var(--gray-600);">none</em>' }
        $lis = foreach ($i in @($Items)) {
            $safe = [System.Net.WebUtility]::HtmlEncode([string]$i)
            if ($AsCode) { "<li><code>$safe</code></li>" } else { "<li>$safe</li>" }
        }
        return "<ul>$($lis -join '')</ul>"
    }

    foreach ($dsKey in $orderedKeys) {
        if (-not $dataSources.ContainsKey($dsKey)) { continue }
        $src = $dataSources[$dsKey]
        $title = $titleMap[$dsKey]
        $cardClass = $cardClassMap[$dsKey]
        $statusBadge = if ($src.Available) {
            '<span class="badge badge-success">Active</span>'
        } else {
            '<span class="badge badge-warning">Not Available</span>'
        }

        $providerSafe = [System.Net.WebUtility]::HtmlEncode([string]$src.Provider)
        $endpointsHtml = Format-DataSourceList -Items $src.Endpoints -AsCode
        $cmdletsHtml = Format-DataSourceList -Items $src.Cmdlets -AsCode
        $scopesHtml = Format-DataSourceList -Items $src.Scopes

        $authLine = if ($src.AuthMethod) {
            $auth = [System.Net.WebUtility]::HtmlEncode([string]$src.AuthMethod)
            if ($src.Upn) { $auth += " &middot; " + [System.Net.WebUtility]::HtmlEncode([string]$src.Upn) }
            $auth
        } else { '<em style="color:var(--gray-600);">not yet queried</em>' }

        $tenantLine = if ($src.Tenant) { [System.Net.WebUtility]::HtmlEncode([string]$src.Tenant) } else { '&mdash;' }

        $subsLine = if ($src.Subscriptions -and @($src.Subscriptions).Count -gt 0) {
            ([System.Net.WebUtility]::HtmlEncode((@($src.Subscriptions) -join ', ')))
        } else { '&mdash;' }

        $queriedLine = if ($src.QueriedAt) { (Get-Date $src.QueriedAt -Format 'yyyy-MM-dd HH:mm:ss') + ' UTC' } else { '&mdash;' }

        $resultLine = Get-DataSourceResultLine -Key $dsKey -Source $src
        $resultHtml = if ($resultLine) {
            '<div class="ds-card-footer"><strong>Result:</strong> ' + [System.Net.WebUtility]::HtmlEncode($resultLine) + '</div>'
        } else { '' }

        $referenceHtml = if ($src.ReferenceUrl) {
            $url = [System.Net.WebUtility]::HtmlEncode([string]$src.ReferenceUrl)
            "<div class=`"ds-card-footer`"><a href=`"$url`" target=`"_blank`" rel=`"noopener`">$url &rarr;</a></div>"
        } else { '' }

        $html += @"
            <div class="ds-card $cardClass" id="data-source-$dsKey">
                <div class="ds-card-head">
                    <h3>$title</h3>
                    $statusBadge
                </div>
                <div class="ds-card-provider">$providerSafe</div>
                <dl class="ds-fields">
                    <dt>Endpoint</dt><dd>$endpointsHtml</dd>
                    <dt>Cmdlet</dt><dd>$cmdletsHtml</dd>
                    <dt>Scope</dt><dd>$scopesHtml</dd>
                    <dt>Auth</dt><dd>$authLine</dd>
                    <dt>Tenant</dt><dd><code>$tenantLine</code></dd>
                    <dt>Subscriptions</dt><dd>$subsLine</dd>
                    <dt>Queried</dt><dd>$queriedLine</dd>
                </dl>
                $resultHtml
                $referenceHtml
            </div>
"@
    }

    $html += @"
        </div>

        <details class="ds-table-flyout">
            <summary>Source reference table (flat view for evidence)</summary>
            <div class="ds-table-flyout-body">
                <table>
                    <thead>
                        <tr>
                            <th>Source</th>
                            <th>Status</th>
                            <th>Provider</th>
                            <th>Endpoint(s)</th>
                            <th>Cmdlet(s)</th>
                            <th>Scope</th>
                            <th>Auth</th>
                            <th>Tenant</th>
                            <th>Subscriptions</th>
                            <th>Queried</th>
                            <th>Reference</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    foreach ($dsKey in $orderedKeys) {
        if (-not $dataSources.ContainsKey($dsKey)) { continue }
        $src = $dataSources[$dsKey]
        $rowStatus = if ($src.Available) { '<span class="badge badge-success">Active</span>' } else { '<span class="badge badge-warning">Not Available</span>' }
        $endpointJoined = if ($src.Endpoints) { ((@($src.Endpoints)) -join '; ') } else { '' }
        $cmdletJoined = if ($src.Cmdlets) { ((@($src.Cmdlets)) -join '; ') } else { '' }
        $scopeJoined = if ($src.Scopes) { ((@($src.Scopes)) -join '; ') } else { '' }
        $tenantSafe = if ($src.Tenant) { [System.Net.WebUtility]::HtmlEncode([string]$src.Tenant) } else { '&mdash;' }
        $subsSafe = if ($src.Subscriptions -and @($src.Subscriptions).Count -gt 0) {
            [System.Net.WebUtility]::HtmlEncode((@($src.Subscriptions) -join ', '))
        } else { '&mdash;' }
        $queriedSafe = if ($src.QueriedAt) { (Get-Date $src.QueriedAt -Format 'yyyy-MM-dd HH:mm:ss') + ' UTC' } else { '&mdash;' }
        $authSafe = if ($src.AuthMethod) {
            $a = [System.Net.WebUtility]::HtmlEncode([string]$src.AuthMethod)
            if ($src.Upn) { $a += ' · ' + [System.Net.WebUtility]::HtmlEncode([string]$src.Upn) }
            $a
        } else { '&mdash;' }
        $refSafe = if ($src.ReferenceUrl) {
            $u = [System.Net.WebUtility]::HtmlEncode([string]$src.ReferenceUrl)
            "<a href=`"$u`" target=`"_blank`" rel=`"noopener`">link</a>"
        } else { '&mdash;' }

        $html += @"
                        <tr>
                            <td><strong>$($titleMap[$dsKey])</strong></td>
                            <td>$rowStatus</td>
                            <td>$([System.Net.WebUtility]::HtmlEncode([string]$src.Provider))</td>
                            <td><code>$([System.Net.WebUtility]::HtmlEncode($endpointJoined))</code></td>
                            <td><code>$([System.Net.WebUtility]::HtmlEncode($cmdletJoined))</code></td>
                            <td>$([System.Net.WebUtility]::HtmlEncode($scopeJoined))</td>
                            <td>$authSafe</td>
                            <td><code>$tenantSafe</code></td>
                            <td>$subsSafe</td>
                            <td>$queriedSafe</td>
                            <td>$refSafe</td>
                        </tr>
"@
    }

    $html += @"
                    </tbody>
                </table>
            </div>
        </details>

        <footer>
            <p>Generated by EntraChecks Unified Compliance Module v$script:ModuleVersion</p>
            <p>Aggregating: EntraChecks | Microsoft Secure Score | Defender for Cloud | Azure Policy | Purview Compliance</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Host "`n[OK] Unified HTML report: $htmlPath" -ForegroundColor Green
    
    # Export unified CSV
    $csvGapsPath = Join-Path $OutputDirectory "UnifiedCompliance-AllGaps-$timestamp.csv"
    $unifiedData.AllGaps | Select-Object Source, Framework, ControlId, Title, Status, Severity, Evidence, Remediation |
        Export-Csv -Path $csvGapsPath -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] All gaps CSV: $csvGapsPath" -ForegroundColor Green
    
    # Export framework summary
    $csvFrameworksPath = Join-Path $OutputDirectory "UnifiedCompliance-Frameworks-$timestamp.csv"
    $unifiedData.Frameworks | ForEach-Object { [PSCustomObject]$_ } |
        Export-Csv -Path $csvFrameworksPath -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Frameworks CSV: $csvFrameworksPath" -ForegroundColor Green
    
    Write-Host "`n[+] Unified Compliance Report Complete" -ForegroundColor Magenta
    
    return @{
        UnifiedData = $unifiedData
        HTMLReport = $htmlPath
        GapsCSV = $csvGapsPath
        FrameworksCSV = $csvFrameworksPath
        OutputDirectory = $OutputDirectory
    }
}

#endregion

# Update exports to include new function
Export-ModuleMember -Function @(
    'Initialize-ComplianceModule',
    'Get-CISComplianceMapping',
    'Get-NISTComplianceMapping',
    'Get-ComplianceGaps',
    'Get-ComplianceScore',
    'Export-ComplianceReportHTML',
    'Export-ComplianceReportCSV',
    'Export-ComplianceReport',
    'Invoke-ComplianceAssessment',
    'Export-UnifiedComplianceReport'
)

# Auto-initialize when module is imported
$null = Initialize-ComplianceModule
