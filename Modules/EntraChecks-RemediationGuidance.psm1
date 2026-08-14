# EntraChecks Remediation Guidance Module
# Provides actionable step-by-step remediation instructions

<#
.SYNOPSIS
    Provides detailed remediation guidance for EntraChecks findings.

.DESCRIPTION
    This module contains step-by-step instructions, PowerShell commands, and Azure Portal
    guidance for remediating security findings. Includes:
    - Detailed remediation steps
    - PowerShell scripts
    - Azure Portal navigation
    - Impact analysis
    - Testing verification
    - Rollback procedures

.NOTES
    Author: NamelessSaint
    Version: 1.0.0
#>

#region Remediation Guidance Data

$Script:RemediationGuidance = @{
    'MFA_Disabled' = @{
        Title = 'Enable Multi-Factor Authentication for All Users'
        Summary = 'Require MFA for all users to add an additional layer of security beyond passwords'
        Impact = @{
            Positive = 'Significantly reduces account compromise risk; Protects against password attacks'
            Negative = 'Users will need MFA device/app; Initial enrollment required; May cause support tickets'
        }
        Prerequisites = @(
            'Global Administrator or Authentication Policy Administrator role'
            'Microsoft Authenticator app or compatible MFA method'
            'Communication plan for user rollout'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Protection > Authentication methods'
            '3. Click on "Authentication methods" > "Policies"'
            '4. Enable Microsoft Authenticator and/or SMS/Phone authentication'
            '5. Navigate to Protection > Conditional Access'
            '6. Create new policy: "Require MFA for all users"'
            '7. Assignments > Users: Include "All users", Exclude "Emergency access accounts"'
            '8. Access controls > Grant: "Require multifactor authentication"'
            '9. Enable policy'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Identity.SignIns module

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Create Conditional Access policy to require MFA
$conditions = @{
    Users = @{
        IncludeUsers = @("All")
        ExcludeUsers = @() # Add emergency access accounts here
    }
    Applications = @{
        IncludeApplications = @("All")
    }
}

$grantControls = @{
    Operator = "OR"
    BuiltInControls = @("Mfa")
}

$params = @{
    DisplayName = "Require MFA for all users"
    State = "enabledForReportingButNotEnforced" # Start in report-only mode
    Conditions = $conditions
    GrantControls = $grantControls
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params

# After testing, enable the policy:
# Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId <PolicyId> -State "enabled"
'@
        Verification = @(
            'Test with a non-admin user account'
            'Sign out and sign back in - should prompt for MFA'
            'Verify MFA registration portal: https://aka.ms/mfasetup'
            'Check sign-in logs for MFA requirements'
        )
        Rollback = @(
            'Set Conditional Access policy to "Report-only" mode'
            'Or disable the policy temporarily'
            'Emergency access: Use break-glass admin account'
        )
        CommonIssues = @(
            'Issue: Users cannot enroll MFA | Solution: Verify authentication methods are enabled'
            'Issue: Policy not applying | Solution: Check user exclusions and policy scope'
            'Issue: MFA prompt every time | Solution: Configure trusted locations and remember MFA settings'
        )
        References = @(
            'https://learn.microsoft.com/entra/identity/authentication/tutorial-enable-azure-mfa'
            'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa'
        )
    }

    'MFA_AdminDisabled' = @{
        Title = 'Enable Multi-Factor Authentication for Admin Users'
        Summary = 'Require MFA for all administrative accounts as a critical security control'
        Impact = @{
            Positive = 'Protects privileged accounts from compromise; Required by compliance standards'
            Negative = 'Admins must enroll in MFA; May slow down admin access initially'
        }
        Prerequisites = @(
            'Global Administrator role'
            'MFA methods enabled (Microsoft Authenticator recommended)'
            'Emergency access accounts excluded from policy'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Protection > Conditional Access'
            '3. Create new policy: "Require MFA for administrators"'
            '4. Assignments > Users > Select "Directory roles"'
            '5. Select admin roles: Global Admin, Security Admin, etc.'
            '6. Exclude emergency access accounts'
            '7. Cloud apps: "All cloud apps"'
            '8. Access controls > Grant: "Require multifactor authentication"'
            '9. Enable policy'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Identity.SignIns module
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Get directory role IDs for admin roles
$adminRoles = @(
    "62e90394-69f5-4237-9190-012177145e10" # Global Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d" # Security Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8" # Helpdesk Administrator
    "b79dfe3e-3197-4047-8f90-e5e7f82e8ef2" # Privileged Role Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" # SharePoint Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1" # User Administrator
)

$conditions = @{
    Users = @{
        IncludeRoles = $adminRoles
        ExcludeUsers = @() # Add emergency access accounts
    }
    Applications = @{
        IncludeApplications = @("All")
    }
}

$grantControls = @{
    Operator = "OR"
    BuiltInControls = @("Mfa")
}

$params = @{
    DisplayName = "Require MFA for administrators"
    State = "enabled" # Can enforce immediately for admins
    Conditions = $conditions
    GrantControls = $grantControls
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params
'@
        Verification = @(
            'Sign in with admin account - should require MFA'
            'Verify all admin accounts have MFA registered'
            'Check sign-in logs for admin MFA compliance'
            'Test emergency access account still works'
        )
        Rollback = @(
            'Disable Conditional Access policy'
            'Use emergency access account if locked out'
        )
        CommonIssues = @(
            'Issue: Admin locked out | Solution: Use break-glass emergency account'
            'Issue: MFA not required for certain admins | Solution: Check role assignments and policy scope'
        )
        References = @(
            'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa'
        )
    }

    'LegacyAuth_Enabled' = @{
        Title = 'Block Legacy Authentication Protocols'
        Summary = 'Prevent sign-ins using legacy protocols that do not support modern authentication (MFA)'
        Impact = @{
            Positive = 'Blocks protocols vulnerable to password spray attacks; Enforces MFA capability'
            Negative = 'May break old email clients (Outlook 2010, older); POP3/IMAP apps may fail'
        }
        Prerequisites = @(
            'Global Administrator or Security Administrator role'
            'Inventory of applications using legacy auth (check sign-in logs)'
            'Plan to migrate users to modern authentication'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Protection > Conditional Access'
            '3. Create new policy: "Block legacy authentication"'
            '4. Assignments > Users: "All users" (or start with pilot group)'
            '5. Assignments > Cloud apps: "All cloud apps"'
            '6. Conditions > Client apps: Select "Exchange ActiveSync clients" and "Other clients"'
            '7. Access controls > Block access'
            '8. Start in "Report-only" mode to identify impact'
            '9. After validation, set to "Enabled"'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Identity.SignIns module
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$conditions = @{
    Users = @{
        IncludeUsers = @("All")
        ExcludeUsers = @() # Exclude service accounts if needed
    }
    Applications = @{
        IncludeApplications = @("All")
    }
    ClientAppTypes = @("exchangeActiveSync", "other") # Legacy auth protocols
}

$grantControls = @{
    Operator = "OR"
    BuiltInControls = @("Block")
}

$params = @{
    DisplayName = "Block legacy authentication"
    State = "enabledForReportingButNotEnforced" # Start with report-only
    Conditions = $conditions
    GrantControls = $grantControls
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params

# After testing period, enable the policy:
# Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId <PolicyId> -State "enabled"
'@
        Verification = @(
            'Run policy in report-only mode for 1-2 weeks'
            'Review sign-in logs for legacy auth attempts'
            'Contact affected users to update their applications'
            'Enable policy and monitor for issues'
        )
        Rollback = @(
            'Set policy to "Report-only" mode'
            'Or temporarily disable policy'
            'Allow specific users/apps via exclusions'
        )
        CommonIssues = @(
            'Issue: Email stops working | Solution: Update to modern Outlook client or configure OAuth'
            'Issue: Mobile app cannot sync | Solution: Update app or enable modern auth for Exchange Online'
            'Issue: Third-party app fails | Solution: Update app or work with vendor for modern auth support'
        )
        References = @(
            'https://learn.microsoft.com/entra/identity/conditional-access/block-legacy-authentication'
            'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/enable-or-disable-modern-authentication-in-exchange-online'
        )
    }

    'ConditionalAccess_Missing' = @{
        Title = 'Configure Conditional Access Policies'
        Summary = 'Implement risk-based access controls using Conditional Access'
        Impact = @{
            Positive = 'Fine-grained access control; Risk-based authentication; Compliance enforcement'
            Negative = 'Requires Azure AD P1/P2; More complex management; Potential user friction'
        }
        Prerequisites = @(
            'Azure AD Premium P1 or P2 license'
            'Global Administrator or Conditional Access Administrator role'
            'Understanding of organizational access requirements'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Protection > Conditional Access'
            '3. Create baseline policies:'
            '   a. Require MFA for all users'
            '   b. Require MFA for administrators'
            '   c. Block legacy authentication'
            '   d. Require compliant devices for access'
            '   e. Require MFA for risky sign-ins'
            '4. Configure each policy with appropriate conditions'
            '5. Test policies with pilot users'
            '6. Enable policies gradually'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Identity.SignIns module
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Example: Create risky sign-in policy
$conditions = @{
    Users = @{
        IncludeUsers = @("All")
        ExcludeUsers = @() # Emergency accounts
    }
    Applications = @{
        IncludeApplications = @("All")
    }
    SignInRiskLevels = @("high", "medium") # Requires Azure AD P2
}

$grantControls = @{
    Operator = "OR"
    BuiltInControls = @("Mfa")
}

$params = @{
    DisplayName = "Require MFA for risky sign-ins"
    State = "enabledForReportingButNotEnforced"
    Conditions = $conditions
    GrantControls = $grantControls
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params
'@
        Verification = @(
            'Test each policy with pilot users before organization-wide rollout'
            'Monitor sign-in logs for policy application'
            'Review report-only mode results'
            'Validate emergency access accounts are excluded'
        )
        Rollback = @(
            'Set policies to "Report-only" mode'
            'Disable problematic policies'
            'Use emergency access accounts if needed'
        )
        CommonIssues = @(
            'Issue: Users locked out | Solution: Check exclusions and emergency access'
            'Issue: Policy not applying | Solution: Verify license requirements and scope'
            'Issue: Conflicting policies | Solution: Review policy order and conditions'
        )
        References = @(
            'https://learn.microsoft.com/entra/identity/conditional-access/overview'
            'https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access'
        )
    }

    'AuditLog_NotEnabled' = @{
        Title = 'Enable Audit Logging'
        Summary = 'Enable comprehensive audit logging for security monitoring and compliance'
        Impact = @{
            Positive = 'Security event visibility; Compliance requirement; Investigation capability'
            Negative = 'Generates log data; May require additional storage; Licensing requirements'
        }
        Prerequisites = @(
            'Global Administrator role'
            'Azure AD Premium P1/P2 for extended retention'
            'Log Analytics workspace for long-term storage (optional)'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Identity > Monitoring & health > Audit logs'
            '3. Verify audit logs are being collected'
            '4. Navigate to Identity > Monitoring & health > Diagnostic settings'
            '5. Click "+ Add diagnostic setting"'
            '6. Select log categories: AuditLogs, SignInLogs, NonInteractiveUserSignInLogs'
            '7. Select destination: Log Analytics workspace (recommended)'
            '8. Save diagnostic settings'
        )
        StepsPowerShell = @'
# Requires: Az.Monitor and Microsoft.Graph modules
Connect-AzAccount
Connect-MgGraph -Scopes "Policy.ReadWrite.AuditLog"

# Create diagnostic setting to send logs to Log Analytics
$workspaceId = "/subscriptions/<SubscriptionId>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<WorkspaceName>"

$logCategories = @(
    @{Category = "AuditLogs"; Enabled = $true}
    @{Category = "SignInLogs"; Enabled = $true}
    @{Category = "NonInteractiveUserSignInLogs"; Enabled = $true}
    @{Category = "ServicePrincipalSignInLogs"; Enabled = $true}
    @{Category = "ManagedIdentitySignInLogs"; Enabled = $true}
    @{Category = "ProvisioningLogs"; Enabled = $true}
    @{Category = "RiskyUsers"; Enabled = $true}
    @{Category = "UserRiskEvents"; Enabled = $true}
)

$diagnosticSetting = @{
    WorkspaceId = $workspaceId
    Logs = $logCategories
}

# Note: Set-AzDiagnosticSetting requires resource ID for Azure AD
# Use Azure Portal or REST API for Azure AD diagnostic settings
'@
        Verification = @(
            'Navigate to Audit logs in Azure AD portal'
            'Verify recent activities are logged'
            'Check Log Analytics workspace for ingested logs'
            'Run sample KQL query to validate data'
        )
        Rollback = @(
            'N/A - Audit logging should always be enabled'
            'Can disable diagnostic settings if storage costs are a concern'
        )
        CommonIssues = @(
            'Issue: Logs not appearing | Solution: Check diagnostic settings configuration and permissions'
            'Issue: Retention too short | Solution: Configure Log Analytics for longer retention'
            'Issue: High costs | Solution: Optimize log categories and retention policies'
        )
        References = @(
            'https://learn.microsoft.com/entra/identity/monitoring-health/howto-integrate-activity-logs-with-azure-monitor-logs'
            'https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs'
        )
    }

    'GlobalAdmin_Multiple' = @{
        Title = 'Reduce Number of Global Administrators'
        Summary = 'Limit Global Administrator role to minimum required accounts (recommended: 2-4)'
        Impact = @{
            Positive = 'Reduces attack surface; Limits privilege escalation risk; Compliance alignment'
            Negative = 'May require role re-assignment; Users lose some access initially'
        }
        Prerequisites = @(
            'Global Administrator role'
            'Review of current Global Admins and their needs'
            'Alternative role mapping (User Admin, Security Admin, etc.)'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Identity > Roles & admins > Roles & admins'
            '3. Click "Global Administrator" role'
            '4. Review list of current Global Administrators'
            '5. For each admin, determine if they need full Global Admin rights'
            '6. Assign more specific roles where possible:'
            '   - User Administrator (for user management)'
            '   - Security Administrator (for security settings)'
            '   - Application Administrator (for app registrations)'
            '7. Remove Global Administrator role from users who received alternative roles'
            '8. Maintain 2-4 Global Admins plus 1-2 emergency access accounts'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Identity.DirectoryManagement module
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# Get all Global Administrators
$globalAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'"
$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id

Write-Host "Current Global Administrators: $($globalAdmins.Count)" -ForegroundColor Yellow
$globalAdmins | ForEach-Object {
    $user = Get-MgUser -UserId $_.Id
    Write-Host "  - $($user.DisplayName) ($($user.UserPrincipalName))"
}

# Example: Assign User Administrator role instead
$userAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'User Administrator'"
$userId = "<UserId-to-change>"

# Add to User Administrator role
New-MgDirectoryRoleMemberByRef -DirectoryRoleId $userAdminRole.Id -BodyParameter @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$userId"
}

# Remove from Global Administrator (only after verifying alternative access)
# Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $userId
'@
        Verification = @(
            'Verify Global Admin count reduced to 2-4 active users'
            'Test that reassigned users can still perform their job functions'
            'Verify emergency access accounts are properly configured'
            'Document who has Global Admin access and why'
        )
        Rollback = @(
            'Re-assign Global Administrator role if needed'
            'Maintain list of previous Global Admins for quick restoration'
        )
        CommonIssues = @(
            'Issue: User cannot perform task | Solution: Assign additional specific role (e.g., Exchange Admin)'
            'Issue: Too restrictive | Solution: Use Privileged Identity Management (PIM) for just-in-time access'
            'Issue: Compliance audit failure | Solution: Document all Global Admins with business justification'
        )
        References = @(
            'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices'
            'https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference'
        )
    }

    'SecurityDefaults_Disabled' = @{
        Title = 'Enable Security Defaults (If Not Using Conditional Access)'
        Summary = 'Enable baseline security controls for organizations without Conditional Access'
        Impact = @{
            Positive = 'Free baseline security; Enforces MFA for admins; Blocks legacy auth'
            Negative = 'Less flexible than Conditional Access; All-or-nothing approach'
        }
        Prerequisites = @(
            'Global Administrator role'
            'No Conditional Access policies in place (Security Defaults and CA are mutually exclusive)'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Identity > Overview > Properties'
            '3. Click "Manage security defaults"'
            '4. Set "Security defaults" to "Enabled"'
            '5. Click "Save"'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Identity.SignIns module
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Enable Security Defaults
$params = @{
    IsEnabled = $true
}

Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params

# Verify status
Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Select-Object IsEnabled
'@
        Verification = @(
            'Verify Security Defaults is enabled'
            'Test admin MFA requirement'
            'Verify legacy auth is blocked'
        )
        Rollback = @(
            'Disable Security Defaults via portal or PowerShell'
        )
        CommonIssues = @(
            'Issue: Cannot enable with Conditional Access | Solution: Choose one approach (CA recommended for enterprises)'
            'Issue: Too restrictive | Solution: Consider upgrading to Azure AD P1 and using Conditional Access instead'
        )
        References = @(
            'https://learn.microsoft.com/entra/fundamentals/security-defaults'
        )
    }
}

#endregion

#region Public Functions

function Get-RemediationGuidance {
    <#
    .SYNOPSIS
        Retrieves remediation guidance for a finding type.

    .DESCRIPTION
        Returns detailed remediation instructions including steps, scripts, and verification procedures.

    .PARAMETER FindingType
        The type of finding to get remediation guidance for

    .EXAMPLE
        Get-RemediationGuidance -FindingType "MFA_Disabled"
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FindingType
    )

    if ($Script:RemediationGuidance.ContainsKey($FindingType)) {
        return $Script:RemediationGuidance[$FindingType]
    }

    # Return generic guidance if specific guidance not available
    return @{
        Title = "Remediation Required"
        Summary = "Please review this finding and implement appropriate controls"
        Impact = @{
            Positive = "Improved security posture"
            Negative = "May require configuration changes"
        }
        Prerequisites = @("Administrative access required")
        StepsPortal = @("Refer to Microsoft documentation for specific guidance")
        StepsPowerShell = "# No automated remediation available"
        Verification = @("Verify the security control is in place")
        Rollback = @("Review changes before implementing")
        CommonIssues = @("Consult Microsoft documentation")
        References = @("https://learn.microsoft.com/entra/")
    }
}

function Add-RemediationGuidance {
    <#
    .SYNOPSIS
        Adds remediation guidance to a finding object.

    .DESCRIPTION
        Enhances a finding with detailed remediation instructions.

    .PARAMETER Finding
        The finding object to enhance

    .EXAMPLE
        $finding | Add-RemediationGuidance
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Finding
    )

    process {
        $findingType = if ($null -ne $Finding.Type) { $Finding.Type } elseif ($null -ne $Finding.CheckType) { $Finding.CheckType } else { $Finding.Category }

        if ($findingType) {
            $guidance = Get-RemediationGuidance -FindingType $findingType
            $Finding | Add-Member -NotePropertyName 'RemediationGuidance' -NotePropertyValue $guidance -Force
        }

        return $Finding
    }
}

function Format-RemediationSteps {
    <#
    .SYNOPSIS
        Formats remediation guidance for display.

    .DESCRIPTION
        Converts remediation guidance into formatted output for reports.

    .PARAMETER FindingType
        The type of finding

    .PARAMETER Format
        Output format: 'Text', 'HTML', 'Markdown'

    .PARAMETER IncludeSections
        Sections to include: 'All', 'StepsOnly', 'SummaryOnly'

    .EXAMPLE
        Format-RemediationSteps -FindingType "MFA_Disabled" -Format "HTML"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FindingType,

        [ValidateSet('Text', 'HTML', 'Markdown')]
        [string]$Format = 'Text',

        [ValidateSet('All', 'StepsOnly', 'SummaryOnly')]
        [string]$IncludeSections = 'All'
    )

    $guidance = Get-RemediationGuidance -FindingType $FindingType
    $output = @()

    switch ($Format) {
        'HTML' {
            $output += "<div class='remediation-guidance'>"

            if ($IncludeSections -ne 'StepsOnly') {
                $output += "<h3>$($guidance.Title)</h3>"
                $output += "<p class='summary'>$($guidance.Summary)</p>"

                $output += "<div class='impact'>"
                $output += "<h4>Impact Analysis</h4>"
                $output += "- [+] Positive: $($guidance.Impact.Positive)"
                $output += "- [!] Considerations: $($guidance.Impact.Negative)"
                $output += "</div>"
            }

            if ($IncludeSections -ne 'SummaryOnly') {
                $output += "<div class='steps'>"
                $output += "<h4>Remediation Steps (Azure Portal)</h4>"
                $output += "<ol>"
                foreach ($step in $guidance.StepsPortal) {
                    $output += "<li>$step</li>"
                }
                $output += "</ol>"
                $output += "</div>"

                $output += "<div class='powershell'>"
                $output += "<h4>PowerShell Remediation</h4>"
                $output += "<pre><code>$($guidance.StepsPowerShell)</code></pre>"
                $output += "</div>"
            }

            $output += "</div>"
        }
        'Markdown' {
            if ($IncludeSections -ne 'StepsOnly') {
                $output += "### $($guidance.Title)"
                $output += ""
                $output += "**Summary:** $($guidance.Summary)"
                $output += ""
                $output += "**Impact:**"
                $output += "- [+] Positive: $($guidance.Impact.Positive)"
                $output += "- [!] Considerations: $($guidance.Impact.Negative)"
                $output += ""
            }

            if ($IncludeSections -ne 'SummaryOnly') {
                $output += "#### Remediation Steps (Azure Portal)"
                $output += ""
                foreach ($step in $guidance.StepsPortal) {
                    $output += $step
                }
                $output += ""
                $output += "#### PowerShell Remediation"
                $output += '```powershell'
                $output += $guidance.StepsPowerShell
                $output += '```'
                $output += ""
            }
        }
        'Text' {
            if ($IncludeSections -ne 'StepsOnly') {
                $output += $guidance.Title
                $output += "= " * $guidance.Title.Length
                $output += ""
                $output += "Summary: $($guidance.Summary)"
                $output += ""
                $output += "Impact:"
                $output += "  [+] $($guidance.Impact.Positive)"
                $output += "  [-] $($guidance.Impact.Negative)"
                $output += ""
            }

            if ($IncludeSections -ne 'SummaryOnly') {
                $output += "Remediation Steps (Azure Portal):"
                $output += "-" * 40
                $guidance.StepsPortal | ForEach-Object { $output += $_ }
                $output += ""
                $output += "PowerShell Remediation:"
                $output += "-" * 40
                $output += $guidance.StepsPowerShell
                $output += ""
            }
        }
    }

    return ($output -join "`n")
}

#endregion

#region Export Module Members

Export-ModuleMember -Function @(
    'Get-RemediationGuidance',
    'Add-RemediationGuidance',
    'Format-RemediationSteps'
)

#endregion
