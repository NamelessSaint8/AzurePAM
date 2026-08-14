# EntraChecks Extended Remediation Guidance Module
# Comprehensive remediation instructions with best practices for all 24 checks

<#
.SYNOPSIS
    Extended remediation guidance covering all EntraChecks security findings.

.DESCRIPTION
    This module extends the base RemediationGuidance module with comprehensive
    coverage for all 24 security checks, including:
    - Detailed step-by-step remediation (Portal & PowerShell)
    - Best practices and security implications
    - Common pitfalls and how to avoid them
    - Compliance framework context
    - Rollback procedures
    - Testing and verification steps

.NOTES
    Author: NamelessSaint
    Version: 2.0.0
    Extends: EntraChecks-RemediationGuidance.psm1
#>

# Import base remediation guidance
$modulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $modulePath "EntraChecks-RemediationGuidance.psm1") -Force

#region Extended Remediation Guidance

$Script:ExtendedRemediationGuidance = @{

    'PasswordNeverExpires' = @{
        Title = 'Enable Password Expiration for User Accounts'
        Summary = 'Configure password expiration policies to enforce regular password changes'
        BestPractices = @(
            'Set password expiration to 90 days for standard users'
            'Implement self-service password reset (SSPR) to reduce help desk calls'
            'Exclude service accounts and use Azure AD service principals instead'
            'Consider passwordless authentication (Windows Hello, FIDO2) as an alternative'
            'Combine with strong password complexity requirements'
        )
        SecurityImplications = @{
            Risk = 'Passwords that never expire increase the window for credential compromise'
            Impact = 'Reduces effectiveness of password-based attacks over time'
            Compliance = @('CIS Microsoft 365 1.1.3', 'NIST 800-53 IA-5', 'PCI-DSS Req 8.2.4')
        }
        Prerequisites = @(
            'Global Administrator or User Administrator role'
            'Microsoft Graph PowerShell SDK installed'
            'Understanding of service account requirements'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Identity > Users > All users'
            '3. Select the user account with password never expires'
            '4. Click "Password"'
            '5. Uncheck "Password never expires"'
            '6. Click "Save"'
            '7. Repeat for each affected user'
            ''
            'For bulk operations:'
            '1. Navigate to Identity > Users > User settings'
            '2. Under "Password expiration policy" ensure proper settings are configured'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Users module
Connect-MgGraph -Scopes "User.ReadWrite.All"

# Find all users with password never expires
$usersNeverExpire = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,PasswordPolicies |
    Where-Object { $_.PasswordPolicies -match "DisablePasswordExpiration" }

Write-Host "Found $($usersNeverExpire.Count) users with password never expires" -ForegroundColor Yellow

# Review each user before making changes
foreach ($user in $usersNeverExpire) {
    Write-Host "User: $($user.DisplayName) ($($user.UserPrincipalName))"

    # Prompt for confirmation or auto-fix service accounts differently
    $isServiceAccount = $user.UserPrincipalName -match "svc|service|app|admin"

    if ($isServiceAccount) {
        Write-Host "  [!] Appears to be service account - consider converting to service principal" -ForegroundColor Yellow
        continue
    }

    # Remove DisablePasswordExpiration policy
    $currentPolicies = $user.PasswordPolicies
    $newPolicies = $currentPolicies -replace "DisablePasswordExpiration", "" -replace ",,", ","
    $newPolicies = $newPolicies.Trim(',')

    Update-MgUser -UserId $user.Id -PasswordPolicies $newPolicies
    Write-Host "  [OK] Password expiration enabled" -ForegroundColor Green
}

# Verify changes
Get-MgUser -All -Property UserPrincipalName,PasswordPolicies |
    Where-Object { $_.PasswordPolicies -match "DisablePasswordExpiration" } |
    Select-Object UserPrincipalName, PasswordPolicies
'@
        Verification = @(
            'Run PowerShell verification: Get-MgUser -All -Property PasswordPolicies | Where-Object { $_.PasswordPolicies -match "DisablePasswordExpiration" }'
            'Verify count is zero or only includes intentional exceptions'
            'Test user password expiration notification emails are being sent'
            'Check Azure AD logs for password policy updates'
        )
        Rollback = @(
            'Re-apply "Password never expires" if needed: Update-MgUser -UserId <UserId> -PasswordPolicies "DisablePasswordExpiration"'
            'Consider implementing service principals for service accounts instead of rolling back'
        )
        CommonPitfalls = @(
            'Pitfall: Breaking automated processes that use service accounts | Solution: Identify service accounts first and migrate to service principals'
            'Pitfall: Users not prepared for password changes | Solution: Implement self-service password reset and communicate policy changes'
            'Pitfall: Help desk overwhelmed by password reset requests | Solution: Enable SSPR before rolling out password expiration'
        )
        References = @(
            'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-howitworks'
            'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad'
        )
    }

    'DirectoryRoles_TooManyGlobalAdmins' = @{
        Title = 'Reduce Number of Global Administrators'
        Summary = 'Limit Global Administrator role to minimum required (2-4 accounts plus emergency access)'
        BestPractices = @(
            'Maintain only 2-4 active Global Administrator accounts'
            'Create 2 emergency access (break-glass) accounts stored securely offline'
            'Use Privileged Identity Management (PIM) for just-in-time admin access'
            'Assign least-privileged roles instead (User Admin, Security Admin, etc.)'
            'Document all Global Admin assignments with business justification'
            'Review Global Admin assignments quarterly'
        )
        SecurityImplications = @{
            Risk = 'Excessive Global Admins increases attack surface and privilege escalation risk'
            Impact = 'Limits blast radius of compromised admin accounts'
            Compliance = @('CIS Microsoft 365 1.2.1', 'NIST 800-53 AC-6', 'SOC 2 CC6.3')
        }
        Prerequisites = @(
            'Global Administrator role (to make changes)'
            'Review of current Global Admins and their responsibilities'
            'Mapping of alternative roles for each admin'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Identity > Roles & admins > Roles & admins'
            '3. Click "Global Administrator" role'
            '4. Review current assignments - note who needs this role vs. alternative'
            ''
            '5. For each admin who does NOT need full Global Admin:'
            '   a. Determine appropriate alternative role:'
            '      - User Administrator: User/group management'
            '      - Security Administrator: Security policies, MFA'
            '      - Application Administrator: App registrations'
            '      - Exchange Administrator: Exchange Online management'
            '      - SharePoint Administrator: SharePoint Online management'
            '   b. Click "+ Add assignments" in the alternative role'
            '   c. Search for and select the user'
            '   d. Choose assignment type: Eligible (PIM) or Active'
            '   e. Click "Next" then "Assign"'
            ''
            '6. After assigning alternative role, verify user can perform their duties'
            '7. Return to Global Administrator role'
            '8. Select the user assignment'
            '9. Click "Remove assignment"'
            '10. Confirm removal'
            ''
            '11. Final verification:'
            '    - 2-4 active Global Admins for operations'
            '    - 1-2 emergency access accounts (excluded from MFA/CA)'
            '    - All others reassigned to least-privileged roles'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Identity.DirectoryManagement module
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory","Directory.Read.All"

# Get Global Administrator role
$globalAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'"

# List current Global Admins
$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
Write-Host "`n[!] Current Global Administrators: $($globalAdmins.Count)" -ForegroundColor Yellow

$adminDetails = @()
foreach ($admin in $globalAdmins) {
    $user = Get-MgUser -UserId $admin.Id -Property DisplayName,UserPrincipalName,AccountEnabled
    $adminDetails += [PSCustomObject]@{
        DisplayName = $user.DisplayName
        UPN = $user.UserPrincipalName
        Enabled = $user.AccountEnabled
        Id = $user.Id
    }
    Write-Host "  - $($user.DisplayName) ($($user.UserPrincipalName))" -ForegroundColor Gray
}

# Export for review
$adminDetails | Export-Csv -Path ".\GlobalAdmins-Review-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

Write-Host "`n[i] Review the CSV and determine alternative roles for each admin" -ForegroundColor Cyan
Write-Host "[i] Then use the following commands to reassign:" -ForegroundColor Cyan

# Example: Assign User Administrator role
<#
$userAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'User Administrator'"
$userId = "<UserId-from-review>"

# Add to User Administrator
New-MgDirectoryRoleMemberByRef -DirectoryRoleId $userAdminRole.Id -BodyParameter @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$userId"
}

# Verify user can perform their tasks before removing Global Admin

# Remove from Global Administrator (only after verification!)
Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $userId
Write-Host "[OK] Removed from Global Administrator role" -ForegroundColor Green
#>

# Alternative roles reference:
$alternativeRoles = @{
    'User Administrator' = 'User/group management, password resets'
    'Security Administrator' = 'Security policies, read logs, manage Entra ID Protection'
    'Application Administrator' = 'Create and manage app registrations, enterprise apps'
    'Authentication Administrator' = 'Reset passwords, manage authentication methods'
    'Compliance Administrator' = 'Compliance management, DLP, retention'
    'Exchange Administrator' = 'Exchange Online management'
    'SharePoint Administrator' = 'SharePoint Online management'
    'Privileged Role Administrator' = 'Manage role assignments, PIM settings'
    'Conditional Access Administrator' = 'Create and manage Conditional Access policies'
}

Write-Host "`n[i] Alternative Roles Available:" -ForegroundColor Cyan
$alternativeRoles.GetEnumerator() | ForEach-Object {
    Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Gray
}
'@
        Verification = @(
            'Verify Global Admin count: (Get-MgDirectoryRole -Filter "DisplayName eq ''Global Administrator''" | Get-MgDirectoryRoleMember).Count'
            'Target: 4-6 total (2-4 active admins + 2 emergency access)'
            'Test that reassigned users can still perform their job functions'
            'Document all Global Admin assignments with business justification'
            'Set up PIM alerts for Global Admin activations'
        )
        Rollback = @(
            'Re-assign Global Administrator role if critical duties cannot be performed'
            'Use PIM for temporary elevation instead of permanent assignment'
            'Emergency access accounts can restore access if needed'
        )
        CommonPitfalls = @(
            'Pitfall: Removing too many admins at once | Solution: Implement gradually, verify each change'
            'Pitfall: No emergency access plan | Solution: Create break-glass accounts before reducing Global Admins'
            'Pitfall: Users cannot perform tasks | Solution: Use PIM for just-in-time elevation instead of permanent roles'
            'Pitfall: No documentation | Solution: Document who has what role and why before making changes'
        )
        References = @(
            'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices'
            'https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference'
            'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access'
        )
    }

    'InactiveUsers' = @{
        Title = 'Disable or Remove Inactive User Accounts'
        Summary = 'Identify and disable accounts that have not signed in for 90+ days'
        BestPractices = @(
            'Define inactive threshold (typically 90 days for standard users, 30 days for privileged users)'
            'Implement automated account lifecycle management'
            'Disable accounts first (60 days), then delete if still inactive (additional 30 days)'
            'Exclude service accounts and emergency access accounts from automation'
            'Review shared mailboxes separately - they should not sign in'
            'Set up alerts for newly inactive accounts'
        )
        SecurityImplications = @{
            Risk = 'Inactive accounts are targets for compromise and privilege escalation'
            Impact = 'Reduces attack surface and license costs'
            Compliance = @('CIS Microsoft 365 1.1.8', 'NIST 800-53 AC-2', 'SOC 2 CC6.1')
        }
        Prerequisites = @(
            'User Administrator or Global Administrator role'
            'Sign-in logs access (requires Azure AD Premium P1)'
            'Stakeholder approval process for account disablement'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Identity > Users > All users'
            '3. Click "Add filter" > "Last sign-in date"'
            '4. Select "Before" and enter date (e.g., 90 days ago)'
            '5. Review the list - verify these are truly inactive:'
            '   - Check if accounts are service accounts (should use service principals)'
            '   - Check if accounts are temporary/vendor accounts'
            '   - Verify with managers before disabling'
            ''
            'For each inactive user:'
            '6. Select the user'
            '7. Click "Edit properties"'
            '8. Under "Account status" toggle "Block sign-in" to ON'
            '9. Click "Save"'
            '10. Add note to user description: "Disabled due to inactivity - [Date]"'
            ''
            'After 30 additional days of inactivity:'
            '11. Delete the disabled account if no reactivation request received'
            ''
            'Best practice - Automated approach:'
            '1. Navigate to Identity > Governance > Access reviews'
            '2. Create recurring access review for inactive users'
            '3. Set scope: Users inactive for X days'
            '4. Auto-disable accounts if managers do not respond'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Users, Microsoft.Graph.Reports modules
Connect-MgGraph -Scopes "User.ReadWrite.All","AuditLog.Read.All"

# Define inactivity threshold
$inactiveDays = 90
$thresholdDate = (Get-Date).AddDays(-$inactiveDays)

Write-Host "[+] Finding users inactive for more than $inactiveDays days..." -ForegroundColor Cyan

# Get all users with sign-in activity
$inactiveUsers = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,SignInActivity,UserType,Mail |
    Where-Object {
        $_.AccountEnabled -eq $true -and
        $_.UserType -eq "Member" -and
        (
            $null -eq $_.SignInActivity -or
            $null -eq $_.SignInActivity.LastSignInDateTime -or
            $_.SignInActivity.LastSignInDateTime -lt $thresholdDate
        )
    }

Write-Host "  Found $($inactiveUsers.Count) inactive user accounts" -ForegroundColor Yellow

# Export for review
$report = $inactiveUsers | Select-Object `
    DisplayName,
    UserPrincipalName,
    @{N='LastSignIn';E={$_.SignInActivity.LastSignInDateTime}},
    @{N='DaysInactive';E={
        if ($null -ne $_.SignInActivity.LastSignInDateTime) {
            [int]((Get-Date) - $_.SignInActivity.LastSignInDateTime).TotalDays
        } else {
            "Never signed in"
        }
    }},
    Mail,
    Id

$report | Export-Csv -Path ".\InactiveUsers-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
Write-Host "[OK] Exported report: .\InactiveUsers-$(Get-Date -Format 'yyyyMMdd').csv" -ForegroundColor Green

# Review and confirm before disabling
Write-Host "`n[!] Review the exported CSV file before proceeding" -ForegroundColor Yellow
Write-Host "[!] Verify accounts are truly inactive and not service accounts" -ForegroundColor Yellow

$proceed = Read-Host "Proceed with disabling accounts? (yes/no)"
if ($proceed -ne "yes") {
    Write-Host "[i] Cancelled - no changes made" -ForegroundColor Cyan
    return
}

# Disable inactive accounts
foreach ($user in $inactiveUsers) {
    Write-Host "Disabling: $($user.DisplayName) ($($user.UserPrincipalName))"

    Update-MgUser -UserId $user.Id -AccountEnabled:$false

    # Optionally add note to description
    # $currentDesc = (Get-MgUser -UserId $user.Id -Property OnPremisesExtensionAttributes).OnPremisesExtensionAttributes
    # Update description with inactivity notice

    Write-Host "  [OK] Account disabled" -ForegroundColor Green
}

Write-Host "`n[OK] Disabled $($inactiveUsers.Count) inactive accounts" -ForegroundColor Green
Write-Host "[i] Monitor for 30 days before deleting" -ForegroundColor Cyan
'@
        Verification = @(
            'Verify disabled accounts: Get-MgUser -Filter "accountEnabled eq false" -ConsistencyLevel eventual -Count userCount'
            'Review sign-in logs to ensure no sign-in attempts from disabled accounts'
            'Set calendar reminder to delete accounts after 30 days if no reactivation requests'
            'Monitor help desk tickets for account reactivation requests'
        )
        Rollback = @(
            'Re-enable account: Update-MgUser -UserId <UserId> -AccountEnabled:$true'
            'User will receive account enabled email notification'
            'Reset password if security concern about why account was inactive'
        )
        CommonPitfalls = @(
            'Pitfall: Disabling service accounts breaks automation | Solution: Tag service accounts and exclude from review'
            'Pitfall: Seasonal workers marked as inactive | Solution: Document seasonal accounts and review separately'
            'Pitfall: Shared mailboxes appear inactive | Solution: Shared mailboxes should not be sign-in enabled'
            'Pitfall: No notification to users | Solution: Send email notice before disabling accounts'
        )
        References = @(
            'https://learn.microsoft.com/entra/identity/governance/access-reviews-overview'
            'https://learn.microsoft.com/entra/identity/monitoring-health/howto-manage-inactive-user-accounts'
        )
    }

    'GuestUsers_Unrestricted' = @{
        Title = 'Restrict Guest User Permissions'
        Summary = 'Configure guest user access restrictions to limit directory enumeration'
        BestPractices = @(
            'Set guest user access to "most restrictive" (limited to own object properties)'
            'Review guest users quarterly for continued business need'
            'Implement expiration dates on guest invitations'
            'Require multi-factor authentication for guest users'
            'Use entitlement management for structured guest access'
            'Monitor guest user sign-in activity'
        )
        SecurityImplications = @{
            Risk = 'Unrestricted guests can enumerate all users, groups, and applications'
            Impact = 'Prevents information disclosure to external users'
            Compliance = @('CIS Microsoft 365 1.3.1', 'NIST 800-53 AC-3', 'SOC 2 CC6.1')
        }
        Prerequisites = @(
            'Global Administrator role'
            'Review of current guest users and their access needs'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Identity > External Identities > External collaboration settings'
            '3. Scroll to "Guest user access restrictions"'
            '4. Select "Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)"'
            '5. Click "Save"'
            ''
            'Additional best practices:'
            '6. Under "Guest invite settings":'
            '   - Set "Admins and users in the guest inviter role can invite" or more restrictive'
            '   - Enable "Guest users can invite" only if business requires it (not recommended)'
            '7. Under "Collaboration restrictions":'
            '   - Configure allowed/denied domains if needed'
            '8. Navigate to Identity > Governance > Entitlement management'
            '9. Create access packages for structured guest access'
            '10. Set expiration policies (e.g., 90 days) on guest access packages'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Identity.DirectoryManagement module
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

# Get current authorization policy
$authPolicy = Get-MgPolicyAuthorizationPolicy

Write-Host "[+] Current guest user access restrictions:" -ForegroundColor Cyan
Write-Host "  Permission scope: $($authPolicy.GuestUserRoleId)" -ForegroundColor Gray

# Set most restrictive guest permissions
# GuestUserRoleId values:
#   2af84b1e-32c8-42b7-82bc-daa82404023b = Guest user access is restricted (most restrictive)
#   10dae51f-b6af-4016-8d66-8c2a99b929b3 = Guest users have limited access
#   a0b1b346-4d3e-4e8b-98f8-753987be4970 = Guest users have the same access as members (not recommended)

$params = @{
    GuestUserRoleId = "2af84b1e-32c8-42b7-82bc-daa82404023b"
}

Update-MgPolicyAuthorizationPolicy -BodyParameter $params
Write-Host "[OK] Guest user access set to most restrictive" -ForegroundColor Green

# Review current guest users
Write-Host "`n[+] Reviewing current guest users..." -ForegroundColor Cyan
$guests = Get-MgUser -Filter "userType eq 'Guest'" -All -Property Id,DisplayName,UserPrincipalName,SignInActivity,CreatedDateTime

Write-Host "  Total guest users: $($guests.Count)" -ForegroundColor Yellow

# Export guest user report
$guestReport = $guests | Select-Object `
    DisplayName,
    UserPrincipalName,
    @{N='InvitedDate';E={$_.CreatedDateTime}},
    @{N='LastSignIn';E={$_.SignInActivity.LastSignInDateTime}},
    @{N='DaysSinceCreated';E={[int]((Get-Date) - $_.CreatedDateTime).TotalDays}},
    @{N='DaysSinceLastSignIn';E={
        if ($null -ne $_.SignInActivity.LastSignInDateTime) {
            [int]((Get-Date) - $_.SignInActivity.LastSignInDateTime).TotalDays
        } else {
            "Never"
        }
    }},
    Id

$guestReport | Export-Csv -Path ".\GuestUsers-Review-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
Write-Host "[OK] Exported guest user report for review" -ForegroundColor Green

# Identify stale guest accounts (never signed in and > 30 days old, or not signed in > 90 days)
$staleGuests = $guests | Where-Object {
    ($null -eq $_.SignInActivity.LastSignInDateTime -and ((Get-Date) - $_.CreatedDateTime).TotalDays -gt 30) -or
    ($null -ne $_.SignInActivity.LastSignInDateTime -and ((Get-Date) - $_.SignInActivity.LastSignInDateTime).TotalDays -gt 90)
}

Write-Host "`n[!] Found $($staleGuests.Count) stale guest accounts" -ForegroundColor Yellow
Write-Host "[i] Review GuestUsers-Review CSV and consider removing stale accounts" -ForegroundColor Cyan
'@
        Verification = @(
            'Verify restriction: (Get-MgPolicyAuthorizationPolicy).GuestUserRoleId should be "2af84b1e-32c8-42b7-82bc-daa82404023b"'
            'Test guest user experience - guests should not see full directory'
            'Review guest user report quarterly'
            'Monitor guest sign-in logs for anomalies'
        )
        Rollback = @(
            'Restore previous settings: Update-MgPolicyAuthorizationPolicy -GuestUserRoleId <previous-value>'
            'Note: Rollback may be required if business processes rely on guest directory access'
        )
        CommonPitfalls = @(
            'Pitfall: Breaking guest collaboration workflows | Solution: Test with pilot guests before organization-wide rollout'
            'Pitfall: No process to review guest access | Solution: Implement automated access reviews for guests'
            'Pitfall: Stale guest accounts accumulating | Solution: Set expiration dates on guest invitations'
        )
        References = @(
            'https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure'
            'https://learn.microsoft.com/entra/id-governance/entitlement-management-overview'
        )
    }

    'ApplicationCredentials_Expiring' = @{
        Title = 'Rotate Expiring Application Credentials'
        Summary = 'Identify and rotate application secrets and certificates before expiration'
        BestPractices = @(
            'Set maximum credential lifetime to 12 months (6 months preferred)'
            'Implement automated credential rotation where possible'
            'Use Azure Key Vault for storing application secrets'
            'Monitor for credentials expiring within 30 days'
            'Prefer certificates over secrets when possible'
            'Use managed identities instead of app credentials when possible'
            'Never store credentials in source code'
        )
        SecurityImplications = @{
            Risk = 'Expired credentials cause application outages; long-lived credentials increase compromise risk'
            Impact = 'Prevents service disruptions and reduces credential theft window'
            Compliance = @('CIS Microsoft 365 3.1.12', 'NIST 800-53 IA-5', 'PCI-DSS Req 8.2.4')
        }
        Prerequisites = @(
            'Application Administrator or Global Administrator role'
            'Inventory of applications and their credential owners'
            'Access to application configuration and Key Vault'
        )
        StepsPortal = @(
            '1. Sign in to Azure AD portal (https://entra.microsoft.com)'
            '2. Navigate to Identity > Applications > App registrations'
            '3. Select "All applications"'
            '4. Click on each application to review credentials'
            '5. Click "Certificates & secrets"'
            '6. Note expiration dates - identify those expiring soon'
            ''
            'For each expiring secret/certificate:'
            '7. Click "+ New client secret" or "+ New certificate"'
            '8. Enter description: "Rotated [Date]"'
            '9. Set expiration: 12 months maximum (6 months recommended)'
            '10. Click "Add"'
            '11. IMMEDIATELY copy the secret value (only shown once!)'
            '12. Store in Azure Key Vault:'
            '    a. Navigate to your Key Vault'
            '    b. Click "Secrets" > "+ Generate/Import"'
            '    c. Name: [AppName]-ClientSecret-[Date]'
            '    d. Paste secret value'
            '    e. Set expiration date'
            '    f. Click "Create"'
            '13. Update application configuration to use new secret'
            '14. Test application functionality with new credential'
            '15. After verification (e.g., 7 days), delete old secret/certificate'
            ''
            'Prevention - Set up monitoring:'
            '16. Navigate to Identity > Monitoring > Workbooks'
            '17. Select "Application credentials expiration" workbook'
            '18. Create alert for credentials expiring within 30 days'
        )
        StepsPowerShell = @'
# Requires: Microsoft.Graph.Applications module
Connect-MgGraph -Scopes "Application.Read.All"

# Get all applications with their credentials
Write-Host "[+] Analyzing application credentials..." -ForegroundColor Cyan

$apps = Get-MgApplication -All -Property Id,DisplayName,AppId,PasswordCredentials,KeyCredentials

$credentialReport = @()
$warningDays = 30

foreach ($app in $apps) {
    # Check password credentials (secrets)
    foreach ($secret in $app.PasswordCredentials) {
        $daysUntilExpiry = ($secret.EndDateTime - (Get-Date)).TotalDays

        if ($daysUntilExpiry -le $warningDays) {
            $credentialReport += [PSCustomObject]@{
                AppDisplayName = $app.DisplayName
                AppId = $app.AppId
                CredentialType = "Secret"
                CredentialId = $secret.KeyId
                DisplayName = $secret.DisplayName
                StartDate = $secret.StartDateTime
                EndDate = $secret.EndDateTime
                DaysUntilExpiry = [math]::Round($daysUntilExpiry, 0)
                Status = if ($daysUntilExpiry -lt 0) { "EXPIRED" }
                         elseif ($daysUntilExpiry -le 7) { "CRITICAL" }
                         elseif ($daysUntilExpiry -le 30) { "WARNING" }
                         else { "OK" }
            }
        }
    }

    # Check key credentials (certificates)
    foreach ($cert in $app.KeyCredentials) {
        $daysUntilExpiry = ($cert.EndDateTime - (Get-Date)).TotalDays

        if ($daysUntilExpiry -le $warningDays) {
            $credentialReport += [PSCustomObject]@{
                AppDisplayName = $app.DisplayName
                AppId = $app.AppId
                CredentialType = "Certificate"
                CredentialId = $cert.KeyId
                DisplayName = $cert.DisplayName
                StartDate = $cert.StartDateTime
                EndDate = $cert.EndDateTime
                DaysUntilExpiry = [math]::Round($daysUntilExpiry, 0)
                Status = if ($daysUntilExpiry -lt 0) { "EXPIRED" }
                         elseif ($daysUntilExpiry -le 7) { "CRITICAL" }
                         elseif ($daysUntilExpiry -le 30) { "WARNING" }
                         else { "OK" }
            }
        }
    }
}

# Export report
$credentialReport | Sort-Object DaysUntilExpiry |
    Export-Csv -Path ".\AppCredentials-Expiring-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

Write-Host "`n[!] Credential Status Summary:" -ForegroundColor Yellow
$expiredCount = ($credentialReport | Where-Object { $_.Status -eq "EXPIRED" }).Count
$criticalCount = ($credentialReport | Where-Object { $_.Status -eq "CRITICAL" }).Count
$warningCount = ($credentialReport | Where-Object { $_.Status -eq "WARNING" }).Count

Write-Host "  EXPIRED (action required immediately): $expiredCount" -ForegroundColor Red
Write-Host "  CRITICAL (< 7 days): $criticalCount" -ForegroundColor Red
Write-Host "  WARNING (< 30 days): $warningCount" -ForegroundColor Yellow

Write-Host "`n[OK] Exported report: .\AppCredentials-Expiring-$(Get-Date -Format 'yyyyMMdd').csv" -ForegroundColor Green

# Display critical/expired credentials
if ($expiredCount -gt 0 -or $criticalCount -gt 0) {
    Write-Host "`n[!] URGENT - Credentials requiring immediate attention:" -ForegroundColor Red
    $credentialReport | Where-Object { $_.Status -in @("EXPIRED", "CRITICAL") } |
        Select-Object AppDisplayName, CredentialType, DisplayName, DaysUntilExpiry, Status |
        Format-Table -AutoSize
}

# Rotation script (requires Application.ReadWrite.All scope)
Write-Host "`n[i] To rotate a secret, use:" -ForegroundColor Cyan
Write-Host "Connect-MgGraph -Scopes 'Application.ReadWrite.All'" -ForegroundColor Gray
Write-Host "# Set appId, create new secret with 6-month expiry:" -ForegroundColor Gray
Write-Host "  Add-MgApplicationPassword -ApplicationId <AppId> -BodyParameter @{ PasswordCredential = @{ DisplayName = 'Rotated'; EndDateTime = (Get-Date).AddMonths(6) } }" -ForegroundColor Gray
Write-Host "# Store in Key Vault, then remove old credential after testing" -ForegroundColor Gray
'@
        Verification = @(
            'Run credential report script regularly (weekly recommended)'
            'Verify no credentials in EXPIRED or CRITICAL status'
            'Test application functionality after rotation'
            'Confirm old credentials are deleted after successful rotation'
            'Check Azure Key Vault for stored secrets'
        )
        Rollback = @(
            'Keep old credential active until new credential is verified'
            'If new credential fails, continue using old credential'
            'Do not delete old credential until successful testing'
        )
        CommonPitfalls = @(
            'Pitfall: Application outage after rotation | Solution: Test new credential before deleting old one'
            'Pitfall: Lost secret value | Solution: Always store immediately in Key Vault'
            'Pitfall: No tracking of credential owners | Solution: Use DisplayName field to document owner/purpose'
            'Pitfall: Hard-coded secrets in code | Solution: Use environment variables or Key Vault references'
        )
        References = @(
            'https://learn.microsoft.com/entra/identity-platform/howto-create-service-principal-portal'
            'https://learn.microsoft.com/azure/key-vault/secrets/quick-create-powershell'
            'https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview'
        )
    }
}

#endregion

#region Public Functions

function Get-ExtendedRemediationGuidance {
    <#
    .SYNOPSIS
        Gets extended remediation guidance for a finding type.

    .PARAMETER FindingType
        The type of finding (check name)

    .PARAMETER IncludeBestPractices
        Include best practices section

    .PARAMETER IncludeSecurityContext
        Include security implications and compliance context
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FindingType,

        [switch]$IncludeBestPractices,

        [switch]$IncludeSecurityContext
    )

    # Try extended guidance first
    if ($Script:ExtendedRemediationGuidance.ContainsKey($FindingType)) {
        $guidance = $Script:ExtendedRemediationGuidance[$FindingType]
    }
    else {
        # Fall back to base guidance
        $guidance = Get-RemediationGuidance -FindingType $FindingType
    }

    # Add sections if requested
    if ($IncludeBestPractices -and $guidance.BestPractices) {
        $guidance.BestPracticesFormatted = Format-BestPractices -BestPractices $guidance.BestPractices
    }

    if ($IncludeSecurityContext -and $guidance.SecurityImplications) {
        $guidance.SecurityContextFormatted = Format-SecurityContext -SecurityImplications $guidance.SecurityImplications
    }

    return $guidance
}

<#
.SYNOPSIS
    Formats an array of best practices into a Markdown-formatted string.
#>
function Format-BestPractices {
    param([array]$BestPractices)

    $output = @()
    $output += "## Best Practices"
    $output += ""
    foreach ($practice in $BestPractices) {
        $output += "- $practice"
    }
    return ($output -join "`n")
}

<#
.SYNOPSIS
    Formats security implications into a Markdown-formatted string with risk and impact details.
#>
function Format-SecurityContext {
    param($SecurityImplications)

    $output = @()
    $output += "## Security Implications"
    $output += ""
    $output += "**Risk:** $($SecurityImplications.Risk)"
    $output += "**Impact:** $($SecurityImplications.Impact)"
    if ($SecurityImplications.Compliance) {
        $output += "**Compliance Frameworks:** $($SecurityImplications.Compliance -join ', ')"
    }
    return ($output -join "`n")
}

#endregion

#region Export Module Members

Export-ModuleMember -Function @(
    'Get-ExtendedRemediationGuidance',
    'Format-BestPractices',
    'Format-SecurityContext'
)

#endregion
