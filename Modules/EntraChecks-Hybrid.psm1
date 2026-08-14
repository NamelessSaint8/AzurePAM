<#
.SYNOPSIS
    EntraChecks-Hybrid.psm1
    Optional module for Azure AD Connect and hybrid identity checks

.DESCRIPTION
    This module extends Invoke-EntraChecks.ps1 with hybrid identity checks.
    Covers directory synchronization, password hash sync, pass-through authentication,
    and on-premises provisioning errors.
    
    Checks included:
    - Test-DirectorySyncStatus: Overall sync enabled/healthy
    - Test-SyncErrors: User/group synchronization errors
    - Test-PasswordHashSync: PHS configuration status
    - Test-PassThroughAuthentication: PTA agent status
    - Test-SeamlessSSOStatus: Seamless SSO configuration
    - Test-OnPremisesProvisioningErrors: Object provisioning errors
    
.NOTES
    Version: 1.0.0
    Author: NamelessSaint
    Requires: Microsoft.Graph PowerShell SDK
    
    License Requirements:
    - Basic sync info: Azure AD Free
    - Connect Health monitoring: Azure AD P1
    - PHS/PTA monitoring: Azure AD P1
    
    Required Graph Permissions:
    - Directory.Read.All
    - Organization.Read.All
    - Application.Read.All
    
    IMPORTANT: Some advanced Connect Health features require the Azure AD Connect
    Health API (via Azure Resource Manager), which is not covered by this module.
    This module provides best-effort checks using Microsoft Graph.
    
.LINK
    Main Script: Invoke-EntraChecks.ps1
    Graph API Reference: https://learn.microsoft.com/en-us/graph/api/resources/organization
#>

#Requires -Version 5.1

# Module version
$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-Hybrid"

# Default thresholds
$script:SyncDelayThresholdHours = 3
$script:SyncDelayWarningHours = 1

#region ==================== MODULE INITIALIZATION ====================

<#
.SYNOPSIS
    Initializes the Hybrid module.

.DESCRIPTION
    Checks prerequisites and verifies hybrid identity is configured.
    Called automatically when module is imported.
#>
function Initialize-HybridModule {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Loading module: $script:ModuleName v$script:ModuleVersion" -ForegroundColor Magenta
    
    # Verify main script context
    if (-not (Get-Variable -Name "Findings" -Scope Script -ErrorAction SilentlyContinue)) {
        $script:Findings = @()
        Write-Host "    [!] Running in standalone mode (no main script context)" -ForegroundColor Yellow
    }
    
    # Load thresholds from config if available
    if (Get-Variable -Name "Config" -Scope Script -ErrorAction SilentlyContinue) {
        if ($script:Config.Modules.Hybrid.SyncDelayThresholdHours) {
            $script:SyncDelayThresholdHours = $script:Config.Modules.Hybrid.SyncDelayThresholdHours
        }
    }
    
    Write-Host "    [OK] Module loaded successfully" -ForegroundColor Green
    Write-Host "    [i] Sync delay threshold: $script:SyncDelayThresholdHours hours" -ForegroundColor Gray
    Write-Host "    [i] Note: Some Connect Health features require Azure Resource Manager API" -ForegroundColor Gray
    
    # Return module info
    return @{
        Name = $script:ModuleName
        Version = $script:ModuleVersion
        Checks = @(
            "Test-DirectorySyncStatus",
            "Test-SyncErrors",
            "Test-PasswordHashSync",
            "Test-PassThroughAuthentication",
            "Test-SeamlessSSOStatus",
            "Test-OnPremisesProvisioningErrors"
        )
        RequiredLicense = "Azure AD Free (basic), Azure AD P1 (Connect Health)"
        RequiredPermissions = @(
            "Directory.Read.All",
            "Organization.Read.All",
            "Application.Read.All"
        )
    }
}

#endregion

#region ==================== HELPER FUNCTIONS ====================

<#
.SYNOPSIS
    Adds a finding to the findings collection.
#>
function Add-ModuleFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("OK", "INFO", "WARNING", "FAIL")]
        [string]$Status,
        
        [Parameter(Mandatory)]
        [string]$Object,
        
        [Parameter(Mandatory)]
        [string]$Description,
        
        [string]$Remediation = ""
    )
    
    if (Get-Command -Name "Add-Finding" -ErrorAction SilentlyContinue) {
        Add-Finding -Status $Status -Object $Object -Description $Description -Remediation $Remediation
    }
    else {
        $finding = [PSCustomObject]@{
            Time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Status = $Status
            Object = $Object
            Description = $Description
            Remediation = $Remediation
            Module = $script:ModuleName
        }
        
        $script:Findings += $finding
        
        $color = switch ($Status) {
            "OK" { "Green" }
            "INFO" { "Cyan" }
            "WARNING" { "Yellow" }
            "FAIL" { "Red" }
        }
        Write-Host "[$Status] $Object" -ForegroundColor $color
    }
}

<#
.SYNOPSIS
    Invokes a Graph API request.
#>
function Invoke-ModuleGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        
        [switch]$AllPages
    )
    
    if (Get-Command -Name "Invoke-GraphRequest" -ErrorAction SilentlyContinue) {
        if ($AllPages) {
            return Invoke-GraphRequest -Uri $Uri -AllPages
        }
        else {
            return Invoke-GraphRequest -Uri $Uri
        }
    }
    else {
        try {
            $results = @()
            $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
            
            if ($response.value) {
                $results += $response.value
                
                if ($AllPages) {
                    while ($response.'@odata.nextLink') {
                        $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
                        if ($response.value) {
                            $results += $response.value
                        }
                    }
                }
                
                return $results
            }
            else {
                return $response
            }
        }
        catch {
            Write-Host "[!] Graph API Error: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
}

#endregion

#region ==================== HYBRID CHECKS ====================

<#
.SYNOPSIS
    Test-DirectorySyncStatus - Checks overall directory synchronization status.

.DESCRIPTION
    Examines the Azure AD Connect synchronization state:
    - Whether directory sync is enabled
    - Last successful sync time
    - Sync client information
    - Sync latency analysis
    
    Graph Endpoints Used:
    - GET /organization
    
.OUTPUTS
    Findings based on sync status
    
.NOTES
    Required Permissions: Organization.Read.All
    Minimum License: Azure AD Free
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/organization-list
#>
function Test-DirectorySyncStatus {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking directory sync status..." -ForegroundColor Cyan
    
    try {
        # Get organization info
        $org = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesLastPasswordSyncDateTime,directorySizeQuota"
        
        if (-not $org) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Directory Sync Status" `
                -Description "Unable to retrieve organization information." `
                -Remediation "Check Graph permissions (Organization.Read.All required)."
            return
        }
        
        # Handle array response
        if ($org -is [System.Array]) {
            $org = $org[0]
        }
        
        # Check if sync is enabled
        $syncEnabled = $org.onPremisesSyncEnabled
        $lastSyncTime = $org.onPremisesLastSyncDateTime
        $lastPasswordSyncTime = $org.onPremisesLastPasswordSyncDateTime
        
        if (-not $syncEnabled) {
            Add-ModuleFinding -Status "INFO" `
                -Object "Directory Sync" `
                -Description "Directory synchronization is not enabled. This is a cloud-only tenant." `
                -Remediation "If this is a hybrid environment, verify Azure AD Connect is installed and configured."
            return
        }
        
        Add-ModuleFinding -Status "INFO" `
            -Object "Directory Sync Enabled" `
            -Description "Directory synchronization is enabled for tenant: $($org.displayName)." `
            -Remediation "Continue monitoring sync health via Azure AD Connect Health."
        
        # Check last sync time
        if ($lastSyncTime) {
            $lastSync = [DateTime]$lastSyncTime
            $timeSinceSync = (Get-Date) - $lastSync
            $hoursSinceSync = [math]::Round($timeSinceSync.TotalHours, 1)
            $formattedLastSync = $lastSync.ToString("yyyy-MM-dd HH:mm:ss UTC")
            
            if ($timeSinceSync.TotalHours -gt $script:SyncDelayThresholdHours) {
                Add-ModuleFinding -Status "FAIL" `
                    -Object "Directory Sync Delay" `
                    -Description "Last directory sync was $hoursSinceSync hours ago ($formattedLastSync). This exceeds the $($script:SyncDelayThresholdHours)-hour threshold." `
                    -Remediation "URGENT: Check Azure AD Connect service on sync server. Verify network connectivity to Azure AD. Review sync errors in Azure AD Connect Health."
            }
            elseif ($timeSinceSync.TotalHours -gt $script:SyncDelayWarningHours) {
                Add-ModuleFinding -Status "WARNING" `
                    -Object "Directory Sync Timing" `
                    -Description "Last directory sync was $hoursSinceSync hours ago ($formattedLastSync). Default sync cycle is 30 minutes." `
                    -Remediation "Monitor sync status. If sync times continue to lag, check Azure AD Connect server health."
            }
            else {
                Add-ModuleFinding -Status "OK" `
                    -Object "Directory Sync Timing" `
                    -Description "Last directory sync: $formattedLastSync ($hoursSinceSync hours ago). Sync is current." `
                    -Remediation "Continue monitoring via Azure AD Connect Health."
            }
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Directory Sync Time Unknown" `
                -Description "Unable to determine last sync time. Sync may never have completed successfully." `
                -Remediation "Check Azure AD Connect configuration and run initial sync."
        }
        
        # Check password sync time if available
        if ($lastPasswordSyncTime) {
            $lastPwdSync = [DateTime]$lastPasswordSyncTime
            $timeSincePwdSync = (Get-Date) - $lastPwdSync
            $hoursSincePwdSync = [math]::Round($timeSincePwdSync.TotalHours, 1)
            
            if ($timeSincePwdSync.TotalHours -gt $script:SyncDelayThresholdHours) {
                Add-ModuleFinding -Status "WARNING" `
                    -Object "Password Hash Sync Delay" `
                    -Description "Last password hash sync was $hoursSincePwdSync hours ago. Password changes may not be reflected in cloud." `
                    -Remediation "Check Azure AD Connect PHS configuration. Verify the sync service is running."
            }
            else {
                Add-ModuleFinding -Status "OK" `
                    -Object "Password Hash Sync Timing" `
                    -Description "Last password hash sync: $hoursSincePwdSync hours ago. PHS is current." `
                    -Remediation "N/A"
            }
        }
        
        # Check directory size quota
        if ($org.directorySizeQuota) {
            $quota = $org.directorySizeQuota
            $used = $quota.used
            $total = $quota.total
            $usedPercent = [math]::Round(($used / $total) * 100, 1)
            
            if ($usedPercent -gt 90) {
                Add-ModuleFinding -Status "FAIL" `
                    -Object "Directory Size Quota" `
                    -Description "Directory is at $usedPercent% capacity ($used of $total objects). You may not be able to sync new objects." `
                    -Remediation "Contact Microsoft support to increase directory quota, or remove unnecessary objects."
            }
            elseif ($usedPercent -gt 75) {
                Add-ModuleFinding -Status "WARNING" `
                    -Object "Directory Size Quota" `
                    -Description "Directory is at $usedPercent% capacity ($used of $total objects)." `
                    -Remediation "Monitor directory growth. Plan for quota increase if needed."
            }
            else {
                Add-ModuleFinding -Status "INFO" `
                    -Object "Directory Size Quota" `
                    -Description "Directory usage: $usedPercent% ($used of $total objects)." `
                    -Remediation "N/A"
            }
        }
    }
    catch {
        Add-ModuleFinding -Status "WARNING" `
            -Object "Directory Sync Status" `
            -Description "Unable to check directory sync status: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Organization.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-SyncErrors - Checks for directory synchronization errors.

.DESCRIPTION
    Examines users and groups for on-premises sync errors:
    - Users with provisioning errors
    - Groups with provisioning errors
    - Error types and counts
    - Specific object details
    
    Graph Endpoints Used:
    - GET /users (filter for onPremisesProvisioningErrors)
    - GET /groups (filter for onPremisesProvisioningErrors)
    
.OUTPUTS
    Findings based on sync errors found
    
.NOTES
    Required Permissions: Directory.Read.All
    Minimum License: Azure AD Free
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/user-list
#>
function Test-SyncErrors {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking for sync errors..." -ForegroundColor Cyan
    
    try {
        # First check if this is a hybrid environment
        $org = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization?`$select=onPremisesSyncEnabled"
        
        if ($org -is [System.Array]) { $org = $org[0] }
        
        if (-not $org.onPremisesSyncEnabled) {
            Add-ModuleFinding -Status "INFO" `
                -Object "Sync Errors" `
                -Description "Directory synchronization is not enabled. No sync errors to check." `
                -Remediation "N/A - Cloud-only tenant."
            return
        }
        
        $totalErrors = 0
        $errorCategories = @{}
        
        # Check users with sync errors
        try {
            # Get users that have sync errors (they will have onPremisesProvisioningErrors populated)
            $usersWithErrors = @()
            $allUsers = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,onPremisesProvisioningErrors,onPremisesSyncEnabled&`$filter=onPremisesSyncEnabled eq true" -AllPages
            
            if ($allUsers) {
                $usersWithErrors = $allUsers | Where-Object { 
                    $_.onPremisesProvisioningErrors -and $_.onPremisesProvisioningErrors.Count -gt 0 
                }
            }
            
            if ($usersWithErrors.Count -gt 0) {
                Add-ModuleFinding -Status "FAIL" `
                    -Object "User Sync Errors" `
                    -Description "$($usersWithErrors.Count) users have synchronization errors. These users may not be properly synced from on-premises." `
                    -Remediation "Review each user's provisioning errors. Common causes: duplicate proxyAddresses, invalid characters, attribute conflicts."
                
                # Categorize and list errors
                foreach ($user in $usersWithErrors | Select-Object -First 10) {
                    foreach ($syncError in $user.onPremisesProvisioningErrors) {
                        $category = $syncError.category
                        if (-not $errorCategories.ContainsKey($category)) {
                            $errorCategories[$category] = 0
                        }
                        $errorCategories[$category]++
                        $totalErrors++
                    }
                    
                    $errorDesc = ($user.onPremisesProvisioningErrors | ForEach-Object { $_.value }) -join "; "
                    Add-ModuleFinding -Status "FAIL" `
                        -Object "User: $($user.displayName)" `
                        -Description "Sync error: $errorDesc" `
                        -Remediation "Fix the attribute conflict in on-premises Active Directory and force a sync."
                }
                
                if ($usersWithErrors.Count -gt 10) {
                    Add-ModuleFinding -Status "INFO" `
                        -Object "Additional User Sync Errors" `
                        -Description "$($usersWithErrors.Count - 10) additional users have sync errors. Review in Azure AD Connect Health." `
                        -Remediation "Export full error list from Azure AD Connect Health for remediation planning."
                }
            }
            else {
                Add-ModuleFinding -Status "OK" `
                    -Object "User Sync Errors" `
                    -Description "No user synchronization errors found." `
                    -Remediation "Continue monitoring via Azure AD Connect Health."
            }
        }
        catch {
            Add-ModuleFinding -Status "WARNING" `
                -Object "User Sync Errors" `
                -Description "Unable to check user sync errors: $($_.Exception.Message)" `
                -Remediation "Check Graph permissions and try again."
        }
        
        # Check groups with sync errors
        try {
            $groupsWithErrors = @()
            $allGroups = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,onPremisesProvisioningErrors,onPremisesSyncEnabled&`$filter=onPremisesSyncEnabled eq true" -AllPages
            
            if ($allGroups) {
                $groupsWithErrors = $allGroups | Where-Object { 
                    $_.onPremisesProvisioningErrors -and $_.onPremisesProvisioningErrors.Count -gt 0 
                }
            }
            
            if ($groupsWithErrors.Count -gt 0) {
                Add-ModuleFinding -Status "FAIL" `
                    -Object "Group Sync Errors" `
                    -Description "$($groupsWithErrors.Count) groups have synchronization errors." `
                    -Remediation "Review group provisioning errors. Common causes: duplicate mail addresses, nested group issues."
                
                foreach ($group in $groupsWithErrors | Select-Object -First 5) {
                    $errorDesc = ($group.onPremisesProvisioningErrors | ForEach-Object { $_.value }) -join "; "
                    Add-ModuleFinding -Status "FAIL" `
                        -Object "Group: $($group.displayName)" `
                        -Description "Sync error: $errorDesc" `
                        -Remediation "Fix the attribute conflict in on-premises Active Directory."
                }
            }
            else {
                Add-ModuleFinding -Status "OK" `
                    -Object "Group Sync Errors" `
                    -Description "No group synchronization errors found." `
                    -Remediation "N/A"
            }
        }
        catch {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Group Sync Errors" `
                -Description "Unable to check group sync errors: $($_.Exception.Message)" `
                -Remediation "Check Graph permissions and try again."
        }
        
        # Summary by error category
        if ($errorCategories.Count -gt 0) {
            $categorySummary = ($errorCategories.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ", "
            Add-ModuleFinding -Status "INFO" `
                -Object "Sync Error Categories" `
                -Description "Error distribution: $categorySummary" `
                -Remediation "Focus on resolving the most common error categories first."
        }
    }
    catch {
        Add-ModuleFinding -Status "WARNING" `
            -Object "Sync Errors" `
            -Description "Unable to check sync errors: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Directory.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-PasswordHashSync - Checks Password Hash Synchronization status.

.DESCRIPTION
    Examines PHS configuration:
    - Whether PHS is enabled
    - Last password sync time
    - Recommendations for backup authentication
    
    Note: Full PHS status requires Azure AD Connect Health API
    
    Graph Endpoints Used:
    - GET /organization (for last password sync time)
    
.OUTPUTS
    Findings based on PHS status
    
.NOTES
    Required Permissions: Organization.Read.All
    Minimum License: Azure AD P1 (for Connect Health)
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/azure/active-directory/hybrid/whatis-phs
#>
function Test-PasswordHashSync {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking Password Hash Sync status..." -ForegroundColor Cyan
    
    try {
        # Get organization info for password sync time
        $org = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization?`$select=onPremisesSyncEnabled,onPremisesLastPasswordSyncDateTime"
        
        if ($org -is [System.Array]) { $org = $org[0] }
        
        if (-not $org.onPremisesSyncEnabled) {
            Add-ModuleFinding -Status "INFO" `
                -Object "Password Hash Sync" `
                -Description "Directory synchronization is not enabled. PHS is not applicable for cloud-only tenants." `
                -Remediation "N/A"
            return
        }
        
        $lastPasswordSyncTime = $org.onPremisesLastPasswordSyncDateTime
        
        if ($lastPasswordSyncTime) {
            $lastSync = [DateTime]$lastPasswordSyncTime
            $timeSinceSync = (Get-Date) - $lastSync
            $hoursSinceSync = [math]::Round($timeSinceSync.TotalHours, 1)
            
            Add-ModuleFinding -Status "OK" `
                -Object "Password Hash Sync Enabled" `
                -Description "Password Hash Sync appears to be enabled. Last sync: $hoursSinceSync hours ago." `
                -Remediation "PHS provides backup authentication and enables leaked credential detection. Ensure it remains enabled."
            
            # Provide recommendations based on PHS status
            Add-ModuleFinding -Status "INFO" `
                -Object "PHS Security Benefits" `
                -Description "Password Hash Sync enables: Azure AD Password Protection, Leaked Credential Detection, Smart Lockout, and backup authentication during on-premises outages." `
                -Remediation "Keep PHS enabled even if using PTA or Federation as primary authentication."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Password Hash Sync Status Unknown" `
                -Description "Unable to determine PHS status. Password sync time not available. PHS may not be enabled." `
                -Remediation "Enable PHS in Azure AD Connect for backup authentication and enhanced security features. PHS is recommended even with PTA or Federation."
        }
    }
    catch {
        Add-ModuleFinding -Status "WARNING" `
            -Object "Password Hash Sync" `
            -Description "Unable to check PHS status: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions and Azure AD Connect Health for detailed PHS status."
    }
}

<#
.SYNOPSIS
    Test-PassThroughAuthentication - Checks PTA agent status.

.DESCRIPTION
    Examines Pass-Through Authentication configuration:
    - PTA agents registered
    - Agent count (redundancy check)
    - Agent health status
    
    Graph Endpoints Used:
    - GET /onPremisesPublishingProfiles/provisioning/agents
    - GET /servicePrincipals (for Connect-related apps)
    
.OUTPUTS
    Findings based on PTA status
    
.NOTES
    Required Permissions: Directory.Read.All, Application.Read.All
    Minimum License: Azure AD P1
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-pta
#>
function Test-PassThroughAuthentication {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking Pass-Through Authentication status..." -ForegroundColor Cyan
    
    try {
        # First check if this is a hybrid environment
        $org = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization?`$select=onPremisesSyncEnabled"
        
        if ($org -is [System.Array]) { $org = $org[0] }
        
        if (-not $org.onPremisesSyncEnabled) {
            Add-ModuleFinding -Status "INFO" `
                -Object "Pass-Through Authentication" `
                -Description "Directory synchronization is not enabled. PTA is not applicable for cloud-only tenants." `
                -Remediation "N/A"
            return
        }
        
        # Try to get PTA agents via the publishing profiles API
        try {
            $ptaAgents = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/onPremisesPublishingProfiles/provisioning/agents"
            
            if ($ptaAgents -and $ptaAgents.Count -gt 0) {
                # Filter for PTA agents
                $ptaProvisioningAgents = $ptaAgents | Where-Object { 
                    $_.publishingType -eq "passthrough" -or 
                    $_.publishingType -eq "authentication" 
                }
                
                if ($ptaProvisioningAgents.Count -gt 0) {
                    $activeAgents = $ptaProvisioningAgents | Where-Object { $_.status -eq "active" }
                    $inactiveAgents = $ptaProvisioningAgents | Where-Object { $_.status -ne "active" }
                    
                    Add-ModuleFinding -Status "INFO" `
                        -Object "PTA Agents Found" `
                        -Description "Pass-Through Authentication is configured with $($ptaProvisioningAgents.Count) agent(s). Active: $($activeAgents.Count). Inactive: $($inactiveAgents.Count)." `
                        -Remediation "Ensure at least 2 PTA agents for redundancy."
                    
                    # Check for single agent (no redundancy)
                    if ($activeAgents.Count -eq 1) {
                        Add-ModuleFinding -Status "WARNING" `
                            -Object "PTA Single Agent" `
                            -Description "Only 1 active PTA agent. If this agent fails, users cannot authenticate." `
                            -Remediation "IMPORTANT: Install at least one additional PTA agent on a different server for high availability."
                    }
                    elseif ($activeAgents.Count -eq 0) {
                        Add-ModuleFinding -Status "FAIL" `
                            -Object "PTA No Active Agents" `
                            -Description "No active PTA agents found. Pass-Through Authentication is non-functional." `
                            -Remediation "URGENT: Check PTA agent servers. Ensure agents are running and can reach Azure AD."
                    }
                    else {
                        Add-ModuleFinding -Status "OK" `
                            -Object "PTA Agent Redundancy" `
                            -Description "$($activeAgents.Count) active PTA agents provide redundancy for authentication." `
                            -Remediation "Continue monitoring agent health via Azure AD Connect Health."
                    }
                    
                    # Check for inactive agents
                    if ($inactiveAgents.Count -gt 0) {
                        Add-ModuleFinding -Status "WARNING" `
                            -Object "PTA Inactive Agents" `
                            -Description "$($inactiveAgents.Count) PTA agent(s) are inactive or unhealthy." `
                            -Remediation "Investigate inactive agents. Check server health, network connectivity, and agent service status."
                    }
                    
                    return
                }
            }
        }
        catch {
            Write-Verbose "Connect API not accessible, trying alternative detection: $_"
        }
        
        # Alternative: Check for Azure AD Connect service principals
        try {
            $connectApps = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=startswith(displayName,'Microsoft Azure AD Connect')"
            
            if ($connectApps -and $connectApps.Count -gt 0) {
                Add-ModuleFinding -Status "INFO" `
                    -Object "Azure AD Connect Detected" `
                    -Description "Azure AD Connect service principal(s) found. PTA status requires Azure AD Connect Health for detailed monitoring." `
                    -Remediation "Use Azure AD Connect Health portal for detailed PTA agent status and health monitoring."
            }
            else {
                Add-ModuleFinding -Status "INFO" `
                    -Object "PTA Status" `
                    -Description "Unable to determine PTA status via Graph API. PTA may not be enabled, or additional permissions are required." `
                    -Remediation "Check Azure AD Connect configuration. Use Azure AD Connect Health for PTA monitoring."
            }
        }
        catch {
            Add-ModuleFinding -Status "INFO" `
                -Object "PTA Status" `
                -Description "Unable to determine PTA configuration. Check Azure AD Connect Health for detailed status." `
                -Remediation "Access Azure AD Connect Health in Azure Portal for PTA agent monitoring."
        }
    }
    catch {
        Add-ModuleFinding -Status "WARNING" `
            -Object "Pass-Through Authentication" `
            -Description "Unable to check PTA status: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions and Azure AD Connect Health."
    }
}

<#
.SYNOPSIS
    Test-SeamlessSSOStatus - Checks Seamless Single Sign-On configuration.

.DESCRIPTION
    Examines Seamless SSO status:
    - Whether Seamless SSO is configured
    - Computer account age recommendations
    
    Note: Seamless SSO status is primarily managed via Azure AD Connect
    
.OUTPUTS
    Findings based on Seamless SSO status
    
.NOTES
    Required Permissions: Directory.Read.All
    Minimum License: Azure AD Free
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sso
#>
function Test-SeamlessSSOStatus {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking Seamless SSO status..." -ForegroundColor Cyan
    
    try {
        # Check if this is a hybrid environment
        $org = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization?`$select=onPremisesSyncEnabled"
        
        if ($org -is [System.Array]) { $org = $org[0] }
        
        if (-not $org.onPremisesSyncEnabled) {
            Add-ModuleFinding -Status "INFO" `
                -Object "Seamless SSO" `
                -Description "Directory synchronization is not enabled. Seamless SSO is not applicable for cloud-only tenants." `
                -Remediation "N/A"
            return
        }
        
        # Seamless SSO status isn't directly exposed via Graph
        # We can check for the AZUREADSSOACC computer account in synced devices
        # or look for related service principals
        
        try {
            $ssoApps = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=startswith(displayName,'Azure Active Directory Seamless SSO')"
            
            if ($ssoApps -and $ssoApps.Count -gt 0) {
                Add-ModuleFinding -Status "OK" `
                    -Object "Seamless SSO" `
                    -Description "Seamless SSO appears to be configured. Service principal found." `
                    -Remediation "Ensure Kerberos decryption key is rotated every 30 days for security."
            }
            else {
                # Also check for AZUREADSSOACC computer account indicator
                $domains = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/domains?`$select=id,isDefault,authenticationType"
                
                $managedDomains = $domains | Where-Object { $_.authenticationType -eq "Managed" }
                
                if ($managedDomains.Count -gt 0) {
                    Add-ModuleFinding -Status "INFO" `
                        -Object "Seamless SSO Status" `
                        -Description "Seamless SSO configuration cannot be fully verified via Graph API. Managed authentication is in use for $($managedDomains.Count) domain(s)." `
                        -Remediation "Check Azure AD Connect configuration to verify Seamless SSO status. Enable if using PHS or PTA for improved user experience."
                }
            }
        }
        catch {
            Add-ModuleFinding -Status "INFO" `
                -Object "Seamless SSO" `
                -Description "Unable to determine Seamless SSO status via Graph API." `
                -Remediation "Check Azure AD Connect configuration for Seamless SSO settings."
        }
        
        # Provide general guidance
        Add-ModuleFinding -Status "INFO" `
            -Object "Seamless SSO Best Practices" `
            -Description "If Seamless SSO is enabled: 1) Rotate Kerberos key every 30 days. 2) Ensure AZUREADSSOACC computer account is protected. 3) Monitor for abnormal Kerberos ticket requests." `
            -Remediation "Use the Azure AD Connect wizard to rotate the Kerberos decryption key regularly."
    }
    catch {
        Add-ModuleFinding -Status "WARNING" `
            -Object "Seamless SSO" `
            -Description "Unable to check Seamless SSO status: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions and Azure AD Connect configuration."
    }
}

<#
.SYNOPSIS
    Test-OnPremisesProvisioningErrors - Detailed check for object provisioning errors.

.DESCRIPTION
    Performs detailed analysis of on-premises provisioning errors:
    - Error categories and distribution
    - Common error patterns
    - Affected object types
    - Remediation guidance per error type
    
    Graph Endpoints Used:
    - GET /users
    - GET /groups
    - GET /contacts
    
.OUTPUTS
    Findings with detailed error analysis
    
.NOTES
    Required Permissions: Directory.Read.All
    Minimum License: Azure AD Free
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/azure/active-directory/hybrid/tshoot-connect-sync-errors
#>
function Test-OnPremisesProvisioningErrors {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking on-premises provisioning errors..." -ForegroundColor Cyan
    
    try {
        # Check if this is a hybrid environment
        $org = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization?`$select=onPremisesSyncEnabled"
        
        if ($org -is [System.Array]) { $org = $org[0] }
        
        if (-not $org.onPremisesSyncEnabled) {
            Add-ModuleFinding -Status "INFO" `
                -Object "Provisioning Errors" `
                -Description "Directory synchronization is not enabled. No provisioning errors to check." `
                -Remediation "N/A"
            return
        }
        
        $errorsByCategory = @{}
        $errorsByType = @{
            "PropertyConflict" = @()
            "DataValidationFailed" = @()
            "FederatedDomainChangeError" = @()
            "LargeObject" = @()
            "Other" = @()
        }
        
        $totalObjectsWithErrors = 0
        
        # Check all synced users for errors
        $syncedUsers = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,onPremisesProvisioningErrors&`$filter=onPremisesSyncEnabled eq true&`$top=999" -AllPages
        
        if ($syncedUsers) {
            foreach ($user in $syncedUsers) {
                if ($user.onPremisesProvisioningErrors -and $user.onPremisesProvisioningErrors.Count -gt 0) {
                    $totalObjectsWithErrors++
                    
                    foreach ($syncError in $user.onPremisesProvisioningErrors) {
                        $category = if ($syncError.category) { $syncError.category } else { "Unknown" }
                        
                        if (-not $errorsByCategory.ContainsKey($category)) {
                            $errorsByCategory[$category] = 0
                        }
                        $errorsByCategory[$category]++
                        
                        # Categorize by error pattern
                        $errorValue = if ($error.value) { $error.value } else { "" }
                        
                        if ($errorValue -match "PropertyConflict|duplicate|already exists") {
                            $errorsByType["PropertyConflict"] += @{Object = $user.displayName; Error = $errorValue }
                        }
                        elseif ($errorValue -match "validation|invalid|format") {
                            $errorsByType["DataValidationFailed"] += @{Object = $user.displayName; Error = $errorValue }
                        }
                        elseif ($errorValue -match "federated|domain") {
                            $errorsByType["FederatedDomainChangeError"] += @{Object = $user.displayName; Error = $errorValue }
                        }
                        elseif ($errorValue -match "large|size|limit") {
                            $errorsByType["LargeObject"] += @{Object = $user.displayName; Error = $errorValue }
                        }
                        else {
                            $errorsByType["Other"] += @{Object = $user.displayName; Error = $errorValue }
                        }
                    }
                }
            }
        }
        
        # Check groups too
        $syncedGroups = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,onPremisesProvisioningErrors&`$filter=onPremisesSyncEnabled eq true" -AllPages
        
        if ($syncedGroups) {
            foreach ($group in $syncedGroups) {
                if ($group.onPremisesProvisioningErrors -and $group.onPremisesProvisioningErrors.Count -gt 0) {
                    $totalObjectsWithErrors++
                    
                    foreach ($syncError in $group.onPremisesProvisioningErrors) {
                        $category = if ($syncError.category) { $syncError.category } else { "Unknown" }
                        
                        if (-not $errorsByCategory.ContainsKey($category)) {
                            $errorsByCategory[$category] = 0
                        }
                        $errorsByCategory[$category]++
                    }
                }
            }
        }
        
        # Report summary
        if ($totalObjectsWithErrors -eq 0) {
            Add-ModuleFinding -Status "OK" `
                -Object "Provisioning Errors" `
                -Description "No on-premises provisioning errors found across users and groups." `
                -Remediation "Continue monitoring via Azure AD Connect Health."
            return
        }
        
        Add-ModuleFinding -Status "FAIL" `
            -Object "Provisioning Errors Summary" `
            -Description "$totalObjectsWithErrors objects have provisioning errors preventing proper synchronization." `
            -Remediation "Review and resolve each error category. Errors prevent objects from syncing correctly."
        
        # Report by category
        if ($errorsByCategory.Count -gt 0) {
            $categorySummary = ($errorsByCategory.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ", "
            Add-ModuleFinding -Status "INFO" `
                -Object "Error Categories" `
                -Description "Distribution: $categorySummary" `
                -Remediation "Focus on the most common categories first."
        }
        
        # Provide specific guidance per error type
        if ($errorsByType["PropertyConflict"].Count -gt 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "Property Conflict Errors ($($errorsByType["PropertyConflict"].Count))" `
                -Description "Objects have conflicting attribute values (e.g., duplicate proxyAddresses, UPNs). Top affected: $(($errorsByType["PropertyConflict"] | Select-Object -First 3 | ForEach-Object { $_.Object }) -join ', ')" `
                -Remediation "Identify the source of the conflict in on-premises AD. Use IdFix tool to find and fix issues. Remove duplicate proxy addresses or resolve UPN conflicts."
        }
        
        if ($errorsByType["DataValidationFailed"].Count -gt 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "Data Validation Errors ($($errorsByType["DataValidationFailed"].Count))" `
                -Description "Objects have invalid attribute formats. Top affected: $(($errorsByType["DataValidationFailed"] | Select-Object -First 3 | ForEach-Object { $_.Object }) -join ', ')" `
                -Remediation "Check for invalid characters in attributes. Common issues: spaces in UPNs, invalid email formats. Use IdFix tool to identify and correct."
        }
        
        if ($errorsByType["LargeObject"].Count -gt 0) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Large Object Errors ($($errorsByType["LargeObject"].Count))" `
                -Description "Objects exceed attribute size limits. Top affected: $(($errorsByType["LargeObject"] | Select-Object -First 3 | ForEach-Object { $_.Object }) -join ', ')" `
                -Remediation "Reduce the number of values in multi-valued attributes (e.g., group membership). Consider using group-based licensing to reduce direct memberships."
        }
        
        if ($errorsByType["FederatedDomainChangeError"].Count -gt 0) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Federated Domain Errors ($($errorsByType["FederatedDomainChangeError"].Count))" `
                -Description "Errors related to federated domain configuration changes." `
                -Remediation "Verify domain federation settings are correct. Ensure users are not being moved between federated and managed domains incorrectly."
        }
    }
    catch {
        Add-ModuleFinding -Status "WARNING" `
            -Object "Provisioning Errors" `
            -Description "Unable to check provisioning errors: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Directory.Read.All required)."
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

<#
.SYNOPSIS
    Runs all hybrid identity checks.

.DESCRIPTION
    Convenience function to execute all checks in this module.
#>
function Invoke-HybridChecks {
    [CmdletBinding()]
    param()
    
    Write-Host "`n" -NoNewline
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host " Hybrid Identity Module Checks" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Magenta
    
    # Run all checks
    Test-DirectorySyncStatus
    Test-SyncErrors
    Test-PasswordHashSync
    Test-PassThroughAuthentication
    Test-SeamlessSSOStatus
    Test-OnPremisesProvisioningErrors
    
    Write-Host "`n[+] Hybrid identity checks complete." -ForegroundColor Magenta
}

# Export module members
Export-ModuleMember -Function @(
    'Initialize-HybridModule',
    'Test-DirectorySyncStatus',
    'Test-SyncErrors',
    'Test-PasswordHashSync',
    'Test-PassThroughAuthentication',
    'Test-SeamlessSSOStatus',
    'Test-OnPremisesProvisioningErrors',
    'Invoke-HybridChecks'
)

#endregion

# Auto-initialize when module is imported
$null = Initialize-HybridModule
