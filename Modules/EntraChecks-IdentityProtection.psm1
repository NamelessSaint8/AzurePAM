<#
.SYNOPSIS
    EntraChecks-IdentityProtection.psm1
    Optional module for Azure AD Identity Protection security checks

.DESCRIPTION
    This module extends Invoke-EntraChecks.ps1 with Identity Protection checks.
    These checks require Azure AD Premium P2 licensing.

    Checks included:
    - Test-RiskyUsers: Users flagged with risk by Identity Protection
    - Test-RiskySignIns: Recent risky sign-in events
    - Test-UserRiskPolicy: User risk policy configuration
    - Test-SignInRiskPolicy: Sign-in risk policy configuration
    - Test-RiskDetections: Recent risk detection events
    
.NOTES
    Version: 1.0.0
    Author: NamelessSaint
    Requires: Microsoft.Graph PowerShell SDK
    License Requirement: Azure AD Premium P2
    
    Required Graph Permissions:
    - IdentityRiskEvent.Read.All
    - IdentityRiskyUser.Read.All
    - Policy.Read.All
    
.LINK
    Main Script: Invoke-EntraChecks.ps1
    Graph API Reference: https://learn.microsoft.com/en-us/graph/api/resources/identityprotection-overview
#>

#Requires -Version 5.1

# Module version
$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-IdentityProtection"

#region ==================== MODULE INITIALIZATION ====================

<#
.SYNOPSIS
    Initializes the Identity Protection module.

.DESCRIPTION
    Checks prerequisites and registers module checks with the main script.
    Called automatically when module is imported.
#>
function Initialize-IdentityProtectionModule {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Loading module: $script:ModuleName v$script:ModuleVersion" -ForegroundColor Magenta
    
    # Verify main script context
    if (-not (Get-Variable -Name "Findings" -Scope Script -ErrorAction SilentlyContinue)) {
        # Create findings collection if running standalone
        $script:Findings = @()
        Write-Host "    [!] Running in standalone mode (no main script context)" -ForegroundColor Yellow
    }
    
    # Check for P2 license capability
    $hasP2 = $false
    if (Get-Variable -Name "TenantCapabilities" -Scope Script -ErrorAction SilentlyContinue) {
        $hasP2 = $script:TenantCapabilities.HasP2License
    }
    
    if (-not $hasP2) {
        Write-Host "    [!] Warning: Azure AD P2 license may not be available. Identity Protection checks may fail." -ForegroundColor Yellow
    }
    
    Write-Host "    [OK] Module loaded successfully" -ForegroundColor Green
    
    # Return module info
    return @{
        Name = $script:ModuleName
        Version = $script:ModuleVersion
        Checks = @(
            "Test-RiskyUsers",
            "Test-RiskySignIns", 
            "Test-UserRiskPolicy",
            "Test-SignInRiskPolicy",
            "Test-RiskDetections"
        )
        RequiredLicense = "Azure AD Premium P2"
        RequiredPermissions = @(
            "IdentityRiskEvent.Read.All",
            "IdentityRiskyUser.Read.All",
            "Policy.Read.All"
        )
    }
}

#endregion

#region ==================== HELPER FUNCTIONS ====================

<#
.SYNOPSIS
    Adds a finding to the findings collection (mirrors main script function).

.DESCRIPTION
    If running within main script context, uses the main Add-Finding function.
    If running standalone, adds to local collection.
#>
function Add-ModuleFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        # See Add-Finding for the REVIEW semantics — keep these two in sync.
        [ValidateSet("OK", "INFO", "WARNING", "FAIL", "REVIEW")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Object,

        [Parameter(Mandatory)]
        [string]$Description,

        [string]$Remediation = "",

        # v2 schema metadata (PR 2 of Central-Finding-Schema-GRC-Plan).
        # Mirror the surface from Add-Finding so module checks can supply
        # rich identity/owner/evidence inline.
        [string]$FindingKey = '',
        [string]$ObjectId = '',
        [string]$ObjectType = '',
        [string]$ResourceId = '',
        [string]$TenantId = '',
        [string]$SubscriptionId = '',
        $OwnerHint,
        [object[]]$Evidence
    )

    # Try to use main script's Add-Finding if available — forward the new
    # params via splatting so we don't drift from the canonical surface.
    if (Get-Command -Name "Add-Finding" -ErrorAction SilentlyContinue) {
        $forwardArgs = @{
            Status = $Status
            Object = $Object
            Description = $Description
            Remediation = $Remediation
        }
        foreach ($k in 'FindingKey', 'ObjectId', 'ObjectType', 'ResourceId', 'TenantId', 'SubscriptionId') {
            $val = (Get-Variable -Name $k -ValueOnly)
            if ($val) { $forwardArgs[$k] = $val }
        }
        if ($OwnerHint) { $forwardArgs['OwnerHint'] = $OwnerHint }
        if ($Evidence) { $forwardArgs['Evidence'] = $Evidence }
        Add-Finding @forwardArgs
    }
    else {
        # Standalone mode - add to local collection
        $finding = [PSCustomObject]@{
            Time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Status = $Status
            Object = $Object
            Description = $Description
            Remediation = $Remediation
            Module = $script:ModuleName
            FindingKey = $FindingKey
            ObjectId = $ObjectId
            ObjectType = $ObjectType
            ResourceId = $ResourceId
            TenantId = $TenantId
            SubscriptionId = $SubscriptionId
            OwnerHint = $OwnerHint
            Evidence = $Evidence
        }

        $script:Findings += $finding

        # Color-coded console output
        $color = switch ($Status) {
            "OK" { "Green" }
            "INFO" { "Cyan" }
            "REVIEW" { "Magenta" }
            "WARNING" { "Yellow" }
            "FAIL" { "Red" }
        }
        Write-Host "[$Status] $Object" -ForegroundColor $color
    }
}

<#
.SYNOPSIS
    Invokes a Graph API request (mirrors main script function).

.DESCRIPTION
    If running within main script context, uses the main Invoke-GraphRequest function.
    If running standalone, makes direct Graph API calls.
#>
function Invoke-ModuleGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        
        [switch]$AllPages
    )
    
    # Try to use main script's Invoke-GraphRequest if available
    if (Get-Command -Name "Invoke-GraphRequest" -ErrorAction SilentlyContinue) {
        if ($AllPages) {
            return Invoke-GraphRequest -Uri $Uri -AllPages
        }
        else {
            return Invoke-GraphRequest -Uri $Uri
        }
    }
    else {
        # Standalone mode - use Invoke-MgGraphRequest directly
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

#region ==================== IDENTITY PROTECTION CHECKS ====================

<#
.SYNOPSIS
    Test-RiskyUsers - Audits users flagged with risk by Identity Protection.

.DESCRIPTION
    Examines users that Identity Protection has identified as risky:
    - Users at high risk level (FAIL)
    - Users at medium risk level (WARNING)
    - Users at low risk level (INFO)
    - Risk state (atRisk, confirmedCompromised, remediated, dismissed)
    - Risk detail (reason for risk)
    
    Graph Endpoints Used:
    - GET /identityProtection/riskyUsers
    
.OUTPUTS
    Findings with Status based on risk level and state
    
.NOTES
    Required Permissions: IdentityRiskyUser.Read.All
    Minimum License: Azure AD Premium P2
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/riskyuser-list
#>
function Test-RiskyUsers {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking risky users (Identity Protection)..." -ForegroundColor Cyan
    
    try {
        # Get all risky users
        $riskyUsers = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$top=999" -AllPages
        
        if (-not $riskyUsers -or $riskyUsers.Count -eq 0) {
            Add-ModuleFinding -Status "OK" `
                -Object "Risky Users" `
                -Description "No users are currently flagged as risky by Identity Protection." `
                -Remediation "Continue monitoring. Identity Protection will flag users when risk is detected."
            return
        }
        
        # Categorize by risk level and state
        $highRisk = $riskyUsers | Where-Object { $_.riskLevel -eq "high" -and $_.riskState -in @("atRisk", "confirmedCompromised") }
        $mediumRisk = $riskyUsers | Where-Object { $_.riskLevel -eq "medium" -and $_.riskState -in @("atRisk", "confirmedCompromised") }
        $lowRisk = $riskyUsers | Where-Object { $_.riskLevel -eq "low" -and $_.riskState -in @("atRisk", "confirmedCompromised") }
        $remediated = $riskyUsers | Where-Object { $_.riskState -eq "remediated" }
        $dismissed = $riskyUsers | Where-Object { $_.riskState -eq "dismissed" }
        $confirmedCompromised = $riskyUsers | Where-Object { $_.riskState -eq "confirmedCompromised" }
        
        # Summary finding
        Add-ModuleFinding -Status "INFO" `
            -Object "Risky Users Summary" `
            -Description "Total risky users: $($riskyUsers.Count). High: $($highRisk.Count). Medium: $($mediumRisk.Count). Low: $($lowRisk.Count). Remediated: $($remediated.Count). Dismissed: $($dismissed.Count)." `
            -Remediation "Review all users at risk and take appropriate action (remediate, confirm compromise, or dismiss if false positive)."
        
        # High risk users - FAIL
        foreach ($user in $highRisk) {
            $riskDetail = if ($user.riskDetail) { $user.riskDetail } else { "Not specified" }
            $lastUpdated = if ($user.riskLastUpdatedDateTime) { 
                ([DateTime]$user.riskLastUpdatedDateTime).ToString("yyyy-MM-dd HH:mm") 
            } else { "Unknown" }
            
            Add-ModuleFinding -Status "FAIL" `
                -Object $user.userPrincipalName `
                -Description "HIGH RISK user detected. Risk state: $($user.riskState). Risk detail: $riskDetail. Last updated: $lastUpdated." `
                -Remediation "IMMEDIATE ACTION: Investigate this user. Reset password, revoke sessions, require MFA re-registration, and review sign-in logs for compromise indicators."
        }
        
        # Confirmed compromised users - FAIL
        foreach ($user in ($confirmedCompromised | Where-Object { $_.riskLevel -ne "high" })) {
            Add-ModuleFinding -Status "FAIL" `
                -Object $user.userPrincipalName `
                -Description "User CONFIRMED COMPROMISED. Risk level: $($user.riskLevel). This account has been marked as compromised." `
                -Remediation "IMMEDIATE ACTION: Reset password, revoke all sessions, review for data exfiltration, and re-enable only after full investigation."
        }
        
        # Medium risk users - WARNING
        foreach ($user in $mediumRisk) {
            $riskDetail = if ($user.riskDetail) { $user.riskDetail } else { "Not specified" }
            
            Add-ModuleFinding -Status "REVIEW" `
                -Object $user.userPrincipalName `
                -Description "MEDIUM RISK user detected. Risk state: $($user.riskState). Risk detail: $riskDetail." `
                -Remediation "Investigate this user. Consider requiring password reset or additional authentication verification."
        }
        
        # Low risk users - INFO (only if significant count)
        if ($lowRisk.Count -gt 0) {
            if ($lowRisk.Count -le 5) {
                foreach ($user in $lowRisk) {
                    Add-ModuleFinding -Status "INFO" `
                        -Object $user.userPrincipalName `
                        -Description "Low risk user detected. Risk detail: $($user.riskDetail)." `
                        -Remediation "Monitor this user. Low risk typically resolves automatically but should be reviewed."
                }
            }
            else {
                Add-ModuleFinding -Status "INFO" `
                    -Object "Low Risk Users" `
                    -Description "$($lowRisk.Count) users are at low risk level. These are typically minor anomalies." `
                    -Remediation "Review low-risk users periodically. Consider configuring risk-based Conditional Access to require step-up authentication."
            }
        }
        
        # Check for stale risks (not remediated for extended period)
        $staleThreshold = (Get-Date).AddDays(-30)
        $staleRisks = $riskyUsers | Where-Object { 
            $_.riskState -eq "atRisk" -and 
            $_.riskLastUpdatedDateTime -and 
            ([DateTime]$_.riskLastUpdatedDateTime) -lt $staleThreshold
        }
        
        if ($staleRisks.Count -gt 0) {
            Add-ModuleFinding -Status "REVIEW" `
                -Object "Stale Risk Detections" `
                -Description "$($staleRisks.Count) users have been at risk for over 30 days without remediation or dismissal." `
                -Remediation "Review stale risks. Either remediate (password reset) or dismiss if investigated and determined to be false positive."
        }
    }
    catch {
        if ($_.Exception.Message -match "Forbidden|Authorization|Premium") {
            Add-ModuleFinding -Status "INFO" `
                -Object "Risky Users" `
                -Description "Unable to check risky users. This feature requires Azure AD Premium P2 licensing." `
                -Remediation "Upgrade to Azure AD P2 to enable Identity Protection risky user detection."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Risky Users" `
                -Description "Unable to check risky users: $($_.Exception.Message)" `
                -Remediation "Check Graph permissions (IdentityRiskyUser.Read.All required) and P2 licensing."
        }
    }
}

<#
.SYNOPSIS
    Test-RiskySignIns - Audits recent risky sign-in events.

.DESCRIPTION
    Examines sign-ins that Identity Protection has flagged as risky:
    - High risk sign-ins
    - Medium risk sign-ins  
    - Sign-in risk aggregated by user
    - Risk types detected
    
    Graph Endpoints Used:
    - GET /identityProtection/riskDetections
    
.OUTPUTS
    Findings with Status based on risk severity and volume
    
.NOTES
    Required Permissions: IdentityRiskEvent.Read.All
    Minimum License: Azure AD Premium P2
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/riskdetection-list
#>
function Test-RiskySignIns {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking risky sign-ins (Identity Protection)..." -ForegroundColor Cyan
    
    try {
        # Get recent risk detections (last 7 days)
        $sevenDaysAgo = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        $riskDetections = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $sevenDaysAgo&`$top=999&`$orderby=detectedDateTime desc" -AllPages
        
        if (-not $riskDetections -or $riskDetections.Count -eq 0) {
            Add-ModuleFinding -Status "OK" `
                -Object "Risky Sign-Ins" `
                -Description "No risky sign-ins detected in the past 7 days." `
                -Remediation "Continue monitoring. Identity Protection will detect and flag risky sign-ins automatically."
            return
        }
        
        # Categorize detections
        $highRiskDetections = $riskDetections | Where-Object { $_.riskLevel -eq "high" }
        $mediumRiskDetections = $riskDetections | Where-Object { $_.riskLevel -eq "medium" }
        $lowRiskDetections = $riskDetections | Where-Object { $_.riskLevel -eq "low" }
        
        # Count by risk type
        $riskTypes = $riskDetections | Group-Object -Property riskEventType | Sort-Object Count -Descending
        
        # Count by user
        $userRiskCounts = $riskDetections | Group-Object -Property userPrincipalName | Sort-Object Count -Descending
        
        # Summary finding
        $topRiskTypes = ($riskTypes | Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
        
        Add-ModuleFinding -Status "INFO" `
            -Object "Risky Sign-Ins Summary (7 days)" `
            -Description "Total risk detections: $($riskDetections.Count). High: $($highRiskDetections.Count). Medium: $($mediumRiskDetections.Count). Low: $($lowRiskDetections.Count). Top risk types: $topRiskTypes." `
            -Remediation "Review high and medium risk detections. Configure risk-based Conditional Access policies to automatically respond to risky sign-ins."
        
        # High risk detections - FAIL
        if ($highRiskDetections.Count -gt 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "High Risk Sign-Ins" `
                -Description "$($highRiskDetections.Count) HIGH RISK sign-in(s) detected in the past 7 days. These indicate likely compromised accounts or active attacks." `
                -Remediation "URGENT: Investigate each high-risk sign-in immediately. Check source IPs, locations, and devices. Reset passwords for affected users."
            
            # Detail top 5 high risk detections
            $topHighRisk = $highRiskDetections | Select-Object -First 5
            foreach ($detection in $topHighRisk) {
                $detectedTime = ([DateTime]$detection.detectedDateTime).ToString("yyyy-MM-dd HH:mm")
                $location = if ($detection.location.city) { "$($detection.location.city), $($detection.location.countryOrRegion)" } else { "Unknown" }
                
                Add-ModuleFinding -Status "FAIL" `
                    -Object "$($detection.userPrincipalName) - $($detection.riskEventType)" `
                    -Description "High risk detection at $detectedTime. Type: $($detection.riskEventType). Location: $location. IP: $($detection.ipAddress). Status: $($detection.riskState)." `
                    -Remediation "Investigate this specific sign-in. Verify if user recognizes the activity. If not, treat as compromise."
            }
        }
        
        # Medium risk detections - REVIEW (per-detection investigation needed)
        if ($mediumRiskDetections.Count -gt 0) {
            Add-ModuleFinding -Status "REVIEW" `
                -Object "Medium Risk Sign-Ins" `
                -Description "$($mediumRiskDetections.Count) medium risk sign-in(s) detected in the past 7 days." `
                -Remediation "Review medium-risk sign-ins. Consider requiring MFA or password reset for affected users."
        }
        
        # Users with multiple risk detections
        $repeatOffenders = $userRiskCounts | Where-Object { $_.Count -ge 3 }
        
        if ($repeatOffenders.Count -gt 0) {
            foreach ($user in $repeatOffenders) {
                $userDetections = $riskDetections | Where-Object { $_.userPrincipalName -eq $user.Name }
                $highCount = ($userDetections | Where-Object { $_.riskLevel -eq "high" }).Count
                
                $status = if ($highCount -gt 0) { "FAIL" } else { "WARNING" }
                
                Add-ModuleFinding -Status $status `
                    -Object $user.Name `
                    -Description "User has $($user.Count) risk detections in 7 days ($highCount high risk). This pattern suggests ongoing targeting or compromise." `
                    -Remediation "Investigate this user thoroughly. Consider blocking sign-in until investigation complete. Review all recent activity."
            }
        }
        
        # Check for specific concerning risk types
        $concerningTypes = @(
            "anonymizedIPAddress",
            "malwareInfectedIPAddress", 
            "suspiciousIPAddress",
            "leakedCredentials",
            "investigationsThreatIntelligence"
        )
        
        $concerningDetections = $riskDetections | Where-Object { $concerningTypes -contains $_.riskEventType }
        
        if ($concerningDetections.Count -gt 0) {
            $typeCounts = ($concerningDetections | Group-Object riskEventType | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
            
            Add-ModuleFinding -Status "WARNING" `
                -Object "Concerning Risk Types Detected" `
                -Description "High-concern risk types found: $typeCounts. These indicate potential credential leaks, malware, or threat intelligence matches." `
                -Remediation "Prioritize investigation of these detections. Leaked credentials require immediate password reset. Malware detections require endpoint investigation."
        }
        
        # Check for impossible travel
        $impossibleTravel = $riskDetections | Where-Object { $_.riskEventType -eq "impossibleTravel" }
        
        if ($impossibleTravel.Count -gt 0) {
            Add-ModuleFinding -Status "REVIEW" `
                -Object "Impossible Travel Detections" `
                -Description "$($impossibleTravel.Count) impossible travel detection(s). Users appear to be signing in from geographically distant locations in short time periods." `
                -Remediation "Review each detection. Some may be VPN usage or legitimate travel. Others may indicate credential sharing or compromise."
        }
    }
    catch {
        if ($_.Exception.Message -match "Forbidden|Authorization|Premium") {
            Add-ModuleFinding -Status "INFO" `
                -Object "Risky Sign-Ins" `
                -Description "Unable to check risky sign-ins. This feature requires Azure AD Premium P2 licensing." `
                -Remediation "Upgrade to Azure AD P2 to enable Identity Protection risk detections."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Risky Sign-Ins" `
                -Description "Unable to check risky sign-ins: $($_.Exception.Message)" `
                -Remediation "Check Graph permissions (IdentityRiskEvent.Read.All required) and P2 licensing."
        }
    }
}

<#
.SYNOPSIS
    Test-UserRiskPolicy - Audits user risk policy configuration.

.DESCRIPTION
    Examines the user risk policy settings in Identity Protection:
    - Policy enabled/disabled state
    - Risk level threshold (high, medium, low)
    - Controls applied (block, MFA, password change)
    - User/group inclusions and exclusions
    
    Graph Endpoints Used:
    - GET /identity/conditionalAccess/policies (filter for risk-based)
    
.OUTPUTS
    Findings with Status based on policy configuration
    
.NOTES
    Required Permissions: Policy.Read.All
    Minimum License: Azure AD Premium P2
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy
#>
function Test-UserRiskPolicy {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking user risk policy configuration..." -ForegroundColor Cyan
    
    try {
        # Get Conditional Access policies and look for user risk conditions
        $caPolicies = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -AllPages
        
        # Filter for policies that use user risk
        $userRiskPolicies = @()
        
        if ($caPolicies) {
            foreach ($policy in $caPolicies) {
                if ($policy.conditions.userRiskLevels -and $policy.conditions.userRiskLevels.Count -gt 0) {
                    $userRiskPolicies += $policy
                }
            }
        }
        
        if ($userRiskPolicies.Count -eq 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "User Risk Policy" `
                -Description "No Conditional Access policies are configured to respond to user risk. Risky users will not be automatically remediated." `
                -Remediation "Create a Conditional Access policy that requires password change or blocks access when user risk is high or medium."
            return
        }
        
        # Analyze each user risk policy
        $hasHighRiskPolicy = $false
        $hasMediumRiskPolicy = $false
        $enabledPolicyCount = 0
        
        foreach ($policy in $userRiskPolicies) {
            $state = $policy.state
            $riskLevels = $policy.conditions.userRiskLevels -join ", "
            $grantControls = if ($policy.grantControls.builtInControls) { $policy.grantControls.builtInControls -join ", " } else { "None" }
            
            if ($state -eq "enabled") {
                $enabledPolicyCount++
                
                if ($policy.conditions.userRiskLevels -contains "high") { $hasHighRiskPolicy = $true }
                if ($policy.conditions.userRiskLevels -contains "medium") { $hasMediumRiskPolicy = $true }
            }
            
            # Determine finding status
            $status = switch ($state) {
                "enabled" { "OK" }
                "enabledForReportingButNotEnforced" { "WARNING" }
                "disabled" { "WARNING" }
                default { "INFO" }
            }
            
            # Check for appropriate controls
            $hasGoodControls = $policy.grantControls.builtInControls -contains "passwordChange" -or 
            $policy.grantControls.builtInControls -contains "block" -or
            $policy.grantControls.builtInControls -contains "mfa"
            
            if ($state -eq "enabled" -and -not $hasGoodControls) {
                $status = "WARNING"
            }
            
            Add-ModuleFinding -Status $status `
                -Object "User Risk Policy: $($policy.displayName)" `
                -Description "State: $state. Risk levels: $riskLevels. Controls: $grantControls." `
                -Remediation $(if ($state -ne "enabled") { "Enable this policy to protect against risky users." } 
                elseif (-not $hasGoodControls) { "Add password change or block control for better protection." }
                else { "Policy is configured appropriately. Review periodically." })
        }
        
        # Summary findings
        if ($enabledPolicyCount -eq 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "User Risk Policies" `
                -Description "User risk policies exist but none are enabled. Risky users are not being automatically remediated." `
                -Remediation "Enable at least one user risk policy to protect against compromised accounts."
        }
        elseif (-not $hasHighRiskPolicy) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "High Risk Coverage" `
                -Description "No enabled policy covers high-risk users. High-risk users represent the most likely compromised accounts." `
                -Remediation "Create or modify a policy to require password change or block for high-risk users."
        }
        else {
            Add-ModuleFinding -Status "OK" `
                -Object "User Risk Policy Coverage" `
                -Description "$enabledPolicyCount enabled user risk polic(ies) found. High risk covered: $hasHighRiskPolicy. Medium risk covered: $hasMediumRiskPolicy." `
                -Remediation "Continue monitoring policy effectiveness. Review remediation rates in Identity Protection reports."
        }
    }
    catch {
        if ($_.Exception.Message -match "Forbidden|Authorization|Premium") {
            Add-ModuleFinding -Status "INFO" `
                -Object "User Risk Policy" `
                -Description "Unable to check user risk policy. Risk-based Conditional Access requires Azure AD Premium P2." `
                -Remediation "Upgrade to Azure AD P2 to enable risk-based Conditional Access policies."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "User Risk Policy" `
                -Description "Unable to check user risk policy: $($_.Exception.Message)" `
                -Remediation "Check Graph permissions (Policy.Read.All required) and P2 licensing."
        }
    }
}

<#
.SYNOPSIS
    Test-SignInRiskPolicy - Audits sign-in risk policy configuration.

.DESCRIPTION
    Examines the sign-in risk policy settings in Identity Protection:
    - Policy enabled/disabled state
    - Risk level threshold (high, medium, low)
    - Controls applied (block, MFA)
    - Real-time vs offline detection coverage
    
    Graph Endpoints Used:
    - GET /identity/conditionalAccess/policies (filter for sign-in risk)
    
.OUTPUTS
    Findings with Status based on policy configuration
    
.NOTES
    Required Permissions: Policy.Read.All
    Minimum License: Azure AD Premium P2
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy
#>
function Test-SignInRiskPolicy {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking sign-in risk policy configuration..." -ForegroundColor Cyan
    
    try {
        # Get Conditional Access policies and look for sign-in risk conditions
        $caPolicies = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -AllPages
        
        # Filter for policies that use sign-in risk
        $signInRiskPolicies = @()
        
        if ($caPolicies) {
            foreach ($policy in $caPolicies) {
                if ($policy.conditions.signInRiskLevels -and $policy.conditions.signInRiskLevels.Count -gt 0) {
                    $signInRiskPolicies += $policy
                }
            }
        }
        
        if ($signInRiskPolicies.Count -eq 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "Sign-In Risk Policy" `
                -Description "No Conditional Access policies are configured to respond to sign-in risk. Risky sign-ins will not be challenged or blocked." `
                -Remediation "Create a Conditional Access policy that requires MFA or blocks access when sign-in risk is high or medium."
            return
        }
        
        # Analyze each sign-in risk policy
        $hasHighRiskPolicy = $false
        $hasMediumRiskPolicy = $false
        $enabledPolicyCount = 0
        $hasMfaControl = $false
        
        foreach ($policy in $signInRiskPolicies) {
            $state = $policy.state
            $riskLevels = $policy.conditions.signInRiskLevels -join ", "
            $grantControls = if ($policy.grantControls.builtInControls) { $policy.grantControls.builtInControls -join ", " } else { "None" }
            
            if ($state -eq "enabled") {
                $enabledPolicyCount++
                
                if ($policy.conditions.signInRiskLevels -contains "high") { $hasHighRiskPolicy = $true }
                if ($policy.conditions.signInRiskLevels -contains "medium") { $hasMediumRiskPolicy = $true }
                if ($policy.grantControls.builtInControls -contains "mfa") { $hasMfaControl = $true }
            }
            
            # Determine finding status
            $status = switch ($state) {
                "enabled" { "OK" }
                "enabledForReportingButNotEnforced" { "WARNING" }
                "disabled" { "WARNING" }
                default { "INFO" }
            }
            
            # Check for appropriate controls
            $hasGoodControls = $policy.grantControls.builtInControls -contains "mfa" -or 
            $policy.grantControls.builtInControls -contains "block"
            
            if ($state -eq "enabled" -and -not $hasGoodControls) {
                $status = "WARNING"
            }
            
            Add-ModuleFinding -Status $status `
                -Object "Sign-In Risk Policy: $($policy.displayName)" `
                -Description "State: $state. Risk levels: $riskLevels. Controls: $grantControls." `
                -Remediation $(if ($state -ne "enabled") { "Enable this policy to challenge risky sign-ins." } 
                elseif (-not $hasGoodControls) { "Add MFA or block control for better protection." }
                else { "Policy is configured appropriately. Review periodically." })
        }
        
        # Summary findings
        if ($enabledPolicyCount -eq 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "Sign-In Risk Policies" `
                -Description "Sign-in risk policies exist but none are enabled. Risky sign-ins are not being challenged." `
                -Remediation "Enable at least one sign-in risk policy to protect against suspicious authentication attempts."
        }
        elseif (-not $hasHighRiskPolicy) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "High Risk Sign-In Coverage" `
                -Description "No enabled policy covers high-risk sign-ins. High-risk sign-ins are very likely to be attacks." `
                -Remediation "Create or modify a policy to block or require MFA for high-risk sign-ins."
        }
        elseif (-not $hasMfaControl -and -not ($signInRiskPolicies | Where-Object { $_.state -eq "enabled" -and $_.grantControls.builtInControls -contains "block" })) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Sign-In Risk Controls" `
                -Description "Sign-in risk policies don't require MFA or block. Without these controls, risky sign-ins may still succeed." `
                -Remediation "Add MFA requirement as a minimum control for risky sign-ins."
        }
        else {
            Add-ModuleFinding -Status "OK" `
                -Object "Sign-In Risk Policy Coverage" `
                -Description "$enabledPolicyCount enabled sign-in risk polic(ies) found. High risk covered: $hasHighRiskPolicy. Medium risk covered: $hasMediumRiskPolicy. MFA required: $hasMfaControl." `
                -Remediation "Continue monitoring policy effectiveness. Review blocked/challenged sign-ins in reports."
        }
    }
    catch {
        if ($_.Exception.Message -match "Forbidden|Authorization|Premium") {
            Add-ModuleFinding -Status "INFO" `
                -Object "Sign-In Risk Policy" `
                -Description "Unable to check sign-in risk policy. Risk-based Conditional Access requires Azure AD Premium P2." `
                -Remediation "Upgrade to Azure AD P2 to enable risk-based Conditional Access policies."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Sign-In Risk Policy" `
                -Description "Unable to check sign-in risk policy: $($_.Exception.Message)" `
                -Remediation "Check Graph permissions (Policy.Read.All required) and P2 licensing."
        }
    }
}

<#
.SYNOPSIS
    Test-RiskDetections - Provides detailed analysis of recent risk detections.

.DESCRIPTION
    Deep-dive analysis of risk detection patterns:
    - Detection types distribution
    - Source IP analysis
    - Geographic patterns
    - Time-based patterns
    - Token issuer anomalies
    
    Graph Endpoints Used:
    - GET /identityProtection/riskDetections
    
.OUTPUTS
    Findings with Status based on detection patterns
    
.NOTES
    Required Permissions: IdentityRiskEvent.Read.All
    Minimum License: Azure AD Premium P2
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/riskdetection-list
#>
function Test-RiskDetections {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Analyzing risk detection patterns..." -ForegroundColor Cyan
    
    try {
        # Get risk detections from last 30 days
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        $riskDetections = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $thirtyDaysAgo&`$top=999" -AllPages
        
        if (-not $riskDetections -or $riskDetections.Count -eq 0) {
            Add-ModuleFinding -Status "OK" `
                -Object "Risk Detections (30 days)" `
                -Description "No risk detections in the past 30 days. The environment appears secure." `
                -Remediation "Continue monitoring. Consider this a healthy baseline for future comparison."
            return
        }
        
        # Analyze detection types
        $detectionTypes = $riskDetections | Group-Object -Property riskEventType | Sort-Object Count -Descending
        
        # Analyze by location
        $locations = $riskDetections | Where-Object { $_.location.countryOrRegion } | 
            Group-Object -Property { $_.location.countryOrRegion } | 
            Sort-Object Count -Descending
        
        # Analyze by IP
        $ipAddresses = $riskDetections | Where-Object { $_.ipAddress } | 
            Group-Object -Property ipAddress | 
            Sort-Object Count -Descending
        
        # Summary finding
        $topTypes = ($detectionTypes | Select-Object -First 3 | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
        
        Add-ModuleFinding -Status "INFO" `
            -Object "Risk Detection Analysis (30 days)" `
            -Description "Total detections: $($riskDetections.Count). Unique detection types: $($detectionTypes.Count). Top types: $topTypes." `
            -Remediation "Use this data to identify patterns and tune security controls."
        
        # Check for concerning geographic patterns
        $unexpectedCountries = @()
        $expectedCountries = @("US", "CA", "GB", "DE", "FR", "AU")  # Adjust based on org
        
        foreach ($loc in $locations) {
            if ($expectedCountries -notcontains $loc.Name -and $loc.Count -ge 3) {
                $unexpectedCountries += "$($loc.Name): $($loc.Count)"
            }
        }
        
        if ($unexpectedCountries.Count -gt 0) {
            Add-ModuleFinding -Status "REVIEW" `
                -Object "Unexpected Geographic Activity" `
                -Description "Risk detections from unexpected countries: $($unexpectedCountries -join ', '). This may indicate credential abuse from foreign locations." `
                -Remediation "Review if these countries are expected for your organization. Consider blocking authentication from unexpected regions."
        }
        
        # Report top source IPs
        $topIPs = $ipAddresses | Where-Object { $_.Count -ge 5 } | Select-Object -First 5
        
        if ($topIPs.Count -gt 0) {
            $ipSummary = ($topIPs | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
            
            Add-ModuleFinding -Status "WARNING" `
                -Object "Repeat Offender IPs" `
                -Description "IP addresses with multiple risk detections: $ipSummary. These IPs are generating repeated suspicious activity." `
                -Remediation "Consider blocking these IPs at the network level or in Conditional Access named locations."
        }
        
        # Check for anonymous IP usage
        $anonymousIP = $detectionTypes | Where-Object { $_.Name -eq "anonymizedIPAddress" }
        
        if ($anonymousIP -and $anonymousIP.Count -ge 5) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Anonymous IP Activity" `
                -Description "$($anonymousIP.Count) sign-ins detected from anonymous IP addresses (VPNs, Tor, proxies) in 30 days." `
                -Remediation "If anonymous IPs are not expected, create a Conditional Access policy to block or challenge sign-ins from anonymous IPs."
        }
        
        # Check for leaked credentials
        $leakedCreds = $detectionTypes | Where-Object { $_.Name -eq "leakedCredentials" }
        
        if ($leakedCreds -and $leakedCreds.Count -gt 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "Leaked Credentials Detected" `
                -Description "$($leakedCreds.Count) user(s) have credentials that appear in known breach databases." `
                -Remediation "IMMEDIATE ACTION: Force password reset for all affected users. Enable password protection to prevent known-breached passwords."
        }
        
        # Check for malware-linked IPs
        $malwareIP = $detectionTypes | Where-Object { $_.Name -eq "malwareInfectedIPAddress" }
        
        if ($malwareIP -and $malwareIP.Count -gt 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "Malware-Linked IP Activity" `
                -Description "$($malwareIP.Count) sign-in(s) from IP addresses associated with malware command and control." `
                -Remediation "IMMEDIATE ACTION: Investigate affected users and devices. Check for malware infection. Reset credentials and scan endpoints."
        }
        
        # Check for password spray attacks
        $passwordSpray = $detectionTypes | Where-Object { $_.Name -eq "passwordSpray" }
        
        if ($passwordSpray -and $passwordSpray.Count -gt 0) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Password Spray Attack Detected" `
                -Description "$($passwordSpray.Count) password spray detection(s). Attackers are attempting to authenticate with common passwords across multiple accounts." `
                -Remediation "Enable Azure AD Password Protection to block common passwords. Ensure MFA is enforced for all users. Review Smart Lockout settings."
        }
        
        # Trend analysis - compare to previous period
        $previousPeriodStart = (Get-Date).AddDays(-60).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $previousPeriodEnd = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        try {
            $previousDetections = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $previousPeriodStart and detectedDateTime lt $previousPeriodEnd&`$count=true" -AllPages
            
            $previousCount = if ($previousDetections) { $previousDetections.Count } else { 0 }
            $currentCount = $riskDetections.Count
            
            if ($previousCount -gt 0) {
                $changePercent = [math]::Round((($currentCount - $previousCount) / $previousCount) * 100, 0)
                
                if ($changePercent -gt 50) {
                    Add-ModuleFinding -Status "REVIEW" `
                        -Object "Risk Detection Trend" `
                        -Description "Risk detections increased by $changePercent% compared to previous 30 days (from $previousCount to $currentCount). This may indicate increased targeting." `
                        -Remediation "Investigate the increase. Review if new attack campaigns are targeting your organization."
                }
                elseif ($changePercent -lt -30) {
                    Add-ModuleFinding -Status "OK" `
                        -Object "Risk Detection Trend" `
                        -Description "Risk detections decreased by $([math]::Abs($changePercent))% compared to previous 30 days (from $previousCount to $currentCount)." `
                        -Remediation "Positive trend. Continue current security practices."
                }
                else {
                    Add-ModuleFinding -Status "INFO" `
                        -Object "Risk Detection Trend" `
                        -Description "Risk detections relatively stable: $previousCount (prev 30d) vs $currentCount (current 30d). Change: $changePercent%." `
                        -Remediation "Stable baseline. Monitor for significant changes."
                }
            }
        }
        catch {
            Write-Verbose "Trend analysis failed (not critical): $_"
        }
    }
    catch {
        if ($_.Exception.Message -match "Forbidden|Authorization|Premium") {
            Add-ModuleFinding -Status "INFO" `
                -Object "Risk Detections" `
                -Description "Unable to analyze risk detections. This feature requires Azure AD Premium P2 licensing." `
                -Remediation "Upgrade to Azure AD P2 to enable Identity Protection risk detection analysis."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Risk Detections" `
                -Description "Unable to analyze risk detections: $($_.Exception.Message)" `
                -Remediation "Check Graph permissions (IdentityRiskEvent.Read.All required) and P2 licensing."
        }
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

<#
.SYNOPSIS
    Runs all Identity Protection checks.

.DESCRIPTION
    Convenience function to execute all checks in this module.
#>
function Invoke-IdentityProtectionChecks {
    [CmdletBinding()]
    param()
    
    Write-Host "`n" -NoNewline
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host " Identity Protection Module Checks" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Magenta
    
    # Run all checks
    Test-RiskyUsers
    Test-RiskySignIns
    Test-UserRiskPolicy
    Test-SignInRiskPolicy
    Test-RiskDetections
    
    Write-Host "`n[+] Identity Protection checks complete." -ForegroundColor Magenta
}

# Export module members
Export-ModuleMember -Function @(
    'Initialize-IdentityProtectionModule',
    'Test-RiskyUsers',
    'Test-RiskySignIns',
    'Test-UserRiskPolicy',
    'Test-SignInRiskPolicy',
    'Test-RiskDetections',
    'Invoke-IdentityProtectionChecks'
)

#endregion

# Auto-initialize when module is imported
$null = Initialize-IdentityProtectionModule
