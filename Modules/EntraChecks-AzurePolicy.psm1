<#
.SYNOPSIS
    EntraChecks-AzurePolicy.psm1
    Module for Azure Policy compliance state integration

.DESCRIPTION
    This module retrieves Azure Policy compliance data across subscriptions,
    providing visibility into policy assignments, compliance states, and
    non-compliant resources. It integrates with the EntraChecks compliance
    reporting framework.
    
    Features:
    - Multi-subscription policy compliance assessment
    - Initiative (policy set) compliance tracking
    - Individual policy compliance details
    - Non-compliant resource identification
    - Remediation task status
    - Integration with unified compliance reporting
    
.NOTES
    Version: 1.0.0
    Author: David Stells
    Requires: Az.PolicyInsights, Az.Resources, Az.Accounts PowerShell modules
    
    Required Azure RBAC Role:
    - Reader (minimum for compliance data)
    - Resource Policy Contributor (for remediation details)
    
.LINK
    Main Script: Invoke-EntraChecks.ps1
    Azure Policy: https://learn.microsoft.com/en-us/azure/governance/policy/
#>

#Requires -Version 5.1

# Module version
$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-AzurePolicy"

# Provenance: data source key for any findings this module emits via Add-Finding.
# Matches a key in EntraChecks-DataSources.psm1 :: $script:DataSourceCatalog.
$script:DataSourceKey = 'AzurePolicy'

#region ==================== POLICY CATEGORY MAPPINGS ====================

# Map Azure Policy categories to compliance frameworks
$script:PolicyCategoryToFramework = @{
    "Security Center" = @("CIS", "NIST", "Security")
    "Compute" = @("CIS", "Security")
    "Storage" = @("CIS", "NIST", "Security")
    "Network" = @("CIS", "NIST", "Security")
    "Monitoring" = @("NIST", "Audit")
    "Key Vault" = @("CIS", "NIST", "Security")
    "SQL" = @("CIS", "Security", "Data")
    "App Service" = @("CIS", "Security")
    "Kubernetes" = @("CIS", "Security")
    "Guest Configuration" = @("CIS", "NIST", "Security")
    "Regulatory Compliance" = @("CIS", "NIST", "PCI", "ISO")
    "Tags" = @("Governance")
    "General" = @("Governance")
    "Backup" = @("NIST", "Resilience")
    "Managed Identity" = @("Security", "Identity")
}

# Well-known built-in initiative definitions (Policy Sets)
$script:WellKnownInitiatives = @{
    # CIS Benchmarks
    "CIS Microsoft Azure Foundations Benchmark v1.4.0" = @{
        ShortName = "CIS Azure 1.4"
        Framework = "CIS"
        Type = "Regulatory"
    }
    "CIS Microsoft Azure Foundations Benchmark v2.0.0" = @{
        ShortName = "CIS Azure 2.0"
        Framework = "CIS"
        Type = "Regulatory"
    }
    
    # NIST
    "NIST SP 800-53 Rev. 5" = @{
        ShortName = "NIST 800-53 R5"
        Framework = "NIST"
        Type = "Regulatory"
    }
    "NIST SP 800-171 Rev. 2" = @{
        ShortName = "NIST 800-171"
        Framework = "NIST"
        Type = "Regulatory"
    }
    
    # PCI-DSS
    "PCI DSS v4" = @{
        ShortName = "PCI-DSS 4.0"
        Framework = "PCI"
        Type = "Regulatory"
    }
    "PCI v3.2.1:2018" = @{
        ShortName = "PCI-DSS 3.2.1"
        Framework = "PCI"
        Type = "Regulatory"
    }
    
    # ISO
    "ISO 27001:2013" = @{
        ShortName = "ISO 27001"
        Framework = "ISO"
        Type = "Regulatory"
    }
    
    # Azure Security Benchmark
    "Azure Security Benchmark" = @{
        ShortName = "ASB"
        Framework = "Microsoft"
        Type = "Security"
    }
    "Microsoft cloud security benchmark" = @{
        ShortName = "MCSB"
        Framework = "Microsoft"
        Type = "Security"
    }
    
    # SOC
    "SOC 2 Type 2" = @{
        ShortName = "SOC 2"
        Framework = "SOC"
        Type = "Regulatory"
    }
}

#endregion

#region ==================== MODULE INITIALIZATION ====================

<#
.SYNOPSIS
    Initializes the Azure Policy compliance module and verifies required Az modules.
#>
function Initialize-AzurePolicyModule {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Loading module: $script:ModuleName v$script:ModuleVersion" -ForegroundColor Magenta
    
    # Check for Az modules
    $requiredModules = @("Az.Accounts", "Az.PolicyInsights", "Az.Resources")
    $missingModules = @()
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Host "    [!] Missing modules: $($missingModules -join ', ')" -ForegroundColor Yellow
        Write-Host "    [!] Install with: Install-Module $($missingModules -join ', ')" -ForegroundColor Yellow
    }
    
    # Check Azure connection
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azContext) {
        Write-Host "    [!] Not connected to Azure. Connect with: Connect-AzAccount" -ForegroundColor Yellow
    }
    else {
        Write-Host "    [i] Connected as: $($azContext.Account.Id)" -ForegroundColor Gray
        Write-Host "    [i] Current subscription: $($azContext.Subscription.Name)" -ForegroundColor Gray
    }
    
    Write-Host "    [OK] Module loaded successfully" -ForegroundColor Green
    
    return @{
        Name = $script:ModuleName
        Version = $script:ModuleVersion
        Type = "ExternalCompliance"
        RequiredAuth = "AzureRM"
        RequiredModules = $requiredModules
        RequiredRole = "Reader"
    }
}

#endregion

#region ==================== HELPER FUNCTIONS ====================

<#
.SYNOPSIS
    Gets available Azure subscriptions for policy assessment.
#>
function Get-PolicySubscriptions {
    [CmdletBinding()]
    param(
        [string[]]$SubscriptionFilter,
        [string[]]$ExcludeSubscriptions
    )
    
    try {
        $subscriptions = Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq "Enabled" }
        
        if ($SubscriptionFilter -and $SubscriptionFilter.Count -gt 0) {
            $subscriptions = $subscriptions | Where-Object { 
                $_.Id -in $SubscriptionFilter -or $_.Name -in $SubscriptionFilter 
            }
        }
        
        if ($ExcludeSubscriptions -and $ExcludeSubscriptions.Count -gt 0) {
            $subscriptions = $subscriptions | Where-Object { 
                $_.Id -notin $ExcludeSubscriptions -and $_.Name -notin $ExcludeSubscriptions 
            }
        }
        
        return $subscriptions
    }
    catch {
        Write-Host "[!] Error getting subscriptions: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

<#
.SYNOPSIS
    Determines if a policy/initiative is regulatory compliance related.
#>
function Get-InitiativeFrameworkInfo {
    [CmdletBinding()]
    param(
        [string]$DisplayName
    )
    
    foreach ($key in $script:WellKnownInitiatives.Keys) {
        if ($DisplayName -like "*$key*") {
            return $script:WellKnownInitiatives[$key]
        }
    }
    
    return $null
}

<#
.SYNOPSIS
    Converts Azure Policy compliance state to standard status.
#>
function ConvertTo-PolicyStatus {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [string]$ComplianceState
    )
    
    switch ($ComplianceState.ToLower()) {
        "compliant" { return "Passed" }
        "noncompliant" { return "Failed" }
        "exempt" { return "Exempt" }
        "conflicting" { return "Conflict" }
        "notstarted" { return "NotAssessed" }
        "unknown" { return "Unknown" }
        default { return "Unknown" }
    }
}

#endregion

#region ==================== POLICY COMPLIANCE RETRIEVAL ====================

<#
.SYNOPSIS
    Gets policy assignments for a subscription.

.DESCRIPTION
    Retrieves all policy and initiative assignments at subscription scope.

.PARAMETER SubscriptionId
    Azure subscription ID.

.OUTPUTS
    Array of policy assignments.
#>
function Get-PolicyAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )
    
    try {
        $null = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
        
        $assignments = Get-AzPolicyAssignment -ErrorAction Stop
        
        $results = @()
        foreach ($assignment in $assignments) {
            # Determine if this is an initiative or individual policy
            $isInitiative = $assignment.Properties.PolicyDefinitionId -match "policySetDefinitions"
            
            # Get framework info if applicable
            $frameworkInfo = Get-InitiativeFrameworkInfo -DisplayName $assignment.Properties.DisplayName
            
            $results += [PSCustomObject]@{
                AssignmentId = $assignment.ResourceId
                Name = $assignment.Name
                DisplayName = $assignment.Properties.DisplayName
                Description = $assignment.Properties.Description
                PolicyDefinitionId = $assignment.Properties.PolicyDefinitionId
                IsInitiative = $isInitiative
                Scope = $assignment.Properties.Scope
                EnforcementMode = $assignment.Properties.EnforcementMode
                Framework = if ($frameworkInfo) { $frameworkInfo.Framework } else { "Custom" }
                ShortName = if ($frameworkInfo) { $frameworkInfo.ShortName } else { $assignment.Properties.DisplayName }
                Type = if ($frameworkInfo) { $frameworkInfo.Type } else { "Custom" }
            }
        }
        
        return $results
    }
    catch {
        Write-Verbose "Error getting policy assignments: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Gets compliance summary for a subscription.

.DESCRIPTION
    Retrieves overall policy compliance summary including compliant and
    non-compliant resource counts.

.PARAMETER SubscriptionId
    Azure subscription ID.

.OUTPUTS
    Compliance summary object.
#>
function Get-PolicyComplianceSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )
    
    try {
        $null = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
        
        $summary = Get-AzPolicyStateSummary -SubscriptionId $SubscriptionId -ErrorAction Stop
        
        if ($summary -and $summary.Results) {
            return [PSCustomObject]@{
                SubscriptionId = $SubscriptionId
                TotalResources = $summary.Results.ResourceDetails.Count
                NonCompliantResources = $summary.Results.NonCompliantResources
                NonCompliantPolicies = $summary.Results.NonCompliantPolicies
                PolicyAssignments = $summary.PolicyAssignments.Count
                PolicyDefinitions = $summary.PolicyDefinitions.Count
            }
        }
        
        return $null
    }
    catch {
        Write-Verbose "Error getting compliance summary: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Gets detailed policy compliance states.

.DESCRIPTION
    Retrieves policy compliance states for all policies in a subscription,
    including individual policy and resource-level compliance.

.PARAMETER SubscriptionId
    Azure subscription ID.

.PARAMETER PolicyAssignmentId
    Optional - filter to specific assignment.

.PARAMETER Top
    Maximum number of results to return.

.OUTPUTS
    Array of policy state objects.
#>
function Get-PolicyComplianceStates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        
        [Parameter()]
        [string]$PolicyAssignmentId,
        
        [Parameter()]
        [int]$Top = 1000
    )
    
    try {
        $null = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
        
        $params = @{
            SubscriptionId = $SubscriptionId
            Top = $Top
            ErrorAction = "Stop"
        }
        
        if ($PolicyAssignmentId) {
            $params.PolicyAssignmentId = $PolicyAssignmentId
        }
        
        $states = Get-AzPolicyState @params
        
        $results = @()
        foreach ($state in $states) {
            $results += [PSCustomObject]@{
                ResourceId = $state.ResourceId
                ResourceType = $state.ResourceType
                ResourceLocation = $state.ResourceLocation
                ResourceGroup = $state.ResourceGroup
                PolicyAssignmentId = $state.PolicyAssignmentId
                PolicyAssignmentName = $state.PolicyAssignmentName
                PolicyAssignmentScope = $state.PolicyAssignmentScope
                PolicyDefinitionId = $state.PolicyDefinitionId
                PolicyDefinitionName = $state.PolicyDefinitionName
                PolicyDefinitionAction = $state.PolicyDefinitionAction
                ComplianceState = ConvertTo-PolicyStatus -ComplianceState $state.ComplianceState
                IsCompliant = $state.IsCompliant
                Timestamp = $state.Timestamp
                SubscriptionId = $state.SubscriptionId
            }
        }
        
        return $results
    }
    catch {
        Write-Verbose "Error getting policy states: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Gets non-compliant resources for a policy.

.DESCRIPTION
    Retrieves details about resources that are non-compliant with a specific
    policy or across all policies.

.PARAMETER SubscriptionId
    Azure subscription ID.

.PARAMETER PolicyAssignmentId
    Optional - filter to specific assignment.

.OUTPUTS
    Array of non-compliant resource details.
#>
function Get-NonCompliantResources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        
        [Parameter()]
        [string]$PolicyAssignmentId,
        
        [Parameter()]
        [int]$Top = 100
    )
    
    try {
        $null = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
        
        $params = @{
            SubscriptionId = $SubscriptionId
            Filter = "ComplianceState eq 'NonCompliant'"
            Top = $Top
            ErrorAction = "Stop"
        }
        
        if ($PolicyAssignmentId) {
            $params.PolicyAssignmentId = $PolicyAssignmentId
        }
        
        $states = Get-AzPolicyState @params
        
        $results = @()
        foreach ($state in $states) {
            $results += [PSCustomObject]@{
                ResourceId = $state.ResourceId
                ResourceName = ($state.ResourceId -split "/")[-1]
                ResourceType = $state.ResourceType
                ResourceGroup = $state.ResourceGroup
                PolicyName = $state.PolicyDefinitionName
                PolicyAssignment = $state.PolicyAssignmentName
                Reason = $state.PolicyDefinitionAction
                Timestamp = $state.Timestamp
            }
        }
        
        return $results
    }
    catch {
        Write-Verbose "Error getting non-compliant resources: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Gets remediation tasks for a subscription.

.DESCRIPTION
    Retrieves policy remediation tasks and their status.

.PARAMETER SubscriptionId
    Azure subscription ID.

.OUTPUTS
    Array of remediation task objects.
#>
function Get-PolicyRemediationTasks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )
    
    try {
        $null = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
        
        $remediations = Get-AzPolicyRemediation -ErrorAction Stop
        
        $results = @()
        foreach ($remediation in $remediations) {
            $results += [PSCustomObject]@{
                Name = $remediation.Name
                PolicyAssignmentId = $remediation.PolicyAssignmentId
                ProvisioningState = $remediation.ProvisioningState
                DeploymentStatus = $remediation.DeploymentSummary
                CreatedOn = $remediation.CreatedOn
                LastUpdatedOn = $remediation.LastUpdatedOn
                ResourceDiscoveryMode = $remediation.ResourceDiscoveryMode
            }
        }
        
        return $results
    }
    catch {
        Write-Verbose "Error getting remediation tasks: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Gets comprehensive Azure Policy compliance assessment.

.DESCRIPTION
    Main function for gathering Azure Policy compliance data across
    one or more subscriptions. Produces standardized output for
    integration with the Compliance module.

.PARAMETER Subscriptions
    Array of subscription IDs or names. If not specified, uses all available.

.PARAMETER IncludeNonCompliantResources
    Include details about non-compliant resources.

.PARAMETER IncludeRemediationTasks
    Include remediation task status.

.OUTPUTS
    Standardized compliance data object.
#>
function Get-AzurePolicyComplianceAssessment {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$Subscriptions,
        
        [switch]$IncludeNonCompliantResources,
        
        [switch]$IncludeRemediationTasks
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host " Azure Policy Compliance Assessment" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Magenta
    
    # Verify Azure connection
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-Host "`n[!] Not connected to Azure. Run Connect-AzAccount first." -ForegroundColor Red
        return $null
    }
    
    # Get subscriptions
    $targetSubscriptions = if ($Subscriptions) {
        Get-PolicySubscriptions -SubscriptionFilter $Subscriptions
    }
    else {
        Get-PolicySubscriptions
    }
    
    if (-not $targetSubscriptions -or $targetSubscriptions.Count -eq 0) {
        Write-Host "[!] No accessible subscriptions found" -ForegroundColor Red
        return $null
    }
    
    Write-Host "`n[+] Processing $($targetSubscriptions.Count) subscription(s)..." -ForegroundColor Cyan
    
    $allResults = @{
        Source = "AzurePolicy"
        AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Subscriptions = @()
        Initiatives = @{}
        Policies = @()
        NonCompliantResources = @()
        RemediationTasks = @()
        Summary = @{
            TotalSubscriptions = $targetSubscriptions.Count
            TotalAssignments = 0
            TotalPolicies = 0
            CompliantPolicies = 0
            NonCompliantPolicies = 0
            TotalResources = 0
            NonCompliantResources = 0
        }
    }
    
    foreach ($subscription in $targetSubscriptions) {
        Write-Host "`n  [>] Subscription: $($subscription.Name)" -ForegroundColor White
        
        $subscriptionResult = @{
            SubscriptionId = $subscription.Id
            SubscriptionName = $subscription.Name
            Assignments = @()
            ComplianceSummary = $null
        }
        
        # Get policy assignments
        $assignments = Get-PolicyAssignments -SubscriptionId $subscription.Id
        
        if ($assignments) {
            $subscriptionResult.Assignments = $assignments
            $allResults.Summary.TotalAssignments += $assignments.Count
            
            # Identify initiatives
            $initiatives = $assignments | Where-Object { $_.IsInitiative }
            foreach ($init in $initiatives) {
                if (-not $allResults.Initiatives.ContainsKey($init.DisplayName)) {
                    $allResults.Initiatives[$init.DisplayName] = @{
                        DisplayName = $init.DisplayName
                        ShortName = $init.ShortName
                        Framework = $init.Framework
                        Type = $init.Type
                        Subscriptions = @()
                    }
                }
                $allResults.Initiatives[$init.DisplayName].Subscriptions += $subscription.Name
            }
            
            Write-Host "      Assignments: $($assignments.Count) (Initiatives: $($initiatives.Count))" -ForegroundColor Gray
        }
        
        # Get compliance summary
        $summary = Get-PolicyComplianceSummary -SubscriptionId $subscription.Id
        if ($summary) {
            $subscriptionResult.ComplianceSummary = $summary
            $allResults.Summary.NonCompliantPolicies += $summary.NonCompliantPolicies
            $allResults.Summary.NonCompliantResources += $summary.NonCompliantResources
            
            Write-Host "      Non-Compliant: $($summary.NonCompliantPolicies) policies, $($summary.NonCompliantResources) resources" -ForegroundColor $(
                if ($summary.NonCompliantResources -eq 0) { "Green" } 
                elseif ($summary.NonCompliantResources -lt 10) { "Yellow" } 
                else { "Red" }
            )
        }
        
        # Get detailed policy states
        $policyStates = Get-PolicyComplianceStates -SubscriptionId $subscription.Id -Top 500
        if ($policyStates) {
            # Group by policy definition for summary
            $policyGroups = $policyStates | Group-Object PolicyDefinitionName
            
            foreach ($group in $policyGroups) {
                $compliantCount = ($group.Group | Where-Object { $_.ComplianceState -eq "Passed" }).Count
                $nonCompliantCount = ($group.Group | Where-Object { $_.ComplianceState -eq "Failed" }).Count
                $totalCount = $group.Count
                
                $compliancePercent = if ($totalCount -gt 0) {
                    [math]::Round(($compliantCount / $totalCount) * 100, 1)
                } else { 0 }
                
                # Convert to standard format for Compliance module
                $policyResult = [PSCustomObject]@{
                    Source = "AzurePolicy"
                    Framework = "Azure Policy"
                    ControlId = ($group.Group[0].PolicyDefinitionId -split "/")[-1]
                    ControlTitle = $group.Name
                    Status = if ($nonCompliantCount -gt 0) { "Failed" } else { "Passed" }
                    Severity = if ($nonCompliantCount -gt 5) { "High" } elseif ($nonCompliantCount -gt 0) { "Medium" } else { "Info" }
                    PassedResources = $compliantCount
                    FailedResources = $nonCompliantCount
                    TotalResources = $totalCount
                    CompliancePercent = $compliancePercent
                    SubscriptionId = $subscription.Id
                    SubscriptionName = $subscription.Name
                    AssessmentDate = $allResults.AssessmentDate
                    Description = $group.Name
                    Remediation = "Review non-compliant resources in Azure Policy blade"
                }
                
                $allResults.Policies += $policyResult
            }
            
            $allResults.Summary.TotalPolicies += $policyGroups.Count
            $allResults.Summary.CompliantPolicies += ($policyGroups | Where-Object { 
                    ($_.Group | Where-Object { $_.ComplianceState -eq "Failed" }).Count -eq 0 
                }).Count
        }
        
        # Get non-compliant resources if requested
        if ($IncludeNonCompliantResources) {
            $ncResources = Get-NonCompliantResources -SubscriptionId $subscription.Id
            if ($ncResources) {
                foreach ($r in $ncResources) {
                    $r | Add-Member -NotePropertyName "SubscriptionName" -NotePropertyValue $subscription.Name
                }
                $allResults.NonCompliantResources += $ncResources
            }
        }
        
        # Get remediation tasks if requested
        if ($IncludeRemediationTasks) {
            $remTasks = Get-PolicyRemediationTasks -SubscriptionId $subscription.Id
            if ($remTasks) {
                foreach ($t in $remTasks) {
                    $t | Add-Member -NotePropertyName "SubscriptionName" -NotePropertyValue $subscription.Name
                }
                $allResults.RemediationTasks += $remTasks
            }
        }
        
        $allResults.Subscriptions += $subscriptionResult
    }
    
    # Calculate overall compliance
    $overallCompliance = if ($allResults.Summary.TotalPolicies -gt 0) {
        [math]::Round(($allResults.Summary.CompliantPolicies / $allResults.Summary.TotalPolicies) * 100, 1)
    } else { 0 }
    
    Write-Host "`n[+] Assessment Complete" -ForegroundColor Magenta
    Write-Host "    Subscriptions: $($allResults.Summary.TotalSubscriptions)" -ForegroundColor Cyan
    Write-Host "    Policy Assignments: $($allResults.Summary.TotalAssignments)" -ForegroundColor Cyan
    Write-Host "    Unique Policies: $($allResults.Summary.TotalPolicies)" -ForegroundColor Cyan
    Write-Host "    Non-Compliant Policies: $($allResults.Summary.NonCompliantPolicies)" -ForegroundColor Cyan
    Write-Host "    Non-Compliant Resources: $($allResults.Summary.NonCompliantResources)" -ForegroundColor Cyan
    Write-Host "    Overall Compliance: $overallCompliance%" -ForegroundColor $(
        if ($overallCompliance -ge 90) { "Green" } elseif ($overallCompliance -ge 70) { "Yellow" } else { "Red" }
    )
    
    # Store in script scope for Compliance module
    $script:AzurePolicyData = $allResults
    
    return $allResults
}

#endregion

#region ==================== REPORTING ====================

<#
.SYNOPSIS
    Exports Azure Policy compliance report.

.DESCRIPTION
    Generates HTML and CSV reports for Azure Policy compliance data.

.PARAMETER PolicyData
    Policy compliance data from Get-AzurePolicyComplianceAssessment.

.PARAMETER OutputDirectory
    Directory for output files.

.PARAMETER TenantName
    Name of the tenant/organization.
#>
function Export-AzurePolicyReport {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter()]
        $PolicyData,
        
        [Parameter(Mandatory)]
        [string]$OutputDirectory,
        
        [Parameter()]
        [string]$TenantName = "Unknown Tenant"
    )
    
    Write-Host "`n[+] Generating Azure Policy compliance report..." -ForegroundColor Cyan
    
    if (-not $PolicyData) {
        $PolicyData = $script:AzurePolicyData
    }
    
    if (-not $PolicyData) {
        Write-Host "    [!] No policy data available. Run Get-AzurePolicyComplianceAssessment first." -ForegroundColor Yellow
        return $null
    }
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $assessmentDate = Get-Date -Format "MMMM dd, yyyy HH:mm"
    
    # Calculate overall compliance
    $overallCompliance = if ($PolicyData.Summary.TotalPolicies -gt 0) {
        [math]::Round(($PolicyData.Summary.CompliantPolicies / $PolicyData.Summary.TotalPolicies) * 100, 1)
    } else { 0 }
    
    # Generate HTML Report
    $htmlPath = Join-Path $OutputDirectory "AzurePolicy-Report-$timestamp.html"
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Policy Compliance Report</title>
    <style>
        :root {
            --primary: #0078d4;
            --success: #107c10;
            --warning: #ff8c00;
            --danger: #d13438;
            --azure: #0089d6;
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
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        header {
            background: linear-gradient(135deg, #0078d4, #005a9e);
            color: white;
            padding: 40px;
            margin-bottom: 30px;
            border-radius: 8px;
        }
        
        header h1 { font-size: 2rem; margin-bottom: 10px; }
        
        .score-hero {
            display: flex;
            align-items: center;
            gap: 40px;
            margin-top: 30px;
        }
        
        .score-circle {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: rgba(255,255,255,0.2);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            border: 4px solid white;
        }
        
        .score-circle .value { font-size: 2.5rem; font-weight: 700; }
        .score-circle .label { font-size: 0.9rem; opacity: 0.9; }
        
        .score-details { flex: 1; }
        .score-details p { margin: 5px 0; opacity: 0.9; }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .stat-value { font-size: 2rem; font-weight: 700; }
        .stat-label { color: var(--gray-600); font-size: 0.85rem; }
        
        .stat-value.good { color: var(--success); }
        .stat-value.warn { color: var(--warning); }
        .stat-value.bad { color: var(--danger); }
        
        .section-title {
            font-size: 1.3rem;
            margin: 30px 0 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--azure);
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
        }
        
        .card-body { padding: 20px; }
        
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--gray-200); }
        th { background: var(--gray-100); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }
        tr:hover { background: var(--gray-100); }
        
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
        
        .initiative-card {
            border-left: 4px solid var(--azure);
            padding: 15px 20px;
            margin-bottom: 15px;
            background: white;
            border-radius: 0 8px 8px 0;
        }
        
        .initiative-title { font-weight: 600; font-size: 1.1rem; }
        .initiative-meta { font-size: 0.85rem; color: var(--gray-600); margin-top: 5px; }
        
        footer {
            text-align: center;
            padding: 30px;
            color: var(--gray-600);
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Azure Policy Compliance Report</h1>
            <p>Policy compliance assessment across Azure subscriptions</p>
            <div class="score-hero">
                <div class="score-circle">
                    <span class="value">$overallCompliance%</span>
                    <span class="label">Compliance</span>
                </div>
                <div class="score-details">
                    <p><strong>Tenant:</strong> $TenantName</p>
                    <p><strong>Subscriptions:</strong> $($PolicyData.Summary.TotalSubscriptions)</p>
                    <p><strong>Policy Assignments:</strong> $($PolicyData.Summary.TotalAssignments)</p>
                    <p><strong>Assessment Date:</strong> $assessmentDate</p>
                </div>
            </div>
        </header>

        <!-- Summary Stats -->
        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-value">$($PolicyData.Summary.TotalPolicies)</div>
                <div class="stat-label">Unique Policies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value good">$($PolicyData.Summary.CompliantPolicies)</div>
                <div class="stat-label">Compliant Policies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value $(if ($PolicyData.Summary.NonCompliantPolicies -eq 0) {'good'} elseif ($PolicyData.Summary.NonCompliantPolicies -lt 5) {'warn'} else {'bad'})">$($PolicyData.Summary.NonCompliantPolicies)</div>
                <div class="stat-label">Non-Compliant Policies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value $(if ($PolicyData.Summary.NonCompliantResources -eq 0) {'good'} elseif ($PolicyData.Summary.NonCompliantResources -lt 10) {'warn'} else {'bad'})">$($PolicyData.Summary.NonCompliantResources)</div>
                <div class="stat-label">Non-Compliant Resources</div>
            </div>
        </div>
"@

    # Initiatives section
    if ($PolicyData.Initiatives.Count -gt 0) {
        $html += @"
        
        <h2 class="section-title">Policy Initiatives Assigned</h2>
"@
        
        foreach ($initName in $PolicyData.Initiatives.Keys) {
            $init = $PolicyData.Initiatives[$initName]
            $frameworkBadge = switch ($init.Framework) {
                "CIS" { '<span class="badge badge-success">CIS</span>' }
                "NIST" { '<span class="badge badge-warning">NIST</span>' }
                "PCI" { '<span class="badge badge-danger">PCI</span>' }
                "Microsoft" { '<span class="badge" style="background:#e8f4fd;color:#0078d4;">Microsoft</span>' }
                default { '<span class="badge" style="background:#e1dfdd;">Custom</span>' }
            }
            
            $html += @"
        <div class="initiative-card">
            <div class="initiative-title">$($init.DisplayName) $frameworkBadge</div>
            <div class="initiative-meta">
                Type: $($init.Type) | Subscriptions: $($init.Subscriptions -join ", ")
            </div>
        </div>
"@
        }
    }

    # Non-compliant policies table
    $nonCompliantPolicies = $PolicyData.Policies | Where-Object { $_.Status -eq "Failed" } | Sort-Object FailedResources -Descending | Select-Object -First 20
    
    if ($nonCompliantPolicies.Count -gt 0) {
        $html += @"
        
        <h2 class="section-title">Non-Compliant Policies (Top 20)</h2>
        <div class="card">
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Policy</th>
                            <th>Subscription</th>
                            <th>Failed</th>
                            <th>Passed</th>
                            <th>Compliance</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($policy in $nonCompliantPolicies) {
            $compClass = if ($policy.CompliancePercent -ge 90) { "badge-success" } elseif ($policy.CompliancePercent -ge 70) { "badge-warning" } else { "badge-danger" }
            
            $html += @"
                        <tr>
                            <td><strong>$($policy.ControlTitle)</strong></td>
                            <td>$($policy.SubscriptionName)</td>
                            <td><span class="badge badge-danger">$($policy.FailedResources)</span></td>
                            <td><span class="badge badge-success">$($policy.PassedResources)</span></td>
                            <td><span class="badge $compClass">$($policy.CompliancePercent)%</span></td>
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

    # Non-compliant resources (if available)
    if ($PolicyData.NonCompliantResources.Count -gt 0) {
        $html += @"
        
        <h2 class="section-title">Non-Compliant Resources (Sample)</h2>
        <div class="card">
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Resource</th>
                            <th>Type</th>
                            <th>Policy</th>
                            <th>Subscription</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($resource in ($PolicyData.NonCompliantResources | Select-Object -First 15)) {
            $html += @"
                        <tr>
                            <td><strong>$($resource.ResourceName)</strong></td>
                            <td>$($resource.ResourceType)</td>
                            <td>$($resource.PolicyName)</td>
                            <td>$($resource.SubscriptionName)</td>
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
            <p>Generated by EntraChecks Azure Policy Module v$script:ModuleVersion</p>
            <p>Data sourced from Azure Policy service</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Host "    [OK] HTML report: $htmlPath" -ForegroundColor Green
    
    # Export CSV - Policies
    $csvPoliciesPath = Join-Path $OutputDirectory "AzurePolicy-Policies-$timestamp.csv"
    $PolicyData.Policies | Select-Object Framework, ControlId, ControlTitle, Status, Severity, PassedResources, FailedResources, CompliancePercent, SubscriptionName |
        Export-Csv -Path $csvPoliciesPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] Policies CSV: $csvPoliciesPath" -ForegroundColor Green
    
    # Export CSV - Summary
    $csvSummaryPath = Join-Path $OutputDirectory "AzurePolicy-Summary-$timestamp.csv"
    @([PSCustomObject]@{
            Tenant = $TenantName
            AssessmentDate = $PolicyData.AssessmentDate
            TotalSubscriptions = $PolicyData.Summary.TotalSubscriptions
            TotalAssignments = $PolicyData.Summary.TotalAssignments
            TotalPolicies = $PolicyData.Summary.TotalPolicies
            CompliantPolicies = $PolicyData.Summary.CompliantPolicies
            NonCompliantPolicies = $PolicyData.Summary.NonCompliantPolicies
            NonCompliantResources = $PolicyData.Summary.NonCompliantResources
            OverallCompliance = "$overallCompliance%"
        }) | Export-Csv -Path $csvSummaryPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] Summary CSV: $csvSummaryPath" -ForegroundColor Green
    
    # Export non-compliant resources if available
    if ($PolicyData.NonCompliantResources.Count -gt 0) {
        $csvResourcesPath = Join-Path $OutputDirectory "AzurePolicy-NonCompliantResources-$timestamp.csv"
        $PolicyData.NonCompliantResources | Export-Csv -Path $csvResourcesPath -NoTypeInformation -Encoding UTF8
        Write-Host "    [OK] Non-compliant resources CSV: $csvResourcesPath" -ForegroundColor Green
    }
    
    return @{
        HTMLReport = $htmlPath
        PoliciesCSV = $csvPoliciesPath
        SummaryCSV = $csvSummaryPath
        OutputDirectory = $OutputDirectory
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

# Export module members
Export-ModuleMember -Function @(
    'Initialize-AzurePolicyModule',
    'Get-PolicySubscriptions',
    'Get-PolicyAssignments',
    'Get-PolicyComplianceSummary',
    'Get-PolicyComplianceStates',
    'Get-NonCompliantResources',
    'Get-PolicyRemediationTasks',
    'Get-AzurePolicyComplianceAssessment',
    'Export-AzurePolicyReport'
)

# Export variables for integration
Export-ModuleMember -Variable @(
    'WellKnownInitiatives',
    'PolicyCategoryToFramework'
)

#endregion

# Auto-initialize when module is imported
$null = Initialize-AzurePolicyModule
