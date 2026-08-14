<#
.SYNOPSIS
    EntraChecks-PurviewCompliance.psm1
    Module for Microsoft Purview Compliance Manager integration

.DESCRIPTION
    This module retrieves compliance data from Microsoft Purview, including:

    - Compliance Manager assessment scores
    - Improvement actions and status
    - Data Loss Prevention (DLP) policies
    - Sensitivity labels and policies
    - Retention policies
    - Information protection status
    
    Note: Some Purview features have limited API availability. This module
    provides what's programmatically accessible and guidance for manual
    integration where needed.
    
.NOTES
    Version: 1.0.0
    Author: NamelessSaint
    Requires: Microsoft.Graph PowerShell SDK
    
    Required Graph Permissions:
    - ComplianceManager.Read.All (for Compliance Manager)
    - InformationProtectionPolicy.Read (for sensitivity labels)
    - Policy.Read.All (for DLP policies)
    
    Some features require:
    - Microsoft 365 E5 or E5 Compliance
    - Compliance Manager premium assessments
    
.LINK
    Main Script: Invoke-EntraChecks.ps1
    Purview Compliance: https://compliance.microsoft.com
#>

#Requires -Version 5.1

# Module version
$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-PurviewCompliance"

# Provenance: data source key for any findings this module emits via Add-Finding.
# Matches a key in EntraChecks-DataSources.psm1 :: $script:DataSourceCatalog.
$script:DataSourceKey = 'PurviewCompliance'

#region ==================== COMPLIANCE MANAGER MAPPINGS ====================

# Compliance Manager assessment templates and their frameworks
$script:ComplianceManagerTemplates = @{
    # Regulatory
    "GDPR" = @{ Framework = "GDPR"; Type = "Regulatory"; Region = "EU" }
    "CCPA" = @{ Framework = "CCPA"; Type = "Regulatory"; Region = "California" }
    "HIPAA" = @{ Framework = "HIPAA"; Type = "Regulatory"; Region = "US Healthcare" }
    "SOC 2" = @{ Framework = "SOC"; Type = "Regulatory"; Region = "Global" }
    "ISO 27001:2013" = @{ Framework = "ISO"; Type = "Regulatory"; Region = "Global" }
    "ISO 27701:2019" = @{ Framework = "ISO"; Type = "Regulatory"; Region = "Global" }
    "NIST 800-53" = @{ Framework = "NIST"; Type = "Regulatory"; Region = "US Federal" }
    "NIST 800-171" = @{ Framework = "NIST"; Type = "Regulatory"; Region = "US Federal" }
    "NIST CSF" = @{ Framework = "NIST"; Type = "Framework"; Region = "Global" }
    "PCI DSS" = @{ Framework = "PCI"; Type = "Regulatory"; Region = "Global" }
    "FedRAMP" = @{ Framework = "FedRAMP"; Type = "Regulatory"; Region = "US Federal" }
    
    # Microsoft Baselines
    "Microsoft 365 Data Protection Baseline" = @{ Framework = "Microsoft"; Type = "Baseline"; Region = "Global" }
    "Microsoft Cloud Security Benchmark" = @{ Framework = "Microsoft"; Type = "Baseline"; Region = "Global" }
}

# Improvement action categories
$script:ImprovementActionCategories = @{
    "Protect information" = "Data Protection"
    "Govern information" = "Information Governance"
    "Manage insider risk" = "Insider Risk"
    "Discover & respond" = "eDiscovery"
    "Manage compliance" = "Compliance Management"
    "Protect against threats" = "Threat Protection"
}

#endregion

#region ==================== MODULE INITIALIZATION ====================

<#
.SYNOPSIS
    Initializes the Purview Compliance Manager module and verifies Graph connection.
#>
function Initialize-PurviewComplianceModule {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Loading module: $script:ModuleName v$script:ModuleVersion" -ForegroundColor Magenta
    
    # Check Graph connection
    $context = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-Host "    [!] Not connected to Microsoft Graph. Connect first with required scopes." -ForegroundColor Yellow
    }
    else {
        Write-Host "    [i] Connected as: $($context.Account)" -ForegroundColor Gray
        
        # Check for compliance-related scopes
        $complianceScopes = @(
            "ComplianceManager.Read.All",
            "InformationProtectionPolicy.Read",
            "Policy.Read.All"
        )
        
        $missingScopes = $complianceScopes | Where-Object { $_ -notin $context.Scopes }
        if ($missingScopes.Count -gt 0) {
            Write-Host "    [!] Some compliance scopes may be missing: $($missingScopes -join ', ')" -ForegroundColor Yellow
        }
    }
    
    Write-Host "    [OK] Module loaded successfully" -ForegroundColor Green
    Write-Host "    [i] Note: Some Purview features require E5/E5 Compliance license" -ForegroundColor Gray
    
    return @{
        Name = $script:ModuleName
        Version = $script:ModuleVersion
        Type = "ExternalCompliance"
        RequiredAuth = "Graph"
        RequiredPermissions = @(
            "ComplianceManager.Read.All",
            "InformationProtectionPolicy.Read",
            "Policy.Read.All"
        )
        RequiredLicense = "Microsoft 365 E5 or E5 Compliance (for full features)"
    }
}

#endregion

#region ==================== HELPER FUNCTIONS ====================

function Invoke-PurviewGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        
        [string]$ApiVersion = "v1.0"
    )
    
    try {
        $fullUri = if ($Uri -match "^https://") { $Uri } else { "https://graph.microsoft.com/$ApiVersion/$Uri" }
        $response = Invoke-MgGraphRequest -Uri $fullUri -Method GET -ErrorAction Stop
        return $response
    }
    catch {
        Write-Verbose "Graph API Error: $($_.Exception.Message)"
        return $null
    }
}

function ConvertTo-ComplianceStatus {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [string]$Status
    )
    
    switch ($Status.ToLower()) {
        "passed" { return "Passed" }
        "completed" { return "Passed" }
        "implemented" { return "Passed" }
        "failed" { return "Failed" }
        "notimplemented" { return "Failed" }
        "inprogress" { return "InProgress" }
        "notstarted" { return "NotStarted" }
        "notapplicable" { return "NotApplicable" }
        "outofscope" { return "NotApplicable" }
        default { return "Unknown" }
    }
}

#endregion

#region ==================== COMPLIANCE MANAGER ====================

<#
.SYNOPSIS
    Gets Compliance Manager score and assessment overview.

.DESCRIPTION
    Retrieves the overall Compliance Manager score and assessment status.
    Note: Full Compliance Manager API access requires appropriate licensing.

.OUTPUTS
    Compliance Manager overview object.
#>
function Get-ComplianceManagerOverview {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Retrieving Compliance Manager overview..." -ForegroundColor Cyan
    
    try {
        # Try to get compliance score
        # Note: This endpoint may have limited availability
        $scoreUri = "https://graph.microsoft.com/beta/compliance/complianceScore"
        $scoreResponse = Invoke-PurviewGraphRequest -Uri $scoreUri -ApiVersion "beta"
        
        $overview = @{
            Available = $false
            Score = $null
            MaxScore = $null
            ScorePercent = $null
            Categories = @()
            LastUpdated = $null
        }
        
        if ($scoreResponse) {
            $overview.Available = $true
            $overview.Score = $scoreResponse.score
            $overview.MaxScore = $scoreResponse.maxScore
            $overview.ScorePercent = if ($scoreResponse.maxScore -gt 0) {
                [math]::Round(($scoreResponse.score / $scoreResponse.maxScore) * 100, 1)
            } else { 0 }
            $overview.LastUpdated = $scoreResponse.lastModifiedDateTime
            
            Write-Host "    [OK] Compliance Score: $($overview.Score)/$($overview.MaxScore) ($($overview.ScorePercent)%)" -ForegroundColor Green
        }
        else {
            Write-Host "    [!] Compliance Manager score not available via API" -ForegroundColor Yellow
            Write-Host "    [i] Access Compliance Manager at: https://compliance.microsoft.com/compliancemanager" -ForegroundColor Gray
        }
        
        return $overview
    }
    catch {
        Write-Host "    [!] Error accessing Compliance Manager: $($_.Exception.Message)" -ForegroundColor Yellow
        return @{ Available = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Gets Compliance Manager improvement actions.

.DESCRIPTION
    Retrieves improvement actions from Compliance Manager with their status.

.OUTPUTS
    Array of improvement action objects.
#>
function Get-ComplianceManagerActions {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Retrieving Compliance Manager improvement actions..." -ForegroundColor Cyan
    
    try {
        # Try beta endpoint for improvement actions
        $actionsUri = "https://graph.microsoft.com/beta/compliance/complianceManagement/improvementActions"
        $response = Invoke-PurviewGraphRequest -Uri $actionsUri -ApiVersion "beta"
        
        if (-not $response -or -not $response.value) {
            Write-Host "    [!] Improvement actions not available via API" -ForegroundColor Yellow
            return $null
        }
        
        $actions = @()
        foreach ($action in $response.value) {
            $actions += [PSCustomObject]@{
                Id = $action.id
                Title = $action.title
                Description = $action.description
                Category = $action.category
                Status = ConvertTo-ComplianceStatus -Status $action.implementationStatus
                Score = $action.score
                MaxScore = $action.maxScore
                Owner = $action.owner
                DueDate = $action.dueDate
                LastUpdated = $action.lastModifiedDateTime
                ControlFamily = $action.controlFamily
                TestStatus = $action.testStatus
            }
        }
        
        $completedCount = ($actions | Where-Object { $_.Status -eq "Passed" }).Count
        Write-Host "    [OK] Retrieved $($actions.Count) improvement actions ($completedCount completed)" -ForegroundColor Green
        
        return $actions
    }
    catch {
        Write-Host "    [!] Cannot retrieve improvement actions: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

<#
.SYNOPSIS
    Gets Compliance Manager assessments.

.DESCRIPTION
    Retrieves assessments configured in Compliance Manager.

.OUTPUTS
    Array of assessment objects.
#>
function Get-ComplianceManagerAssessments {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Retrieving Compliance Manager assessments..." -ForegroundColor Cyan
    
    try {
        $assessmentsUri = "https://graph.microsoft.com/beta/compliance/complianceManagement/assessments"
        $response = Invoke-PurviewGraphRequest -Uri $assessmentsUri -ApiVersion "beta"
        
        if (-not $response -or -not $response.value) {
            Write-Host "    [!] Assessments not available via API" -ForegroundColor Yellow
            return $null
        }
        
        $assessments = @()
        foreach ($assessment in $response.value) {
            $templateInfo = $script:ComplianceManagerTemplates[$assessment.templateDisplayName]
            
            $assessments += [PSCustomObject]@{
                Id = $assessment.id
                Name = $assessment.displayName
                Template = $assessment.templateDisplayName
                Framework = if ($templateInfo) { $templateInfo.Framework } else { "Custom" }
                Type = if ($templateInfo) { $templateInfo.Type } else { "Custom" }
                Status = $assessment.status
                Score = $assessment.complianceScore
                MaxScore = $assessment.maxComplianceScore
                ScorePercent = if ($assessment.maxComplianceScore -gt 0) {
                    [math]::Round(($assessment.complianceScore / $assessment.maxComplianceScore) * 100, 1)
                } else { 0 }
                CreatedDate = $assessment.createdDateTime
                LastUpdated = $assessment.lastModifiedDateTime
            }
        }
        
        Write-Host "    [OK] Retrieved $($assessments.Count) assessments" -ForegroundColor Green
        
        return $assessments
    }
    catch {
        Write-Host "    [!] Cannot retrieve assessments: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

#endregion

#region ==================== DATA PROTECTION ====================

<#
.SYNOPSIS
    Gets Data Loss Prevention (DLP) policies.

.DESCRIPTION
    Retrieves DLP policies configured in the tenant.

.OUTPUTS
    Array of DLP policy objects.
#>
function Get-DLPPolicies {
    [OutputType([object[]])]
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Retrieving Data Loss Prevention policies..." -ForegroundColor Cyan
    
    try {
        # DLP policies via Security & Compliance
        $dlpUri = "https://graph.microsoft.com/v1.0/informationProtection/policy/labels"
        $null = Invoke-PurviewGraphRequest -Uri $dlpUri

        # Also try the policies endpoint
        $policiesUri = "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels"
        $null = Invoke-PurviewGraphRequest -Uri $policiesUri -ApiVersion "beta"
        
        $policies = @()
        
        # Get DLP policy configurations if available
        $dlpConfigUri = "https://graph.microsoft.com/beta/informationProtection/dataLossPreventionPolicies"
        $dlpConfigResponse = Invoke-PurviewGraphRequest -Uri $dlpConfigUri -ApiVersion "beta"
        
        if ($dlpConfigResponse -and $dlpConfigResponse.value) {
            foreach ($policy in $dlpConfigResponse.value) {
                $policies += [PSCustomObject]@{
                    Id = $policy.id
                    Name = $policy.displayName
                    Description = $policy.description
                    Status = if ($policy.state -eq "enabled") { "Enabled" } else { "Disabled" }
                    Mode = $policy.mode
                    Priority = $policy.priority
                    Workloads = $policy.locations
                    CreatedDate = $policy.createdDateTime
                    LastUpdated = $policy.lastModifiedDateTime
                    Type = "DLP"
                }
            }
            
            $enabledCount = ($policies | Where-Object { $_.Status -eq "Enabled" }).Count
            Write-Host "    [OK] Retrieved $($policies.Count) DLP policies ($enabledCount enabled)" -ForegroundColor Green
        }
        else {
            Write-Host "    [!] DLP policies not available via Graph API" -ForegroundColor Yellow
            Write-Host "    [i] View DLP policies at: https://compliance.microsoft.com/datalossprevention" -ForegroundColor Gray
        }
        
        return $policies
    }
    catch {
        Write-Host "    [!] Cannot retrieve DLP policies: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

<#
.SYNOPSIS
    Gets sensitivity labels and policies.

.DESCRIPTION
    Retrieves sensitivity labels configured in the tenant.

.OUTPUTS
    Array of sensitivity label objects.
#>
function Get-SensitivityLabels {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Retrieving sensitivity labels..." -ForegroundColor Cyan
    
    try {
        $labelsUri = "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels"
        $response = Invoke-PurviewGraphRequest -Uri $labelsUri -ApiVersion "beta"
        
        if (-not $response -or -not $response.value) {
            # Try alternate endpoint
            $labelsUri = "https://graph.microsoft.com/v1.0/informationProtection/policy/labels"
            $response = Invoke-PurviewGraphRequest -Uri $labelsUri
        }
        
        if (-not $response -or -not $response.value) {
            Write-Host "    [!] Sensitivity labels not available via API" -ForegroundColor Yellow
            return $null
        }
        
        $labels = @()
        foreach ($label in $response.value) {
            $labels += [PSCustomObject]@{
                Id = $label.id
                Name = $label.name
                DisplayName = $label.displayName
                Description = $label.description
                Color = $label.color
                Priority = $label.priority
                IsActive = $label.isActive
                Parent = $label.parent
                Scope = $label.scope
                ContentFormats = $label.contentFormats
                HasProtection = $label.hasProtection
                EncryptionEnabled = if ($label.encryption) { $true } else { $false }
            }
        }
        
        $activeCount = ($labels | Where-Object { $_.IsActive }).Count
        Write-Host "    [OK] Retrieved $($labels.Count) sensitivity labels ($activeCount active)" -ForegroundColor Green
        
        return $labels
    }
    catch {
        Write-Host "    [!] Cannot retrieve sensitivity labels: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

<#
.SYNOPSIS
    Gets retention policies and labels.

.DESCRIPTION
    Retrieves retention policies configured in the tenant.

.OUTPUTS
    Array of retention policy objects.
#>
function Get-RetentionPolicies {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Retrieving retention policies..." -ForegroundColor Cyan
    
    try {
        $retentionUri = "https://graph.microsoft.com/beta/security/labels/retentionLabels"
        $response = Invoke-PurviewGraphRequest -Uri $retentionUri -ApiVersion "beta"
        
        if (-not $response -or -not $response.value) {
            Write-Host "    [!] Retention labels not available via API" -ForegroundColor Yellow
            Write-Host "    [i] View retention policies at: https://compliance.microsoft.com/informationgovernance" -ForegroundColor Gray
            return $null
        }
        
        $policies = @()
        foreach ($label in $response.value) {
            $policies += [PSCustomObject]@{
                Id = $label.id
                Name = $label.displayName
                Description = $label.descriptionForUsers
                IsInUse = $label.isInUse
                RetentionDuration = $label.retentionDuration
                RetentionAction = $label.retentionAction
                DefaultRecordBehavior = $label.defaultRecordBehavior
                CreatedDate = $label.createdDateTime
                LastUpdated = $label.lastModifiedDateTime
            }
        }
        
        Write-Host "    [OK] Retrieved $($policies.Count) retention labels" -ForegroundColor Green
        
        return $policies
    }
    catch {
        Write-Host "    [!] Cannot retrieve retention policies: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

#endregion

#region ==================== MAIN ASSESSMENT ====================

<#
.SYNOPSIS
    Gets comprehensive Purview compliance assessment.

.DESCRIPTION
    Main function for gathering Purview compliance data including:
    - Compliance Manager score and assessments
    - DLP policies
    - Sensitivity labels
    - Retention policies
    
    Produces standardized output for integration with the Compliance module.

.PARAMETER IncludeActions
    Include improvement actions from Compliance Manager.

.OUTPUTS
    Standardized compliance data object.
#>
function Get-PurviewComplianceAssessment {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [switch]$IncludeActions
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host " Purview Compliance Assessment" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Magenta
    
    # Verify Graph connection
    $context = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-Host "`n[!] Not connected to Microsoft Graph. Run Connect-MgGraph first." -ForegroundColor Red
        return $null
    }
    
    $allResults = @{
        Source = "PurviewCompliance"
        AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComplianceManager = @{
            Available = $false
            Overview = $null
            Assessments = @()
            Actions = @()
        }
        DataProtection = @{
            DLPPolicies = @()
            SensitivityLabels = @()
            RetentionPolicies = @()
        }
        Controls = @()
        Summary = @{
            ComplianceManagerAvailable = $false
            ComplianceScore = $null
            TotalAssessments = 0
            TotalActions = 0
            CompletedActions = 0
            DLPPoliciesCount = 0
            SensitivityLabelsCount = 0
            RetentionPoliciesCount = 0
        }
    }
    
    # Get Compliance Manager data
    $cmOverview = Get-ComplianceManagerOverview
    if ($cmOverview.Available) {
        $allResults.ComplianceManager.Available = $true
        $allResults.ComplianceManager.Overview = $cmOverview
        $allResults.Summary.ComplianceManagerAvailable = $true
        $allResults.Summary.ComplianceScore = $cmOverview.ScorePercent
    }
    
    # Get assessments
    $assessments = Get-ComplianceManagerAssessments
    if ($assessments) {
        $allResults.ComplianceManager.Assessments = $assessments
        $allResults.Summary.TotalAssessments = $assessments.Count
        
        # Convert assessments to standard control format
        foreach ($assessment in $assessments) {
            $allResults.Controls += [PSCustomObject]@{
                Source = "PurviewCompliance"
                Framework = $assessment.Framework
                ControlId = "CM-$($assessment.Id)"
                ControlTitle = $assessment.Name
                Status = if ($assessment.ScorePercent -ge 80) { "Passed" } 
                elseif ($assessment.ScorePercent -ge 50) { "Partial" } 
                else { "Failed" }
                Severity = if ($assessment.ScorePercent -lt 50) { "High" } 
                elseif ($assessment.ScorePercent -lt 80) { "Medium" } 
                else { "Info" }
                Score = $assessment.Score
                MaxScore = $assessment.MaxScore
                CompliancePercent = $assessment.ScorePercent
                AssessmentDate = $allResults.AssessmentDate
                Description = "Compliance Manager assessment: $($assessment.Template)"
                Remediation = "Review improvement actions in Compliance Manager"
            }
        }
    }
    
    # Get improvement actions if requested
    if ($IncludeActions) {
        $actions = Get-ComplianceManagerActions
        if ($actions) {
            $allResults.ComplianceManager.Actions = $actions
            $allResults.Summary.TotalActions = $actions.Count
            $allResults.Summary.CompletedActions = ($actions | Where-Object { $_.Status -eq "Passed" }).Count
        }
    }
    
    # Get DLP policies
    $dlpPolicies = Get-DLPPolicies
    if ($dlpPolicies) {
        $allResults.DataProtection.DLPPolicies = $dlpPolicies
        $allResults.Summary.DLPPoliciesCount = $dlpPolicies.Count
        
        # Add DLP as a control
        $enabledDLP = ($dlpPolicies | Where-Object { $_.Status -eq "Enabled" }).Count
        $allResults.Controls += [PSCustomObject]@{
            Source = "PurviewCompliance"
            Framework = "Data Protection"
            ControlId = "DLP-POLICIES"
            ControlTitle = "Data Loss Prevention Policies"
            Status = if ($enabledDLP -gt 0) { "Passed" } else { "Failed" }
            Severity = if ($enabledDLP -eq 0) { "High" } else { "Info" }
            Score = $enabledDLP
            MaxScore = $dlpPolicies.Count
            CompliancePercent = if ($dlpPolicies.Count -gt 0) { 
                [math]::Round(($enabledDLP / $dlpPolicies.Count) * 100, 1) 
            } else { 0 }
            AssessmentDate = $allResults.AssessmentDate
            Description = "$enabledDLP of $($dlpPolicies.Count) DLP policies enabled"
            Remediation = "Review and enable DLP policies for data protection"
        }
    }
    
    # Get sensitivity labels
    $labels = Get-SensitivityLabels
    if ($labels) {
        $allResults.DataProtection.SensitivityLabels = $labels
        $allResults.Summary.SensitivityLabelsCount = $labels.Count
        
        # Add as a control
        $activeLabels = ($labels | Where-Object { $_.IsActive }).Count
        $protectedLabels = ($labels | Where-Object { $_.HasProtection -or $_.EncryptionEnabled }).Count
        
        $allResults.Controls += [PSCustomObject]@{
            Source = "PurviewCompliance"
            Framework = "Information Protection"
            ControlId = "SENSITIVITY-LABELS"
            ControlTitle = "Sensitivity Labels Configuration"
            Status = if ($activeLabels -gt 0) { "Passed" } else { "Failed" }
            Severity = if ($activeLabels -eq 0) { "High" } elseif ($protectedLabels -eq 0) { "Medium" } else { "Info" }
            Score = $activeLabels
            MaxScore = $labels.Count
            CompliancePercent = if ($labels.Count -gt 0) { 
                [math]::Round(($activeLabels / $labels.Count) * 100, 1) 
            } else { 0 }
            AssessmentDate = $allResults.AssessmentDate
            Description = "$activeLabels active labels, $protectedLabels with protection"
            Remediation = "Configure sensitivity labels with appropriate protection settings"
        }
    }
    
    # Get retention policies
    $retention = Get-RetentionPolicies
    if ($retention) {
        $allResults.DataProtection.RetentionPolicies = $retention
        $allResults.Summary.RetentionPoliciesCount = $retention.Count
        
        $allResults.Controls += [PSCustomObject]@{
            Source = "PurviewCompliance"
            Framework = "Information Governance"
            ControlId = "RETENTION-LABELS"
            ControlTitle = "Retention Labels Configuration"
            Status = if ($retention.Count -gt 0) { "Passed" } else { "Failed" }
            Severity = if ($retention.Count -eq 0) { "Medium" } else { "Info" }
            Score = $retention.Count
            MaxScore = $retention.Count
            CompliancePercent = 100
            AssessmentDate = $allResults.AssessmentDate
            Description = "$($retention.Count) retention labels configured"
            Remediation = "Configure retention labels for information governance"
        }
    }
    
    # Summary
    Write-Host "`n[+] Assessment Complete" -ForegroundColor Magenta
    Write-Host "    Compliance Manager: $(if ($allResults.Summary.ComplianceManagerAvailable) { "Available - Score: $($allResults.Summary.ComplianceScore)%" } else { "Not available via API" })" -ForegroundColor Cyan
    Write-Host "    Assessments: $($allResults.Summary.TotalAssessments)" -ForegroundColor Cyan
    Write-Host "    DLP Policies: $($allResults.Summary.DLPPoliciesCount)" -ForegroundColor Cyan
    Write-Host "    Sensitivity Labels: $($allResults.Summary.SensitivityLabelsCount)" -ForegroundColor Cyan
    Write-Host "    Retention Labels: $($allResults.Summary.RetentionPoliciesCount)" -ForegroundColor Cyan
    
    # Store in script scope for Compliance module
    $script:PurviewComplianceData = $allResults
    
    return $allResults
}

#endregion

#region ==================== REPORTING ====================

<#
.SYNOPSIS
    Exports Purview compliance report.

.DESCRIPTION
    Generates HTML and CSV reports for Purview compliance data.

.PARAMETER PurviewData
    Purview compliance data from Get-PurviewComplianceAssessment.

.PARAMETER OutputDirectory
    Directory for output files.

.PARAMETER TenantName
    Name of the tenant/organization.
#>
function Export-PurviewComplianceReport {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter()]
        $PurviewData,
        
        [Parameter(Mandatory)]
        [string]$OutputDirectory,
        
        [Parameter()]
        [string]$TenantName = "Unknown Tenant"
    )
    
    Write-Host "`n[+] Generating Purview compliance report..." -ForegroundColor Cyan
    
    if (-not $PurviewData) {
        $PurviewData = $script:PurviewComplianceData
    }
    
    if (-not $PurviewData) {
        Write-Host "    [!] No Purview data available. Run Get-PurviewComplianceAssessment first." -ForegroundColor Yellow
        return $null
    }
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $assessmentDate = Get-Date -Format "MMMM dd, yyyy HH:mm"
    
    # Generate HTML Report
    $htmlPath = Join-Path $OutputDirectory "PurviewCompliance-Report-$timestamp.html"
    
    $complianceScore = if ($PurviewData.Summary.ComplianceScore) { 
        "$($PurviewData.Summary.ComplianceScore)%" 
    } else { 
        "N/A" 
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Purview Compliance Report</title>
    <style>
        :root {
            --primary: #742774;
            --success: #107c10;
            --warning: #ff8c00;
            --danger: #d13438;
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
            background: linear-gradient(135deg, #742774, #9b4f9b);
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
        
        .score-circle .value { font-size: 2rem; font-weight: 700; }
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
            border-bottom: 2px solid var(--primary);
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
        .badge-info { background: #e8f4fd; color: #0078d4; }
        
        .info-banner {
            background: #fff4ce;
            border-left: 4px solid var(--warning);
            padding: 15px 20px;
            margin-bottom: 20px;
            border-radius: 0 8px 8px 0;
        }
        
        .info-banner a { color: var(--primary); }
        
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
            <h1>Microsoft Purview Compliance Report</h1>
            <p>Compliance Manager, Data Protection, and Information Governance</p>
            <div class="score-hero">
                <div class="score-circle">
                    <span class="value">$complianceScore</span>
                    <span class="label">Compliance Score</span>
                </div>
                <div class="score-details">
                    <p><strong>Tenant:</strong> $TenantName</p>
                    <p><strong>Assessments:</strong> $($PurviewData.Summary.TotalAssessments)</p>
                    <p><strong>Assessment Date:</strong> $assessmentDate</p>
                </div>
            </div>
        </header>
"@

    # API availability notice
    if (-not $PurviewData.Summary.ComplianceManagerAvailable) {
        $html += @"
        
        <div class="info-banner">
            <strong>Note:</strong> Some Compliance Manager data is not available via API. 
            For complete compliance information, visit the 
            <a href="https://compliance.microsoft.com/compliancemanager" target="_blank">Compliance Manager portal</a>.
        </div>
"@
    }

    # Summary stats
    $html += @"
        
        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-value">$($PurviewData.Summary.TotalAssessments)</div>
                <div class="stat-label">Assessments</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$($PurviewData.Summary.DLPPoliciesCount)</div>
                <div class="stat-label">DLP Policies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$($PurviewData.Summary.SensitivityLabelsCount)</div>
                <div class="stat-label">Sensitivity Labels</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$($PurviewData.Summary.RetentionPoliciesCount)</div>
                <div class="stat-label">Retention Labels</div>
            </div>
        </div>
"@

    # Assessments table
    if ($PurviewData.ComplianceManager.Assessments.Count -gt 0) {
        $html += @"
        
        <h2 class="section-title">Compliance Manager Assessments</h2>
        <div class="card">
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Assessment</th>
                            <th>Framework</th>
                            <th>Type</th>
                            <th>Score</th>
                            <th>Compliance</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($assessment in $PurviewData.ComplianceManager.Assessments) {
            $scoreClass = if ($assessment.ScorePercent -ge 80) { "badge-success" } 
            elseif ($assessment.ScorePercent -ge 50) { "badge-warning" } 
            else { "badge-danger" }
            
            $html += @"
                        <tr>
                            <td><strong>$($assessment.Name)</strong></td>
                            <td>$($assessment.Framework)</td>
                            <td>$($assessment.Type)</td>
                            <td>$($assessment.Score)/$($assessment.MaxScore)</td>
                            <td><span class="badge $scoreClass">$($assessment.ScorePercent)%</span></td>
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

    # Sensitivity Labels
    if ($PurviewData.DataProtection.SensitivityLabels.Count -gt 0) {
        $html += @"
        
        <h2 class="section-title">Sensitivity Labels</h2>
        <div class="card">
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Label</th>
                            <th>Status</th>
                            <th>Protection</th>
                            <th>Encryption</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($label in $PurviewData.DataProtection.SensitivityLabels) {
            $statusBadge = if ($label.IsActive) { '<span class="badge badge-success">Active</span>' } else { '<span class="badge badge-warning">Inactive</span>' }
            $protectionBadge = if ($label.HasProtection) { '<span class="badge badge-info">Yes</span>' } else { '<span class="badge">No</span>' }
            $encryptionBadge = if ($label.EncryptionEnabled) { '<span class="badge badge-info">Yes</span>' } else { '<span class="badge">No</span>' }
            
            $html += @"
                        <tr>
                            <td><strong>$($label.DisplayName)</strong></td>
                            <td>$statusBadge</td>
                            <td>$protectionBadge</td>
                            <td>$encryptionBadge</td>
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
            <p>Generated by EntraChecks Purview Compliance Module v$script:ModuleVersion</p>
            <p>For complete compliance data, visit <a href="https://compliance.microsoft.com">Microsoft Purview</a></p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Host "    [OK] HTML report: $htmlPath" -ForegroundColor Green
    
    # Export CSV - Controls
    $csvControlsPath = Join-Path $OutputDirectory "PurviewCompliance-Controls-$timestamp.csv"
    $PurviewData.Controls | Select-Object Source, Framework, ControlId, ControlTitle, Status, Severity, Score, MaxScore, CompliancePercent, Description |
        Export-Csv -Path $csvControlsPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] Controls CSV: $csvControlsPath" -ForegroundColor Green
    
    # Export CSV - Summary
    $csvSummaryPath = Join-Path $OutputDirectory "PurviewCompliance-Summary-$timestamp.csv"
    @([PSCustomObject]@{
            Tenant = $TenantName
            AssessmentDate = $PurviewData.AssessmentDate
            ComplianceManagerAvailable = $PurviewData.Summary.ComplianceManagerAvailable
            ComplianceScore = $PurviewData.Summary.ComplianceScore
            TotalAssessments = $PurviewData.Summary.TotalAssessments
            DLPPolicies = $PurviewData.Summary.DLPPoliciesCount
            SensitivityLabels = $PurviewData.Summary.SensitivityLabelsCount
            RetentionLabels = $PurviewData.Summary.RetentionPoliciesCount
        }) | Export-Csv -Path $csvSummaryPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] Summary CSV: $csvSummaryPath" -ForegroundColor Green
    
    return @{
        HTMLReport = $htmlPath
        ControlsCSV = $csvControlsPath
        SummaryCSV = $csvSummaryPath
        OutputDirectory = $OutputDirectory
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

# Export module members
Export-ModuleMember -Function @(
    'Initialize-PurviewComplianceModule',
    'Get-ComplianceManagerOverview',
    'Get-ComplianceManagerActions',
    'Get-ComplianceManagerAssessments',
    'Get-DLPPolicies',
    'Get-SensitivityLabels',
    'Get-RetentionPolicies',
    'Get-PurviewComplianceAssessment',
    'Export-PurviewComplianceReport'
)

# Export variables for integration
Export-ModuleMember -Variable @(
    'ComplianceManagerTemplates',
    'ImprovementActionCategories'
)

#endregion

# Auto-initialize when module is imported
$null = Initialize-PurviewComplianceModule
