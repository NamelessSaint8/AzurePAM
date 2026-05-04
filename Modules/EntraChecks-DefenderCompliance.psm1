<#
.SYNOPSIS
    EntraChecks-DefenderCompliance.psm1
    Module for Microsoft Defender for Cloud regulatory compliance integration

.DESCRIPTION
    This module retrieves regulatory compliance assessments from Microsoft Defender
    for Cloud across Azure subscriptions. It provides:

    - Multi-subscription compliance assessment
    - Support for CIS, NIST, PCI-DSS, ISO 27001, and other standards
    - Control-level compliance status
    - Resource-level findings
    - Integration with EntraChecks compliance reporting
    
.NOTES
    Version: 1.0.0
    Author: David Stells
    Requires: Az.Security, Az.Accounts PowerShell modules
    
    Required Azure RBAC Role:
    - Security Reader (minimum)
    - Security Admin (for full details)
    
.LINK
    Main Script: Invoke-EntraChecks.ps1
    Defender for Cloud: https://learn.microsoft.com/en-us/azure/defender-for-cloud/
#>

#Requires -Version 5.1

# Module version
$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-DefenderCompliance"

# Provenance: data source key for any findings this module emits via Add-Finding.
# Matches a key in EntraChecks-DataSources.psm1 :: $script:DataSourceCatalog.
$script:DataSourceKey = 'DefenderCompliance'

# Supported regulatory standards in Defender for Cloud
$script:SupportedStandards = @{
    "Azure-CIS-1.4.0" = @{
        DisplayName = "CIS Microsoft Azure Foundations Benchmark v1.4.0"
        ShortName = "CIS Azure 1.4"
        Framework = "CIS"
    }
    "Azure-CIS-2.0.0" = @{
        DisplayName = "CIS Microsoft Azure Foundations Benchmark v2.0.0"
        ShortName = "CIS Azure 2.0"
        Framework = "CIS"
    }
    "NIST-SP-800-53-R5" = @{
        DisplayName = "NIST SP 800-53 Rev. 5"
        ShortName = "NIST 800-53 R5"
        Framework = "NIST"
    }
    "NIST-SP-800-53-R4" = @{
        DisplayName = "NIST SP 800-53 Rev. 4"
        ShortName = "NIST 800-53 R4"
        Framework = "NIST"
    }
    "PCI-DSS-4.0" = @{
        DisplayName = "PCI DSS v4.0"
        ShortName = "PCI-DSS 4.0"
        Framework = "PCI"
    }
    "PCI-DSS-3.2.1" = @{
        DisplayName = "PCI DSS v3.2.1"
        ShortName = "PCI-DSS 3.2.1"
        Framework = "PCI"
    }
    "ISO-27001-2013" = @{
        DisplayName = "ISO 27001:2013"
        ShortName = "ISO 27001"
        Framework = "ISO"
    }
    "SOC-2-Type-2" = @{
        DisplayName = "SOC 2 Type 2"
        ShortName = "SOC 2"
        Framework = "SOC"
    }
    "Azure-Security-Benchmark" = @{
        DisplayName = "Microsoft Cloud Security Benchmark"
        ShortName = "MCSB"
        Framework = "Microsoft"
    }
    "Azure-CIS-1.3.0" = @{
        DisplayName = "CIS Microsoft Azure Foundations Benchmark v1.3.0"
        ShortName = "CIS Azure 1.3"
        Framework = "CIS"
    }
    "NIST-SP-800-171-R2" = @{
        DisplayName = "NIST SP 800-171 Rev. 2"
        ShortName = "NIST 800-171 R2"
        Framework = "NIST"
    }
    "CMMC-Level-3" = @{
        DisplayName = "CMMC Level 3"
        ShortName = "CMMC L3"
        Framework = "CMMC"
    }
    "FedRAMP-H" = @{
        DisplayName = "FedRAMP High"
        ShortName = "FedRAMP High"
        Framework = "FedRAMP"
    }
    "FedRAMP-M" = @{
        DisplayName = "FedRAMP Moderate"
        ShortName = "FedRAMP Mod"
        Framework = "FedRAMP"
    }
    "HIPAA-HITRUST" = @{
        DisplayName = "HIPAA HITRUST"
        ShortName = "HIPAA HITRUST"
        Framework = "HIPAA"
    }
    "Canada-Federal-PBMM" = @{
        DisplayName = "Canada Federal PBMM"
        ShortName = "Canada PBMM"
        Framework = "Canada"
    }
    "Azure-CSPM" = @{
        DisplayName = "Azure Cloud Security Posture Management"
        ShortName = "Azure CSPM"
        Framework = "Microsoft"
    }
}

#region ==================== MODULE INITIALIZATION ====================

<#
.SYNOPSIS
    Initializes the Defender for Cloud compliance module and verifies required Az modules.
#>
function Initialize-DefenderComplianceModule {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Loading module: $script:ModuleName v$script:ModuleVersion" -ForegroundColor Magenta
    
    # Check for Az modules
    $azAccountsModule = Get-Module -Name Az.Accounts -ListAvailable
    $azSecurityModule = Get-Module -Name Az.Security -ListAvailable
    
    if (-not $azAccountsModule) {
        Write-Host "    [!] Az.Accounts module not found. Install with: Install-Module Az.Accounts" -ForegroundColor Yellow
    }
    
    if (-not $azSecurityModule) {
        Write-Host "    [!] Az.Security module not found. Install with: Install-Module Az.Security" -ForegroundColor Yellow
    }
    
    # Check Azure connection
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azContext) {
        Write-Host "    [!] Not connected to Azure. Connect with: Connect-AzAccount" -ForegroundColor Yellow
    }
    else {
        Write-Host "    [i] Connected to Azure as: $($azContext.Account.Id)" -ForegroundColor Gray
        Write-Host "    [i] Current subscription: $($azContext.Subscription.Name)" -ForegroundColor Gray
    }
    
    Write-Host "    [OK] Module loaded successfully" -ForegroundColor Green
    Write-Host "    [i] Supported standards: $($script:SupportedStandards.Count)" -ForegroundColor Gray
    
    return @{
        Name = $script:ModuleName
        Version = $script:ModuleVersion
        Type = "ExternalCompliance"
        RequiredAuth = "AzureRM"
        RequiredModules = @("Az.Accounts", "Az.Security")
        RequiredRole = "Security Reader"
        SupportedStandards = $script:SupportedStandards.Keys
    }
}

#endregion

#region ==================== HELPER FUNCTIONS ====================

<#
.SYNOPSIS
    Gets available Azure subscriptions.
#>
function Get-AvailableSubscriptions {
    [CmdletBinding()]
    param(
        [string[]]$SubscriptionFilter,
        [string[]]$ExcludeSubscriptions
    )
    
    try {
        $subscriptions = Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq "Enabled" }
        
        # Apply filters if specified
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
    Invokes Azure REST API request.
#>
function Invoke-AzureRestRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        
        [string]$ApiVersion = "2022-01-01"
    )
    
    try {
        # Ensure URI has API version
        if ($Uri -notmatch "api-version=") {
            $separator = if ($Uri -match "\?") { "&" } else { "?" }
            $Uri = "$Uri${separator}api-version=$ApiVersion"
        }
        
        $response = Invoke-AzRestMethod -Uri $Uri -Method GET
        
        if ($response.StatusCode -eq 200) {
            return $response.Content | ConvertFrom-Json
        }
        else {
            Write-Host "    [!] API returned HTTP $($response.StatusCode) for: $Uri" -ForegroundColor Yellow
            if ($response.StatusCode -eq 403) {
                Write-Host "    [i] Insufficient permissions - Security Reader role required" -ForegroundColor Gray
            }
            elseif ($response.StatusCode -eq 404) {
                Write-Host "    [i] Resource not found - Defender for Cloud may not be enabled" -ForegroundColor Gray
            }
            return $null
        }
    }
    catch {
        Write-Host "    [!] REST API error: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

<#
.SYNOPSIS
    Converts Defender compliance state to standard status.
#>
function ConvertTo-StandardStatus {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [string]$State
    )
    
    switch ($State.ToLower()) {
        "passed" { return "Passed" }
        "healthy" { return "Passed" }
        "compliant" { return "Passed" }
        "failed" { return "Failed" }
        "unhealthy" { return "Failed" }
        "noncompliant" { return "Failed" }
        "skipped" { return "NotApplicable" }
        "exempt" { return "Exempt" }
        "notapplicable" { return "NotApplicable" }
        "unsupported" { return "NotApplicable" }
        default { return "Unknown" }
    }
}

#endregion

#region ==================== COMPLIANCE RETRIEVAL ====================

<#
.SYNOPSIS
    Gets regulatory compliance standards available in a subscription.

.DESCRIPTION
    Retrieves the list of regulatory compliance standards that are enabled
    in Defender for Cloud for a specific subscription.

.PARAMETER SubscriptionId
    Azure subscription ID to query.

.OUTPUTS
    Array of available compliance standards.
#>
function Get-DefenderComplianceStandards {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SubscriptionId
    )
    
    if (-not $SubscriptionId) {
        $context = Get-AzContext
        $SubscriptionId = $context.Subscription.Id
    }
    
    Write-Host "`n[+] Getting compliance standards for subscription..." -ForegroundColor Cyan
    
    try {
        # Check if Microsoft.Security resource provider is registered
        $secProvider = Get-AzResourceProvider -ProviderNamespace "Microsoft.Security" -ErrorAction SilentlyContinue
        if (-not $secProvider -or ($secProvider | Where-Object { $_.RegistrationState -eq "Registered" }).Count -eq 0) {
            Write-Host "    [!] Microsoft.Security resource provider is not registered" -ForegroundColor Yellow
            Write-Host "    [i] Register with: Register-AzResourceProvider -ProviderNamespace 'Microsoft.Security'" -ForegroundColor Gray
            Write-Host "    [i] Registration may take a few minutes to complete" -ForegroundColor Gray
            return $null
        }

        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/regulatoryComplianceStandards"
        $response = Invoke-AzureRestRequest -Uri $uri -ApiVersion "2019-01-01-preview"

        if (-not $response -or -not $response.value) {
            Write-Host "    [!] No compliance standards found" -ForegroundColor Yellow
            Write-Host "    [i] Possible causes:" -ForegroundColor Gray
            Write-Host "        - Defender for Cloud free tier does not include regulatory compliance" -ForegroundColor Gray
            Write-Host "        - No compliance standards have been enabled for this subscription" -ForegroundColor Gray
            Write-Host "    [i] To enable: Azure Portal > Defender for Cloud > Regulatory Compliance > Manage compliance policies" -ForegroundColor Gray
            return $null
        }
        
        $standards = @()
        foreach ($standard in $response.value) {
            $standardId = $standard.name
            $knownStandard = $script:SupportedStandards[$standardId]
            
            $standards += [PSCustomObject]@{
                Id = $standardId
                Name = $standard.properties.displayName
                ShortName = if ($knownStandard) { $knownStandard.ShortName } else { $standardId }
                Framework = if ($knownStandard) { $knownStandard.Framework } else { "Other" }
                State = $standard.properties.state
                PassedControls = $standard.properties.passedControls
                FailedControls = $standard.properties.failedControls
                SkippedControls = $standard.properties.skippedControls
                UnsupportedControls = $standard.properties.unsupportedControls
            }
        }
        
        $activeCount = ($standards | Where-Object { $_.State -ne "Unsupported" }).Count
        Write-Host "    [OK] Found $($standards.Count) standards ($activeCount active)" -ForegroundColor Green
        
        return $standards
    }
    catch {
        Write-Host "    [!] Error getting standards: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

<#
.SYNOPSIS
    Gets compliance controls for a specific standard.

.DESCRIPTION
    Retrieves all controls within a regulatory compliance standard,
    including their compliance status.

.PARAMETER SubscriptionId
    Azure subscription ID.

.PARAMETER StandardId
    Regulatory compliance standard identifier.

.OUTPUTS
    Array of compliance controls with status.
#>
function Get-DefenderComplianceControls {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory)]
        [string]$StandardId
    )
    
    Write-Verbose "Getting controls for standard: $StandardId"
    
    try {
        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/regulatoryComplianceStandards/$StandardId/regulatoryComplianceControls"
        $response = Invoke-AzureRestRequest -Uri $uri -ApiVersion "2019-01-01-preview"
        
        if (-not $response -or -not $response.value) {
            return $null
        }
        
        $controls = @()
        foreach ($control in $response.value) {
            $controls += [PSCustomObject]@{
                ControlId = $control.name
                StandardId = $StandardId
                Description = $control.properties.description
                State = ConvertTo-StandardStatus -State $control.properties.state
                PassedAssessments = $control.properties.passedAssessments
                FailedAssessments = $control.properties.failedAssessments
                SkippedAssessments = $control.properties.skippedAssessments
            }
        }
        
        return $controls
    }
    catch {
        Write-Verbose "Error getting controls: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Gets detailed assessments for a specific control.

.DESCRIPTION
    Retrieves resource-level assessment results for a compliance control.

.PARAMETER SubscriptionId
    Azure subscription ID.

.PARAMETER StandardId
    Regulatory compliance standard identifier.

.PARAMETER ControlId
    Control identifier within the standard.

.OUTPUTS
    Array of assessment results.
#>
function Get-DefenderComplianceAssessments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory)]
        [string]$StandardId,
        
        [Parameter(Mandatory)]
        [string]$ControlId
    )
    
    try {
        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/regulatoryComplianceStandards/$StandardId/regulatoryComplianceControls/$ControlId/regulatoryComplianceAssessments"
        $response = Invoke-AzureRestRequest -Uri $uri -ApiVersion "2019-01-01-preview"
        
        if (-not $response -or -not $response.value) {
            return $null
        }
        
        $assessments = @()
        foreach ($assessment in $response.value) {
            $assessments += [PSCustomObject]@{
                AssessmentId = $assessment.name
                ControlId = $ControlId
                StandardId = $StandardId
                Description = $assessment.properties.description
                State = ConvertTo-StandardStatus -State $assessment.properties.state
                PassedResources = $assessment.properties.passedResources
                FailedResources = $assessment.properties.failedResources
                SkippedResources = $assessment.properties.skippedResources
                UnsupportedResources = $assessment.properties.unsupportedResources
            }
        }
        
        return $assessments
    }
    catch {
        Write-Verbose "Error getting assessments: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Gets comprehensive compliance assessment across subscriptions.

.DESCRIPTION
    Retrieves regulatory compliance data from Defender for Cloud across
    one or more Azure subscriptions. This is the main function for
    gathering compliance data.

.PARAMETER Subscriptions
    Array of subscription IDs or names. If not specified, uses all available.

.PARAMETER Standards
    Array of standard IDs to retrieve. If not specified, gets all enabled standards.

.PARAMETER IncludeAssessments
    Include resource-level assessment details (slower but more detailed).

.OUTPUTS
    Standardized compliance data object for integration with Compliance module.
#>
function Get-DefenderComplianceAssessment {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$Subscriptions,
        
        [Parameter()]
        [string[]]$Standards,
        
        [switch]$IncludeAssessments
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host " Defender for Cloud Compliance Assessment" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Magenta
    
    # Verify Azure connection
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-Host "`n[!] Not connected to Azure. Run Connect-AzAccount first." -ForegroundColor Red
        return $null
    }
    
    # Get subscriptions
    $targetSubscriptions = if ($Subscriptions) {
        Get-AvailableSubscriptions -SubscriptionFilter $Subscriptions
    }
    else {
        Get-AvailableSubscriptions
    }
    
    if (-not $targetSubscriptions -or $targetSubscriptions.Count -eq 0) {
        Write-Host "[!] No accessible subscriptions found" -ForegroundColor Red
        return $null
    }
    
    Write-Host "`n[+] Processing $($targetSubscriptions.Count) subscription(s)..." -ForegroundColor Cyan
    
    $allResults = @{
        Source = "DefenderForCloud"
        AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Subscriptions = @()
        Standards = @{}
        Controls = @()
        Summary = @{
            TotalSubscriptions = $targetSubscriptions.Count
            TotalStandards = 0
            TotalControls = 0
            PassedControls = 0
            FailedControls = 0
        }
    }
    
    foreach ($subscription in $targetSubscriptions) {
        Write-Host "`n  [>] Subscription: $($subscription.Name)" -ForegroundColor White
        
        # Set subscription context
        $null = Set-AzContext -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue
        
        $subscriptionResult = @{
            SubscriptionId = $subscription.Id
            SubscriptionName = $subscription.Name
            Standards = @()
        }
        
        # Get standards for this subscription
        $subStandards = Get-DefenderComplianceStandards -SubscriptionId $subscription.Id
        
        if (-not $subStandards) {
            Write-Host "      [!] No compliance data available" -ForegroundColor Yellow
            $allResults.Subscriptions += $subscriptionResult
            continue
        }
        
        # Include all standards except Unsupported (API returns state as Passed/Failed/Skipped, not Enabled/Disabled)
        $enabledStandards = $subStandards | Where-Object { $_.State -ne "Unsupported" }

        if (-not $enabledStandards -or @($enabledStandards).Count -eq 0) {
            Write-Host "      [!] No active compliance standards found" -ForegroundColor Yellow
            Write-Host "      [i] Found $(@($subStandards).Count) standard(s), but all are unsupported" -ForegroundColor Gray
            Write-Host "      [i] Manage standards: Azure Portal > Defender for Cloud > Regulatory Compliance" -ForegroundColor Gray
            $allResults.Subscriptions += $subscriptionResult
            continue
        }

        if ($Standards -and $Standards.Count -gt 0) {
            $enabledStandards = $enabledStandards | Where-Object { $_.Id -in $Standards }
        }

        foreach ($standard in $enabledStandards) {
            Write-Host "      [>] Standard: $($standard.ShortName)" -ForegroundColor Gray
            
            $standardResult = @{
                StandardId = $standard.Id
                StandardName = $standard.Name
                ShortName = $standard.ShortName
                Framework = $standard.Framework
                PassedControls = $standard.PassedControls
                FailedControls = $standard.FailedControls
                SkippedControls = $standard.SkippedControls
            }
            
            # Calculate compliance percentage
            $totalAssessed = $standard.PassedControls + $standard.FailedControls
            $standardResult.CompliancePercent = if ($totalAssessed -gt 0) {
                [math]::Round(($standard.PassedControls / $totalAssessed) * 100, 1)
            } else { 0 }
            
            $subscriptionResult.Standards += $standardResult
            
            # Get control-level details
            $controls = Get-DefenderComplianceControls -SubscriptionId $subscription.Id -StandardId $standard.Id
            
            if ($controls) {
                foreach ($control in $controls) {
                    # Convert to standard format for Compliance module
                    $controlResult = [PSCustomObject]@{
                        Source = "DefenderForCloud"
                        Framework = $standard.ShortName
                        ControlId = $control.ControlId
                        ControlTitle = $control.Description
                        Status = $control.State
                        Severity = switch ($control.State) {
                            "Failed" { "High" }
                            "Passed" { "Info" }
                            default { "Medium" }
                        }
                        PassedResources = $control.PassedAssessments
                        FailedResources = $control.FailedAssessments
                        SubscriptionId = $subscription.Id
                        SubscriptionName = $subscription.Name
                        AssessmentDate = $allResults.AssessmentDate
                        Description = $control.Description
                        Remediation = "Review in Defender for Cloud: https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/RegulatoryCompliance"
                    }
                    
                    $allResults.Controls += $controlResult
                    
                    # Get resource-level assessments if requested
                    if ($IncludeAssessments -and $control.State -eq "Failed") {
                        $assessments = Get-DefenderComplianceAssessments -SubscriptionId $subscription.Id -StandardId $standard.Id -ControlId $control.ControlId
                        if ($assessments) {
                            $controlResult | Add-Member -NotePropertyName "Assessments" -NotePropertyValue $assessments
                        }
                    }
                }
            }
            
            # Track in standards dictionary
            if (-not $allResults.Standards.ContainsKey($standard.Id)) {
                $allResults.Standards[$standard.Id] = @{
                    Name = $standard.Name
                    ShortName = $standard.ShortName
                    Framework = $standard.Framework
                    Subscriptions = @()
                }
            }
            $allResults.Standards[$standard.Id].Subscriptions += [PSCustomObject]@{
                SubscriptionId = $subscription.Id
                SubscriptionName = $subscription.Name
                CompliancePercent = $standardResult.CompliancePercent
                Passed = $standard.PassedControls
                Failed = $standard.FailedControls
            }
            
            Write-Host "          Compliance: $($standardResult.CompliancePercent)% (P:$($standard.PassedControls) F:$($standard.FailedControls))" -ForegroundColor $(
                if ($standardResult.CompliancePercent -ge 80) { "Green" } 
                elseif ($standardResult.CompliancePercent -ge 60) { "Yellow" } 
                else { "Red" }
            )
        }
        
        $allResults.Subscriptions += $subscriptionResult
    }
    
    # Update summary
    $allResults.Summary.TotalStandards = $allResults.Standards.Count
    $allResults.Summary.TotalControls = $allResults.Controls.Count
    $allResults.Summary.PassedControls = ($allResults.Controls | Where-Object { $_.Status -eq "Passed" }).Count
    $allResults.Summary.FailedControls = ($allResults.Controls | Where-Object { $_.Status -eq "Failed" }).Count
    
    $overallPercent = if ($allResults.Summary.TotalControls -gt 0) {
        [math]::Round(($allResults.Summary.PassedControls / $allResults.Summary.TotalControls) * 100, 1)
    } else { 0 }
    
    Write-Host "`n[+] Assessment Complete" -ForegroundColor Magenta
    Write-Host "    Subscriptions: $($allResults.Summary.TotalSubscriptions)" -ForegroundColor Cyan
    Write-Host "    Standards: $($allResults.Summary.TotalStandards)" -ForegroundColor Cyan
    Write-Host "    Controls: $($allResults.Summary.TotalControls) (P:$($allResults.Summary.PassedControls) F:$($allResults.Summary.FailedControls))" -ForegroundColor Cyan
    Write-Host "    Overall Compliance: $overallPercent%" -ForegroundColor $(
        if ($overallPercent -ge 80) { "Green" } elseif ($overallPercent -ge 60) { "Yellow" } else { "Red" }
    )
    
    # Store in script scope for Compliance module
    $script:DefenderComplianceData = $allResults
    
    return $allResults
}

#endregion

#region ==================== REPORTING ====================

<#
.SYNOPSIS
    Exports Defender for Cloud compliance report.

.DESCRIPTION
    Generates HTML and CSV reports for Defender for Cloud compliance data.

.PARAMETER ComplianceData
    Compliance data from Get-DefenderComplianceAssessment.

.PARAMETER OutputDirectory
    Directory for output files.

.PARAMETER TenantName
    Name of the tenant/organization.
#>
function Export-DefenderComplianceReport {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter()]
        $ComplianceData,
        
        [Parameter(Mandatory)]
        [string]$OutputDirectory,
        
        [Parameter()]
        [string]$TenantName = "Unknown Tenant"
    )
    
    Write-Host "`n[+] Generating Defender for Cloud compliance report..." -ForegroundColor Cyan
    
    if (-not $ComplianceData) {
        $ComplianceData = $script:DefenderComplianceData
    }
    
    if (-not $ComplianceData) {
        Write-Host "    [!] No compliance data available. Run Get-DefenderComplianceAssessment first." -ForegroundColor Yellow
        return $null
    }
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $assessmentDate = Get-Date -Format "MMMM dd, yyyy HH:mm"
    
    # Calculate overall compliance
    $overallPercent = if ($ComplianceData.Summary.TotalControls -gt 0) {
        [math]::Round(($ComplianceData.Summary.PassedControls / $ComplianceData.Summary.TotalControls) * 100, 1)
    } else { 0 }
    
    # Generate HTML Report
    $htmlPath = Join-Path $OutputDirectory "DefenderCompliance-Report-$timestamp.html"
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Defender for Cloud Compliance Report</title>
    <style>
        :root {
            --primary: #0078d4;
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
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--gray-800);
            background: var(--gray-100);
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        header {
            background: linear-gradient(135deg, #5c2d91, #8661c5);
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
        
        .section-title {
            font-size: 1.3rem;
            margin: 30px 0 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #5c2d91;
        }
        
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--gray-200); }
        th { background: var(--gray-100); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
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
        .badge-info { background: #e8f4fd; color: var(--primary); }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
        
        .stat-value { font-size: 2.5rem; font-weight: 700; }
        .stat-label { color: var(--gray-600); }
        
        .stat-value.good { color: var(--success); }
        .stat-value.warn { color: var(--warning); }
        .stat-value.bad { color: var(--danger); }
        
        .standard-card {
            border-left: 4px solid #5c2d91;
            padding: 15px 20px;
            margin-bottom: 15px;
            background: white;
            border-radius: 0 8px 8px 0;
        }
        
        .standard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .standard-title { font-weight: 600; font-size: 1.1rem; }
        
        .progress-bar {
            height: 8px;
            background: var(--gray-200);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 4px;
        }
        
        .progress-fill.good { background: var(--success); }
        .progress-fill.warn { background: var(--warning); }
        .progress-fill.bad { background: var(--danger); }
        
        footer {
            text-align: center;
            padding: 20px;
            color: var(--gray-600);
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Defender for Cloud Compliance Report</h1>
            <p>Regulatory compliance assessment across Azure subscriptions</p>
            <div class="score-hero">
                <div class="score-circle">
                    <span class="value">$overallPercent%</span>
                    <span class="label">Compliance</span>
                </div>
                <div class="score-details">
                    <p><strong>Tenant:</strong> $TenantName</p>
                    <p><strong>Subscriptions:</strong> $($ComplianceData.Summary.TotalSubscriptions)</p>
                    <p><strong>Standards Assessed:</strong> $($ComplianceData.Summary.TotalStandards)</p>
                    <p><strong>Assessment Date:</strong> $assessmentDate</p>
                </div>
            </div>
        </header>

        <!-- Summary Stats -->
        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-value">$($ComplianceData.Summary.TotalControls)</div>
                <div class="stat-label">Total Controls</div>
            </div>
            <div class="stat-card">
                <div class="stat-value good">$($ComplianceData.Summary.PassedControls)</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value bad">$($ComplianceData.Summary.FailedControls)</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value $(if ($overallPercent -ge 80) {'good'} elseif ($overallPercent -ge 60) {'warn'} else {'bad'})">$overallPercent%</div>
                <div class="stat-label">Overall Compliance</div>
            </div>
        </div>

        <!-- Standards Overview -->
        <h2 class="section-title">Compliance Standards</h2>
"@

    foreach ($standardId in $ComplianceData.Standards.Keys) {
        $standard = $ComplianceData.Standards[$standardId]
        
        # Calculate average compliance across subscriptions
        $avgCompliance = if ($standard.Subscriptions.Count -gt 0) {
            [math]::Round(($standard.Subscriptions | Measure-Object -Property CompliancePercent -Average).Average, 1)
        } else { 0 }
        
        $totalPassed = ($standard.Subscriptions | Measure-Object -Property Passed -Sum).Sum
        $totalFailed = ($standard.Subscriptions | Measure-Object -Property Failed -Sum).Sum
        
        $progressClass = if ($avgCompliance -ge 80) { "good" } elseif ($avgCompliance -ge 60) { "warn" } else { "bad" }
        
        $html += @"
        <div class="standard-card">
            <div class="standard-header">
                <div>
                    <div class="standard-title">$($standard.Name)</div>
                    <small>Framework: $($standard.Framework) | Subscriptions: $($standard.Subscriptions.Count)</small>
                </div>
                <span class="stat-value $(if ($avgCompliance -ge 80) {'good'} elseif ($avgCompliance -ge 60) {'warn'} else {'bad'})" style="font-size: 1.5rem;">$avgCompliance%</span>
            </div>
            <div>Passed: $totalPassed | Failed: $totalFailed</div>
            <div class="progress-bar">
                <div class="progress-fill $progressClass" style="width: $avgCompliance%"></div>
            </div>
        </div>
"@
    }

    # Failed Controls Detail
    $failedControls = $ComplianceData.Controls | Where-Object { $_.Status -eq "Failed" } | Select-Object -First 20
    
    if ($failedControls.Count -gt 0) {
        $html += @"
        
        <h2 class="section-title">Failed Controls (Top 20)</h2>
        <div class="card">
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Control ID</th>
                            <th>Framework</th>
                            <th>Description</th>
                            <th>Subscription</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($control in $failedControls) {
            $html += @"
                        <tr>
                            <td><strong>$($control.ControlId)</strong></td>
                            <td>$($control.Framework)</td>
                            <td>$($control.ControlTitle)</td>
                            <td>$($control.SubscriptionName)</td>
                            <td><span class="badge badge-danger">Failed</span></td>
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
            <p>Generated by EntraChecks Defender Compliance Module v$script:ModuleVersion</p>
            <p>Data sourced from Microsoft Defender for Cloud</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Host "    [OK] HTML report: $htmlPath" -ForegroundColor Green
    
    # Export CSV - Controls
    $csvControlsPath = Join-Path $OutputDirectory "DefenderCompliance-Controls-$timestamp.csv"
    $ComplianceData.Controls | Select-Object Framework, ControlId, ControlTitle, Status, SubscriptionName, PassedResources, FailedResources |
        Export-Csv -Path $csvControlsPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] Controls CSV: $csvControlsPath" -ForegroundColor Green
    
    # Export CSV - Summary by Standard
    $csvSummaryPath = Join-Path $OutputDirectory "DefenderCompliance-Summary-$timestamp.csv"
    $summaryData = @()
    foreach ($standardId in $ComplianceData.Standards.Keys) {
        $standard = $ComplianceData.Standards[$standardId]
        foreach ($sub in $standard.Subscriptions) {
            $summaryData += [PSCustomObject]@{
                Standard = $standard.Name
                Framework = $standard.Framework
                Subscription = $sub.SubscriptionName
                CompliancePercent = $sub.CompliancePercent
                PassedControls = $sub.Passed
                FailedControls = $sub.Failed
                AssessmentDate = $ComplianceData.AssessmentDate
            }
        }
    }
    $summaryData | Export-Csv -Path $csvSummaryPath -NoTypeInformation -Encoding UTF8
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
    'Initialize-DefenderComplianceModule',
    'Get-AvailableSubscriptions',
    'Get-DefenderComplianceStandards',
    'Get-DefenderComplianceControls',
    'Get-DefenderComplianceAssessments',
    'Get-DefenderComplianceAssessment',
    'Export-DefenderComplianceReport'
)

# Export variables for integration
Export-ModuleMember -Variable @(
    'SupportedStandards'
)

#endregion

# Auto-initialize when module is imported
$null = Initialize-DefenderComplianceModule
