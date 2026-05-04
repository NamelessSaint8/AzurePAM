<#
.SYNOPSIS
    EntraChecks-SecureScore.psm1
    Module for Microsoft Secure Score integration and comparison

.DESCRIPTION
    This module retrieves Microsoft Secure Score data and integrates it with
    the EntraChecks security assessment. It provides:

    - Current Secure Score retrieval
    - Control profile analysis
    - Comparison with EntraChecks findings
    - Actionable improvement recommendations
    - Historical score tracking
    
.NOTES
    Version: 1.0.0
    Author: David Stells
    Requires: Microsoft.Graph PowerShell SDK
    
    Required Graph Permissions:
    - SecurityEvents.Read.All
    
.LINK
    Main Script: Invoke-EntraChecks.ps1
    Secure Score API: https://learn.microsoft.com/en-us/graph/api/security-list-securescores
#>

#Requires -Version 5.1

# Module version
$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-SecureScore"

# Provenance: data source key for any findings this module emits via Add-Finding.
# Matches a key in EntraChecks-DataSources.psm1 :: $script:DataSourceCatalog.
$script:DataSourceKey = 'SecureScore'

#region ==================== SECURE SCORE CONTROL MAPPINGS ====================

# Mapping between Microsoft Secure Score controls and EntraChecks
# This allows correlation between Microsoft's assessment and ours
$script:SecureScoreToEntraCheckMapping = @{
    # MFA Controls
    "MFARegistrationV2" = @{
        EntraChecks = @("Check-AuthenticationMethodsPolicy", "Check-ConditionalAccessPolicies")
        Category = "Identity"
        Description = "MFA registration for all users"
    }
    "AdminMFAV2" = @{
        EntraChecks = @("Check-PrivilegedUserMFACoverage", "Check-ConditionalAccessPolicies")
        Category = "Identity"
        Description = "MFA for administrative roles"
    }
    "SigninRiskPolicy" = @{
        EntraChecks = @("Check-SignInRiskPolicy")
        Category = "Identity"
        Description = "Sign-in risk policy"
    }
    "UserRiskPolicy" = @{
        EntraChecks = @("Check-UserRiskPolicy")
        Category = "Identity"
        Description = "User risk policy"
    }
    
    # Password Controls
    "PasswordHashSync" = @{
        EntraChecks = @("Check-PasswordHashSync", "Check-DirectorySyncStatus")
        Category = "Identity"
        Description = "Password hash synchronization"
    }
    "BlockLegacyAuthentication" = @{
        EntraChecks = @("Check-ConditionalAccessPolicies")
        Category = "Identity"
        Description = "Block legacy authentication"
    }
    "SelfServicePasswordReset" = @{
        EntraChecks = @("Check-SelfServicePasswordReset")
        Category = "Identity"
        Description = "Self-service password reset"
    }
    
    # Privileged Access Controls
    "PrivilegedAccessReview" = @{
        EntraChecks = @("Check-AccessReviewsConfiguration", "Check-PIMConfiguration")
        Category = "Identity"
        Description = "Privileged access reviews"
    }
    "RoleOverlap" = @{
        EntraChecks = @("Check-PrivilegedRoleCreep", "Check-DirectoryRolesAndMembers")
        Category = "Identity"
        Description = "Role assignment overlap"
    }
    "LimitedAdminRoles" = @{
        EntraChecks = @("Check-DirectoryRolesAndMembers", "Check-PrivilegedRoleCreep")
        Category = "Identity"
        Description = "Use of limited admin roles"
    }
    "PIMUsage" = @{
        EntraChecks = @("Check-PIMConfiguration")
        Category = "Identity"
        Description = "Privileged Identity Management usage"
    }
    
    # Application Controls
    "IntegratedApps" = @{
        EntraChecks = @("Check-ApplicationInventory", "Check-ConsentPolicy")
        Category = "Apps"
        Description = "Integrated application security"
    }
    "NonAdminAppConsent" = @{
        EntraChecks = @("Check-ConsentPolicy", "Check-AdminConsentWorkflow")
        Category = "Apps"
        Description = "User consent to applications"
    }
    "AppPermissionGrants" = @{
        EntraChecks = @("Check-AppPermissionsAnalysis", "Check-ServicePrincipalCredentials")
        Category = "Apps"
        Description = "Application permission grants"
    }
    
    # Device Controls
    "DeviceCompliance" = @{
        EntraChecks = @("Check-DeviceComplianceStatus", "Check-DeviceCompliancePolicies")
        Category = "Device"
        Description = "Device compliance status"
    }
    "DeviceCompliancePolicy" = @{
        EntraChecks = @("Check-ConditionalAccessDeviceControls", "Check-DeviceCompliancePolicies")
        Category = "Device"
        Description = "Device compliance in Conditional Access"
    }
    "BitLocker" = @{
        EntraChecks = @("Check-BitLockerRecoveryKeys")
        Category = "Device"
        Description = "BitLocker encryption"
    }
    
    # Data Protection
    "AuditLogging" = @{
        EntraChecks = @("Check-AuditLogRetention")
        Category = "Data"
        Description = "Audit logging enabled"
    }
    
    # Conditional Access
    "ConditionalAccessPolicies" = @{
        EntraChecks = @("Check-ConditionalAccessPolicies")
        Category = "Identity"
        Description = "Conditional Access policy coverage"
    }
}

# Categories for grouping Secure Score controls
$script:SecureScoreCategories = @{
    "Identity" = "Identity and Access Management"
    "Data" = "Data Protection"
    "Device" = "Device Security"
    "Apps" = "Application Security"
    "Infrastructure" = "Infrastructure Security"
}

#endregion

#region ==================== MODULE INITIALIZATION ====================

<#
.SYNOPSIS
    Initializes the Secure Score module and verifies Graph connection and required scopes.
#>
function Initialize-SecureScoreModule {
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
        
        # Check for required scope
        $requiredScopes = @("SecurityEvents.Read.All")
        $hasRequiredScope = $false
        foreach ($scope in $requiredScopes) {
            if ($context.Scopes -contains $scope) {
                $hasRequiredScope = $true
                Write-Host "    [i] Using scope: $scope" -ForegroundColor Gray
                break
            }
        }

        if (-not $hasRequiredScope) {
            Write-Host "    [!] Required scope missing. Need SecurityEvents.Read.All" -ForegroundColor Yellow
        }
    }
    
    Write-Host "    [OK] Module loaded successfully" -ForegroundColor Green
    
    return @{
        Name = $script:ModuleName
        Version = $script:ModuleVersion
        MappedControls = $script:SecureScoreToEntraCheckMapping.Count
        RequiredPermissions = @("SecurityEvents.Read.All")
    }
}

#endregion

#region ==================== HELPER FUNCTIONS ====================

function Invoke-SecureScoreGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )
    
    try {
        $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
        return $response
    }
    catch {
        Write-Host "[!] Graph API Error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

#endregion

#region ==================== SECURE SCORE RETRIEVAL ====================

<#
.SYNOPSIS
    Retrieves the current Microsoft Secure Score.

.DESCRIPTION
    Gets the most recent Secure Score data including:
    - Current score and max score
    - Score by category
    - Comparison with averages
    - Historical trend (if available)

.PARAMETER IncludeHistory
    Include historical score data (last 90 days).

.OUTPUTS
    Hashtable with Secure Score data.

.NOTES
    Required Permission: SecurityEvents.Read.All
#>
function Get-SecureScore {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [switch]$IncludeHistory
    )
    
    Write-Host "`n[+] Retrieving Microsoft Secure Score..." -ForegroundColor Cyan
    
    try {
        # Get secure scores (returns multiple entries, most recent first)
        $uri = "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1"
        if ($IncludeHistory) {
            $uri = "https://graph.microsoft.com/v1.0/security/secureScores?`$top=90"
        }
        
        $response = Invoke-SecureScoreGraphRequest -Uri $uri
        
        if (-not $response -or -not $response.value -or $response.value.Count -eq 0) {
            Write-Host "    [!] No Secure Score data available" -ForegroundColor Yellow
            return $null
        }
        
        $currentScore = $response.value[0]
        
        # Calculate percentage
        $scorePercent = if ($currentScore.maxScore -gt 0) {
            [math]::Round(($currentScore.currentScore / $currentScore.maxScore) * 100, 1)
        } else { 0 }
        
        # Parse category scores
        $categoryScores = @()
        if ($currentScore.averageComparativeScores) {
            foreach ($avg in $currentScore.averageComparativeScores) {
                $categoryScores += [PSCustomObject]@{
                    Basis = $avg.basis
                    AverageScore = $avg.averageScore
                }
            }
        }
        
        # Parse control scores
        $controlScores = @()
        if ($currentScore.controlScores) {
            foreach ($control in $currentScore.controlScores) {
                $controlScores += [PSCustomObject]@{
                    ControlName = $control.controlName
                    ControlCategory = $control.controlCategory
                    Score = $control.score
                    MaxScore = if ($control.scoreInPercentage -and $control.score) {
                        [math]::Round($control.score / ($control.scoreInPercentage / 100), 2)
                    } else { $null }
                    ScorePercent = $control.scoreInPercentage
                    Description = $control.description
                    OnImplementation = $control.on
                    ImplementationStatus = $control.implementationStatus
                }
            }
        }
        
        $result = @{
            TenantId = $currentScore.azureTenantId
            CreatedDate = $currentScore.createdDateTime
            CurrentScore = $currentScore.currentScore
            MaxScore = $currentScore.maxScore
            ScorePercent = $scorePercent
            EnabledServices = $currentScore.enabledServices
            LicensedUserCount = $currentScore.licensedUserCount
            ActiveUserCount = $currentScore.activeUserCount
            CategoryScores = $categoryScores
            ControlScores = $controlScores
            VendorInformation = $currentScore.vendorInformation
        }
        
        # Add historical data if requested
        if ($IncludeHistory -and $response.value.Count -gt 1) {
            $history = @()
            foreach ($score in $response.value) {
                $history += [PSCustomObject]@{
                    Date = $score.createdDateTime
                    Score = $score.currentScore
                    MaxScore = $score.maxScore
                    Percent = if ($score.maxScore -gt 0) {
                        [math]::Round(($score.currentScore / $score.maxScore) * 100, 1)
                    } else { 0 }
                }
            }
            $result.History = $history
        }
        
        Write-Host "    [OK] Current Score: $($result.CurrentScore)/$($result.MaxScore) ($scorePercent%)" -ForegroundColor $(
            if ($scorePercent -ge 80) { "Green" } elseif ($scorePercent -ge 60) { "Yellow" } else { "Red" }
        )
        
        return $result
    }
    catch {
        Write-Host "    [!] Error retrieving Secure Score: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

<#
.SYNOPSIS
    Retrieves Secure Score control profiles.

.DESCRIPTION
    Gets detailed information about each Secure Score control including:
    - Control name and description
    - Implementation status
    - Remediation steps
    - Impact on score

.OUTPUTS
    Array of control profile objects.

.NOTES
    Required Permission: SecurityEvents.Read.All
#>
function Get-SecureScoreControlProfiles {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Retrieving Secure Score control profiles..." -ForegroundColor Cyan
    
    try {
        $allControls = @()
        $uri = "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles"
        
        do {
            $response = Invoke-SecureScoreGraphRequest -Uri $uri
            
            if ($response -and $response.value) {
                foreach ($control in $response.value) {
                    $allControls += [PSCustomObject]@{
                        Id = $control.id
                        ControlName = $control.controlName
                        Title = $control.title
                        ControlCategory = $control.controlCategory
                        ActionType = $control.actionType
                        Service = $control.service
                        MaxScore = $control.maxScore
                        Tier = $control.tier
                        UserImpact = $control.userImpact
                        ImplementationCost = $control.implementationCost
                        Rank = $control.rank
                        Threats = $control.threats
                        Deprecated = $control.deprecated
                        Remediation = $control.remediation
                        RemediationImpact = $control.remediationImpact
                        ActionUrl = $control.actionUrl
                        ControlStateUpdates = $control.controlStateUpdates
                        ComplianceInformation = $control.complianceInformation
                    }
                }
            }
            
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        # Filter out deprecated controls
        $activeControls = $allControls | Where-Object { -not $_.Deprecated }
        
        Write-Host "    [OK] Retrieved $($activeControls.Count) active control profiles" -ForegroundColor Green
        
        return $activeControls
    }
    catch {
        Write-Host "    [!] Error retrieving control profiles: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

<#
.SYNOPSIS
    Gets improvement actions from Secure Score.

.DESCRIPTION
    Analyzes control profiles to identify improvement actions sorted by impact.

.PARAMETER ControlProfiles
    Control profiles from Get-SecureScoreControlProfiles.

.PARAMETER SecureScore
    Current secure score from Get-SecureScore.

.OUTPUTS
    Array of improvement actions prioritized by impact.
#>
function Get-SecureScoreImprovementActions {
    [CmdletBinding()]
    param(
        [Parameter()]
        $ControlProfiles,
        
        [Parameter()]
        $SecureScore
    )
    
    Write-Host "`n[+] Analyzing improvement actions..." -ForegroundColor Cyan
    
    if (-not $ControlProfiles) {
        $ControlProfiles = Get-SecureScoreControlProfiles
    }
    
    if (-not $SecureScore) {
        $SecureScore = Get-SecureScore
    }
    
    if (-not $ControlProfiles -or -not $SecureScore) {
        Write-Host "    [!] Unable to analyze - missing data" -ForegroundColor Yellow
        return $null
    }
    
    # Create lookup for current control scores
    $currentScores = @{}
    foreach ($cs in $SecureScore.ControlScores) {
        if ($cs.ControlName) {
            $currentScores[$cs.ControlName] = $cs
        }
    }
    
    $improvements = @()
    
    foreach ($profile in $ControlProfiles) {
        if (-not $profile.ControlName) { continue }
        $currentControl = $currentScores[$profile.ControlName]
        
        # Calculate potential improvement
        $currentScore = if ($currentControl) { $currentControl.Score } else { 0 }
        $maxScore = $profile.MaxScore
        $potentialImprovement = $maxScore - $currentScore
        
        # Only include if there's room for improvement
        if ($potentialImprovement -gt 0) {
            # Determine implementation status
            $status = if ($currentControl) { 
                $currentControl.ImplementationStatus 
            } else { 
                "notImplemented" 
            }
            
            $improvements += [PSCustomObject]@{
                ControlName = $profile.ControlName
                Title = $profile.Title
                Category = $profile.ControlCategory
                Service = $profile.Service
                CurrentScore = $currentScore
                MaxScore = $maxScore
                PotentialImprovement = $potentialImprovement
                ImplementationStatus = $status
                ImplementationCost = $profile.ImplementationCost
                UserImpact = $profile.UserImpact
                Tier = $profile.Tier
                Rank = $profile.Rank
                Remediation = $profile.Remediation
                RemediationImpact = $profile.RemediationImpact
                ActionUrl = $profile.ActionUrl
                Threats = ($profile.Threats -join ", ")
                # Priority score (higher = more important)
                PriorityScore = [math]::Round(
                    ($potentialImprovement * 10) +
                    $(if ($profile.ImplementationCost -eq "Low") { 3 } elseif ($profile.ImplementationCost -eq "Moderate") { 2 } elseif ($profile.ImplementationCost -eq "High") { 1 } else { 0 }) +
                    $(if ($profile.UserImpact -eq "Low") { 3 } elseif ($profile.UserImpact -eq "Moderate") { 2 } elseif ($profile.UserImpact -eq "High") { 1 } else { 0 })
                    , 2)
            }
        }
    }
    
    # Sort by priority (potential improvement and cost/impact)
    $improvements = $improvements | Sort-Object PriorityScore -Descending
    
    $totalPotential = ($improvements | Measure-Object -Property PotentialImprovement -Sum).Sum
    Write-Host "    [OK] Found $($improvements.Count) improvement actions (+$totalPotential potential points)" -ForegroundColor Green
    
    return $improvements
}

#endregion

#region ==================== COMPARISON AND ANALYSIS ====================

<#
.SYNOPSIS
    Compares Secure Score controls with EntraChecks findings.

.DESCRIPTION
    Creates a correlation between Microsoft Secure Score controls and
    EntraChecks security assessment findings to:
    - Show alignment between assessments
    - Identify gaps in either assessment
    - Provide consolidated view of security posture

.PARAMETER SecureScore
    Current secure score data.

.PARAMETER ControlProfiles
    Secure Score control profiles.

.PARAMETER Findings
    EntraChecks findings array.

.OUTPUTS
    Comparison results with aligned and divergent findings.
#>
function Compare-SecureScoreWithFindings {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter()]
        $SecureScore,

        [Parameter()]
        $ControlProfiles,

        [Parameter()]
        [array]$Findings = $script:Findings
    )
    
    Write-Host "`n[+] Comparing Secure Score with EntraChecks findings..." -ForegroundColor Cyan
    
    if (-not $SecureScore) {
        $SecureScore = Get-SecureScore
    }
    
    if (-not $SecureScore) {
        Write-Host "    [!] No Secure Score data available" -ForegroundColor Yellow
        return $null
    }
    
    # Create lookup for control scores
    $controlScoreLookup = @{}
    foreach ($cs in $SecureScore.ControlScores) {
        if ($cs.ControlName) {
            $controlScoreLookup[$cs.ControlName] = $cs
        }
    }
    
    $comparison = @()
    $alignedCount = 0
    $divergentCount = 0
    $noMappingCount = 0
    
    foreach ($controlName in $script:SecureScoreToEntraCheckMapping.Keys) {
        $mapping = $script:SecureScoreToEntraCheckMapping[$controlName]
        $secureScoreControl = $controlScoreLookup[$controlName]
        
        # Find related EntraCheck findings
        $relatedFindings = @()
        foreach ($checkName in $mapping.EntraChecks) {
            $checkPattern = $checkName -replace "Check-", ""
            $matchingFindings = $Findings | Where-Object { 
                $_.Object -match $checkPattern -or 
                $_.Description -match $checkPattern
            }
            $relatedFindings += $matchingFindings
        }
        $relatedFindings = $relatedFindings | Select-Object -Unique
        
        # Determine Secure Score status
        $ssStatus = "Unknown"
        $ssPercent = 0
        if ($secureScoreControl) {
            $ssPercent = $secureScoreControl.ScorePercent
            $ssStatus = switch ($secureScoreControl.ImplementationStatus) {
                "implemented" { "Implemented" }
                "notImplemented" { "Not Implemented" }
                "partiallyImplemented" { "Partial" }
                "thirdParty" { "Third Party" }
                "ignored" { "Ignored" }
                "plannedToAddress" { "Planned" }
                default { $secureScoreControl.ImplementationStatus }
            }
        }
        
        # Determine EntraChecks status
        $ecStatus = "Not Assessed"
        $ecIssues = @()
        if ($relatedFindings.Count -gt 0) {
            $failCount = ($relatedFindings | Where-Object { $_.Status -eq "FAIL" }).Count
            $warnCount = ($relatedFindings | Where-Object { $_.Status -eq "WARNING" }).Count
            $okCount = ($relatedFindings | Where-Object { $_.Status -eq "OK" }).Count
            
            if ($failCount -gt 0) {
                $ecStatus = "Issues Found"
                $ecIssues = $relatedFindings | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object { $_.Description }
            }
            elseif ($warnCount -gt 0) {
                $ecStatus = "Warnings"
                $ecIssues = $relatedFindings | Where-Object { $_.Status -eq "WARNING" } | ForEach-Object { $_.Description }
            }
            elseif ($okCount -gt 0) {
                $ecStatus = "OK"
            }
        }
        
        # Determine alignment
        $alignment = "No Data"
        if ($secureScoreControl -and $relatedFindings.Count -gt 0) {
            $ssGood = $ssStatus -in @("Implemented", "Third Party") -or $ssPercent -ge 80
            $ecGood = $ecStatus -eq "OK"
            
            if ($ssGood -and $ecGood) {
                $alignment = "Aligned - Good"
                $alignedCount++
            }
            elseif (-not $ssGood -and -not $ecGood) {
                $alignment = "Aligned - Needs Work"
                $alignedCount++
            }
            else {
                $alignment = "Divergent"
                $divergentCount++
            }
        }
        else {
            $noMappingCount++
        }
        
        $comparison += [PSCustomObject]@{
            ControlName = $controlName
            Description = $mapping.Description
            Category = $mapping.Category
            SecureScoreStatus = $ssStatus
            SecureScorePercent = $ssPercent
            EntraChecksStatus = $ecStatus
            EntraChecksIssues = ($ecIssues -join " | ")
            Alignment = $alignment
            MappedChecks = ($mapping.EntraChecks -join ", ")
            FindingCount = $relatedFindings.Count
        }
    }
    
    # Sort by alignment (divergent first, then needs work)
    $comparison = $comparison | Sort-Object @{Expression = {
            switch ($_.Alignment) {
                "Divergent" { 1 }
                "Aligned - Needs Work" { 2 }
                "No Data" { 3 }
                "Aligned - Good" { 4 }
                default { 5 }
            }
        } }
    
    Write-Host "    [i] Aligned: $alignedCount | Divergent: $divergentCount | No mapping: $noMappingCount" -ForegroundColor $(
        if ($divergentCount -eq 0) { "Green" } elseif ($divergentCount -le 3) { "Yellow" } else { "Red" }
    )
    
    return @{
        Comparison = $comparison
        Summary = @{
            TotalMapped = $script:SecureScoreToEntraCheckMapping.Count
            Aligned = $alignedCount
            Divergent = $divergentCount
            NoData = $noMappingCount
        }
        SecureScore = $SecureScore
    }
}

<#
.SYNOPSIS
    Generates a consolidated security posture report.

.DESCRIPTION
    Creates a comprehensive view combining Secure Score and EntraChecks
    assessment data.

.PARAMETER OutputDirectory
    Directory for output files.

.PARAMETER TenantName
    Name of the tenant.

.PARAMETER Findings
    EntraChecks findings array.
#>
function Export-SecureScoreReport {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputDirectory,
        
        [Parameter()]
        [string]$TenantName = "Unknown Tenant",
        
        [Parameter()]
        [array]$Findings = $script:Findings
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host " Secure Score Integration Report" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Magenta
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    
    # Gather data
    $secureScore = Get-SecureScore -IncludeHistory
    $controlProfiles = Get-SecureScoreControlProfiles

    if (-not $secureScore) {
        Write-Host "`n[!] Unable to generate report - no Secure Score data" -ForegroundColor Red
        return $null
    }

    $improvements = Get-SecureScoreImprovementActions -SecureScore $secureScore -ControlProfiles $controlProfiles
    $comparison = Compare-SecureScoreWithFindings -SecureScore $secureScore -ControlProfiles $controlProfiles -Findings $Findings
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $assessmentDate = Get-Date -Format "MMMM dd, yyyy HH:mm"
    
    # Generate HTML Report
    $htmlPath = Join-Path $OutputDirectory "SecureScore-Report-$timestamp.html"
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Secure Score Report</title>
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
            background: linear-gradient(135deg, #0078d4, #106ebe);
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
            border-bottom: 2px solid var(--primary);
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
        .badge-secondary { background: var(--gray-200); color: var(--gray-600); }
        
        .improvement-item {
            border-left: 4px solid var(--primary);
            padding: 15px 20px;
            margin-bottom: 15px;
            background: white;
            border-radius: 0 8px 8px 0;
        }
        
        .improvement-item.high-impact { border-left-color: var(--success); }
        
        .improvement-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        
        .improvement-title { font-weight: 600; }
        .improvement-points { font-weight: 700; color: var(--success); }
        
        .improvement-meta {
            display: flex;
            gap: 15px;
            font-size: 0.85rem;
            color: var(--gray-600);
            margin-bottom: 10px;
        }
        
        .improvement-remediation {
            background: var(--gray-100);
            padding: 10px 15px;
            border-radius: 4px;
            font-size: 0.9rem;
        }
        
        .comparison-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
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
        
        .category-bar {
            display: flex;
            align-items: center;
            margin: 10px 0;
        }
        
        .category-label { width: 120px; font-size: 0.85rem; }
        .category-progress {
            flex: 1;
            height: 24px;
            background: var(--gray-200);
            border-radius: 4px;
            overflow: hidden;
        }
        
        .category-fill {
            height: 100%;
            display: flex;
            align-items: center;
            padding: 0 10px;
            color: white;
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .category-fill.good { background: var(--success); }
        .category-fill.warn { background: var(--warning); }
        .category-fill.bad { background: var(--danger); }
        
        footer {
            text-align: center;
            padding: 20px;
            color: var(--gray-600);
            font-size: 0.85rem;
        }
        
        @media print {
            body { background: white; }
            .card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Microsoft Secure Score Report</h1>
            <p>Security posture assessment with improvement recommendations</p>
            <div class="score-hero">
                <div class="score-circle">
                    <span class="value">$($secureScore.ScorePercent)%</span>
                    <span class="label">Secure Score</span>
                </div>
                <div class="score-details">
                    <p><strong>Tenant:</strong> $TenantName</p>
                    <p><strong>Score:</strong> $($secureScore.CurrentScore) / $($secureScore.MaxScore) points</p>
                    <p><strong>Assessment Date:</strong> $assessmentDate</p>
                    <p><strong>Licensed Users:</strong> $($secureScore.LicensedUserCount)</p>
                </div>
            </div>
        </header>

        <!-- Summary Stats -->
        <div class="comparison-grid">
            <div class="stat-card">
                <div class="stat-value $(if ($secureScore.ScorePercent -ge 80) {'good'} elseif ($secureScore.ScorePercent -ge 60) {'warn'} else {'bad'})">$($secureScore.ScorePercent)%</div>
                <div class="stat-label">Microsoft Secure Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-value good">+$([math]::Round(($improvements | Measure-Object -Property PotentialImprovement -Sum).Sum, 0))</div>
                <div class="stat-label">Potential Improvement Points</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$($improvements.Count)</div>
                <div class="stat-label">Improvement Actions Available</div>
            </div>
        </div>
"@

    # Category breakdown
    if ($secureScore.ControlScores) {
        $categoryGroups = $secureScore.ControlScores | Group-Object ControlCategory
        
        $html += @"
        
        <h2 class="section-title">Score by Category</h2>
        <div class="card">
            <div class="card-body">
"@
        
        foreach ($cat in $categoryGroups) {
            $catTotal = ($cat.Group | Measure-Object -Property Score -Sum).Sum
            $catMax = ($cat.Group | Where-Object { $_.MaxScore } | Measure-Object -Property MaxScore -Sum).Sum
            if (-not $catMax) { $catMax = $catTotal * 1.5 } # Estimate if not available
            $catPercent = if ($catMax -gt 0) { [math]::Round(($catTotal / $catMax) * 100, 0) } else { 0 }
            $catClass = if ($catPercent -ge 80) { "good" } elseif ($catPercent -ge 60) { "warn" } else { "bad" }
            
            $html += @"
                <div class="category-bar">
                    <span class="category-label">$($cat.Name)</span>
                    <div class="category-progress">
                        <div class="category-fill $catClass" style="width: $catPercent%">$catPercent%</div>
                    </div>
                </div>
"@
        }
        
        $html += @"
            </div>
        </div>
"@
    }

    # Comparison with EntraChecks
    if ($comparison) {
        $html += @"
        
        <h2 class="section-title">Comparison with EntraChecks Assessment</h2>
        <div class="comparison-grid">
            <div class="stat-card">
                <div class="stat-value good">$($comparison.Summary.Aligned)</div>
                <div class="stat-label">Aligned Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value $(if ($comparison.Summary.Divergent -eq 0) {'good'} else {'warn'})">$($comparison.Summary.Divergent)</div>
                <div class="stat-label">Divergent Findings</div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">Control Comparison Details</div>
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Control</th>
                            <th>Secure Score</th>
                            <th>EntraChecks</th>
                            <th>Alignment</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($item in $comparison.Comparison) {
            $ssClass = switch ($item.SecureScoreStatus) {
                "Implemented" { "badge-success" }
                "Partial" { "badge-warning" }
                "Not Implemented" { "badge-danger" }
                default { "badge-secondary" }
            }
            
            $ecClass = switch ($item.EntraChecksStatus) {
                "OK" { "badge-success" }
                "Warnings" { "badge-warning" }
                "Issues Found" { "badge-danger" }
                default { "badge-secondary" }
            }
            
            $alignClass = switch ($item.Alignment) {
                "Aligned - Good" { "badge-success" }
                "Aligned - Needs Work" { "badge-warning" }
                "Divergent" { "badge-danger" }
                default { "badge-secondary" }
            }
            
            $html += @"
                        <tr>
                            <td><strong>$($item.ControlName)</strong><br><small>$($item.Description)</small></td>
                            <td><span class="badge $ssClass">$($item.SecureScoreStatus)</span></td>
                            <td><span class="badge $ecClass">$($item.EntraChecksStatus)</span></td>
                            <td><span class="badge $alignClass">$($item.Alignment)</span></td>
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

    # Top Improvement Actions
    $html += @"
        
        <h2 class="section-title">Top Improvement Actions</h2>
        <p style="margin-bottom: 20px; color: var(--gray-600);">Prioritized by potential score impact and implementation ease</p>
"@

    $topImprovements = $improvements | Select-Object -First 10
    foreach ($imp in $topImprovements) {
        $impactClass = if ($imp.PotentialImprovement -ge 5) { "high-impact" } else { "" }
        
        $html += @"
        <div class="improvement-item $impactClass">
            <div class="improvement-header">
                <div>
                    <div class="improvement-title">$($imp.Title)</div>
                    <small>$($imp.Category) - $($imp.Service)</small>
                </div>
                <span class="improvement-points">+$($imp.PotentialImprovement) points</span>
            </div>
            <div class="improvement-meta">
                <span>Cost: $($imp.ImplementationCost)</span>
                <span>User Impact: $($imp.UserImpact)</span>
                <span>Status: $($imp.ImplementationStatus)</span>
            </div>
"@
        if ($imp.Remediation) {
            $html += @"
            <div class="improvement-remediation">
                <strong>How to implement:</strong> $($imp.Remediation -replace '<[^>]+>', '')
            </div>
"@
        }
        if ($imp.ActionUrl) {
            $html += @"
            <p style="margin-top: 10px;"><a href="$($imp.ActionUrl)" target="_blank">Take action in Microsoft 365 &#8594;</a></p>
"@
        }
        $html += @"
        </div>
"@
    }

    # Footer
    $html += @"
        
        <footer>
            <p>Generated by EntraChecks Secure Score Module v$script:ModuleVersion</p>
            <p>Data sourced from Microsoft Secure Score API</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Host "`n[OK] HTML report saved: $htmlPath" -ForegroundColor Green
    
    # Export CSV files
    $improvementsCsvPath = Join-Path $OutputDirectory "SecureScore-Improvements-$timestamp.csv"
    $improvements | Select-Object ControlName, Title, Category, Service, CurrentScore, MaxScore, PotentialImprovement, ImplementationStatus, ImplementationCost, UserImpact, Remediation, ActionUrl |
        Export-Csv -Path $improvementsCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Improvements CSV: $improvementsCsvPath" -ForegroundColor Green
    
    if ($comparison) {
        $comparisonCsvPath = Join-Path $OutputDirectory "SecureScore-Comparison-$timestamp.csv"
        $comparison.Comparison | Export-Csv -Path $comparisonCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "[OK] Comparison CSV: $comparisonCsvPath" -ForegroundColor Green
    }
    
    # Summary CSV
    $summaryCsvPath = Join-Path $OutputDirectory "SecureScore-Summary-$timestamp.csv"
    @([PSCustomObject]@{
            Tenant = $TenantName
            AssessmentDate = $assessmentDate
            CurrentScore = $secureScore.CurrentScore
            MaxScore = $secureScore.MaxScore
            ScorePercent = $secureScore.ScorePercent
            PotentialImprovement = ($improvements | Measure-Object -Property PotentialImprovement -Sum).Sum
            ImprovementActionsCount = $improvements.Count
            LicensedUsers = $secureScore.LicensedUserCount
            ActiveUsers = $secureScore.ActiveUserCount
        }) | Export-Csv -Path $summaryCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Summary CSV: $summaryCsvPath" -ForegroundColor Green
    
    return @{
        SecureScore = $secureScore
        ControlProfiles = $controlProfiles
        Improvements = $improvements
        Comparison = $comparison
        HTMLReport = $htmlPath
        OutputDirectory = $OutputDirectory
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

# Export module members
Export-ModuleMember -Function @(
    'Initialize-SecureScoreModule',
    'Get-SecureScore',
    'Get-SecureScoreControlProfiles',
    'Get-SecureScoreImprovementActions',
    'Compare-SecureScoreWithFindings',
    'Export-SecureScoreReport'
)

#endregion

# Auto-initialize when module is imported
$null = Initialize-SecureScoreModule
