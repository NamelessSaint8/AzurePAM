# EntraChecks Enhanced Excel Reporting Module
# Generates comprehensive Excel workbooks with multiple worksheets

<#
.SYNOPSIS
    Generates enhanced Excel reports for EntraChecks findings.

.DESCRIPTION
    Creates multi-worksheet Excel workbooks with:
    - Executive summary dashboard
    - All findings with complete data
    - Priority findings sorted by score
    - Quick wins worksheet
    - Compliance framework worksheets
    - Risk analysis sheet
    - Pivot-ready data structure

.NOTES
    Author: David Stells
    Version: 1.0.0
    Requires: ImportExcel module (optional - will use CSV fallback if not available)
#>

# Import dependent modules
$modulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $modulePath "EntraChecks-ComplianceMapping.psm1") -Force
Import-Module (Join-Path $modulePath "EntraChecks-RiskScoring.psm1") -Force
Import-Module (Join-Path $modulePath "EntraChecks-RemediationGuidance.psm1") -Force

#region Excel Generation Functions

function New-EnhancedExcelReport {
    <#
    .SYNOPSIS
        Generates an enhanced Excel report with multiple worksheets.

    .DESCRIPTION
        Creates a comprehensive Excel workbook with different views of findings data,
        compliance mapping, and risk analysis.

    .PARAMETER Findings
        Array of finding objects to include in the report

    .PARAMETER OutputPath
        Path where the Excel file will be saved

    .PARAMETER TenantInfo
        Tenant information object (TenantId, TenantName, etc.)

    .PARAMETER UseImportExcel
        If true, uses ImportExcel module. If false or module not available, exports to CSV files

    .EXAMPLE
        New-EnhancedExcelReport -Findings $findings -OutputPath "report.xlsx" -TenantInfo $tenantInfo
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [object]$TenantInfo,

        # New in PR 2 — surface the same data the HTML report now renders.
        # All optional; missing data simply skips the corresponding sheet.
        [object]$SecureScore,

        [object]$AzurePolicy,

        [object]$PurviewCompliance,

        [switch]$UseImportExcel
    )

    # Enhance findings with risk scoring, compliance mapping, and remediation
    Write-Verbose "Enhancing findings with risk scoring and compliance mapping..."
    $enhancedFindings = @()
    foreach ($finding in $Findings) {
        $enhanced = $finding |
            Add-RiskScoring |
            Add-ComplianceMapping |
            Add-RemediationGuidance
        $enhancedFindings += $enhanced
    }

    # Check if ImportExcel module is available
    $hasImportExcel = $false
    if ($UseImportExcel) {
        $hasImportExcel = Get-Module -ListAvailable -Name ImportExcel
        if (-not $hasImportExcel) {
            Write-Warning "ImportExcel module not found. Falling back to CSV export."
            Write-Warning "Install with: Install-Module ImportExcel -Scope CurrentUser"
        }
    }

    if ($hasImportExcel) {
        # Use ImportExcel module for multi-sheet Excel workbook
        Write-Verbose "Generating Excel workbook with ImportExcel module..."
        New-ExcelWorkbook -Findings $enhancedFindings -OutputPath $OutputPath -TenantInfo $TenantInfo `
            -SecureScore $SecureScore -AzurePolicy $AzurePolicy -PurviewCompliance $PurviewCompliance
    }
    else {
        # Fall back to multiple CSV files
        Write-Verbose "Generating CSV files (ImportExcel not available)..."
        New-CSVWorkbook -Findings $enhancedFindings -OutputPath $OutputPath -TenantInfo $TenantInfo `
            -SecureScore $SecureScore -AzurePolicy $AzurePolicy -PurviewCompliance $PurviewCompliance
    }

    return $OutputPath
}

function New-ExcelWorkbook {
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [object]$TenantInfo,

        [object]$SecureScore,

        [object]$AzurePolicy,

        [object]$PurviewCompliance
    )

    # Calculate summaries
    $riskSummary = Get-RiskSummary -Findings $Findings
    $complianceGap = Get-ComplianceGapReport -Findings $Findings -Framework 'All'
    $quickWins = Get-QuickWins -Findings $Findings
    $prioritized = Get-PrioritizedFindings -Findings $Findings

    # Remove existing file if it exists
    if (Test-Path $OutputPath) {
        Remove-Item $OutputPath -Force
    }

    # 1. Executive Summary Sheet
    Write-Verbose "Creating Executive Summary sheet..."
    $execData = @(
        [PSCustomObject]@{Metric = 'Tenant Name'; Value = $TenantInfo.TenantName; Details = $TenantInfo.TenantId }
        [PSCustomObject]@{Metric = 'Report Generated'; Value = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Details = '' }
        [PSCustomObject]@{Metric = 'Total Findings'; Value = $Findings.Count; Details = '' }
        [PSCustomObject]@{Metric = ''; Value = ''; Details = '' }
        [PSCustomObject]@{Metric = 'RISK ANALYSIS'; Value = ''; Details = '' }
        [PSCustomObject]@{Metric = 'Critical Risk Findings'; Value = $riskSummary.CriticalCount; Details = "$($riskSummary.CriticalPercent)%" }
        [PSCustomObject]@{Metric = 'High Risk Findings'; Value = $riskSummary.HighCount; Details = "$($riskSummary.HighPercent)%" }
        [PSCustomObject]@{Metric = 'Medium Risk Findings'; Value = $riskSummary.MediumCount; Details = "$($riskSummary.MediumPercent)%" }
        [PSCustomObject]@{Metric = 'Low Risk Findings'; Value = $riskSummary.LowCount; Details = "$($riskSummary.LowPercent)%" }
        [PSCustomObject]@{Metric = 'Average Risk Score'; Value = $riskSummary.AverageRiskScore; Details = 'Out of 100' }
        [PSCustomObject]@{Metric = 'Max Risk Score'; Value = $riskSummary.MaxRiskScore; Details = 'Out of 100' }
        [PSCustomObject]@{Metric = 'Quick Wins Available'; Value = $riskSummary.QuickWinsCount; Details = 'High impact, low effort' }
        [PSCustomObject]@{Metric = ''; Value = ''; Details = '' }
        [PSCustomObject]@{Metric = 'COMPLIANCE IMPACT'; Value = ''; Details = '' }
        [PSCustomObject]@{Metric = 'CIS M365 Controls'; Value = $complianceGap.FrameworkGaps.CIS.ControlsAffected; Details = 'Controls with findings' }
        [PSCustomObject]@{Metric = 'NIST CSF Functions'; Value = $complianceGap.FrameworkGaps.NIST.ControlsAffected; Details = 'Functions with findings' }
        [PSCustomObject]@{Metric = 'SOC 2 Criteria'; Value = $complianceGap.FrameworkGaps.SOC2.ControlsAffected; Details = 'Criteria with findings' }
        [PSCustomObject]@{Metric = 'PCI-DSS Requirements'; Value = $complianceGap.FrameworkGaps.PCIDSS.ControlsAffected; Details = 'Requirements with findings' }
    )

    $execData | Export-Excel -Path $OutputPath -WorksheetName 'Executive Summary' -AutoSize -BoldTopRow -FreezeTopRow

    # 2. All Findings Sheet
    Write-Verbose "Creating All Findings sheet..."
    $allFindingsExport = $Findings | Select-Object `
    @{N = 'Time'; E = { $_.Time } },
    @{N = 'Status'; E = { $_.Status } },
    @{N = 'Object'; E = { $_.Object } },
    @{N = 'Description'; E = { $_.Description } },
    @{N = 'Remediation'; E = { $_.Remediation } },
    @{N = 'Risk Level'; E = { $_.RiskLevel } },
    @{N = 'Risk Score'; E = { $_.RiskScore } },
    @{N = 'Priority Score'; E = { $_.PriorityScore } },
    @{N = 'Remediation Effort'; E = { $_.RemediationEffortDescription } },
    @{N = 'Compliance Frameworks'; E = { $_.ComplianceReference } }

    $allFindingsExport | Export-Excel -Path $OutputPath -WorksheetName 'All Findings' -AutoSize -BoldTopRow -FreezeTopRow -AutoFilter

    # 3. Priority Findings Sheet
    Write-Verbose "Creating Priority Findings sheet..."
    # Local rank counter — using $script: would leak across re-runs in the same session.
    $rank = [ref]0
    $priorityExport = $prioritized | Select-Object -First 25 | Select-Object `
    @{N = 'Rank'; E = { $rank.Value++; $rank.Value } },
    @{N = 'Description'; E = { $_.Description } },
    @{N = 'Risk Level'; E = { $_.RiskLevel } },
    @{N = 'Risk Score'; E = { $_.RiskScore } },
    @{N = 'Effort'; E = { $_.RemediationEffortDescription } },
    @{N = 'Priority Score'; E = { $_.PriorityScore } },
    @{N = 'Compliance'; E = { $_.ComplianceReference } },
    @{N = 'Remediation'; E = { $_.Remediation } }

    $priorityExport | Export-Excel -Path $OutputPath -WorksheetName 'Priority Findings' -AutoSize -BoldTopRow -FreezeTopRow

    # 4. Quick Wins Sheet
    Write-Verbose "Creating Quick Wins sheet..."
    if ($quickWins.Count -gt 0) {
        $quickWinsExport = $quickWins | Select-Object `
        @{N = 'Description'; E = { $_.Description } },
        @{N = 'Risk Level'; E = { $_.RiskLevel } },
        @{N = 'Risk Score'; E = { $_.RiskScore } },
        @{N = 'Effort'; E = { $_.RemediationEffortDescription } },
        @{N = 'Priority Score'; E = { $_.PriorityScore } },
        @{N = 'Object'; E = { $_.Object } },
        @{N = 'Remediation'; E = { $_.Remediation } }

        $quickWinsExport | Export-Excel -Path $OutputPath -WorksheetName 'Quick Wins' -AutoSize -BoldTopRow -FreezeTopRow
    }

    # 5-8. Compliance Framework Sheets
    Write-Verbose "Creating Compliance framework sheets..."

    # CIS M365
    $cisFindings = $Findings | Where-Object { $_.ComplianceMappings.CIS_M365 }
    if ($cisFindings.Count -gt 0) {
        $cisExport = $cisFindings | Select-Object `
        @{N = 'Description'; E = { $_.Description } },
        @{N = 'Risk Level'; E = { $_.RiskLevel } },
        @{N = 'Risk Score'; E = { $_.RiskScore } },
        @{N = 'CIS Controls'; E = { ($_.ComplianceMappings.CIS_M365.Controls -join ', ') } },
        @{N = 'Control Title'; E = { $_.ComplianceMappings.CIS_M365.Title } },
        @{N = 'Object'; E = { $_.Object } },
        @{N = 'Remediation'; E = { $_.Remediation } }

        $cisExport | Export-Excel -Path $OutputPath -WorksheetName 'Compliance - CIS M365' -AutoSize -BoldTopRow -FreezeTopRow -AutoFilter
    }

    # NIST CSF
    $nistFindings = $Findings | Where-Object { $_.ComplianceMappings.NIST_CSF }
    if ($nistFindings.Count -gt 0) {
        $nistExport = $nistFindings | Select-Object `
        @{N = 'Description'; E = { $_.Description } },
        @{N = 'Risk Level'; E = { $_.RiskLevel } },
        @{N = 'Risk Score'; E = { $_.RiskScore } },
        @{N = 'NIST Functions'; E = { ($_.ComplianceMappings.NIST_CSF.Functions -join ', ') } },
        @{N = 'Function Description'; E = { $_.ComplianceMappings.NIST_CSF.Description } },
        @{N = 'Object'; E = { $_.Object } },
        @{N = 'Remediation'; E = { $_.Remediation } }

        $nistExport | Export-Excel -Path $OutputPath -WorksheetName 'Compliance - NIST CSF' -AutoSize -BoldTopRow -FreezeTopRow -AutoFilter
    }

    # SOC 2
    $soc2Findings = $Findings | Where-Object { $_.ComplianceMappings.SOC2 }
    if ($soc2Findings.Count -gt 0) {
        $soc2Export = $soc2Findings | Select-Object `
        @{N = 'Description'; E = { $_.Description } },
        @{N = 'Risk Level'; E = { $_.RiskLevel } },
        @{N = 'Risk Score'; E = { $_.RiskScore } },
        @{N = 'SOC 2 Criteria'; E = { ($_.ComplianceMappings.SOC2.Criteria -join ', ') } },
        @{N = 'Criteria Description'; E = { $_.ComplianceMappings.SOC2.Description } },
        @{N = 'Object'; E = { $_.Object } },
        @{N = 'Remediation'; E = { $_.Remediation } }

        $soc2Export | Export-Excel -Path $OutputPath -WorksheetName 'Compliance - SOC2' -AutoSize -BoldTopRow -FreezeTopRow -AutoFilter
    }

    # PCI-DSS
    $pciFindings = $Findings | Where-Object { $_.ComplianceMappings.PCI_DSS_4 }
    if ($pciFindings.Count -gt 0) {
        $pciExport = $pciFindings | Select-Object `
        @{N = 'Description'; E = { $_.Description } },
        @{N = 'Risk Level'; E = { $_.RiskLevel } },
        @{N = 'Risk Score'; E = { $_.RiskScore } },
        @{N = 'PCI-DSS Requirements'; E = { ($_.ComplianceMappings.PCI_DSS_4.Requirements -join ', ') } },
        @{N = 'Requirement Description'; E = { $_.ComplianceMappings.PCI_DSS_4.Description } },
        @{N = 'Object'; E = { $_.Object } },
        @{N = 'Remediation'; E = { $_.Remediation } }

        $pciExport | Export-Excel -Path $OutputPath -WorksheetName 'Compliance - PCI-DSS' -AutoSize -BoldTopRow -FreezeTopRow -AutoFilter
    }

    # 9. Risk Analysis Sheet
    Write-Verbose "Creating Risk Analysis sheet..."
    $riskAnalysis = @(
        [PSCustomObject]@{Category = 'Risk Distribution'; Metric = 'Critical'; Count = $riskSummary.CriticalCount; Percentage = "$($riskSummary.CriticalPercent)%" }
        [PSCustomObject]@{Category = 'Risk Distribution'; Metric = 'High'; Count = $riskSummary.HighCount; Percentage = "$($riskSummary.HighPercent)%" }
        [PSCustomObject]@{Category = 'Risk Distribution'; Metric = 'Medium'; Count = $riskSummary.MediumCount; Percentage = "$($riskSummary.MediumPercent)%" }
        [PSCustomObject]@{Category = 'Risk Distribution'; Metric = 'Low'; Count = $riskSummary.LowCount; Percentage = "$($riskSummary.LowPercent)%" }
        [PSCustomObject]@{Category = ''; Metric = ''; Count = ''; Percentage = '' }
        [PSCustomObject]@{Category = 'Risk Scores'; Metric = 'Average'; Count = $riskSummary.AverageRiskScore; Percentage = 'Out of 100' }
        [PSCustomObject]@{Category = 'Risk Scores'; Metric = 'Maximum'; Count = $riskSummary.MaxRiskScore; Percentage = 'Out of 100' }
        [PSCustomObject]@{Category = 'Risk Scores'; Metric = 'Minimum'; Count = $riskSummary.MinRiskScore; Percentage = 'Out of 100' }
        [PSCustomObject]@{Category = ''; Metric = ''; Count = ''; Percentage = '' }
        [PSCustomObject]@{Category = 'Remediation Effort'; Metric = 'Quick Wins'; Count = $riskSummary.QuickWinsCount; Percentage = 'High impact, low effort' }
        [PSCustomObject]@{Category = 'Remediation Effort'; Metric = 'Complex'; Count = $riskSummary.ComplexCount; Percentage = 'High effort required' }
        [PSCustomObject]@{Category = 'Remediation Effort'; Metric = 'Top Priority'; Count = $riskSummary.TopPriorityCount; Percentage = 'Priority score >= 20' }
    )

    $riskAnalysis | Export-Excel -Path $OutputPath -WorksheetName 'Risk Analysis' -AutoSize -BoldTopRow -FreezeTopRow

    # 10. Secure Score (only if data was supplied)
    if ($SecureScore) {
        Write-Verbose "Creating Secure Score sheet..."
        # @() guard prevents the single-element-array unwrap that would make .Count $null.
        $ssRows = @(ConvertTo-SecureScoreRows -SecureScore $SecureScore)
        if ($ssRows.Count -gt 0) {
            $ssRows | Export-Excel -Path $OutputPath -WorksheetName 'Secure Score' -AutoSize -BoldTopRow -FreezeTopRow -AutoFilter
        }
    }

    # 11. Azure Policy (only if data was supplied)
    if ($AzurePolicy) {
        Write-Verbose "Creating Azure Policy sheet..."
        $apRows = @(ConvertTo-AzurePolicyRows -AzurePolicy $AzurePolicy)
        if ($apRows.Count -gt 0) {
            $apRows | Export-Excel -Path $OutputPath -WorksheetName 'Azure Policy' -AutoSize -BoldTopRow -FreezeTopRow -AutoFilter
        }
    }

    # 12. Purview Compliance (only if data was supplied)
    if ($PurviewCompliance) {
        Write-Verbose "Creating Purview sheet..."
        $pvRows = @(ConvertTo-PurviewRows -PurviewCompliance $PurviewCompliance)
        if ($pvRows.Count -gt 0) {
            $pvRows | Export-Excel -Path $OutputPath -WorksheetName 'Purview' -AutoSize -BoldTopRow -FreezeTopRow -AutoFilter
        }
    }

    Write-Host "[OK] Excel workbook created: $OutputPath" -ForegroundColor Green
}

function ConvertTo-SecureScoreRows {
    <#
    .SYNOPSIS
        Flattens a Get-SecureScore hashtable into row objects suitable for
        Excel / CSV export. If .ImprovementActions was attached by the caller,
        each action becomes a row; otherwise the per-control scores are used.
    #>
    param([Parameter(Mandatory)] [object]$SecureScore)

    $rows = @()
    if ($null -ne $SecureScore.ImprovementActions) {
        foreach ($a in $SecureScore.ImprovementActions) {
            $rows += [PSCustomObject]@{
                Title = $a.Title
                ControlName = $a.ControlName
                Category = $a.Category
                Service = $a.Service
                CurrentScore = $a.CurrentScore
                MaxScore = $a.MaxScore
                PotentialImprovement = $a.PotentialImprovement
                ImplementationStatus = $a.ImplementationStatus
                ImplementationCost = $a.ImplementationCost
                UserImpact = $a.UserImpact
                PriorityScore = $a.PriorityScore
                Threats = $a.Threats
                ActionUrl = $a.ActionUrl
            }
        }
        return $rows
    }
    if ($SecureScore.ControlScores) {
        foreach ($c in $SecureScore.ControlScores) {
            $rows += [PSCustomObject]@{
                ControlName = $c.ControlName
                Category = $c.ControlCategory
                Score = $c.Score
                MaxScore = $c.MaxScore
                ScorePercent = $c.ScorePercent
                Description = $c.Description
                ImplementationStatus = $c.ImplementationStatus
            }
        }
    }
    return $rows
}

function ConvertTo-AzurePolicyRows {
    <#
    .SYNOPSIS
        Flattens an Azure Policy assessment into one row per (subscription, policy)
        pair, with compliance summary fields.
    #>
    param([Parameter(Mandatory)] [object]$AzurePolicy)

    $rows = @()
    foreach ($sub in $AzurePolicy.Subscriptions) {
        $cs = $sub.ComplianceSummary
        $row = [PSCustomObject]@{
            Subscription = $sub.SubscriptionName
            SubscriptionId = $sub.SubscriptionId
            Assignments = if ($sub.Assignments) { @($sub.Assignments).Count } else { 0 }
            CompliantPolicies = if ($cs) { $cs.CompliantPolicies } else { 0 }
            NonCompliantPolicies = if ($cs) { $cs.NonCompliantPolicies } else { 0 }
            CompliantResources = if ($cs) { $cs.CompliantResources } else { 0 }
            NonCompliantResources = if ($cs) { $cs.NonCompliantResources } else { 0 }
        }
        $rows += $row
    }
    return $rows
}

function ConvertTo-PurviewRows {
    <#
    .SYNOPSIS
        Flattens Purview Compliance Manager controls (assessments + DLP/labels/retention)
        into a single per-control row schema.
    #>
    param([Parameter(Mandatory)] [object]$PurviewCompliance)

    $rows = @()
    if ($PurviewCompliance.Controls) {
        foreach ($c in $PurviewCompliance.Controls) {
            $rows += [PSCustomObject]@{
                Framework = $c.Framework
                ControlId = $c.ControlId
                ControlTitle = $c.ControlTitle
                Status = $c.Status
                Severity = $c.Severity
                Score = $c.Score
                MaxScore = $c.MaxScore
                CompliancePercent = $c.CompliancePercent
                Description = $c.Description
                Remediation = $c.Remediation
            }
        }
    }
    return $rows
}

function New-CSVWorkbook {
    <#
    .SYNOPSIS
        CSV fallback for environments without the ImportExcel module.

    .DESCRIPTION
        Mirrors the 9-sheet (now 12-sheet when the new optional inputs are
        provided) structure of New-ExcelWorkbook, one CSV per sheet, in a
        sibling directory next to the would-be .xlsx. Each CSV carries the
        same columns as its Excel counterpart so users can re-combine them via
        Excel's "Get Data > From Folder".
    #>
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [object]$TenantInfo,

        [object]$SecureScore,

        [object]$AzurePolicy,

        [object]$PurviewCompliance
    )

    # Create directory for CSV files
    $baseDir = Split-Path $OutputPath -Parent
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
    $csvDir = Join-Path $baseDir "$baseName-CSV"

    if (-not (Test-Path $csvDir)) {
        New-Item -Path $csvDir -ItemType Directory | Out-Null
    }

    Write-Host "[INFO] ImportExcel module not available. Exporting to CSV files in: $csvDir" -ForegroundColor Yellow

    # Calculate summaries
    $riskSummary = Get-RiskSummary -Findings $Findings
    $complianceGap = Get-ComplianceGapReport -Findings $Findings -Framework 'All'
    $quickWins = Get-QuickWins -Findings $Findings
    $prioritized = Get-PrioritizedFindings -Findings $Findings

    # 1. Executive Summary
    $execData = @(
        [PSCustomObject]@{Metric = 'Tenant Name'; Value = $TenantInfo.TenantName; Details = $TenantInfo.TenantId }
        [PSCustomObject]@{Metric = 'Report Generated'; Value = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Details = '' }
        [PSCustomObject]@{Metric = 'Total Findings'; Value = $Findings.Count; Details = '' }
        [PSCustomObject]@{Metric = 'RISK ANALYSIS'; Value = ''; Details = '' }
        [PSCustomObject]@{Metric = 'Critical Risk Findings'; Value = $riskSummary.CriticalCount; Details = "$($riskSummary.CriticalPercent)%" }
        [PSCustomObject]@{Metric = 'High Risk Findings'; Value = $riskSummary.HighCount; Details = "$($riskSummary.HighPercent)%" }
        [PSCustomObject]@{Metric = 'Medium Risk Findings'; Value = $riskSummary.MediumCount; Details = "$($riskSummary.MediumPercent)%" }
        [PSCustomObject]@{Metric = 'Low Risk Findings'; Value = $riskSummary.LowCount; Details = "$($riskSummary.LowPercent)%" }
        [PSCustomObject]@{Metric = 'Average Risk Score'; Value = $riskSummary.AverageRiskScore; Details = 'Out of 100' }
        [PSCustomObject]@{Metric = 'Max Risk Score'; Value = $riskSummary.MaxRiskScore; Details = 'Out of 100' }
        [PSCustomObject]@{Metric = 'Quick Wins Available'; Value = $riskSummary.QuickWinsCount; Details = 'High impact, low effort' }
        [PSCustomObject]@{Metric = 'COMPLIANCE IMPACT'; Value = ''; Details = '' }
        [PSCustomObject]@{Metric = 'CIS M365 Controls'; Value = $complianceGap.FrameworkGaps.CIS.ControlsAffected; Details = 'Controls with findings' }
        [PSCustomObject]@{Metric = 'NIST CSF Functions'; Value = $complianceGap.FrameworkGaps.NIST.ControlsAffected; Details = 'Functions with findings' }
        [PSCustomObject]@{Metric = 'SOC 2 Criteria'; Value = $complianceGap.FrameworkGaps.SOC2.ControlsAffected; Details = 'Criteria with findings' }
        [PSCustomObject]@{Metric = 'PCI-DSS Requirements'; Value = $complianceGap.FrameworkGaps.PCIDSS.ControlsAffected; Details = 'Requirements with findings' }
    )
    $execData | Export-Csv -LiteralPath (Join-Path $csvDir '01-ExecutiveSummary.csv') -NoTypeInformation -Encoding UTF8

    # 2. All Findings
    $allFindingsExport = $Findings | Select-Object `
    @{N = 'Time'; E = { $_.Time } },
    @{N = 'Status'; E = { $_.Status } },
    @{N = 'Object'; E = { $_.Object } },
    @{N = 'Description'; E = { $_.Description } },
    @{N = 'Remediation'; E = { $_.Remediation } },
    @{N = 'Risk Level'; E = { $_.RiskLevel } },
    @{N = 'Risk Score'; E = { $_.RiskScore } },
    @{N = 'Priority Score'; E = { $_.PriorityScore } },
    @{N = 'Remediation Effort'; E = { $_.RemediationEffortDescription } },
    @{N = 'Compliance Frameworks'; E = { $_.ComplianceReference } }
    $allFindingsExport | Export-Csv -LiteralPath (Join-Path $csvDir '02-AllFindings.csv') -NoTypeInformation -Encoding UTF8

    # 3. Priority Findings (top 25)
    $rank = [ref]0
    $priorityExport = $prioritized | Select-Object -First 25 | Select-Object `
    @{N = 'Rank'; E = { $rank.Value++; $rank.Value } },
    @{N = 'Description'; E = { $_.Description } },
    @{N = 'Risk Level'; E = { $_.RiskLevel } },
    @{N = 'Risk Score'; E = { $_.RiskScore } },
    @{N = 'Effort'; E = { $_.RemediationEffortDescription } },
    @{N = 'Priority Score'; E = { $_.PriorityScore } },
    @{N = 'Compliance'; E = { $_.ComplianceReference } },
    @{N = 'Remediation'; E = { $_.Remediation } }
    $priorityExport | Export-Csv -LiteralPath (Join-Path $csvDir '03-PriorityFindings.csv') -NoTypeInformation -Encoding UTF8

    # 4. Quick Wins
    if ($quickWins.Count -gt 0) {
        $quickWinsExport = $quickWins | Select-Object `
        @{N = 'Description'; E = { $_.Description } },
        @{N = 'Risk Level'; E = { $_.RiskLevel } },
        @{N = 'Risk Score'; E = { $_.RiskScore } },
        @{N = 'Effort'; E = { $_.RemediationEffortDescription } },
        @{N = 'Priority Score'; E = { $_.PriorityScore } },
        @{N = 'Object'; E = { $_.Object } },
        @{N = 'Remediation'; E = { $_.Remediation } }
        $quickWinsExport | Export-Csv -LiteralPath (Join-Path $csvDir '04-QuickWins.csv') -NoTypeInformation -Encoding UTF8
    }

    # 5. CIS M365
    $cisFindings = $Findings | Where-Object { $_.ComplianceMappings.CIS_M365 }
    if ($cisFindings.Count -gt 0) {
        $cisExport = $cisFindings | Select-Object `
        @{N = 'Description'; E = { $_.Description } },
        @{N = 'Risk Level'; E = { $_.RiskLevel } },
        @{N = 'Risk Score'; E = { $_.RiskScore } },
        @{N = 'CIS Controls'; E = { ($_.ComplianceMappings.CIS_M365.Controls -join ', ') } },
        @{N = 'Control Title'; E = { $_.ComplianceMappings.CIS_M365.Title } },
        @{N = 'Object'; E = { $_.Object } },
        @{N = 'Remediation'; E = { $_.Remediation } }
        $cisExport | Export-Csv -LiteralPath (Join-Path $csvDir '05-Compliance-CIS-M365.csv') -NoTypeInformation -Encoding UTF8
    }

    # 6. NIST CSF
    $nistFindings = $Findings | Where-Object { $_.ComplianceMappings.NIST_CSF }
    if ($nistFindings.Count -gt 0) {
        $nistExport = $nistFindings | Select-Object `
        @{N = 'Description'; E = { $_.Description } },
        @{N = 'Risk Level'; E = { $_.RiskLevel } },
        @{N = 'Risk Score'; E = { $_.RiskScore } },
        @{N = 'NIST Functions'; E = { ($_.ComplianceMappings.NIST_CSF.Functions -join ', ') } },
        @{N = 'Function Description'; E = { $_.ComplianceMappings.NIST_CSF.Description } },
        @{N = 'Object'; E = { $_.Object } },
        @{N = 'Remediation'; E = { $_.Remediation } }
        $nistExport | Export-Csv -LiteralPath (Join-Path $csvDir '06-Compliance-NIST-CSF.csv') -NoTypeInformation -Encoding UTF8
    }

    # 7. SOC 2
    $soc2Findings = $Findings | Where-Object { $_.ComplianceMappings.SOC2 }
    if ($soc2Findings.Count -gt 0) {
        $soc2Export = $soc2Findings | Select-Object `
        @{N = 'Description'; E = { $_.Description } },
        @{N = 'Risk Level'; E = { $_.RiskLevel } },
        @{N = 'Risk Score'; E = { $_.RiskScore } },
        @{N = 'SOC 2 Criteria'; E = { ($_.ComplianceMappings.SOC2.Criteria -join ', ') } },
        @{N = 'Criteria Description'; E = { $_.ComplianceMappings.SOC2.Description } },
        @{N = 'Object'; E = { $_.Object } },
        @{N = 'Remediation'; E = { $_.Remediation } }
        $soc2Export | Export-Csv -LiteralPath (Join-Path $csvDir '07-Compliance-SOC2.csv') -NoTypeInformation -Encoding UTF8
    }

    # 8. PCI-DSS
    $pciFindings = $Findings | Where-Object { $_.ComplianceMappings.PCI_DSS_4 }
    if ($pciFindings.Count -gt 0) {
        $pciExport = $pciFindings | Select-Object `
        @{N = 'Description'; E = { $_.Description } },
        @{N = 'Risk Level'; E = { $_.RiskLevel } },
        @{N = 'Risk Score'; E = { $_.RiskScore } },
        @{N = 'PCI-DSS Requirements'; E = { ($_.ComplianceMappings.PCI_DSS_4.Requirements -join ', ') } },
        @{N = 'Requirement Description'; E = { $_.ComplianceMappings.PCI_DSS_4.Description } },
        @{N = 'Object'; E = { $_.Object } },
        @{N = 'Remediation'; E = { $_.Remediation } }
        $pciExport | Export-Csv -LiteralPath (Join-Path $csvDir '08-Compliance-PCI-DSS.csv') -NoTypeInformation -Encoding UTF8
    }

    # 9. Risk Analysis
    $riskAnalysis = @(
        [PSCustomObject]@{Category = 'Risk Distribution'; Metric = 'Critical'; Count = $riskSummary.CriticalCount; Percentage = "$($riskSummary.CriticalPercent)%" }
        [PSCustomObject]@{Category = 'Risk Distribution'; Metric = 'High'; Count = $riskSummary.HighCount; Percentage = "$($riskSummary.HighPercent)%" }
        [PSCustomObject]@{Category = 'Risk Distribution'; Metric = 'Medium'; Count = $riskSummary.MediumCount; Percentage = "$($riskSummary.MediumPercent)%" }
        [PSCustomObject]@{Category = 'Risk Distribution'; Metric = 'Low'; Count = $riskSummary.LowCount; Percentage = "$($riskSummary.LowPercent)%" }
        [PSCustomObject]@{Category = 'Risk Scores'; Metric = 'Average'; Count = $riskSummary.AverageRiskScore; Percentage = 'Out of 100' }
        [PSCustomObject]@{Category = 'Risk Scores'; Metric = 'Maximum'; Count = $riskSummary.MaxRiskScore; Percentage = 'Out of 100' }
        [PSCustomObject]@{Category = 'Risk Scores'; Metric = 'Minimum'; Count = $riskSummary.MinRiskScore; Percentage = 'Out of 100' }
        [PSCustomObject]@{Category = 'Remediation Effort'; Metric = 'Quick Wins'; Count = $riskSummary.QuickWinsCount; Percentage = 'High impact, low effort' }
        [PSCustomObject]@{Category = 'Remediation Effort'; Metric = 'Complex'; Count = $riskSummary.ComplexCount; Percentage = 'High effort required' }
        [PSCustomObject]@{Category = 'Remediation Effort'; Metric = 'Top Priority'; Count = $riskSummary.TopPriorityCount; Percentage = 'Priority score >= 20' }
    )
    $riskAnalysis | Export-Csv -LiteralPath (Join-Path $csvDir '09-RiskAnalysis.csv') -NoTypeInformation -Encoding UTF8

    # 10-12. Optional dead-data sheets (skipped silently if not provided)
    if ($SecureScore) {
        $ssRows = @(ConvertTo-SecureScoreRows -SecureScore $SecureScore)
        if ($ssRows.Count -gt 0) {
            $ssRows | Export-Csv -LiteralPath (Join-Path $csvDir '10-SecureScore.csv') -NoTypeInformation -Encoding UTF8
        }
    }
    if ($AzurePolicy) {
        $apRows = @(ConvertTo-AzurePolicyRows -AzurePolicy $AzurePolicy)
        if ($apRows.Count -gt 0) {
            $apRows | Export-Csv -LiteralPath (Join-Path $csvDir '11-AzurePolicy.csv') -NoTypeInformation -Encoding UTF8
        }
    }
    if ($PurviewCompliance) {
        $pvRows = @(ConvertTo-PurviewRows -PurviewCompliance $PurviewCompliance)
        if ($pvRows.Count -gt 0) {
            $pvRows | Export-Csv -LiteralPath (Join-Path $csvDir '12-Purview.csv') -NoTypeInformation -Encoding UTF8
        }
    }

    Write-Host "[OK] CSV files created in: $csvDir" -ForegroundColor Green
    Write-Host "[INFO] To create Excel workbook: Open any CSV file, then use Excel's 'Get Data > From Folder' to combine all sheets" -ForegroundColor Cyan
}

#endregion

#region Export Module Members

Export-ModuleMember -Function @(
    'New-EnhancedExcelReport'
)

#endregion
