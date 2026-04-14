<#
.SYNOPSIS
    Generates comprehensive compliance assessment reports with meaningful insights.

.DESCRIPTION
    Master reporting function that orchestrates all EntraChecks reporting capabilities:
    - Executive summary dashboard with key metrics
    - Framework-specific compliance (CIS, NIST, ISO 27001, SOC 2, PCI-DSS)
    - Risk scoring and prioritization
    - Detailed findings with remediation guidance and best practices
    - Integration with external data sources (Secure Score, Defender, Azure Policy, Purview)
    - Visualizations and trend analysis
    - Delta reporting (comparison with previous assessments)
    - Excel workbooks with multiple worksheets
    - Automated remediation script generation
    - Executive summary PDF

.PARAMETER Findings
    Array of findings from Core EntraChecks assessment.

.PARAMETER OutputDirectory
    Directory for generated reports.

.PARAMETER TenantName
    Name of the tenant being assessed.

.PARAMETER IncludeExternalSources
    Include data from external sources (Secure Score, Defender, etc.) if available.

.PARAMETER Frameworks
    Specific frameworks to include in the report. Default: All available.
    Options: CIS, NIST, SOC2, PCI, ISO27001, All

.PARAMETER SaveSnapshot
    Save current assessment as a snapshot for future delta comparison.

.PARAMETER CompareWithSnapshot
    Path to previous snapshot for delta/trend analysis.

.PARAMETER GenerateExcelReport
    Generate multi-sheet Excel workbook (requires ImportExcel module).

.PARAMETER GenerateRemediationScripts
    Generate automated PowerShell remediation scripts for findings.

.PARAMETER GenerateExecutivePDF
    Generate one-page executive summary PDF (requires wkhtmltopdf or similar).

.EXAMPLE
    .\New-ComprehensiveAssessmentReport.ps1 -Findings $script:Findings -OutputDirectory ".\Output" -TenantName "Contoso" -SaveSnapshot -GenerateExcelReport

.EXAMPLE
    .\New-ComprehensiveAssessmentReport.ps1 -Findings $script:Findings -OutputDirectory ".\Output" -TenantName "Contoso" -CompareWithSnapshot ".\Output\Snapshot-20260201-120000.json"

.NOTES
    Version: 2.0.0
    Author: David Stells
    Requires: EntraChecks modules (ComplianceMapping, RiskScoring, HTMLReporting, DeltaReporting, ExcelReporting, RemediationGuidance)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [array]$Findings,

    [Parameter()]
    [string]$OutputDirectory = ".\Reports",

    [Parameter()]
    [string]$TenantName = "Unknown Tenant",

    [switch]$IncludeExternalSources,

    [Parameter()]
    [ValidateSet("CIS", "NIST", "SOC2", "PCI", "ISO27001", "All")]
    [string[]]$Frameworks = @("All"),

    [switch]$SaveSnapshot,

    [Parameter()]
    [string]$CompareWithSnapshot,

    [switch]$GenerateExcelReport,

    [switch]$GenerateRemediationScripts,

    [switch]$GenerateExecutivePDF,

    [Parameter()]
    [hashtable]$ExternalData
)

#region Module Imports

# Modules are in the project root's Modules folder (this script is in Scripts/)
$script:ProjectRoot = Split-Path $PSScriptRoot -Parent
$script:ModulesPath = Join-Path $script:ProjectRoot "Modules"

# Import required modules
$requiredModules = @(
    "EntraChecks-ComplianceMapping.psm1",
    "EntraChecks-RiskScoring.psm1",
    "EntraChecks-HTMLReporting.psm1",
    "EntraChecks-RemediationGuidance.psm1"
)

# Import optional modules for enhanced features
$optionalModules = @(
    "EntraChecks-RemediationGuidance-Extended.psm1",
    "EntraChecks-DeltaReporting.psm1",
    "EntraChecks-ExcelReporting.psm1"
)

foreach ($module in $requiredModules) {
    $modulePath = Join-Path $script:ModulesPath $module
    if (Test-Path $modulePath) {
        try {
            Import-Module $modulePath -Force -Global -DisableNameChecking -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to import required module $module : $($_.Exception.Message)"
        }
    }
    else {
        Write-Warning "Module not found: $module - Some features may be unavailable"
    }
}

foreach ($module in $optionalModules) {
    $modulePath = Join-Path $script:ModulesPath $module
    if (Test-Path $modulePath) {
        try {
            Import-Module $modulePath -Force -Global -DisableNameChecking -ErrorAction Stop
            Write-Verbose "Loaded optional module: $module"
        }
        catch {
            Write-Verbose "Optional module $module not loaded: $($_.Exception.Message)"
        }
    }
}

#endregion

#region Data Preparation

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Comprehensive Assessment Report" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Ensure output directory exists
if (-not (Test-Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$assessmentDate = Get-Date -Format "MMMM dd, yyyy HH:mm"

Write-Host "[1/6] Analyzing findings..." -ForegroundColor Cyan
Write-Host "    Total findings: $($Findings.Count)" -ForegroundColor Gray

# Categorize findings by status
$findingsByStatus = $Findings | Group-Object Status
$failCount = ($findingsByStatus | Where-Object { $_.Name -eq 'FAIL' }).Count
$warnCount = ($findingsByStatus | Where-Object { $_.Name -eq 'WARNING' }).Count
$okCount = ($findingsByStatus | Where-Object { $_.Name -eq 'OK' }).Count
$infoCount = ($findingsByStatus | Where-Object { $_.Name -eq 'INFO' }).Count

Write-Host "    FAIL: $failCount | WARNING: $warnCount | OK: $okCount | INFO: $infoCount" -ForegroundColor Gray

#endregion

#region Risk Scoring

Write-Host "`n[2/6] Calculating risk scores..." -ForegroundColor Cyan

# Verify risk scoring functions are available
$hasRiskScoring = $null -ne (Get-Command Measure-RiskScore -ErrorAction SilentlyContinue)
if (-not $hasRiskScoring) {
    Write-Warning "Measure-RiskScore function not available. Attempting manual module import..."
    $riskModule = Join-Path $script:ModulesPath "EntraChecks-RiskScoring.psm1"
    if (Test-Path $riskModule) {
        Import-Module $riskModule -Force -Global -DisableNameChecking -ErrorAction SilentlyContinue
        $hasRiskScoring = $null -ne (Get-Command Measure-RiskScore -ErrorAction SilentlyContinue)
    }
}

$findingsWithRisk = @()
foreach ($finding in $Findings) {
    # Calculate risk score for each finding
    if ($hasRiskScoring) {
        $riskScore = Measure-RiskScore -Finding $finding
        $riskLevel = Get-RiskLevel -RiskScore $riskScore
    }
    else {
        # Fallback: assign risk based on Status
        $riskScore = switch ($finding.Status) {
            'FAIL' { 70 }
            'WARNING' { 40 }
            'INFO' { 10 }
            default { 0 }
        }
        $riskLevel = switch ($finding.Status) {
            'FAIL' { 'High' }
            'WARNING' { 'Medium' }
            'INFO' { 'Low' }
            default { 'Info' }
        }
    }

    # Add/overwrite risk properties on finding object
    $finding | Add-Member -NotePropertyName RiskScore -NotePropertyValue $riskScore -Force
    $finding | Add-Member -NotePropertyName RiskLevel -NotePropertyValue $riskLevel -Force

    $findingsWithRisk += $finding
}

# Deduplicate findings by Description + Object (same logic as HTMLReporting)
$seen = @{}
$dedupedFindings = @()
foreach ($f in $findingsWithRisk) {
    $key = "$($f.Description)|$($f.Object)"
    if (-not $seen.ContainsKey($key)) {
        $seen[$key] = $true
        $dedupedFindings += $f
    }
}

$duplicateCount = $findingsWithRisk.Count - $dedupedFindings.Count
if ($duplicateCount -gt 0) {
    Write-Host "    Deduplicated: removed $duplicateCount duplicate findings" -ForegroundColor Yellow
}
$findingsWithRisk = $dedupedFindings

# Recompute status counts after deduplication
$findingsByStatus = $findingsWithRisk | Group-Object Status
$failCount = @($findingsByStatus | Where-Object { $_.Name -eq 'FAIL' }).Count
$warnCount = @($findingsByStatus | Where-Object { $_.Name -eq 'WARNING' }).Count
$okCount = @($findingsByStatus | Where-Object { $_.Name -eq 'OK' }).Count
$infoCount = @($findingsByStatus | Where-Object { $_.Name -eq 'INFO' }).Count

# Get prioritized findings
if ($hasRiskScoring) {
    $prioritizedFindings = Get-PrioritizedFindings -Findings $findingsWithRisk
    $quickWins = Get-QuickWins -Findings $findingsWithRisk
    $riskSummary = Get-RiskSummary -Findings $findingsWithRisk
}
else {
    # Fallback: sort by risk score descending
    $prioritizedFindings = $findingsWithRisk | Sort-Object RiskScore -Descending
    $quickWins = @($findingsWithRisk | Where-Object { $_.Status -eq 'FAIL' } | Select-Object -First 5)
    $critCount = @($findingsWithRisk | Where-Object { $_.RiskScore -ge 80 }).Count
    $highCount = @($findingsWithRisk | Where-Object { $_.RiskScore -ge 60 -and $_.RiskScore -lt 80 }).Count
    $medCount = @($findingsWithRisk | Where-Object { $_.RiskScore -ge 40 -and $_.RiskScore -lt 60 }).Count
    $lowCount = @($findingsWithRisk | Where-Object { $_.RiskScore -lt 40 }).Count
    $avgScore = if ($findingsWithRisk.Count -gt 0) { ($findingsWithRisk | Measure-Object RiskScore -Average).Average } else { 0 }
    $riskSummary = New-Object PSObject
    $riskSummary | Add-Member -NotePropertyName CriticalCount -NotePropertyValue $critCount
    $riskSummary | Add-Member -NotePropertyName HighCount -NotePropertyValue $highCount
    $riskSummary | Add-Member -NotePropertyName MediumCount -NotePropertyValue $medCount
    $riskSummary | Add-Member -NotePropertyName LowCount -NotePropertyValue $lowCount
    $riskSummary | Add-Member -NotePropertyName OverallScore -NotePropertyValue $avgScore
}

Write-Host "    Critical: $($riskSummary.CriticalCount) | High: $($riskSummary.HighCount) | Medium: $($riskSummary.MediumCount) | Low: $($riskSummary.LowCount)" -ForegroundColor $(
    if ($riskSummary.CriticalCount -gt 0) { "Red" }
    elseif ($riskSummary.HighCount -gt 0) { "Yellow" }
    else { "Green" }
)
Write-Host "    Quick wins identified: $($quickWins.Count)" -ForegroundColor Green

#endregion

#region Compliance Mapping

Write-Host "`n[3/6] Mapping findings to compliance frameworks..." -ForegroundColor Cyan

# Determine which frameworks to include
$selectedFrameworks = if ($Frameworks -contains "All") {
    @("CIS", "NIST", "SOC2", "PCI")
}
else {
    $Frameworks
}

$complianceMappings = @{}
$complianceGaps = @{}
$hasComplianceMapping = $null -ne (Get-Command Get-AllComplianceMappings -ErrorAction SilentlyContinue)
if ($hasComplianceMapping) {
    foreach ($framework in $selectedFrameworks) {
        try {
            $mappings = Get-AllComplianceMappings -Framework $framework
            if ($mappings) {
                $complianceMappings[$framework] = $mappings
                Write-Host "    $framework`: $($mappings.Count) controls mapped" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "    [!] Error mapping $framework`: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Generate compliance gap reports
    foreach ($framework in $selectedFrameworks) {
        try {
            $gaps = Get-ComplianceGapReport -Framework $framework -Findings $findingsWithRisk
            if ($gaps) {
                $complianceGaps[$framework] = $gaps
            }
        }
        catch {
            Write-Host "    [!] Error generating $framework gap report: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host "    [!] Compliance mapping module not available - skipping framework mapping" -ForegroundColor Yellow
}

#endregion

#region External Data Sources

Write-Host "`n[4/6] Gathering external data sources..." -ForegroundColor Cyan

$externalData = @{
    SecureScore = $null
    DefenderCompliance = $null
    AzurePolicy = $null
    PurviewCompliance = $null
}

# Use ExternalData parameter if provided (called from Start-EntraChecks),
# otherwise fall back to script-scoped variables (standalone use)
if ($ExternalData) {
    if ($ExternalData.SecureScore) {
        $externalData.SecureScore = $ExternalData.SecureScore
        Write-Host "    Secure Score: Available" -ForegroundColor Green
    }
    else {
        Write-Host "    Secure Score: Not available" -ForegroundColor Yellow
    }

    if ($ExternalData.DefenderCompliance) {
        $externalData.DefenderCompliance = $ExternalData.DefenderCompliance
        Write-Host "    Defender: Available" -ForegroundColor Green
    }
    else {
        Write-Host "    Defender: Not available" -ForegroundColor Yellow
    }

    if ($ExternalData.AzurePolicy) {
        $externalData.AzurePolicy = $ExternalData.AzurePolicy
        Write-Host "    Azure Policy: Available" -ForegroundColor Green
    }
    else {
        Write-Host "    Azure Policy: Not available" -ForegroundColor Yellow
    }

    if ($ExternalData.PurviewCompliance) {
        $externalData.PurviewCompliance = $ExternalData.PurviewCompliance
        Write-Host "    Purview: Available" -ForegroundColor Green
    }
    else {
        Write-Host "    Purview: Not available" -ForegroundColor Yellow
    }
}
elseif ($IncludeExternalSources) {
    # Standalone mode: use script-scoped variables
    if ($script:SecureScoreData) {
        $externalData.SecureScore = $script:SecureScoreData
        Write-Host "    Secure Score: $($script:SecureScoreData.ScorePercent)%" -ForegroundColor Green
    }
    else {
        Write-Host "    Secure Score: Not available" -ForegroundColor Yellow
    }

    if ($script:DefenderComplianceData) {
        $externalData.DefenderCompliance = $script:DefenderComplianceData
        Write-Host "    Defender: $($script:DefenderComplianceData.Summary.TotalStandards) standards" -ForegroundColor Green
    }
    else {
        Write-Host "    Defender: Not available" -ForegroundColor Yellow
    }

    if ($script:AzurePolicyData) {
        $externalData.AzurePolicy = $script:AzurePolicyData
        Write-Host "    Azure Policy: $($script:AzurePolicyData.Summary.TotalPolicies) policies" -ForegroundColor Green
    }
    else {
        Write-Host "    Azure Policy: Not available" -ForegroundColor Yellow
    }

    if ($script:PurviewComplianceData) {
        $externalData.PurviewCompliance = $script:PurviewComplianceData
        Write-Host "    Purview: $($script:PurviewComplianceData.Summary.TotalAssessments) assessments" -ForegroundColor Green
    }
    else {
        Write-Host "    Purview: Not available" -ForegroundColor Yellow
    }
}
else {
    Write-Host "    External sources not requested (use -IncludeExternalSources or -ExternalData)" -ForegroundColor Gray
}

#endregion

#region Snapshot Management and Delta Reporting

$deltaData = $null
$snapshotPath = $null

if ($SaveSnapshot -or $CompareWithSnapshot) {
    Write-Host "`n[+] Snapshot Management..." -ForegroundColor Cyan

    # Save current assessment as snapshot
    if ($SaveSnapshot) {
        if (Get-Command Save-ComplianceSnapshot -ErrorAction SilentlyContinue) {
            $snapshotPath = Save-ComplianceSnapshot `
                -OutputDirectory $OutputDirectory `
                -TenantName $TenantName `
                -Findings $Findings `
                -SecureScoreData $script:SecureScoreData `
                -DefenderComplianceData $script:DefenderComplianceData `
                -AzurePolicyData $script:AzurePolicyData `
                -PurviewComplianceData $script:PurviewComplianceData

            Write-Host "    [OK] Snapshot saved: $snapshotPath" -ForegroundColor Green
        }
        else {
            Write-Host "    [!] DeltaReporting module not available - snapshot not saved" -ForegroundColor Yellow
        }
    }

    # Compare with previous snapshot
    if ($CompareWithSnapshot) {
        if (Get-Command Compare-ComplianceSnapshots -ErrorAction SilentlyContinue) {
            if (Test-Path $CompareWithSnapshot) {
                Write-Host "    Loading baseline snapshot..." -ForegroundColor Gray
                $baselineSnapshot = Import-ComplianceSnapshot -SnapshotPath $CompareWithSnapshot

                if ($baselineSnapshot) {
                    # Create current snapshot for comparison
                    $currentSnapshotData = @{
                        SnapshotId = "Current-$timestamp"
                        TenantName = $TenantName
                        CreatedAt = $assessmentDate
                        Sources = @{
                            Findings = @{
                                Available = $true
                                Data = $Findings
                            }
                            SecureScore = @{
                                Available = ($null -ne $script:SecureScoreData)
                                Data = $script:SecureScoreData
                            }
                            DefenderCompliance = @{
                                Available = ($null -ne $script:DefenderComplianceData)
                                Data = $script:DefenderComplianceData
                            }
                        }
                        Scores = @{
                            SecureScore = if ($script:SecureScoreData) { $script:SecureScoreData.ScorePercent } else { $null }
                        }
                        Summary = @{
                            TotalFindings = $findingsWithRisk.Count
                            FailCount = $failCount
                            WarningCount = $warnCount
                            OKCount = $okCount
                            InfoCount = $infoCount
                        }
                    }

                    # Compare snapshots
                    $deltaData = Compare-ComplianceSnapshots -BaselineSnapshot $baselineSnapshot -CurrentSnapshot $currentSnapshotData

                    # Export delta report
                    if ($deltaData) {
                        $deltaReport = Export-DeltaReport -DeltaData $deltaData -OutputDirectory $OutputDirectory
                        Write-Host "    [OK] Delta report generated: $($deltaReport.HTMLReport)" -ForegroundColor Green
                    }
                }
                else {
                    Write-Host "    [!] Failed to load baseline snapshot" -ForegroundColor Red
                }
            }
            else {
                Write-Host "    [!] Baseline snapshot not found: $CompareWithSnapshot" -ForegroundColor Red
            }
        }
        else {
            Write-Host "    [!] DeltaReporting module not available - comparison skipped" -ForegroundColor Yellow
        }
    }
}

#endregion

#region Generate HTML Report

Write-Host "`n[5/6] Generating comprehensive HTML report..." -ForegroundColor Cyan

$htmlPath = Join-Path $OutputDirectory "Comprehensive-Assessment-Report-$timestamp.html"

# Build tenant info object for the report
$tenantInfo = [PSCustomObject]@{
    TenantName = $TenantName
    TenantId = if ($script:MgContext) { $script:MgContext.TenantId } else { "N/A" }
    AssessmentDate = $assessmentDate
    Timestamp = $timestamp
    FindingsCount = $findingsWithRisk.Count
    FailCount = $failCount
    WarnCount = $warnCount
    OkCount = $okCount
    InfoCount = $infoCount
}

# Generate the HTML report using the existing EnhancedHTMLReport module
# Pass original Findings (not findingsWithRisk) because New-EnhancedHTMLReport
# runs its own Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance pipeline
try {
    # Enrich Secure Score with improvement actions (rendered as a top-10 table
    # in the unified report). Only attempt when SecureScore data is present
    # AND the helper is available — both gracefully degrade.
    $secureScoreForReport = $externalData.SecureScore
    if ($secureScoreForReport -and (Get-Command Get-SecureScoreImprovementActions -ErrorAction SilentlyContinue)) {
        try {
            $actions = Get-SecureScoreImprovementActions -SecureScore $secureScoreForReport
            if ($actions) {
                $secureScoreForReport['ImprovementActions'] = $actions
            }
        }
        catch {
            Write-Host "    [i] Could not enrich Secure Score with improvement actions: $($_.Exception.Message)" -ForegroundColor Gray
        }
    }

    $reportPath = New-EnhancedHTMLReport `
        -Findings $Findings `
        -OutputPath $htmlPath `
        -TenantInfo $tenantInfo `
        -DefenderCompliance $externalData.DefenderCompliance `
        -SecureScore $secureScoreForReport `
        -AzurePolicy $externalData.AzurePolicy `
        -PurviewCompliance $externalData.PurviewCompliance `
        -IncludeSections @('All')

    Write-Host "    HTML report generated successfully" -ForegroundColor Green
}
catch {
    Write-Host "    [!] Error generating HTML report: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Generating standalone findings report..." -ForegroundColor Yellow

    # Fallback: generate a self-contained analyst-friendly HTML report
    $actionableFindings = $findingsWithRisk | Where-Object { $_.Status -in @('FAIL', 'WARNING') } |
        Sort-Object -Property RiskScore -Descending
    $passingFindings = $findingsWithRisk | Where-Object { $_.Status -eq 'OK' }

    $criticalFindings = @($actionableFindings | Where-Object { $_.RiskLevel -eq 'Critical' })
    $highFindings = @($actionableFindings | Where-Object { $_.RiskLevel -eq 'High' })
    $mediumFindings = @($actionableFindings | Where-Object { $_.RiskLevel -eq 'Medium' })
    $lowFindings = @($actionableFindings | Where-Object { $_.RiskLevel -in @('Low', 'Info') })

    function Get-FindingRows {
        param([array]$Items, [string]$BadgeClass, [string]$BadgeLabel)
        $rows = ""
        foreach ($f in $Items) {
            $desc = [System.Net.WebUtility]::HtmlEncode($f.Description)
            $obj = [System.Net.WebUtility]::HtmlEncode($f.Object)
            $rem = [System.Net.WebUtility]::HtmlEncode($f.Remediation)
            $rows += @"
<tr>
    <td><span class="badge $BadgeClass">$BadgeLabel</span></td>
    <td><span class="status-$($f.Status.ToLower())">$($f.Status)</span></td>
    <td><strong>$obj</strong><br><span class="desc">$desc</span></td>
    <td class="remediation">$rem</td>
    <td class="score">$($f.RiskScore)</td>
</tr>
"@
        }
        return $rows
    }

    $criticalRows = Get-FindingRows -Items $criticalFindings -BadgeClass 'critical' -BadgeLabel 'CRITICAL'
    $highRows = Get-FindingRows -Items $highFindings -BadgeClass 'high' -BadgeLabel 'HIGH'
    $mediumRows = Get-FindingRows -Items $mediumFindings -BadgeClass 'medium' -BadgeLabel 'MEDIUM'
    $lowRows = Get-FindingRows -Items $lowFindings -BadgeClass 'low' -BadgeLabel 'LOW'

    # Build error/warnings section if any assessment errors occurred
    $errorSectionHtml = ""
    $assessmentErrors = if ($ExternalData -and $ExternalData['AssessmentErrors']) { $ExternalData['AssessmentErrors'] } else { @() }
    $failedModules = if ($ExternalData -and $ExternalData['FailedModules']) { $ExternalData['FailedModules'] } else { @() }
    if ($assessmentErrors.Count -gt 0 -or $failedModules.Count -gt 0) {
        $errorRows = ""
        foreach ($fm in $failedModules) {
            $modName = [System.Net.WebUtility]::HtmlEncode($fm.Key)
            $modErr = [System.Net.WebUtility]::HtmlEncode($fm.Value.Error)
            $errorRows += "<tr><td><strong>$modName</strong></td><td>$modErr</td></tr>`n"
        }
        foreach ($ae in $assessmentErrors) {
            $errMod = [System.Net.WebUtility]::HtmlEncode($ae.Module)
            $errMsg = [System.Net.WebUtility]::HtmlEncode($ae.Error)
            if (-not $errorRows.Contains($errMod)) {
                $errorRows += "<tr><td><strong>$errMod</strong></td><td>$errMsg</td></tr>`n"
            }
        }
        $errorSectionHtml = @"
    <div class="section">
        <h2 style="color:#dc3545;">Assessment Errors ($($failedModules.Count + $assessmentErrors.Count))</h2>
        <p style="margin-bottom:12px;color:#666;">The following errors occurred during the assessment. Some results may be incomplete. Check the log file for full details.</p>
        <table><tr><th>Module/Check</th><th>Error</th></tr>
        $errorRows
        </table>
    </div>
"@
    }

    $fallbackHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report - $TenantName</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; color: #333; }
    .header { background: linear-gradient(135deg, #0078d4, #0053a6); color: white; padding: 30px 40px; }
    .header h1 { font-size: 1.8em; margin-bottom: 8px; }
    .header .meta { opacity: 0.9; font-size: 0.95em; }
    .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
    .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 20px 0; }
    .card { background: white; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .card .number { font-size: 2.5em; font-weight: 700; }
    .card .label { font-size: 0.85em; color: #666; margin-top: 4px; }
    .card.critical .number { color: #d13438; }
    .card.high .number { color: #ff8c00; }
    .card.medium .number { color: #ffc107; }
    .card.low .number { color: #107c10; }
    .card.pass .number { color: #0078d4; }
    .card.total .number { color: #333; }
    .section { background: white; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; }
    .section h2 { padding: 16px 24px; border-bottom: 2px solid #f0f2f5; font-size: 1.2em; }
    .section h2.critical-header { border-left: 4px solid #d13438; }
    .section h2.high-header { border-left: 4px solid #ff8c00; }
    .section h2.medium-header { border-left: 4px solid #ffc107; }
    .section h2.low-header { border-left: 4px solid #107c10; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    th { background: #f8f9fa; text-align: left; padding: 10px 16px; font-size: 0.8em; text-transform: uppercase; color: #666; }
    td { padding: 12px 16px; border-top: 1px solid #eee; vertical-align: top; font-size: 0.9em; word-wrap: break-word; overflow-wrap: break-word; }
    th:nth-child(1) { width: 8%; }
    th:nth-child(2) { width: 7%; }
    th:nth-child(3) { width: 40%; }
    th:nth-child(4) { width: 35%; }
    th:nth-child(5) { width: 10%; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75em; font-weight: 600; color: white; }
    .badge.critical { background: #d13438; }
    .badge.high { background: #ff8c00; }
    .badge.medium { background: #ffc107; color: #333; }
    .badge.low { background: #107c10; }
    .status-fail { color: #d13438; font-weight: 600; }
    .status-warning { color: #ff8c00; font-weight: 600; }
    .status-ok { color: #107c10; }
    .status-info { color: #0078d4; }
    .desc { color: #555; }
    .remediation { color: #0053a6; font-size: 0.85em; }
    .score { text-align: center; font-weight: 600; }
    .passing-summary { padding: 16px 24px; color: #555; }
    .footer { text-align: center; padding: 20px; color: #999; font-size: 0.8em; }
    @media print { body { background: white; } .section { box-shadow: none; border: 1px solid #ddd; } }
</style>
</head>
<body>
<div class="header">
    <h1>Microsoft Entra ID Security Assessment</h1>
    <div class="meta">Tenant: $TenantName | Generated: $assessmentDate | Total Findings: $($findingsWithRisk.Count)</div>
</div>
<div class="container">
    <div class="summary-cards">
        <div class="card critical"><div class="number">$($criticalFindings.Count)</div><div class="label">Critical</div></div>
        <div class="card high"><div class="number">$($highFindings.Count)</div><div class="label">High</div></div>
        <div class="card medium"><div class="number">$($mediumFindings.Count)</div><div class="label">Medium</div></div>
        <div class="card low"><div class="number">$($lowFindings.Count)</div><div class="label">Low</div></div>
        <div class="card pass"><div class="number">$($passingFindings.Count)</div><div class="label">Passing</div></div>
        <div class="card total"><div class="number">$($findingsWithRisk.Count)</div><div class="label">Total Checks</div></div>
    </div>

$(if ($criticalFindings.Count -gt 0) { @"
    <div class="section">
        <h2 class="critical-header">Critical Findings ($($criticalFindings.Count))</h2>
        <table><tr><th>Severity</th><th>Status</th><th>Finding</th><th>Remediation</th><th>Score</th></tr>
        $criticalRows
        </table>
    </div>
"@ })

$(if ($highFindings.Count -gt 0) { @"
    <div class="section">
        <h2 class="high-header">High Findings ($($highFindings.Count))</h2>
        <table><tr><th>Severity</th><th>Status</th><th>Finding</th><th>Remediation</th><th>Score</th></tr>
        $highRows
        </table>
    </div>
"@ })

$(if ($mediumFindings.Count -gt 0) { @"
    <div class="section">
        <h2 class="medium-header">Medium Findings ($($mediumFindings.Count))</h2>
        <table><tr><th>Severity</th><th>Status</th><th>Finding</th><th>Remediation</th><th>Score</th></tr>
        $mediumRows
        </table>
    </div>
"@ })

$(if ($lowFindings.Count -gt 0) { @"
    <div class="section">
        <h2 class="low-header">Low Findings ($($lowFindings.Count))</h2>
        <table><tr><th>Severity</th><th>Status</th><th>Finding</th><th>Remediation</th><th>Score</th></tr>
        $lowRows
        </table>
    </div>
"@ })

$errorSectionHtml

    <div class="section">
        <h2>Passing Controls ($($passingFindings.Count))</h2>
        <div class="passing-summary">
            $($passingFindings.Count) checks passed successfully across the assessment.
        </div>
    </div>

    <div class="footer">
        Generated by EntraChecks Comprehensive Assessment | $assessmentDate
    </div>
</div>
</body>
</html>
"@
    $fallbackHtml | Set-Content -Path $htmlPath -Encoding UTF8
    $reportPath = $htmlPath
    Write-Host "    [OK] Standalone findings report generated" -ForegroundColor Green
}

#endregion

#region Generate Excel Report

$excelPath = $null

if ($GenerateExcelReport) {
    Write-Host "`n[+] Generating Excel workbook..." -ForegroundColor Cyan

    if (Get-Command New-EnhancedExcelReport -ErrorAction SilentlyContinue) {
        $excelPath = Join-Path $OutputDirectory "Comprehensive-Assessment-Excel-$timestamp.xlsx"

        try {
            $tenantInfoObj = [PSCustomObject]@{
                TenantName = $TenantName
                TenantId = if ($script:MgContext) { $script:MgContext.TenantId } else { "Unknown" }
                AssessmentDate = $assessmentDate
            }

            # Reuse the same enriched Secure Score object the HTML report received
            # (or fall back to the raw external data if HTML generation didn't run).
            $ssForExcel = if ($secureScoreForReport) { $secureScoreForReport } else { $externalData.SecureScore }

            New-EnhancedExcelReport `
                -Findings $findingsWithRisk `
                -OutputPath $excelPath `
                -TenantInfo $tenantInfoObj `
                -SecureScore $ssForExcel `
                -AzurePolicy $externalData.AzurePolicy `
                -PurviewCompliance $externalData.PurviewCompliance `
                -UseImportExcel

            Write-Host "    [OK] Excel workbook generated: $excelPath" -ForegroundColor Green
        }
        catch {
            Write-Host "    [!] Error generating Excel report: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "    [!] ExcelReporting module not available" -ForegroundColor Yellow
    }
}

#endregion

#region Generate Remediation Scripts

$remediationScriptsPath = $null

if ($GenerateRemediationScripts) {
    Write-Host "`n[+] Generating automated remediation scripts..." -ForegroundColor Cyan

    $remediationScriptsPath = Join-Path $OutputDirectory "RemediationScripts-$timestamp"

    if (-not (Test-Path $remediationScriptsPath)) {
        New-Item -Path $remediationScriptsPath -ItemType Directory -Force | Out-Null
    }

    # Group findings by type for remediation
    $findingsByType = $findingsWithRisk | Where-Object { $_.Status -in @('FAIL', 'WARNING') } | Group-Object { $_.CheckName }

    $scriptCount = 0

    foreach ($group in $findingsByType) {
        $checkName = $group.Name
        $checkFindings = $group.Group

        # Get remediation guidance
        $guidance = if (Get-Command Get-ExtendedRemediationGuidance -ErrorAction SilentlyContinue) {
            Get-ExtendedRemediationGuidance -FindingType $checkName -IncludeBestPractices -IncludeSecurityContext -ErrorAction SilentlyContinue
        }
        else {
            Get-RemediationGuidance -FindingType $checkName -ErrorAction SilentlyContinue
        }

        if ($guidance -and $guidance.StepsPowerShell) {
            # Create remediation script
            $scriptName = "Fix-$($checkName -replace '[^a-zA-Z0-9]', '').ps1"
            $scriptPath = Join-Path $remediationScriptsPath $scriptName

            $scriptContent = @"
<#
.SYNOPSIS
    Automated remediation script for: $($guidance.Title)

.DESCRIPTION
    $($guidance.Summary)

    ** IMPORTANT: Review and test this script before running in production! **

    This script was automatically generated based on findings from EntraChecks assessment.
    It includes safety checks and rollback procedures.

.PARAMETER WhatIf
    Show what would happen without making changes (recommended for first run)

.PARAMETER Confirm
    Prompt for confirmation before making each change

.EXAMPLE
    # Test mode - see what would change
    .\$scriptName -WhatIf

.EXAMPLE
    # Interactive mode - confirm each change
    .\$scriptName -Confirm

.EXAMPLE
    # Auto-remediate (use with caution)
    .\$scriptName

.NOTES
    Generated: $assessmentDate
    Findings affected: $($checkFindings.Count)

    PREREQUISITES:
$(foreach ($prereq in $guidance.Prerequisites) { "    - $prereq`n" })

    BEST PRACTICES:
$(if ($guidance.BestPractices) { foreach ($bp in $guidance.BestPractices) { "    - $bp`n" } } else { "    - Review Microsoft documentation before implementing`n" })

.LINK
$(foreach ($ref in $guidance.References) { "    $ref`n" })
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]`$WhatIf,
    [switch]`$Confirm
)

# Safety check - require explicit confirmation
if (-not `$WhatIf -and -not `$Confirm) {
    Write-Host "`n[!] WARNING: This script will make changes to your environment" -ForegroundColor Red
    Write-Host "[!] Run with -WhatIf first to preview changes" -ForegroundColor Yellow
    `$response = Read-Host "Continue? (yes/no)"
    if (`$response -ne "yes") {
        Write-Host "Cancelled - no changes made" -ForegroundColor Cyan
        return
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Remediation: $($guidance.Title)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Log start
`$logPath = ".\Remediation-$checkName-`$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
"Remediation started: `$(Get-Date)" | Out-File -FilePath `$logPath -Append

try {
    # Remediation code
$($guidance.StepsPowerShell)

    Write-Host "`n[OK] Remediation completed successfully" -ForegroundColor Green
    "Remediation completed successfully: `$(Get-Date)" | Out-File -FilePath `$logPath -Append
}
catch {
    Write-Host "`n[!] Error during remediation: `$(`$_.Exception.Message)" -ForegroundColor Red
    "Error: `$(`$_.Exception.Message)" | Out-File -FilePath `$logPath -Append

    Write-Host "`n[i] ROLLBACK PROCEDURES:" -ForegroundColor Cyan
$(foreach ($rollback in $guidance.Rollback) { "    Write-Host '  - $rollback' -ForegroundColor Gray`n" })

    throw
}

Write-Host "`n[i] Log saved: `$logPath" -ForegroundColor Cyan

# Verification steps
Write-Host "`n[i] VERIFICATION STEPS:" -ForegroundColor Cyan
$(foreach ($verify in $guidance.Verification) { "Write-Host '  - $verify' -ForegroundColor Gray`n" })
"@

            $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8 -Force
            $scriptCount++
        }
    }

    if ($scriptCount -gt 0) {
        Write-Host "    [OK] Generated $scriptCount remediation scripts in: $remediationScriptsPath" -ForegroundColor Green

        # Create master remediation script
        $masterScriptPath = Join-Path $remediationScriptsPath "_Run-All-Remediations.ps1"
        $masterScript = @"
<#
.SYNOPSIS
    Master script to run all remediation scripts in order.

.DESCRIPTION
    This script orchestrates the execution of all remediation scripts.
    Scripts are ordered by priority (Critical -> High -> Medium -> Low).

    ** ALWAYS run with -WhatIf first! **

.PARAMETER WhatIf
    Show what would happen without making changes

.EXAMPLE
    .\\_Run-All-Remediations.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param()

Write-Host "========================================" -ForegroundColor Magenta
Write-Host " Bulk Remediation Orchestrator" -ForegroundColor Magenta
Write-Host "========================================`n" -ForegroundColor Magenta

`$scripts = Get-ChildItem -Path "`$PSScriptRoot" -Filter "Fix-*.ps1"
Write-Host "[i] Found `$(`$scripts.Count) remediation scripts`n" -ForegroundColor Cyan

foreach (`$script in `$scripts) {
    Write-Host "`n[+] Running: `$(`$script.Name)" -ForegroundColor Cyan
    try {
        & `$script.FullName -WhatIf:`$WhatIf
        Write-Host "    [OK] Completed" -ForegroundColor Green
    }
    catch {
        Write-Host "    [!] Failed: `$(`$_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n[OK] Bulk remediation complete" -ForegroundColor Green
"@
        $masterScript | Out-File -FilePath $masterScriptPath -Encoding UTF8 -Force
        Write-Host "    [OK] Master orchestration script: $masterScriptPath" -ForegroundColor Green
    }
    else {
        Write-Host "    [i] No remediation scripts generated (no actionable findings with PowerShell guidance)" -ForegroundColor Gray
    }
}

#endregion

#region Generate Executive Summary

$executiveSummaryPath = $null

if ($GenerateExecutivePDF) {
    Write-Host "`n[+] Generating executive summary..." -ForegroundColor Cyan

    $executiveSummaryPath = Join-Path $OutputDirectory "Executive-Summary-$timestamp.html"

    try {
        & "$PSScriptRoot\New-ExecutiveSummary.ps1" `
            -RiskSummary $riskSummary `
            -FindingsCount $findingsWithRisk.Count `
            -TenantName $TenantName `
            -ComplianceMappings $complianceMappings `
            -QuickWins $quickWins `
            -ExternalData $externalData `
            -OutputPath $executiveSummaryPath

        Write-Host "    [OK] Executive summary generated: $executiveSummaryPath" -ForegroundColor Green
    }
    catch {
        Write-Host "    [!] Error generating executive summary: $($_.Exception.Message)" -ForegroundColor Red
    }
}

#endregion

#region Generate Additional Outputs

Write-Host "`n[6/6] Generating additional outputs..." -ForegroundColor Cyan

# Export prioritized findings CSV
$csvPrioritizedPath = Join-Path $OutputDirectory "Prioritized-Findings-$timestamp.csv"
$prioritizedFindings | Select-Object RiskLevel, RiskScore, Status, Object, Description, Remediation |
    Export-Csv -Path $csvPrioritizedPath -NoTypeInformation -Encoding UTF8
Write-Host "    Prioritized findings CSV: $csvPrioritizedPath" -ForegroundColor Gray

# Export quick wins CSV
$csvQuickWinsPath = Join-Path $OutputDirectory "Quick-Wins-$timestamp.csv"
$quickWins | Select-Object RiskLevel, RiskScore, Status, Object, Description, Remediation |
    Export-Csv -Path $csvQuickWinsPath -NoTypeInformation -Encoding UTF8
Write-Host "    Quick wins CSV: $csvQuickWinsPath" -ForegroundColor Gray

# Export compliance gaps CSVs
foreach ($framework in $selectedFrameworks) {
    if ($complianceGaps[$framework]) {
        $csvGapsPath = Join-Path $OutputDirectory "Compliance-Gaps-$framework-$timestamp.csv"
        $complianceGaps[$framework] | Export-Csv -Path $csvGapsPath -NoTypeInformation -Encoding UTF8
        Write-Host "    $framework gaps CSV: $csvGapsPath" -ForegroundColor Gray
    }
}

# Export full findings JSON (for trending/comparison)
$jsonPath = Join-Path $OutputDirectory "Assessment-Data-$timestamp.json"
$reportData = @{
    Metadata = @{
        TenantName = $TenantName
        AssessmentDate = $assessmentDate
        Timestamp = $timestamp
        GeneratedBy = 'EntraChecks Comprehensive Assessment'
    }
    Summary = @{
        TotalFindings = $findingsWithRisk.Count
        FailCount = $failCount
        WarnCount = $warnCount
        OkCount = $okCount
        InfoCount = $infoCount
        RiskSummary = $riskSummary
    }
    Findings = $findingsWithRisk
    ComplianceMappings = $complianceMappings
    ComplianceGaps = $complianceGaps
    ExternalData = $externalData
}
$reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host "    Full assessment JSON: $jsonPath" -ForegroundColor Gray

#endregion

#region Summary

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " Report Generation Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Primary Report:" -ForegroundColor Cyan
Write-Host "  $reportPath" -ForegroundColor White
Write-Host ""
Write-Host "Key Findings:" -ForegroundColor Cyan
Write-Host "  Critical Issues: $($riskSummary.CriticalCount)" -ForegroundColor $(if ($riskSummary.CriticalCount -gt 0) { "Red" } else { "Green" })
Write-Host "  High Priority: $($riskSummary.HighCount)" -ForegroundColor $(if ($riskSummary.HighCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Quick Wins Available: $($quickWins.Count)" -ForegroundColor Green
Write-Host ""
Write-Host "Compliance Coverage:" -ForegroundColor Cyan
foreach ($framework in $selectedFrameworks) {
    if ($complianceMappings[$framework]) {
        $passedControls = ($complianceMappings[$framework] | Where-Object { $_.Status -eq 'Passed' }).Count
        $totalControls = $complianceMappings[$framework].Count
        $percentage = if ($totalControls -gt 0) {
            [math]::Round(($passedControls / $totalControls) * 100, 1)
        }
        else { 0 }

        Write-Host "  $framework`: $passedControls/$totalControls ($percentage%)" -ForegroundColor $(
            if ($percentage -ge 80) { "Green" }
            elseif ($percentage -ge 60) { "Yellow" }
            else { "Red" }
        )
    }
}
Write-Host ""

#endregion

# Return report paths for pipeline usage
return @{
    HTMLReport = $reportPath
    ExecutiveSummary = $executiveSummaryPath
    PrioritizedFindings = $csvPrioritizedPath
    QuickWins = $csvQuickWinsPath
    FullData = $jsonPath
    RiskSummary = $riskSummary
    ComplianceMappings = $complianceMappings
    Snapshot = $snapshotPath
    DeltaReport = if ($deltaData) { $deltaData.HTMLReport } else { $null }
    ExcelReport = $excelPath
    RemediationScripts = $remediationScriptsPath
}
