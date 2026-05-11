# EntraChecks Reporting - Practical Examples

Real-world usage examples and recipes for common scenarios.

---

## Table of Contents

1. [Basic Usage Examples](#basic-usage-examples)
2. [Filtering and Custom Reports](#filtering-and-custom-reports)
3. [Compliance-Focused Examples](#compliance-focused-examples)
4. [Automation Examples](#automation-examples)
5. [Advanced Scenarios](#advanced-scenarios)
6. [Integration Examples](#integration-examples)

---

## Basic Usage Examples

### Example 1: Your First Complete Assessment

```powershell
# Complete workflow from scan to report

# Step 1: Connect to Entra ID
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "Organization.Read.All"

# Step 2: Navigate to EntraChecks
Set-Location "C:\Tools\EntraChecks"

# Step 3: Run the assessment
.\EntraChecks.ps1

# Step 4: Import all reporting modules
Import-Module .\Modules\EntraChecks-ComplianceMapping.psm1 -Force
Import-Module .\Modules\EntraChecks-RiskScoring.psm1 -Force
Import-Module .\Modules\EntraChecks-RemediationGuidance.psm1 -Force
Import-Module .\Modules\EntraChecks-HTMLReporting.ps1 -Force
Import-Module .\Modules\EntraChecks-ExcelReporting.psm1 -Force

# Step 5: Get tenant information
$tenantInfo = [PSCustomObject]@{
    TenantName = (Get-MgOrganization).DisplayName
    TenantId = (Get-MgOrganization).Id
}

# Step 6: Enhance findings with all metadata
$enhancedFindings = $findings |
    Add-RiskScoring |
    Add-ComplianceMapping |
    Add-RemediationGuidance

# Step 7: Generate reports
$timestamp = Get-Date -Format "yyyy-MM-dd"
New-EnhancedHTMLReport `
    -Findings $enhancedFindings `
    -OutputPath ".\EntraChecks-$timestamp.html" `
    -TenantInfo $tenantInfo

New-EnhancedExcelReport `
    -Findings $enhancedFindings `
    -OutputPath ".\EntraChecks-$timestamp.xlsx" `
    -TenantInfo $tenantInfo `
    -UseImportExcel

# Step 8: Open reports
Start-Process ".\EntraChecks-$timestamp.html"

# Step 9: Disconnect when done
Disconnect-MgGraph

Write-Host "Assessment complete! Reports generated:" -ForegroundColor Green
Write-Host "  HTML: EntraChecks-$timestamp.html" -ForegroundColor Cyan
Write-Host "  Excel: EntraChecks-$timestamp.xlsx" -ForegroundColor Cyan
```

---

### Example 2: Quick Daily Health Check

```powershell
# Quick script for daily security checks
# Focuses on Critical and High findings only

# Connect and scan
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "Organization.Read.All"
Set-Location "C:\Tools\EntraChecks"
.\EntraChecks.ps1

# Import modules and enhance
Import-Module .\Modules\*.psm1 -Force
$enhancedFindings = $findings | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance

# Get high-priority items only
$highPriority = $enhancedFindings | Where-Object {
    $_.RiskLevel -in @('Critical', 'High')
} | Sort-Object -Property RiskScore -Descending

# Display summary
Write-Host "`n=== DAILY SECURITY SUMMARY ===" -ForegroundColor Cyan
Write-Host "Critical Findings: $(($highPriority | Where-Object RiskLevel -eq 'Critical').Count)" -ForegroundColor Red
Write-Host "High Findings: $(($highPriority | Where-Object RiskLevel -eq 'High').Count)" -ForegroundColor Yellow
Write-Host "Total Findings: $($findings.Count)" -ForegroundColor White

# Show top 5 issues
Write-Host "`nTop 5 Issues to Address:" -ForegroundColor Cyan
$highPriority | Select-Object -First 5 | ForEach-Object {
    Write-Host "  [$($_.RiskLevel)] $($_.Description)" -ForegroundColor $(
        switch ($_.RiskLevel) {
            'Critical' { 'Red' }
            'High' { 'Yellow' }
            default { 'White' }
        }
    )
}

Disconnect-MgGraph
```

---

## Filtering and Custom Reports

### Example 3: Generate Report for Specific Risk Levels

```powershell
# Generate separate reports for different risk levels

Import-Module .\Modules\*.psm1 -Force
$enhancedFindings = $findings | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance

$tenantInfo = [PSCustomObject]@{
    TenantName = (Get-MgOrganization).DisplayName
    TenantId = (Get-MgOrganization).Id
}

# Critical findings report
$critical = $enhancedFindings | Where-Object { $_.RiskLevel -eq 'Critical' }
if ($critical.Count -gt 0) {
    New-EnhancedHTMLReport `
        -Findings $critical `
        -OutputPath ".\Critical-Findings-$(Get-Date -Format 'yyyy-MM-dd').html" `
        -TenantInfo $tenantInfo
}

# High findings report
$high = $enhancedFindings | Where-Object { $_.RiskLevel -eq 'High' }
if ($high.Count -gt 0) {
    New-EnhancedHTMLReport `
        -Findings $high `
        -OutputPath ".\High-Findings-$(Get-Date -Format 'yyyy-MM-dd').html" `
        -TenantInfo $tenantInfo
}

Write-Host "Reports generated for critical and high risk findings." -ForegroundColor Green
```

---

### Example 4: Quick Wins Report for Management

```powershell
# Generate a focused report on easy wins for leadership

Import-Module .\Modules\*.psm1 -Force
$enhancedFindings = $findings | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance

# Get quick wins (high impact, low effort)
$quickWins = Get-QuickWins -Findings $enhancedFindings

# Generate focused report
$tenantInfo = [PSCustomObject]@{
    TenantName = (Get-MgOrganization).DisplayName
    TenantId = (Get-MgOrganization).Id
}

New-EnhancedHTMLReport `
    -Findings $quickWins `
    -OutputPath ".\QuickWins-$(Get-Date -Format 'yyyy-MM-dd').html" `
    -TenantInfo $tenantInfo

# Create summary for email
$summary = @"
Quick Wins Security Improvements

We've identified $($quickWins.Count) high-impact, low-effort security improvements
that can be implemented quickly to significantly improve our security posture.

Risk Reduction Potential:
- Total Risk Score: $([Math]::Round(($quickWins | Measure-Object -Property RiskScore -Sum).Sum, 0))
- Average Priority Score: $([Math]::Round(($quickWins | Measure-Object -Property PriorityScore -Average).Average, 1))

Top 3 Quick Wins:
"@

$quickWins | Select-Object -First 3 | ForEach-Object {
    $summary += "`n$($_.Priority). $($_.Description)"
    $summary += "`n   Risk: $($_.RiskLevel) | Effort: $($_.RemediationEffortDescription)"
}

$summary | Out-File ".\QuickWins-Summary.txt"
Write-Host "Quick wins report and summary generated!" -ForegroundColor Green
```

---

### Example 5: Filter by Finding Category

```powershell
# Generate reports by security category

$categories = @{
    'MFA' = $enhancedFindings | Where-Object { $_.Type -like "*MFA*" }
    'ConditionalAccess' = $enhancedFindings | Where-Object { $_.Type -like "*ConditionalAccess*" }
    'Admin' = $enhancedFindings | Where-Object { $_.Type -like "*Admin*" }
    'Audit' = $enhancedFindings | Where-Object { $_.Type -like "*Audit*" }
}

foreach ($category in $categories.Keys) {
    $categoryFindings = $categories[$category]
    if ($categoryFindings.Count -gt 0) {
        New-EnhancedHTMLReport `
            -Findings $categoryFindings `
            -OutputPath ".\$category-Findings-$(Get-Date -Format 'yyyy-MM-dd').html" `
            -TenantInfo $tenantInfo

        Write-Host "$category Report: $($categoryFindings.Count) findings" -ForegroundColor Cyan
    }
}
```

---

## Compliance-Focused Examples

### Example 6: CIS Benchmark Compliance Report

```powershell
# Generate report focused on CIS Microsoft 365 Foundations Benchmark

Import-Module .\Modules\*.psm1 -Force
$enhancedFindings = $findings | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance

# Get CIS-relevant findings only
$cisFindings = $enhancedFindings | Where-Object {
    $_.ComplianceMappings.CIS_M365
}

# Get compliance gap report
$cisGap = Get-ComplianceGapReport -Findings $enhancedFindings -Framework 'CIS'

# Generate HTML report
New-EnhancedHTMLReport `
    -Findings $cisFindings `
    -OutputPath ".\CIS-Compliance-Report-$(Get-Date -Format 'yyyy-MM-dd').html" `
    -TenantInfo $tenantInfo

# Create summary report
$cisSummary = @"
CIS Microsoft 365 Foundations Benchmark - Gap Analysis
Date: $(Get-Date -Format 'yyyy-MM-dd')

Total Findings Affecting CIS Controls: $($cisFindings.Count)

Controls with Gaps: $($cisGap.FrameworkGaps.CIS.ControlsAffected)
Total Controls in Framework: $($cisGap.FrameworkGaps.CIS.TotalControls)
Compliance Rate: $([Math]::Round((1 - ($cisGap.FrameworkGaps.CIS.ControlsAffected / $cisGap.FrameworkGaps.CIS.TotalControls)) * 100, 1))%

Risk Breakdown:
- Critical: $(($cisFindings | Where-Object RiskLevel -eq 'Critical').Count)
- High: $(($cisFindings | Where-Object RiskLevel -eq 'High').Count)
- Medium: $(($cisFindings | Where-Object RiskLevel -eq 'Medium').Count)
- Low: $(($cisFindings | Where-Object RiskLevel -eq 'Low').Count)

Remediation Priority:
$($cisFindings | Sort-Object -Property PriorityScore -Descending | Select-Object -First 10 | ForEach-Object {
    "- [$($_.RiskLevel)] $($_.Description)"
} | Out-String)
"@

$cisSummary | Out-File ".\CIS-Summary-$(Get-Date -Format 'yyyy-MM-dd').txt"
Write-Host "CIS compliance report generated!" -ForegroundColor Green
```

---

### Example 7: Multi-Framework Compliance Dashboard

```powershell
# Generate a comprehensive compliance report covering all frameworks

$frameworks = @('CIS', 'NIST', 'SOC2', 'PCIDSS')
$complianceData = @()

foreach ($framework in $frameworks) {
    $gapReport = Get-ComplianceGapReport -Findings $enhancedFindings -Framework $framework
    $frameworkFindings = $enhancedFindings | Where-Object {
        $_.ComplianceMappings."$($framework)_*"
    }

    $complianceData += [PSCustomObject]@{
        Framework = $framework
        TotalFindings = $frameworkFindings.Count
        ControlsAffected = $gapReport.FrameworkGaps.$framework.ControlsAffected
        TotalControls = $gapReport.FrameworkGaps.$framework.TotalControls
        ComplianceRate = [Math]::Round((1 - ($gapReport.FrameworkGaps.$framework.ControlsAffected / $gapReport.FrameworkGaps.$framework.TotalControls)) * 100, 1)
        CriticalFindings = ($frameworkFindings | Where-Object RiskLevel -eq 'Critical').Count
        HighFindings = ($frameworkFindings | Where-Object RiskLevel -eq 'High').Count
    }
}

# Display compliance dashboard
Write-Host "`n=== COMPLIANCE DASHBOARD ===" -ForegroundColor Cyan
$complianceData | Format-Table -AutoSize

# Export to CSV for further analysis
$complianceData | Export-Csv -Path ".\Compliance-Dashboard-$(Get-Date -Format 'yyyy-MM-dd').csv" -NoTypeInformation
```

---

## Automation Examples

### Example 8: Scheduled Weekly Assessment

```powershell
# Save as: Run-WeeklyAssessment.ps1
# Schedule with Windows Task Scheduler to run weekly

param(
    [string]$OutputFolder = "C:\Reports\EntraChecks",
    [string]$EmailTo = "security-team@company.com",
    [string]$SmtpServer = "smtp.company.com"
)

# Ensure output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory | Out-Null
}

# Start logging
$logFile = Join-Path $OutputFolder "assessment-log.txt"
"=== Assessment started at $(Get-Date) ===" | Out-File -FilePath $logFile -Append

try {
    # Connect (using app credentials for automation)
    Connect-MgGraph -ClientId $env:ENTRACHECKS_CLIENTID `
                    -TenantId $env:ENTRACHECKS_TENANTID `
                    -CertificateThumbprint $env:ENTRACHECKS_CERT_THUMBPRINT

    # Navigate and scan
    Set-Location "C:\Tools\EntraChecks"
    .\EntraChecks.ps1

    # Import modules and enhance
    Import-Module .\Modules\*.psm1 -Force
    $tenantInfo = [PSCustomObject]@{
        TenantName = (Get-MgOrganization).DisplayName
        TenantId = (Get-MgOrganization).Id
    }

    $enhancedFindings = $findings |
        Add-RiskScoring |
        Add-ComplianceMapping |
        Add-RemediationGuidance

    # Generate reports
    $weekNumber = Get-Date -UFormat %V
    $year = Get-Date -Format yyyy
    $htmlPath = Join-Path $OutputFolder "EntraChecks-Week$weekNumber-$year.html"
    $excelPath = Join-Path $OutputFolder "EntraChecks-Week$weekNumber-$year.xlsx"

    New-EnhancedHTMLReport -Findings $enhancedFindings -OutputPath $htmlPath -TenantInfo $tenantInfo
    New-EnhancedExcelReport -Findings $enhancedFindings -OutputPath $excelPath -TenantInfo $tenantInfo -UseImportExcel

    # Create summary for email
    $riskSummary = Get-RiskSummary -Findings $enhancedFindings
    $emailBody = @"
Weekly EntraChecks Security Assessment - Week $weekNumber, $year

Tenant: $($tenantInfo.TenantName)

Summary:
- Total Findings: $($findings.Count)
- Critical Risk: $($riskSummary.CriticalCount)
- High Risk: $($riskSummary.HighCount)
- Medium Risk: $($riskSummary.MediumCount)
- Low Risk: $($riskSummary.LowCount)

Average Risk Score: $($riskSummary.AverageRiskScore)
Quick Wins Available: $($riskSummary.QuickWinsCount)

Reports are attached.

--
Automated EntraChecks Assessment
"@

    # Send email with reports
    Send-MailMessage `
        -To $EmailTo `
        -From "entrachecks@company.com" `
        -Subject "Weekly EntraChecks Report - Week $weekNumber" `
        -Body $emailBody `
        -Attachments $htmlPath,$excelPath `
        -SmtpServer $SmtpServer

    "Assessment completed successfully at $(Get-Date)" | Out-File -FilePath $logFile -Append

} catch {
    $errorMessage = "ERROR at $(Get-Date): $($_.Exception.Message)"
    $errorMessage | Out-File -FilePath $logFile -Append

    # Send error notification email
    Send-MailMessage `
        -To $EmailTo `
        -From "entrachecks@company.com" `
        -Subject "EntraChecks Assessment FAILED - Week $(Get-Date -UFormat %V)" `
        -Body "The weekly EntraChecks assessment failed. Error: $($_.Exception.Message)" `
        -SmtpServer $SmtpServer

} finally {
    Disconnect-MgGraph
}
```

---

### Example 9: Compare Current vs Previous Assessment

```powershell
# Track security posture changes over time

# Run current assessment
$currentFindings = $findings | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance

# Load previous assessment (assuming you saved it)
$previousPath = ".\PreviousAssessment.xml"
if (Test-Path $previousPath) {
    $previousFindings = Import-Clixml $previousPath

    # Compare findings
    $newIssues = $currentFindings | Where-Object {
        $current = $_
        -not ($previousFindings | Where-Object {
            $_.Description -eq $current.Description -and
            $_.Object -eq $current.Object
        })
    }

    $resolvedIssues = $previousFindings | Where-Object {
        $previous = $_
        -not ($currentFindings | Where-Object {
            $_.Description -eq $previous.Description -and
            $_.Object -eq $previous.Object
        })
    }

    # Display comparison
    Write-Host "`n=== SECURITY POSTURE CHANGE ===" -ForegroundColor Cyan
    Write-Host "Previous Findings: $($previousFindings.Count)" -ForegroundColor White
    Write-Host "Current Findings: $($currentFindings.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "New Issues: $($newIssues.Count)" -ForegroundColor $(if ($newIssues.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Resolved Issues: $($resolvedIssues.Count)" -ForegroundColor $(if ($resolvedIssues.Count -gt 0) { 'Green' } else { 'White' })

    if ($newIssues.Count -gt 0) {
        Write-Host "`nNew Issues Detected:" -ForegroundColor Yellow
        $newIssues | Select-Object -First 5 | ForEach-Object {
            Write-Host "  - $($_.Description)" -ForegroundColor White
        }
    }

    if ($resolvedIssues.Count -gt 0) {
        Write-Host "`nResolved Issues:" -ForegroundColor Green
        $resolvedIssues | Select-Object -First 5 | ForEach-Object {
            Write-Host "  - $($_.Description)" -ForegroundColor White
        }
    }
}

# Save current findings for next comparison
$currentFindings | Export-Clixml $previousPath
```

---

## Advanced Scenarios

### Example 10: Custom Risk Scoring for Your Organization

```powershell
# Adjust risk scores based on your organization's priorities

$enhancedFindings = $findings | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance

# Increase risk score for findings affecting VIP users
$vipUsers = @('ceo@company.com', 'cfo@company.com', 'ciso@company.com')

foreach ($finding in $enhancedFindings) {
    if ($finding.Object -in $vipUsers) {
        # Increase risk score by 20%
        $finding.RiskScore = [Math]::Min(100, $finding.RiskScore * 1.2)
        # Recalculate risk level
        $finding.RiskLevel = switch ($finding.RiskScore) {
            { $_ -ge 90 } { 'Critical' }
            { $_ -ge 70 } { 'High' }
            { $_ -ge 40 } { 'Medium' }
            default { 'Low' }
        }
        # Add note
        Add-Member -InputObject $finding -NotePropertyName 'AdjustmentReason' -NotePropertyValue 'VIP User' -Force
    }
}

# Increase priority for compliance-critical findings
foreach ($finding in $enhancedFindings) {
    if ($finding.ComplianceMappings.SOC2 -or $finding.ComplianceMappings.PCI_DSS_4) {
        $finding.RiskScore = [Math]::Min(100, $finding.RiskScore * 1.15)
        Add-Member -InputObject $finding -NotePropertyName 'ComplianceCritical' -NotePropertyValue $true -Force
    }
}

# Re-sort by updated priority
$prioritized = $enhancedFindings | Sort-Object -Property RiskScore -Descending

# Generate report with custom scoring
New-EnhancedHTMLReport `
    -Findings $prioritized `
    -OutputPath ".\CustomRisk-Report-$(Get-Date -Format 'yyyy-MM-dd').html" `
    -TenantInfo $tenantInfo
```

---

### Example 11: Export Data for Business Intelligence Tools

```powershell
# Export findings data for PowerBI, Tableau, or other BI tools

$enhancedFindings = $findings | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance

# Flatten findings for BI tool consumption
$flattenedFindings = $enhancedFindings | Select-Object `
    Time,
    Status,
    Object,
    Description,
    Remediation,
    RiskScore,
    RiskLevel,
    PriorityScore,
    RemediationEffort,
    RemediationEffortDescription,
    @{N='CIS_Mapped';E={if($_.ComplianceMappings.CIS_M365){'Yes'}else{'No'}}},
    @{N='NIST_Mapped';E={if($_.ComplianceMappings.NIST_CSF){'Yes'}else{'No'}}},
    @{N='SOC2_Mapped';E={if($_.ComplianceMappings.SOC2){'Yes'}else{'No'}}},
    @{N='PCIDSS_Mapped';E={if($_.ComplianceMappings.PCI_DSS_4){'Yes'}else{'No'}}},
    @{N='HasRemediationGuidance';E={if($_.RemediationGuidance){'Yes'}else{'No'}}},
    @{N='AssessmentDate';E={Get-Date -Format 'yyyy-MM-dd'}},
    @{N='TenantId';E={$tenantInfo.TenantId}},
    @{N='TenantName';E={$tenantInfo.TenantName}}

# Export to CSV
$flattenedFindings | Export-Csv -Path ".\EntraChecks-BI-Export-$(Get-Date -Format 'yyyy-MM-dd').csv" -NoTypeInformation

# Export to JSON (for API consumption)
$flattenedFindings | ConvertTo-Json -Depth 10 | Out-File ".\EntraChecks-API-Export-$(Get-Date -Format 'yyyy-MM-dd').json"

Write-Host "Data exported for BI tools!" -ForegroundColor Green
Write-Host "  CSV: EntraChecks-BI-Export-$(Get-Date -Format 'yyyy-MM-dd').csv" -ForegroundColor Cyan
Write-Host "  JSON: EntraChecks-API-Export-$(Get-Date -Format 'yyyy-MM-dd').json" -ForegroundColor Cyan
```

---

## Integration Examples

### Example 12: Integration with ServiceNow or Jira

```powershell
# Create tickets in your ITSM system for Critical and High findings

$enhancedFindings = $findings | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance

# Get Critical and High findings
$urgentFindings = $enhancedFindings | Where-Object {
    $_.RiskLevel -in @('Critical', 'High')
}

# Create tickets (pseudocode - adapt to your ITSM API)
foreach ($finding in $urgentFindings) {
    $ticketData = @{
        Summary = "Entra ID Security: $($finding.Description)"
        Description = @"
Risk Level: $($finding.RiskLevel)
Risk Score: $($finding.RiskScore)
Affected Object: $($finding.Object)

Remediation:
$($finding.Remediation)

Detailed Steps:
$($finding.RemediationGuidance.StepsPortal -join "`n")

PowerShell Automation:
$($finding.RemediationGuidance.StepsPowerShell)

Compliance Impact:
- CIS: $($finding.ComplianceMappings.CIS_M365 -ne $null)
- NIST: $($finding.ComplianceMappings.NIST_CSF -ne $null)
- SOC2: $($finding.ComplianceMappings.SOC2 -ne $null)
"@
        Priority = switch ($finding.RiskLevel) {
            'Critical' { '1 - Critical' }
            'High' { '2 - High' }
            default { '3 - Medium' }
        }
        Category = 'Security'
        AssignmentGroup = 'Identity & Access Management'
        Tags = @('EntraID', 'Security', 'Compliance')
    }

    # Send to ServiceNow/Jira API
    # Invoke-RestMethod -Uri $ticketApiUrl -Method Post -Body ($ticketData | ConvertTo-Json) -Headers $headers

    Write-Host "Ticket created for: $($finding.Description)" -ForegroundColor Green
}
```

---

### Example 13: Integration with Microsoft Teams

```powershell
# Post assessment summary to Microsoft Teams channel

$riskSummary = Get-RiskSummary -Findings $enhancedFindings
$quickWins = Get-QuickWins -Findings $enhancedFindings

# Create Teams adaptive card
$card = @{
    type = "message"
    attachments = @(
        @{
            contentType = "application/vnd.microsoft.card.adaptive"
            content = @{
                type = "AdaptiveCard"
                version = "1.2"
                body = @(
                    @{
                        type = "TextBlock"
                        text = "EntraChecks Weekly Assessment"
                        size = "Large"
                        weight = "Bolder"
                    },
                    @{
                        type = "TextBlock"
                        text = "$(Get-Date -Format 'MMMM dd, yyyy')"
                        spacing = "None"
                    },
                    @{
                        type = "FactSet"
                        facts = @(
                            @{title = "Critical"; value = "$($riskSummary.CriticalCount)"},
                            @{title = "High"; value = "$($riskSummary.HighCount)"},
                            @{title = "Medium"; value = "$($riskSummary.MediumCount)"},
                            @{title = "Low"; value = "$($riskSummary.LowCount)"},
                            @{title = "Quick Wins"; value = "$($quickWins.Count)"}
                        )
                    }
                )
            }
        }
    )
}

# Post to Teams webhook
$teamsWebhookUrl = "https://outlook.office.com/webhook/YOUR-WEBHOOK-URL"
Invoke-RestMethod -Uri $teamsWebhookUrl -Method Post -Body ($card | ConvertTo-Json -Depth 10) -ContentType 'application/json'

Write-Host "Summary posted to Microsoft Teams!" -ForegroundColor Green
```

---

## GRC Workflow Examples

### Example 14: Author analyst state for the v2 finding schema

The central finding schema (`SchemaVersion='2.0'`) carries a deterministic `FindingId` per finding. Analyst workflow state — Owner / Exception / ReviewStatus / Tags / Links — lives in a local JSON file keyed by `FindingId`, overlaid at report time without mutating raw assessment results.

Run the end-to-end walkthrough:

```powershell
pwsh -File Examples/Example-FindingState.ps1
```

The script:
1. Constructs three synthetic legacy findings.
2. Normalizes them to v2 (assigning each a stable `ECF-<20 hex>` FindingId).
3. Writes a temp state file mapping each `FindingId` to Owner / Exception / ReviewStatus overlays.
4. Re-normalizes with the state file applied and prints the resulting Disposition for each finding.
5. Confirms raw assessment fields (Status, Source, Description) are immutable.
6. Dumps one finding's complete v2 object as JSON.

For real-world use:

```powershell
# 1. Copy the tracked example to the gitignored local path.
Copy-Item config/finding-state.example.json config/finding-state.local.json

# 2. Edit finding-state.local.json — replace the example ECF-... key with
#    a real FindingId from your last assessment's JSON export.

# 3. Re-run the assessment. The orchestrator reads GRC.FindingStatePath
#    from entrachecks.config.json and applies the overlay automatically.
.\Start-EntraChecks.ps1 -Mode Quick -Modules All

# 4. Inspect the Excel "Analyst Queue" / "Exceptions" sheets or the HTML
#    "Action Queue" / "Exceptions Lifecycle" sections — your overlays
#    appear as Owner badges, Exception lifecycle rows, and Disposition
#    transitions.
```

**Reference:** [docs/Finding-Schema-Guide.md](../docs/Finding-Schema-Guide.md) covers the full schema + workflow.

---

## Pro Tips

### Tip 1: Create a Master Assessment Function

```powershell
function Invoke-EntraChecksComplete {
    param(
        [string]$OutputPath = ".",
        [switch]$GenerateHTML,
        [switch]$GenerateExcel,
        [switch]$OpenReports
    )

    # Full assessment in one command
    Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "Organization.Read.All"
    Set-Location "C:\Tools\EntraChecks"
    .\EntraChecks.ps1

    Import-Module .\Modules\*.psm1 -Force
    $tenantInfo = [PSCustomObject]@{
        TenantName = (Get-MgOrganization).DisplayName
        TenantId = (Get-MgOrganization).Id
    }

    $enhancedFindings = $findings | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance

    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"

    if ($GenerateHTML) {
        $htmlPath = Join-Path $OutputPath "EntraChecks-$timestamp.html"
        New-EnhancedHTMLReport -Findings $enhancedFindings -OutputPath $htmlPath -TenantInfo $tenantInfo
        if ($OpenReports) { Start-Process $htmlPath }
    }

    if ($GenerateExcel) {
        $excelPath = Join-Path $OutputPath "EntraChecks-$timestamp.xlsx"
        New-EnhancedExcelReport -Findings $enhancedFindings -OutputPath $excelPath -TenantInfo $tenantInfo -UseImportExcel
        if ($OpenReports) { Start-Process $excelPath }
    }

    Disconnect-MgGraph
    return $enhancedFindings
}

# Usage:
# Invoke-EntraChecksComplete -GenerateHTML -GenerateExcel -OpenReports
```

---

**For more examples and scenarios, check out:**
- [GETTING-STARTED.md](GETTING-STARTED.md) - Beginner's tutorial
- [USER-GUIDE.md](USER-GUIDE.md) - Comprehensive documentation
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions
