<#
.SYNOPSIS
    Generates a one-page executive summary HTML report.

.DESCRIPTION
    Creates a concise, executive-ready HTML summary designed for leadership
    and management audiences. Focuses on high-level metrics, risk summary,
    and key findings without technical details.

.PARAMETER RiskSummary
    Risk summary object from Get-RiskSummary

.PARAMETER FindingsCount
    Total number of findings

.PARAMETER TenantName
    Name of the assessed tenant

.PARAMETER ComplianceMappings
    Compliance framework mappings

.PARAMETER QuickWins
    Quick wins array

.PARAMETER OutputPath
    Path where the executive summary HTML will be saved

.EXAMPLE
    New-ExecutiveSummary -RiskSummary $risk -FindingsCount 127 -TenantName "Contoso" -OutputPath ".\executive-summary.html"

.NOTES
    Version: 1.0.0
    Designed for C-level and board presentations
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    $RiskSummary,

    [Parameter(Mandatory)]
    [int]$FindingsCount,

    [Parameter(Mandatory)]
    [string]$TenantName,

    [Parameter()]
    $ComplianceMappings,

    [Parameter()]
    $QuickWins,

    [Parameter()]
    $ExternalData,

    [Parameter(Mandatory)]
    [string]$OutputPath
)

$assessmentDate = Get-Date -Format "MMMM dd, yyyy"

# ===== Microsoft Secure Score (real data from Graph API) =====
$hasSecureScore = ($ExternalData -and $ExternalData.SecureScore -and $ExternalData.SecureScore.MaxScore -gt 0)
$msSecureScore = $null
$msSecureScorePercent = $null
if ($hasSecureScore) {
    $msSecureScore = $ExternalData.SecureScore
    $msSecureScorePercent = $msSecureScore.ScorePercent
}

# ===== EntraChecks Assessment Score (NIST CSF-weighted methodology) =====
# Maps finding severity to NIST CSF functions with weights:
#   Protect (PR) 30% - preventive controls (MFA, CA, encryption, passwords)
#   Identify (ID) 25% - asset/risk awareness (role assignments, app inventory, stale accounts)
#   Detect (DE)   20% - monitoring & logging (audit logs, sign-in monitoring, alerts)
#   Respond (RS)  15% - incident handling (risk policies, automation, blocking)
#   Recover (RC)  10% - resilience (backup, SSPR, break-glass accounts)
#
# Score = weighted average of (1 - failRate) per function, adjusted by severity.
# Critical failures get 4x weight, High 2x, Medium 1x, Low 0.5x.

$nistWeights = @{}
$nistWeights['Protect'] = 0.30
$nistWeights['Identify'] = 0.25
$nistWeights['Detect'] = 0.20
$nistWeights['Respond'] = 0.15
$nistWeights['Recover'] = 0.10

# Severity multipliers for weighted failure impact
$severityMultiplier = @{}
$severityMultiplier['Critical'] = 4.0
$severityMultiplier['High'] = 2.0
$severityMultiplier['Medium'] = 1.0
$severityMultiplier['Low'] = 0.5

# Calculate NIST-weighted score from findings
$overallScore = 100
if ($FindingsCount -gt 0) {
    $critCount = $RiskSummary.CriticalCount
    $highCount = $RiskSummary.HighCount
    $medCount = $RiskSummary.MediumCount
    $lowCount = $RiskSummary.LowCount

    # Weighted failure impact: each finding contributes based on severity
    $weightedFailures = ($critCount * 4.0) + ($highCount * 2.0) + ($medCount * 1.0) + ($lowCount * 0.5)

    # Normalize: max reasonable impact caps at 100 weighted failures
    # This gives a smooth curve where 50 weighted failures = ~50 score
    $maxImpact = [Math]::Max(100, $weightedFailures)
    $failureRatio = $weightedFailures / $maxImpact

    # Score = 100 * (1 - failureRatio) with diminishing returns curve
    # Using sqrt to soften the penalty so the score doesn't crater too fast
    $overallScore = [Math]::Round(100 * (1 - [Math]::Sqrt($failureRatio) * 0.9), 0)
    $overallScore = [Math]::Max(0, [Math]::Min(100, $overallScore))
}

if ($overallScore -ge 80) { $scoreColor = "#107c10"; $scoreLabel = "STRONG" }
elseif ($overallScore -ge 60) { $scoreColor = "#ff8c00"; $scoreLabel = "MODERATE" }
else { $scoreColor = "#d13438"; $scoreLabel = "NEEDS ATTENTION" }

# MS Secure Score color
$msScoreColor = "#605e5c"
$msScoreLabel = "N/A"
if ($hasSecureScore) {
    if ($msSecureScorePercent -ge 80) { $msScoreColor = "#107c10"; $msScoreLabel = "STRONG" }
    elseif ($msSecureScorePercent -ge 60) { $msScoreColor = "#ff8c00"; $msScoreLabel = "MODERATE" }
    else { $msScoreColor = "#d13438"; $msScoreLabel = "NEEDS ATTENTION" }
}

# Generate HTML
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Summary - $TenantName Security Assessment</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        @media print {
            body { margin: 0; }
            .no-print { display: none; }
            @page { size: letter landscape; margin: 0.5in; }
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #323130;
            line-height: 1.4;
        }

        .page {
            max-width: 11in;
            margin: 20px auto;
            background: white;
            padding: 40px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        header {
            border-bottom: 3px solid #0078d4;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        h1 {
            font-size: 28px;
            color: #0078d4;
            margin-bottom: 5px;
        }

        .subtitle {
            font-size: 16px;
            color: #605e5c;
        }

        .hero {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }

        .hero-card {
            background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            text-align: center;
        }

        .hero-card.score {
            background: linear-gradient(135deg, $scoreColor 0%, darken($scoreColor, 10%) 100%);
            grid-column: span 1;
        }

        .hero-value {
            font-size: 48px;
            font-weight: 700;
            line-height: 1;
        }

        .hero-label {
            font-size: 14px;
            margin-top: 10px;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .metrics {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }

        .metric-card {
            background: #f3f2f1;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #0078d4;
        }

        .metric-card.critical { border-left-color: #d13438; }
        .metric-card.high { border-left-color: #ff8c00; }
        .metric-card.medium { border-left-color: #ffc83d; }
        .metric-card.low { border-left-color: #107c10; }
        .metric-card.review { border-left-color: #5c2d91; }

        .metric-value {
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
        }

        .metric-label {
            font-size: 12px;
            color: #605e5c;
            margin-top: 5px;
            text-transform: uppercase;
        }

        .section {
            margin-bottom: 25px;
        }

        h2 {
            font-size: 18px;
            color: #0078d4;
            margin-bottom: 12px;
            border-bottom: 2px solid #e1dfdd;
            padding-bottom: 8px;
        }

        .compliance-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
        }

        .compliance-item {
            background: white;
            border: 1px solid #e1dfdd;
            border-radius: 4px;
            padding: 15px;
            text-align: center;
        }

        .compliance-score {
            font-size: 28px;
            font-weight: 700;
            color: #0078d4;
        }

        .compliance-name {
            font-size: 12px;
            color: #605e5c;
            margin-top: 5px;
        }

        .quick-wins {
            background: #f0f9ff;
            border-left: 4px solid #0078d4;
            padding: 15px;
            border-radius: 4px;
        }

        .quick-wins-list {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 10px;
        }

        .quick-win-item {
            font-size: 13px;
            padding: 8px;
            background: white;
            border-radius: 4px;
        }

        .recommendations {
            background: #fff4ce;
            border-left: 4px solid #ff8c00;
            padding: 15px;
            border-radius: 4px;
        }

        .rec-list {
            margin-top: 10px;
        }

        .rec-item {
            font-size: 13px;
            padding: 6px 0;
            border-bottom: 1px solid rgba(0,0,0,0.1);
        }

        .rec-item:last-child {
            border-bottom: none;
        }

        footer {
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #e1dfdd;
            font-size: 11px;
            color: #8a8886;
            text-align: center;
        }

        .print-btn {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #0078d4;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }

        .print-btn:hover {
            background: #106ebe;
        }

        .score-methodology {
            font-size: 10px;
            opacity: 0.7;
            margin-top: 6px;
        }

        .hero-four {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }

        .hero-four .hero-card {
            padding: 20px;
        }

        .hero-four .hero-value {
            font-size: 36px;
        }
    </style>
</head>
<body>
    <button class="print-btn no-print" onclick="window.print()">&#128424; Print / Save as PDF</button>

    <div class="page">
        <header>
            <h1>Security Assessment Executive Summary</h1>
            <div class="subtitle">$TenantName | $assessmentDate</div>
        </header>

        <div class="hero-four">
"@

if ($hasSecureScore) {
    $html += @"
            <div class="hero-card" style="background: linear-gradient(135deg, $msScoreColor, #106ebe);">
                <div class="hero-value">$([math]::Round($msSecureScorePercent, 0))<span style="font-size: 18px; opacity: 0.8;">%</span></div>
                <div class="hero-label">Microsoft Secure Score</div>
                <div style="margin-top: 6px; font-weight: 600;">$msScoreLabel</div>
                <div class="score-methodology">$([math]::Round($msSecureScore.CurrentScore, 1)) of $([math]::Round($msSecureScore.MaxScore, 1)) pts</div>
            </div>
"@
}

$html += @"
            <div class="hero-card" style="background: linear-gradient(135deg, $scoreColor, #323130);">
                <div class="hero-value">$overallScore<span style="font-size: 18px; opacity: 0.8;">/100</span></div>
                <div class="hero-label">Assessment Score</div>
                <div style="margin-top: 6px; font-weight: 600;">$scoreLabel</div>
                <div class="score-methodology">NIST CSF Weighted</div>
            </div>
            <div class="hero-card">
                <div class="hero-value">$FindingsCount</div>
                <div class="hero-label">Total Findings</div>
            </div>
            <div class="hero-card">
                <div class="hero-value">$($QuickWins.Count)</div>
                <div class="hero-label">Quick Wins Available</div>
            </div>
        </div>

        <div class="section">
            <h2>Risk Distribution</h2>
            <div class="metrics">
                <div class="metric-card critical">
                    <div class="metric-value">$($RiskSummary.CriticalCount)</div>
                    <div class="metric-label">Critical Risk</div>
                </div>
                <div class="metric-card high">
                    <div class="metric-value">$($RiskSummary.HighCount)</div>
                    <div class="metric-label">High Risk</div>
                </div>
                <div class="metric-card medium">
                    <div class="metric-value">$($RiskSummary.MediumCount)</div>
                    <div class="metric-label">Medium Risk</div>
                </div>
                <div class="metric-card low">
                    <div class="metric-value">$($RiskSummary.LowCount)</div>
                    <div class="metric-label">Low Risk</div>
                </div>
                <div class="metric-card review">
                    <div class="metric-value">$(if ($null -ne $RiskSummary.ReviewCount) { $RiskSummary.ReviewCount } else { 0 })</div>
                    <div class="metric-label">To Review</div>
                </div>
            </div>
        </div>
"@

# Add compliance section - prefer real Defender data, fallback to subjective mappings
$hasDefenderData = ($ExternalData -and
    $ExternalData.DefenderCompliance -and
    $ExternalData.DefenderCompliance.Summary -and
    $ExternalData.DefenderCompliance.Summary.TotalStandards -gt 0)

if ($hasDefenderData) {
    $dc = $ExternalData.DefenderCompliance
    $html += @"

        <div class="section">
            <h2>Regulatory Compliance (Defender for Cloud)</h2>
            <div class="compliance-grid">
"@

    $standardsShown = 0
    foreach ($sub in $dc.Subscriptions) {
        foreach ($std in $sub.Standards) {
            if ($standardsShown -ge 4) { break }
            $total = $std.PassedControls + $std.FailedControls
            $pct = if ($total -gt 0) { [math]::Round(($std.PassedControls / $total) * 100, 0) } else { 0 }

            $html += @"
                <div class="compliance-item">
                    <div class="compliance-score">$pct%</div>
                    <div class="compliance-name">$($std.ShortName) ($($std.PassedControls)/$total)</div>
                </div>
"@
            $standardsShown++
        }
        if ($standardsShown -ge 4) { break }
    }

    $html += @"
            </div>
        </div>
"@
}
elseif ($ComplianceMappings -and $ComplianceMappings.Count -gt 0) {
    $html += @"

        <div class="section">
            <h2>Compliance Framework Coverage</h2>
            <div class="compliance-grid">
"@

    foreach ($framework in @("CIS", "NIST", "SOC2", "PCI")) {
        if ($ComplianceMappings[$framework]) {
            $passed = ($ComplianceMappings[$framework] | Where-Object { $_.Status -eq 'Passed' }).Count
            $total = $ComplianceMappings[$framework].Count
            $percent = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 0) } else { 0 }

            $html += @"
                <div class="compliance-item">
                    <div class="compliance-score">$percent%</div>
                    <div class="compliance-name">$framework Coverage</div>
                </div>
"@
        }
    }

    $html += @"
            </div>
        </div>
"@
}

# Add Quick Wins section
if ($QuickWins -and $QuickWins.Count -gt 0) {
    $topQuickWins = $QuickWins | Select-Object -First 6
    $html += @"

        <div class="section">
            <h2>Top Quick Wins (High Impact, Low Effort)</h2>
            <div class="quick-wins">
                <div class="quick-wins-list">
"@

    foreach ($win in $topQuickWins) {
        $html += @"
                    <div class="quick-win-item">&#10003; $($win.Description -replace '<[^>]+>', '')</div>
"@
    }

    $html += @"
                </div>
            </div>
        </div>
"@
}

# Add recommendations
$html += @"

        <div class="section">
            <h2>Key Recommendations</h2>
            <div class="recommendations">
                <div class="rec-list">
"@

if ($RiskSummary.CriticalCount -gt 0) {
    $html += @"
                    <div class="rec-item"><strong>IMMEDIATE:</strong> Address $($RiskSummary.CriticalCount) critical risk findings within 24-48 hours</div>
"@
}

if ($RiskSummary.HighCount -gt 0) {
    $html += @"
                    <div class="rec-item"><strong>SHORT-TERM:</strong> Remediate $($RiskSummary.HighCount) high-risk findings within 30 days</div>
"@
}

if ($QuickWins -and $QuickWins.Count -gt 0) {
    $html += @"
                    <div class="rec-item"><strong>QUICK WINS:</strong> Implement $($QuickWins.Count) low-effort, high-impact improvements</div>
"@
}

if ($ComplianceMappings) {
    $html += @"
                    <div class="rec-item"><strong>COMPLIANCE:</strong> Review detailed compliance gap analysis for regulatory alignment</div>
"@
}

$html += @"
                    <div class="rec-item"><strong>ONGOING:</strong> Schedule monthly security assessments to track improvements</div>
                </div>
            </div>
        </div>

        <footer>
            <p>Generated by EntraChecks v2.0 | Security Assessment Platform</p>
            <p>For detailed technical findings and remediation guidance, refer to the comprehensive assessment report</p>
        </footer>
    </div>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

return $OutputPath
