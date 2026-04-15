# EntraChecks Enhanced HTML Reporting Module
# Generates comprehensive HTML reports with executive dashboard

<#
.SYNOPSIS
    Generates enhanced HTML reports for EntraChecks findings.

.DESCRIPTION
    Creates interactive HTML reports with:
    - Executive dashboard with risk summary
    - Compliance framework mapping
    - Risk scoring and prioritization
    - Actionable remediation guidance
    - Interactive filtering and search
    - Professional styling for IT leadership

.NOTES
    Author: David Stells
    Version: 1.0.0
#>

# Import dependent modules
$modulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $modulePath "EntraChecks-ComplianceMapping.psm1") -Force
Import-Module (Join-Path $modulePath "EntraChecks-RiskScoring.psm1") -Force -DisableNameChecking
Import-Module (Join-Path $modulePath "EntraChecks-RemediationGuidance.psm1") -Force
# NOTE: EntraChecks-Branding.psm1 provides Get-ReportBrandingContext, which
# callers can use to construct the -Branding object passed to
# New-EnhancedHTMLReport. We don't import it here — only its output is
# consumed inside this module — so the caller's import scope wins.

# Module-scoped list of check names that produce findings the team has flagged
# as fixture-verified-only / low-confidence. Empty by default — populate per
# environment via $module:LowConfidenceCheckNames or by editing this file.
$script:LowConfidenceCheckNames = @()

#region HTML Generation Functions

function New-EnhancedHTMLReport {
    <#
    .SYNOPSIS
        Generates an enhanced HTML report with executive dashboard.

    .DESCRIPTION
        Creates a comprehensive HTML report integrating risk scoring, compliance mapping,
        and remediation guidance with interactive features.

    .PARAMETER Findings
        Array of finding objects to include in the report

    .PARAMETER OutputPath
        Path where the HTML report will be saved

    .PARAMETER TenantInfo
        Tenant information object (TenantId, TenantName, etc.)

    .PARAMETER PreviousAssessment
        Optional previous assessment data for delta comparison

    .PARAMETER IncludeSections
        Sections to include: All, Executive, Detailed, Compliance, Remediation

    .EXAMPLE
        New-EnhancedHTMLReport -Findings $findings -OutputPath "report.html" -TenantInfo $tenantInfo
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

        [object]$PreviousAssessment,

        [object]$DefenderCompliance,

        # New in PR 2 — surface data the orchestrator already collects but
        # that the unified report previously discarded. All three are optional;
        # missing data renders a "Not collected" placeholder so the user knows
        # the section exists but was skipped.
        [object]$SecureScore,

        [object]$AzurePolicy,

        [object]$PurviewCompliance,

        # PR 2 (AD-Hybrid): output of Get-HybridIdentityCorrelation. When
        # provided, a new "Hybrid Correlation" section renders showing
        # principals flagged in BOTH cloud and on-prem findings.
        [object]$HybridCorrelation,

        # PR 3 backports.
        # Branding context (Get-ReportBrandingContext output). When provided,
        # overrides report title, header gradient, organization name, and logo.
        [object]$Branding,

        # Default-true so the integrity badge ships in every report. Pass
        # -IncludeIntegrityBadge:$false to suppress (e.g., for HTML diffs in CI).
        [bool]$IncludeIntegrityBadge = $true,

        # Default-true so the executive digest renders by default.
        [bool]$IncludeExecutiveDigest = $true,

        # Override the module-scoped low-confidence list per call.
        [string[]]$LowConfidenceCheckNames,

        [string[]]$IncludeSections = @('All')
    )

    # Enhance findings with risk scoring, compliance mapping, and remediation
    $enhancedFindings = @()
    foreach ($finding in $Findings) {
        $enhanced = $finding |
            Add-RiskScoring |
            Add-ComplianceMapping |
            Add-RemediationGuidance
        $enhancedFindings += $enhanced
    }

    # Deduplicate findings by Description + Object to prevent repeated entries
    $seen = @{}
    $deduped = @()
    foreach ($f in $enhancedFindings) {
        $key = "$($f.Description)|$($f.Object)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $deduped += $f
        }
    }
    $enhancedFindings = $deduped

    # Calculate summaries
    $riskSummary = Get-RiskSummary -Findings $enhancedFindings
    $complianceGap = Get-ComplianceGapReport -Findings $enhancedFindings -Framework 'All'
    $quickWins = Get-QuickWins -Findings $enhancedFindings
    $prioritized = Get-PrioritizedFindings -Findings $enhancedFindings

    # Compute findings delta if a previous assessment was supplied. Accepts
    # either a snapshot object (with a .Findings array) or a bare findings
    # array — both shapes are reasonable inputs for callers.
    $findingsDelta = $null
    if ($PreviousAssessment) {
        $previousFindings = if ($PreviousAssessment.PSObject.Properties['Findings']) {
            $PreviousAssessment.Findings
        }
        else {
            @($PreviousAssessment)
        }
        $findingsDelta = Get-FindingsDelta -Current $enhancedFindings -Previous $previousFindings
    }

    # PR 3: resolve effective low-confidence list (per-call override falls back
    # to module-scoped default).
    $effectiveLowConfidence = if ($PSBoundParameters.ContainsKey('LowConfidenceCheckNames')) {
        $LowConfidenceCheckNames
    }
    else {
        $script:LowConfidenceCheckNames
    }

    # PR 3: compute the executive digest once so it can flow into the cover
    # block and any downstream summary rendering.
    $execDigest = $null
    if ($IncludeExecutiveDigest) {
        $execDigest = Get-EntraChecksExecutiveDigest -Findings $enhancedFindings -RiskSummary $riskSummary -ComplianceGap $complianceGap -FindingsDelta $findingsDelta
    }

    # PR 3: low-confidence banner — present when any rendered finding is on
    # the configured fixture-verified list.
    $lowConfidenceBanner = ""
    if ($effectiveLowConfidence -and $effectiveLowConfidence.Count -gt 0) {
        $hits = @($enhancedFindings | Where-Object {
                $_.CheckName -and ($effectiveLowConfidence -contains $_.CheckName)
            })
        if ($hits.Count -gt 0) {
            $checkList = ($hits.CheckName | Select-Object -Unique | Sort-Object) -join ', '
            $lowConfidenceBanner = @"
    <div class="low-confidence-banner">
        <strong>Low-confidence checks present.</strong>
        $($hits.Count) finding(s) come from fixture-verified checks
        ($([System.Net.WebUtility]::HtmlEncode($checkList))).
        Treat these as advisory until validated against your live tenant.
    </div>
"@
        }
    }

    # PR 3: branding — overrides report title, header gradient, org name, logo.
    $brandedTitleHtml = "&#128274; Microsoft Entra ID Security Assessment"
    $brandedOrgHtml = ""
    $headerStyleAttr = ""
    if ($Branding) {
        if ($Branding.ReportTitle) {
            $brandedTitleHtml = [System.Web.HttpUtility]::HtmlEncode([string]$Branding.ReportTitle)
        }
        if ($Branding.LogoDataUri) {
            $brandedTitleHtml = "<img class='branded-logo' src='$($Branding.LogoDataUri)' alt='logo' /> $brandedTitleHtml"
        }
        if ($Branding.OrganizationName) {
            $brandedOrgHtml = "<p><strong>Organization:</strong> $([System.Web.HttpUtility]::HtmlEncode([string]$Branding.OrganizationName))</p>"
        }
        if ($Branding.PrimaryColor) {
            $headerStyleAttr = " style=`"--brand-primary: $($Branding.PrimaryColor); background: $($Branding.PrimaryColor) !important;`""
        }
    }

    # PR 3: integrity badge — SHA-256 of the canonical findings JSON, written to
    # a sibling .findings.json so Test-EntraChecksReportIntegrity can verify.
    $integrityBlock = ""
    if ($IncludeIntegrityBadge) {
        $integrityBlock = New-IntegrityBlock -EnhancedFindings $enhancedFindings -OutputPath $OutputPath
    }

    # Generate HTML sections
    $htmlHead = Get-HTMLHead
    $htmlNav = Get-HTMLNavigation
    $htmlDigest = if ($execDigest) { Format-ExecutiveDigest -Digest $execDigest -TenantInfo $TenantInfo } else { "" }
    $htmlExecutive = Get-ExecutiveDashboard -RiskSummary $riskSummary -ComplianceGap $complianceGap -TenantInfo $TenantInfo -DefenderCompliance $DefenderCompliance -FindingsDelta $findingsDelta
    $htmlQuickWins = Get-QuickWinsSection -QuickWins $quickWins
    $htmlPriority = Get-PrioritySection -PrioritizedFindings $prioritized
    $htmlCompliance = Get-ComplianceSection -Findings $enhancedFindings -ComplianceGap $complianceGap -DefenderCompliance $DefenderCompliance
    $htmlSecureScore = Get-SecureScoreSection -SecureScore $SecureScore
    $htmlAzurePolicy = Get-AzurePolicySection -AzurePolicy $AzurePolicy
    $htmlPurview = Get-PurviewSection -PurviewCompliance $PurviewCompliance
    $htmlHybridCorr = Get-HybridCorrelationSection -HybridCorrelation $HybridCorrelation
    $htmlDetailed = Get-DetailedFindingsSection -Findings $enhancedFindings -LowConfidenceCheckNames $effectiveLowConfidence
    $htmlJavaScript = Get-HTMLJavaScript

    # Assemble complete HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Entra ID Security Assessment - $($TenantInfo.TenantName)</title>
    $htmlHead
</head>
<body>
    $htmlNav
    <div class="container">
        <header class="report-header branded-header"$headerStyleAttr>
            <h1>$brandedTitleHtml</h1>
            <div class="tenant-info">
                $brandedOrgHtml
                <p><strong>Tenant:</strong> $($TenantInfo.TenantName)</p>
                <p><strong>Tenant ID:</strong> $($TenantInfo.TenantId)</p>
                <p><strong>Report Generated:</strong> $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss")</p>
                <p><strong>Total Findings:</strong> $($Findings.Count)</p>
            </div>
        </header>

        $lowConfidenceBanner
        $htmlDigest
        $htmlExecutive
        $htmlQuickWins
        $htmlPriority
        $htmlCompliance
        $htmlSecureScore
        $htmlAzurePolicy
        $htmlPurview
        $htmlHybridCorr
        $htmlDetailed
        $integrityBlock
    </div>
    $htmlJavaScript
</body>
</html>
"@

    # Write to file
    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Verbose "Enhanced HTML report generated: $OutputPath"

    return $OutputPath
}

function Get-HTMLHead {
    return @'
<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #f5f7fa;
        color: #333;
        line-height: 1.6;
    }

    .container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 20px;
    }

    .report-header {
        background: linear-gradient(135deg, #0078d4 0%, #0053a6 100%);
        color: white;
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 30px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }

    .report-header h1 {
        font-size: 2.5em;
        margin-bottom: 15px;
    }

    .tenant-info {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 10px;
        margin-top: 15px;
    }

    .tenant-info p {
        background: rgba(255, 255, 255, 0.2);
        padding: 10px;
        border-radius: 4px;
    }

    /* Navigation */
    .nav-bar {
        background: white;
        padding: 15px 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        position: sticky;
        top: 0;
        z-index: 1000;
        margin-bottom: 20px;
    }

    .nav-bar ul {
        list-style: none;
        display: flex;
        gap: 20px;
        flex-wrap: wrap;
    }

    .nav-bar a {
        color: #0078d4;
        text-decoration: none;
        font-weight: 500;
        padding: 8px 15px;
        border-radius: 4px;
        transition: background 0.3s;
    }

    .nav-bar a:hover {
        background: #f0f0f0;
    }

    /* Executive Dashboard */
    .executive-dashboard {
        background: white;
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 30px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .dashboard-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }

    .metric-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #ffffff 100%);
        padding: 20px;
        border-radius: 8px;
        border-left: 4px solid #0078d4;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }

    .metric-card.critical {
        border-left-color: #d13438;
    }

    .metric-card.high {
        border-left-color: #ff8c00;
    }

    .metric-card.medium {
        border-left-color: #ffb900;
    }

    .metric-card.low {
        border-left-color: #107c10;
    }

    .metric-value {
        font-size: 2.5em;
        font-weight: bold;
        margin: 10px 0;
    }

    .metric-label {
        font-size: 0.9em;
        color: #666;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Risk Level Badges */
    .risk-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: 600;
        text-transform: uppercase;
    }

    .risk-badge.critical {
        background: #d13438;
        color: white;
    }

    .risk-badge.high {
        background: #ff8c00;
        color: white;
    }

    .risk-badge.medium {
        background: #ffb900;
        color: #000;
    }

    .risk-badge.low {
        background: #107c10;
        color: white;
    }

    .risk-badge.info {
        background: #0078d4;
        color: white;
    }

    /* Sections */
    .section {
        background: white;
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 30px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .section-title {
        font-size: 1.8em;
        margin-bottom: 20px;
        color: #0078d4;
        border-bottom: 2px solid #0078d4;
        padding-bottom: 10px;
    }

    /* Quick Wins */
    .quick-wins-grid {
        display: grid;
        gap: 15px;
        margin-top: 20px;
    }

    .quick-win-card {
        background: #fff4ce;
        padding: 20px;
        border-radius: 8px;
        border-left: 4px solid #ffb900;
    }

    .quick-win-card h3 {
        color: #333;
        margin-bottom: 10px;
    }

    .quick-win-meta {
        display: flex;
        gap: 20px;
        margin-top: 10px;
        flex-wrap: wrap;
    }

    .quick-win-meta span {
        background: white;
        padding: 5px 10px;
        border-radius: 4px;
        font-size: 0.9em;
    }

    /* Priority Table */
    .priority-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
    }

    .priority-table th {
        background: #0078d4;
        color: white;
        padding: 12px;
        text-align: left;
        font-weight: 600;
    }

    .priority-table td {
        padding: 12px;
        border-bottom: 1px solid #e0e0e0;
    }

    .priority-table tr:hover {
        background: #f5f7fa;
    }

    .priority-score {
        font-size: 1.2em;
        font-weight: bold;
        color: #0078d4;
    }

    /* Compliance Grid */
    .compliance-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }

    .compliance-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #ffffff 100%);
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }

    .compliance-card h3 {
        color: #0078d4;
        margin-bottom: 15px;
    }

    .compliance-stat {
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        border-bottom: 1px solid #e0e0e0;
    }

    /* Detailed Findings */
    .finding-card {
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        margin-bottom: 20px;
        overflow: hidden;
    }

    .finding-header {
        padding: 20px;
        background: #f5f7fa;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .finding-header:hover {
        background: #e8eef5;
    }

    .finding-title {
        font-weight: 600;
        font-size: 1.1em;
    }

    .finding-body {
        padding: 20px;
        display: none;
    }

    .finding-body.active {
        display: block;
    }

    .finding-meta {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
        margin: 15px 0;
        padding: 15px;
        background: #f5f7fa;
        border-radius: 4px;
    }

    .remediation-steps {
        background: #e7f3ff;
        padding: 15px;
        border-radius: 4px;
        margin-top: 15px;
    }

    .remediation-steps h4 {
        color: #0078d4;
        margin-bottom: 10px;
    }

    .remediation-steps ol {
        margin-left: 20px;
    }

    .remediation-steps li {
        margin-bottom: 8px;
    }

    /* Search and Filters */
    .controls-bar {
        background: white;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .controls-bar input,
    .controls-bar select {
        padding: 10px;
        border: 1px solid #ddd;
        border-radius: 4px;
        font-size: 1em;
        margin-right: 10px;
    }

    .controls-bar input {
        width: 300px;
    }

    /* Print Styles */
    @media print {
        .nav-bar,
        .controls-bar,
        .expand-all-btn {
            display: none;
        }

        .finding-body {
            display: block !important;
        }

        body {
            background: white;
        }

        .section {
            box-shadow: none;
            page-break-inside: avoid;
        }
    }

    /* Responsive */
    @media (max-width: 768px) {
        .dashboard-grid,
        .compliance-grid {
            grid-template-columns: 1fr;
        }

        .report-header h1 {
            font-size: 1.8em;
        }

        .controls-bar input {
            width: 100%;
            margin-bottom: 10px;
        }
    }

    .code-block {
        background: #1e1e1e;
        color: #d4d4d4;
        padding: 15px;
        border-radius: 4px;
        overflow-x: auto;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.9em;
        margin: 10px 0;
    }

    .expand-all-btn {
        background: #0078d4;
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 1em;
        margin-bottom: 15px;
    }

    .expand-all-btn:hover {
        background: #0053a6;
    }

    /* Category Accordions */
    .category-accordion {
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        margin-bottom: 12px;
        overflow: hidden;
    }

    .category-header {
        padding: 16px 20px;
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
        user-select: none;
        transition: background 0.2s;
    }

    .category-header:hover {
        background: linear-gradient(135deg, #e9ecef 0%, #dee2e6 100%);
    }

    .category-title {
        font-weight: 700;
        font-size: 1.15em;
        color: #333;
    }

    .category-badges {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }

    .category-badges .count-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.8em;
        font-weight: 600;
    }

    .count-badge.fail-badge { background: #d13438; color: white; }
    .count-badge.warning-badge { background: #ff8c00; color: white; }
    .count-badge.ok-badge { background: #107c10; color: white; }
    .count-badge.info-badge { background: #0078d4; color: white; }

    .category-arrow {
        font-size: 0.9em;
        transition: transform 0.2s;
        color: #666;
    }

    .category-arrow.open { transform: rotate(180deg); }

    .category-body {
        display: none;
        padding: 0 16px 16px 16px;
    }

    .category-body.active {
        display: block;
    }

    /* Status Sub-Accordions */
    .status-accordion {
        border: 1px solid #e8e8e8;
        border-radius: 6px;
        margin-top: 10px;
        overflow: hidden;
    }

    .status-header {
        padding: 12px 16px;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
        user-select: none;
        transition: background 0.2s;
    }

    .status-header:hover { opacity: 0.9; }

    .status-header.fail-header { background: #fde7e8; border-left: 4px solid #d13438; }
    .status-header.warning-header { background: #fff4ce; border-left: 4px solid #ff8c00; }
    .status-header.ok-header { background: #dff6dd; border-left: 4px solid #107c10; }
    .status-header.info-header { background: #e7f3ff; border-left: 4px solid #0078d4; }

    .status-title {
        font-weight: 600;
        font-size: 1em;
    }

    .status-arrow {
        font-size: 0.85em;
        transition: transform 0.2s;
        color: #666;
    }

    .status-arrow.open { transform: rotate(180deg); }

    .status-body {
        display: none;
        padding: 8px 12px 12px 12px;
    }

    .status-body.active {
        display: block;
    }

    /* Filter controls enhancements */
    .controls-bar {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        align-items: center;
    }

    .filter-group {
        display: flex;
        align-items: center;
        gap: 6px;
    }

    .filter-group label {
        font-size: 0.85em;
        font-weight: 600;
        color: #555;
    }

    .controls-bar select {
        min-width: 140px;
    }

    .clear-filters-btn {
        background: #f0f0f0;
        color: #333;
        border: 1px solid #ccc;
        padding: 10px 16px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 0.95em;
    }

    .clear-filters-btn:hover {
        background: #e0e0e0;
    }

    .filter-count {
        font-size: 0.85em;
        color: #666;
        margin-left: auto;
    }

    /* Compliance Progress Bars (Defender for Cloud real data) */
    .compliance-source-label {
        font-size: 0.8em;
        color: #8a8886;
        margin-bottom: 15px;
        font-style: italic;
    }

    .compliance-standard-card {
        background: white;
        border: 1px solid #e1dfdd;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 15px;
    }

    .compliance-standard-card h3 {
        font-size: 1.05em;
        color: #323130;
        margin-bottom: 12px;
    }

    .compliance-progress-bar {
        background: #e1dfdd;
        border-radius: 6px;
        height: 24px;
        overflow: hidden;
        margin-bottom: 10px;
        position: relative;
    }

    .compliance-progress-fill {
        height: 100%;
        border-radius: 6px;
        transition: width 0.3s;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 0.8em;
        font-weight: 600;
        min-width: 40px;
    }

    .compliance-progress-fill.high { background: #107c10; }
    .compliance-progress-fill.medium { background: #ff8c00; }
    .compliance-progress-fill.low { background: #d13438; }

    .compliance-stats-row {
        display: flex;
        gap: 20px;
        font-size: 0.85em;
        color: #605e5c;
        margin-bottom: 8px;
    }

    .compliance-stats-row span {
        display: flex;
        align-items: center;
        gap: 4px;
    }

    .stat-passed { color: #107c10; font-weight: 600; }
    .stat-failed { color: #d13438; font-weight: 600; }

    .compliance-detail-toggle {
        background: none;
        border: 1px solid #0078d4;
        color: #0078d4;
        padding: 4px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 0.8em;
        margin-top: 4px;
    }

    .compliance-detail-toggle:hover {
        background: #0078d4;
        color: white;
    }

    .compliance-detail-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 12px;
        font-size: 0.85em;
        display: none;
    }

    .compliance-detail-table.active {
        display: table;
    }

    .compliance-detail-table th {
        background: #f3f2f1;
        text-align: left;
        padding: 8px 12px;
        font-weight: 600;
        border-bottom: 2px solid #e1dfdd;
    }

    .compliance-detail-table td {
        padding: 6px 12px;
        border-bottom: 1px solid #f3f2f1;
    }

    .compliance-detail-table tr:hover td {
        background: #f8f8f8;
    }

    .control-status-passed { color: #107c10; font-weight: 600; }
    .control-status-failed { color: #d13438; font-weight: 600; }
    .control-status-na { color: #8a8886; }

    .compliance-fallback-note {
        font-size: 0.8em;
        color: #8a8886;
        font-style: italic;
        margin-top: 10px;
    }

    /* PR 3 backports: exec digest + verdict */
    .exec-digest {
        background: white;
        padding: 24px;
        border-radius: 8px;
        margin-bottom: 30px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        border-left: 6px solid #0078d4;
    }
    .exec-digest h2 { margin-bottom: 8px; }
    .exec-digest .verdict-line { font-size: 1.05em; margin: 8px 0 16px 0; }
    .exec-verdict { display: inline-block; padding: 3px 12px; border-radius: 3px; font-weight: 700; font-size: 0.95em; margin-left: 6px; }
    .verdict-strong { background: #def4dc; color: #1f6f1a; }
    .verdict-minor { background: #fff4d4; color: #7b5e00; }
    .verdict-gaps { background: #fadbd8; color: #8a1f1a; }
    .verdict-insufficient { background: #e1dfdd; color: #605e5c; }
    .exec-digest .top-list { margin-top: 8px; }
    .exec-digest .top-list li { margin: 3px 0 3px 20px; }

    /* Low-confidence callouts */
    .low-confidence-banner { background: #fff8e1; border-left: 6px solid #d89b00; padding: 12px 16px; margin: 16px 0; border-radius: 4px; font-size: 0.9em; }
    .low-confidence-banner strong { color: #7b5e00; }
    .low-confidence-tag { display: inline-block; background: #fff8e1; color: #7b5e00; padding: 1px 6px; border-radius: 3px; font-size: 0.75em; margin-left: 6px; }

    /* Per-finding deep links */
    .finding-anchor { font-size: 0.75em; opacity: 0.4; margin-left: 8px; cursor: pointer; text-decoration: none; }
    .finding-anchor:hover { opacity: 1; }
    .finding-anchor.copied { opacity: 1; color: #107c10; }

    /* Integrity footer */
    .integrity-footer { margin-top: 40px; padding: 16px 24px; background: #f8f8f8; border-radius: 4px; font-size: 0.85em; color: #605e5c; }
    .integrity-footer .badge { display: inline-block; padding: 2px 8px; background: #def4dc; color: #1f6f1a; border-radius: 3px; font-weight: 600; margin-right: 6px; }
    .integrity-footer .hash { font-family: 'Cascadia Code', Consolas, monospace; word-break: break-all; }

    /* White-label branding override hooks */
    .branded-header { background: var(--brand-primary, linear-gradient(135deg, #0078d4 0%, #0053a6 100%)) !important; }
    .branded-logo { max-height: 48px; vertical-align: middle; margin-right: 14px; }

    /* Print stylesheet */
    @media print {
        body { background: white; color: black; }
        .nav-bar, .controls-bar, .finding-anchor { display: none; }
        .container { max-width: none; padding: 0; }
        .report-header { background: white !important; color: black !important; box-shadow: none; border: 1px solid #d0d5dc; page-break-after: avoid; }
        .report-header h1 { color: black; }
        .tenant-info p { background: white; color: black; border: 1px solid #d0d5dc; }
        section, .exec-digest, .metric-card { break-inside: avoid; page-break-inside: avoid; box-shadow: none; }
        .low-confidence-banner { break-inside: avoid; }
        .finding-row { break-inside: avoid; page-break-inside: avoid; }
        a[href^="#"] { text-decoration: none; color: inherit; }
        * { -webkit-print-color-adjust: exact !important; color-adjust: exact !important; print-color-adjust: exact !important; }
    }
</style>
'@
}

function Get-HTMLNavigation {
    return @'
<nav class="nav-bar">
    <ul>
        <li><a href="#executive">Executive Summary</a></li>
        <li><a href="#quick-wins">Quick Wins</a></li>
        <li><a href="#priority">Priority Findings</a></li>
        <li><a href="#compliance">Compliance Mapping</a></li>
        <li><a href="#secure-score">Secure Score</a></li>
        <li><a href="#azure-policy">Azure Policy</a></li>
        <li><a href="#purview">Purview</a></li>
        <li><a href="#hybrid-correlation">Hybrid Correlation</a></li>
        <li><a href="#detailed">Detailed Findings</a></li>
    </ul>
</nav>
'@
}

function Get-NotCollectedPlaceholder {
    <#
    .SYNOPSIS
        Standard "data not collected" callout for unified-report sections.
    #>
    param(
        [Parameter(Mandatory)] [string]$SectionName,
        [Parameter(Mandatory)] [string]$Hint
    )
    return @"
    <div class="compliance-fallback-note" style="padding: 16px; background: #f5f5f5; border-left: 4px solid #b0b7c3; border-radius: 4px;">
        <p><strong>Not collected:</strong> ${SectionName} data was not provided to this report.</p>
        <p>$Hint</p>
    </div>
"@
}

function Get-SecureScoreSection {
    <#
    .SYNOPSIS
        Renders the Secure Score section of the unified report.
    .DESCRIPTION
        Accepts the hashtable shape returned by Get-SecureScore. Optionally also
        renders the top improvement actions when SecureScore.ImprovementActions
        is present (caller can attach this in advance).
    #>
    param([object]$SecureScore)

    $hint = 'To populate this section, run the orchestrator with Secure Score collection enabled (menu [4] or pass a SecureScore object via -SecureScore on direct calls).'
    if (-not $SecureScore) {
        return @"
<section class="secure-score" id="secure-score">
    <h2 class="section-title">&#127919; Microsoft Secure Score</h2>
    $(Get-NotCollectedPlaceholder -SectionName 'Microsoft Secure Score' -Hint $hint)
</section>
"@
    }

    $score = if ($null -ne $SecureScore.CurrentScore) { $SecureScore.CurrentScore } else { 0 }
    $maxScore = if ($null -ne $SecureScore.MaxScore) { $SecureScore.MaxScore } else { 0 }
    $pct = if ($null -ne $SecureScore.ScorePercent) {
        $SecureScore.ScorePercent
    }
    elseif ($maxScore -gt 0) {
        [math]::Round(($score / $maxScore) * 100, 1)
    }
    else { 0 }
    $color = if ($pct -ge 80) { 'low' } elseif ($pct -ge 60) { 'medium' } else { 'critical' }

    # Improvement actions are attached by the caller as an .ImprovementActions
    # member. Works for both hashtables (member access falls back to lookup)
    # and PSCustomObjects.
    $actionsRows = ""
    if ($null -ne $SecureScore.ImprovementActions) {
        $top10 = $SecureScore.ImprovementActions | Select-Object -First 10
        foreach ($a in $top10) {
            $linkCell = if ($a.ActionUrl) {
                "<a href='$([System.Net.WebUtility]::HtmlEncode($a.ActionUrl))' target='_blank' rel='noopener'>Open in portal</a>"
            }
            else { '&mdash;' }
            $title = [System.Net.WebUtility]::HtmlEncode([string]$a.Title)
            $cat = [System.Net.WebUtility]::HtmlEncode([string]$a.Category)
            $status = [System.Net.WebUtility]::HtmlEncode([string]$a.ImplementationStatus)
            $cost = [System.Net.WebUtility]::HtmlEncode([string]$a.ImplementationCost)
            $impact = [System.Net.WebUtility]::HtmlEncode([string]$a.UserImpact)
            $actionsRows += "<tr><td>$title</td><td>$cat</td><td>$status</td><td>+$($a.PotentialImprovement)</td><td>$cost</td><td>$impact</td><td>$linkCell</td></tr>`n"
        }
    }
    $actionsTable = if ($actionsRows) {
        @"
    <h3 style="margin-top: 24px;">Top improvement actions (by priority)</h3>
    <table>
        <thead><tr><th>Action</th><th>Category</th><th>Status</th><th>Potential</th><th>Cost</th><th>User impact</th><th>Portal</th></tr></thead>
        <tbody>$actionsRows</tbody>
    </table>
"@
    }
    else {
        '<p class="compliance-fallback-note">Improvement actions were not provided. Pass <code>Get-SecureScoreImprovementActions</code> output on a <code>.ImprovementActions</code> property to populate this table.</p>'
    }

    return @"
<section class="secure-score" id="secure-score">
    <h2 class="section-title">&#127919; Microsoft Secure Score</h2>
    <div class="dashboard-grid">
        <div class="metric-card $color">
            <div class="metric-label">Current Score</div>
            <div class="metric-value">$score / $maxScore</div>
            <div>$pct% of attainable</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Active Users</div>
            <div class="metric-value">$($SecureScore.ActiveUserCount)</div>
            <div>of $($SecureScore.LicensedUserCount) licensed</div>
        </div>
    </div>
    $actionsTable
</section>
"@
}

function Get-AzurePolicySection {
    <#
    .SYNOPSIS
        Renders the Azure Policy compliance section of the unified report.
    .DESCRIPTION
        Accepts the hashtable shape returned by Get-AzurePolicyComplianceAssessment.
    #>
    param([object]$AzurePolicy)

    $hint = 'To populate this section, run the orchestrator with Azure Policy collection enabled (menu [6] or pass an AzurePolicy object via -AzurePolicy).'
    if (-not $AzurePolicy) {
        return @"
<section class="azure-policy" id="azure-policy">
    <h2 class="section-title">&#9889; Azure Policy Compliance</h2>
    $(Get-NotCollectedPlaceholder -SectionName 'Azure Policy' -Hint $hint)
</section>
"@
    }

    $summary = $AzurePolicy.Summary
    $totalSubs = if ($summary.TotalSubscriptions) { $summary.TotalSubscriptions } else { 0 }
    $nonCompliantPolicies = if ($summary.NonCompliantPolicies) { $summary.NonCompliantPolicies } else { 0 }
    $nonCompliantResources = if ($summary.NonCompliantResources) { $summary.NonCompliantResources } else { 0 }
    $totalResources = if ($summary.TotalResources) { $summary.TotalResources } else { 0 }

    $compliancePct = if ($totalResources -gt 0) {
        [math]::Round((($totalResources - $nonCompliantResources) / $totalResources) * 100, 1)
    }
    else { 0 }
    $color = if ($compliancePct -ge 80) { 'low' } elseif ($compliancePct -ge 60) { 'medium' } else { 'critical' }

    $initiativeRows = ""
    if ($AzurePolicy.Initiatives -and $AzurePolicy.Initiatives.Keys.Count -gt 0) {
        foreach ($key in ($AzurePolicy.Initiatives.Keys | Sort-Object)) {
            $init = $AzurePolicy.Initiatives[$key]
            $name = [System.Net.WebUtility]::HtmlEncode([string]$init.DisplayName)
            $framework = [System.Net.WebUtility]::HtmlEncode([string]$init.Framework)
            $subCount = if ($init.Subscriptions) { @($init.Subscriptions).Count } else { 0 }
            $initiativeRows += "<tr><td>$name</td><td>$framework</td><td>$subCount</td></tr>`n"
        }
    }
    $initiativesTable = if ($initiativeRows) {
        @"
    <h3 style="margin-top: 24px;">Built-in initiatives in scope</h3>
    <table>
        <thead><tr><th>Initiative</th><th>Framework</th><th>Subscriptions</th></tr></thead>
        <tbody>$initiativeRows</tbody>
    </table>
"@
    }
    else {
        '<p class="compliance-fallback-note">No regulatory initiatives detected in the assigned policy set.</p>'
    }

    return @"
<section class="azure-policy" id="azure-policy">
    <h2 class="section-title">&#9889; Azure Policy Compliance</h2>
    <div class="dashboard-grid">
        <div class="metric-card $color">
            <div class="metric-label">Resource Compliance</div>
            <div class="metric-value">$compliancePct%</div>
            <div>$($totalResources - $nonCompliantResources) of $totalResources resources</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Subscriptions</div>
            <div class="metric-value">$totalSubs</div>
            <div>in scope</div>
        </div>
        <div class="metric-card $(if ($nonCompliantPolicies -gt 0) { 'high' } else { '' })">
            <div class="metric-label">Non-compliant policies</div>
            <div class="metric-value">$nonCompliantPolicies</div>
            <div>across all subscriptions</div>
        </div>
    </div>
    $initiativesTable
</section>
"@
}

function Get-PurviewSection {
    <#
    .SYNOPSIS
        Renders the Purview Compliance Manager section of the unified report.
    #>
    param([object]$PurviewCompliance)

    $hint = 'To populate this section, run the orchestrator with Purview collection enabled (menu [7] or pass a PurviewCompliance object via -PurviewCompliance).'
    if (-not $PurviewCompliance) {
        return @"
<section class="purview" id="purview">
    <h2 class="section-title">&#128274; Purview Compliance Manager</h2>
    $(Get-NotCollectedPlaceholder -SectionName 'Purview Compliance Manager' -Hint $hint)
</section>
"@
    }

    $summary = $PurviewCompliance.Summary
    $cmAvailable = $summary.ComplianceManagerAvailable
    $cmScore = $summary.ComplianceScore
    $assessments = if ($summary.TotalAssessments) { $summary.TotalAssessments } else { 0 }
    $actions = if ($summary.TotalActions) { $summary.TotalActions } else { 0 }
    $completedActions = if ($summary.CompletedActions) { $summary.CompletedActions } else { 0 }
    $dlpCount = if ($summary.DLPPoliciesCount) { $summary.DLPPoliciesCount } else { 0 }
    $labelCount = if ($summary.SensitivityLabelsCount) { $summary.SensitivityLabelsCount } else { 0 }
    $retentionCount = if ($summary.RetentionPoliciesCount) { $summary.RetentionPoliciesCount } else { 0 }

    $cmCard = if ($cmAvailable -and $null -ne $cmScore) {
        $color = if ($cmScore -ge 80) { 'low' } elseif ($cmScore -ge 60) { 'medium' } else { 'critical' }
        @"
        <div class="metric-card $color">
            <div class="metric-label">Compliance Manager score</div>
            <div class="metric-value">$cmScore%</div>
            <div>$completedActions of $actions actions complete</div>
        </div>
"@
    }
    else {
        @"
        <div class="metric-card">
            <div class="metric-label">Compliance Manager</div>
            <div class="metric-value">N/A</div>
            <div>Not licensed or no data</div>
        </div>
"@
    }

    return @"
<section class="purview" id="purview">
    <h2 class="section-title">&#128274; Purview Compliance Manager</h2>
    <div class="dashboard-grid">
        $cmCard
        <div class="metric-card">
            <div class="metric-label">Assessments</div>
            <div class="metric-value">$assessments</div>
            <div>in scope</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">DLP Policies</div>
            <div class="metric-value">$dlpCount</div>
            <div>in tenant</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Sensitivity labels</div>
            <div class="metric-value">$labelCount</div>
            <div>published</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Retention policies</div>
            <div class="metric-value">$retentionCount</div>
            <div>configured</div>
        </div>
    </div>
</section>
"@
}

function Get-HybridCorrelationSection {
    <#
    .SYNOPSIS
        Renders the Hybrid Correlation section (PR 2 — AD integration).
    .DESCRIPTION
        Accepts output of Get-HybridIdentityCorrelation from
        EntraChecks-HybridCorrelation.psm1. Shows principals flagged in BOTH
        cloud (Entra) and on-prem (AD) findings.
    #>
    param([object]$HybridCorrelation)

    $hint = 'This section populates only when a Hybrid Analysis run has executed (menu [Y] or -Mode Hybrid). Cloud-only runs skip correlation.'
    if (-not $HybridCorrelation) {
        return @"
<section class="hybrid-correlation" id="hybrid-correlation">
    <h2 class="section-title">&#128279; Hybrid Correlation</h2>
    $(Get-NotCollectedPlaceholder -SectionName 'Hybrid Correlation' -Hint $hint)
</section>
"@
    }

    $corrCount = if ($HybridCorrelation.CorrelationCount) { $HybridCorrelation.CorrelationCount } else { 0 }
    $cloudTotal = if ($HybridCorrelation.TotalCloudFindings) { $HybridCorrelation.TotalCloudFindings } else { 0 }
    $onPremTotal = if ($HybridCorrelation.TotalOnPremFindings) { $HybridCorrelation.TotalOnPremFindings } else { 0 }

    $bodyRows = ''
    if ($HybridCorrelation.CorrelatedPrincipals -and $HybridCorrelation.CorrelatedPrincipals.Count -gt 0) {
        $top = $HybridCorrelation.CorrelatedPrincipals |
            Sort-Object { $_.CloudCount + $_.OnPremCount } -Descending |
            Select-Object -First 10
        foreach ($c in $top) {
            $principal = [System.Web.HttpUtility]::HtmlEncode([string]$c.Principal)
            $conf = [System.Web.HttpUtility]::HtmlEncode([string]$c.Confidence)
            $matchKey = [System.Web.HttpUtility]::HtmlEncode([string]$c.MatchKey)
            $cloudSev = [System.Web.HttpUtility]::HtmlEncode([string]$c.MaxCloudSeverity)
            $onPremSev = [System.Web.HttpUtility]::HtmlEncode([string]$c.MaxOnPremSeverity)
            $bodyRows += "<tr><td>$principal</td><td>$conf / $matchKey</td><td>$($c.CloudCount) ($cloudSev)</td><td>$($c.OnPremCount) ($onPremSev)</td></tr>`n"
        }
    }

    $table = if ($bodyRows) {
        @"
    <h3 style="margin-top: 24px;">Top correlated principals</h3>
    <p style="font-size: 0.85em; color: #605e5c;">Principals flagged in BOTH cloud (Entra) and on-prem (Active Directory) findings. <code>Exact</code> = UPN match; <code>Inferred</code> = sAMAccountName match with no UPN-level confirmation.</p>
    <table>
        <thead><tr><th>Principal</th><th>Match</th><th>Cloud findings (max severity)</th><th>On-prem findings (max severity)</th></tr></thead>
        <tbody>$bodyRows</tbody>
    </table>
"@
    }
    else {
        '<p class="compliance-fallback-note">No principals were flagged in both planes during this run.</p>'
    }

    return @"
<section class="hybrid-correlation" id="hybrid-correlation">
    <h2 class="section-title">&#128279; Hybrid Correlation</h2>
    <div class="dashboard-grid">
        <div class="metric-card $(if ($corrCount -gt 0) { 'high' } else { '' })">
            <div class="metric-label">Correlated principals</div>
            <div class="metric-value">$corrCount</div>
            <div>flagged in both planes</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Cloud findings indexed</div>
            <div class="metric-value">$cloudTotal</div>
            <div>identity-bearing</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">On-prem findings indexed</div>
            <div class="metric-value">$onPremTotal</div>
            <div>identity-bearing</div>
        </div>
    </div>
    $table
</section>
"@
}

function Get-FindingsDelta {
    <#
    .SYNOPSIS
        Compares two finding sets keyed on Description+Object.
    .DESCRIPTION
        Returns Resolved / New / Persistent counts. Used by the executive
        dashboard's "Since last assessment" card row when -PreviousAssessment
        is supplied to New-EnhancedHTMLReport. Empty / null inputs are valid
        (e.g., a first-ever run has no previous findings).
    #>
    param(
        [AllowNull()] [AllowEmptyCollection()] [Parameter(Mandatory)] [object[]]$Current,
        [AllowNull()] [AllowEmptyCollection()] [Parameter(Mandatory)] [object[]]$Previous
    )

    $currentKeys = @{}
    if ($Current) {
        foreach ($f in $Current) {
            $currentKeys["$($f.Description)|$($f.Object)"] = $true
        }
    }
    $previousKeys = @{}
    if ($Previous) {
        foreach ($f in $Previous) {
            $previousKeys["$($f.Description)|$($f.Object)"] = $true
        }
    }

    $resolved = 0
    foreach ($k in $previousKeys.Keys) {
        if (-not $currentKeys.ContainsKey($k)) { $resolved++ }
    }
    $newCount = 0
    $persistent = 0
    foreach ($k in $currentKeys.Keys) {
        if ($previousKeys.ContainsKey($k)) { $persistent++ } else { $newCount++ }
    }

    # Individual assignments to avoid PSAlignAssignmentStatement / PSUseConsistentWhitespace conflict.
    $result = @{}
    $result['Resolved'] = $resolved
    $result['New'] = $newCount
    $result['Persistent'] = $persistent
    $result['Total'] = $Current.Count
    return $result
}

function Get-EntraChecksExecutiveDigest {
    <#
    .SYNOPSIS
        Computes a one-paragraph posture verdict for the unified report.
    .DESCRIPTION
        Mirrors the Get-SOC2ExecutiveDigest shape but operates on enhanced
        EntraChecks findings (which already carry RiskLevel + RiskScore from
        Add-RiskScoring). Returns a PSCustomObject with the verdict, headline
        counts, top failing checks, and a delta line if FindingsDelta was
        supplied.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [array]$Findings,
        [Parameter(Mandatory)] [object]$RiskSummary,
        [Parameter(Mandatory)] [object]$ComplianceGap,
        [object]$FindingsDelta
    )

    $crit = if ($null -ne $RiskSummary.CriticalCount) { [int]$RiskSummary.CriticalCount } else { 0 }
    $high = if ($null -ne $RiskSummary.HighCount) { [int]$RiskSummary.HighCount } else { 0 }
    $quickWins = if ($null -ne $RiskSummary.QuickWinsCount) { [int]$RiskSummary.QuickWinsCount } else { 0 }
    $total = $Findings.Count

    $verdict = 'INSUFFICIENT DATA'
    $verdictClass = 'verdict-insufficient'
    if ($total -gt 0) {
        if ($crit -eq 0 -and $high -eq 0) {
            $verdict = 'STRONG'
            $verdictClass = 'verdict-strong'
        }
        elseif ($crit -eq 0 -and $high -le 5) {
            $verdict = 'MINOR DEFICIENCIES'
            $verdictClass = 'verdict-minor'
        }
        else {
            $verdict = 'GAPS IDENTIFIED'
            $verdictClass = 'verdict-gaps'
        }
    }

    # Top 3 highest-risk findings (by RiskScore).
    $topFindings = @($Findings |
            Where-Object { $_.Status -in @('FAIL', 'WARNING') } |
            Sort-Object { [int]($_.RiskScore) } -Descending |
            Select-Object -First 3)

    # Frameworks with the most affected controls.
    $frameworkGaps = @()
    if ($ComplianceGap -and $ComplianceGap.FrameworkGaps) {
        foreach ($key in @('CIS', 'NIST', 'SOC2', 'PCIDSS')) {
            $g = $ComplianceGap.FrameworkGaps[$key]
            if ($g -and $g.ControlsAffected -gt 0) {
                $frameworkGaps += [pscustomobject]@{ Framework = $key; ControlsAffected = $g.ControlsAffected }
            }
        }
        $frameworkGaps = @($frameworkGaps | Sort-Object ControlsAffected -Descending | Select-Object -First 3)
    }

    return [pscustomobject]@{
        Verdict = $verdict
        VerdictClass = $verdictClass
        TotalFindings = $total
        CriticalCount = $crit
        HighCount = $high
        QuickWinsCount = $quickWins
        TopFindings = $topFindings
        FrameworkGaps = $frameworkGaps
        FindingsDelta = $FindingsDelta
    }
}

function Format-ExecutiveDigest {
    <#
    .SYNOPSIS
        Renders the Get-EntraChecksExecutiveDigest output as the cover digest
        block at the top of the unified report.
    #>
    param(
        [Parameter(Mandatory)] [object]$Digest,
        [Parameter(Mandatory)] [object]$TenantInfo
    )

    $verdictHtml = "<span class='exec-verdict $($Digest.VerdictClass)'>$($Digest.Verdict)</span>"

    $deltaLine = ""
    if ($Digest.FindingsDelta) {
        $d = $Digest.FindingsDelta
        $deltaLine = "<p><strong>Since last assessment:</strong> $($d.Resolved) resolved &middot; $($d.New) new &middot; $($d.Persistent) persistent.</p>"
    }

    $topRows = ""
    if ($Digest.TopFindings -and $Digest.TopFindings.Count -gt 0) {
        $topRows = "<p><strong>Top findings (by risk score):</strong></p><ol class='top-list'>"
        foreach ($f in $Digest.TopFindings) {
            $desc = [System.Web.HttpUtility]::HtmlEncode([string]$f.Description)
            $obj = [System.Web.HttpUtility]::HtmlEncode([string]$f.Object)
            $topRows += "<li>${desc} <em>(${obj})</em> &mdash; risk $($f.RiskScore)</li>"
        }
        $topRows += "</ol>"
    }

    $gapLine = ""
    if ($Digest.FrameworkGaps -and $Digest.FrameworkGaps.Count -gt 0) {
        $parts = $Digest.FrameworkGaps | ForEach-Object { "$($_.Framework) ($($_.ControlsAffected))" }
        $gapLine = "<p><strong>Compliance gaps:</strong> $($parts -join ' &middot; ')</p>"
    }

    return @"
<section class="exec-digest" id="exec-digest">
    <h2>&#128202; Executive Digest</h2>
    <p class="verdict-line"><strong>Posture:</strong>$verdictHtml &mdash; $($Digest.TotalFindings) findings total ($($Digest.CriticalCount) critical, $($Digest.HighCount) high). $($Digest.QuickWinsCount) quick wins available.</p>
    $deltaLine
    $topRows
    $gapLine
</section>
"@
}

function New-IntegrityBlock {
    <#
    .SYNOPSIS
        Computes a SHA-256 hash of the canonical findings JSON and writes a
        sibling .findings.json file. Returns the HTML footer block displaying
        the hash and verification command.
    .DESCRIPTION
        The sidecar is the verifiable artifact; the HTML carries the hash for
        display only. Test-EntraChecksReportIntegrity reads both and confirms
        they agree. Intentionally tolerant: if writing the sidecar fails
        (read-only path, etc.) the in-HTML hash is still emitted.
    #>
    param(
        [Parameter(Mandatory)] [array]$EnhancedFindings,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    # Canonicalize so identical inputs always hash identically — sort keys via
    # ConvertTo-Json -Depth, then compute hash on UTF-8 bytes.
    try {
        $json = $EnhancedFindings | ConvertTo-Json -Depth 8 -Compress
    }
    catch {
        return ""
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $hashBytes = $sha.ComputeHash($bytes)
        $hashHex = [BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }

    # Write sidecar JSON. Use WriteAllText (no BOM, no trailing newline) so the
    # sidecar bytes round-trip exactly through Test-EntraChecksReportIntegrity.
    # Failure to write is non-fatal — the badge still shows in the HTML.
    $sidecarPath = "$OutputPath.findings.json"
    try {
        [System.IO.File]::WriteAllText($sidecarPath, $json, [System.Text.UTF8Encoding]::new($false))
    }
    catch {
        Write-Verbose "Could not write integrity sidecar at ${sidecarPath}: $($_.Exception.Message)"
    }

    $sidecarLeaf = Split-Path -Leaf $sidecarPath
    return @"
<footer class="integrity-footer" id="integrity">
    <span class="badge">Integrity-verifiable</span>
    SHA-256 of findings JSON (sidecar: <code>$([System.Web.HttpUtility]::HtmlEncode($sidecarLeaf))</code>):
    <span class="hash">$hashHex</span>
    <p style="margin-top: 8px;">Verify with: <code>Test-EntraChecksReportIntegrity -ReportPath '$([System.Web.HttpUtility]::HtmlEncode((Split-Path -Leaf $OutputPath)))'</code></p>
</footer>
"@
}

function Test-EntraChecksReportIntegrity {
    <#
    .SYNOPSIS
        Verifies that a unified HTML report's findings JSON sidecar still hashes
        to the value baked into the report footer.
    .DESCRIPTION
        Reads <ReportPath>.findings.json, recomputes its SHA-256, and compares
        against the hash recorded in the report's integrity footer. Returns a
        PSCustomObject with .IsValid + diagnostic fields.
    .PARAMETER ReportPath
        Path to the unified HTML report. The companion sidecar is expected at
        <ReportPath>.findings.json.
    .EXAMPLE
        Test-EntraChecksReportIntegrity -ReportPath .\Output\report.html
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$ReportPath
    )

    $result = [ordered]@{
        IsValid = $false
        ReportPath = $ReportPath
        SidecarPath = "$ReportPath.findings.json"
        ExpectedHash = $null
        ActualHash = $null
        Reason = $null
    }

    if (-not (Test-Path -LiteralPath $ReportPath)) {
        $result['Reason'] = "Report not found: $ReportPath"
        return [pscustomobject]$result
    }
    if (-not (Test-Path -LiteralPath $result['SidecarPath'])) {
        $result['Reason'] = "Sidecar not found: $($result['SidecarPath']) (was the report generated with -IncludeIntegrityBadge:`$false?)"
        return [pscustomobject]$result
    }

    $html = Get-Content -LiteralPath $ReportPath -Raw
    $match = [regex]::Match($html, '<span class="hash">([a-f0-9]{64})</span>')
    if (-not $match.Success) {
        $result['Reason'] = "No integrity hash found in report HTML."
        return [pscustomobject]$result
    }
    $result['ExpectedHash'] = $match.Groups[1].Value

    # Read raw bytes (not via Get-Content -Raw, which can mutate line endings).
    $bytes = [System.IO.File]::ReadAllBytes($result['SidecarPath'])
    # Strip UTF-8 BOM if present, so older sidecars written via Set-Content
    # also verify cleanly.
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $bytes = $bytes[3..($bytes.Length - 1)]
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash($bytes)
        $result['ActualHash'] = [BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }

    if ($result['ExpectedHash'] -eq $result['ActualHash']) {
        $result['IsValid'] = $true
        $result['Reason'] = 'Sidecar matches report-embedded hash.'
    }
    else {
        $result['Reason'] = 'Sidecar hash does not match report-embedded hash — file may have been modified.'
    }
    return [pscustomobject]$result
}

function Get-ExecutiveDashboard {
    param(
        [Parameter(Mandatory)]
        [object]$RiskSummary,

        [Parameter(Mandatory)]
        [object]$ComplianceGap,

        [Parameter(Mandatory)]
        [object]$TenantInfo,

        [object]$DefenderCompliance,

        [object]$FindingsDelta
    )

    # Build compliance impact section based on data source
    $hasDefenderData = ($DefenderCompliance -and
        $DefenderCompliance.Summary -and
        $DefenderCompliance.Summary.TotalStandards -gt 0)

    $complianceCards = ""
    if ($hasDefenderData) {
        # Show real Defender compliance data - up to 4 standards as summary cards
        $standardsShown = 0
        foreach ($sub in $DefenderCompliance.Subscriptions) {
            foreach ($std in $sub.Standards) {
                if ($standardsShown -ge 4) { break }
                $total = $std.PassedControls + $std.FailedControls
                $pct = if ($total -gt 0) { [math]::Round(($std.PassedControls / $total) * 100, 0) } else { 0 }
                $cardColor = if ($pct -ge 80) { '' } elseif ($pct -ge 60) { 'medium' } else { 'critical' }

                $complianceCards += @"
            <div class="metric-card $cardColor">
                <div class="metric-label">$($std.ShortName)</div>
                <div class="metric-value">$pct%</div>
                <div>$($std.PassedControls) of $total passed</div>
            </div>
"@
                $standardsShown++
            }
            if ($standardsShown -ge 4) { break }
        }
    }
    else {
        # Fallback: show subjective compliance gap counts
        $complianceCards = @"
            <div class="metric-card">
                <div class="metric-label">CIS M365 Controls</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.CIS.ControlsAffected)</div>
                <div>Controls with findings</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">NIST CSF Functions</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.NIST.ControlsAffected)</div>
                <div>Functions with findings</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">SOC 2 Criteria</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.SOC2.ControlsAffected)</div>
                <div>Criteria with findings</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">PCI-DSS Requirements</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.PCIDSS.ControlsAffected)</div>
                <div>Requirements with findings</div>
            </div>
"@
    }

    # Optional "Since last assessment" row — only rendered when caller supplied
    # a previous snapshot via -PreviousAssessment.
    $deltaRow = ""
    if ($FindingsDelta) {
        $resolvedColor = if ($FindingsDelta.Resolved -gt 0) { 'low' } else { '' }
        $newColor = if ($FindingsDelta.New -gt 0) { 'high' } else { '' }
        $deltaRow = @"

    <h3 style="margin-top: 30px;">&#128260; Since last assessment</h3>
    <div class="dashboard-grid">
        <div class="metric-card $resolvedColor">
            <div class="metric-label">Resolved</div>
            <div class="metric-value">$($FindingsDelta.Resolved)</div>
            <div>Findings closed since last run</div>
        </div>

        <div class="metric-card $newColor">
            <div class="metric-label">New</div>
            <div class="metric-value">$($FindingsDelta.New)</div>
            <div>Findings introduced since last run</div>
        </div>

        <div class="metric-card">
            <div class="metric-label">Persistent</div>
            <div class="metric-value">$($FindingsDelta.Persistent)</div>
            <div>Carried over from prior run</div>
        </div>
    </div>
"@
    }

    return @"
<section class="executive-dashboard" id="executive">
    <h2 class="section-title">&#128202; Executive Summary</h2>

    <div class="dashboard-grid">
        <div class="metric-card critical">
            <div class="metric-label">Critical Risk</div>
            <div class="metric-value">$($RiskSummary.CriticalCount)</div>
            <div>$($RiskSummary.CriticalPercent)% of findings</div>
        </div>

        <div class="metric-card high">
            <div class="metric-label">High Risk</div>
            <div class="metric-value">$($RiskSummary.HighCount)</div>
            <div>$($RiskSummary.HighPercent)% of findings</div>
        </div>

        <div class="metric-card medium">
            <div class="metric-label">Medium Risk</div>
            <div class="metric-value">$($RiskSummary.MediumCount)</div>
            <div>$($RiskSummary.MediumPercent)% of findings</div>
        </div>

        <div class="metric-card low">
            <div class="metric-label">Quick Wins Available</div>
            <div class="metric-value">$($RiskSummary.QuickWinsCount)</div>
            <div>High impact, low effort</div>
        </div>
    </div>
    $deltaRow

    <div style="margin-top: 30px;">
        <h3>&#128200; Risk Analysis</h3>
        <p><strong>Average Risk Score:</strong> $($RiskSummary.AverageRiskScore) / 100</p>
        <p><strong>Highest Risk Score:</strong> $($RiskSummary.MaxRiskScore) / 100</p>
        <p><strong>Top Priority Items:</strong> $($RiskSummary.TopPriorityCount) findings require immediate attention</p>
    </div>

    <div style="margin-top: 30px;">
        <h3>&#128203; Compliance Impact</h3>
        <div class="dashboard-grid">
$complianceCards
        </div>
    </div>
</section>
"@
}

function Get-QuickWinsSection {
    param(
        # Tolerate null/empty (pre-existing — reports with no FAIL findings end
        # up with $null after the Where-Object filter in Get-QuickWins).
        [AllowNull()] [AllowEmptyCollection()]
        [Parameter(Mandatory)]
        [array]$QuickWins
    )

    if (-not $QuickWins -or $QuickWins.Count -eq 0) {
        return @"
<section class="section" id="quick-wins">
    <h2 class="section-title">&#9889; Quick Wins</h2>
    <p>No quick wins identified - all findings require moderate to high effort.</p>
</section>
"@
    }

    $quickWinCards = ""
    $topQuickWins = $QuickWins | Select-Object -First 5

    foreach ($qw in $topQuickWins) {
        $quickWinCards += @"
<div class="quick-win-card">
    <h3>$($qw.Description -replace '<', '&lt;' -replace '>', '&gt;')</h3>
    <div class="quick-win-meta">
        <span><strong>Risk Score:</strong> <span class="risk-badge $($qw.RiskLevel.ToLower())">$($qw.RiskLevel)</span> $($qw.RiskScore)</span>
        <span><strong>Effort:</strong> $($qw.RemediationEffortDescription)</span>
        <span><strong>Priority Score:</strong> <span class="priority-score">$($qw.PriorityScore)</span></span>
    </div>
    <p style="margin-top: 10px;"><strong>Remediation:</strong> $($qw.Remediation -replace '<', '&lt;' -replace '>', '&gt;')</p>
</div>
"@
    }

    return @"
<section class="section" id="quick-wins">
    <h2 class="section-title">&#9889; Quick Wins - High Impact, Low Effort</h2>
    <p>These findings provide significant security improvements with minimal implementation time. Prioritize these for immediate action.</p>
    <div class="quick-wins-grid">
        $quickWinCards
    </div>
</section>
"@
}

function Get-PrioritySection {
    param(
        [AllowNull()] [AllowEmptyCollection()]
        [Parameter(Mandatory)]
        [array]$PrioritizedFindings
    )

    $topFindings = if ($PrioritizedFindings) { $PrioritizedFindings | Select-Object -First 15 } else { @() }
    $tableRows = ""

    $rank = 1
    foreach ($finding in $topFindings) {
        $tableRows += @"
<tr>
    <td><strong>$rank</strong></td>
    <td>$($finding.Description -replace '<', '&lt;' -replace '>', '&gt;')</td>
    <td><span class="risk-badge $($finding.RiskLevel.ToLower())">$($finding.RiskLevel)</span></td>
    <td>$($finding.RiskScore)</td>
    <td>$($finding.RemediationEffortDescription)</td>
    <td class="priority-score">$($finding.PriorityScore)</td>
</tr>
"@
        $rank++
    }

    return @"
<section class="section" id="priority">
    <h2 class="section-title">&#127919; Top Priority Findings - Recommended Remediation Order</h2>
    <p>Findings are prioritized by their Priority Score (Risk Score / Remediation Effort), providing the best return on investment.</p>

    <table class="priority-table">
        <thead>
            <tr>
                <th>Rank</th>
                <th>Finding</th>
                <th>Risk Level</th>
                <th>Risk Score</th>
                <th>Effort</th>
                <th>Priority Score</th>
            </tr>
        </thead>
        <tbody>
            $tableRows
        </tbody>
    </table>
</section>
"@
}

function Get-ComplianceSection {
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [object]$ComplianceGap,

        [object]$DefenderCompliance
    )

    # Determine if real Defender for Cloud data is available
    $hasDefenderData = ($DefenderCompliance -and
        $DefenderCompliance.Summary -and
        $DefenderCompliance.Summary.TotalStandards -gt 0)

    if ($hasDefenderData) {
        return Get-ComplianceSectionFromDefender -DefenderCompliance $DefenderCompliance
    }
    else {
        return Get-ComplianceSectionFallback -Findings $Findings -ComplianceGap $ComplianceGap
    }
}

function Get-ComplianceSectionFromDefender {
    param(
        [Parameter(Mandatory)]
        [object]$DefenderCompliance
    )

    $standardCards = ""
    $cardIndex = 0

    # Aggregate standards across subscriptions
    $standardsMap = @{}
    foreach ($sub in $DefenderCompliance.Subscriptions) {
        foreach ($std in $sub.Standards) {
            $key = $std.StandardName
            if (-not $standardsMap.ContainsKey($key)) {
                $standardsMap[$key] = @{
                    StandardName = $std.StandardName
                    ShortName = $std.ShortName
                    Framework = $std.Framework
                    PassedControls = 0
                    FailedControls = 0
                    TotalControls = 0
                    CompliancePercent = 0
                    Subscriptions = @()
                }
            }
            $standardsMap[$key].PassedControls += $std.PassedControls
            $standardsMap[$key].FailedControls += $std.FailedControls
            $standardsMap[$key].TotalControls += ($std.PassedControls + $std.FailedControls)
            $standardsMap[$key].Subscriptions += $sub.SubscriptionName
        }
    }

    # Sort standards by name
    $sortedStandards = $standardsMap.GetEnumerator() | Sort-Object { $_.Value.StandardName }

    foreach ($entry in $sortedStandards) {
        $std = $entry.Value
        $total = $std.TotalControls
        $passed = $std.PassedControls
        $failed = $std.FailedControls
        $pct = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }

        $progressClass = if ($pct -ge 80) { 'high' } elseif ($pct -ge 60) { 'medium' } else { 'low' }
        $subList = ($std.Subscriptions | Select-Object -Unique) -join ', '

        # Get controls for this standard for the detail table
        $stdControls = @($DefenderCompliance.Controls | Where-Object {
                $_.Framework -eq $std.Framework -or $_.Framework -eq $std.ShortName
            })

        $controlRows = ""
        if ($stdControls.Count -gt 0) {
            $sortedControls = $stdControls | Sort-Object ControlId
            foreach ($ctrl in $sortedControls) {
                $statusClass = switch ($ctrl.Status) {
                    'Passed' { 'control-status-passed' }
                    'Failed' { 'control-status-failed' }
                    default { 'control-status-na' }
                }
                $titleSafe = $ctrl.ControlTitle -replace '<', '&lt;' -replace '>', '&gt;'
                $controlRows += @"
            <tr>
                <td>$($ctrl.ControlId)</td>
                <td>$titleSafe</td>
                <td class="$statusClass">$($ctrl.Status)</td>
                <td>$($ctrl.PassedResources)</td>
                <td>$($ctrl.FailedResources)</td>
            </tr>
"@
            }
        }

        $detailTable = ""
        if ($controlRows) {
            $detailTable = @"
        <button class="compliance-detail-toggle" onclick="toggleComplianceDetail(this)">Show Control Details</button>
        <table class="compliance-detail-table" id="compliance-detail-$cardIndex">
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Control</th>
                    <th>Status</th>
                    <th>Passed</th>
                    <th>Failed</th>
                </tr>
            </thead>
            <tbody>
$controlRows
            </tbody>
        </table>
"@
        }

        $standardCards += @"
    <div class="compliance-standard-card">
        <h3>$($std.StandardName -replace '<', '&lt;' -replace '>', '&gt;')</h3>
        <div class="compliance-progress-bar">
            <div class="compliance-progress-fill $progressClass" style="width: $pct%">$pct%</div>
        </div>
        <div class="compliance-stats-row">
            <span class="stat-passed">&#10003; $passed Passed</span>
            <span class="stat-failed">&#10007; $failed Failed</span>
            <span>$total Total Controls</span>
        </div>
        <div class="compliance-stats-row">
            <span>Subscriptions: $subList</span>
        </div>
$detailTable
    </div>
"@
        $cardIndex++
    }

    $totalPassed = $DefenderCompliance.Summary.PassedControls
    $totalFailed = $DefenderCompliance.Summary.FailedControls
    $totalAll = $totalPassed + $totalFailed
    $overallPct = if ($totalAll -gt 0) { [math]::Round(($totalPassed / $totalAll) * 100, 1) } else { 0 }

    return @"
<section class="section" id="compliance">
    <h2 class="section-title">&#128203; Regulatory Compliance (Defender for Cloud)</h2>
    <p class="compliance-source-label">Source: Microsoft Defender for Cloud Regulatory Compliance | $($DefenderCompliance.Summary.TotalStandards) standards across $($DefenderCompliance.Summary.TotalSubscriptions) subscription(s) | Overall: $totalPassed of $totalAll controls passed ($overallPct%)</p>

    $standardCards
</section>
"@
}

function Get-ComplianceSectionFallback {
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [object]$ComplianceGap
    )

    $cisCard = @"
<div class="compliance-card">
    <h3>CIS Microsoft 365 Foundations</h3>
    <div class="compliance-stat">
        <span>Controls Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.CIS.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.CIS_M365 }).Count)</strong></span>
    </div>
</div>
"@

    $nistCard = @"
<div class="compliance-card">
    <h3>NIST Cybersecurity Framework</h3>
    <div class="compliance-stat">
        <span>Functions Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.NIST.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.NIST_CSF }).Count)</strong></span>
    </div>
</div>
"@

    $soc2Card = @"
<div class="compliance-card">
    <h3>SOC 2 Trust Services</h3>
    <div class="compliance-stat">
        <span>Criteria Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.SOC2.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.SOC2 }).Count)</strong></span>
    </div>
</div>
"@

    $pciCard = @"
<div class="compliance-card">
    <h3>PCI-DSS v4.0.1</h3>
    <div class="compliance-stat">
        <span>Requirements Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.PCIDSS.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.PCI_DSS_4 }).Count)</strong></span>
    </div>
</div>
"@

    return @"
<section class="section" id="compliance">
    <h2 class="section-title">&#128203; Compliance Framework Mapping</h2>
    <p>This assessment maps findings to industry-standard compliance frameworks, helping you understand regulatory impact and compliance gaps.</p>

    <div class="compliance-grid">
        $cisCard
        $nistCard
        $soc2Card
        $pciCard
    </div>
    <p class="compliance-fallback-note">Based on EntraChecks assessment mapping. Enable regulatory compliance standards in Microsoft Defender for Cloud for real-time compliance data.</p>
</section>
"@
}

function Get-DetailedFindingsSection {
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        # PR 3: per-finding anchor + tag.
        [string[]]$LowConfidenceCheckNames
    )

    # Helper function to generate a single finding card with data attributes for filtering
    function Get-FindingCard {
        param($finding, $index, $lowConfList)

        $riskLevel = if ($finding.RiskLevel) { $finding.RiskLevel } else { 'Info' }
        $riskLower = $riskLevel.ToLower()
        $status = if ($finding.Status) { $finding.Status } else { 'INFO' }
        $statusLower = $status.ToLower()
        $category = if ($finding.Category) { $finding.Category } else { 'General' }
        $categoryLower = $category.ToLower() -replace '\s+', '-'

        $descSafe = if ($finding.Description) { $finding.Description -replace '<', '&lt;' -replace '>', '&gt;' } else { 'N/A' }
        $objSafe = if ($finding.Object) { $finding.Object -replace '<', '&lt;' -replace '>', '&gt;' } else { 'N/A' }
        $remSafe = if ($finding.Remediation) { $finding.Remediation -replace '<', '&lt;' -replace '>', '&gt;' } else { '' }

        # PR 3: stable per-finding anchor id from a hash of description+object.
        # MD5 is fine here — we're not doing crypto, just generating a short id.
        $anchorBasis = "$($finding.Description)|$($finding.Object)"
        $md5 = [System.Security.Cryptography.MD5]::Create()
        try {
            $hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($anchorBasis))
            $anchorHash = [BitConverter]::ToString($hashBytes).Replace('-', '').Substring(0, 10).ToLowerInvariant()
        }
        finally { $md5.Dispose() }
        $anchorId = "finding-$anchorHash"

        # PR 3: low-confidence tag (rendered next to the title when applicable).
        $lcTag = ""
        if ($finding.CheckName -and $lowConfList -and ($lowConfList -contains $finding.CheckName)) {
            $lcTag = " <span class='low-confidence-tag' title='Fixture-verified only — see -LowConfidenceCheckNames in New-EnhancedHTMLReport'>fixture-verified</span>"
        }

        # PR 3: per-finding deep-link affordance ("link" emoji that copies the
        # full URL with #anchor to the clipboard via JS).
        $anchorLink = "<a href='#$anchorId' class='finding-anchor' onclick='copyFindingLink(event, this)' title='Copy link to this finding'>&#128279;</a>"

        $complianceRef = if ($finding.ComplianceReference) {
            "<p><strong>Compliance Frameworks:</strong> $($finding.ComplianceReference)</p>"
        }
        else { "" }

        $remediationGuidance = ""
        if ($finding.RemediationGuidance) {
            $rg = $finding.RemediationGuidance
            $stepsHtml = ($rg.StepsPortal | ForEach-Object { "<li>$($_ -replace '^\d+\.\s*', '')</li>" }) -join ""

            $remediationGuidance = @"
<div class="remediation-steps">
    <h4>&#128273; Remediation Steps (Azure Portal)</h4>
    <ol>
        $stepsHtml
    </ol>

    <h4 style="margin-top: 15px;">&#128187; PowerShell Remediation</h4>
    <div class="code-block">$($rg.StepsPowerShell -replace '<', '&lt;' -replace '>', '&gt;')</div>

    <p style="margin-top: 10px;"><strong>Impact:</strong> $($rg.Impact.Positive)</p>
    <p><strong>Considerations:</strong> $($rg.Impact.Negative)</p>
</div>
"@
        }

        return @"
<div class="finding-card finding-row" id="$anchorId" data-risk="$riskLower" data-status="$statusLower" data-category="$categoryLower">
    <div class="finding-header" onclick="toggleFinding(this)">
        <div>
            <span class="risk-badge $riskLower">$riskLevel</span>
            <span class="finding-title">$descSafe</span>$lcTag$anchorLink
        </div>
        <span>&#9660;</span>
    </div>
    <div class="finding-body">
        <div class="finding-meta">
            <div><strong>Object:</strong> $objSafe</div>
            <div><strong>Risk Score:</strong> $($finding.RiskScore) / 100</div>
            <div><strong>Priority Score:</strong> $($finding.PriorityScore)</div>
            <div><strong>Remediation Effort:</strong> $($finding.RemediationEffortDescription)</div>
        </div>

        $complianceRef

        $(if ($remSafe) { "<p style='margin: 15px 0;'><strong>Quick Remediation:</strong> $remSafe</p>" })

        $remediationGuidance
    </div>
</div>
"@
    }

    # Gather unique categories and build the accordion structure
    $categoryGroups = $Findings | Group-Object {
        if ($_.Category) { $_.Category } else { 'General' }
    } | Sort-Object Name

    # Build category filter options
    $categoryOptions = ""
    foreach ($cg in $categoryGroups) {
        $catSafe = $cg.Name -replace '<', '&lt;' -replace '>', '&gt;'
        $catValue = $cg.Name.ToLower() -replace '\s+', '-'
        $categoryOptions += "            <option value=`"$catValue`">$catSafe ($($cg.Count))</option>`n"
    }

    # Build category accordions
    $categoryAccordions = ""
    $statusOrder = @('FAIL', 'WARNING', 'INFO', 'OK')

    foreach ($catGroup in $categoryGroups) {
        $catName = $catGroup.Name
        $catNameSafe = $catName -replace '<', '&lt;' -replace '>', '&gt;'
        $catValue = $catName.ToLower() -replace '\s+', '-'
        $catFindings = @($catGroup.Group)

        # Count by status for badges
        $failN = @($catFindings | Where-Object { $_.Status -eq 'FAIL' }).Count
        $warnN = @($catFindings | Where-Object { $_.Status -eq 'WARNING' }).Count
        $okN = @($catFindings | Where-Object { $_.Status -eq 'OK' }).Count
        $infoN = @($catFindings | Where-Object { $_.Status -eq 'INFO' }).Count

        $badges = ""
        if ($failN -gt 0) { $badges += "<span class='count-badge fail-badge'>$failN FAIL</span>" }
        if ($warnN -gt 0) { $badges += "<span class='count-badge warning-badge'>$warnN WARNING</span>" }
        if ($infoN -gt 0) { $badges += "<span class='count-badge info-badge'>$infoN INFO</span>" }
        if ($okN -gt 0) { $badges += "<span class='count-badge ok-badge'>$okN OK</span>" }

        # Build status sub-accordions within this category
        $statusAccordions = ""
        foreach ($st in $statusOrder) {
            $stFindings = @($catFindings | Where-Object { $_.Status -eq $st })
            if ($stFindings.Count -eq 0) { continue }

            $stLower = $st.ToLower()
            $stHeaderClass = "$stLower-header"

            # Sort findings within status by risk score descending
            $stFindings = $stFindings | Sort-Object { if ($_.RiskScore) { $_.RiskScore } else { 0 } } -Descending

            $findingCards = ""
            $cardIndex = 0
            foreach ($f in $stFindings) {
                $findingCards += Get-FindingCard -finding $f -index $cardIndex -lowConfList $LowConfidenceCheckNames
                $cardIndex++
            }

            $statusAccordions += @"
        <div class="status-accordion" data-status="$stLower">
            <div class="status-header $stHeaderClass" onclick="toggleStatus(this)">
                <span class="status-title">$st ($($stFindings.Count))</span>
                <span class="status-arrow">&#9660;</span>
            </div>
            <div class="status-body">
                $findingCards
            </div>
        </div>
"@
        }

        $categoryAccordions += @"
    <div class="category-accordion" data-category="$catValue">
        <div class="category-header" onclick="toggleCategory(this)">
            <span class="category-title">$catNameSafe ($($catFindings.Count))</span>
            <span class="category-badges">$badges</span>
            <span class="category-arrow">&#9660;</span>
        </div>
        <div class="category-body">
            $statusAccordions
        </div>
    </div>
"@
    }

    return @"
<section class="section" id="detailed">
    <h2 class="section-title">Detailed Findings</h2>
    <div class="controls-bar">
        <input type="text" id="searchBox" placeholder="Search findings..." onkeyup="applyFilters()">
        <div class="filter-group">
            <label for="categoryFilter">Category:</label>
            <select id="categoryFilter" onchange="applyFilters()">
                <option value="all">All Categories</option>
$categoryOptions
            </select>
        </div>
        <div class="filter-group">
            <label for="statusFilter">Status:</label>
            <select id="statusFilter" onchange="applyFilters()">
                <option value="all">All Statuses</option>
                <option value="fail">FAIL</option>
                <option value="warning">WARNING</option>
                <option value="info">INFO</option>
                <option value="ok">OK</option>
            </select>
        </div>
        <div class="filter-group">
            <label for="riskFilter">Risk:</label>
            <select id="riskFilter" onchange="applyFilters()">
                <option value="all">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
        </div>
        <button class="expand-all-btn" onclick="expandAllCategories()">Expand All</button>
        <button class="expand-all-btn" onclick="collapseAllCategories()">Collapse All</button>
        <button class="clear-filters-btn" onclick="clearFilters()">Clear Filters</button>
        <span class="filter-count" id="filterCount"></span>
    </div>

    $categoryAccordions
</section>
"@
}

function Get-HTMLJavaScript {
    return @'
<script>
    // PR 3 backport: per-finding deep-link copy. Falls back to selection-based
    // copy on browsers where navigator.clipboard is unavailable (e.g., file://
    // in older Chromium without secure-context exemption).
    function copyFindingLink(evt, anchorEl) {
        evt.preventDefault();
        evt.stopPropagation();
        var url = window.location.href.split('#')[0] + anchorEl.getAttribute('href');
        var done = function () {
            anchorEl.classList.add('copied');
            setTimeout(function () { anchorEl.classList.remove('copied'); }, 1500);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(url).then(done, function () {
                window.prompt('Copy this link:', url);
            });
        } else {
            window.prompt('Copy this link:', url);
            done();
        }
    }

    function toggleComplianceDetail(btn) {
        var table = btn.nextElementSibling;
        if (table && table.classList.contains('compliance-detail-table')) {
            if (table.classList.contains('active')) {
                table.classList.remove('active');
                btn.textContent = 'Show Control Details';
            } else {
                table.classList.add('active');
                btn.textContent = 'Hide Control Details';
            }
        }
    }

    function toggleCategory(header) {
        var body = header.nextElementSibling;
        var arrow = header.querySelector('.category-arrow');
        if (body.classList.contains('active')) {
            body.classList.remove('active');
            arrow.classList.remove('open');
        } else {
            body.classList.add('active');
            arrow.classList.add('open');
        }
    }

    function toggleStatus(header) {
        var body = header.nextElementSibling;
        var arrow = header.querySelector('.status-arrow');
        if (body.classList.contains('active')) {
            body.classList.remove('active');
            arrow.classList.remove('open');
        } else {
            body.classList.add('active');
            arrow.classList.add('open');
        }
    }

    function toggleFinding(header) {
        var body = header.nextElementSibling;
        var arrow = header.querySelector('.finding-arrow');
        if (body.classList.contains('active')) {
            body.classList.remove('active');
            if (arrow) arrow.innerHTML = '&#9660;';
        } else {
            body.classList.add('active');
            if (arrow) arrow.innerHTML = '&#9650;';
        }
    }

    function expandAllCategories() {
        document.querySelectorAll('.category-body').forEach(function(b) { b.classList.add('active'); });
        document.querySelectorAll('.category-arrow').forEach(function(a) { a.classList.add('open'); });
        document.querySelectorAll('.status-body').forEach(function(b) { b.classList.add('active'); });
        document.querySelectorAll('.status-arrow').forEach(function(a) { a.classList.add('open'); });
        document.querySelectorAll('.finding-body').forEach(function(b) { b.classList.add('active'); });
        document.querySelectorAll('.finding-arrow').forEach(function(a) { a.innerHTML = '&#9650;'; });
    }

    function collapseAllCategories() {
        document.querySelectorAll('.category-body').forEach(function(b) { b.classList.remove('active'); });
        document.querySelectorAll('.category-arrow').forEach(function(a) { a.classList.remove('open'); });
        document.querySelectorAll('.status-body').forEach(function(b) { b.classList.remove('active'); });
        document.querySelectorAll('.status-arrow').forEach(function(a) { a.classList.remove('open'); });
        document.querySelectorAll('.finding-body').forEach(function(b) { b.classList.remove('active'); });
        document.querySelectorAll('.finding-arrow').forEach(function(a) { a.innerHTML = '&#9660;'; });
    }

    function applyFilters() {
        var searchTerm = document.getElementById('searchBox').value.toLowerCase();
        var categoryVal = document.getElementById('categoryFilter').value;
        var statusVal = document.getElementById('statusFilter').value;
        var riskVal = document.getElementById('riskFilter').value;

        var totalVisible = 0;
        var totalCards = 0;

        document.querySelectorAll('.finding-card').forEach(function(card) {
            totalCards++;
            var show = true;

            if (searchTerm && !card.textContent.toLowerCase().includes(searchTerm)) {
                show = false;
            }
            if (show && categoryVal !== 'all' && card.getAttribute('data-category') !== categoryVal) {
                show = false;
            }
            if (show && statusVal !== 'all' && card.getAttribute('data-status') !== statusVal) {
                show = false;
            }
            if (show && riskVal !== 'all' && card.getAttribute('data-risk') !== riskVal) {
                show = false;
            }

            card.style.display = show ? '' : 'none';
            if (show) totalVisible++;
        });

        document.querySelectorAll('.status-accordion').forEach(function(sa) {
            var visibleCards = sa.querySelectorAll('.finding-card:not([style*="display: none"])').length;
            sa.style.display = visibleCards > 0 ? '' : 'none';
        });

        document.querySelectorAll('.category-accordion').forEach(function(ca) {
            var visibleCards = ca.querySelectorAll('.finding-card:not([style*="display: none"])').length;
            ca.style.display = visibleCards > 0 ? '' : 'none';
        });

        var countEl = document.getElementById('filterCount');
        if (searchTerm || categoryVal !== 'all' || statusVal !== 'all' || riskVal !== 'all') {
            countEl.textContent = 'Showing ' + totalVisible + ' of ' + totalCards + ' findings';
        } else {
            countEl.textContent = '';
        }

        if (searchTerm || categoryVal !== 'all' || statusVal !== 'all' || riskVal !== 'all') {
            document.querySelectorAll('.category-accordion:not([style*="display: none"]) .category-body').forEach(function(b) { b.classList.add('active'); });
            document.querySelectorAll('.category-accordion:not([style*="display: none"]) .category-arrow').forEach(function(a) { a.classList.add('open'); });
            document.querySelectorAll('.status-accordion:not([style*="display: none"]) .status-body').forEach(function(b) { b.classList.add('active'); });
            document.querySelectorAll('.status-accordion:not([style*="display: none"]) .status-arrow').forEach(function(a) { a.classList.add('open'); });
        }
    }

    function clearFilters() {
        document.getElementById('searchBox').value = '';
        document.getElementById('categoryFilter').value = 'all';
        document.getElementById('statusFilter').value = 'all';
        document.getElementById('riskFilter').value = 'all';
        applyFilters();
        collapseAllCategories();
    }

    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            var target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
</script>
'@
}

#endregion

#region Export Module Members

Export-ModuleMember -Function @(
    'New-EnhancedHTMLReport',
    'Test-EntraChecksReportIntegrity'
)

#endregion
