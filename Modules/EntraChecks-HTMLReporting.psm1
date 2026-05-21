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
Import-Module (Join-Path $modulePath "EntraChecks-PrivilegedIdentityRender.psm1") -Force -DisableNameChecking -ErrorAction SilentlyContinue
# NOTE: EntraChecks-Branding.psm1 provides Get-ReportBrandingContext, which
# callers can use to construct the -Branding object passed to
# New-EnhancedHTMLReport. We don't import it here — only its output is
# consumed inside this module — so the caller's import scope wins.

# Module-scoped list of check names that produce findings the team has flagged
# as fixture-verified-only / low-confidence. Empty by default — populate per
# environment via $module:LowConfidenceCheckNames or by editing this file.
$script:LowConfidenceCheckNames = @()

#region HTML Safety Helpers (PR 1 of HTML-Reporting-Consolidation-Plan)

# Centralized encoders + safe-link/safe-id builders. Every dynamic value
# rendered into the cockpit HTML should pass through one of these so the
# encoding decisions are auditable in one place rather than scattered across
# 2,500 lines of string interpolation.
#
# These helpers do NOT alter the output of the existing legacy report
# functions in this module — they're foundation pieces for the cockpit
# renderer that PR 2 introduces. Call sites in existing functions can migrate
# opportunistically; this PR is additive.

function ConvertTo-SafeHtml {
    <#
    .SYNOPSIS
        Encodes arbitrary text for use as HTML element content.
    .DESCRIPTION
        Wraps `[System.Net.WebUtility]::HtmlEncode` with two guarantees the
        raw call doesn't give us:
          1. $null input returns '' (not the literal string "null", not an error).
          2. The implementation is in one place, so a future move to a stricter
             encoder is a one-line change for the whole report path.

        Use this for any value going INTO HTML element content
        (e.g. `<td>$x</td>`). For attribute values use
        `ConvertTo-SafeHtmlAttribute`. For embedding into `<script>` blocks
        use `ConvertTo-SafeHtmlJson`.
    .OUTPUTS
        Encoded string. Empty string for $null / empty input.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-SafeHtmlAttribute {
    <#
    .SYNOPSIS
        Encodes arbitrary text for use INSIDE an HTML attribute.
    .DESCRIPTION
        `WebUtility.HtmlEncode` already escapes `<`, `>`, `&`, `"`, `'` — which
        covers double-quoted attribute contexts. This wrapper exists so
        call-site intent is explicit ("this is being used in an attribute")
        and so a stricter encoder (e.g. AntiXSS) can be swapped in later
        without grep-and-replace across the whole module.

        ALWAYS double-quote the attribute when interpolating the result:

            <input type="text" value="$(ConvertTo-SafeHtmlAttribute -Text $x)" />

        Single-quoted attributes are also safe because HtmlEncode escapes
        `'` to `&#39;`. Avoid unquoted attributes — they're vulnerable to
        whitespace and `>` even with encoding.
    .OUTPUTS
        Encoded string. Empty string for $null / empty input.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-SafeHtmlJson {
    <#
    .SYNOPSIS
        Encodes an object as JSON that's safe to embed in a `<script>` block.
    .DESCRIPTION
        Plain `ConvertTo-Json` output is JSON-safe but NOT HTML-safe. A
        finding description containing `</script>` would break out of the
        script block. JavaScript also treats U+2028 (line separator) and
        U+2029 (paragraph separator) as line terminators inside string
        literals — those need escaping even though JSON doesn't require it.

        This function:
          - calls ConvertTo-Json with the requested depth
          - replaces `<`, `>`, `&` with their `\uXXXX` JSON escapes so the
            embedded string can never close the surrounding `<script>` tag
            or be misinterpreted by HTML-aware parsers
          - escapes U+2028 and U+2029 explicitly

        The result is valid JSON AND safe to drop inside `<script>...</script>`.
    .EXAMPLE
        $payload | ConvertTo-SafeHtmlJson -Depth 10
        # then embed inside <script>const data = $result;</script>
    .OUTPUTS
        Single string of safe JSON.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][AllowNull()] $InputObject,
        [int]$Depth = 10
    )
    process {
        if ($null -eq $InputObject) { return 'null' }
        $json = $InputObject | ConvertTo-Json -Depth $Depth -Compress:$false
        # The four escapes that matter for HTML embedding + JS parsing.
        # Order is irrelevant — replacements don't overlap.
        
        $json = $json `
            -replace '<', '\u003c' `
            -replace '>', '\u003e' `
            -replace '&', '\u0026' `
            -replace "`u{2028}", '\u2028' `
            -replace "`u{2029}", '\u2029'

        return $json
    }
}

function New-SafeExternalLink {
    <#
    .SYNOPSIS
        Builds an `<a>` tag for an external URL with safe scheme validation
        and noopener/noreferrer attributes.
    .DESCRIPTION
        Use this for ANY URL that came from a finding, evidence reference,
        owner block, or any other dynamic source — including URLs that look
        trustworthy (e.g. portal.azure.com). A malicious `javascript:` URL
        smuggled into a Defender finding's `ActionUrl` would otherwise run
        when the user clicks the link.

        Behavior:
          - Only `http://` and `https://` schemes pass; anything else
            (`javascript:`, `data:`, `vbscript:`, `file:`, `chrome:`, etc.)
            is rejected and the function returns the encoded LinkText only,
            wrapped in `<span>` so the user sees the text but can't click it.
          - `rel="noopener noreferrer"` on every external link (prevents
            window.opener access + Referer leakage to third parties).
          - `target="_blank"` so the cockpit isn't navigated away from.
          - URL and link text are HTML-encoded for attribute and content
            contexts respectively.

        $null/empty URL returns the encoded LinkText only.
    .OUTPUTS
        HTML string: either an `<a>` or a `<span>` depending on URL safety.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Url,
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$LinkText
    )
    $safeText = ConvertTo-SafeHtml -Text $LinkText
    if (-not $Url) { return "<span>$safeText</span>" }

    # Scheme check. We deliberately compare against an allowlist rather than
    # blocking known-bad schemes — new dangerous schemes appear over time
    # (e.g. `intent:` on Android, `ms-cxh:` on Windows).
    $allowedSchemes = @('http', 'https')
    $parsedScheme = $null
    if ($Url -match '^([a-zA-Z][a-zA-Z0-9+.\-]*):') {
        $parsedScheme = $matches[1].ToLowerInvariant()
    }
    if (-not $parsedScheme -or $parsedScheme -notin $allowedSchemes) {
        # Reject — render text only, no clickable element.
        return "<span title=`"Link rejected: unsafe scheme`">$safeText</span>"
    }

    $safeUrl = ConvertTo-SafeHtmlAttribute -Text $Url
    return "<a href=`"$safeUrl`" target=`"_blank`" rel=`"noopener noreferrer`">$safeText</a>"
}

function New-SafeElementId {
    <#
    .SYNOPSIS
        Generates a stable, ASCII-safe HTML id from arbitrary input.
    .DESCRIPTION
        HTML id values are author-controlled but in this codebase the inputs
        are dynamic — FindingIds, object names, UPNs, framework labels. Raw
        substitution would produce ids like `id="<img src=x>"` or
        `id="user@contoso.com #1"` which break selectors, break querySelector
        escaping, and open XSS surfaces in JavaScript that later reads them.

        This function:
          - hashes the input with SHA1 (id stability only, not security)
          - returns `<Prefix><first 16 hex chars>` — always ASCII, always
            valid as both an HTML id and a CSS selector.

        SHA1 is fine here: this is for collision-resistant readable ids, not
        cryptography. Two different inputs will not collide in practice; an
        attacker forcing a collision gains nothing.
    .OUTPUTS
        Safe id string, e.g. `ecf-anchor-d8bbd4ad379dae12`.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$InputText,
        [string]$Prefix = 'ecf-anchor-'
    )
    if ([string]::IsNullOrEmpty($InputText)) { $InputText = 'empty' }
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
        $hash = $sha1.ComputeHash($bytes)
        $hex = -join ($hash | ForEach-Object { $_.ToString('x2') })
        return $Prefix + $hex.Substring(0, 16)
    }
    finally {
        $sha1.Dispose()
    }
}

#endregion

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

        # Output of Merge-PrivilegedIdentityRosters (PR 4). When supplied,
        # the standalone HTML report appends a Privileged Identity Roster
        # section with the same visual treatment as the unified report.
        [object]$PrivilegedIdentityRoster,

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

    # PR 5 — Privileged Identity Roster section. Skipped silently if no
    # roster supplied OR the render module isn't loaded.
    $htmlPrivilegedIdentity = ''
    $htmlPrivilegedIdentityCss = ''
    if ($PrivilegedIdentityRoster -and (Get-Command Get-PrivilegedIdentityHtmlSection -ErrorAction SilentlyContinue)) {
        $piMatchSummary = if ($PrivilegedIdentityRoster -is [hashtable] -and $PrivilegedIdentityRoster.ContainsKey('Statistics')) { $PrivilegedIdentityRoster.Statistics } else { $null }
        $htmlPrivilegedIdentity = '<section class="section">' + (Get-PrivilegedIdentityHtmlSection -RosterInput $PrivilegedIdentityRoster -MatchSummary $piMatchSummary) + '</section>'
        $htmlPrivilegedIdentityCss = '<style>' + (Get-PrivilegedIdentityRosterCss) + '</style>'
    }

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
    $htmlPrivilegedIdentityCss
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
        $htmlPrivilegedIdentity
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

#region Cockpit Renderer (PR 2 of HTML-Reporting-Consolidation-Plan)
# The cockpit is the single primary analyst HTML report that will become the
# default in PR 4. It composes existing section builders (executive digest,
# compliance, full findings, integrity footer) plus three new sections
# (Source Posture, Evidence/Provenance, Deep Dive Hub) and basic non-
# interactive Action Queue + Review Queue tables. PR 3 upgrades the queues
# to interactive (filters, pagination, expandable rows). PR 4 flips the
# orchestrator default.

function Get-CockpitSourcePostureSection {
    <#
    .SYNOPSIS
        Renders the Source Posture cards summarising what was collected.
    .DESCRIPTION
        One card per data source. Each card shows collection status
        (collected / not collected / failed), provider name, and a brief
        metric where available. Sources for which we have no data render
        a "Not collected" placeholder so the analyst knows the section
        exists but the data wasn't gathered.
    #>
    [OutputType([string])]
    param(
        [object]$SecureScore,
        [object]$DefenderCompliance,
        [object]$AzurePolicy,
        [object]$PurviewCompliance,
        [object]$HybridCorrelation,
        [object]$PrivilegedIdentityRoster
    )

    function _Card {
        param([string]$Name, [bool]$Collected, [string]$Metric, [string]$Anchor)
        $statusClass = if ($Collected) { 'good' } else { 'muted' }
        $statusLabel = if ($Collected) { 'Collected' } else { 'Not collected' }
        $safeName = ConvertTo-SafeHtml -Text $Name
        $safeMetric = ConvertTo-SafeHtml -Text $Metric
        $safeAnchor = ConvertTo-SafeHtmlAttribute -Text $Anchor
        $linkAttr = if ($Anchor) { " data-anchor=`"$safeAnchor`"" } else { '' }
        return @"
            <div class="source-card $statusClass"$linkAttr>
                <h4>$safeName</h4>
                <p class="source-status">$statusLabel</p>
                <p class="source-metric">$safeMetric</p>
            </div>
"@
    }

    # Pre-compute metrics so the array-of-Card-calls is parser-friendly.
    # Inline multi-line `if (...) { ... } else { '' }` expressions inside
    # `_Card -Metric (...)` get parsed as separate commands across lines
    # in PowerShell's array literal context.
    $secureScoreMetric = ''
    if ($SecureScore -and $SecureScore.PSObject.Properties['CurrentScore']) {
        $secureScoreMetric = "Score: $($SecureScore.CurrentScore)"
    }
    $defenderMetric = ''
    if ($DefenderCompliance -and $DefenderCompliance.PSObject.Properties['Standards']) {
        $defenderMetric = "$(@($DefenderCompliance.Standards).Count) standards"
    }
    $policyMetric = ''
    if ($AzurePolicy -and $AzurePolicy.PSObject.Properties['Initiatives']) {
        $policyMetric = "$(@($AzurePolicy.Initiatives).Count) initiatives"
    }
    $purviewMetric = ''
    if ($PurviewCompliance -and $PurviewCompliance.PSObject.Properties['Assessments']) {
        $purviewMetric = "$(@($PurviewCompliance.Assessments).Count) assessments"
    }
    $hybridMetric = ''
    if ($HybridCorrelation -and $HybridCorrelation.PSObject.Properties['Correlations']) {
        $hybridMetric = "$(@($HybridCorrelation.Correlations).Count) correlations"
    }
    $rosterMetric = ''
    if ($PrivilegedIdentityRoster -and $PrivilegedIdentityRoster.PSObject.Properties['Statistics']) {
        $rosterMetric = "$($PrivilegedIdentityRoster.Statistics.TotalIdentities) identities"
    }

    $cards = @(
        _Card -Name 'EntraChecks (Internal)' -Collected $true -Metric 'Always present'
        _Card -Name 'Microsoft Secure Score' -Collected ([bool]$SecureScore) -Metric $secureScoreMetric
        _Card -Name 'Defender for Cloud' -Collected ([bool]$DefenderCompliance) -Metric $defenderMetric
        _Card -Name 'Azure Policy' -Collected ([bool]$AzurePolicy) -Metric $policyMetric
        _Card -Name 'Purview Compliance Manager' -Collected ([bool]$PurviewCompliance) -Metric $purviewMetric
        _Card -Name 'Hybrid Correlation' -Collected ([bool]$HybridCorrelation) -Metric $hybridMetric
        _Card -Name 'Privileged Identity Roster' -Collected ([bool]$PrivilegedIdentityRoster) -Metric $rosterMetric
    )
    $cardHtml = $cards -join "`n"
    return @"
<section class="cockpit-section" id="source-posture">
    <h2 class="cockpit-section-title">Source Posture</h2>
    <p class="cockpit-section-lede">What was collected, and from where. Sources marked "Not collected" can be enabled with the matching <code>-Include&lt;Source&gt;</code> switch.</p>
    <div class="source-card-grid">
$cardHtml
    </div>
</section>
"@
}

function Get-CockpitEvidenceProvenanceSection {
    <#
    .SYNOPSIS
        Renders the Evidence / Provenance flat table.
    .DESCRIPTION
        One row per Evidence reference flattened across all findings. Carries
        EvidenceId, Source, Provider, Cmdlet, Scope, ResourceId, Hash, and
        RedactionStatus so an auditor can trace any finding back to the API
        call that produced it. Section is suppressed when no v2 Evidence
        data exists (legacy findings).
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)][array]$Findings)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($f in $Findings) {
        if (-not $f.PSObject.Properties['Evidence']) { continue }
        $ev = $f.Evidence
        if (-not $ev) { continue }
        foreach ($e in @($ev)) {
            if ($null -eq $e) { continue }
            $row = [pscustomobject]@{
                EvidenceId = [string]$e.EvidenceId
                FindingId = [string]$f.FindingId
                Source = [string]$e.Source
                Provider = [string]$e.Provider
                Cmdlet = [string]$e.Cmdlet
                QueryScope = [string]$e.QueryScope
                ResourceId = [string]$e.ResourceId
                Hash = [string]$e.Hash
                RedactionStatus = [string]$e.RedactionStatus
            }
            $rows.Add($row)
        }
    }
    if ($rows.Count -eq 0) { return '' }

    $rowsHtml = ($rows | ForEach-Object {
            $eid = ConvertTo-SafeHtml -Text $_.EvidenceId
            $fid = ConvertTo-SafeHtml -Text $_.FindingId
            $src = ConvertTo-SafeHtml -Text $_.Source
            $prov = ConvertTo-SafeHtml -Text $_.Provider
            $cmd = ConvertTo-SafeHtml -Text $_.Cmdlet
            $scope = ConvertTo-SafeHtml -Text $_.QueryScope
            $resId = ConvertTo-SafeHtml -Text $_.ResourceId
            $hash = ConvertTo-SafeHtml -Text $_.Hash
            $redact = ConvertTo-SafeHtml -Text $_.RedactionStatus
            "<tr><td><code>$eid</code></td><td><code>$fid</code></td><td>$src</td><td>$prov</td><td>$cmd</td><td>$scope</td><td><code>$resId</code></td><td class=`"hash-cell`">$hash</td><td>$redact</td></tr>"
        }) -join "`n"

    return @"
<section class="cockpit-section" id="evidence-provenance">
    <h2 class="cockpit-section-title">Evidence and Provenance</h2>
    <p class="cockpit-section-lede">Provenance audit trail. Every evidence reference includes the source, cmdlet, scope, hash, and redaction status so any finding can be traced back to the API call that produced it.</p>
    <table class="provenance-table">
        <thead>
            <tr>
                <th>Evidence ID</th><th>Finding ID</th><th>Source</th><th>Provider</th><th>Cmdlet</th><th>Scope</th><th>Resource</th><th>Hash</th><th>Redaction</th>
            </tr>
        </thead>
        <tbody>
$rowsHtml
        </tbody>
    </table>
</section>
"@
}

function Get-CockpitCompliancePostureSection {
    <#
    .SYNOPSIS
        Renders the Defender for Cloud Compliance Posture section.
    .DESCRIPTION
        Heatmap-style standard rows. Each row shows the framework name,
        aggregate compliance percentage across subscriptions, a stacked
        pass/fail bar, and P/F counts. Each row is a <details> accordion
        that expands to show up to the top 25 failing controls for that
        standard, sorted by failed-resource count descending.

        Returns the empty string when $DefenderCompliance is $null (the
        cockpit assembler is responsible for deciding whether to call this
        function). Standards with zero failing controls render in a
        secondary "fully passing" group at the bottom so analyst attention
        stays on the worst-first ordering.
    #>
    [OutputType([string])]
    param(
        [object]$DefenderCompliance,
        [int]$MaxControlsPerStandard = 25
    )

    if (-not $DefenderCompliance) { return '' }
    # Hashtables don't expose keys through PSObject.Properties the way
    # PSCustomObjects do, so check direct property access — it works for
    # both shapes the orchestrator might hand us.
    if (-not $DefenderCompliance.Standards) { return '' }

    # The Standards property is a hashtable keyed by StandardId. Aggregate
    # Passed/Failed across subscriptions and join each standard to its
    # per-control rows from the flat Controls array.
    $controls = @()
    if ($DefenderCompliance.Controls) {
        $controls = @($DefenderCompliance.Controls)
    }
    $controlsByFramework = @{}
    foreach ($c in $controls) {
        $fw = [string]$c.Framework
        if (-not $controlsByFramework.ContainsKey($fw)) {
            $controlsByFramework[$fw] = New-Object System.Collections.Generic.List[object]
        }
        $controlsByFramework[$fw].Add($c)
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $DefenderCompliance.Standards.GetEnumerator()) {
        $std = $entry.Value
        $totalPassed = 0
        $totalFailed = 0
        if ($std.Subscriptions) {
            foreach ($subRow in $std.Subscriptions) {
                # $subRow is a PSCustomObject (see DefenderCompliance.psm1
                # line ~670), so PSObject.Properties works here.
                if ($subRow.PSObject.Properties['Passed']) { $totalPassed += [int]$subRow.Passed }
                if ($subRow.PSObject.Properties['Failed']) { $totalFailed += [int]$subRow.Failed }
            }
        }
        $totalAssessed = $totalPassed + $totalFailed
        $compliancePercent = if ($totalAssessed -gt 0) {
            [math]::Round(($totalPassed / $totalAssessed) * 100, 1)
        } else { 0 }

        $shortName = if ($std.ShortName) {
            [string]$std.ShortName
        } else { [string]$entry.Key }
        $longName = if ($std.Name) {
            [string]$std.Name
        } else { $shortName }

        $rows.Add([PSCustomObject]@{
                StandardId        = [string]$entry.Key
                ShortName         = $shortName
                LongName          = $longName
                Passed            = $totalPassed
                Failed            = $totalFailed
                CompliancePercent = $compliancePercent
                Controls          = if ($controlsByFramework.ContainsKey($shortName)) {
                    $controlsByFramework[$shortName]
                } else {
                    New-Object System.Collections.Generic.List[object]
                }
            })
    }

    # Worst-first: standards with failed controls, sorted by compliance %
    # ascending. Fully-passing standards sink to the bottom so the analyst
    # sees real gaps before the green checkmarks.
    $withGaps = @($rows | Where-Object { $_.Failed -gt 0 } | Sort-Object CompliancePercent)
    $allPassing = @($rows | Where-Object { $_.Failed -eq 0 } | Sort-Object ShortName)

    if ($rows.Count -eq 0) {
        return @"
<section class="cockpit-section" id="compliance-posture">
    <h2 class="cockpit-section-title">Compliance Posture (Defender for Cloud)</h2>
    <p class="cockpit-section-lede empty">No compliance standards returned from Defender for Cloud. Confirm the assessment ran with Azure credentials that have <code>Reader</code> on at least one subscription.</p>
</section>
"@
    }

    function _RenderRow {
        param([PSCustomObject]$Row, [int]$MaxControls)
        $short = ConvertTo-SafeHtml -Text $Row.ShortName
        $long = ConvertTo-SafeHtml -Text $Row.LongName
        $pct = $Row.CompliancePercent
        $passed = $Row.Passed
        $failed = $Row.Failed
        $passedPct = if (($passed + $failed) -gt 0) {
            [math]::Round(($passed / ($passed + $failed)) * 100, 2)
        } else { 0 }
        $failedPct = if (($passed + $failed) -gt 0) { 100 - $passedPct } else { 0 }
        $sevClass = if ($pct -ge 80) { 'good' } elseif ($pct -ge 60) { 'warn' } else { 'bad' }

        # Pick failing controls; sort by FailedResources desc, then ControlId.
        $failingControls = @($Row.Controls | Where-Object {
                [string]$_.Status -eq 'Failed'
            } | Sort-Object @{ Expression = {
                    if ($_.PSObject.Properties['FailedResources']) { -([int]$_.FailedResources) } else { 0 }
                }
            }, ControlId)

        $totalFailingControls = $failingControls.Count
        $shown = $failingControls | Select-Object -First $MaxControls

        $controlCardsHtml = ''
        if ($shown.Count -gt 0) {
            $controlCardsHtml = ($shown | ForEach-Object {
                    $ctrlId = ConvertTo-SafeHtml -Text ([string]$_.ControlId)
                    $title = ''
                    if ($_.PSObject.Properties['ControlTitle']) { $title = [string]$_.ControlTitle }
                    if ([string]::IsNullOrWhiteSpace($title) -and $_.PSObject.Properties['Description']) {
                        $title = [string]$_.Description
                    }
                    $titleHtml = ConvertTo-SafeHtml -Text $title
                    $failedRes = if ($_.PSObject.Properties['FailedResources']) { [int]$_.FailedResources } else { 0 }
                    $passedRes = if ($_.PSObject.Properties['PassedResources']) { [int]$_.PassedResources } else { 0 }
                    $subName = if ($_.PSObject.Properties['SubscriptionName']) {
                        ConvertTo-SafeHtml -Text ([string]$_.SubscriptionName)
                    } else { '' }
                    $remediation = if ($_.PSObject.Properties['Remediation']) {
                        ConvertTo-SafeHtml -Text ([string]$_.Remediation)
                    } else { '' }
                    $subRow = if ($subName) { "<span class=`"compliance-control-sub`">$subName</span>" } else { '' }
                    @"
            <article class="compliance-control-card">
                <header class="compliance-control-head">
                    <code class="compliance-control-id">$ctrlId</code>
                    $subRow
                    <span class="compliance-control-count" title="Failed resources / passed resources">${failedRes} failed &middot; ${passedRes} passed</span>
                </header>
                <p class="compliance-control-title">$titleHtml</p>
                <p class="compliance-control-remediation">$remediation</p>
            </article>
"@
                }) -join "`n"
        }

        $moreNote = ''
        if ($totalFailingControls -gt $MaxControls) {
            $extra = $totalFailingControls - $MaxControls
            $moreNote = "<p class=`"compliance-control-overflow`">+ $extra additional failing control(s) — see the Defender for Cloud regulatory compliance blade for the full list.</p>"
        }
        $emptyNote = ''
        if ($totalFailingControls -eq 0) {
            $emptyNote = '<p class="compliance-control-empty">No failing controls reported for this standard.</p>'
        }

        $controlsBody = if ($controlCardsHtml) { $controlCardsHtml } else { $emptyNote }

        return @"
<details class="compliance-standard $sevClass">
    <summary class="compliance-standard-summary">
        <span class="compliance-standard-name">$short</span>
        <span class="compliance-standard-fullname">$long</span>
        <span class="compliance-standard-pct" aria-label="Compliance percentage">${pct}%</span>
        <span class="compliance-standard-bar" role="img" aria-label="Pass/fail ratio">
            <span class="bar-pass" style="width: ${passedPct}%"></span><span class="bar-fail" style="width: ${failedPct}%"></span>
        </span>
        <span class="compliance-standard-counts">P:$passed &nbsp;&middot;&nbsp; F:$failed</span>
        <span class="compliance-standard-caret" aria-hidden="true">&#x25BE;</span>
    </summary>
    <div class="compliance-standard-body">
        $controlsBody
        $moreNote
    </div>
</details>
"@
    }

    $withGapsHtml = ($withGaps | ForEach-Object { _RenderRow -Row $_ -MaxControls $MaxControlsPerStandard }) -join "`n"
    $allPassingHtml = ''
    if ($allPassing.Count -gt 0) {
        $passingRows = ($allPassing | ForEach-Object { _RenderRow -Row $_ -MaxControls $MaxControlsPerStandard }) -join "`n"
        $allPassingHtml = @"
<details class="compliance-passing-group">
    <summary class="compliance-passing-group-summary">All passing standards ($($allPassing.Count))</summary>
    <div class="compliance-passing-group-body">
$passingRows
    </div>
</details>
"@
    }

    $summary = $DefenderCompliance.Summary
    $totalControls = if ($summary -and $null -ne $summary.TotalControls) { [int]$summary.TotalControls } else { 0 }
    $passedControls = if ($summary -and $null -ne $summary.PassedControls) { [int]$summary.PassedControls } else { 0 }
    $failedControls = if ($summary -and $null -ne $summary.FailedControls) { [int]$summary.FailedControls } else { 0 }
    $totalStandards = if ($summary -and $null -ne $summary.TotalStandards) { [int]$summary.TotalStandards } else { $rows.Count }
    $totalSubs = if ($summary -and $null -ne $summary.TotalSubscriptions) { [int]$summary.TotalSubscriptions } else { 0 }
    $overallPct = if ($totalControls -gt 0) {
        [math]::Round(($passedControls / $totalControls) * 100, 1)
    } else { 0 }

    return @"
<section class="cockpit-section" id="compliance-posture">
    <h2 class="cockpit-section-title">Compliance Posture (Defender for Cloud)</h2>
    <p class="cockpit-section-lede">$totalStandards standard(s) assessed across $totalSubs subscription(s). Overall control compliance: <strong>$overallPct%</strong> ($passedControls passing / $failedControls failing of $totalControls). Worst-first ordering — expand a standard to see the highest-impact failing controls.</p>
    <div class="compliance-standard-list">
$withGapsHtml
$allPassingHtml
    </div>
    <p class="cockpit-section-note">Up to $MaxControlsPerStandard failing controls per standard shown. Defender for Cloud assesses additional controls beyond what is surfaced here; open the Azure portal Regulatory Compliance blade for the complete catalog.</p>
</section>
"@
}

function Get-CockpitDeepDiveHubSection {
    <#
    .SYNOPSIS
        Renders the Deep Dive Hub — status cards for each on-demand report.
    .DESCRIPTION
        Each domain (Secure Score, Defender, Azure Policy, Purview, Delta,
        Privileged Identity) gets a card with one of four honest states:

          1. Generated   — the deep-dive HTML was produced this run.
          2. Skipped (no data)       — the user requested it but the
             underlying assessment returned no rows.
          3. Skipped (not collected) — the matching module wasn't run
             this assessment, so there's nothing to report on.
          4. Skipped (not requested) — the user did not tick the box.

        The CockpitDir parameter (parent directory of the cockpit HTML
        file) is required so the "Open deep dive" link can render the
        correct relative href: deep-dive files live in a `DeepDives/`
        sub-folder alongside the cockpit, not next to it, so a plain
        filename href returns ERR_FILE_NOT_FOUND in the browser.
    #>
    [OutputType([string])]
    param(
        [hashtable]$DeepDives = @{},
        [string[]]$RequestedDeepDives = @(),
        [hashtable]$Availability = @{},
        [string]$CockpitDir = ''
    )

    $domains = @(
        @{ Key = 'SecureScore'; Name = 'Microsoft Secure Score' }
        @{ Key = 'DefenderCompliance'; Name = 'Defender for Cloud Compliance' }
        @{ Key = 'AzurePolicy'; Name = 'Azure Policy Initiatives' }
        @{ Key = 'PurviewCompliance'; Name = 'Purview Compliance Manager' }
        @{ Key = 'Delta'; Name = 'Delta vs Previous Assessment' }
        @{ Key = 'PrivilegedIdentity'; Name = 'Privileged Identity Roster' }
    )

    $cardsHtml = ($domains | ForEach-Object {
            $key = $_.Key
            $name = ConvertTo-SafeHtml -Text $_.Name
            $shortName = $_.Name
            $hint = ConvertTo-SafeHtml -Text ("To include the $shortName report in your next run, tick its box in the Deep-dive reports section before clicking Run assessment.")

            $wasRequested = $RequestedDeepDives -contains $key
            $hasArtifact = ($DeepDives.ContainsKey($key) -and $DeepDives[$key])
            $hasData = if ($Availability.ContainsKey($key)) { [bool]$Availability[$key] } else { $true }

            if ($hasArtifact) {
                # Build a relative href the cockpit's <a> can actually
                # follow. Deep-dive files live in `<reportDir>/DeepDives/`
                # while the cockpit sits at `<reportDir>/<cockpit>.html`,
                # so the link must include the parent folder. Try the
                # platform's relative-path helper when CockpitDir is known;
                # fall back to "DeepDives/<filename>" otherwise (matches
                # the orchestrator's actual layout for Cockpit mode).
                $deepPath = [string]$DeepDives[$key]
                $rel = ''
                if ($CockpitDir) {
                    try {
                        $rel = [System.IO.Path]::GetRelativePath($CockpitDir, $deepPath)
                    } catch { $rel = '' }
                }
                if (-not $rel -or $rel -eq $deepPath) {
                    $parent = Split-Path -Leaf (Split-Path -Parent $deepPath)
                    $leaf = Split-Path -Leaf $deepPath
                    $rel = if ($parent) { "$parent/$leaf" } else { $leaf }
                }
                # Normalize backslashes for cross-platform href correctness.
                $rel = $rel -replace '\\', '/'
                $relAttr = ConvertTo-SafeHtmlAttribute -Text $rel
                $linkHtml = "<a href=`"$relAttr`">Open deep dive</a>"
                "<div class=`"deep-dive-card generated`"><h4>$name</h4><p class=`"status`">Generated</p><p>$linkHtml</p></div>"
            }
            elseif ($wasRequested -and -not $hasData) {
                "<div class=`"deep-dive-card no-data`"><h4>$name</h4><p class=`"status`">Skipped &mdash; no data</p><p class=`"hint`">The assessment ran but didn't return any data for this surface. The most common causes are a missing Microsoft license (e.g. Defender for Cloud, Microsoft Purview, Azure AD P2) or a role on the signed-in account that lacks read access. See the Source Posture panel above for what was collected.</p></div>"
            }
            elseif ($wasRequested) {
                # Requested, data was there, but no artifact was produced —
                # rare, e.g. reporter threw partway through. Engine log
                # has the underlying error.
                "<div class=`"deep-dive-card no-data`"><h4>$name</h4><p class=`"status`">Skipped &mdash; report not produced</p><p class=`"hint`">The data was collected but the deep-dive report didn't write out successfully. Re-run the assessment to retry; if it persists, capture the log and open an issue.</p></div>"
            }
            elseif (-not $hasData) {
                "<div class=`"deep-dive-card not-available`"><h4>$name</h4><p class=`"status`">Skipped &mdash; not collected</p><p class=`"hint`">The matching module wasn't selected for this assessment, so there's nothing to report on. Tick its module checkbox before re-running.</p></div>"
            }
            else {
                "<div class=`"deep-dive-card not-selected`"><h4>$name</h4><p class=`"status`">Skipped &mdash; not requested</p><p class=`"hint`">$hint</p></div>"
            }
        }) -join "`n"

    return @"
<section class="cockpit-section" id="deep-dive-hub">
    <h2 class="cockpit-section-title">Deep Dive Hub</h2>
    <p class="cockpit-section-lede">Detailed per-domain reports that accompany this cockpit. Each card below shows whether the report was generated, skipped because the data source returned nothing (e.g. missing license or read role), skipped because the module wasn't selected, or skipped because the box wasn't ticked when the run was launched.</p>
    <div class="deep-dive-grid">
$cardsHtml
    </div>
</section>
"@
}

function Get-CockpitFindingRowSearchHay {
    <#
    Build the lowercase "search haystack" string for a finding's data-search
    attribute. Concatenates the fields users are likely to grep against,
    HTML-attribute-encoded once. The inline JS does a case-insensitive
    substring match.
    #>
    param([Parameter(Mandatory)] $Finding)
    $findingIdStr = ''
    if ($Finding.PSObject.Properties['FindingId']) { $findingIdStr = [string]$Finding.FindingId }
    $parts = @(
        [string]$Finding.Object
        [string]$Finding.Description
        [string]$Finding.Remediation
        [string]$Finding.CheckName
        [string]$Finding.Type
        [string]$Finding.Source
        $findingIdStr
    )
    if ($Finding.PSObject.Properties['Owner'] -and $Finding.Owner) {
        $parts += [string]$Finding.Owner.DisplayName
        $parts += [string]$Finding.Owner.Email
    }
    return (($parts | Where-Object { $_ }) -join ' ').ToLowerInvariant()
}

function Get-CockpitFindingRowBodyId {
    <#
    Returns a stable, ASCII-safe DOM id for a finding's expandable body.
    The matching <button class="cockpit-row-header"> uses this id as the
    target of aria-controls so screen readers know which content the
    expand button controls. Stable across runs so deep links survive.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)] $Finding)
    # Prefer FindingId when present — it's already a deterministic hash.
    # Otherwise derive from (Description|Object) like the legacy
    # Get-DetailedFindingsSection anchor.
    $basis = if ($Finding.PSObject.Properties['FindingId'] -and $Finding.FindingId) {
        [string]$Finding.FindingId
    } else {
        "$($Finding.Description)|$($Finding.Object)"
    }
    return New-SafeElementId -InputText $basis -Prefix 'cockpit-body-'
}

function Get-CockpitFindingRowBody {
    <#
    Renders the expandable row body shared by all 3 queue sections — surfaces
    v2 metadata that's too verbose for the always-visible summary row.
    Every dynamic value goes through ConvertTo-SafeHtml so XSS attempts
    via Description/Owner/etc. are neutralised.

    -BodyId is the DOM id the parent button's aria-controls points at.
    Get it via Get-CockpitFindingRowBodyId so the renderer and button
    stay in sync.
    #>
    param(
        [Parameter(Mandatory)] $Finding,
        [Parameter(Mandatory)][string]$BodyId
    )
    $obj = ConvertTo-SafeHtml -Text ([string]$Finding.Object)
    $desc = ConvertTo-SafeHtml -Text ([string]$Finding.Description)
    $rem = ConvertTo-SafeHtml -Text ([string]$Finding.Remediation)
    $src = ConvertTo-SafeHtml -Text ([string]$Finding.Source)
    $checkName = ConvertTo-SafeHtml -Text ([string]$Finding.CheckName)

    $ownerLine = ''
    if ($Finding.PSObject.Properties['Owner'] -and $Finding.Owner -and [string]$Finding.Owner.OwnerType -and $Finding.Owner.OwnerType -ne 'Unknown') {
        $name = ConvertTo-SafeHtml -Text ([string]$Finding.Owner.DisplayName)
        $email = ConvertTo-SafeHtml -Text ([string]$Finding.Owner.Email)
        $due = ConvertTo-SafeHtml -Text ([string]$Finding.Owner.DueDate)
        $ownerLine = "<p><strong>Owner:</strong> $name"
        if ($email) { $ownerLine += " ($email)" }
        if ($due) { $ownerLine += " &middot; <strong>Due:</strong> $due" }
        $ownerLine += '</p>'
    }

    $exceptionLine = ''
    if ($Finding.PSObject.Properties['Exception'] -and $Finding.Exception -and [string]$Finding.Exception.Status -and $Finding.Exception.Status -ne 'None') {
        $st = ConvertTo-SafeHtml -Text ([string]$Finding.Exception.Status)
        $type = ConvertTo-SafeHtml -Text ([string]$Finding.Exception.Type)
        $expires = ConvertTo-SafeHtml -Text ([string]$Finding.Exception.ExpiresAt)
        $just = ConvertTo-SafeHtml -Text ([string]$Finding.Exception.Justification)
        $parts = @("<strong>Exception:</strong> $st")
        if ($type) { $parts += $type }
        if ($expires) { $parts += "expires $expires" }
        $exceptionLine = '<p>' + ($parts -join ' &middot; ') + '</p>'
        if ($just) {
            $exceptionLine += "<p class=`"cockpit-justification`">$just</p>"
        }
    }

    $evidenceLine = ''
    if ($Finding.PSObject.Properties['Evidence'] -and $Finding.Evidence) {
        $count = @($Finding.Evidence).Count
        if ($count -gt 0) {
            $evidenceLine = "<p class=`"cockpit-meta-line`"><strong>Evidence:</strong> $count reference$(if ($count -ne 1) {'s'}) &mdash; see Evidence and Provenance section below.</p>"
        }
    }

    $findingIdLine = ''
    if ($Finding.PSObject.Properties['FindingId'] -and $Finding.FindingId) {
        $idSafe = ConvertTo-SafeHtml -Text ([string]$Finding.FindingId)
        $findingIdLine = "<p class=`"cockpit-finding-id`"><code>$idSafe</code></p>"
    }

    $bodyIdSafe = ConvertTo-SafeHtml -Text $BodyId

    return @"
<div class="cockpit-row-body" id="$bodyIdSafe" role="region">
    <div class="cockpit-row-body-grid">
        <div><strong>Object:</strong> $obj</div>
        <div><strong>Source:</strong> $src</div>
        <div><strong>Check:</strong> $checkName</div>
    </div>
    <p><strong>Description:</strong> $desc</p>
    $ownerLine
    $exceptionLine
    <p><strong>Remediation:</strong> $rem</p>
    $evidenceLine
    $findingIdLine
</div>
"@
}

function Get-CockpitActionQueueSection {
    <#
    .SYNOPSIS
        Interactive Action Queue with filters, expandable rows, and pagination.
    .DESCRIPTION
        Filter rule:
          Include: Disposition in {Open, ActionRequired, Review, ExpiredException}.
          Exclude: Passing, Informational, AcceptedRisk, CompensatingControl,
                   FalsePositive, OutOfScope, Resolved, Suppressed.
        Legacy fallback: Status in {FAIL, WARNING, REVIEW}.
        Sort order (plan §10.2):
          1. ExpiredException dispositions first (don't let lapsed waivers hide)
          2. Critical / High risk
          3. Earliest Owner.DueDate
          4. Priority score (descending)
          5. Owner DisplayName
        Inline JS (Get-CockpitJavaScript) wires the filter inputs to data-*
        attributes on each row.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][array]$EnhancedFindings,
        [int]$MaxInitialRows = 100
    )

    $actionable = @('Open', 'ActionRequired', 'Review', 'ExpiredException')
    $queue = @($EnhancedFindings | Where-Object {
            $disp = if ($_.PSObject.Properties['Disposition']) { [string]$_.Disposition } else { '' }
            if ($disp) { return ($disp -in $actionable) }
            return ($_.Status -in @('FAIL', 'WARNING', 'REVIEW'))
        })

    # Documented sort order. Sort keys built as an array so the multi-line
    # form doesn't fight with PSScriptAnalyzer's indentation rule for
    # backtick-continued pipelines.
    $sortKeys = @(
        @{ Expression = { if ([string]$_.Disposition -eq 'ExpiredException') { 0 } else { 1 } } }
        @{ Expression = { switch ([string]$_.RiskLevel) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } } } }
        @{ Expression = { if ($_.PSObject.Properties['Owner'] -and $_.Owner -and $_.Owner.DueDate) { [string]$_.Owner.DueDate } else { 'zzz' } } }
        @{ Expression = { if ($_.PSObject.Properties['PriorityScore'] -and $null -ne $_.PriorityScore) { -1 * [double]$_.PriorityScore } else { 0 } } }
        @{ Expression = { if ($_.PSObject.Properties['Owner'] -and $_.Owner) { [string]$_.Owner.DisplayName } else { 'zzz' } } }
    )
    $queue = $queue | Sort-Object -Property $sortKeys

    if ($queue.Count -eq 0) {
        return @"
<section class="cockpit-section cockpit-interactive" id="action-queue" data-max-initial-rows="$MaxInitialRows">
    <h2 class="cockpit-section-title">Action Queue (0)</h2>
    <p class="cockpit-section-lede empty">No findings need immediate action. Approved exceptions and passing checks are still listed under Full Findings.</p>
</section>
"@
    }

    # Build filter option sets from the live data so dropdowns only offer
    # values that exist in the current run.
    $statusOpts = ($queue | ForEach-Object { [string]$_.Status } | Where-Object { $_ } | Sort-Object -Unique)
    $riskOpts = ($queue | ForEach-Object { [string]$_.RiskLevel } | Where-Object { $_ } | Sort-Object -Unique)
    $dispOpts = ($queue | ForEach-Object { [string]$_.Disposition } | Where-Object { $_ } | Sort-Object -Unique)

    $statusOptionsHtml = ($statusOpts | ForEach-Object {
            $v = ConvertTo-SafeHtmlAttribute -Text $_
            "<option value=`"$($v.ToLowerInvariant())`">$v</option>"
        }) -join ''
    $riskOptionsHtml = ($riskOpts | ForEach-Object {
            $v = ConvertTo-SafeHtmlAttribute -Text $_
            "<option value=`"$($v.ToLowerInvariant())`">$v</option>"
        }) -join ''
    $dispOptionsHtml = ($dispOpts | ForEach-Object {
            $v = ConvertTo-SafeHtmlAttribute -Text $_
            "<option value=`"$($v.ToLowerInvariant())`">$v</option>"
        }) -join ''

    $rowsHtml = ($queue | ForEach-Object {
            $status = [string]$_.Status
            $statusSafe = ConvertTo-SafeHtml -Text $status
            $statusAttr = ConvertTo-SafeHtmlAttribute -Text $status.ToLowerInvariant()
            $disp = [string]$_.Disposition
            $dispSafe = ConvertTo-SafeHtml -Text $disp
            $dispAttr = ConvertTo-SafeHtmlAttribute -Text $disp.ToLowerInvariant()
            $risk = [string]$_.RiskLevel
            $riskSafe = ConvertTo-SafeHtml -Text $risk
            $riskAttr = ConvertTo-SafeHtmlAttribute -Text $risk.ToLowerInvariant()
            $obj = ConvertTo-SafeHtml -Text ([string]$_.Object)
            $desc = ConvertTo-SafeHtml -Text ([string]$_.Description)
            $owner = ''
            if ($_.PSObject.Properties['Owner'] -and $_.Owner -and $_.Owner.OwnerType -and $_.Owner.OwnerType -ne 'Unknown') {
                $owner = ConvertTo-SafeHtml -Text ([string]$_.Owner.DisplayName)
            }
            $searchHay = ConvertTo-SafeHtmlAttribute -Text (Get-CockpitFindingRowSearchHay -Finding $_)
            $bodyId = Get-CockpitFindingRowBodyId -Finding $_
            $bodyIdAttr = ConvertTo-SafeHtmlAttribute -Text $bodyId
            $bodyHtml = Get-CockpitFindingRowBody -Finding $_ -BodyId $bodyId
            @"
<div class="cockpit-row" data-status="$statusAttr" data-disposition="$dispAttr" data-risk="$riskAttr" data-search="$searchHay">
    <button type="button" class="cockpit-row-header" aria-expanded="false" aria-controls="$bodyIdAttr">
        <span class="cockpit-badge status-$statusAttr">$statusSafe</span>
        <span class="cockpit-badge risk-$riskAttr">$riskSafe</span>
        <span class="cockpit-cell-object">$obj</span>
        <span class="cockpit-cell-desc">$desc</span>
        <span class="cockpit-cell-owner">$owner</span>
        <span class="cockpit-cell-disposition">$dispSafe</span>
        <span class="cockpit-caret" aria-hidden="true">&#9660;</span>
    </button>
    $bodyHtml
</div>
"@
        }) -join "`n"

    return @"
<section class="cockpit-section cockpit-interactive" id="action-queue" data-max-initial-rows="$MaxInitialRows">
    <h2 class="cockpit-section-title">Action Queue (<span class="cockpit-total-count">$($queue.Count)</span>)</h2>
    <p class="cockpit-section-lede">Findings that need attention right now. Approved non-expired exceptions are excluded; expired exceptions surface here so they don't slip through. Click any row to expand for the full v2 detail (Owner, Exception, Evidence, FindingId).</p>
    <div class="cockpit-filters">
        <input type="search" placeholder="Search description, object, owner..." data-filter-key="_search" aria-label="Search Action Queue" />
        <select data-filter-key="status" aria-label="Filter by status">
            <option value="">All statuses</option>
            $statusOptionsHtml
        </select>
        <select data-filter-key="risk" aria-label="Filter by risk level">
            <option value="">All risk levels</option>
            $riskOptionsHtml
        </select>
        <select data-filter-key="disposition" aria-label="Filter by disposition">
            <option value="">All dispositions</option>
            $dispOptionsHtml
        </select>
        <span class="cockpit-counter" aria-live="polite"></span>
    </div>
    <div class="cockpit-row-list">
$rowsHtml
    </div>
    <button type="button" class="cockpit-show-more" data-section-id="action-queue">Show more (100 at a time)</button>
</section>
"@
}

function Get-CockpitReviewQueueSection {
    <#
    .SYNOPSIS
        Interactive Review Queue with filters and expandable rows.
    .DESCRIPTION
        Includes findings with Status='REVIEW' OR ReviewStatus.State in
        {NeedsReview, InReview, ActionRequired}. Sorted by RiskScore desc.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][array]$EnhancedFindings,
        [int]$MaxInitialRows = 100
    )

    $queue = @($EnhancedFindings | Where-Object {
            if ($_.Status -eq 'REVIEW') { return $true }
            if (-not $_.PSObject.Properties['ReviewStatus']) { return $false }
            $rs = $_.ReviewStatus
            if (-not $rs) { return $false }
            return ([string]$rs.State -in @('NeedsReview', 'InReview', 'ActionRequired'))
        }) | Sort-Object @{Expression = { if ($_.PSObject.Properties['RiskScore'] -and $null -ne $_.RiskScore) { -1 * [double]$_.RiskScore } else { 0 } } }

    if ($queue.Count -eq 0) { return '' }

    $riskOpts = ($queue | ForEach-Object { [string]$_.RiskLevel } | Where-Object { $_ } | Sort-Object -Unique)
    $stateOpts = ($queue | ForEach-Object {
            if ($_.PSObject.Properties['ReviewStatus'] -and $_.ReviewStatus) { [string]$_.ReviewStatus.State } else { '' }
        } | Where-Object { $_ } | Sort-Object -Unique)

    $riskOptionsHtml = ($riskOpts | ForEach-Object {
            $v = ConvertTo-SafeHtmlAttribute -Text $_
            "<option value=`"$($v.ToLowerInvariant())`">$v</option>"
        }) -join ''
    $stateOptionsHtml = ($stateOpts | ForEach-Object {
            $v = ConvertTo-SafeHtmlAttribute -Text $_
            "<option value=`"$($v.ToLowerInvariant())`">$v</option>"
        }) -join ''

    $rowsHtml = ($queue | ForEach-Object {
            $risk = [string]$_.RiskLevel
            $riskSafe = ConvertTo-SafeHtml -Text $risk
            $riskAttr = ConvertTo-SafeHtmlAttribute -Text $risk.ToLowerInvariant()
            $rs = if ($_.PSObject.Properties['ReviewStatus']) { $_.ReviewStatus } else { $null }
            $state = if ($rs) { [string]$rs.State } else { '' }
            $stateSafe = ConvertTo-SafeHtml -Text $state
            $stateAttr = ConvertTo-SafeHtmlAttribute -Text $state.ToLowerInvariant()
            $riskScoreSafe = ConvertTo-SafeHtml -Text ([string]$_.RiskScore)
            $obj = ConvertTo-SafeHtml -Text ([string]$_.Object)
            $desc = ConvertTo-SafeHtml -Text ([string]$_.Description)
            $searchHay = ConvertTo-SafeHtmlAttribute -Text (Get-CockpitFindingRowSearchHay -Finding $_)
            $bodyId = Get-CockpitFindingRowBodyId -Finding $_
            $bodyIdAttr = ConvertTo-SafeHtmlAttribute -Text $bodyId
            $bodyHtml = Get-CockpitFindingRowBody -Finding $_ -BodyId $bodyId
            @"
<div class="cockpit-row" data-risk="$riskAttr" data-reviewstate="$stateAttr" data-search="$searchHay">
    <button type="button" class="cockpit-row-header" aria-expanded="false" aria-controls="$bodyIdAttr">
        <span class="cockpit-badge risk-$riskAttr">$riskSafe</span>
        <span class="cockpit-cell-score">$riskScoreSafe</span>
        <span class="cockpit-cell-state">$stateSafe</span>
        <span class="cockpit-cell-object">$obj</span>
        <span class="cockpit-cell-desc">$desc</span>
        <span class="cockpit-caret" aria-hidden="true">&#9660;</span>
    </button>
    $bodyHtml
</div>
"@
        }) -join "`n"

    return @"
<section class="cockpit-section cockpit-interactive" id="review-queue" data-max-initial-rows="$MaxInitialRows">
    <h2 class="cockpit-section-title">Review Queue (<span class="cockpit-total-count">$($queue.Count)</span>)</h2>
    <p class="cockpit-section-lede">Human-judgment items &mdash; sorted by risk score. Click any row to expand for the full v2 detail.</p>
    <div class="cockpit-filters">
        <input type="search" placeholder="Search description, object, owner..." data-filter-key="_search" aria-label="Search Review Queue" />
        <select data-filter-key="risk" aria-label="Filter by risk level">
            <option value="">All risk levels</option>
            $riskOptionsHtml
        </select>
        <select data-filter-key="reviewstate" aria-label="Filter by review state">
            <option value="">All review states</option>
            $stateOptionsHtml
        </select>
        <span class="cockpit-counter" aria-live="polite"></span>
    </div>
    <div class="cockpit-row-list">
$rowsHtml
    </div>
    <button type="button" class="cockpit-show-more" data-section-id="review-queue">Show more (100 at a time)</button>
</section>
"@
}

function Get-CockpitDueDateBucket {
    <#
    .SYNOPSIS
        Converts a v2 Owner.DueDate into a stable bucket value for the
        Full Findings due-date filter.
    .DESCRIPTION
        Buckets:
          'overdue'   — date is in the past
          'due-0-7'   — within the next 7 days inclusive
          'due-8-30'  — 8 to 30 days out
          'due-31+'   — more than 30 days out
          'no-due'    — empty / unparseable

        Computed in PowerShell at render time so the JS filter is a simple
        exact-match against `data-due-bucket`. Computing in JS would
        require shipping a date library or doing parsing in every render.
    .OUTPUTS
        Stable lowercase bucket key.
    #>
    [OutputType([string])]
    param([AllowNull()][string]$IsoDate)
    if ([string]::IsNullOrWhiteSpace($IsoDate)) { return 'no-due' }
    [datetime]$parsed = [datetime]::MinValue
    if (-not [datetime]::TryParse($IsoDate, [ref]$parsed)) { return 'no-due' }
    $daysOut = ($parsed.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalDays
    if ($daysOut -lt 0) { return 'overdue' }
    if ($daysOut -le 7) { return 'due-0-7' }
    if ($daysOut -le 30) { return 'due-8-30' }
    return 'due-31+'
}

function Get-CockpitFullFindingsSection {
    <#
    .SYNOPSIS
        Renders the Full Findings section with text search, multi-column
        filters, and client-side pagination.
    .DESCRIPTION
        Unlike the Action / Review queues, this section includes EVERY
        finding regardless of disposition — OK, INFO, accepted risks, false
        positives, out-of-scope, resolved items, the lot. The plan §10.7
        rule: "Avoid hidden findings."

        Filters (plan §10.7 complete set): text search, status, risk level,
        disposition, source, owner, framework, control, exception status,
        review state, due date bucket.

        Pagination: shows first `-MaxInitialRows` (default 100); "Show more"
        button bumps the visible window by 100 each click.

        Performance: rows are rendered statically with `data-*` attributes;
        the JS in Get-CockpitJavaScript filters by toggling a `filtered-out`
        class. Multi-value attributes (frameworks, controls) use space-padded
        values so the JS `data-filter-mode="contains"` substring match acts
        as an exact-word match.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][array]$EnhancedFindings,
        [int]$MaxInitialRows = 100
    )

    if ($EnhancedFindings.Count -eq 0) { return '' }

    # No filter on inclusion — include everything. Sort by Status priority
    # then PriorityScore so failures float to the top.
    $sortKeys = @(
        @{ Expression = { switch ([string]$_.Status) { 'FAIL' { 0 } 'WARNING' { 1 } 'REVIEW' { 2 } 'INFO' { 3 } 'OK' { 4 } default { 5 } } } }
        @{ Expression = { if ($_.PSObject.Properties['PriorityScore'] -and $null -ne $_.PriorityScore) { -1 * [double]$_.PriorityScore } else { 0 } } }
    )
    $sorted = $EnhancedFindings | Sort-Object -Property $sortKeys

    # Collect option sets for the dropdowns. Each filter's value space is
    # whatever shows up in this run — never offer a value that no row has,
    # because that confuses analysts ("why does this filter not match anything?").
    $statusOpts = ($sorted | ForEach-Object { [string]$_.Status } | Where-Object { $_ } | Sort-Object -Unique)
    $riskOpts = ($sorted | ForEach-Object { [string]$_.RiskLevel } | Where-Object { $_ } | Sort-Object -Unique)
    $dispOpts = ($sorted | ForEach-Object { [string]$_.Disposition } | Where-Object { $_ } | Sort-Object -Unique)
    $sourceOpts = ($sorted | ForEach-Object { [string]$_.Source } | Where-Object { $_ } | Sort-Object -Unique)

    $ownerOpts = ($sorted | ForEach-Object {
            if ($_.PSObject.Properties['Owner'] -and $_.Owner -and $_.Owner.OwnerType -and $_.Owner.OwnerType -ne 'Unknown' -and [string]$_.Owner.DisplayName) {
                [string]$_.Owner.DisplayName
            }
        } | Where-Object { $_ } | Sort-Object -Unique)

    $frameworkOpts = ($sorted | ForEach-Object {
            if ($_.PSObject.Properties['ControlMappings'] -and $_.ControlMappings) {
                @($_.ControlMappings) | ForEach-Object { if ($_) { [string]$_.Framework } }
            }
        } | Where-Object { $_ } | Sort-Object -Unique)

    $exceptionOpts = ($sorted | ForEach-Object {
            if ($_.PSObject.Properties['Exception'] -and $_.Exception -and [string]$_.Exception.Status -and $_.Exception.Status -ne 'None') {
                [string]$_.Exception.Status
            }
        } | Where-Object { $_ } | Sort-Object -Unique)

    $reviewStateOpts = ($sorted | ForEach-Object {
            if ($_.PSObject.Properties['ReviewStatus'] -and $_.ReviewStatus -and [string]$_.ReviewStatus.State) {
                [string]$_.ReviewStatus.State
            }
        } | Where-Object { $_ } | Sort-Object -Unique)

    $mkOpts = {
        param($opts)
        ($opts | ForEach-Object {
            $v = ConvertTo-SafeHtmlAttribute -Text $_
            "<option value=`"$($v.ToLowerInvariant())`">$v</option>"
        }) -join ''
    }

    # Due-date bucket dropdown is a fixed set, not derived. Use friendly
    # labels but stable lowercase values for the data-* attribute.
    $dueBucketOptionsHtml = @(
        '<option value="overdue">Overdue</option>'
        '<option value="due-0-7">Due in 0-7 days</option>'
        '<option value="due-8-30">Due in 8-30 days</option>'
        '<option value="due-31+">Due in 31+ days</option>'
        '<option value="no-due">No due date</option>'
    ) -join ''

    $rowsHtml = ($sorted | ForEach-Object {
            $status = [string]$_.Status
            $statusSafe = ConvertTo-SafeHtml -Text $status
            $statusAttr = ConvertTo-SafeHtmlAttribute -Text $status.ToLowerInvariant()
            $disp = [string]$_.Disposition
            $dispSafe = ConvertTo-SafeHtml -Text $disp
            $dispAttr = ConvertTo-SafeHtmlAttribute -Text $disp.ToLowerInvariant()
            $risk = [string]$_.RiskLevel
            $riskSafe = ConvertTo-SafeHtml -Text $risk
            $riskAttr = ConvertTo-SafeHtmlAttribute -Text $risk.ToLowerInvariant()
            $source = [string]$_.Source
            $sourceSafe = ConvertTo-SafeHtml -Text $source
            $sourceAttr = ConvertTo-SafeHtmlAttribute -Text $source.ToLowerInvariant()
            $obj = ConvertTo-SafeHtml -Text ([string]$_.Object)
            $desc = ConvertTo-SafeHtml -Text ([string]$_.Description)
            $searchHay = ConvertTo-SafeHtmlAttribute -Text (Get-CockpitFindingRowSearchHay -Finding $_)

            # v2 filter attributes (plan §10.7 expansion).
            $ownerNameAttr = ''
            $dueBucketAttr = 'no-due'
            if ($_.PSObject.Properties['Owner'] -and $_.Owner -and $_.Owner.OwnerType -and $_.Owner.OwnerType -ne 'Unknown') {
                $ownerNameAttr = ConvertTo-SafeHtmlAttribute -Text ([string]$_.Owner.DisplayName).ToLowerInvariant()
                $dueBucketAttr = Get-CockpitDueDateBucket -IsoDate ([string]$_.Owner.DueDate)
            }

            $exceptionStatusAttr = 'none'
            if ($_.PSObject.Properties['Exception'] -and $_.Exception -and [string]$_.Exception.Status) {
                $exceptionStatusAttr = ConvertTo-SafeHtmlAttribute -Text ([string]$_.Exception.Status).ToLowerInvariant()
            }

            $reviewStateAttr = ''
            if ($_.PSObject.Properties['ReviewStatus'] -and $_.ReviewStatus -and [string]$_.ReviewStatus.State) {
                $reviewStateAttr = ConvertTo-SafeHtmlAttribute -Text ([string]$_.ReviewStatus.State).ToLowerInvariant()
            }

            # Multi-value attributes for frameworks + controls. Space-padded
            # so the JS contains-mode does exact-word matching: a needle of
            # 'cis_m365' wrapped in spaces matches " cis_m365 " but never
            # accidentally matches a longer prefix.
            $frameworkTokens = New-Object System.Collections.Generic.List[string]
            $controlTokens = New-Object System.Collections.Generic.List[string]
            if ($_.PSObject.Properties['ControlMappings'] -and $_.ControlMappings) {
                foreach ($m in @($_.ControlMappings)) {
                    if (-not $m) { continue }
                    $fw = [string]$m.Framework
                    $cid = [string]$m.ControlId
                    if ($fw) {
                        $tok = $fw.ToLowerInvariant() -replace '\s+', '_'
                        if ($frameworkTokens -notcontains $tok) { $frameworkTokens.Add($tok) }
                    }
                    if ($fw -and $cid) {
                        $tok = "${fw}:${cid}".ToLowerInvariant() -replace '\s+', '_'
                        $controlTokens.Add($tok)
                    }
                }
            }
            $frameworksAttr = if ($frameworkTokens.Count -gt 0) { ' ' + ($frameworkTokens -join ' ') + ' ' } else { '' }
            $controlsAttr = if ($controlTokens.Count -gt 0) { ' ' + ($controlTokens -join ' ') + ' ' } else { '' }
            $frameworksAttr = ConvertTo-SafeHtmlAttribute -Text $frameworksAttr
            $controlsAttr = ConvertTo-SafeHtmlAttribute -Text $controlsAttr

            $bodyId = Get-CockpitFindingRowBodyId -Finding $_
            $bodyIdAttr = ConvertTo-SafeHtmlAttribute -Text $bodyId
            $bodyHtml = Get-CockpitFindingRowBody -Finding $_ -BodyId $bodyId
            @"
<div class="cockpit-row" data-status="$statusAttr" data-disposition="$dispAttr" data-risk="$riskAttr" data-source="$sourceAttr" data-owner="$ownerNameAttr" data-frameworks="$frameworksAttr" data-controls="$controlsAttr" data-exception-status="$exceptionStatusAttr" data-review-state="$reviewStateAttr" data-due-bucket="$dueBucketAttr" data-search="$searchHay">
    <button type="button" class="cockpit-row-header" aria-expanded="false" aria-controls="$bodyIdAttr">
        <span class="cockpit-badge status-$statusAttr">$statusSafe</span>
        <span class="cockpit-badge risk-$riskAttr">$riskSafe</span>
        <span class="cockpit-cell-object">$obj</span>
        <span class="cockpit-cell-desc">$desc</span>
        <span class="cockpit-cell-disposition">$dispSafe</span>
        <span class="cockpit-cell-source">$sourceSafe</span>
        <span class="cockpit-caret" aria-hidden="true">&#9660;</span>
    </button>
    $bodyHtml
</div>
"@
        }) -join "`n"

    # Pre-build dropdown HTML so the section literal stays readable.
    $statusOptionsHtml = & $mkOpts $statusOpts
    $riskOptionsHtml = & $mkOpts $riskOpts
    $dispOptionsHtml = & $mkOpts $dispOpts
    $sourceOptionsHtml = & $mkOpts $sourceOpts
    $ownerOptionsHtml = & $mkOpts $ownerOpts
    $frameworkOptionsHtml = & $mkOpts $frameworkOpts
    $exceptionOptionsHtml = & $mkOpts $exceptionOpts
    $reviewStateOptionsHtml = & $mkOpts $reviewStateOpts

    return @"
<section class="cockpit-section cockpit-interactive" id="full-findings" data-max-initial-rows="$MaxInitialRows">
    <h2 class="cockpit-section-title">Full Findings (<span class="cockpit-total-count">$($sorted.Count)</span>)</h2>
    <p class="cockpit-section-lede">Every finding from this run &mdash; including accepted risks, false positives, out-of-scope, OK, and INFO. Use the filters to narrow down; click any row to expand.</p>
    <div class="cockpit-saved-views" role="group" aria-label="Saved views">
        <span class="cockpit-saved-views-label">Saved views:</span>
        <button type="button" class="cockpit-saved-view" data-view-set="review-state=actionrequired">Owner queue</button>
        <button type="button" class="cockpit-saved-view" data-view-set="exception-status=expired">Expired exceptions</button>
        <button type="button" class="cockpit-saved-view" data-view-set="due-bucket=due-0-7">Due within 7 days</button>
        <button type="button" class="cockpit-saved-view cockpit-saved-view-clear" data-view-set="">Clear filters</button>
    </div>
    <div class="cockpit-filters cockpit-filters-primary">
        <input type="search" placeholder="Search description, object, owner..." data-filter-key="_search" aria-label="Search Full Findings" />
        <select data-filter-key="status" aria-label="Filter by status">
            <option value="">All statuses</option>
            $statusOptionsHtml
        </select>
        <select data-filter-key="risk" aria-label="Filter by risk level">
            <option value="">All risk levels</option>
            $riskOptionsHtml
        </select>
        <span class="cockpit-counter" aria-live="polite"></span>
    </div>
    <details class="cockpit-filters-advanced">
        <summary class="cockpit-filters-advanced-summary">Advanced filters</summary>
        <div class="cockpit-filters cockpit-filters-secondary">
            <select data-filter-key="disposition" aria-label="Filter by disposition">
                <option value="">All dispositions</option>
                $dispOptionsHtml
            </select>
            <select data-filter-key="source" aria-label="Filter by source">
                <option value="">All sources</option>
                $sourceOptionsHtml
            </select>
            <select data-filter-key="owner" aria-label="Filter by owner">
                <option value="">All owners</option>
                $ownerOptionsHtml
            </select>
            <select data-filter-key="frameworks" data-filter-mode="contains" aria-label="Filter by framework">
                <option value="">All frameworks</option>
                $frameworkOptionsHtml
            </select>
            <input type="search" placeholder="Filter by control id (e.g. 1.1.1)" data-filter-key="controls" data-filter-mode="contains" aria-label="Filter by control id" />
            <select data-filter-key="exception-status" aria-label="Filter by exception status">
                <option value="">All exception states</option>
                $exceptionOptionsHtml
            </select>
            <select data-filter-key="review-state" aria-label="Filter by review state">
                <option value="">All review states</option>
                $reviewStateOptionsHtml
            </select>
            <select data-filter-key="due-bucket" aria-label="Filter by due date">
                <option value="">All due dates</option>
                $dueBucketOptionsHtml
            </select>
        </div>
    </details>
    <div class="cockpit-row-list">
$rowsHtml
    </div>
    <button type="button" class="cockpit-show-more" data-section-id="full-findings">Show more (100 at a time)</button>
</section>
"@
}

function Get-CockpitJavaScript {
    <#
    .SYNOPSIS
        Emits the inline <script> block that powers cockpit interactivity.
    .DESCRIPTION
        Wires data-filter-key inputs/selects to data-* attributes on the
        rows. Toggles a `filtered-out` class for non-matching rows and a
        `paginated-out` class for rows past the current page window.
        Updates the "Showing X of Y" counter and the "Show more" button
        visibility.

        IMPORTANT: this script must remain self-contained — no external
        CDNs, no third-party libraries — so the cockpit works under
        file:// and survives the static-report CSP policy.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return @'
<script>
(function () {
  "use strict";

  // Per-section pagination cursor. Initialized lazily from
  // data-max-initial-rows on the section element.
  var paginationState = {};

  function getMaxRows(sectionId) {
    if (paginationState[sectionId]) return paginationState[sectionId];
    var section = document.getElementById(sectionId);
    var initial = 100;
    if (section) {
      var attr = section.getAttribute('data-max-initial-rows');
      if (attr) {
        var parsed = parseInt(attr, 10);
        if (!isNaN(parsed) && parsed > 0) initial = parsed;
      }
    }
    paginationState[sectionId] = initial;
    return initial;
  }

  function applyFilters(sectionId) {
    var section = document.getElementById(sectionId);
    if (!section) return;
    var filterEls = section.querySelectorAll('[data-filter-key]');
    var filters = {};
    // Track each filter's mode alongside its value. The two non-default
    // modes are documented on the filter element itself via data-filter-mode:
    //   - "contains" → substring match on the row's matching data-* attribute
    //                  (used for multi-value attributes like data-frameworks
    //                  which the renderer space-pads; the needle is wrapped
    //                  with leading+trailing spaces so the match is on a
    //                  whole token, not a prefix).
    //   - "substring" → raw indexOf, no padding (for free-text inputs like
    //                   control id where "1.1.1" should also match "1.1.10").
    //   - default → exact match (existing single-value enums).
    var filterModes = {};
    for (var i = 0; i < filterEls.length; i++) {
      var key = filterEls[i].getAttribute('data-filter-key');
      var raw = (filterEls[i].value || '').toLowerCase().trim();
      if (raw) {
        filters[key] = raw;
        filterModes[key] = filterEls[i].getAttribute('data-filter-mode') || '';
      }
    }
    var rows = section.querySelectorAll('.cockpit-row');
    var matchedCount = 0;
    for (var r = 0; r < rows.length; r++) {
      var row = rows[r];
      var matches = true;
      for (var key in filters) {
        if (!Object.prototype.hasOwnProperty.call(filters, key)) continue;
        var needle = filters[key];
        if (key === '_search') {
          var hay = (row.getAttribute('data-search') || '').toLowerCase();
          if (hay.indexOf(needle) === -1) { matches = false; break; }
        } else if (filterModes[key] === 'contains') {
          var rowMulti = (row.getAttribute('data-' + key) || '').toLowerCase();
          // Space-wrap needle for whole-token match against the
          // space-padded attribute. Falls back to raw indexOf when the
          // attribute isn't space-padded (e.g. control id text input).
          if (rowMulti.indexOf(' ' + needle + ' ') === -1 && rowMulti.indexOf(needle) === -1) {
            matches = false; break;
          }
        } else {
          var rowVal = (row.getAttribute('data-' + key) || '').toLowerCase();
          if (rowVal !== needle) { matches = false; break; }
        }
      }
      if (matches) {
        row.classList.remove('filtered-out');
        matchedCount++;
      } else {
        row.classList.add('filtered-out');
      }
    }
    applyPagination(sectionId, matchedCount);
    updateCounter(section, matchedCount);
  }

  function applyPagination(sectionId, matchedCount) {
    var section = document.getElementById(sectionId);
    if (!section) return;
    var maxRows = getMaxRows(sectionId);
    var visible = section.querySelectorAll('.cockpit-row:not(.filtered-out)');
    for (var i = 0; i < visible.length; i++) {
      if (i >= maxRows) {
        visible[i].classList.add('paginated-out');
      } else {
        visible[i].classList.remove('paginated-out');
      }
    }
    var btn = section.querySelector('.cockpit-show-more');
    if (btn) {
      btn.style.display = (matchedCount > maxRows) ? 'inline-block' : 'none';
    }
  }

  function updateCounter(section, matchedCount) {
    var counterEl = section.querySelector('.cockpit-counter');
    if (!counterEl) return;
    var sectionId = section.id;
    var maxRows = getMaxRows(sectionId);
    var visibleNow = Math.min(matchedCount, maxRows);
    counterEl.textContent = 'Showing ' + visibleNow + ' of ' + matchedCount;
  }

  function showMore(sectionId) {
    var cur = getMaxRows(sectionId);
    paginationState[sectionId] = cur + 100;
    applyFilters(sectionId);
  }

  function toggleRow(headerEl) {
    var row = headerEl.parentElement;
    if (!row) return;
    var expanded = row.classList.toggle('expanded');
    // Mirror visual state into ARIA so screen readers announce the change.
    // The button itself owns aria-expanded; aria-controls already points
    // at the body so assistive tech can jump straight to the revealed
    // content.
    headerEl.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    var caret = headerEl.querySelector('.cockpit-caret');
    if (caret) {
      caret.innerHTML = expanded ? '&#9650;' : '&#9660;';
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    // Click handler for every row header (expand/collapse).
    // Headers are <button> elements, so Space/Enter fire click natively —
    // no separate keydown handler needed.
    var headers = document.querySelectorAll('.cockpit-row-header');
    for (var i = 0; i < headers.length; i++) {
      (function (h) {
        h.addEventListener('click', function () { toggleRow(h); });
      })(headers[i]);
    }

    // Filter input handlers — input fires on every keystroke, change for
    // the select dropdowns.
    var filterEls = document.querySelectorAll('[data-filter-key]');
    for (var j = 0; j < filterEls.length; j++) {
      (function (el) {
        var section = el.closest('.cockpit-section');
        if (!section) return;
        var sectionId = section.id;
        el.addEventListener('input', function () { applyFilters(sectionId); });
        el.addEventListener('change', function () { applyFilters(sectionId); });
      })(filterEls[j]);
    }

    // "Show more" pagination buttons.
    var btns = document.querySelectorAll('.cockpit-show-more');
    for (var k = 0; k < btns.length; k++) {
      (function (b) {
        b.addEventListener('click', function () {
          showMore(b.getAttribute('data-section-id'));
        });
      })(btns[k]);
    }

    // Saved views (plan §11.5). A saved-view button is a preset over the
    // section's existing data-filter-key controls: clear them all, then
    // apply the "key=value;key=value" pairs from data-view-set (empty =
    // just clear), then run the same applyFilters the manual controls
    // use. No new filter engine — purely drives the existing one.
    var savedViews = document.querySelectorAll('.cockpit-saved-view');
    for (var sv = 0; sv < savedViews.length; sv++) {
      (function (b) {
        b.addEventListener('click', function () {
          var section = b.closest('.cockpit-section');
          if (!section) return;
          var fe = section.querySelectorAll('[data-filter-key]');
          for (var x = 0; x < fe.length; x++) { fe[x].value = ''; }
          var spec = b.getAttribute('data-view-set') || '';
          if (spec) {
            var pairs = spec.split(';');
            for (var p = 0; p < pairs.length; p++) {
              var eq = pairs[p].indexOf('=');
              if (eq < 1) continue;
              var fk = pairs[p].substring(0, eq);
              var fv = pairs[p].substring(eq + 1);
              var el = section.querySelector('[data-filter-key="' + fk + '"]');
              if (el) { el.value = fv; }
            }
          }
          applyFilters(section.id);
          var all = section.querySelectorAll('.cockpit-saved-view');
          for (var a = 0; a < all.length; a++) { all[a].classList.remove('active'); }
          b.classList.add('active');
        });
      })(savedViews[sv]);
    }

    // Initial pass so counters and pagination are correct on first paint.
    var interactiveSections = document.querySelectorAll('.cockpit-interactive');
    for (var m = 0; m < interactiveSections.length; m++) {
      applyFilters(interactiveSections[m].id);
    }
  });
})();
</script>
'@
}

function Get-HtmlReportPlan {
    <#
    .SYNOPSIS
        Decides which HTML reports to generate for the current run.
    .DESCRIPTION
        The orchestrator's HTML routing decision (PR 4 of
        HTML-Reporting-Consolidation-Plan). Inputs: the report-set mode
        (`Cockpit` | `CockpitAndDeepDives` | `DeepDivesOnly` | `LegacyAll`),
        the requested deep-dive domains, and flags for which auxiliary data
        was collected (Secure Score / Defender / etc.).

        Output: a plan hashtable the orchestrator can act on without
        re-implementing the decision tree at every call site. Same plan
        shape is testable in isolation — see Tests/HtmlReportPlan.Tests.ps1.

        Decision rules (plan §12):

        - Cockpit               → cockpit only. No legacy multi-reports.
                                  No domain deep dives.
        - CockpitAndDeepDives   → cockpit + only the explicitly listed
                                  deep-dive domains. Empty list = cockpit
                                  alone (no inference).
        - DeepDivesOnly         → no cockpit; only the listed deep dives.
                                  Empty list = warning + no HTML.
        - LegacyAll             → preserves pre-PR-4 behavior: every
                                  available source emits a deep-dive
                                  report, plus the legacy comprehensive
                                  report and unified report. No cockpit
                                  (those reports cover the same ground).

        A deep-dive domain is "available" when the matching `$AvailableSources`
        flag is true AND the domain is listed in `-HtmlDeepDiveDomains` (or
        we're in LegacyAll mode, which infers all available domains).

    .PARAMETER HtmlReportSet
        One of `Cockpit`, `CockpitAndDeepDives`, `DeepDivesOnly`, `LegacyAll`.
        Default: `Cockpit`.

    .PARAMETER HtmlDeepDiveDomains
        Subset of `SecureScore`, `DefenderCompliance`, `AzurePolicy`,
        `PurviewCompliance`, `Delta`, `PrivilegedIdentity`.

    .PARAMETER AvailableSources
        Hashtable from domain name to `[bool]`. Set values to `$true` for
        sources the run actually collected. Missing keys default to `$false`.

    .OUTPUTS
        Hashtable with:
          - GenerateCockpit         : bool
          - GenerateComprehensive   : bool
          - GenerateUnified         : bool
          - GenerateDomainReports   : string[] (concrete list to emit)
          - Warnings                : string[]
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [ValidateSet('Cockpit', 'CockpitAndDeepDives', 'DeepDivesOnly', 'LegacyAll')]
        [string]$HtmlReportSet = 'Cockpit',
        [string[]]$HtmlDeepDiveDomains = @(),
        [hashtable]$AvailableSources = @{}
    )

    $allDomains = @('SecureScore', 'DefenderCompliance', 'AzurePolicy', 'PurviewCompliance', 'Delta', 'PrivilegedIdentity')
    $warnings = New-Object System.Collections.Generic.List[string]

    # Validate requested domains. Anything not in the canonical set becomes a
    # warning rather than a hard error — orchestrator continues.
    $requested = @($HtmlDeepDiveDomains | Where-Object { $_ })
    $invalidDomains = @($requested | Where-Object { $_ -notin $allDomains })
    foreach ($bad in $invalidDomains) {
        $warnings.Add("HtmlDeepDiveDomains: '$bad' is not a recognised domain. Allowed: $($allDomains -join ', ').")
    }
    $valid = @($requested | Where-Object { $_ -in $allDomains })

    switch ($HtmlReportSet) {
        'Cockpit' {
            if ($valid.Count -gt 0) {
                $warnings.Add("HtmlDeepDiveDomains was supplied but HtmlReportSet is 'Cockpit' — deep dives ignored. Use 'CockpitAndDeepDives' to include them.")
            }
            return @{
                GenerateCockpit = $true
                GenerateComprehensive = $false
                GenerateUnified = $false
                GenerateDomainReports = @()
                Warnings = $warnings.ToArray()
            }
        }
        'CockpitAndDeepDives' {
            # Only emit deep dives for domains that BOTH were requested AND
            # have data. Requesting a domain whose data wasn't collected is a
            # warning, not silent skip.
            $emitted = New-Object System.Collections.Generic.List[string]
            foreach ($d in $valid) {
                if ($AvailableSources[$d]) {
                    $emitted.Add($d)
                }
                else {
                    $warnings.Add("Deep dive '$d' requested but no data was collected for it this run — skipping.")
                }
            }
            return @{
                GenerateCockpit = $true
                GenerateComprehensive = $false
                GenerateUnified = $false
                GenerateDomainReports = $emitted.ToArray()
                Warnings = $warnings.ToArray()
            }
        }
        'DeepDivesOnly' {
            if ($valid.Count -eq 0) {
                $warnings.Add("HtmlReportSet='DeepDivesOnly' but HtmlDeepDiveDomains is empty — no HTML will be generated. Pass at least one domain (e.g. -HtmlDeepDiveDomains AzurePolicy).")
                return @{
                    GenerateCockpit = $false
                    GenerateComprehensive = $false
                    GenerateUnified = $false
                    GenerateDomainReports = @()
                    Warnings = $warnings.ToArray()
                }
            }
            $emitted = New-Object System.Collections.Generic.List[string]
            foreach ($d in $valid) {
                if ($AvailableSources[$d]) {
                    $emitted.Add($d)
                }
                else {
                    $warnings.Add("Deep dive '$d' requested but no data was collected for it this run — skipping.")
                }
            }
            return @{
                GenerateCockpit = $false
                GenerateComprehensive = $false
                GenerateUnified = $false
                GenerateDomainReports = $emitted.ToArray()
                Warnings = $warnings.ToArray()
            }
        }
        'LegacyAll' {
            # Old behavior: comprehensive + unified + every available domain.
            # No cockpit (those reports cover the same ground). No warning for
            # extra HtmlDeepDiveDomains — we already emit every available one.
            $emitted = New-Object System.Collections.Generic.List[string]
            foreach ($d in $allDomains) {
                if ($AvailableSources[$d]) { $emitted.Add($d) }
            }
            return @{
                GenerateCockpit = $false
                GenerateComprehensive = $true
                GenerateUnified = $true
                GenerateDomainReports = $emitted.ToArray()
                Warnings = $warnings.ToArray()
            }
        }
    }
}

function New-EntraChecksAnalystHtmlReport {
    <#
    .SYNOPSIS
        Generates the single primary analyst cockpit HTML report.
    .DESCRIPTION
        Composes the executive digest, action queue, review queue, control
        impact, source posture, evidence/provenance, full findings, deep
        dive hub, and integrity footer into one HTML document. Every dynamic
        value passes through the safe-encoding helpers from PR 1.

        The cockpit is opt-in in PR 2 — the orchestrator default remains the
        existing multi-report behavior. PR 4 of HTML-Reporting-Consolidation
        flips the default after PR 3 adds interactive filtering.
    .PARAMETER DeepDives
        Optional hashtable mapping deep-dive domain name (e.g. 'SecureScore',
        'AzurePolicy', 'Delta', etc.) to the path of the generated deep-dive
        HTML file. The Deep Dive Hub renders linkified cards for present
        entries and "not generated this run" cards for missing ones.
    .PARAMETER RequestedDeepDives
        Optional array of deep-dive domain names the user explicitly
        opted into for this run (the GUI checkbox group, or the
        `-HtmlDeepDiveDomains` switch). Drives the four-state status
        the Deep Dive Hub renders per card:
          - Generated         (requested AND in $DeepDives)
          - Skipped (no data) (requested but data source unavailable)
          - Skipped (no license / not selected) (not requested)
    .OUTPUTS
        String — the OutputPath of the written HTML file.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Findings,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][object]$TenantInfo,
        [object]$PreviousAssessment,
        [object]$SecureScore,
        [object]$DefenderCompliance,
        [object]$AzurePolicy,
        [object]$PurviewCompliance,
        [object]$HybridCorrelation,
        [object]$PrivilegedIdentityRoster,
        [object]$Branding,
        [hashtable]$DeepDives = @{},
        [string[]]$RequestedDeepDives = @(),
        [int]$MaxInitialRows = 100,
        [bool]$IncludeIntegrityBadge = $true
    )

    # Enrich findings — same pipeline as New-EnhancedHTMLReport so the cockpit
    # consumes identical data shapes.
    #
    # Performance note (2026-05-14):
    # When the orchestrator runs Initialize-FindingsForReport upstream (which
    # is the default code path), every finding already carries RiskScore,
    # ComplianceMappings, and RemediationGuidance. Running the Add-* cmdlets
    # again was pure overhead — at 1,200 findings it added ~5s on top of the
    # ~5s normalize cost (total ~10s).
    #
    # We now check per-finding whether enrichment is needed and pipe only the
    # un-enriched ones through the Add-* cmdlets. For external callers that
    # bypass Initialize-FindingsForReport (e.g. invoking
    # New-EntraChecksAnalystHtmlReport directly with raw findings), the
    # missing fields trigger normal enrichment so the behavior is unchanged
    # for that path. Collections use List[object] to avoid O(n^2) array
    # growth on the += operator.
    $enrichedList = New-Object System.Collections.Generic.List[object]
    foreach ($finding in $Findings) {
        $hasRisk = $finding.PSObject.Properties['RiskScore'] -and $null -ne $finding.RiskScore
        $hasMap = $finding.PSObject.Properties['ComplianceMappings'] -and $null -ne $finding.ComplianceMappings
        $hasRem = $finding.PSObject.Properties['RemediationGuidance'] -and $null -ne $finding.RemediationGuidance
        if ($hasRisk -and $hasMap -and $hasRem) {
            # Already enriched (typically by Initialize-FindingsForReport) —
            # pass through without re-running the Add-* cmdlets.
            $enrichedList.Add($finding)
        }
        else {
            $enrichedList.Add(($finding | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance))
        }
    }

    # Dedupe (Description + Object) — identical heuristic to the existing report.
    # HashSet + List[object] avoids the array += quadratic blowup the
    # previous implementation suffered at 1,000+ findings.
    $seenSet = New-Object System.Collections.Generic.HashSet[string]
    $dedupedList = New-Object System.Collections.Generic.List[object]
    foreach ($f in $enrichedList) {
        $key = "$($f.Description)|$($f.Object)"
        if ($seenSet.Add($key)) { $dedupedList.Add($f) }
    }
    $enhancedFindings = $dedupedList.ToArray()

    # Summaries
    $riskSummary = Get-RiskSummary -Findings $enhancedFindings
    $complianceGap = Get-ComplianceGapReport -Findings $enhancedFindings -Framework 'All'

    $findingsDelta = $null
    if ($PreviousAssessment) {
        $previousFindings = if ($PreviousAssessment.PSObject.Properties['Findings']) {
            $PreviousAssessment.Findings
        } else { @($PreviousAssessment) }
        $findingsDelta = Get-FindingsDelta -Current $enhancedFindings -Previous $previousFindings
    }

    $execDigest = Get-EntraChecksExecutiveDigest -Findings $enhancedFindings -RiskSummary $riskSummary -ComplianceGap $complianceGap -FindingsDelta $findingsDelta
    $execDigestHtml = Format-ExecutiveDigest -Digest $execDigest -TenantInfo $TenantInfo

    # Section composition (plan §9 ordering). PR 3: Action Queue, Review
    # Queue, and Full Findings are now interactive (filters + pagination +
    # expandable rows). Wired by the cockpit JS emitted near </body>.
    $actionQueueHtml = Get-CockpitActionQueueSection -EnhancedFindings $enhancedFindings -MaxInitialRows $MaxInitialRows
    $reviewQueueHtml = Get-CockpitReviewQueueSection -EnhancedFindings $enhancedFindings -MaxInitialRows $MaxInitialRows
    $compliancePostureHtml = Get-CockpitCompliancePostureSection -DefenderCompliance $DefenderCompliance
    $sourcePostureHtml = Get-CockpitSourcePostureSection `
        -SecureScore $SecureScore -DefenderCompliance $DefenderCompliance `
        -AzurePolicy $AzurePolicy -PurviewCompliance $PurviewCompliance `
        -HybridCorrelation $HybridCorrelation -PrivilegedIdentityRoster $PrivilegedIdentityRoster
    $evidenceHtml = Get-CockpitEvidenceProvenanceSection -Findings $enhancedFindings

    # Availability map for the four-state Deep Dive Hub. A deep-dive can
    # be unavailable for two distinct reasons — the user didn't tick it
    # (skipped: not selected) vs. they did but no underlying data came
    # back (skipped: no data, typically a missing license or RBAC).
    $availability = @{
        SecureScore = [bool]$SecureScore
        DefenderCompliance = [bool]$DefenderCompliance
        AzurePolicy = [bool]$AzurePolicy
        PurviewCompliance = [bool]$PurviewCompliance
        Delta = [bool]$PreviousAssessment
        PrivilegedIdentity = [bool]$PrivilegedIdentityRoster
    }
    $cockpitDir = Split-Path -Parent $OutputPath
    $deepDiveHtml = Get-CockpitDeepDiveHubSection -DeepDives $DeepDives -RequestedDeepDives $RequestedDeepDives -Availability $availability -CockpitDir $cockpitDir
    $fullFindingsHtml = Get-CockpitFullFindingsSection -EnhancedFindings $enhancedFindings -MaxInitialRows $MaxInitialRows
    $cockpitJs = Get-CockpitJavaScript

    $integrityHtml = if ($IncludeIntegrityBadge) {
        New-IntegrityBlock -EnhancedFindings $enhancedFindings -OutputPath $OutputPath
    } else { '' }

    $htmlHead = Get-HTMLHead
    $cockpitCss = Get-CockpitCss

    # Header — branding overrides if supplied. PR Cockpit-Polish:
    # hero tenant name + posture badge + stat row replace the prior
    # squished single-block header. Posture / counts come from the digest
    # we already computed above.
    $tenantName = ConvertTo-SafeHtml -Text ([string]$TenantInfo.TenantName)
    $tenantId = ConvertTo-SafeHtml -Text ([string]$TenantInfo.TenantId)
    $reportTitle = if ($Branding -and $Branding.ReportTitle) {
        ConvertTo-SafeHtml -Text ([string]$Branding.ReportTitle)
    } else { 'EntraChecks Analyst Cockpit' }
    $reportGeneratedDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss"
    $verdictText = ConvertTo-SafeHtml -Text ([string]$execDigest.Verdict)
    $verdictClassAttr = ConvertTo-SafeHtmlAttribute -Text ([string]$execDigest.VerdictClass)

    # Static-report Content Security Policy. This is a local file: inline
    # script and inline style are required (no external CDNs). Block
    # everything else so a malicious finding value can't trigger a network
    # request (img-src 'self' data: lets data-URL icons render).
    $cspMeta = "<meta http-equiv=`"Content-Security-Policy`" content=`"default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none';`">"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    $cspMeta
    <title>$reportTitle - $tenantName</title>
    $htmlHead
    $cockpitCss
</head>
<body>
    <a class="skip-link" href="#main-content">Skip to main content</a>
    <main id="main-content" class="container">
        <header class="cockpit-hero">
            <div class="cockpit-hero-meta">
                <p class="cockpit-hero-product">$reportTitle</p>
                <h1 class="cockpit-hero-tenant">$tenantName</h1>
                <p class="cockpit-hero-tenantid"><span class="cockpit-hero-tenantid-label">Tenant ID</span> <code>$tenantId</code></p>
                <p class="cockpit-hero-generated">Generated $reportGeneratedDate</p>
            </div>
            <div class="cockpit-hero-verdict">
                <span class="cockpit-hero-verdict-label">Overall posture</span>
                <span class="cockpit-hero-verdict-pill $verdictClassAttr">$verdictText</span>
                <span class="cockpit-hero-verdict-count">$($enhancedFindings.Count) findings</span>
            </div>
        </header>

        <!-- Section 1: Executive Digest -->
        $execDigestHtml

        <!-- Section 1b: Defender for Cloud Compliance Posture -->
        $compliancePostureHtml

        <!-- Section 2: Action Queue (PR 3 makes this interactive) -->
        $actionQueueHtml

        <!-- Section 3: Review Queue (PR 3 makes this interactive) -->
        $reviewQueueHtml

        <!-- Section 5: Source Posture -->
        $sourcePostureHtml

        <!-- Section 6: Evidence and Provenance -->
        $evidenceHtml

        <!-- Section 7: Full Findings -->
        $fullFindingsHtml

        <!-- Section 8: Deep Dive Hub -->
        $deepDiveHtml

        $integrityHtml
    </main>
    $cockpitJs
</body>
</html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Verbose "Analyst cockpit HTML generated: $OutputPath"
    return $OutputPath
}

function Get-CockpitCss {
    <#
    .SYNOPSIS
        Cockpit-specific CSS (cards, queue tables, provenance table).
    .DESCRIPTION
        Returned as a single <style> block. Loaded ADDITIONALLY to the
        existing Get-HTMLHead so the cockpit inherits the base look-and-feel
        and only adds the new sections' styles.
    #>
    return @'
<style>
.cockpit-section { margin: 30px 0; padding: 20px; background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04); }
.cockpit-section-title { font-size: 1.5em; color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 8px; margin-bottom: 12px; }
.cockpit-section-lede { color: #555; font-size: 0.95em; margin-bottom: 16px; }
.cockpit-section-lede.empty { font-style: italic; }
.cockpit-section-note { color: #888; font-size: 0.85em; margin-top: 10px; font-style: italic; }
.source-card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
.source-card { padding: 12px; border-radius: 6px; border-left: 4px solid #ccc; background: #f8f9fb; }
.source-card.good { border-left-color: #107c10; }
.source-card.muted { border-left-color: #999; opacity: 0.85; }
.source-card h4 { margin: 0 0 6px 0; font-size: 1em; }
.source-status { font-weight: 600; font-size: 0.9em; }
.source-card.good .source-status { color: #107c10; }
.source-card.muted .source-status { color: #888; }
.source-metric { color: #555; font-size: 0.85em; margin-top: 4px; }
.deep-dive-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }
.deep-dive-card { padding: 12px; border-radius: 6px; border-left: 4px solid #ccc; background: #f8f9fb; }
.deep-dive-card.generated { border-left-color: #0078d4; background: #eff6fb; }
.deep-dive-card.pending { border-left-color: #ffaa44; opacity: 0.95; }
.deep-dive-card.no-data { border-left-color: #c52733; background: #fdeded; }
.deep-dive-card.not-available { border-left-color: #9aa3af; }
.deep-dive-card.not-selected { border-left-color: #5c6873; opacity: 0.9; }
.deep-dive-card h4 { margin: 0 0 6px 0; font-size: 1em; }
.deep-dive-card .status { font-weight: 600; font-size: 0.9em; }
.deep-dive-card.generated .status { color: #0078d4; }
.deep-dive-card.pending .status { color: #b87100; }
.deep-dive-card.no-data .status { color: #a4373a; }
.deep-dive-card.not-available .status { color: #4b5563; }
.deep-dive-card.not-selected .status { color: #4b5563; }
.deep-dive-card .hint { color: #555; font-size: 0.82em; margin-top: 6px; }
.deep-dive-card .hint code { background: #eef; padding: 2px 5px; border-radius: 3px; font-size: 0.92em; }
.provenance-table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
.provenance-table th, .provenance-table td { padding: 6px 8px; text-align: left; border-bottom: 1px solid #e5e7eb; }
.provenance-table th { background: #f0f3f7; font-weight: 600; }
.provenance-table .hash-cell { font-family: monospace; word-break: break-all; max-width: 200px; }
.provenance-table code { font-size: 0.9em; background: #f4f5f7; padding: 1px 4px; border-radius: 3px; }
.cockpit-queue-table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
.cockpit-queue-table th, .cockpit-queue-table td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #e5e7eb; }
.cockpit-queue-table th { background: #f0f3f7; font-weight: 600; }
.cockpit-queue-table tr:hover { background: #fafbfc; }
/* PR 3: interactive queue styles */
.cockpit-saved-views { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
.cockpit-saved-views-label { font-size: 0.82em; color: #6b7280; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }
.cockpit-saved-view { padding: 5px 12px; border: 1px solid #0078d4; background: #fff; color: #0078d4; border-radius: 14px; font-size: 0.85em; cursor: pointer; }
.cockpit-saved-view:hover { background: #eaf3fb; }
.cockpit-saved-view:focus-visible { outline: 3px solid #0078d4; outline-offset: 2px; }
.cockpit-saved-view.active { background: #0078d4; color: #fff; }
.cockpit-saved-view-clear { border-color: #9aa3af; color: #555; }
.cockpit-saved-view-clear:hover { background: #f0f1f3; }
.cockpit-filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; align-items: center; }
.cockpit-filters-primary { margin-bottom: 8px; }
.cockpit-filters-advanced { margin: 0 0 14px 0; border: 1px solid #e5e7eb; border-radius: 6px; background: #fafbfc; }
.cockpit-filters-advanced-summary { cursor: pointer; padding: 8px 14px; font-size: 0.86em; color: #0078d4; font-weight: 600; list-style: none; user-select: none; }
.cockpit-filters-advanced-summary::-webkit-details-marker { display: none; }
.cockpit-filters-advanced-summary::before { content: '\25BE'; display: inline-block; margin-right: 8px; transition: transform 0.15s; color: #888; }
.cockpit-filters-advanced[open] .cockpit-filters-advanced-summary::before { transform: rotate(180deg); }
.cockpit-filters-advanced[open] .cockpit-filters-advanced-summary { border-bottom: 1px solid #e5e7eb; }
.cockpit-filters-advanced .cockpit-filters-secondary { padding: 10px 14px 12px; margin-bottom: 0; }
.cockpit-filters input[type="search"], .cockpit-filters select { padding: 6px 10px; border: 1px solid #d0d5dc; border-radius: 4px; font-size: 0.9em; background: #fff; }
.cockpit-filters input[type="search"] { flex: 1 1 240px; min-width: 200px; }
.cockpit-filters select { min-width: 130px; }
.cockpit-filters input:focus, .cockpit-filters select:focus { outline: 2px solid #0078d4; outline-offset: 1px; }
.cockpit-counter { margin-left: auto; color: #555; font-size: 0.85em; }
.cockpit-row-list { display: flex; flex-direction: column; gap: 4px; }
.cockpit-row { background: #fff; border: 1px solid #e5e7eb; border-radius: 4px; transition: box-shadow 0.15s; }
.cockpit-row.filtered-out, .cockpit-row.paginated-out { display: none; }
.cockpit-row:hover { box-shadow: 0 2px 4px rgba(0,0,0,0.06); }
.cockpit-row-header { display: grid; grid-template-columns: auto auto minmax(160px, 1.4fr) minmax(240px, 2.6fr) auto auto auto; gap: 10px; align-items: center; padding: 8px 12px; cursor: pointer; user-select: none; font-size: 0.9em; width: 100%; background: transparent; border: 0; text-align: left; font-family: inherit; color: inherit; }
.cockpit-row-header:hover { background: #f7f9fb; }
.cockpit-row-header:focus { outline: none; }
.cockpit-row-header:focus-visible { outline: 3px solid #0078d4; outline-offset: -3px; box-shadow: inset 0 0 0 1px #fff; }
.cockpit-row[aria-expanded] .cockpit-caret, .cockpit-row-header[aria-expanded="true"] .cockpit-caret { transform: rotate(180deg); }
.cockpit-badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.78em; font-weight: 600; }
.cockpit-badge.status-fail { background: #fde7e9; color: #a4373a; }
.cockpit-badge.status-warning { background: #fff4ce; color: #8a5a00; }
.cockpit-badge.status-review { background: #ede4f5; color: #5c2d91; }
.cockpit-badge.status-ok { background: #dff6dd; color: #107c10; }
.cockpit-badge.status-info { background: #deecf9; color: #004578; }
.cockpit-badge.risk-critical { background: #c52733; color: #fff; }
.cockpit-badge.risk-high { background: #e8893a; color: #fff; }
.cockpit-badge.risk-medium { background: #ffd166; color: #7b5e00; }
.cockpit-badge.risk-low { background: #95c19e; color: #1f3d22; }
.cockpit-badge.risk-info { background: #d6deea; color: #283b50; }
.cockpit-badge.risk-review { background: #5c2d91; color: #fff; }
.cockpit-cell-object { font-family: monospace; font-size: 0.88em; color: #333; overflow-wrap: anywhere; min-width: 0; }
.cockpit-cell-desc { color: #444; overflow-wrap: anywhere; min-width: 0; }
.cockpit-cell-owner, .cockpit-cell-disposition, .cockpit-cell-source, .cockpit-cell-state, .cockpit-cell-score { color: #555; font-size: 0.85em; }
.cockpit-caret { color: #888; font-size: 0.85em; transition: transform 0.15s; }
.cockpit-row-body { display: none; padding: 14px 18px; background: #fafbfc; border-top: 1px solid #e5e7eb; }
.cockpit-row.expanded .cockpit-row-body { display: block; }
.cockpit-row-body-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; margin-bottom: 10px; font-size: 0.88em; }
.cockpit-row-body p { margin: 6px 0; font-size: 0.9em; }
.cockpit-justification { color: #555; font-size: 0.85em; font-style: italic; margin-left: 12px; }
.cockpit-meta-line, .cockpit-finding-id { font-size: 0.82em; color: #666; }
.cockpit-finding-id code { font-family: monospace; }
.cockpit-show-more { margin-top: 12px; padding: 8px 16px; border: 1px solid #0078d4; background: #fff; color: #0078d4; border-radius: 4px; cursor: pointer; font-size: 0.9em; display: none; }
.cockpit-show-more:hover { background: #0078d4; color: #fff; }
.cockpit-show-more:focus { outline: 2px solid #0078d4; outline-offset: 2px; }
/* Cockpit hero header */
.cockpit-hero { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 24px; align-items: center; padding: 28px 30px; margin: 20px 0 24px 0; background: linear-gradient(135deg, #0a2540 0%, #0078d4 100%); color: #fff; border-radius: 12px; box-shadow: 0 4px 16px rgba(0, 50, 100, 0.18); }
.cockpit-hero-meta { min-width: 0; }
.cockpit-hero-product { margin: 0 0 4px 0; font-size: 0.84em; text-transform: uppercase; letter-spacing: 0.12em; color: rgba(255, 255, 255, 0.78); font-weight: 600; }
.cockpit-hero-tenant { margin: 0; font-size: 2.05em; font-weight: 700; color: #fff; letter-spacing: -0.01em; line-height: 1.15; word-break: break-word; }
.cockpit-hero-tenantid { margin: 6px 0 0 0; font-size: 0.86em; color: rgba(255, 255, 255, 0.78); }
.cockpit-hero-tenantid-label { text-transform: uppercase; letter-spacing: 0.06em; font-size: 0.86em; margin-right: 4px; }
.cockpit-hero-tenantid code { background: rgba(255, 255, 255, 0.12); padding: 2px 8px; border-radius: 4px; font-family: monospace; color: #fff; }
.cockpit-hero-generated { margin: 4px 0 0 0; font-size: 0.82em; color: rgba(255, 255, 255, 0.7); }
.cockpit-hero-verdict { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; min-width: 180px; }
.cockpit-hero-verdict-label { font-size: 0.74em; text-transform: uppercase; letter-spacing: 0.08em; color: rgba(255, 255, 255, 0.72); font-weight: 600; }
.cockpit-hero-verdict-pill { padding: 8px 16px; border-radius: 22px; font-weight: 700; font-size: 1em; letter-spacing: 0.02em; background: rgba(255, 255, 255, 0.92); color: #1f2937; box-shadow: 0 2px 6px rgba(0, 0, 0, 0.16); }
.cockpit-hero-verdict-pill.verdict-strong { background: #dff6dd; color: #107c10; }
.cockpit-hero-verdict-pill.verdict-minor { background: #fff4ce; color: #8a5a00; }
.cockpit-hero-verdict-pill.verdict-gaps { background: #fde7e9; color: #a4373a; }
.cockpit-hero-verdict-pill.verdict-insufficient { background: #e5e7eb; color: #4b5563; }
.cockpit-hero-verdict-count { font-size: 0.86em; color: rgba(255, 255, 255, 0.86); font-variant-numeric: tabular-nums; }
@media (max-width: 720px) {
    .cockpit-hero { grid-template-columns: 1fr; padding: 20px 22px; }
    .cockpit-hero-tenant { font-size: 1.6em; }
    .cockpit-hero-verdict { align-items: flex-start; }
}
@media print {
    .cockpit-hero { background: #fff !important; color: #0a2540 !important; box-shadow: none !important; border: 1px solid #0078d4; }
    .cockpit-hero-product, .cockpit-hero-tenantid, .cockpit-hero-tenantid-label, .cockpit-hero-generated, .cockpit-hero-verdict-label, .cockpit-hero-verdict-count { color: #4b5563 !important; }
    .cockpit-hero-tenant { color: #0a2540 !important; }
    .cockpit-hero-tenantid code { background: #f4f5f7 !important; color: #1f2937 !important; }
}

/* Executive Digest redesign */
.exec-digest { margin: 20px 0 30px 0; padding: 24px 26px; background: #fff; border-radius: 10px; box-shadow: 0 3px 10px rgba(0,0,0,0.05); border-top: 4px solid #0078d4; }
.exec-digest-head { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 14px; }
.exec-digest-title { margin: 0; font-size: 1.55em; color: #0078d4; }
.exec-verdict-line { margin: 0; font-size: 1.02em; color: #1f2937; }
.exec-verdict { display: inline-block; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.88em; margin-left: 6px; }
.exec-verdict.verdict-strong { background: #dff6dd; color: #107c10; }
.exec-verdict.verdict-minor { background: #fff4ce; color: #8a5a00; }
.exec-verdict.verdict-gaps { background: #fde7e9; color: #a4373a; }
.exec-verdict.verdict-insufficient { background: #e5e7eb; color: #4b5563; }
.exec-stat-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; margin: 14px 0; }
.exec-stat { padding: 12px 14px; border-radius: 8px; background: #f8f9fb; border-left: 4px solid #9aa3af; }
.exec-stat-value { font-size: 1.7em; font-weight: 700; font-variant-numeric: tabular-nums; line-height: 1; color: #1f2937; }
.exec-stat-label { font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; margin-top: 4px; }
.exec-stat-total { border-left-color: #0078d4; }
.exec-stat-critical { border-left-color: #c52733; }
.exec-stat-critical .exec-stat-value { color: #a4373a; }
.exec-stat-high { border-left-color: #e8893a; }
.exec-stat-high .exec-stat-value { color: #c46a1f; }
.exec-stat-review { border-left-color: #5c2d91; }
.exec-stat-review .exec-stat-value { color: #5c2d91; }
.exec-stat-quickwin { border-left-color: #107c10; }
.exec-stat-quickwin .exec-stat-value { color: #107c10; }
.exec-delta { color: #555; font-size: 0.92em; margin: 6px 0 12px 0; }
.exec-subhead { font-size: 1.08em; color: #1f2937; margin: 18px 0 8px 0; }
.exec-subhead-meta { font-weight: 400; color: #6b7280; font-size: 0.82em; margin-left: 8px; }
.exec-top-cards-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }
.exec-top-card { padding: 14px 16px; border-radius: 8px; background: #fff; border: 1px solid #e5e7eb; border-left: 4px solid #c52733; box-shadow: 0 2px 4px rgba(0,0,0,0.04); }
.exec-top-card-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; gap: 8px; }
.exec-pill { display: inline-block; padding: 2px 9px; border-radius: 11px; font-size: 0.78em; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; background: #e5e7eb; color: #1f2937; }
.exec-pill-critical { background: #c52733; color: #fff; }
.exec-pill-high { background: #e8893a; color: #fff; }
.exec-pill-medium { background: #ffd166; color: #7b5e00; }
.exec-pill-low { background: #95c19e; color: #1f3d22; }
.exec-pill-info { background: #deecf9; color: #004578; }
.exec-pill-review { background: #5c2d91; color: #fff; }
.exec-card-risk { font-size: 0.82em; color: #6b7280; font-variant-numeric: tabular-nums; }
.exec-card-desc { font-size: 0.96em; color: #1f2937; line-height: 1.4; margin: 4px 0 6px 0; }
.exec-card-object { font-size: 0.82em; color: #555; margin: 4px 0; }
.exec-card-object code { font-family: monospace; background: #f4f5f7; padding: 1px 5px; border-radius: 3px; }
.exec-card-remediation { font-size: 0.84em; color: #4b5563; line-height: 1.4; margin: 6px 0 0 0; padding-top: 6px; border-top: 1px dashed #e5e7eb; }
.exec-gap-list { display: flex; flex-direction: column; gap: 6px; }
.exec-gap-framework { border: 1px solid #e5e7eb; border-radius: 6px; background: #fff; }
.exec-gap-framework > summary { display: grid; grid-template-columns: 1fr auto 16px; gap: 10px; align-items: center; padding: 10px 14px; cursor: pointer; font-size: 0.94em; list-style: none; }
.exec-gap-framework > summary::-webkit-details-marker { display: none; }
.exec-gap-framework > summary:focus-visible { outline: 3px solid #0078d4; outline-offset: -3px; }
.exec-gap-framework-name { font-weight: 700; color: #1f2937; }
.exec-gap-framework-count { color: #a4373a; font-weight: 600; font-size: 0.86em; }
.exec-gap-caret { color: #888; font-size: 0.85em; transition: transform 0.15s; justify-self: end; }
.exec-gap-framework[open] > summary .exec-gap-caret { transform: rotate(180deg); }
.exec-gap-framework[open] > summary { border-bottom: 1px solid #e5e7eb; }
.exec-gap-framework-body { padding: 10px 14px 14px; background: #fafbfc; display: flex; flex-direction: column; gap: 6px; }
.exec-gap-control { border: 1px solid #e5e7eb; border-radius: 4px; background: #fff; }
.exec-gap-control > summary { padding: 7px 12px; cursor: pointer; font-size: 0.88em; list-style: none; display: flex; gap: 8px; align-items: center; }
.exec-gap-control > summary::-webkit-details-marker { display: none; }
.exec-gap-control > summary::before { content: '\25BE'; color: #888; transition: transform 0.15s; }
.exec-gap-control[open] > summary::before { transform: rotate(180deg); }
.exec-gap-control-id { font-family: monospace; font-size: 0.88em; background: #f4f5f7; padding: 1px 6px; border-radius: 3px; color: #1f2937; }
.exec-gap-control-count { color: #6b7280; font-size: 0.82em; margin-left: auto; }
.exec-gap-finding-list { padding: 4px 14px 10px 28px; margin: 0; font-size: 0.86em; color: #444; list-style-type: disc; }
.exec-gap-finding-list li { margin: 3px 0; line-height: 1.4; }
.exec-gap-finding-desc { color: #1f2937; }
.exec-gap-finding-obj { font-family: monospace; font-size: 0.92em; background: #f4f5f7; padding: 1px 4px; border-radius: 3px; color: #4b5563; }
.exec-gap-finding-risk { color: #6b7280; font-size: 0.86em; }
.exec-gap-finding-overflow { color: #6b7280; font-style: italic; list-style: none; margin-left: -16px; }
.exec-gap-overflow { color: #6b7280; font-style: italic; font-size: 0.84em; margin: 6px 0 0 0; }
@media print {
    .exec-gap-framework, .exec-gap-control { page-break-inside: avoid; }
    .exec-gap-framework-body, .exec-gap-finding-list { display: block !important; }
    .exec-top-card { page-break-inside: avoid; }
}

/* Compliance Posture (Defender for Cloud) */
.compliance-standard-list { display: flex; flex-direction: column; gap: 6px; }
.compliance-standard { border: 1px solid #e5e7eb; border-left-width: 4px; border-radius: 4px; background: #fff; }
.compliance-standard.good { border-left-color: #107c10; }
.compliance-standard.warn { border-left-color: #d29200; }
.compliance-standard.bad  { border-left-color: #c52733; }
.compliance-standard-summary { display: grid; grid-template-columns: minmax(120px, 1fr) minmax(140px, 2fr) 60px minmax(120px, 1.5fr) 110px 16px; gap: 12px; align-items: center; padding: 10px 14px; cursor: pointer; font-size: 0.92em; list-style: none; }
.compliance-standard-summary::-webkit-details-marker { display: none; }
.compliance-standard-summary:focus-visible { outline: 3px solid #0078d4; outline-offset: -3px; }
.compliance-standard[open] .compliance-standard-summary { border-bottom: 1px solid #e5e7eb; }
.compliance-standard[open] .compliance-standard-caret { transform: rotate(180deg); }
.compliance-standard-name { font-weight: 700; color: #1f2937; }
.compliance-standard-fullname { color: #555; font-size: 0.88em; }
.compliance-standard-pct { font-weight: 700; font-variant-numeric: tabular-nums; text-align: right; }
.compliance-standard.good .compliance-standard-pct { color: #107c10; }
.compliance-standard.warn .compliance-standard-pct { color: #8a5a00; }
.compliance-standard.bad  .compliance-standard-pct { color: #a4373a; }
.compliance-standard-bar { display: flex; height: 10px; border-radius: 5px; overflow: hidden; background: #eef0f2; }
.compliance-standard-bar .bar-pass { background: #107c10; }
.compliance-standard-bar .bar-fail { background: #c52733; }
.compliance-standard-counts { color: #555; font-size: 0.85em; font-variant-numeric: tabular-nums; }
.compliance-standard-caret { color: #888; font-size: 0.85em; transition: transform 0.15s; justify-self: end; }
.compliance-standard-body { padding: 12px 16px 16px; background: #fafbfc; display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 10px; }
.compliance-control-card { border: 1px solid #e5e7eb; border-radius: 4px; background: #fff; padding: 10px 12px; }
.compliance-control-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 6px; }
.compliance-control-id { font-family: monospace; font-size: 0.85em; background: #f4f5f7; padding: 2px 6px; border-radius: 3px; color: #1f2937; }
.compliance-control-sub { font-size: 0.78em; color: #6b7280; }
.compliance-control-count { margin-left: auto; font-size: 0.78em; color: #a4373a; font-weight: 600; }
.compliance-control-title { font-size: 0.92em; color: #1f2937; margin: 4px 0; line-height: 1.35; }
.compliance-control-remediation { font-size: 0.82em; color: #555; word-break: break-word; }
.compliance-control-empty { grid-column: 1 / -1; color: #6b7280; font-style: italic; font-size: 0.88em; }
.compliance-control-overflow { grid-column: 1 / -1; color: #555; font-size: 0.82em; margin-top: 4px; font-style: italic; }
.compliance-passing-group { margin-top: 10px; border: 1px dashed #d0d5dc; border-radius: 4px; background: #f8f9fb; }
.compliance-passing-group-summary { cursor: pointer; padding: 8px 14px; font-size: 0.88em; color: #555; }
.compliance-passing-group-summary::-webkit-details-marker { display: none; }
.compliance-passing-group-summary::before { content: '\25BE'; display: inline-block; margin-right: 8px; transition: transform 0.15s; }
.compliance-passing-group[open] .compliance-passing-group-summary::before { transform: rotate(180deg); }
.compliance-passing-group-body { padding: 8px 12px 12px; display: flex; flex-direction: column; gap: 4px; }
@media (max-width: 800px) {
    .compliance-standard-summary { grid-template-columns: 1fr auto; row-gap: 4px; }
    .compliance-standard-fullname, .compliance-standard-bar, .compliance-standard-counts { grid-column: 1 / -1; }
    .compliance-standard-caret { grid-column: 2; }
}
@media print {
    .cockpit-filters, .cockpit-saved-views, .cockpit-show-more, .cockpit-caret { display: none !important; }
    .cockpit-row { page-break-inside: avoid; }
    .cockpit-row-body { display: block !important; }
    .compliance-standard { page-break-inside: avoid; }
    .compliance-standard-body { display: block !important; }
    .compliance-passing-group-body { display: block !important; }
}
</style>
'@
}

#endregion

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

    /* Skip link: hidden until a keyboard user tabs to it, then jumps to the
       main content. Required by WCAG 2.4.1 (Bypass Blocks). */
    .skip-link {
        position: absolute;
        left: -10000px;
        top: auto;
        width: 1px;
        height: 1px;
        overflow: hidden;
        background: #0078d4;
        color: #fff;
        padding: 8px 16px;
        border-radius: 0 0 4px 0;
        font-weight: 600;
        z-index: 1000;
    }
    .skip-link:focus {
        left: 0;
        top: 0;
        width: auto;
        height: auto;
        outline: 3px solid #ffd166;
        outline-offset: 2px;
    }

    .container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 20px;
    }
    main.container { display: block; }

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

    .metric-card.review {
        border-left-color: #5c2d91;
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

    /* REVIEW = human-judgment item, not a severity band. Purple keeps it
       visually distinct from the warning/severity palette (yellow/red/green). */
    .risk-badge.review {
        background: #5c2d91;
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

    # PR 5 - Cross-surface findings section.
    $crossCount = if ($HybridCorrelation.CrossSurfaceCount) { $HybridCorrelation.CrossSurfaceCount } else { 0 }
    $crossBody = ''
    if ($HybridCorrelation.CrossSurfaceFindings -and $HybridCorrelation.CrossSurfaceFindings.Count -gt 0) {
        $sevRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
        $ordered = $HybridCorrelation.CrossSurfaceFindings | Sort-Object { $sevRank[[string]$_.Severity] }
        foreach ($cs in $ordered) {
            $sev = [System.Web.HttpUtility]::HtmlEncode([string]$cs.Severity)
            $sevClass = switch ([string]$cs.Severity) {
                'Critical' { 'critical' }
                'High' { 'high' }
                'Medium' { 'medium' }
                default { '' }
            }
            $typeEncoded = [System.Web.HttpUtility]::HtmlEncode([string]($cs.Type -replace '^HybridCrossSurface_', ''))
            $principal = [System.Web.HttpUtility]::HtmlEncode([string]$cs.Principal)
            $desc = [System.Web.HttpUtility]::HtmlEncode([string]$cs.Description)
            $rem = [System.Web.HttpUtility]::HtmlEncode([string]$cs.Remediation)
            $crossBody += @"
<tr class="$sevClass"><td>$sev</td><td>$typeEncoded</td><td>$principal</td><td>$desc<br/><em>Fix:</em> $rem</td></tr>

"@
        }
    }
    $crossSection = if ($crossBody) {
        @"
    <h3 style="margin-top: 28px;">Cross-surface findings (PR 5)</h3>
    <p style="font-size: 0.85em; color: #605e5c;">Correlators emit these when on-prem AD exposure intersects cloud privilege, yielding a one-step hybrid takeover path. Each is higher-severity than its cloud or on-prem half alone.</p>
    <table>
        <thead><tr><th>Severity</th><th>Type</th><th>Principal</th><th>Detail</th></tr></thead>
        <tbody>$crossBody</tbody>
    </table>
"@
    }
    else {
        '<p class="compliance-fallback-note" style="margin-top: 28px;">No cross-surface (hybrid takeover) paths detected this run.</p>'
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
        <div class="metric-card $(if ($crossCount -gt 0) { 'critical' } else { '' })">
            <div class="metric-label">Cross-surface paths</div>
            <div class="metric-value">$crossCount</div>
            <div>one-step hybrid takeover</div>
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
    $crossSection
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
    $review = if ($null -ne $RiskSummary.ReviewCount) { [int]$RiskSummary.ReviewCount } else { 0 }
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
    # Carry the underlying Controls hashtable through so the renderer can
    # show specific failing controls + their findings inside an accordion
    # rather than just a count.
    $frameworkGaps = @()
    if ($ComplianceGap -and $ComplianceGap.FrameworkGaps) {
        foreach ($key in @('CIS', 'NIST', 'SOC2', 'PCIDSS')) {
            $g = $ComplianceGap.FrameworkGaps[$key]
            if ($g -and $g.ControlsAffected -gt 0) {
                $frameworkGaps += [pscustomobject]@{
                    Framework        = $key
                    ControlsAffected = $g.ControlsAffected
                    Controls         = $g.Controls
                }
            }
        }
        $frameworkGaps = @($frameworkGaps | Sort-Object ControlsAffected -Descending | Select-Object -First 4)
    }

    return [pscustomobject]@{
        Verdict = $verdict
        VerdictClass = $verdictClass
        TotalFindings = $total
        CriticalCount = $crit
        HighCount = $high
        ReviewCount = $review
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
    .DESCRIPTION
        Top findings render as feature cards (risk pill + description + object
        + remediation). Compliance gaps render as accordions — each framework
        is a <details> that expands to show the specific failing controls and
        the findings underneath each one.
    #>
    param(
        [Parameter(Mandatory)] [object]$Digest,
        [Parameter(Mandatory)] [object]$TenantInfo
    )

    $verdictHtml = "<span class='exec-verdict $($Digest.VerdictClass)'>$($Digest.Verdict)</span>"

    $deltaLine = ""
    if ($Digest.FindingsDelta) {
        $d = $Digest.FindingsDelta
        $deltaLine = "<p class=`"exec-delta`"><strong>Since last assessment:</strong> $($d.Resolved) resolved &middot; $($d.New) new &middot; $($d.Persistent) persistent.</p>"
    }

    # Top findings as feature cards.
    $topCards = ""
    if ($Digest.TopFindings -and $Digest.TopFindings.Count -gt 0) {
        $cards = foreach ($f in $Digest.TopFindings) {
            $desc = ConvertTo-SafeHtml -Text ([string]$f.Description)
            $obj = ConvertTo-SafeHtml -Text ([string]$f.Object)
            $score = if ($f.PSObject.Properties['RiskScore']) { [int]$f.RiskScore } else { 0 }
            $level = if ($f.PSObject.Properties['RiskLevel'] -and $f.RiskLevel) {
                [string]$f.RiskLevel
            } elseif ($f.PSObject.Properties['Severity'] -and $f.Severity) {
                [string]$f.Severity
            } else { 'Unknown' }
            $levelLower = $level.ToLowerInvariant()
            $levelClass = "exec-pill exec-pill-$levelLower"
            $levelLabel = ConvertTo-SafeHtml -Text $level
            $remediation = ''
            if ($f.PSObject.Properties['RemediationGuidance'] -and $f.RemediationGuidance) {
                $rg = $f.RemediationGuidance
                if ($rg -is [string]) {
                    $remediation = $rg
                } elseif ($rg.PSObject.Properties['Summary'] -and $rg.Summary) {
                    $remediation = [string]$rg.Summary
                } elseif ($rg.PSObject.Properties['Description'] -and $rg.Description) {
                    $remediation = [string]$rg.Description
                }
            }
            if ([string]::IsNullOrWhiteSpace($remediation) -and $f.PSObject.Properties['Remediation']) {
                $remediation = [string]$f.Remediation
            }
            $remediationHtml = if ($remediation) {
                "<p class=`"exec-card-remediation`">$([System.Web.HttpUtility]::HtmlEncode($remediation))</p>"
            } else { '' }
            @"
        <article class="exec-top-card">
            <header class="exec-top-card-head">
                <span class="$levelClass">$levelLabel</span>
                <span class="exec-card-risk" title="Risk score">Risk $score</span>
            </header>
            <p class="exec-card-desc">$desc</p>
            <p class="exec-card-object"><code>$obj</code></p>
            $remediationHtml
        </article>
"@
        }
        $topCardsBody = $cards -join "`n"
        $topCards = @"
    <h3 class="exec-subhead">Top findings <span class="exec-subhead-meta">by risk score</span></h3>
    <div class="exec-top-cards-grid">
$topCardsBody
    </div>
"@
    }

    # Compliance gap accordions.
    $gapAccordions = ""
    if ($Digest.FrameworkGaps -and $Digest.FrameworkGaps.Count -gt 0) {
        $accordions = foreach ($g in $Digest.FrameworkGaps) {
            $fwLabel = ConvertTo-SafeHtml -Text ([string]$g.Framework)
            $controlsAffected = [int]$g.ControlsAffected
            $controlsHtml = ''
            if ($g.PSObject.Properties['Controls'] -and $g.Controls) {
                # Sort controls by # of findings desc.
                $sortedKeys = @($g.Controls.Keys | Sort-Object @{ Expression = { -([int](@($g.Controls[$_]).Count)) } }, { [string]$_ })
                $topKeys = $sortedKeys | Select-Object -First 12
                $controlRows = foreach ($key in $topKeys) {
                    $findings = @($g.Controls[$key])
                    $ctrl = ConvertTo-SafeHtml -Text ([string]$key)
                    $count = $findings.Count
                    # Sort findings by risk desc, take top 5 to keep the
                    # digest scannable. Full list is in the Action Queue.
                    $topFindings = $findings | Sort-Object @{ Expression = {
                            if ($_.PSObject.Properties['RiskScore']) { -([int]$_.RiskScore) } else { 0 }
                        }
                    } | Select-Object -First 5
                    $itemRows = foreach ($itm in $topFindings) {
                        $itmDesc = ConvertTo-SafeHtml -Text ([string]$itm.Description)
                        $itmObj = ConvertTo-SafeHtml -Text ([string]$itm.Object)
                        $itmScore = if ($itm.PSObject.Properties['RiskScore']) { [int]$itm.RiskScore } else { 0 }
                        "<li><span class=`"exec-gap-finding-desc`">$itmDesc</span> <code class=`"exec-gap-finding-obj`">$itmObj</code> <span class=`"exec-gap-finding-risk`">risk $itmScore</span></li>"
                    }
                    $overflow = if ($count -gt 5) {
                        $extra = $count - 5
                        "<li class=`"exec-gap-finding-overflow`">+ $extra more under this control &mdash; see Action Queue.</li>"
                    } else { '' }
                    @"
                <details class="exec-gap-control">
                    <summary><code class="exec-gap-control-id">$ctrl</code> <span class="exec-gap-control-count">$count finding(s)</span></summary>
                    <ul class="exec-gap-finding-list">
                        $($itemRows -join "`n                        ")
                        $overflow
                    </ul>
                </details>
"@
                }
                $controlsHtml = $controlRows -join "`n"
                if ($sortedKeys.Count -gt 12) {
                    $extraCtrls = $sortedKeys.Count - 12
                    $controlsHtml += "`n<p class=`"exec-gap-overflow`">+ $extraCtrls additional affected control(s) under this framework.</p>"
                }
            }
            @"
        <details class="exec-gap-framework">
            <summary>
                <span class="exec-gap-framework-name">$fwLabel</span>
                <span class="exec-gap-framework-count">$controlsAffected control(s) affected</span>
                <span class="exec-gap-caret" aria-hidden="true">&#x25BE;</span>
            </summary>
            <div class="exec-gap-framework-body">
                $controlsHtml
            </div>
        </details>
"@
        }
        $gapAccordionsBody = $accordions -join "`n"
        $gapAccordions = @"
    <h3 class="exec-subhead">Compliance gaps <span class="exec-subhead-meta">expand a framework to see failing controls</span></h3>
    <div class="exec-gap-list">
$gapAccordionsBody
    </div>
"@
    }

    return @"
<section class="exec-digest" id="exec-digest">
    <header class="exec-digest-head">
        <h2 class="exec-digest-title">Executive Digest</h2>
        <p class="exec-verdict-line"><strong>Posture:</strong> $verdictHtml</p>
    </header>
    <div class="exec-stat-row">
        <div class="exec-stat exec-stat-total"><div class="exec-stat-value">$($Digest.TotalFindings)</div><div class="exec-stat-label">Total findings</div></div>
        <div class="exec-stat exec-stat-critical"><div class="exec-stat-value">$($Digest.CriticalCount)</div><div class="exec-stat-label">Critical</div></div>
        <div class="exec-stat exec-stat-high"><div class="exec-stat-value">$($Digest.HighCount)</div><div class="exec-stat-label">High</div></div>
        <div class="exec-stat exec-stat-review"><div class="exec-stat-value">$($Digest.ReviewCount)</div><div class="exec-stat-label">To review</div></div>
        <div class="exec-stat exec-stat-quickwin"><div class="exec-stat-value">$($Digest.QuickWinsCount)</div><div class="exec-stat-label">Quick wins</div></div>
    </div>
    $deltaLine
    $topCards
    $gapAccordions
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

        <div class="metric-card review">
            <div class="metric-label">Items to Review</div>
            <div class="metric-value">$(if ($null -ne $RiskSummary.ReviewCount) { $RiskSummary.ReviewCount } else { 0 })</div>
            <div>Require human judgment</div>
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
            <div><strong>Source:</strong> $(if ($finding.Source) { [System.Net.WebUtility]::HtmlEncode([string]$finding.Source) } else { 'Internal' })</div>
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
    # REVIEW sits between WARNING and INFO — visible above advisory items but
    # below the broken-state findings that demand action.
    $statusOrder = @('FAIL', 'WARNING', 'REVIEW', 'INFO', 'OK')

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
    'Test-EntraChecksReportIntegrity',
    # PR 1 of HTML-Reporting-Consolidation-Plan — safety helpers consumed by
    # the cockpit renderer that PR 2 introduces. Exported so cross-module
    # callers (Compliance.psm1, ExcelReporting.psm1 link rendering, etc.)
    # can use the same encoders.
    'ConvertTo-SafeHtml',
    'ConvertTo-SafeHtmlAttribute',
    'ConvertTo-SafeHtmlJson',
    'New-SafeExternalLink',
    'New-SafeElementId',
    # PR 2 of HTML-Reporting-Consolidation-Plan — single analyst cockpit
    # renderer. Opt-in in PR 2; PR 4 flips the orchestrator default.
    'New-EntraChecksAnalystHtmlReport',
    # PR 4 of HTML-Reporting-Consolidation-Plan — orchestrator-facing routing
    # decision. Returns a plan hashtable the orchestrator acts on.
    'Get-HtmlReportPlan'
)

#endregion
