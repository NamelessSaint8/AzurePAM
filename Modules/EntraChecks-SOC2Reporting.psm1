<#
.SYNOPSIS
    EntraChecks-SOC2Reporting.psm1 - SOC 2 standalone report builder
    (HTML + Excel/CSV) for internal readiness assessments.

.DESCRIPTION
    Renders the SOC 2 audit view as a TSC-structured report distinct from the
    severity-ranked unified EntraChecks report. The HTML report supports an
    optional local "identity lookup" side panel that resolves redacted hashes
    back to UPNs when the companion identity-resolution map is co-located.

    Excel output is provided when the optional ImportExcel module is available;
    otherwise a multi-CSV fallback is produced.

.NOTES
    Version: 1.0.0
    Author: EntraChecks Project

.LINK
    SOC 2 Implementation Plan: plans/SOC2-Implementation-Plan.md
#>

#Requires -Version 5.1

$script:ModuleName = 'EntraChecks-SOC2Reporting'
$script:ModuleVersion = '1.0.0'

# Phase 2 decision 1 (Path C): these check names ship fixture-verified only;
# the rendered HTML surfaces a caveat banner when results from these appear.
# Graduate to a config key if the list grows.
$script:LowConfidenceCheckNames = @(
    'Test-SOC2DiagnosticSettingsExport',
    'Test-SOC2BreakGlassAccountsConfigured'
)

#region ==================== INTERNAL HELPERS (row builders + digest) ====================

<#
.SYNOPSIS
    Builds summary-by-category rows once, consumed by both Excel and CSV branches.
#>
function Get-SOC2SummaryByCategoryRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][pscustomobject]$Summary)

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $f = $Summary.ByFamily[$family]
        if (-not $f) { continue }
        if (($f.Automated + $f.Manual) -eq 0) { continue }
        $licensingGapCount = if ($null -ne $f.LicensingGaps) { $f.LicensingGaps } else { 0 }
        $row = [pscustomobject]@{
            Family = $family
            Automated = $f.Automated
            Manual = $f.Manual
            Pass = $f.Pass
            Fail = $f.Fail
            Warning = $f.Warning
            Info = $f.Info
            LicensingGaps = $licensingGapCount
        }
        $rows.Add($row) | Out-Null
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds control-register rows for either report format.
#>
function Get-SOC2ControlRegisterRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object[]]$Catalog,
        [Parameter(Mandatory)][pscustomobject]$Summary
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($control in $Catalog) {
        $count = if ($Summary.ControlFindings.ContainsKey($control.Id)) {
            @($Summary.ControlFindings[$control.Id]).Count
        } else { 0 }
        $row = [pscustomobject]@{
            ControlId = $control.Id
            Family = $control.Family
            FamilyName = $control.FamilyName
            Automation = $control.Automation
            Description = $control.Description
            ControlOwnerHint = $control.ControlOwnerHint
            FindingCount = $count
        }
        $rows.Add($row) | Out-Null
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds finding rows for a given TSC-family predicate (e.g., "starts with CC6").
    Returns empty array when no findings match (callers skip empty sheets/files).
#>
function Get-SOC2FindingsByFamilyRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object[]]$Catalog,
        [Parameter(Mandatory)][pscustomobject]$Summary,
        [Parameter(Mandatory)][scriptblock]$Predicate
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($control in $Catalog) {
        if (-not (& $Predicate $control.Id)) { continue }
        $controlFindings = if ($Summary.ControlFindings.ContainsKey($control.Id)) {
            @($Summary.ControlFindings[$control.Id])
        } else { @() }
        foreach ($finding in $controlFindings) {
            $severity = if ($finding.PSObject.Properties['Severity']) { $finding.Severity } else { '' }
            $row = [pscustomobject]@{
                ControlId = $control.Id
                Status = $finding.Status
                Severity = $severity
                CheckName = $finding.CheckName
                Object = $finding.Object
                Description = $finding.Description
                Remediation = $finding.Remediation
            }
            $rows.Add($row) | Out-Null
        }
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds licensing-gap rows (de-duped by Type + Object).
#>
function Get-SOC2LicensingGapRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][pscustomobject]$Summary)

    $rows = [System.Collections.Generic.List[object]]::new()
    $allFindings = @()
    foreach ($controlId in $Summary.ControlFindings.Keys) {
        $allFindings += @($Summary.ControlFindings[$controlId])
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($finding in $allFindings) {
        if (-not ($finding.PSObject.Properties['Type'] -and $finding.Type -like 'SOC2_LicensingGap_*')) { continue }
        $key = "$($finding.Type)|$($finding.Object)"
        if (-not $seen.Add($key)) { continue }
        $feature = $finding.Type.Substring('SOC2_LicensingGap_'.Length)
        $tscList = ''
        if ($finding.PSObject.Properties['TSCReferences']) { $tscList = ($finding.TSCReferences -join ', ') }
        $severity = if ($finding.PSObject.Properties['Severity']) { $finding.Severity } else { '' }
        $owner = if ($finding.PSObject.Properties['ControlOwnerHint']) { $finding.ControlOwnerHint } else { '' }
        $row = [pscustomobject]@{
            Feature = $feature
            Status = $finding.Status
            Severity = $severity
            AffectedTSCs = $tscList
            Description = $finding.Description
            Remediation = $finding.Remediation
            ControlOwnerHint = $owner
        }
        $rows.Add($row) | Out-Null
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds manual-attestation register rows.
#>
function Get-SOC2ManualAttestationRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][object[]]$Catalog)

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($control in $Catalog) {
        if ($control.Automation -ne 'Manual') { continue }
        $row = [pscustomobject]@{
            ControlId = $control.Id
            Family = $control.Family
            Description = $control.Description
            ControlOwner = ''
            DescriptionOfOperation = ''
            Frequency = ''
            EvidenceLocation = ''
            AttestedBy = ''
            AttestedDate = ''
        }
        $rows.Add($row) | Out-Null
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Builds evidence-register rows from a manifest. Returns empty when no manifest.

.PARAMETER Evidence
    Evidence object returned by New-SOC2EvidenceBundle (a PSCustomObject with
    ManifestPath, BundleHash, Directory, FileCount, GeneratedAt). Accepts null.

    The parameter is typed as [object] rather than [hashtable] because the
    real production path returns a PSCustomObject; PowerShell does not
    auto-coerce PSCustomObject -> Hashtable. Tests may pass a hashtable
    fixture — both shapes expose the same dotted-property access this
    function uses.
#>
function Get-SOC2EvidenceRegisterRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object]$Evidence
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    if ($Evidence -and $Evidence.ManifestPath -and (Test-Path -LiteralPath $Evidence.ManifestPath)) {
        $manifest = Get-Content -LiteralPath $Evidence.ManifestPath -Raw | ConvertFrom-Json
        foreach ($file in $manifest.Files) {
            $row = [pscustomobject]@{
                RelativePath = $file.RelativePath
                SHA256 = $file.SHA256
            }
            $rows.Add($row) | Out-Null
        }
    }
    return , $rows.ToArray()
}

<#
.SYNOPSIS
    Per-family predicate registry used by both Excel and CSV branches.
    Returns an ordered list of @{Name; Predicate} objects.
#>
function Get-SOC2FamilyPredicates {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return , @(
        [pscustomobject]@{ Name = 'CC6'; Predicate = { param($c) $c.StartsWith('CC6') } },
        [pscustomobject]@{ Name = 'CC7'; Predicate = { param($c) $c.StartsWith('CC7') } },
        [pscustomobject]@{ Name = 'CC8'; Predicate = { param($c) $c.StartsWith('CC8') } },
        [pscustomobject]@{ Name = 'Other-CC'; Predicate = { param($c) $c.StartsWith('CC') -and -not ($c.StartsWith('CC6') -or $c.StartsWith('CC7') -or $c.StartsWith('CC8')) } },
        [pscustomobject]@{ Name = 'Availability'; Predicate = { param($c) $c.StartsWith('A') } },
        [pscustomobject]@{ Name = 'Confidentiality'; Predicate = { param($c) $c.StartsWith('C') -and -not $c.StartsWith('CC') } }
    )
}

<#
.SYNOPSIS
    Computes the executive digest: readiness verdict + top failing TSCs + top
    licensing-gap features. Consumed by New-SOC2AuditReport for the Executive
    Summary section.
#>
function Get-SOC2ExecutiveDigest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object[]]$Catalog,
        [Parameter(Mandatory)][pscustomobject]$Summary
    )

    # Readiness verdict (simple heuristic — no magic tuning; documented thresholds)
    $totalFail = 0
    $totalWarn = 0
    $totalPass = 0
    $totalControls = 0
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $f = $Summary.ByFamily[$family]
        if (-not $f) { continue }
        $totalFail += $f.Fail
        $totalWarn += $f.Warning
        $totalPass += $f.Pass
        $totalControls += ($f.Automated + $f.Manual)
    }

    $verdict = 'INSUFFICIENT DATA'
    $verdictClass = 'state-Unobserved'
    if ($totalControls -gt 0) {
        if ($totalFail -eq 0 -and $totalWarn -eq 0) {
            $verdict = 'STRONG'
            $verdictClass = 'state-ConsistentlyPassing'
        } elseif ($totalFail -gt 0) {
            $verdict = 'GAPS IDENTIFIED'
            $verdictClass = 'state-Inconsistent'
        } else {
            $verdict = 'MINOR DEFICIENCIES'
            $verdictClass = 'state-DegradedButOperating'
        }
    }

    # Top failing TSCs: per control, count FAIL+WARNING findings, sort desc
    $tscFailCounts = [System.Collections.Generic.List[object]]::new()
    foreach ($control in $Catalog) {
        if (-not $Summary.ControlFindings.ContainsKey($control.Id)) { continue }
        $findings = @($Summary.ControlFindings[$control.Id])
        $fail = @($findings | Where-Object { $_.Status -eq 'FAIL' -or $_.Status -eq 'WARNING' }).Count
        if ($fail -gt 0) {
            $row = [pscustomobject]@{
                ControlId = $control.Id
                Family = $control.Family
                Description = $control.Description
                FailCount = $fail
            }
            $tscFailCounts.Add($row) | Out-Null
        }
    }
    $topFailingTscs = @($tscFailCounts | Sort-Object FailCount -Descending | Select-Object -First 3)

    # Top licensing gaps by affected TSC count (from ByFeature rollup if present)
    $topLicensingGaps = @()
    if ($Summary.PSObject.Properties['LicensingGaps'] -and $Summary.LicensingGaps -and $Summary.LicensingGaps.ByFeature) {
        $topLicensingGaps = @(
            $Summary.LicensingGaps.ByFeature.GetEnumerator() |
                Where-Object { $_.Value -gt 0 } |
                Sort-Object Value -Descending |
                Select-Object -First 3 |
                ForEach-Object { [pscustomobject]@{ Feature = $_.Key; Count = $_.Value } }
        )
    }

    return [pscustomobject]@{
        Verdict = $verdict
        VerdictClass = $verdictClass
        TotalControls = $totalControls
        TotalPass = $totalPass
        TotalFail = $totalFail
        TotalWarning = $totalWarn
        TotalFindings = $Summary.TotalFindings
        TopFailingTscs = $topFailingTscs
        TopLicensingGaps = $topLicensingGaps
        LicensingGapsTotal = if ($Summary.PSObject.Properties['LicensingGaps'] -and $Summary.LicensingGaps) { $Summary.LicensingGaps.Total } else { 0 }
    }
}

<#
.SYNOPSIS
    Returns $true if the provided check name is on the fixture-verified-only list
    (Phase 2 Path C low-confidence checks).
#>
function Test-SOC2IsLowConfidenceCheck {
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$CheckName)

    if (-not $CheckName) { return $false }
    return ($script:LowConfidenceCheckNames -contains $CheckName)
}

#endregion

#region ==================== HTML REPORT ====================

function New-SOC2AuditReport {
    <#
    .SYNOPSIS
        Renders the SOC 2 standalone HTML audit report.

    .DESCRIPTION
        Produces a TSC-structured report including: cover panel, by-category
        summary, control register, per-control finding tables, manual
        attestation register, evidence summary. Supports white-label branding
        via Get-ReportBrandingContext and an optional identity-lookup side panel
        that loads the resolution map from a sibling local path (data is NOT
        embedded into the HTML).

    .PARAMETER AssessmentResult
        The PSCustomObject returned by Invoke-SOC2Assessment.

    .PARAMETER OutputPath
        Where to write the .html file.

    .PARAMETER Branding
        Optional branding context from Get-ReportBrandingContext.

    .PARAMETER IdentityResolutionMapPath
        Optional local file path to the identity-resolution-*.json. When
        provided, the report exposes an "Identity lookup" side panel.

    .OUTPUTS
        String path to the rendered HTML file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$AssessmentResult,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [pscustomobject]$Branding,

        [string]$IdentityResolutionMapPath
    )

    if (-not $Branding) {
        if (Get-Command Get-ReportBrandingContext -ErrorAction SilentlyContinue) {
            $Branding = Get-ReportBrandingContext -Config $null -ReportTitle 'SOC 2 Internal Readiness Assessment'
        } else {
            $Branding = [pscustomobject]@{
                WhiteLabel = $false
                ReportTitle = 'SOC 2 Internal Readiness Assessment'
                OrganizationName = 'EntraChecks'
                LogoDataUri = ''
                PrimaryColor = '#005A9E'
                Footer = ''
                Attribution = "Generated by EntraChecks v$($script:ModuleVersion)"
                SuppressEntraChecksBranding = $false
            }
        }
    }

    $catalog = $AssessmentResult.Catalog
    $summary = $AssessmentResult.Summary
    $evidence = $AssessmentResult.Evidence

    # Ensure System.Web is loaded before HtmlEncode is called below.
    # In production (.NET Framework PowerShell 5.1) this is a no-op when the
    # assembly is already loaded; in Pester's clean runspace it's required.
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $primaryColor = $Branding.PrimaryColor
    $orgName = $Branding.OrganizationName
    $title = $Branding.ReportTitle
    $logoHtml = if ($Branding.LogoDataUri) {
        "<img src='$($Branding.LogoDataUri)' alt='Logo' class='org-logo' />"
    } else { '' }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en">')
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine("<meta charset='UTF-8'>")
    [void]$sb.AppendLine("<title>$([System.Web.HttpUtility]::HtmlEncode($title))</title>")
    [void]$sb.AppendLine(@"
<style>
* { box-sizing: border-box; }
body { font-family: Segoe UI, Roboto, system-ui, sans-serif; margin: 0; color: #1a1a1a; background: #f4f6f8; }
header { background: $primaryColor; color: white; padding: 24px 32px; display: flex; align-items: center; gap: 16px; }
header .org-logo { max-height: 48px; max-width: 200px; background: white; padding: 4px; border-radius: 4px; }
header h1 { margin: 0; font-size: 1.6em; font-weight: 600; }
header .meta { margin-left: auto; text-align: right; font-size: 0.85em; opacity: 0.9; }
main { display: grid; grid-template-columns: 1fr 320px; gap: 24px; max-width: 1600px; margin: 0 auto; padding: 24px; }
section.report { background: white; border-radius: 6px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 24px; }
aside { position: sticky; top: 24px; align-self: start; }
aside .panel { background: white; border-radius: 6px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 16px; }
h2 { color: $primaryColor; border-bottom: 2px solid $primaryColor; padding-bottom: 8px; margin-top: 0; }
h3 { color: #333; margin-top: 24px; }
table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.9em; }
th { background: #f0f3f6; text-align: left; padding: 8px 12px; border-bottom: 2px solid #d0d5dc; }
td { padding: 8px 12px; border-bottom: 1px solid #e5e8ec; vertical-align: top; }
tr:hover { background: #fafbfc; }
.status-ok { color: #2a8c3c; font-weight: 600; }
.status-fail { color: #c8102e; font-weight: 600; }
.status-warning { color: #d89b00; font-weight: 600; }
.status-info { color: #5a6c7d; }
.status-manual { color: #5b3fa9; font-weight: 600; }
.status-licensing { color: #6a5fb3; font-weight: 600; }
.licensing-panel { background: #f3f0fb; border-left: 4px solid #6a5fb3; padding: 12px 16px; margin: 16px 0; border-radius: 4px; }
.licensing-panel .title { font-weight: 600; color: #6a5fb3; margin-bottom: 8px; }
.licensing-panel .breakdown { font-size: 0.9em; color: #555; }
.licensing-panel .breakdown span { display: inline-block; margin-right: 14px; }
.severity-Critical { background: #c8102e; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.severity-High { background: #ff6f00; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.severity-Medium { background: #d89b00; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.severity-Low { background: #4a90d9; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.severity-Info { background: #6c757d; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 16px 0; }
.summary-card { background: #f8f9fb; padding: 16px; border-left: 4px solid $primaryColor; border-radius: 4px; }
.summary-card .family { font-weight: 600; font-size: 1.1em; margin-bottom: 8px; }
.summary-card .row { font-size: 0.85em; color: #555; }
.tsc-control { background: #f8f9fb; border-left: 4px solid $primaryColor; padding: 12px 16px; margin-bottom: 16px; border-radius: 4px; }
.tsc-control .id { font-weight: 700; font-size: 1.1em; color: $primaryColor; }
.tsc-control .meta { font-size: 0.85em; color: #666; margin-top: 4px; }
.tsc-control .desc { margin-top: 8px; }
footer { background: #2a3441; color: #d0d5dc; text-align: center; padding: 16px; font-size: 0.85em; }
.lookup-input { width: 100%; padding: 8px; border: 1px solid #d0d5dc; border-radius: 4px; font-family: monospace; }
.lookup-result { background: #f0f3f6; padding: 8px; margin-top: 8px; border-radius: 4px; font-family: monospace; font-size: 0.85em; word-break: break-all; }
.lookup-warning { background: #fff8e1; padding: 8px; margin-top: 8px; border-radius: 4px; font-size: 0.85em; color: #7b5e00; }
.lookup-picker { display: none; margin-top: 8px; padding: 8px; background: #eef4fb; border: 1px dashed #5b8fb9; border-radius: 4px; font-size: 0.85em; }
.lookup-picker label { display: block; margin-bottom: 6px; color: #1c3d5a; }
.evidence-hash { font-family: monospace; font-size: 0.85em; word-break: break-all; }
/* Phase-3-followup reporting enhancements */
.badge { display: inline-block; padding: 2px 10px; border-radius: 3px; font-size: 0.85em; font-weight: 600; }
.badge-met { background: #2a8c3c; color: white; }
.badge-unmet { background: #c8102e; color: white; }
.badge-neutral { background: #5a6c7d; color: white; }
.exec-summary { background: linear-gradient(135deg, #f8f9fb 0%, #eef1f6 100%); border-radius: 6px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.exec-summary h2 { border-bottom: none; margin-top: 0; }
.exec-summary .verdict { font-size: 1.4em; font-weight: 700; margin: 8px 0 20px 0; }
.exec-summary .headline-row { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 16px; }
.exec-summary .headline-stat { background: white; padding: 10px 16px; border-radius: 4px; min-width: 120px; }
.exec-summary .headline-stat .label { font-size: 0.75em; color: #666; text-transform: uppercase; letter-spacing: 0.05em; }
.exec-summary .headline-stat .value { font-size: 1.6em; font-weight: 700; color: $primaryColor; }
.exec-summary .section-title { font-weight: 600; margin-top: 16px; margin-bottom: 8px; color: #333; }
.exec-summary .top-list { list-style: none; padding-left: 0; }
.exec-summary .top-list li { background: white; padding: 8px 12px; margin-bottom: 4px; border-left: 3px solid $primaryColor; border-radius: 3px; font-size: 0.9em; }
.exec-summary .top-list .tsc-id { font-weight: 700; color: $primaryColor; margin-right: 8px; }
.exec-summary .top-list .count-chip { background: #f0f3f6; padding: 1px 8px; border-radius: 10px; font-size: 0.8em; margin-left: 6px; }
.exec-summary .nav-links { margin-top: 12px; }
.exec-summary .nav-links a { display: inline-block; background: white; padding: 4px 10px; margin: 2px 4px 2px 0; border-radius: 3px; text-decoration: none; color: $primaryColor; font-size: 0.85em; border: 1px solid #d0d5dc; }
.exec-summary .nav-links a:hover { background: $primaryColor; color: white; }
.low-confidence-banner { background: #fff8e1; border-left: 6px solid #d89b00; padding: 12px 16px; margin: 16px 0; border-radius: 4px; font-size: 0.9em; }
.low-confidence-banner strong { color: #7b5e00; }
.low-confidence-tag { display: inline-block; background: #fff8e1; color: #7b5e00; padding: 1px 6px; border-radius: 3px; font-size: 0.75em; margin-left: 6px; }
.summary-card a.family-link { color: inherit; text-decoration: none; }
.summary-card a.family-link:hover .family { text-decoration: underline; }
.integrity-icon { display: inline-block; vertical-align: middle; margin-right: 4px; }
/* Print stylesheet */
@media print {
    body { background: white; }
    aside { display: none; }
    main { display: block; max-width: none; padding: 0; }
    header { break-inside: avoid; }
    section.report, .exec-summary { break-inside: avoid; page-break-inside: avoid; box-shadow: none; border: 1px solid #d0d5dc; }
    .tsc-control { break-inside: avoid; page-break-inside: avoid; }
    .low-confidence-banner { break-inside: avoid; }
    * { -webkit-print-color-adjust: exact !important; color-adjust: exact !important; print-color-adjust: exact !important; }
    .exec-summary .nav-links { display: none; }
    a[href^="#"] { text-decoration: none; color: inherit; }
}
</style>
"@)
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body>')

    # Header
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine($logoHtml)
    [void]$sb.AppendLine("<h1>$([System.Web.HttpUtility]::HtmlEncode($title))</h1>")
    [void]$sb.AppendLine("<div class='meta'>")
    [void]$sb.AppendLine("<div>$([System.Web.HttpUtility]::HtmlEncode($orgName))</div>")
    [void]$sb.AppendLine("<div>Generated $((Get-Date).ToString('u'))</div>")
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</header>')

    [void]$sb.AppendLine('<main>')
    [void]$sb.AppendLine('<div>')

    # Executive summary (reporting-enhancements PR) — pinned at the top for
    # a one-page readiness view before the reader scrolls into detail.
    $digest = Get-SOC2ExecutiveDigest -Catalog $catalog -Summary $summary
    [void]$sb.AppendLine('<section class="exec-summary">')
    [void]$sb.AppendLine('<h2>Executive Summary</h2>')
    [void]$sb.AppendLine("<div class='verdict'><span class='$($digest.VerdictClass)'>Internal readiness: $($digest.Verdict)</span></div>")
    [void]$sb.AppendLine('<div class="headline-row">')
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Controls</div><div class='value'>$($digest.TotalControls)</div></div>")
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Passing</div><div class='value'>$($digest.TotalPass)</div></div>")
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Failing</div><div class='value'>$($digest.TotalFail)</div></div>")
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Warnings</div><div class='value'>$($digest.TotalWarning)</div></div>")
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Licensing gaps</div><div class='value'>$($digest.LicensingGapsTotal)</div></div>")
    [void]$sb.AppendLine("<div class='headline-stat'><div class='label'>Total findings</div><div class='value'>$($digest.TotalFindings)</div></div>")
    [void]$sb.AppendLine('</div>')

    if ($digest.TopFailingTscs.Count -gt 0) {
        [void]$sb.AppendLine("<div class='section-title'>Top gaps to address</div>")
        [void]$sb.AppendLine("<ul class='top-list'>")
        foreach ($top in $digest.TopFailingTscs) {
            $encDesc = [System.Web.HttpUtility]::HtmlEncode($top.Description)
            [void]$sb.AppendLine("<li><span class='tsc-id'>$($top.ControlId)</span> ($($top.Family)) - $encDesc <span class='count-chip'>$($top.FailCount) issue(s)</span></li>")
        }
        [void]$sb.AppendLine('</ul>')
    }

    if ($digest.TopLicensingGaps.Count -gt 0) {
        [void]$sb.AppendLine("<div class='section-title'>Top licensing gaps</div>")
        [void]$sb.AppendLine("<ul class='top-list'>")
        foreach ($gap in $digest.TopLicensingGaps) {
            [void]$sb.AppendLine("<li><span class='tsc-id'>$($gap.Feature)</span> <span class='count-chip'>$($gap.Count) TSC(s) affected</span></li>")
        }
        [void]$sb.AppendLine('</ul>')
    }

    # Quick-nav links to per-family detail
    [void]$sb.AppendLine("<div class='section-title'>Jump to</div>")
    [void]$sb.AppendLine("<div class='nav-links'>")
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $hasControls = @($catalog | Where-Object { $_.Family -eq $family }).Count -gt 0
        if ($hasControls) {
            [void]$sb.AppendLine("<a href='#family-$family'>$family</a>")
        }
    }
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</section>')

    # Low-confidence check banner (reporting-enhancements PR) — fires only
    # when at least one fixture-verified-only check surfaces in the findings.
    $lowConfidenceFound = $false
    foreach ($controlId in $summary.ControlFindings.Keys) {
        $findingsForControl = @($summary.ControlFindings[$controlId])
        foreach ($finding in $findingsForControl) {
            if (Test-SOC2IsLowConfidenceCheck -CheckName $finding.CheckName) {
                $lowConfidenceFound = $true
                break
            }
        }
        if ($lowConfidenceFound) { break }
    }
    if ($lowConfidenceFound) {
        [void]$sb.AppendLine('<div class="low-confidence-banner">')
        [void]$sb.AppendLine('<strong>Verification note:</strong> This report includes results from checks that ship <em>fixture-verified only</em> (<code>Test-SOC2DiagnosticSettingsExport</code>, <code>Test-SOC2BreakGlassAccountsConfigured</code>). Spot-check these against your live tenant before relying on the output for audit evidence. See <code>docs/SOC2-Guide.md</code> SS11 for the per-check confidence table.')
        [void]$sb.AppendLine('</div>')
    }

    # Cover panel
    [void]$sb.AppendLine('<section class="report">')
    [void]$sb.AppendLine('<h2>Assessment Cover</h2>')
    $integrityBadgeCover = if ($evidence) { "<span class='badge badge-met'>&check; Integrity-verifiable</span>" } else { "<span class='badge badge-neutral'>No bundle</span>" }
    [void]$sb.AppendLine('<table>')
    [void]$sb.AppendLine("<tr><th>TSC Revision</th><td>AICPA TSC 2017 (revised 2022)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Type</th><td>Type 1 (point-in-time)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Categories in scope</th><td>$(($catalog | Select-Object -ExpandProperty Family -Unique) -join ', ')</td></tr>")
    [void]$sb.AppendLine("<tr><th>Total controls</th><td>$($summary.TotalControls)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Total findings</th><td>$($summary.TotalFindings)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Evidence integrity</th><td>$integrityBadgeCover</td></tr>")
    if ($evidence) {
        [void]$sb.AppendLine("<tr><th>Evidence bundle hash (SHA-256)</th><td class='evidence-hash'>$($evidence.BundleHash)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Evidence bundle path</th><td>$([System.Web.HttpUtility]::HtmlEncode($evidence.Directory))</td></tr>")
    }
    [void]$sb.AppendLine('</table>')
    [void]$sb.AppendLine('</section>')

    # Summary grid by family
    [void]$sb.AppendLine('<section class="report">')
    [void]$sb.AppendLine('<h2>Summary by Trust Services Category</h2>')
    [void]$sb.AppendLine('<div class="summary-grid">')
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $f = $summary.ByFamily[$family]
        if (-not $f) { continue }
        $totalControls = $f.Automated + $f.Manual
        if ($totalControls -eq 0) { continue }
        $licensingGapCount = if ($null -ne $f.LicensingGaps) { $f.LicensingGaps } else { 0 }
        [void]$sb.AppendLine('<div class="summary-card">')
        [void]$sb.AppendLine("<a class='family-link' href='#family-$family'><div class='family'>$family</div></a>")
        [void]$sb.AppendLine("<div class='row'>Controls: $totalControls (auto: $($f.Automated), manual: $($f.Manual))</div>")
        [void]$sb.AppendLine("<div class='row'><span class='status-ok'>Pass: $($f.Pass)</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='status-fail'>Fail: $($f.Fail)</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='status-warning'>Warn: $($f.Warning)</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='status-info'>Info: $($f.Info)</span></div>")
        [void]$sb.AppendLine("<div class='row'><span class='status-licensing'>Not Assessed (Licensing): $licensingGapCount</span></div>")
        [void]$sb.AppendLine('</div>')
    }
    [void]$sb.AppendLine('</div>')

    # Phase 3 PR 3: Global licensing-gap callout panel
    if ($summary.PSObject.Properties['LicensingGaps'] -and $summary.LicensingGaps -and $summary.LicensingGaps.Total -gt 0) {
        [void]$sb.AppendLine('<div class="licensing-panel">')
        [void]$sb.AppendLine("<div class='title'>Licensing gaps: $($summary.LicensingGaps.Total) control(s) not assessed due to missing licensing</div>")
        $byFeatureBits = [System.Collections.Generic.List[string]]::new()
        foreach ($feature in @('IdentityProtection', 'Intune', 'PurviewE5', 'DefenderForCloud', 'DefenderForEndpoint', 'Priva')) {
            $count = $summary.LicensingGaps.ByFeature[$feature]
            if ($count -gt 0) {
                $byFeatureBits.Add("<span><strong>${feature}:</strong> $count</span>") | Out-Null
            }
        }
        if ($byFeatureBits.Count -gt 0) {
            [void]$sb.AppendLine("<div class='breakdown'>$([string]::Join(' ', $byFeatureBits.ToArray()))</div>")
        }
        [void]$sb.AppendLine('<div class="breakdown" style="margin-top:6px;font-size:0.85em;">If a feature should be in scope, set its override in <code>SOC2.AzureReadiness.Licensing.Overrides</code> to escalate from INFO to WARNING/FAIL.</div>')
        [void]$sb.AppendLine('</div>')
    }

    [void]$sb.AppendLine('</section>')

    # Control register grouped by family (anchor IDs wired for quick-nav links)
    foreach ($family in @('CC', 'A', 'C', 'PI', 'P')) {
        $controlsInFamily = @($catalog | Where-Object { $_.Family -eq $family })
        if ($controlsInFamily.Count -eq 0) { continue }

        [void]$sb.AppendLine("<section class='report' id='family-$family'>")
        $familyName = ($controlsInFamily | Select-Object -First 1 -ExpandProperty FamilyName)
        [void]$sb.AppendLine("<h2>$family - $([System.Web.HttpUtility]::HtmlEncode($familyName))</h2>")

        foreach ($control in $controlsInFamily) {
            $controlFindings = @()
            if ($summary.ControlFindings.ContainsKey($control.Id)) {
                $controlFindings = @($summary.ControlFindings[$control.Id])
            }

            [void]$sb.AppendLine('<div class="tsc-control">')
            [void]$sb.AppendLine("<div class='id'>$($control.Id)</div>")
            [void]$sb.AppendLine("<div class='meta'>Automation: $($control.Automation) | Owner hint: $([System.Web.HttpUtility]::HtmlEncode($control.ControlOwnerHint)) | Findings: $($controlFindings.Count)</div>")
            [void]$sb.AppendLine("<div class='desc'>$([System.Web.HttpUtility]::HtmlEncode($control.Description))</div>")

            if ($controlFindings.Count -gt 0) {
                [void]$sb.AppendLine('<table>')
                [void]$sb.AppendLine('<thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Object</th><th>Description</th><th>Remediation</th></tr></thead>')
                [void]$sb.AppendLine('<tbody>')
                foreach ($finding in $controlFindings) {
                    $statusClass = "status-$(($finding.Status -as [string]).ToLower())"
                    $severity = if ($finding.PSObject.Properties['Severity']) { $finding.Severity } else { 'Info' }
                    $checkName = if ($finding.PSObject.Properties['CheckName']) { $finding.CheckName } else { '' }
                    $checkTag = ''
                    if (Test-SOC2IsLowConfidenceCheck -CheckName $checkName) {
                        $checkTag = " <span class='low-confidence-tag' title='Fixture-verified only; see SOC2-Guide §11'>fixture-verified</span>"
                    }
                    [void]$sb.AppendLine('<tr>')
                    [void]$sb.AppendLine("<td class='$statusClass'>$($finding.Status)</td>")
                    [void]$sb.AppendLine("<td><span class='severity-$severity'>$severity</span></td>")
                    [void]$sb.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($checkName))$checkTag</td>")
                    [void]$sb.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Object))</td>")
                    [void]$sb.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Description))</td>")
                    [void]$sb.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Remediation))</td>")
                    [void]$sb.AppendLine('</tr>')
                }
                [void]$sb.AppendLine('</tbody>')
                [void]$sb.AppendLine('</table>')
            }

            [void]$sb.AppendLine('</div>')
        }
        [void]$sb.AppendLine('</section>')
    }

    [void]$sb.AppendLine('</div>')

    # Side panel
    [void]$sb.AppendLine('<aside>')
    [void]$sb.AppendLine('<div class="panel">')
    [void]$sb.AppendLine('<h3>Identity lookup</h3>')
    if ($IdentityResolutionMapPath) {
        $escapedPath = $IdentityResolutionMapPath -replace '\\', '\\\\'
        [void]$sb.AppendLine("<p style='font-size: 0.85em; color: #555;'>Resolves redacted hashes shown in this report to UPNs. Lookup data is loaded locally from the resolution map at:</p>")
        [void]$sb.AppendLine("<p style='font-family: monospace; font-size: 0.75em; word-break: break-all;'>$([System.Web.HttpUtility]::HtmlEncode($IdentityResolutionMapPath))</p>")
        [void]$sb.AppendLine("<input type='text' id='lookup-input' class='lookup-input' placeholder='Paste hash prefix (12+ chars)' />")
        [void]$sb.AppendLine("<div id='lookup-result' class='lookup-result'>Awaiting input...</div>")
        [void]$sb.AppendLine("<div id='lookup-picker' class='lookup-picker'>")
        [void]$sb.AppendLine("<label for='lookup-file'>Select the resolution map JSON shown above. Data stays in your browser tab and is never written back to this file.</label>")
        [void]$sb.AppendLine("<input type='file' id='lookup-file' accept='application/json,.json' />")
        [void]$sb.AppendLine("</div>")
        [void]$sb.AppendLine(@"
<script>
(function () {
  let resolutionData = null;

  function setResult(text, warn) {
    const el = document.getElementById('lookup-result');
    el.className = warn ? 'lookup-warning' : 'lookup-result';
    el.textContent = text;
  }

  function showPicker(reason) {
    document.getElementById('lookup-picker').style.display = 'block';
    setResult(reason + ' Use the picker below to load the resolution map manually.', true);
  }

  function applyData(data, source) {
    resolutionData = data;
    const count = (data && data.Entries) ? data.Entries.length : 0;
    setResult('Loaded ' + count + ' entries' + (source ? ' (' + source + ')' : '') + '. Paste a hash prefix above.', false);
    document.getElementById('lookup-picker').style.display = 'none';
  }

  async function tryFetch() {
    try {
      const r = await fetch('$escapedPath');
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const data = await r.json();
      applyData(data, 'auto-loaded');
    } catch (e) {
      // file:// fetch is blocked by the browser; fall back to the picker.
      showPicker('Auto-load blocked by the browser when this report is opened from the file system.');
    }
  }

  function handlePick(evt) {
    const file = evt.target.files && evt.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function (e) {
      try {
        const data = JSON.parse(e.target.result);
        if (!data || !Array.isArray(data.Entries)) {
          throw new Error('JSON does not look like a resolution map (missing Entries array).');
        }
        applyData(data, 'picker: ' + file.name);
      } catch (err) {
        setResult('Could not parse selected file: ' + err.message, true);
      }
    };
    reader.onerror = function () {
      setResult('Could not read selected file.', true);
    };
    reader.readAsText(file);
  }

  function handleQuery(evt) {
    if (evt.target.id !== 'lookup-input') return;
    if (!resolutionData) {
      setResult('No resolution map loaded yet — load one first.', true);
      return;
    }
    const q = (evt.target.value || '').toLowerCase().trim();
    if (q.length < 8) {
      setResult('Type at least 8 hex chars...', false);
      return;
    }
    const matches = resolutionData.Entries.filter(function (x) { return x.Hash && x.Hash.toLowerCase().startsWith(q); });
    const el = document.getElementById('lookup-result');
    el.className = 'lookup-result';
    if (matches.length === 0) {
      el.textContent = 'No match.';
    } else {
      el.innerHTML = matches.slice(0, 5).map(function (m) {
        return 'Hash: ' + m.Hash.substring(0, 16) + '...<br>UPN: ' + (m.UPN || '(none)') + '<br>Display: ' + (m.DisplayName || '(none)');
      }).join('<hr>');
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('lookup-file').addEventListener('change', handlePick);
    tryFetch();
  });
  document.addEventListener('input', handleQuery);
})();
</script>
"@)
    } else {
        [void]$sb.AppendLine("<p style='font-size: 0.85em; color: #555;'>No identity-resolution map is associated with this report (redaction was not enabled, or no PII was redacted).</p>")
    }
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div class="panel">')
    [void]$sb.AppendLine('<h3>Evidence integrity &mdash; verifiable</h3>')
    if ($evidence) {
        # Inline checkmark SVG (hash-chain evocation — no external asset dependency)
        $integrityIcon = "<svg class='integrity-icon' xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 16 16' fill='#2a8c3c'><path d='M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z'/></svg>"
        [void]$sb.AppendLine("<p style='font-size: 0.85em;'>${integrityIcon}<span class='badge badge-met'>Integrity-verifiable</span></p>")
        [void]$sb.AppendLine("<p style='font-size: 0.85em;'>Bundle hash (SHA-256):</p>")
        [void]$sb.AppendLine("<p class='evidence-hash' style='font-size: 0.7em;'>$($evidence.BundleHash)</p>")
        [void]$sb.AppendLine("<p style='font-size: 0.8em;'>To verify: <code>Test-SOC2EvidenceBundle -ManifestPath '$($evidence.ManifestPath)'</code></p>")
    } else {
        [void]$sb.AppendLine("<p style='font-size: 0.85em;'><span class='badge badge-neutral'>No bundle</span></p>")
        [void]$sb.AppendLine("<p style='font-size: 0.85em; color: #555;'>No evidence bundle was produced for this run.</p>")
    }
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('</aside>')
    [void]$sb.AppendLine('</main>')

    [void]$sb.AppendLine('<footer>')
    if ($Branding.Footer) {
        [void]$sb.AppendLine([System.Web.HttpUtility]::HtmlEncode($Branding.Footer))
        [void]$sb.AppendLine('<br>')
    }
    if (-not $Branding.SuppressEntraChecksBranding) {
        [void]$sb.AppendLine($Branding.Attribution)
    }
    [void]$sb.AppendLine('</footer>')

    [void]$sb.AppendLine('</body>')
    [void]$sb.AppendLine('</html>')

    Set-Content -LiteralPath $OutputPath -Value $sb.ToString() -Encoding UTF8

    return $OutputPath
}

#endregion

#region ==================== EXCEL / CSV REPORT ====================

function New-SOC2AuditWorkbook {
    <#
    .SYNOPSIS
        Renders the SOC 2 audit workbook (Excel via ImportExcel if available,
        else multi-CSV fallback).

    .DESCRIPTION
        Sheets / files emitted:
        - Cover
        - Summary by Category
        - Control Register
        - Findings - CC6, CC7, CC8, Other CC, Availability (A), Confidentiality (C)
        - Manual Attestation Register
        - Evidence Register

    .PARAMETER AssessmentResult
        The PSCustomObject returned by Invoke-SOC2Assessment.

    .PARAMETER OutputPath
        Where to write the .xlsx (or CSV directory if ImportExcel is unavailable).

    .OUTPUTS
        String path to the workbook (or directory of CSVs).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$AssessmentResult,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $catalog = $AssessmentResult.Catalog
    $summary = $AssessmentResult.Summary
    $evidence = $AssessmentResult.Evidence

    # Row sets built once via private helpers; consumed by both Excel and CSV branches.
    $coverRows = @(
        [pscustomobject]@{ Field = 'TSC Revision'; Value = 'AICPA TSC 2017 (revised 2022)' }
        [pscustomobject]@{ Field = 'Type'; Value = 'Type 1' }
        [pscustomobject]@{ Field = 'Generated (UTC)'; Value = (Get-Date).ToUniversalTime().ToString('u') }
        [pscustomobject]@{ Field = 'Categories'; Value = (($catalog | Select-Object -ExpandProperty Family -Unique) -join ', ') }
        [pscustomobject]@{ Field = 'Total Controls'; Value = $summary.TotalControls }
        [pscustomobject]@{ Field = 'Total Findings'; Value = $summary.TotalFindings }
        [pscustomobject]@{ Field = 'Bundle Hash (SHA-256)'; Value = if ($evidence) { $evidence.BundleHash } else { '' } }
        [pscustomobject]@{ Field = 'Bundle Path'; Value = if ($evidence) { $evidence.Directory } else { '' } }
    )
    $summaryRows = Get-SOC2SummaryByCategoryRows -Summary $summary
    $registerRows = Get-SOC2ControlRegisterRows -Catalog $catalog -Summary $summary
    $familyPreds = Get-SOC2FamilyPredicates
    $licensingRows = Get-SOC2LicensingGapRows -Summary $summary
    $manualRows = Get-SOC2ManualAttestationRows -Catalog $catalog
    $evidenceRows = Get-SOC2EvidenceRegisterRows -Evidence $evidence

    $useExcel = $null -ne (Get-Module -ListAvailable -Name ImportExcel)

    if ($useExcel) {
        Import-Module ImportExcel -ErrorAction Stop

        $coverRows | Export-Excel -Path $OutputPath -WorksheetName 'Cover' -AutoSize -ClearSheet
        if ($summaryRows) { $summaryRows | Export-Excel -Path $OutputPath -WorksheetName 'Summary by Category' -AutoSize -TableName 'tblSummary' }
        if ($registerRows) { $registerRows | Export-Excel -Path $OutputPath -WorksheetName 'Control Register' -AutoSize -TableName 'tblRegister' }

        foreach ($fp in $familyPreds) {
            $rows = Get-SOC2FindingsByFamilyRows -Catalog $catalog -Summary $summary -Predicate $fp.Predicate
            if ($rows.Count -gt 0) {
                $sheetName = "Findings - $($fp.Name)"
                $rows | Export-Excel -Path $OutputPath -WorksheetName $sheetName -AutoSize
            }
        }

        if ($licensingRows.Count -gt 0) {
            $licensingRows | Export-Excel -Path $OutputPath -WorksheetName 'Findings - Licensing Gaps' -AutoSize -TableName 'tblLicensing'
        }
        if ($manualRows.Count -gt 0) {
            $manualRows | Export-Excel -Path $OutputPath -WorksheetName 'Manual Attestation' -AutoSize -TableName 'tblManual'
        }
        if ($evidenceRows.Count -gt 0) {
            $evidenceRows | Export-Excel -Path $OutputPath -WorksheetName 'Evidence Register' -AutoSize -TableName 'tblEvidence'
        }

        return $OutputPath
    }

    # CSV fallback — mirrors the Excel sheet structure with numbered filenames
    # so a CSV-only consumer gets the same data surface as an Excel consumer.
    $csvDir = if ($OutputPath -like '*.xlsx') { [System.IO.Path]::ChangeExtension($OutputPath, '') -replace '\.$', '' } else { $OutputPath }
    if (-not (Test-Path -LiteralPath $csvDir)) {
        $null = New-Item -Path $csvDir -ItemType Directory -Force
    }

    $coverRows | Export-Csv -Path (Join-Path $csvDir '01-Cover.csv') -NoTypeInformation -Encoding UTF8

    if ($summaryRows) {
        $summaryRows | Export-Csv -Path (Join-Path $csvDir '02-Summary-by-Category.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($registerRows) {
        $registerRows | Export-Csv -Path (Join-Path $csvDir '03-Control-Register.csv') -NoTypeInformation -Encoding UTF8
    }

    # Per-family findings CSVs, numbered 04-09 (matches Excel sheet order)
    $csvIndex = 4
    foreach ($fp in $familyPreds) {
        $rows = Get-SOC2FindingsByFamilyRows -Catalog $catalog -Summary $summary -Predicate $fp.Predicate
        if ($rows.Count -gt 0) {
            $fileName = '{0:D2}-Findings-{1}.csv' -f $csvIndex, $fp.Name
            $rows | Export-Csv -Path (Join-Path $csvDir $fileName) -NoTypeInformation -Encoding UTF8
        }
        $csvIndex++
    }

    if ($licensingRows.Count -gt 0) {
        $licensingRows | Export-Csv -Path (Join-Path $csvDir '10-Findings-Licensing-Gaps.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($manualRows.Count -gt 0) {
        $manualRows | Export-Csv -Path (Join-Path $csvDir '11-Manual-Attestation.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($evidenceRows.Count -gt 0) {
        $evidenceRows | Export-Csv -Path (Join-Path $csvDir '12-Evidence-Register.csv') -NoTypeInformation -Encoding UTF8
    }

    return $csvDir
}

#endregion

Export-ModuleMember -Function @(
    'New-SOC2AuditReport',
    'New-SOC2AuditWorkbook'
)
