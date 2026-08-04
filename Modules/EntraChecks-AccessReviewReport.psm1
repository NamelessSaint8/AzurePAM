<#
.SYNOPSIS
    Access-review report rendering (PR 3 of the Access Review plan).

.DESCRIPTION
    Renders a campaign folder produced by EntraChecks-AccessReview.psm1
    into a standalone, self-contained AccessReview-Report.html with the
    seven evidence sections a SOC 2 / PCI DSS assessor expects:

      1. Cover           — system-generation evidence (tenant, UTC time,
                           tool version, authenticated principal, hashes)
      2. Review summary  — decision + verification counts
      3. Administrators  — privileged principals with decisions (the
                           "administrators must be included" section)
      4. All users       — full roster with decisions (capped in HTML,
                           complete in the CSV artifacts)
      5. Changes         — baseline->final delta cross-referenced to
                           decisions, NOT_REMEDIATED / UNEXPLAINED_CHANGE
                           flags surfaced
      6. Updated list    — final roster when changes occurred, otherwise
                           an explicit "no changes required" statement
      7. Sign-off        — reviewer identity + worksheet SHA-256

    Open (not yet closed) campaigns render with a DRAFT watermark and
    pending placeholders — useful for previewing, never for submission.

    Rendering is presentation-only: this module reads the campaign
    artifacts (CSV/JSON) directly and never talks to Microsoft Graph.
#>

#Requires -Version 5.1

#region ==================== MODULE VARIABLES ====================

$script:ModuleVersion = '1.0.0'

#endregion

#region ==================== PRIVATE FUNCTIONS ====================

function Get-ArEncoded {
    <#
    .SYNOPSIS
        HTML-encodes a value for safe interpolation. Every piece of tenant
        data goes through here — display names are attacker-controllable.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ArHtmlTable {
    <#
    .SYNOPSIS
        Renders rows into an HTML table. Columns is an array of
        @{ Name = <property>; Label = <header> } hashtables. Rows beyond
        MaxRows are dropped with a visible truncation note (0 = no cap).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [Parameter(Mandatory)][object[]]$Columns,
        [int]$MaxRows = 0,
        [string]$CssClass = 'ar-table'
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("<table class=""$CssClass""><thead><tr>")
    foreach ($c in $Columns) {
        [void]$sb.Append('<th>').Append((Get-ArEncoded $c.Label)).AppendLine('</th>')
    }
    [void]$sb.AppendLine('</tr></thead><tbody>')

    $shown = if ($MaxRows -gt 0 -and @($Rows).Count -gt $MaxRows) { @($Rows)[0..($MaxRows - 1)] } else { @($Rows) }
    foreach ($row in $shown) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $val = if ($row.PSObject.Properties[$c.Name]) { $row.($c.Name) } else { '' }
            [void]$sb.Append('<td>').Append((Get-ArEncoded $val)).Append('</td>')
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')

    $hidden = @($Rows).Count - @($shown).Count
    if ($hidden -gt 0) {
        [void]$sb.AppendLine("<p class=""ar-truncation-note"">$hidden additional row(s) not shown — the complete list is in the campaign CSV artifacts.</p>")
    }
    return $sb.ToString()
}

function Get-ArStatTiles {
    <#
    .SYNOPSIS
        Renders label/value pairs as summary tiles. Tiles is an array of
        @{ Label; Value; Css } hashtables (Css optional: 'warn'/'bad').
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object[]]$Tiles
    )
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<div class="ar-tiles">')
    foreach ($t in $Tiles) {
        $css = if ($t.Css) { " ar-tile-$($t.Css)" } else { '' }
        [void]$sb.AppendLine("<div class=""ar-tile$css""><div class=""ar-tile-value"">$(Get-ArEncoded $t.Value)</div><div class=""ar-tile-label"">$(Get-ArEncoded $t.Label)</div></div>")
    }
    [void]$sb.AppendLine('</div>')
    return $sb.ToString()
}

function Read-ArCampaignData {
    <#
    .SYNOPSIS
        Loads every renderable artifact from a campaign folder into one
        hashtable. Missing final/verification artifacts (open campaigns)
        load as $null — the renderer degrades to a DRAFT.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$CampaignDirectory
    )

    $metaPath = Join-Path $CampaignDirectory 'campaign.json'
    if (-not (Test-Path -LiteralPath $metaPath)) {
        return @{ Available = $false; FailureReason = "Not a campaign folder (campaign.json missing): $CampaignDirectory" }
    }

    $readJson = {
        param($Name)
        $p = Join-Path $CampaignDirectory $Name
        if (Test-Path -LiteralPath $p) { Get-Content -LiteralPath $p -Raw | ConvertFrom-Json } else { $null }
    }
    $readCsv = {
        param($Name)
        $p = Join-Path $CampaignDirectory $Name
        if (Test-Path -LiteralPath $p) { , @(Import-Csv -LiteralPath $p) } else { , @() }
    }

    $meta = & $readJson 'campaign.json'
    $manifest = & $readJson 'manifest.json'
    $verification = & $readJson 'verification.json'

    $worksheetHash = ''
    if ($manifest -and $manifest.PSObject.Properties['Files']) {
        $entry = @($manifest.Files) | Where-Object { $_.RelativePath -eq 'review-worksheet.csv' } | Select-Object -First 1
        if ($entry) { $worksheetHash = [string]$entry.SHA256 }
    }

    return @{
        Available = $true
        FailureReason = $null
        Meta = $meta
        IsDraft = ($meta.Status -ne 'Closed')
        BaselineUsers = (& $readCsv 'roster-baseline.csv')
        FinalUsers = (& $readCsv 'roster-final.csv')
        Admins = (& $readCsv 'admins-baseline.csv')
        Verification = $verification
        BundleHash = if ($manifest) { [string]$manifest.BundleHash } else { '' }
        WorksheetHash = $worksheetHash
    }
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-AccessReviewReportHtml {
    <#
    .SYNOPSIS
        Renders campaign data (shape of Read-ArCampaignData) into the full
        report HTML string. Pure presentation — no file or network I/O.

    .PARAMETER CampaignData
        Hashtable produced by Read-ArCampaignData (exposed for tests via
        New-AccessReviewReport in normal use).

    .PARAMETER MaxUserRows
        HTML row cap for the all-users and updated-list tables (the CSV
        artifacts always hold the complete data). Administrators are never
        capped. Default 500.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][hashtable]$CampaignData,
        [int]$MaxUserRows = 500
    )

    $meta = $CampaignData.Meta
    $isDraft = [bool]$CampaignData.IsDraft
    $verification = $CampaignData.Verification

    # Decision/verdict lookup for merging into roster tables
    $decisionByOid = @{}
    if ($verification) {
        foreach ($d in @($verification.Decisions)) { $decisionByOid[[string]$d.ObjectId] = $d }
    }
    $mergeDecision = {
        param($Rows)
        , @(foreach ($r in @($Rows)) {
                $d = $decisionByOid[[string]$r.ObjectId]
                $r | Select-Object *,
                @{ Name = 'Decision'; Expression = { if ($d) { $d.Decision } elseif ($isDraft) { 'Pending' } else { '' } } },
                @{ Name = 'Verdict'; Expression = { if ($d) { $d.Verdict } else { '' } } },
                @{ Name = 'ReviewNotes'; Expression = { if ($d) { $d.Notes } else { '' } } }
            })
    }

    $sb = [System.Text.StringBuilder]::new()

    # ----- Document head -----
    $title = "Access Review Report - $($meta.CampaignId)"
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine("<title>$(Get-ArEncoded $title)</title>")
    [void]$sb.AppendLine(@'
<style>
body { font-family: "Segoe UI", Arial, sans-serif; margin: 0; color: #222; background: #f5f6f8; }
.ar-page { max-width: 1100px; margin: 0 auto; padding: 24px; }
.ar-header { background: #1b2a41; color: #fff; padding: 28px 32px; border-radius: 8px; margin-bottom: 24px; }
.ar-header h1 { margin: 0 0 4px 0; font-size: 1.6em; }
.ar-header .ar-subtitle { color: #9fb3c8; font-size: 0.95em; }
section.ar-section { background: #fff; border-radius: 8px; padding: 20px 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
section.ar-section h2 { margin-top: 0; font-size: 1.15em; border-bottom: 2px solid #e5e8ec; padding-bottom: 8px; }
.ar-meta-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 8px 24px; }
.ar-meta-grid dt { font-weight: 600; font-size: 0.8em; color: #667; text-transform: uppercase; }
.ar-meta-grid dd { margin: 0 0 8px 0; font-size: 0.95em; word-break: break-all; }
.ar-tiles { display: flex; flex-wrap: wrap; gap: 12px; }
.ar-tile { background: #f0f3f6; border-radius: 6px; padding: 12px 18px; min-width: 110px; text-align: center; }
.ar-tile-warn { background: #fff4e0; }
.ar-tile-bad { background: #fdeaea; }
.ar-tile-value { font-size: 1.5em; font-weight: 700; }
.ar-tile-label { font-size: 0.78em; color: #556; }
table.ar-table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
table.ar-table th { background: #f0f3f6; text-align: left; padding: 8px 10px; border-bottom: 2px solid #d0d5dc; }
table.ar-table td { padding: 7px 10px; border-bottom: 1px solid #e5e8ec; vertical-align: top; }
table.ar-table tr:hover td { background: #fafbfc; }
.ar-truncation-note { font-size: 0.8em; color: #856404; background: #fff3cd; padding: 6px 10px; border-radius: 4px; }
.ar-hash { font-family: monospace; font-size: 0.82em; word-break: break-all; color: #555; }
.ar-statement { font-size: 0.95em; padding: 10px 14px; background: #eef7ee; border-left: 4px solid #4a934a; border-radius: 4px; }
.ar-statement-pending { background: #fff3cd; border-left-color: #b8860b; }
.ar-flag-NOT_REMEDIATED td { background: #fdeaea; }
.ar-flag-UNEXPLAINED_CHANGE td { background: #fff4e0; }
.ar-draft-banner { background: #b30000; color: #fff; text-align: center; font-weight: 700; padding: 10px; border-radius: 6px; margin-bottom: 16px; letter-spacing: 2px; }
.ar-watermark { position: fixed; top: 40%; left: 50%; transform: translate(-50%, -50%) rotate(-30deg); font-size: 9em; color: rgba(179, 0, 0, 0.08); font-weight: 900; pointer-events: none; z-index: 999; }
</style>
'@)
    [void]$sb.AppendLine('</head><body><div class="ar-page">')

    if ($isDraft) {
        [void]$sb.AppendLine('<div class="ar-watermark">DRAFT</div>')
        [void]$sb.AppendLine('<div class="ar-draft-banner">DRAFT — CAMPAIGN NOT YET CLOSED — NOT VALID AS AUDIT EVIDENCE</div>')
    }

    # ----- 1. Cover -----
    $tenantLabel = if ($meta.TenantName) { "$($meta.TenantName) — User Access Review" } else { 'User Access Review' }
    [void]$sb.AppendLine('<div class="ar-header"><h1>' + (Get-ArEncoded $tenantLabel) + '</h1>')
    [void]$sb.AppendLine('<div class="ar-subtitle">Periodic review of access rights — SOC 2 CC6.1-CC6.3 / PCI DSS v4.0 7.2.4, 7.2.5.1</div></div>')

    [void]$sb.AppendLine('<section class="ar-section" id="cover"><h2>1. Campaign &amp; System-Generation Evidence</h2><dl class="ar-meta-grid">')
    $coverPairs = @(
        @{ L = 'Campaign'; V = $meta.CampaignId }
        @{ L = 'Review period'; V = $meta.PeriodLabel }
        @{ L = 'Status'; V = $meta.Status }
        @{ L = 'Tenant ID'; V = $meta.TenantId }
        @{ L = 'Tenant name'; V = $meta.TenantName }
        @{ L = 'Generated (UTC)'; V = $meta.GeneratedAtUtc }
        @{ L = 'Closed (UTC)'; V = $(if ($meta.PSObject.Properties['ClosedAtUtc']) { $meta.ClosedAtUtc } else { '—' }) }
        @{ L = 'Generated by tool'; V = "EntraChecks AccessReview v$($meta.EntraChecksVersion)" }
        @{ L = 'Run ID'; V = $meta.RunId }
        @{ L = 'Executing principal'; V = "$($meta.GeneratedBy.Account) ($($meta.GeneratedBy.AuthType))" }
        @{ L = 'Evidence bundle hash (SHA-256)'; V = $CampaignData.BundleHash }
    )
    foreach ($p in $coverPairs) {
        [void]$sb.AppendLine("<div><dt>$(Get-ArEncoded $p.L)</dt><dd>$(Get-ArEncoded $p.V)</dd></div>")
    }
    [void]$sb.AppendLine('</dl></section>')

    # ----- 2. Review summary -----
    [void]$sb.AppendLine('<section class="ar-section" id="summary"><h2>2. Review Summary</h2>')
    $tiles = @(
        @{ Label = 'Users in scope'; Value = $meta.Counts.TotalUsers }
        @{ Label = 'Privileged principals'; Value = $meta.Counts.PrivilegedPrincipals }
        @{ Label = 'Rows reviewed'; Value = $meta.Counts.WorksheetAccessRows }
    )
    if ($verification) {
        $s = $verification.Summary
        $tiles += @(
            @{ Label = 'Certified'; Value = $s.Certified }
            @{ Label = 'Revoked'; Value = $s.Revoked }
            @{ Label = 'Modified'; Value = $s.Modified }
            @{ Label = 'Investigate'; Value = $s.Investigated }
            @{ Label = 'Changes observed'; Value = $s.TotalChanges }
            @{ Label = 'Not remediated'; Value = $s.NotRemediated; Css = $(if ([int]$s.NotRemediated -gt 0) { 'bad' } else { $null }) }
            @{ Label = 'Unexplained changes'; Value = $s.UnexplainedChanges; Css = $(if ([int]$s.UnexplainedChanges -gt 0) { 'warn' } else { $null }) }
        )
    }
    [void]$sb.AppendLine((Get-ArStatTiles -Tiles $tiles))
    if ($isDraft) {
        [void]$sb.AppendLine('<p class="ar-statement ar-statement-pending">Decision and verification counts appear after the campaign is closed.</p>')
    }
    [void]$sb.AppendLine('</section>')

    # ----- 3. Administrators reviewed (never capped) -----
    [void]$sb.AppendLine('<section class="ar-section" id="admins"><h2>3. Administrators Reviewed</h2>')
    [void]$sb.AppendLine('<p>Every privileged principal — including disabled accounts and service principals — requires an explicit review decision.</p>')
    $adminCols = @(
        @{ Name = 'DisplayName'; Label = 'Name' }
        @{ Name = 'UserPrincipalName'; Label = 'UPN / App' }
        @{ Name = 'PrincipalType'; Label = 'Type' }
        @{ Name = 'HighestTier'; Label = 'Tier' }
        @{ Name = 'Privileges'; Label = 'Privileges' }
        @{ Name = 'AccountEnabled'; Label = 'Enabled' }
        @{ Name = 'Decision'; Label = 'Decision' }
        @{ Name = 'Verdict'; Label = 'Verification' }
        @{ Name = 'ReviewNotes'; Label = 'Reviewer notes' }
    )
    [void]$sb.AppendLine((Get-ArHtmlTable -Rows (& $mergeDecision $CampaignData.Admins) -Columns $adminCols))
    [void]$sb.AppendLine('</section>')

    # ----- 4. All users reviewed -----
    [void]$sb.AppendLine('<section class="ar-section" id="users"><h2>4. All Users Reviewed (baseline)</h2>')
    $userCols = @(
        @{ Name = 'DisplayName'; Label = 'Name' }
        @{ Name = 'UserPrincipalName'; Label = 'UPN' }
        @{ Name = 'UserType'; Label = 'Type' }
        @{ Name = 'AccountEnabled'; Label = 'Enabled' }
        @{ Name = 'Roles'; Label = 'Roles' }
        @{ Name = 'LastSignIn'; Label = 'Last sign-in' }
        @{ Name = 'Decision'; Label = 'Decision' }
        @{ Name = 'ReviewNotes'; Label = 'Reviewer notes' }
    )
    [void]$sb.AppendLine((Get-ArHtmlTable -Rows (& $mergeDecision $CampaignData.BaselineUsers) -Columns $userCols -MaxRows $MaxUserRows))
    [void]$sb.AppendLine('</section>')

    # ----- 5. Changes made as a result of the review -----
    [void]$sb.AppendLine('<section class="ar-section" id="changes"><h2>5. Changes Made as a Result of the Review</h2>')
    if ($isDraft) {
        [void]$sb.AppendLine('<p class="ar-statement ar-statement-pending">The change delta is computed when the campaign is closed.</p>')
    }
    elseif (@($verification.Delta).Count -eq 0) {
        [void]$sb.AppendLine('<p class="ar-statement">No access changes were required as a result of this review. All reviewed access rights were certified as appropriate.</p>')
    }
    else {
        $deltaCols = @(
            @{ Name = 'DisplayName'; Label = 'Name' }
            @{ Name = 'UserPrincipalName'; Label = 'UPN / App' }
            @{ Name = 'ChangeType'; Label = 'Change' }
            @{ Name = 'Detail'; Label = 'Detail' }
        )
        [void]$sb.AppendLine((Get-ArHtmlTable -Rows @($verification.Delta) -Columns $deltaCols))
    }
    if ($verification -and @($verification.Flags).Count -gt 0) {
        [void]$sb.AppendLine('<h3>Verification flags</h3>')
        [void]$sb.AppendLine('<table class="ar-table"><thead><tr><th>Flag</th><th>Name</th><th>UPN / App</th><th>Detail</th></tr></thead><tbody>')
        foreach ($f in @($verification.Flags)) {
            $cls = 'ar-flag-' + [string]$f.Flag
            [void]$sb.AppendLine("<tr class=""$(Get-ArEncoded $cls)""><td>$(Get-ArEncoded $f.Flag)</td><td>$(Get-ArEncoded $f.DisplayName)</td><td>$(Get-ArEncoded $f.UserPrincipalName)</td><td>$(Get-ArEncoded $f.Detail)</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
    }
    [void]$sb.AppendLine('</section>')

    # ----- 6. Updated user list -----
    [void]$sb.AppendLine('<section class="ar-section" id="updated"><h2>6. Updated User List (post-review)</h2>')
    if ($isDraft) {
        [void]$sb.AppendLine('<p class="ar-statement ar-statement-pending">The updated user list is captured when the campaign is closed.</p>')
    }
    elseif (@($verification.Delta).Count -eq 0) {
        [void]$sb.AppendLine('<p class="ar-statement">No changes were made, so the baseline user list above remains the list of record for this review period.</p>')
    }
    else {
        $finalCols = @(
            @{ Name = 'DisplayName'; Label = 'Name' }
            @{ Name = 'UserPrincipalName'; Label = 'UPN' }
            @{ Name = 'UserType'; Label = 'Type' }
            @{ Name = 'AccountEnabled'; Label = 'Enabled' }
            @{ Name = 'Roles'; Label = 'Roles' }
        )
        [void]$sb.AppendLine((Get-ArHtmlTable -Rows @($CampaignData.FinalUsers) -Columns $finalCols -MaxRows $MaxUserRows))
    }
    [void]$sb.AppendLine('</section>')

    # ----- 7. Sign-off -----
    [void]$sb.AppendLine('<section class="ar-section" id="signoff"><h2>7. Reviewer Sign-Off</h2>')
    if ($isDraft -or -not $meta.PSObject.Properties['SignOff']) {
        [void]$sb.AppendLine('<p class="ar-statement ar-statement-pending">Pending review sign-off — the campaign has not been closed.</p>')
    }
    else {
        [void]$sb.AppendLine('<dl class="ar-meta-grid">')
        [void]$sb.AppendLine("<div><dt>Reviewer</dt><dd>$(Get-ArEncoded $meta.SignOff.ReviewerName)</dd></div>")
        [void]$sb.AppendLine("<div><dt>Title</dt><dd>$(Get-ArEncoded $meta.SignOff.ReviewerTitle)</dd></div>")
        [void]$sb.AppendLine("<div><dt>Sign-off date</dt><dd>$(Get-ArEncoded $meta.SignOff.SignOffDate)</dd></div>")
        [void]$sb.AppendLine("<div><dt>Completed worksheet SHA-256</dt><dd class=""ar-hash"">$(Get-ArEncoded $CampaignData.WorksheetHash)</dd></div>")
        [void]$sb.AppendLine("<div><dt>Evidence bundle hash</dt><dd class=""ar-hash"">$(Get-ArEncoded $CampaignData.BundleHash)</dd></div>")
        [void]$sb.AppendLine('</dl>')
        [void]$sb.AppendLine('<p>The completed worksheet (per-principal decisions, notes, and this sign-off) is hashed into the campaign manifest — the reviewer''s attestation and the system-generated data share one tamper-evident chain.</p>')
    }
    [void]$sb.AppendLine('</section>')

    [void]$sb.AppendLine("<p style=""color:#889;font-size:0.8em;"">Generated by EntraChecks AccessReview v$(Get-ArEncoded $meta.EntraChecksVersion) — verify artifact integrity against manifest.json (SHA-256).</p>")
    [void]$sb.AppendLine('</div></body></html>')
    return $sb.ToString()
}

function New-AccessReviewReport {
    <#
    .SYNOPSIS
        Renders AccessReview-Report.html for a campaign folder.

    .PARAMETER CampaignDirectory
        Campaign folder created by New-AccessReviewCampaign.

    .PARAMETER OutputPath
        Optional explicit output file. Default: AccessReview-Report.html
        inside the campaign folder.

    .PARAMETER MaxUserRows
        HTML row cap for user tables (CSV artifacts stay complete).

    .EXAMPLE
        New-AccessReviewReport -CampaignDirectory .\Output\AccessReview\2026-Q3-20260803-141500
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$CampaignDirectory,
        [string]$OutputPath = '',
        [int]$MaxUserRows = 500
    )

    $data = Read-ArCampaignData -CampaignDirectory $CampaignDirectory
    if (-not $data.Available) {
        return @{ Success = $false; FailureReason = $data.FailureReason }
    }

    $html = Get-AccessReviewReportHtml -CampaignData $data -MaxUserRows $MaxUserRows
    if (-not $OutputPath) { $OutputPath = Join-Path $CampaignDirectory 'AccessReview-Report.html' }
    $html | Set-Content -LiteralPath $OutputPath -Encoding UTF8

    return @{
        Success = $true
        FailureReason = $null
        ReportPath = $OutputPath
        IsDraft = $data.IsDraft
        CampaignId = [string]$data.Meta.CampaignId
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-AccessReviewReportHtml',
    'New-AccessReviewReport'
)

#endregion
