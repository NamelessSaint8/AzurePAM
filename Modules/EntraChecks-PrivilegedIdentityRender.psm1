<#
.SYNOPSIS
    EntraChecks-PrivilegedIdentityRender.psm1
    Rendering helpers for the Privileged Identity Roster (PR 5 of the
    Privileged Identity Roster work).

.DESCRIPTION
    Owns every consumer-side rendering concern so the unified report,
    the standalone HTML report, and the Excel/CSV exporter all produce
    consistent visual output without duplicating logic. Inputs are the
    output of Merge-PrivilegedIdentityRosters; outputs are HTML strings,
    a CSS string, and flat row arrays ready for Export-Excel / Export-Csv.

.NOTES
    The catalog (PR 1) supplies WhyPrivileged paragraphs, AttackPaths, and
    ReferenceUrls for each privilege key. Non-catalogued keys (e.g.,
    'Entra:Other:<RoleName>') render with a neutral "Not in privilege
    catalog" note rather than failing.

.LINK
    Catalog: Modules/EntraChecks-PrivilegeCatalog.psm1
    Correlator: Modules/EntraChecks-PrivilegedIdentityCorrelator.psm1
    Plan: plans/Privileged-Identity-Roster-Plan.md (PR 5)
#>

#Requires -Version 5.1

$script:ModulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $script:ModulePath 'EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking

$script:ModuleVersion = '1.0.0'
$script:ModuleName = 'EntraChecks-PrivilegedIdentityRender'

#region ==================== PRIVATE HELPERS ====================

function ConvertTo-HtmlSafe {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Format-TierLabel {
    param([object]$Tier)
    if ($Tier -is [int]) { return "Tier $Tier" }
    if ($Tier) { return [string]$Tier }
    return 'Unknown'
}

function Get-TierBadgeClass {
    param([object]$Tier)
    if ($Tier -is [int]) {
        switch ($Tier) {
            0 { return 'pi-tier pi-tier-0' }
            1 { return 'pi-tier pi-tier-1' }
            2 { return 'pi-tier pi-tier-2' }
        }
    }
    return 'pi-tier pi-tier-other'
}

function Get-PrivilegeSurfaceLabel {
    param([string]$Key)
    if ($Key -match '^([^:]+):') { return $Matches[1] }
    return 'Unknown'
}

function Get-PrivilegeDisplayName {
    param([string]$Key, [hashtable]$Catalog)
    if ($Catalog.ContainsKey($Key)) { return $Catalog[$Key].DisplayName }
    if ($Key -like 'Entra:Other:*') { return ($Key -replace '^Entra:Other:', '') + ' (uncatalogued)' }
    return $Key
}

function Get-RosterFromInput {
    <#
    .SYNOPSIS
        Accept either the full output of Merge-PrivilegedIdentityRosters
        (a hashtable with UnifiedRoster) or a bare roster array. Normalises
        to an array of rows.
    #>
    param([object]$Source)
    if ($null -eq $Source) { return @() }
    if ($Source -is [hashtable] -and $Source.ContainsKey('UnifiedRoster')) {
        return @($Source.UnifiedRoster)
    }
    return @($Source)
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-PrivilegedIdentityRosterCss {
    <#
    .SYNOPSIS
        Returns the CSS block for the Privileged Identity Roster section.
        Uses the 'pi-' prefix to avoid collisions with existing report styles.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param()

    @"
        /* Privileged Identity Roster — PR 5 */
        .pi-section { margin-bottom: 30px; }
        .pi-intro {
            color: var(--gray-600, #605e5c);
            margin-bottom: 18px;
            font-size: 0.92rem;
        }
        .pi-stats {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .pi-stat {
            background: white;
            border-radius: 6px;
            padding: 10px 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            font-size: 0.85rem;
        }
        .pi-stat strong {
            display: block;
            font-size: 1.4rem;
            color: var(--primary, #0078d4);
        }
        .pi-stat.pi-stat-critical strong { color: var(--danger, #d13438); }
        .pi-stat.pi-stat-cross strong    { color: var(--purple, #5c2d91); }
        .pi-grid {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .pi-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            overflow: hidden;
            border-left: 4px solid var(--gray-200, #e1dfdd);
            scroll-margin-top: 16px;
        }
        .pi-card.pi-tier-card-0 { border-left-color: var(--danger, #d13438); }
        .pi-card.pi-tier-card-1 { border-left-color: var(--warning, #ff8c00); }
        .pi-card.pi-tier-card-2 { border-left-color: var(--primary, #0078d4); }
        .pi-card > summary {
            padding: 12px 18px;
            cursor: pointer;
            list-style: none;
            display: grid;
            grid-template-columns: 80px 90px 1fr 130px 22px;
            gap: 14px;
            align-items: center;
            font-size: 0.9rem;
            user-select: none;
        }
        .pi-card > summary::-webkit-details-marker { display: none; }
        .pi-card > summary::marker { display: none; }
        .pi-card > summary:hover { background: var(--gray-100, #f3f2f1); }
        .pi-card[open] > summary { border-bottom: 1px solid var(--gray-200, #e1dfdd); }
        .pi-card > summary .pi-caret {
            text-align: right;
            color: var(--gray-600, #605e5c);
            transition: transform 0.15s ease-in-out;
        }
        .pi-card[open] > summary .pi-caret { transform: rotate(180deg); }
        .pi-tier {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            text-align: center;
            min-width: 60px;
        }
        .pi-tier-0     { background: #fde7e9; color: var(--danger, #d13438); }
        .pi-tier-1     { background: #fff4ce; color: var(--warning, #ff8c00); }
        .pi-tier-2     { background: #deecf9; color: var(--primary, #0078d4); }
        .pi-tier-other { background: var(--gray-200, #e1dfdd); color: var(--gray-600, #605e5c); }
        .pi-cross-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
            background: var(--purple, #5c2d91);
            color: white;
            text-transform: uppercase;
        }
        .pi-cross-badge.pi-cross-empty {
            background: transparent;
            color: transparent;
        }
        .pi-name {
            font-weight: 600;
        }
        .pi-name small {
            display: block;
            font-weight: 400;
            color: var(--gray-600, #605e5c);
            font-size: 0.78rem;
        }
        .pi-priv-count {
            color: var(--gray-600, #605e5c);
            font-size: 0.82rem;
            text-align: right;
        }
        .pi-card-body {
            padding: 16px 22px 20px;
            font-size: 0.88rem;
        }
        .pi-meta {
            display: grid;
            grid-template-columns: 110px 1fr;
            row-gap: 6px;
            column-gap: 14px;
            margin-bottom: 14px;
            background: var(--gray-100, #f3f2f1);
            border-radius: 4px;
            padding: 12px 14px;
            font-size: 0.85rem;
        }
        .pi-meta dt {
            color: var(--gray-600, #605e5c);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 0.03em;
            padding-top: 2px;
        }
        .pi-meta dd { margin: 0; }
        .pi-meta code {
            background: white;
            padding: 1px 5px;
            border-radius: 3px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.78rem;
        }
        .pi-priv-list { margin-top: 4px; }
        .pi-priv {
            background: white;
            border: 1px solid var(--gray-200, #e1dfdd);
            border-radius: 4px;
            margin-bottom: 6px;
            overflow: hidden;
        }
        .pi-priv > summary {
            padding: 10px 14px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.86rem;
            user-select: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .pi-priv > summary:hover { background: var(--gray-100, #f3f2f1); }
        .pi-priv-tier {
            font-size: 0.7rem;
            padding: 2px 6px;
            border-radius: 3px;
            background: var(--gray-200, #e1dfdd);
            color: var(--gray-800, #323130);
            margin-left: 8px;
        }
        .pi-priv-body {
            padding: 12px 14px;
            border-top: 1px solid var(--gray-200, #e1dfdd);
            font-size: 0.86rem;
        }
        .pi-why { margin-bottom: 10px; }
        .pi-paths {
            margin: 8px 0 8px 20px;
            color: var(--gray-800, #323130);
        }
        .pi-paths li { margin-bottom: 3px; }
        .pi-controls {
            font-size: 0.82rem;
            color: var(--gray-800, #323130);
            margin-top: 8px;
        }
        .pi-ref {
            margin-top: 8px;
            font-size: 0.82rem;
        }
        .pi-ref a { color: var(--primary, #0078d4); text-decoration: none; }
        .pi-ref a:hover { text-decoration: underline; }
        .pi-no-roster {
            background: white;
            padding: 18px;
            border-radius: 6px;
            color: var(--gray-600, #605e5c);
            font-size: 0.9rem;
        }
"@
}

function Get-PrivilegedIdentityDashboardTile {
    <#
    .SYNOPSIS
        Returns an HTML fragment for a dashboard tile that summarises the
        privileged-identity roster (count + Tier 0 + cross-surface). Designed
        to drop into the unified report's existing meta-grid.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$RosterInput)

    $rows = Get-RosterFromInput -Source $RosterInput
    if (@($rows).Count -eq 0) { return '' }

    $total = @($rows).Count
    $tier0 = @($rows | Where-Object { $_.HighestTier -eq 0 }).Count
    $cross = @($rows | Where-Object { $_.CrossSurface }).Count

    @"
        <a class="ds-tile-link" href="#privileged-identities" title="Jump to Privileged Identity Roster">
        <div class="meta-item">
            <label>Privileged Identities</label>
            <span>$total total &middot; $tier0 Tier 0 &middot; $cross cross-surface &rarr;</span>
        </div>
        </a>
"@
}

function Get-PrivilegedIdentityHtmlSection {
    <#
    .SYNOPSIS
        Returns the full HTML section for the Privileged Identity Roster:
        section title, summary stats, and one expandable card per identity.

    .PARAMETER Input
        Either the full output of Merge-PrivilegedIdentityRosters or a bare
        roster array. The function normalises both shapes.

    .PARAMETER MatchSummary
        Optional pre-computed match-confidence summary (Strong/Probable/Weak/None
        counts). When present it is rendered as an extra stats card. The
        merger's Statistics already carries these, so callers typically pass
        the whole hashtable.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$RosterInput,
        [hashtable]$MatchSummary
    )

    $rows = Get-RosterFromInput -Source $RosterInput

    if (-not $rows -or @($rows).Count -eq 0) {
        return @"
        <h2 class="section-title" id="privileged-identities">Privileged Identity Roster</h2>
        <div class="pi-no-roster">No privileged-identity roster was collected for this report. Run with <code>-EmitPrivilegedRoster</code> on a Windows host with AD RSAT and a connected Microsoft Graph context to populate this section.</div>
"@
    }

    $catalog = Get-PrivilegeCatalog
    $total = @($rows).Count
    $tier0 = @($rows | Where-Object { $_.HighestTier -eq 0 }).Count
    $tier1 = @($rows | Where-Object { $_.HighestTier -eq 1 }).Count
    $tier2 = @($rows | Where-Object { $_.HighestTier -eq 2 }).Count
    $crossSurface = @($rows | Where-Object { $_.CrossSurface }).Count
    $tier0Cross = @($rows | Where-Object { $_.HighestTier -eq 0 -and $_.CrossSurface }).Count

    $strong = if ($MatchSummary -and $MatchSummary.ContainsKey('StrongMatches')) { $MatchSummary.StrongMatches } else { @($rows | Where-Object MatchConfidence -eq 'Strong').Count }
    $probable = if ($MatchSummary -and $MatchSummary.ContainsKey('ProbableMatches')) { $MatchSummary.ProbableMatches } else { @($rows | Where-Object MatchConfidence -eq 'Probable').Count }
    $weak = if ($MatchSummary -and $MatchSummary.ContainsKey('WeakMatches')) { $MatchSummary.WeakMatches } else { @($rows | Where-Object MatchConfidence -eq 'Weak').Count }

    $html = @"
        <h2 class="section-title" id="privileged-identities">Privileged Identity Roster</h2>
        <p class="pi-intro">One row per principal across Active Directory and Entra. Click any card to see every privilege held and a paragraph explaining why each one matters.</p>
        <div class="pi-stats">
            <div class="pi-stat"><strong>$total</strong> identities total</div>
            <div class="pi-stat pi-stat-critical"><strong>$tier0</strong> Tier 0 (critical)</div>
            <div class="pi-stat"><strong>$tier1</strong> Tier 1 · <strong>$tier2</strong> Tier 2</div>
            <div class="pi-stat pi-stat-cross"><strong>$crossSurface</strong> cross-surface ($tier0Cross at Tier 0)</div>
            <div class="pi-stat"><strong>$strong</strong> strong · <strong>$probable</strong> probable · <strong>$weak</strong> weak match</div>
        </div>
        <div class="pi-grid">
"@

    foreach ($row in $rows) {
        $tierClass = Get-TierBadgeClass -Tier $row.HighestTier
        $tierCardClass = if ($row.HighestTier -is [int]) { "pi-tier-card-$($row.HighestTier)" } else { '' }
        $tierLabel = Format-TierLabel -Tier $row.HighestTier

        $crossBadge = if ($row.CrossSurface) {
            '<span class="pi-cross-badge">Cross</span>'
        } else {
            '<span class="pi-cross-badge pi-cross-empty">--</span>'
        }

        $displayName = ConvertTo-HtmlSafe $row.DisplayName
        $canonical = ConvertTo-HtmlSafe $row.CanonicalId
        $privCount = @($row.Privileges).Count

        # Card identity meta
        $adLine = if ($row.AdSid) {
            $sam = ConvertTo-HtmlSafe $row.AdSamAccountName
            $sid = ConvertTo-HtmlSafe $row.AdSid
            $en = if ($row.AdEnabled -eq $false) { ' &middot; <em>Disabled</em>' } elseif ($row.AdEnabled -eq $true) { ' &middot; Enabled' } else { '' }
            $logon = if ($null -ne $row.AdLastLogonDays) { " &middot; Last logon: $($row.AdLastLogonDays)d" } else { '' }
            "<dt>AD</dt><dd><strong>$sam</strong> <code>$sid</code>$en$logon</dd>"
        } else { '' }

        $entraLine = if ($row.EntraObjectId) {
            $upn = ConvertTo-HtmlSafe $row.EntraUpn
            $oid = ConvertTo-HtmlSafe $row.EntraObjectId
            $en = if ($row.EntraEnabled -eq $false) { ' &middot; <em>Disabled</em>' } elseif ($row.EntraEnabled -eq $true) { ' &middot; Enabled' } else { '' }
            $signin = ''
            if ($row.EntraLastSignIn) {
                try {
                    $dt = if ($row.EntraLastSignIn -is [datetime]) { $row.EntraLastSignIn } else { [datetime]::Parse([string]$row.EntraLastSignIn) }
                    $signin = " &middot; Last sign-in: $((Get-Date $dt -Format 'yyyy-MM-dd'))"
                }
                catch { $signin = '' }
            }
            "<dt>Entra</dt><dd><strong>$upn</strong> <code>$oid</code>$en$signin</dd>"
        } else { '' }

        $matchLine = if ($row.MatchConfidence -and $row.MatchConfidence -ne 'None') {
            "<dt>Match</dt><dd>$(ConvertTo-HtmlSafe $row.MatchConfidence) ($(ConvertTo-HtmlSafe $row.MatchedBy))</dd>"
        } elseif ($row.MatchedBy) {
            "<dt>Source</dt><dd>$(ConvertTo-HtmlSafe $row.MatchedBy)</dd>"
        } else { '' }

        $controlsLine = ''
        $controlBits = @()
        if ($row.InProtectedUsers -eq $true) { $controlBits += 'Protected Users' }
        if ($row.SmartCardRequired -eq $true) { $controlBits += 'Smart card required' }
        if ($controlBits.Count -gt 0) {
            $controlsLine = "<dt>Controls</dt><dd>$(($controlBits | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join ' &middot; ')</dd>"
        }

        # Per-privilege flyouts
        $privsHtml = ''
        foreach ($p in @($row.Privileges)) {
            $key = $p.Key
            $surface = Get-PrivilegeSurfaceLabel -Key $key
            $privDisplay = Get-PrivilegeDisplayName -Key $key -Catalog $catalog
            $privDisplaySafe = ConvertTo-HtmlSafe $privDisplay
            $assignSafe = ConvertTo-HtmlSafe $p.AssignmentType

            $catalogEntry = if ($catalog.ContainsKey($key)) { $catalog[$key] } else { $null }
            $privTier = if ($catalogEntry) { $catalogEntry.Tier } else { 'Uncatalogued' }
            $privTierLabel = Format-TierLabel -Tier $privTier

            $whyHtml = if ($catalogEntry -and $catalogEntry.WhyPrivileged) {
                "<p class='pi-why'>$(ConvertTo-HtmlSafe $catalogEntry.WhyPrivileged)</p>"
            } elseif ($key -like 'Entra:Other:*') {
                '<p class="pi-why"><em>This role is not in the curated privilege catalog. Assignment is reported for completeness; review whether the role should be added to the catalog with a tier classification and remediation guidance.</em></p>'
            } else { '' }

            $pathsHtml = ''
            if ($catalogEntry -and $catalogEntry.AttackPaths -and @($catalogEntry.AttackPaths).Count -gt 0) {
                $pathsHtml = '<strong>Attack paths:</strong><ul class="pi-paths">'
                foreach ($ap in @($catalogEntry.AttackPaths)) {
                    $pathsHtml += "<li>$(ConvertTo-HtmlSafe $ap)</li>"
                }
                $pathsHtml += '</ul>'
            }

            $controlsHtml = ''
            if ($catalogEntry -and $catalogEntry.ExpectedControls -and @($catalogEntry.ExpectedControls).Count -gt 0) {
                $controlsList = (@($catalogEntry.ExpectedControls) | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join ' &middot; '
                $controlsHtml = "<p class='pi-controls'><strong>Expected controls:</strong> $controlsList</p>"
            }

            $refHtml = ''
            if ($catalogEntry -and $catalogEntry.ReferenceUrl) {
                $url = ConvertTo-HtmlSafe $catalogEntry.ReferenceUrl
                $refHtml = "<p class='pi-ref'><a href='$url' target='_blank' rel='noopener'>$url &rarr;</a></p>"
            }

            $assignmentPath = if ($p.Path -and @($p.Path).Count -gt 0) {
                ConvertTo-HtmlSafe ((@($p.Path)) -join ' -> ')
            } else { '' }

            $assignmentLine = if ($assignmentPath) {
                "<p style='font-size: 0.82rem; color: var(--gray-600, #605e5c); margin-bottom: 8px;'><strong>Assignment:</strong> $assignSafe &middot; $assignmentPath</p>"
            } else {
                "<p style='font-size: 0.82rem; color: var(--gray-600, #605e5c); margin-bottom: 8px;'><strong>Assignment:</strong> $assignSafe</p>"
            }

            $privsHtml += @"
            <details class="pi-priv">
                <summary>
                    <span>$surface &middot; $privDisplaySafe</span>
                    <span class="pi-priv-tier">$privTierLabel</span>
                </summary>
                <div class="pi-priv-body">
                    $assignmentLine
                    $whyHtml
                    $pathsHtml
                    $controlsHtml
                    $refHtml
                </div>
            </details>
"@
        }

        $cardId = "pi-card-$($row.CanonicalId -replace '[^A-Za-z0-9]','-')"

        $html += @"
            <details class="pi-card $tierCardClass" id="$cardId" data-tier="$($row.HighestTier)" data-cross-surface="$($row.CrossSurface)">
                <summary>
                    <span class="$tierClass">$tierLabel</span>
                    $crossBadge
                    <span class="pi-name">$displayName <small>$canonical</small></span>
                    <span class="pi-priv-count">$privCount privilege$(if ($privCount -ne 1) {'s'})</span>
                    <span class="pi-caret">&#9660;</span>
                </summary>
                <div class="pi-card-body">
                    <dl class="pi-meta">
                        $adLine
                        $entraLine
                        $matchLine
                        $controlsLine
                    </dl>
                    <h4 style="margin: 8px 0 6px 0; font-size: 0.92rem;">Privileges</h4>
                    <div class="pi-priv-list">
                        $privsHtml
                    </div>
                </div>
            </details>
"@
    }

    $html += @"
        </div>
"@

    return $html
}

function Get-PrivilegedIdentityRows {
    <#
    .SYNOPSIS
        Flattens the unified roster into one row per identity, suitable for
        Excel / CSV export.
    #>
    [OutputType([System.Collections.Generic.List[object]])]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$RosterInput)

    $rows = Get-RosterFromInput -Source $RosterInput
    $catalog = Get-PrivilegeCatalog
    $out = [System.Collections.Generic.List[object]]::new()

    foreach ($r in @($rows)) {
        $privSummary = (@($r.Privileges) | ForEach-Object {
                $surface = Get-PrivilegeSurfaceLabel -Key $_.Key
                $display = Get-PrivilegeDisplayName -Key $_.Key -Catalog $catalog
                "$surface : $display ($($_.AssignmentType))"
            }) -join '; '

        [void]$out.Add([pscustomobject]@{
                CanonicalId = $r.CanonicalId
                DisplayName = $r.DisplayName
                HighestTier = if ($r.HighestTier -is [int]) { $r.HighestTier } else { [string]$r.HighestTier }
                CrossSurface = $r.CrossSurface
                PrincipalType = $r.PrincipalType
                AdSamAccountName = $r.AdSamAccountName
                AdSid = $r.AdSid
                AdEnabled = $r.AdEnabled
                AdLastLogonDays = $r.AdLastLogonDays
                EntraUpn = $r.EntraUpn
                EntraObjectId = $r.EntraObjectId
                EntraEnabled = $r.EntraEnabled
                EntraLastSignIn = $r.EntraLastSignIn
                MatchConfidence = $r.MatchConfidence
                MatchedBy = $r.MatchedBy
                InProtectedUsers = $r.InProtectedUsers
                SmartCardRequired = $r.SmartCardRequired
                PrivilegeCount = @($r.Privileges).Count
                Privileges = $privSummary
                Sources = (@($r.Sources)) -join '; '
            })
    }
    return $out
}

function Get-PrivilegeDetailRows {
    <#
    .SYNOPSIS
        Flattens the unified roster into one row per (identity, privilege)
        pair. Pivot-friendly view that auditors can re-aggregate freely in
        Excel.
    #>
    [OutputType([System.Collections.Generic.List[object]])]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$RosterInput)

    $rows = Get-RosterFromInput -Source $RosterInput
    $catalog = Get-PrivilegeCatalog
    $out = [System.Collections.Generic.List[object]]::new()

    foreach ($r in @($rows)) {
        foreach ($p in @($r.Privileges)) {
            $key = $p.Key
            $surface = Get-PrivilegeSurfaceLabel -Key $key
            $display = Get-PrivilegeDisplayName -Key $key -Catalog $catalog
            $entry = if ($catalog.ContainsKey($key)) { $catalog[$key] } else { $null }
            $tier = if ($entry) { $entry.Tier } else { 'Uncatalogued' }
            $sensitivity = if ($entry) { $entry.Sensitivity } else { '' }
            $why = if ($entry) { $entry.WhyPrivileged } else { '' }
            $attackPaths = if ($entry) { (@($entry.AttackPaths)) -join '; ' } else { '' }
            $controls = if ($entry) { (@($entry.ExpectedControls)) -join '; ' } else { '' }
            $reference = if ($entry) { $entry.ReferenceUrl } else { '' }

            [void]$out.Add([pscustomobject]@{
                    CanonicalId = $r.CanonicalId
                    DisplayName = $r.DisplayName
                    IdentityHighestTier = if ($r.HighestTier -is [int]) { $r.HighestTier } else { [string]$r.HighestTier }
                    CrossSurface = $r.CrossSurface
                    Surface = $surface
                    PrivilegeKey = $key
                    PrivilegeDisplayName = $display
                    PrivilegeTier = if ($tier -is [int]) { $tier } else { [string]$tier }
                    PrivilegeSensitivity = $sensitivity
                    AssignmentType = $p.AssignmentType
                    Path = (@($p.Path)) -join ' -> '
                    DiscoveredAt = $p.DiscoveredAt
                    WhyPrivileged = $why
                    AttackPaths = $attackPaths
                    ExpectedControls = $controls
                    ReferenceUrl = $reference
                })
        }
    }
    return $out
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-PrivilegedIdentityRosterCss',
    'Get-PrivilegedIdentityDashboardTile',
    'Get-PrivilegedIdentityHtmlSection',
    'Get-PrivilegedIdentityRows',
    'Get-PrivilegeDetailRows'
)

#endregion
