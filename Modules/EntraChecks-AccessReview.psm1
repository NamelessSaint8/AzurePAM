<#
.SYNOPSIS
    User Access Review (UAR) campaign module — roster generation and
    campaign open (PR 1 of the Access Review plan).

.DESCRIPTION
    Produces the system-generated evidence a SOC 2 / PCI DSS assessor asks
    for in a periodic access review:

      * a point-in-time roster of ALL users with their directory-role
        assignments (administrators explicitly tagged, sourced from the
        privileged identity roster),
      * a pre-seeded review worksheet the reviewer completes in Excel
        (per-row Decision/Notes + sign-off footer rows),
      * campaign metadata proving system generation (tenant, UTC timestamp,
        tool version, authenticated Graph principal),
      * a SHA-256 manifest over every artifact for tamper evidence.

    Campaign folders live under Output/AccessReview/<CampaignId>/ where
    CampaignId = <PeriodLabel>-<yyyyMMdd-HHmmss> (e.g. 2026-Q3-20260803-141500).

    Worksheet scope rule: enabled members, enabled guests (unless
    -IncludeGuests:$false), and EVERY privileged principal regardless of
    enabled state or principal type — a disabled account that still holds
    Global Administrator is still an access right someone must certify,
    and privileged service principals require a decision (PCI DSS 7.2.5.1).
    Disabled non-privileged users appear in the roster artifacts only.

    Campaign close (Complete-AccessReviewCampaign) ingests the completed
    worksheet, re-pulls the tenant, computes the baseline->final delta, and
    runs the verification pass: Revoke/Modify decisions without a matching
    change are flagged NOT_REMEDIATED; changes without a driving decision
    are flagged UNEXPLAINED_CHANGE. The HTML report and menu wiring ship
    in PR 3.

.NOTES
    Maps to SOC 2 TSC CC6.1-CC6.3 and PCI DSS v4.0 7.2.4 / 7.2.5.1.
    Read-only against the tenant: this module never modifies configuration.
#>

#Requires -Version 5.1

#region ==================== MODULE VARIABLES ====================

$script:ModuleVersion = '1.1.0'  # PR 2: worksheet ingest + campaign close + verification delta
$script:CampaignSchemaVersion = '1.0'

$script:WorksheetHeaders = @(
    'RowType', 'ObjectId', 'UserPrincipalName', 'DisplayName', 'PrincipalType',
    'UserType', 'AccountEnabled', 'IsPrivileged', 'HighestTier', 'Roles',
    'LastSignIn', 'Decision', 'Notes'
)
$script:ValidDecisions = @('Certify', 'Revoke', 'Modify', 'Investigate')
$script:SignOffFields = @('ReviewerName', 'ReviewerTitle', 'SignOffDate')

#endregion

#region ==================== PRIVATE FUNCTIONS ====================

function Test-AccessReviewEnvironment {
    <#
    .SYNOPSIS
        Verifies a Microsoft Graph context exists and captures the
        authenticated principal for the evidence trail.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if (-not (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            IsAvailable = $false
            FailureReason = 'Get-MgContext not available — Microsoft.Graph.Authentication is not loaded.'
        }
    }
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        return [pscustomobject]@{
            IsAvailable = $false
            FailureReason = 'No Microsoft Graph context. Run Connect-MgGraph -Scopes Directory.Read.All,RoleManagement.Read.Directory before opening a campaign.'
        }
    }
    return [pscustomobject]@{
        IsAvailable = $true
        FailureReason = $null
        TenantId = $ctx.TenantId
        Account = $ctx.Account
        AuthType = $ctx.AuthType
        Scopes = @($ctx.Scopes)
    }
}

function Invoke-AccessReviewGraphPaged {
    <#
    .SYNOPSIS
        Follows @odata.nextLink pagination on a Graph collection URI and
        returns the accumulated value entries.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][string]$Uri
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        foreach ($item in @($page.value)) { $results.Add($item) | Out-Null }
        $next = $page.'@odata.nextLink'
    }
    return , $results.ToArray()
}

function Get-AccessReviewQuarterLabel {
    <#
    .SYNOPSIS
        Default period label for a campaign: the current calendar quarter
        (quarterly cadence — the stricter of the SOC 2 convention and the
        PCI DSS 7.2.4 semi-annual floor).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [datetime]$Date = (Get-Date)
    )
    $quarter = [math]::Ceiling($Date.Month / 3.0)
    return ('{0}-Q{1}' -f $Date.Year, $quarter)
}

function Format-AccessReviewTier {
    <#
    .SYNOPSIS
        Renders a roster HighestTier value ('0', 'Unclassified', 'Service')
        as a display label.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Tier)
    if ($null -eq $Tier) { return '' }
    if ($Tier -is [int]) { return "Tier $Tier" }
    return [string]$Tier
}

function Get-AccessReviewPrivilegeSummary {
    <#
    .SYNOPSIS
        Flattens a privileged-roster row's Privileges[] into one
        human-readable, semicolon-joined string for CSV cells.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param($RosterRow)

    $parts = foreach ($p in @($RosterRow.Privileges)) {
        $label = if (@($p.Path).Count -gt 0) { @($p.Path)[0] } else { [string]$p.Key }
        $label
    }
    return (@($parts) -join '; ')
}

function Resolve-AccessReviewEntraRoster {
    <#
    .SYNOPSIS
        Returns the supplied privileged roster, or builds one by importing
        the sibling privileged-identity modules. Never throws — returns an
        Available=$false hashtable on failure so callers can fail closed.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [hashtable]$EntraRoster
    )

    if ($EntraRoster) { return $EntraRoster }
    if (-not (Get-Command -Name Get-PrivilegedIdentityRosterEntra -ErrorAction SilentlyContinue)) {
        try {
            Import-Module (Join-Path $PSScriptRoot 'EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking -ErrorAction Stop
            Import-Module (Join-Path $PSScriptRoot 'EntraChecks-PrivilegedIdentityEntra.psm1') -Force -DisableNameChecking -ErrorAction Stop
        }
        catch {
            return @{
                Available = $false
                FailureReason = "Privileged identity modules could not be loaded: $($_.Exception.Message)"
                Roster = @()
            }
        }
    }
    return Get-PrivilegedIdentityRosterEntra
}

function Build-AccessReviewUserRows {
    <#
    .SYNOPSIS
        Joins raw user rows with the privileged roster: every user row gets
        IsPrivileged / HighestTier / Roles columns. Shared by campaign open
        (baseline) and campaign close (final).
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Users,
        [Parameter(Mandatory)][hashtable]$EntraRoster
    )

    $privByObjectId = @{}
    foreach ($row in @($EntraRoster.Roster)) {
        $privByObjectId[[string]$row.ObjectId] = $row
    }

    $rows = foreach ($u in $Users) {
        $priv = $privByObjectId[[string]$u.ObjectId]
        [pscustomobject]@{
            ObjectId = $u.ObjectId
            UserPrincipalName = $u.UserPrincipalName
            DisplayName = $u.DisplayName
            PrincipalType = 'User'
            UserType = $u.UserType
            AccountEnabled = $u.AccountEnabled
            CreatedDateTime = $u.CreatedDateTime
            LastSignIn = $u.LastSignIn
            IsPrivileged = [bool]$priv
            HighestTier = if ($priv) { Format-AccessReviewTier -Tier $priv.HighestTier } else { '' }
            Roles = if ($priv) { Get-AccessReviewPrivilegeSummary -RosterRow $priv } else { '' }
        }
    }
    return , @($rows)
}

function ConvertTo-AccessReviewAdminCsvRows {
    <#
    .SYNOPSIS
        Flattens privileged-roster rows into the admins CSV shape.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][hashtable]$EntraRoster
    )

    $rows = foreach ($row in @($EntraRoster.Roster)) {
        [pscustomobject]@{
            ObjectId = [string]$row.ObjectId
            DisplayName = [string]$row.DisplayName
            UserPrincipalName = if ($row.Upn) { [string]$row.Upn } else { '' }
            PrincipalType = [string]$row.PrincipalType
            AccountEnabled = $row.Enabled
            HighestTier = Format-AccessReviewTier -Tier $row.HighestTier
            PrivilegeCount = @($row.Privileges).Count
            Privileges = Get-AccessReviewPrivilegeSummary -RosterRow $row
            Sources = (@($row.Sources) -join '; ')
        }
    }
    return , @($rows)
}

function Import-AccessReviewWorksheet {
    <#
    .SYNOPSIS
        Parses and validates a completed review worksheet. Returns
        Valid/Errors plus normalized access rows and the sign-off block.

    .DESCRIPTION
        Validation is strict and every error is actionable: header schema
        must match the seeded worksheet exactly, access rows must not be
        added, removed, or duplicated, every access row needs a decision
        from the valid set, and all three sign-off fields must be filled
        (SignOffDate must parse as a date).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ExpectedObjectIds,
        [Parameter(Mandatory)][int]$ExpectedAccessRowCount
    )

    $errors = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path -LiteralPath $Path)) {
        return @{ Valid = $false; Errors = @("Worksheet not found: $Path"); AccessRows = @(); SignOff = @{} }
    }
    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -eq 0) {
        return @{ Valid = $false; Errors = @('Worksheet is empty.'); AccessRows = @(); SignOff = @{} }
    }

    $actualHeaders = @($rows[0].PSObject.Properties.Name)
    $missing = @($script:WorksheetHeaders | Where-Object { $_ -notin $actualHeaders })
    $extra = @($actualHeaders | Where-Object { $_ -notin $script:WorksheetHeaders })
    if ($missing.Count -gt 0) { $errors.Add("Missing columns: $($missing -join ', ') — do not remove columns from the seeded worksheet.") | Out-Null }
    if ($extra.Count -gt 0) { $errors.Add("Unexpected columns: $($extra -join ', ') — do not add columns to the seeded worksheet.") | Out-Null }
    if ($errors.Count -gt 0) {
        return @{ Valid = $false; Errors = @($errors.ToArray()); AccessRows = @(); SignOff = @{} }
    }

    $accessRows = @($rows | Where-Object { $_.RowType -eq 'Access' })
    $signOffRows = @($rows | Where-Object { $_.RowType -eq 'SignOff' })
    $unknownRows = @($rows | Where-Object { $_.RowType -notin @('Access', 'SignOff') })
    if ($unknownRows.Count -gt 0) {
        $errors.Add("Rows with unknown RowType found ($($unknownRows.Count)) — only 'Access' and 'SignOff' rows are allowed.") | Out-Null
    }

    if ($accessRows.Count -ne $ExpectedAccessRowCount) {
        $errors.Add("Expected $ExpectedAccessRowCount access rows but found $($accessRows.Count) — rows must not be added or removed; every seeded principal requires a decision.") | Out-Null
    }
    $dupes = @($accessRows | Group-Object ObjectId | Where-Object { $_.Count -gt 1 })
    if ($dupes.Count -gt 0) {
        $errors.Add("Duplicate access rows for: $(($dupes | ForEach-Object Name | Select-Object -First 5) -join ', ')") | Out-Null
    }
    $expectedSet = @{}
    foreach ($id in $ExpectedObjectIds) { $expectedSet[$id] = $true }
    $foreign = @($accessRows | Where-Object { -not $expectedSet.ContainsKey($_.ObjectId) })
    if ($foreign.Count -gt 0) {
        $errors.Add("Access rows reference principals not in the campaign baseline: $(($foreign | ForEach-Object ObjectId | Select-Object -First 5) -join ', ')") | Out-Null
    }

    $normalized = [System.Collections.Generic.List[object]]::new()
    $undecided = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $accessRows) {
        $decision = ([string]$r.Decision).Trim()
        if (-not $decision) {
            $undecided.Add($(if ($r.UserPrincipalName) { $r.UserPrincipalName } else { $r.ObjectId })) | Out-Null
            continue
        }
        $canonical = $script:ValidDecisions | Where-Object { $_ -eq $decision } | Select-Object -First 1
        if (-not $canonical) {
            $errors.Add("Invalid decision '$decision' for $($r.UserPrincipalName) — valid values: $($script:ValidDecisions -join ', ').") | Out-Null
            continue
        }
        $normalized.Add([pscustomobject]@{
                ObjectId = $r.ObjectId
                UserPrincipalName = $r.UserPrincipalName
                DisplayName = $r.DisplayName
                PrincipalType = $r.PrincipalType
                IsPrivileged = $r.IsPrivileged
                Decision = $canonical
                Notes = $r.Notes
            }) | Out-Null
    }
    if ($undecided.Count -gt 0) {
        $shown = ($undecided | Select-Object -First 10) -join ', '
        $errors.Add("$($undecided.Count) access row(s) have no decision: $shown — every principal must be decided before the campaign can close.") | Out-Null
    }

    $signOff = @{}
    foreach ($field in $script:SignOffFields) {
        $row = $signOffRows | Where-Object { $_.ObjectId -eq $field } | Select-Object -First 1
        $value = if ($row) { ([string]$row.Notes).Trim() } else { '' }
        if (-not $value) {
            $errors.Add("Sign-off field '$field' is empty — fill the Notes column of the $field row.") | Out-Null
        }
        $signOff[$field] = $value
    }
    if ($signOff['SignOffDate']) {
        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParse($signOff['SignOffDate'], [ref]$parsed)) {
            $errors.Add("Sign-off date '$($signOff['SignOffDate'])' is not a recognizable date (use YYYY-MM-DD).") | Out-Null
        }
    }

    return @{
        Valid = ($errors.Count -eq 0)
        Errors = @($errors.ToArray())
        AccessRows = @($normalized.ToArray())
        SignOff = $signOff
    }
}

function Compare-AccessReviewRosters {
    <#
    .SYNOPSIS
        Computes the baseline -> final delta: account-state changes from the
        user rosters, privilege changes from the admins rosters.

    .NOTES
        Privileges are compared by catalog Key only — a PIM-eligible ->
        active transition of the same role is not treated as a change.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$BaselineUsers,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FinalUsers,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$BaselineAdmins,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FinalAdmins
    )

    $delta = [System.Collections.Generic.List[object]]::new()
    function Add-DeltaRow {
        param($List, $ObjectId, $DisplayName, $UserPrincipalName, $ChangeType, $Detail)
        $List.Add([pscustomobject]@{
                ObjectId = [string]$ObjectId
                DisplayName = [string]$DisplayName
                UserPrincipalName = [string]$UserPrincipalName
                ChangeType = $ChangeType
                Detail = $Detail
            }) | Out-Null
    }

    $bUsers = @{}
    foreach ($u in $BaselineUsers) { $bUsers[[string]$u.ObjectId] = $u }
    $fUsers = @{}
    foreach ($u in $FinalUsers) { $fUsers[[string]$u.ObjectId] = $u }

    foreach ($id in $bUsers.Keys) {
        $b = $bUsers[$id]
        if (-not $fUsers.ContainsKey($id)) {
            Add-DeltaRow $delta $id $b.DisplayName $b.UserPrincipalName 'AccountRemoved' 'Account no longer exists in the tenant'
            continue
        }
        $f = $fUsers[$id]
        if ([bool]$b.AccountEnabled -and -not [bool]$f.AccountEnabled) {
            Add-DeltaRow $delta $id $b.DisplayName $b.UserPrincipalName 'AccountDisabled' 'Account was disabled'
        }
        elseif (-not [bool]$b.AccountEnabled -and [bool]$f.AccountEnabled) {
            Add-DeltaRow $delta $id $b.DisplayName $b.UserPrincipalName 'AccountEnabled' 'Account was re-enabled'
        }
    }
    foreach ($id in $fUsers.Keys) {
        if (-not $bUsers.ContainsKey($id)) {
            $f = $fUsers[$id]
            Add-DeltaRow $delta $id $f.DisplayName $f.UserPrincipalName 'AccountAdded' 'Account created during the review window'
        }
    }

    $bAdmins = @{}
    foreach ($a in $BaselineAdmins) { $bAdmins[[string]$a.ObjectId] = $a }
    $fAdmins = @{}
    foreach ($a in $FinalAdmins) { $fAdmins[[string]$a.ObjectId] = $a }

    $allAdminIds = @($bAdmins.Keys) + @($fAdmins.Keys | Where-Object { -not $bAdmins.ContainsKey($_) })
    foreach ($id in $allAdminIds) {
        $b = $bAdmins[$id]
        $f = $fAdmins[$id]
        $bPrivs = if ($b) { @($b.Privileges) } else { @() }
        $fPrivs = if ($f) { @($f.Privileges) } else { @() }
        $bKeys = @($bPrivs | ForEach-Object { [string]$_.Key } | Select-Object -Unique)
        $fKeys = @($fPrivs | ForEach-Object { [string]$_.Key } | Select-Object -Unique)
        $name = if ($b) { $b.DisplayName } else { $f.DisplayName }
        $upn = if ($b -and $b.Upn) { $b.Upn } elseif ($f -and $f.Upn) { $f.Upn } else { '' }

        foreach ($key in $bKeys) {
            if ($key -notin $fKeys) {
                $priv = $bPrivs | Where-Object { [string]$_.Key -eq $key } | Select-Object -First 1
                $detail = if (@($priv.Path).Count -gt 0) { [string]@($priv.Path)[0] } else { $key }
                Add-DeltaRow $delta $id $name $upn 'PrivilegeRemoved' $detail
            }
        }
        foreach ($key in $fKeys) {
            if ($key -notin $bKeys) {
                $priv = $fPrivs | Where-Object { [string]$_.Key -eq $key } | Select-Object -First 1
                $detail = if (@($priv.Path).Count -gt 0) { [string]@($priv.Path)[0] } else { $key }
                Add-DeltaRow $delta $id $name $upn 'PrivilegeAdded' $detail
            }
        }

        # Enabled flips for roster principals outside the user rosters (SPs)
        if ($b -and $f -and -not $bUsers.ContainsKey($id) -and -not $fUsers.ContainsKey($id)) {
            if ([bool]$b.Enabled -and -not [bool]$f.Enabled) {
                Add-DeltaRow $delta $id $name $upn 'AccountDisabled' 'Principal was disabled'
            }
            elseif (-not [bool]$b.Enabled -and [bool]$f.Enabled) {
                Add-DeltaRow $delta $id $name $upn 'AccountEnabled' 'Principal was re-enabled'
            }
        }
    }

    return , @($delta.ToArray())
}

function Get-AccessReviewVerification {
    <#
    .SYNOPSIS
        The verification pass: joins reviewer decisions with the observed
        delta. Revoke/Modify without a matching remediating change ->
        NOT_REMEDIATED. Changes on principals that were certified (or never
        seeded) -> UNEXPLAINED_CHANGE. Investigate tolerates changes.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$AccessRows,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Delta
    )

    $remediatingTypes = @('PrivilegeRemoved', 'AccountDisabled', 'AccountRemoved')

    $deltaByOid = @{}
    foreach ($d in $Delta) {
        if (-not $deltaByOid.ContainsKey($d.ObjectId)) { $deltaByOid[$d.ObjectId] = [System.Collections.Generic.List[object]]::new() }
        $deltaByOid[$d.ObjectId].Add($d) | Out-Null
    }

    $decisions = [System.Collections.Generic.List[object]]::new()
    $flags = [System.Collections.Generic.List[object]]::new()
    $decidedOids = @{}

    foreach ($row in $AccessRows) {
        $decidedOids[[string]$row.ObjectId] = $true
        $changes = if ($deltaByOid.ContainsKey($row.ObjectId)) { @($deltaByOid[$row.ObjectId]) } else { @() }
        $changeSummary = (@($changes | ForEach-Object { "$($_.ChangeType): $($_.Detail)" }) -join '; ')

        $verdict = switch ($row.Decision) {
            'Certify' {
                if ($changes.Count -gt 0) { 'UnexplainedChange' } else { 'Certified' }
            }
            'Investigate' { 'Investigated' }
            default {
                # Revoke / Modify expect a remediating change
                $remediated = @($changes | Where-Object { $_.ChangeType -in $remediatingTypes }).Count -gt 0
                if ($remediated) { 'Remediated' } else { 'NotRemediated' }
            }
        }

        if ($verdict -eq 'NotRemediated') {
            $flags.Add([pscustomobject]@{
                    ObjectId = $row.ObjectId
                    DisplayName = $row.DisplayName
                    UserPrincipalName = $row.UserPrincipalName
                    Flag = 'NOT_REMEDIATED'
                    Detail = "Decision '$($row.Decision)' recorded but no removal, disable, or deletion was observed for this principal."
                }) | Out-Null
        }
        elseif ($verdict -eq 'UnexplainedChange') {
            $flags.Add([pscustomobject]@{
                    ObjectId = $row.ObjectId
                    DisplayName = $row.DisplayName
                    UserPrincipalName = $row.UserPrincipalName
                    Flag = 'UNEXPLAINED_CHANGE'
                    Detail = "Principal was certified but changed during the review window: $changeSummary"
                }) | Out-Null
        }

        $decisions.Add([pscustomobject]@{
                ObjectId = $row.ObjectId
                UserPrincipalName = $row.UserPrincipalName
                DisplayName = $row.DisplayName
                PrincipalType = $row.PrincipalType
                IsPrivileged = $row.IsPrivileged
                Decision = $row.Decision
                Notes = $row.Notes
                Verdict = $verdict
                ObservedChanges = $changeSummary
            }) | Out-Null
    }

    # Changes on principals that never had a worksheet row (created or
    # privileged mid-window) have no driving decision by definition.
    foreach ($oid in $deltaByOid.Keys) {
        if ($decidedOids.ContainsKey($oid)) { continue }
        $changes = @($deltaByOid[$oid])
        $first = $changes[0]
        $flags.Add([pscustomobject]@{
                ObjectId = $oid
                DisplayName = $first.DisplayName
                UserPrincipalName = $first.UserPrincipalName
                Flag = 'UNEXPLAINED_CHANGE'
                Detail = "Change with no review decision: $((@($changes | ForEach-Object { "$($_.ChangeType): $($_.Detail)" }) -join '; '))"
            }) | Out-Null
    }

    $summary = [ordered]@{
        Certified = @($decisions | Where-Object { $_.Decision -eq 'Certify' }).Count
        Revoked = @($decisions | Where-Object { $_.Decision -eq 'Revoke' }).Count
        Modified = @($decisions | Where-Object { $_.Decision -eq 'Modify' }).Count
        Investigated = @($decisions | Where-Object { $_.Decision -eq 'Investigate' }).Count
        Remediated = @($decisions | Where-Object { $_.Verdict -eq 'Remediated' }).Count
        NotRemediated = @($flags | Where-Object { $_.Flag -eq 'NOT_REMEDIATED' }).Count
        UnexplainedChanges = @($flags | Where-Object { $_.Flag -eq 'UNEXPLAINED_CHANGE' }).Count
        TotalChanges = @($Delta).Count
    }

    return @{
        Decisions = @($decisions.ToArray())
        Flags = @($flags.ToArray())
        Summary = $summary
    }
}

function New-AccessReviewManifest {
    <#
    .SYNOPSIS
        Hashes every artifact in a campaign folder and writes manifest.json
        with per-file SHA-256 entries plus a rolling bundle hash. Same hash
        chain construction as the SOC 2 evidence bundle.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$CampaignDirectory,
        [Parameter(Mandatory)][string[]]$FilePaths,
        [Parameter(Mandatory)][string]$CampaignId,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$TenantName = ''
    )

    $hashEntries = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($f in ($FilePaths | Sort-Object)) {
        $hash = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower()
        $relative = $f.Substring($CampaignDirectory.Length).TrimStart('\', '/')
        $entry = @{}
        $entry['RelativePath'] = $relative
        $entry['SHA256'] = $hash
        $hashEntries.Add($entry) | Out-Null
    }

    $concatSource = ($hashEntries | ForEach-Object { "$($_.RelativePath)|$($_.SHA256)" }) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bundleHashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concatSource))
    } finally {
        $sha.Dispose()
    }
    $bundleHash = -join ($bundleHashBytes | ForEach-Object { $_.ToString('x2') })

    $manifest = [ordered]@{
        SchemaVersion = $script:CampaignSchemaVersion
        GeneratedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        EntraChecksVersion = $script:ModuleVersion
        CampaignId = $CampaignId
        TenantId = $TenantId
        TenantName = $TenantName
        HashAlgorithm = 'SHA256'
        BundleHash = $bundleHash
        Files = $hashEntries
    }

    $manifestPath = Join-Path $CampaignDirectory 'manifest.json'
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    return [pscustomobject]@{
        ManifestPath = $manifestPath
        BundleHash = $bundleHash
        FileCount = $hashEntries.Count
    }
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-AccessReviewRoster {
    <#
    .SYNOPSIS
        Pulls every user in the tenant (members, guests, enabled and
        disabled) with the fields the access-review roster needs.

    .DESCRIPTION
        Tries the beta endpoint first to capture signInActivity (requires
        Entra ID P1 + AuditLog.Read.All); on failure falls back to v1.0
        without sign-in data and reports SignInDataAvailable=$false.

    .OUTPUTS
        Hashtable: Available, FailureReason, SignInDataAvailable, Users[].
        Each user row: ObjectId, UserPrincipalName, DisplayName, UserType,
        AccountEnabled, CreatedDateTime, LastSignIn (ISO-8601 or '').
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $betaUri = 'https://graph.microsoft.com/beta/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity&$top=999'
    $v1Uri = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime&$top=999'

    $signInAvailable = $true
    $rawUsers = $null
    try {
        $rawUsers = Invoke-AccessReviewGraphPaged -Uri $betaUri
    }
    catch {
        Write-Verbose "beta users query failed ($($_.Exception.Message)) — falling back to v1.0 without signInActivity."
        $signInAvailable = $false
        try {
            $rawUsers = Invoke-AccessReviewGraphPaged -Uri $v1Uri
        }
        catch {
            return @{
                Available = $false
                FailureReason = "User enumeration failed: $($_.Exception.Message)"
                SignInDataAvailable = $false
                Users = @()
            }
        }
    }

    $rows = foreach ($u in @($rawUsers)) {
        $lastSignIn = ''
        if ($signInAvailable -and $u.signInActivity) {
            if ($u.signInActivity.lastSignInDateTime) {
                $lastSignIn = [string]$u.signInActivity.lastSignInDateTime
            }
            elseif ($u.signInActivity.lastNonInteractiveSignInDateTime) {
                $lastSignIn = [string]$u.signInActivity.lastNonInteractiveSignInDateTime
            }
        }
        @{
            ObjectId = [string]$u.id
            UserPrincipalName = [string]$u.userPrincipalName
            DisplayName = [string]$u.displayName
            UserType = if ($u.userType) { [string]$u.userType } else { 'Member' }
            AccountEnabled = [bool]$u.accountEnabled
            CreatedDateTime = if ($u.createdDateTime) { [string]$u.createdDateTime } else { '' }
            LastSignIn = $lastSignIn
        }
    }

    return @{
        Available = $true
        FailureReason = $null
        SignInDataAvailable = $signInAvailable
        Users = @($rows)
    }
}

function New-AccessReviewCampaign {
    <#
    .SYNOPSIS
        Opens an access-review campaign: generates the system-generated
        roster artifacts, the pre-seeded review worksheet, campaign
        metadata, and the SHA-256 manifest.

    .DESCRIPTION
        Fails closed when the privileged identity roster is unavailable —
        an access review whose worksheet cannot tag administrators does not
        satisfy the assessor requirement that administrators be included.
        Pass a pre-built roster via -EntraRoster (e.g. from an orchestrated
        run) or let the function build one via Get-PrivilegedIdentityRosterEntra.

    .PARAMETER OutputDirectory
        Root folder for campaigns. The campaign gets its own subfolder.

    .PARAMETER PeriodLabel
        Review-period label, e.g. '2026-Q3'. Defaults to the current quarter.

    .PARAMETER TenantName
        Friendly tenant name stamped into the evidence metadata.

    .PARAMETER IncludeGuests
        Seed enabled guest accounts into the review worksheet. Default $true.

    .PARAMETER EntraRoster
        Pre-built privileged roster (output shape of
        Get-PrivilegedIdentityRosterEntra). When omitted, the sibling
        privileged-identity modules are imported and the roster is built here.

    .EXAMPLE
        Connect-MgGraph -Scopes Directory.Read.All,RoleManagement.Read.Directory
        New-AccessReviewCampaign -TenantName Contoso -OutputDirectory .\Output\AccessReview
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$OutputDirectory = '.\Output\AccessReview',
        [string]$PeriodLabel = '',
        [string]$TenantName = '',
        [bool]$IncludeGuests = $true,
        [hashtable]$EntraRoster
    )

    $env = Test-AccessReviewEnvironment
    if (-not $env.IsAvailable) {
        return @{ Success = $false; FailureReason = $env.FailureReason }
    }

    # ----- 1. Collect data (nothing written until every pull succeeds) -----

    $EntraRoster = Resolve-AccessReviewEntraRoster -EntraRoster $EntraRoster
    if (-not $EntraRoster.Available) {
        return @{ Success = $false; FailureReason = "Privileged roster unavailable ($($EntraRoster.FailureReason)) — refusing to open a campaign that cannot tag administrators." }
    }

    $userRoster = Get-AccessReviewRoster
    if (-not $userRoster.Available) {
        return @{ Success = $false; FailureReason = $userRoster.FailureReason }
    }

    # ----- 2. Join: tag users with their privileges -----

    $userRows = Build-AccessReviewUserRows -Users @($userRoster.Users) -EntraRoster $EntraRoster

    # Privileged principals that are not users (service principals, groups)
    # still require a review decision (PCI DSS 7.2.5.1).
    $userIds = @{}
    foreach ($u in $userRows) { $userIds[$u.ObjectId] = $true }
    $nonUserPrivRows = foreach ($row in @($EntraRoster.Roster)) {
        if ($userIds.ContainsKey([string]$row.ObjectId)) { continue }
        [pscustomobject]@{
            ObjectId = [string]$row.ObjectId
            UserPrincipalName = if ($row.Upn) { [string]$row.Upn } else { '' }
            DisplayName = [string]$row.DisplayName
            PrincipalType = [string]$row.PrincipalType
            UserType = ''
            AccountEnabled = $row.Enabled
            CreatedDateTime = ''
            LastSignIn = if ($row.LastSignIn) { [string]$row.LastSignIn } else { '' }
            IsPrivileged = $true
            HighestTier = Format-AccessReviewTier -Tier $row.HighestTier
            Roles = Get-AccessReviewPrivilegeSummary -RosterRow $row
        }
    }
    $nonUserPrivRows = @($nonUserPrivRows)

    # ----- 3. Worksheet scope: enabled members + guests (optional) + all privileged -----

    $worksheetSource = @($userRows | Where-Object {
            $_.IsPrivileged -or
            ($_.AccountEnabled -and ($_.UserType -ne 'Guest' -or $IncludeGuests))
        }) + $nonUserPrivRows

    $worksheetSorted = @($worksheetSource | Sort-Object `
        @{Expression = { if ($_.IsPrivileged) { 0 } else { 1 } } }, `
        @{Expression = { if ($_.HighestTier -match '^Tier (\d+)$') { [int]$Matches[1] } else { 99 } } }, `
        @{Expression = { $_.DisplayName } })

    $worksheetRows = foreach ($r in $worksheetSorted) {
        [pscustomobject]@{
            RowType = 'Access'
            ObjectId = $r.ObjectId
            UserPrincipalName = $r.UserPrincipalName
            DisplayName = $r.DisplayName
            PrincipalType = $r.PrincipalType
            UserType = $r.UserType
            AccountEnabled = $r.AccountEnabled
            IsPrivileged = $r.IsPrivileged
            HighestTier = $r.HighestTier
            Roles = $r.Roles
            LastSignIn = $r.LastSignIn
            Decision = ''
            Notes = ''
        }
    }
    $worksheetRows = @($worksheetRows)

    # Sign-off footer: reviewer fills the Notes column of each SignOff row.
    # Kept inside the worksheet so one SHA-256 covers decisions AND sign-off.
    $signOffRows = foreach ($field in 'ReviewerName', 'ReviewerTitle', 'SignOffDate') {
        [pscustomobject]@{
            RowType = 'SignOff'
            ObjectId = $field
            UserPrincipalName = ''
            DisplayName = ''
            PrincipalType = ''
            UserType = ''
            AccountEnabled = ''
            IsPrivileged = ''
            HighestTier = ''
            Roles = ''
            LastSignIn = ''
            Decision = ''
            Notes = ''
        }
    }

    # ----- 4. Write the campaign folder -----

    if (-not $PeriodLabel) { $PeriodLabel = Get-AccessReviewQuarterLabel }
    $campaignId = '{0}-{1}' -f $PeriodLabel, (Get-Date -Format 'yyyyMMdd-HHmmss')
    $campaignDir = Join-Path $OutputDirectory $campaignId
    $null = New-Item -Path $campaignDir -ItemType Directory -Force

    $written = [System.Collections.Generic.List[string]]::new()

    $rosterJsonPath = Join-Path $campaignDir 'roster-baseline.json'
    @{
        CampaignId = $campaignId
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        TenantId = $env.TenantId
        SignInDataAvailable = $userRoster.SignInDataAvailable
        Users = $userRows
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $rosterJsonPath -Encoding UTF8
    $written.Add($rosterJsonPath) | Out-Null

    $rosterCsvPath = Join-Path $campaignDir 'roster-baseline.csv'
    $userRows | Export-Csv -LiteralPath $rosterCsvPath -NoTypeInformation -Encoding UTF8
    $written.Add($rosterCsvPath) | Out-Null

    $adminsJsonPath = Join-Path $campaignDir 'admins-baseline.json'
    $EntraRoster | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $adminsJsonPath -Encoding UTF8
    $written.Add($adminsJsonPath) | Out-Null

    $adminsCsvPath = Join-Path $campaignDir 'admins-baseline.csv'
    (ConvertTo-AccessReviewAdminCsvRows -EntraRoster $EntraRoster) |
        Export-Csv -LiteralPath $adminsCsvPath -NoTypeInformation -Encoding UTF8
    $written.Add($adminsCsvPath) | Out-Null

    $worksheetPath = Join-Path $campaignDir 'review-worksheet.csv'
    ($worksheetRows + $signOffRows) | Export-Csv -LiteralPath $worksheetPath -NoTypeInformation -Encoding UTF8
    $written.Add($worksheetPath) | Out-Null

    $enabledMembers = @($userRows | Where-Object { $_.AccountEnabled -and $_.UserType -ne 'Guest' }).Count
    $guests = @($userRows | Where-Object { $_.UserType -eq 'Guest' }).Count
    $disabled = @($userRows | Where-Object { -not $_.AccountEnabled }).Count

    $campaignJsonPath = Join-Path $campaignDir 'campaign.json'
    $campaignMeta = [ordered]@{
        SchemaVersion = $script:CampaignSchemaVersion
        CampaignId = $campaignId
        PeriodLabel = $PeriodLabel
        Status = 'Open'
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        TenantId = $env.TenantId
        TenantName = $TenantName
        EntraChecksVersion = $script:ModuleVersion
        RunId = [guid]::NewGuid().ToString()
        GeneratedBy = [ordered]@{
            Account = $env.Account
            AuthType = $env.AuthType
            Scopes = @($env.Scopes)
        }
        Scope = [ordered]@{
            IncludeGuests = $IncludeGuests
            WorksheetIncludesDisabledNonPrivileged = $false
            PrivilegedSource = 'Get-PrivilegedIdentityRosterEntra'
        }
        SignInDataAvailable = $userRoster.SignInDataAvailable
        Counts = [ordered]@{
            TotalUsers = $userRows.Count
            EnabledMembers = $enabledMembers
            Guests = $guests
            DisabledUsers = $disabled
            PrivilegedPrincipals = @($EntraRoster.Roster).Count
            WorksheetAccessRows = $worksheetRows.Count
        }
    }
    $campaignMeta | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $campaignJsonPath -Encoding UTF8
    $written.Add($campaignJsonPath) | Out-Null

    # ----- 5. Manifest over everything written -----

    $manifest = New-AccessReviewManifest `
        -CampaignDirectory $campaignDir `
        -FilePaths $written.ToArray() `
        -CampaignId $campaignId `
        -TenantId $env.TenantId `
        -TenantName $TenantName

    return @{
        Success = $true
        FailureReason = $null
        CampaignId = $campaignId
        Directory = $campaignDir
        WorksheetPath = $worksheetPath
        ManifestPath = $manifest.ManifestPath
        BundleHash = $manifest.BundleHash
        Counts = $campaignMeta.Counts
    }
}

function Complete-AccessReviewCampaign {
    <#
    .SYNOPSIS
        Closes an access-review campaign: ingests the completed worksheet,
        re-pulls the tenant, computes the baseline->final delta, runs the
        verification pass, and refreshes the evidence manifest.

    .DESCRIPTION
        Fails without writing anything when the worksheet is incomplete
        (missing decisions, tampered rows, absent sign-off) — a partially
        reviewed campaign stays Open. On success the campaign folder gains
        roster-final / admins-final (JSON+CSV) and verification.json,
        campaign.json flips to Status=Closed with the embedded sign-off,
        and manifest.json is regenerated over every artifact including the
        completed worksheet — the reviewer's decisions and sign-off are
        covered by the same hash chain as the system-generated data.

        Verification verdicts:
          * Revoke/Modify with an observed privilege removal, disable, or
            deletion -> Remediated; without one -> NOT_REMEDIATED flag.
          * Certify with any observed change -> UNEXPLAINED_CHANGE flag.
          * Changes on principals with no worksheet row -> UNEXPLAINED_CHANGE.
          * Investigate tolerates changes (investigation outcomes vary).

    .PARAMETER CampaignDirectory
        The campaign folder created by New-AccessReviewCampaign.

    .PARAMETER EntraRoster
        Pre-built privileged roster for the FINAL state (output shape of
        Get-PrivilegedIdentityRosterEntra). Built here when omitted.

    .EXAMPLE
        Complete-AccessReviewCampaign -CampaignDirectory .\Output\AccessReview\2026-Q3-20260803-141500
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$CampaignDirectory,
        [hashtable]$EntraRoster
    )

    # ----- 1. Load and gate the campaign -----

    $metaPath = Join-Path $CampaignDirectory 'campaign.json'
    if (-not (Test-Path -LiteralPath $metaPath)) {
        return @{ Success = $false; FailureReason = "Not a campaign folder (campaign.json missing): $CampaignDirectory" }
    }
    $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
    if ($meta.Status -ne 'Open') {
        return @{ Success = $false; FailureReason = "Campaign $($meta.CampaignId) has status '$($meta.Status)' — only Open campaigns can be closed." }
    }

    $baselinePayload = Get-Content -LiteralPath (Join-Path $CampaignDirectory 'roster-baseline.json') -Raw | ConvertFrom-Json
    $baselineAdmins = Get-Content -LiteralPath (Join-Path $CampaignDirectory 'admins-baseline.json') -Raw | ConvertFrom-Json

    # ----- 2. Worksheet ingest + validation (cheap, before any Graph call) -----

    $expectedIds = @(
        @($baselinePayload.Users) | ForEach-Object { [string]$_.ObjectId }
        @($baselineAdmins.Roster) | ForEach-Object { [string]$_.ObjectId }
    )
    $worksheet = Import-AccessReviewWorksheet `
        -Path (Join-Path $CampaignDirectory 'review-worksheet.csv') `
        -ExpectedObjectIds ($expectedIds | Select-Object -Unique) `
        -ExpectedAccessRowCount ([int]$meta.Counts.WorksheetAccessRows)
    if (-not $worksheet.Valid) {
        return @{
            Success = $false
            FailureReason = "Worksheet validation failed — campaign stays Open. $($worksheet.Errors -join ' | ')"
            Errors = $worksheet.Errors
        }
    }

    # ----- 3. Final-state pulls -----

    $envState = Test-AccessReviewEnvironment
    if (-not $envState.IsAvailable) {
        return @{ Success = $false; FailureReason = $envState.FailureReason }
    }
    $EntraRoster = Resolve-AccessReviewEntraRoster -EntraRoster $EntraRoster
    if (-not $EntraRoster.Available) {
        return @{ Success = $false; FailureReason = "Privileged roster unavailable ($($EntraRoster.FailureReason)) — cannot verify remediation without the final privileged state." }
    }
    $userRoster = Get-AccessReviewRoster
    if (-not $userRoster.Available) {
        return @{ Success = $false; FailureReason = $userRoster.FailureReason }
    }
    $finalUserRows = Build-AccessReviewUserRows -Users @($userRoster.Users) -EntraRoster $EntraRoster

    # ----- 4. Delta + verification -----

    $delta = Compare-AccessReviewRosters `
        -BaselineUsers @($baselinePayload.Users) `
        -FinalUsers $finalUserRows `
        -BaselineAdmins @($baselineAdmins.Roster) `
        -FinalAdmins @($EntraRoster.Roster)

    $verification = Get-AccessReviewVerification -AccessRows $worksheet.AccessRows -Delta $delta

    # ----- 5. Write final-state + verification artifacts -----

    $closedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    $finalJsonPath = Join-Path $CampaignDirectory 'roster-final.json'
    @{
        CampaignId = $meta.CampaignId
        GeneratedAtUtc = $closedAt
        TenantId = $envState.TenantId
        SignInDataAvailable = $userRoster.SignInDataAvailable
        Users = $finalUserRows
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $finalJsonPath -Encoding UTF8

    $finalUserRows | Export-Csv -LiteralPath (Join-Path $CampaignDirectory 'roster-final.csv') -NoTypeInformation -Encoding UTF8

    $EntraRoster | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $CampaignDirectory 'admins-final.json') -Encoding UTF8
    (ConvertTo-AccessReviewAdminCsvRows -EntraRoster $EntraRoster) |
        Export-Csv -LiteralPath (Join-Path $CampaignDirectory 'admins-final.csv') -NoTypeInformation -Encoding UTF8

    $verificationPath = Join-Path $CampaignDirectory 'verification.json'
    [ordered]@{
        SchemaVersion = $script:CampaignSchemaVersion
        CampaignId = $meta.CampaignId
        GeneratedAtUtc = $closedAt
        TenantId = $envState.TenantId
        Decisions = $verification.Decisions
        Delta = $delta
        Flags = $verification.Flags
        Summary = $verification.Summary
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $verificationPath -Encoding UTF8

    # ----- 6. Close the campaign -----

    $meta.Status = 'Closed'
    $meta | Add-Member -NotePropertyName ClosedAtUtc -NotePropertyValue $closedAt -Force
    $meta | Add-Member -NotePropertyName SignOff -NotePropertyValue ([pscustomobject]$worksheet.SignOff) -Force
    $meta | Add-Member -NotePropertyName VerificationSummary -NotePropertyValue ([pscustomobject]$verification.Summary) -Force
    $meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metaPath -Encoding UTF8

    # ----- 7. Refresh the manifest over every artifact -----

    $allFiles = @(Get-ChildItem -LiteralPath $CampaignDirectory -File |
            Where-Object { $_.Name -ne 'manifest.json' } |
            ForEach-Object { $_.FullName })
    $manifest = New-AccessReviewManifest `
        -CampaignDirectory $CampaignDirectory `
        -FilePaths $allFiles `
        -CampaignId $meta.CampaignId `
        -TenantId $envState.TenantId `
        -TenantName ([string]$meta.TenantName)

    return @{
        Success = $true
        FailureReason = $null
        CampaignId = $meta.CampaignId
        Status = 'Closed'
        Directory = $CampaignDirectory
        SignOff = $worksheet.SignOff
        Summary = $verification.Summary
        Flags = $verification.Flags
        VerificationPath = $verificationPath
        ManifestPath = $manifest.ManifestPath
        BundleHash = $manifest.BundleHash
    }
}

function Get-AccessReviewCampaign {
    <#
    .SYNOPSIS
        Lists access-review campaigns under an output directory, newest first.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [string]$OutputDirectory = '.\Output\AccessReview'
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) { return @() }

    $campaigns = foreach ($dir in (Get-ChildItem -LiteralPath $OutputDirectory -Directory)) {
        $metaPath = Join-Path $dir.FullName 'campaign.json'
        if (-not (Test-Path -LiteralPath $metaPath)) { continue }
        try {
            $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Verbose "Skipping $($dir.FullName): unreadable campaign.json ($($_.Exception.Message))"
            continue
        }
        [pscustomobject]@{
            CampaignId = $meta.CampaignId
            PeriodLabel = $meta.PeriodLabel
            Status = $meta.Status
            GeneratedAtUtc = $meta.GeneratedAtUtc
            TenantId = $meta.TenantId
            Directory = $dir.FullName
        }
    }
    return , @($campaigns | Sort-Object GeneratedAtUtc -Descending)
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-AccessReviewRoster',
    'New-AccessReviewCampaign',
    'Complete-AccessReviewCampaign',
    'Get-AccessReviewCampaign'
)

#endregion
