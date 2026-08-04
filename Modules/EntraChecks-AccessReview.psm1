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

    Campaign close (decision ingest, delta, verification) ships in PR 2;
    the HTML report and menu wiring ship in PR 3.

.NOTES
    Maps to SOC 2 TSC CC6.1-CC6.3 and PCI DSS v4.0 7.2.4 / 7.2.5.1.
    Read-only against the tenant: this module never modifies configuration.
#>

#Requires -Version 5.1

#region ==================== MODULE VARIABLES ====================

$script:ModuleVersion = '1.0.0'
$script:CampaignSchemaVersion = '1.0'

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

    if (-not $EntraRoster) {
        if (-not (Get-Command -Name Get-PrivilegedIdentityRosterEntra -ErrorAction SilentlyContinue)) {
            try {
                Import-Module (Join-Path $PSScriptRoot 'EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking -ErrorAction Stop
                Import-Module (Join-Path $PSScriptRoot 'EntraChecks-PrivilegedIdentityEntra.psm1') -Force -DisableNameChecking -ErrorAction Stop
            }
            catch {
                return @{ Success = $false; FailureReason = "Privileged identity modules could not be loaded: $($_.Exception.Message)" }
            }
        }
        $EntraRoster = Get-PrivilegedIdentityRosterEntra
    }
    if (-not $EntraRoster.Available) {
        return @{ Success = $false; FailureReason = "Privileged roster unavailable ($($EntraRoster.FailureReason)) — refusing to open a campaign that cannot tag administrators." }
    }

    $userRoster = Get-AccessReviewRoster
    if (-not $userRoster.Available) {
        return @{ Success = $false; FailureReason = $userRoster.FailureReason }
    }

    # ----- 2. Join: tag users with their privileges -----

    $privByObjectId = @{}
    foreach ($row in @($EntraRoster.Roster)) {
        $privByObjectId[[string]$row.ObjectId] = $row
    }

    $userRows = foreach ($u in @($userRoster.Users)) {
        $priv = $privByObjectId[$u.ObjectId]
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
    $userRows = @($userRows)

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
    $adminCsvRows = foreach ($row in @($EntraRoster.Roster)) {
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
    @($adminCsvRows) | Export-Csv -LiteralPath $adminsCsvPath -NoTypeInformation -Encoding UTF8
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
    'Get-AccessReviewCampaign'
)

#endregion
