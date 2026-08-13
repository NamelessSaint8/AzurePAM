<#
.SYNOPSIS
    Turns a closed, hash-verified access-review campaign into a
    ready-to-run remediation script that a human executes deliberately.

.DESCRIPTION
    PR 1 of the Access Review Remediation plan: the generator.

    This module makes NO Microsoft Graph calls and NO network calls of any
    kind. It reads a closed campaign folder and writes two files — a .ps1
    and a markdown summary. EntraChecks remains a read-only assessment
    toolkit; the generated script is what an operator runs later, on
    purpose, after reading it.

    The join is the work: verification.json says WHO was decided and how,
    admins-baseline.json says WHAT each principal holds and by which
    mechanism (Active / Eligible (PIM) / AppRole / Owner / Unclassified).
    Neither alone is enough to write a removal.

    Refuses to generate anything unless the campaign is Closed AND every
    file hash still matches manifest.json — the reviewer's sign-off over a
    sealed bundle is the authorization record, so a tampered or
    half-written bundle produces nothing.

    Output goes to a SIBLING of the campaign folder,
    <campaign root>/remediation/<CampaignId>/, never inside it: manifest.json
    covers every file in the campaign directory, and writing there after
    sign-off would either break the bundle hash or force a re-seal of a
    folder whose contents changed after the reviewer signed.

.NOTES
    Maps to SOC 2 TSC CC6.1-CC6.3 and PCI DSS v4.0 7.2.4 / 7.2.5.1.
    Read-only against the tenant: this module never modifies configuration.
#>

#Requires -Version 5.1

#region ==================== MODULE VARIABLES ====================

$script:ModuleVersion = '1.0.0'
$script:GlobalAdminRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'
$script:ActionableDecisions = @('Revoke', 'Modify')
$script:DefaultStaleDays = 30

# Everything a PowerShell parser, a terminal or an editor can treat as the
# end of a line. A single one of these inside a display name or a reviewer
# note is enough to escape a '#' comment and continue as top-level code, so
# the whole class is neutralised — not just CRLF.
$script:LineBreakPattern = '[\r\n\v\f\x85\p{Zl}\p{Zp}]+'

# Every other C0/C1 control character plus DEL. Tab (U+0009) is deliberately
# absent: it is ordinary whitespace in both a comment and a string literal.
$script:ControlCharPattern = '[\p{Cc}\p{Cf}-[\t]]'

# Every code point the PowerShell tokenizer accepts as a SINGLE-QUOTE
# delimiter. U+2018, U+2019, U+201A and U+201B close a literal that was OPENED
# with an ASCII apostrophe just as readily as another apostrophe does, so
# doubling only U+0027 leaves four other ways out of a generated string —
# straight into code an operator runs as Privileged Role Administrator.
#
# HOW THIS SET WAS DERIVED — brute force against the real tokenizer, not a doc
# page. For every BMP code point c (surrogates skipped):
#
#     $t = $null; $e = $null
#     $a = [System.Management.Automation.Language.Parser]::ParseInput(
#              "`$x = 'A" + $c + "B'", [ref]$t, [ref]$e)
#
# c is a delimiter unless that parse is error-free AND yields exactly one
# StringConstantExpressionAst whose Value is exactly "A$($c)B". Run over all
# 65,536 BMP code points on PowerShell 7.6.4 (Core) and on Windows PowerShell
# 5.1.26100: both editions returned these five and nothing else. U+2032 PRIME
# and U+2033 DOUBLE PRIME look the part and are NOT delimiters — do not add
# characters on sight, re-run the scan. Doubling each character with ITSELF
# was measured to both close the escape and preserve the original character in
# the parsed value, which is why the escaper doubles rather than substitutes.
#
# The double-quote family was measured identically (U+0022, U+201C, U+201D,
# U+201E, plus '$' and '`' which are expansion syntax; U+201F is NOT one) and
# is deliberately absent here: no generated construct puts attacker-influenced
# text in a double-quoted string or a here-string — every such value goes
# through ConvertTo-RemediationLiteral. The test suite re-derives both sets and
# pins that second invariant, so widening the parser or adding a double-quoted
# emission fails a test instead of shipping.
#
# Written as \u escapes, never as the characters themselves: a literal U+2019
# in this file would terminate the very string that is meant to hold it.
$script:SingleQuoteDelimiterPattern = '[\u0027\u2018\u2019\u201a\u201b]'

# The artifacts the generator actually reads and turns into removal commands.
# Any of these left out of manifest.json is an unsigned input.
$script:RequiredManifestFiles = @('campaign.json', 'verification.json', 'admins-baseline.json')

#endregion

#region ==================== PRIVATE FUNCTIONS ====================

function ConvertTo-RemediationSafeText {
    <#
    .SYNOPSIS
        The one choke point every attacker-influenceable string passes
        through before it reaches the generated script. Display names, UPNs
        and reviewer notes all arrive here first.

    .DESCRIPTION
        Two classes of character are neutralised.

        1. Anything that can END A LINE — CR (U+000D), LF (U+000A), vertical
           tab (U+000B), form feed (U+000C), NEL (U+0085), LINE SEPARATOR
           (U+2028) and PARAGRAPH SEPARATOR (U+2029). A run of them collapses
           to ' | ' so the flattening stays visible to a reader.

           Measured against [Parser]::ParseInput, only CR and LF actually end
           a '#' comment — a bare CR does it just as readily as a CRLF, which
           is the escape this class exists to close. The other five are
           flattened anyway because they DO break a line in editors,
           terminals, diff viewers and pagers: leaving them in would let the
           script a human reviews differ from the script that runs, and the
           whole safety model here is that an operator reads the file before
           executing it. Neutralising the class is also what stops the next
           parser change from re-opening the hole.

        2. Every other control character (C0, C1 and DEL) and every Unicode
           FORMAT character is STRIPPED OUTRIGHT — NUL included. Deleting
           beats substituting: nothing is left for a downstream consumer to
           re-interpret, NUL truncates the string in several of them, and a
           bidi override (U+202E) in a display name would make the generated
           script READ differently from how it RUNS, which defeats the point
           of handing a human a script to review before running it. None of
           these carry content a reviewer meant to record.

        TAB is deliberately kept: ordinary whitespace in both a comment and a
        single-quoted literal.

    .NOTES
        Callers must sanitise BEFORE they escape, never after — stripping a
        control character can CREATE a sequence that needed escaping
        (a hash, a NUL and a greater-than sign become a block-comment
        terminator the moment the NUL is stripped).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    $text = if ($null -eq $Value) { '' } else { [string]$Value }
    $text = $text -replace $script:LineBreakPattern, ' | '
    return ($text -replace $script:ControlCharPattern, '')
}

function ConvertTo-RemediationLiteral {
    <#
    .SYNOPSIS
        Renders a value as a single-quoted PowerShell string literal, quotes
        included. Single-quoted is the shape every generated string uses
        because its escaping rule is one line long: double the delimiter.

    .DESCRIPTION
        "The delimiter" is five code points, not one. The tokenizer closes a
        literal opened with an ASCII apostrophe on U+2018, U+2019, U+201A or
        U+201B just as readily — see $script:SingleQuoteDelimiterPattern for
        the measured set and how to re-derive it. A display name carrying a
        curly apostrophe is ordinary; one carrying a curly apostrophe followed
        by a semicolon and a command is an injection into a script an operator
        runs with Privileged Role Administrator rights. Doubling was measured
        to close the escape AND preserve the character, so the name still
        reads correctly to the human reviewing the file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    # Sanitise first, escape second — see ConvertTo-RemediationSafeText.
    # A line break inside a literal does not end the string, but it does
    # break the one-line-per-statement shape the emitted blocks rely on
    # (a backtick continuation followed by a smuggled newline is a parse
    # change), so the same class is flattened here too.
    $text = ConvertTo-RemediationSafeText $Value
    return "'" + ($text -replace $script:SingleQuoteDelimiterPattern, '$0$0') + "'"
}

function ConvertTo-RemediationComment {
    <#
    .SYNOPSIS
        Flattens a value onto one comment line: line breaks become ' | ' and
        a block-comment terminator is defanged, so a reviewer's note can
        never close the generated script's comment-based help block early
        nor escape the '#' line it was written on.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    # Sanitise first, defang second — see ConvertTo-RemediationSafeText.
    return ((ConvertTo-RemediationSafeText $Value) -replace '#>', '#&gt;')
}

function Expand-RemediationTemplate {
    <#
    .SYNOPSIS
        Substitutes {{TOKEN}} placeholders in a block template in ONE pass.

    .DESCRIPTION
        Chained String.Replace calls are unsafe here: a value substituted by
        an earlier call is still part of the string the later calls scan, so
        a display name of '{{NOTES}}' gets expanded a second time and splices
        an already-quoted literal inside another quoted literal — which
        terminates the string and yields executable code. Sequential
        replacement over attacker-controlled values cannot be made safe by
        reordering; the mechanism has to stop rescanning its own output.

        This walks the template left to right and copies each substituted
        value straight to the output, so a value is never re-examined.
        Unknown tokens are left verbatim rather than blanked, so a typo in a
        template shows up instead of silently vanishing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][hashtable]$Values
    )

    $sb = [System.Text.StringBuilder]::new()
    $position = 0
    foreach ($match in ([regex]'\{\{(\w+)\}\}').Matches($Template)) {
        [void]$sb.Append($Template.Substring($position, $match.Index - $position))
        $key = $match.Groups[1].Value
        if ($Values.ContainsKey($key)) {
            [void]$sb.Append([string]$Values[$key])
        }
        else {
            [void]$sb.Append($match.Value)
        }
        $position = $match.Index + $match.Length
    }
    [void]$sb.Append($Template.Substring($position))
    return $sb.ToString()
}

function Format-RemediationNote {
    <#
    .SYNOPSIS
        Renders the reviewer's Notes as comment lines, one per source line,
        so the note survives into the script verbatim.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [string]$Notes,
        [string]$Indent = '#   '
    )

    if (-not $Notes) { return @() }
    # Split on the SAME class ConvertTo-RemediationSafeText flattens. Split
    # on a narrower one and the leftover terminator rides into a '#' line.
    $lines = foreach ($line in ($Notes -split $script:LineBreakPattern)) {
        $Indent + 'Reviewer notes: ' + (ConvertTo-RemediationComment $line)
    }
    return @($lines)
}

function Format-RemediationTimestamp {
    <#
    .SYNOPSIS
        Renders a campaign timestamp as ISO-8601 UTC.

    .NOTES
        ConvertFrom-Json turns an ISO-8601 string into a [datetime], and
        [string] on that yields a CULTURE-formatted local date. Stamping
        that into the script would corrupt the provenance line and skew the
        generated staleness check by the timezone offset.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    if ($Value -is [datetimeoffset]) {
        return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    return [string]$Value
}

function ConvertTo-RemediationMarkdownCell {
    <#
    .SYNOPSIS
        Escapes a value for a markdown table cell.

    .NOTES
        Deliberately does NOT double quote characters. Nothing parses a
        markdown table as code, so a quote here is content, and doubling it
        would show the reviewer a name that is not the name in the directory.
        The single place in the plan that IS meant to be pasted into a shell —
        the 'cd' line in the Running it block — goes through
        ConvertTo-RemediationLiteral instead.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    $text = ConvertTo-RemediationComment $Value
    return ($text -replace '\|', '\|')
}

function Get-RemediationBundleHash {
    <#
    .SYNOPSIS
        Recomputes a manifest's BundleHash from its own Files[] entries,
        using exactly the construction New-AccessReviewManifest used to
        produce it: '<RelativePath>|<SHA256>' per entry, joined with LF,
        SHA-256 of the UTF-8 bytes, lowercase hex.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries)

    $concat = (@($Entries) | ForEach-Object { "$([string]$_.RelativePath)|$([string]$_.SHA256)" }) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concat))
    }
    finally {
        $sha.Dispose()
    }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-AccessReviewBundleIntegrity {
    <#
    .SYNOPSIS
        Verifies that the campaign bundle is the one the reviewer signed:
        every listed file still hashes to its recorded SHA-256, the LIST
        ITSELF still hashes to the recorded BundleHash, and the artifacts
        this generator reads are all covered by it.

    .DESCRIPTION
        Three separate properties, because hashing only the files a manifest
        chooses to list proves nothing about the choice:

        1. Per-file — every entry exists and still matches its SHA-256.
        2. The list — BundleHash is recomputed from Files[]. Without this,
           deleting an entry from Files[] silently un-covers that artifact
           while the output goes on stamping the original BundleHash as
           provenance: the script would assert an integrity property it no
           longer has, and a reader comparing the stamped hash against the
           one recorded at campaign close would see a match.
        3. Coverage — campaign.json, verification.json and admins-baseline.json
           are read by this generator and turned into privileged-removal
           commands. An uncovered one is an unsigned input, so a manifest
           that omits it is rejected even if everything it does list verifies.

    .NOTES
        Files present in the folder but absent from the manifest remain NOT
        an error, deliberately: New-AccessReviewReport writes
        AccessReview-Report.html after the manifest is sealed. That tolerance
        is safe because it cannot affect what this generator emits — the
        three artifacts it reads are all required to be covered by check 3,
        and check 2 pins the file list itself, so an extra file can only be
        something nothing in this module ever opens.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$CampaignDirectory,
        [Parameter(Mandatory)]$Manifest
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    $entries = @($Manifest.Files)
    if ($entries.Count -eq 0) {
        $errors.Add('manifest.json lists no files.') | Out-Null
    }

    $covered = @{}
    foreach ($entry in $entries) {
        $relative = [string]$entry.RelativePath
        $covered[($relative -replace '\\', '/').Trim().ToLower()] = $true
        $path = Join-Path $CampaignDirectory $relative
        if (-not (Test-Path -LiteralPath $path)) {
            $errors.Add("missing artifact: $relative") | Out-Null
            continue
        }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
        $expected = ([string]$entry.SHA256).ToLower()
        if ($actual -ne $expected) {
            $errors.Add("SHA-256 mismatch: $relative (manifest $expected, actual $actual)") | Out-Null
        }
    }

    foreach ($required in $script:RequiredManifestFiles) {
        if (-not $covered.ContainsKey($required.ToLower())) {
            $errors.Add("$required is not covered by manifest.json — this generator reads it and turns it into removal commands, so an unlisted copy is an unsigned input") | Out-Null
        }
    }

    $recordedBundleHash = ([string]$Manifest.BundleHash).Trim().ToLower()
    if (-not $recordedBundleHash) {
        $errors.Add('manifest.json records no BundleHash — the file list itself is unsigned.') | Out-Null
    }
    else {
        $actualBundleHash = Get-RemediationBundleHash -Entries $entries
        if ($actualBundleHash -ne $recordedBundleHash) {
            $errors.Add("BundleHash mismatch: manifest.json records $recordedBundleHash but its own file list hashes to $actualBundleHash — entries were added or removed after the bundle was sealed") | Out-Null
        }
    }

    return @{
        Valid = ($errors.Count -eq 0)
        Errors = @($errors.ToArray())
    }
}

function Get-RemediationActionList {
    <#
    .SYNOPSIS
        The join. Walks in-scope decisions, looks each principal up in the
        privileged baseline, and produces one action record per privilege
        that must be removed (or per manual decision that cannot be derived).

    .OUTPUTS
        Hashtable: Actions[] (records), SkippedCount.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Decisions,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Roster,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$InScopeVerdicts
    )

    $rosterByOid = @{}
    foreach ($row in $Roster) { $rosterByOid[[string]$row.ObjectId] = $row }

    $actions = [System.Collections.Generic.List[hashtable]]::new()
    $skipped = 0

    foreach ($d in $Decisions) {
        $decision = [string]$d.Decision
        $verdict = [string]$d.Verdict

        # Certify and Investigate never produce an action; a decision whose
        # verdict is out of scope was already handled (or is being re-run
        # deliberately via -IncludeRemediated).
        if ($decision -notin $script:ActionableDecisions -or $verdict -notin $InScopeVerdicts) {
            $skipped++
            continue
        }

        $oid = [string]$d.ObjectId
        $rosterRow = $rosterByOid[$oid]
        # Privilege rows are the authority on privileged-ness. The
        # IsPrivileged column arrives from CSV as the STRING 'False', and
        # [bool]'False' is $true — never trust it here.
        $privileges = if ($rosterRow) { @($rosterRow.Privileges) } else { @() }

        $base = @{}
        $base['Decision'] = $decision
        $base['Verdict'] = $verdict
        $base['ObjectId'] = $oid
        $base['DisplayName'] = [string]$d.DisplayName
        $base['UserPrincipalName'] = [string]$d.UserPrincipalName
        $base['PrincipalType'] = [string]$d.PrincipalType
        $base['Notes'] = [string]$d.Notes

        # Modify cannot be derived from a single worksheet cell — what
        # modification? It always becomes a manual block carrying the note.
        if ($decision -eq 'Modify') {
            $rec = $base.Clone()
            $rec['Kind'] = 'Manual'
            $rec['PrivilegeLabel'] = if ($privileges.Count -gt 0) {
                (@($privileges | ForEach-Object { if (@($_.Path).Count -gt 0) { [string]@($_.Path)[0] } else { [string]$_.Key } }) -join '; ')
            } else { '' }
            $rec['PrivilegeKey'] = ''
            $rec['AssignmentType'] = ''
            $rec['Reason'] = "A 'Modify' decision does not say WHAT to modify. Apply the reviewer's intent by hand."
            $actions.Add($rec) | Out-Null
            continue
        }

        # Revoke on a principal with no privilege rows means disabling or
        # deleting an account. Too big a hammer to infer from a CSV cell.
        if ($privileges.Count -eq 0) {
            $rec = $base.Clone()
            $rec['Kind'] = 'Manual'
            $rec['PrivilegeLabel'] = ''
            $rec['PrivilegeKey'] = ''
            $rec['AssignmentType'] = ''
            $rec['Reason'] = "'Revoke' on a principal holding no recorded privilege means disabling or deleting the account. That is not inferred from a review cell — decide and do it by hand."
            $actions.Add($rec) | Out-Null
            continue
        }

        foreach ($priv in $privileges) {
            $label = if (@($priv.Path).Count -gt 0) { [string]@($priv.Path)[0] } else { [string]$priv.Key }
            $rec = $base.Clone()
            $rec['PrivilegeLabel'] = $label
            $rec['PrivilegeKey'] = [string]$priv.Key
            $rec['AssignmentType'] = [string]$priv.AssignmentType
            $rec['RoleDefinitionId'] = [string]$priv.RoleDefinitionId
            $rec['IsGlobalAdministrator'] = (
                ([string]$priv.Key -eq 'Entra:GlobalAdministrator') -or
                ([string]$priv.RoleDefinitionId -eq $script:GlobalAdminRoleTemplateId) -or
                ($label -match 'Global Administrator')
            )

            switch ($rec['AssignmentType']) {
                'Active' {
                    if (-not $rec['RoleDefinitionId']) {
                        $rec['Kind'] = 'Manual'
                        $rec['Reason'] = 'The baseline recorded no RoleDefinitionId for this active assignment, so the role cannot be re-resolved safely. Remove it by hand.'
                    }
                    else {
                        $rec['Kind'] = 'Active'
                    }
                }
                'Eligible (PIM)' {
                    if (-not $rec['RoleDefinitionId']) {
                        $rec['Kind'] = 'Manual'
                        $rec['Reason'] = 'The baseline recorded no RoleDefinitionId for this PIM eligibility, so the schedule cannot be re-resolved safely. Remove it by hand.'
                    }
                    else {
                        $rec['Kind'] = 'Eligible'
                    }
                }
                'Owner' {
                    # The baseline records the owned app by name only, in
                    # Path[0]: "Owner of '<app>' which holds ...".
                    $owned = ''
                    if ($label -match "^Owner of '(?<app>.+?)' which holds") { $owned = $Matches['app'] }
                    if ($owned) {
                        $rec['Kind'] = 'Owner'
                        $rec['OwnedApplication'] = $owned
                    }
                    else {
                        $rec['Kind'] = 'Manual'
                        $rec['Reason'] = 'Ownership was recorded without a resolvable target application. Remove the ownership by hand.'
                    }
                }
                'AppRole' {
                    $rec['Kind'] = 'AppRole'
                    $permission = ''
                    if ($label -match '^App-role: (?<perm>.+?) granted on') { $permission = $Matches['perm'] }
                    $rec['Permission'] = $permission
                }
                default {
                    $rec['Kind'] = 'Manual'
                    $rec['Reason'] = "Assignment type '$($rec['AssignmentType'])' has no derivable removal. Never guess at a privileged change — work out what this grant is and remove it by hand."
                }
            }

            $actions.Add($rec) | Out-Null
        }
    }

    $i = 1
    foreach ($a in $actions) { $a['Index'] = $i; $i++ }

    return @{
        Actions = @($actions.ToArray())
        SkippedCount = $skipped
    }
}

function New-RemediationBlockHeader {
    <#
    .SYNOPSIS
        The comment banner every generated block carries: who, what they
        hold, how it is held, and the reviewer's note.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][hashtable]$Action,
        [Parameter(Mandatory)][string]$Title
    )

    $rule = '# ' + ('-' * 74)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add($rule) | Out-Null
    $lines.Add("# Action $($Action['Index']) — $(ConvertTo-RemediationComment $Action['Decision']) — $Title") | Out-Null
    $lines.Add("#   Principal : $(ConvertTo-RemediationComment $Action['DisplayName']) <$(ConvertTo-RemediationComment $Action['UserPrincipalName'])>") | Out-Null
    $lines.Add("#   ObjectId  : $(ConvertTo-RemediationComment $Action['ObjectId']) ($(ConvertTo-RemediationComment $Action['PrincipalType']))") | Out-Null
    if ($Action['PrivilegeLabel']) {
        $key = if ($Action['PrivilegeKey']) { "  [$(ConvertTo-RemediationComment $Action['PrivilegeKey'])]" } else { '' }
        $lines.Add("#   Privilege : $(ConvertTo-RemediationComment $Action['PrivilegeLabel'])$key") | Out-Null
    }
    if ($Action['AssignmentType']) {
        $lines.Add("#   Held as   : $(ConvertTo-RemediationComment $Action['AssignmentType'])") | Out-Null
    }
    $lines.Add("#   Verdict   : $(ConvertTo-RemediationComment $Action['Verdict']) at campaign close") | Out-Null
    foreach ($n in (Format-RemediationNote -Notes $Action['Notes'])) { $lines.Add($n) | Out-Null }
    $lines.Add($rule) | Out-Null
    return (($lines.ToArray()) -join [Environment]::NewLine)
}

function New-RemediationActiveBlock {
    <#
    .SYNOPSIS
        Removes an ACTIVE directory role assignment, re-resolved live.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Action)

    $values = @{}
    $values['INDEX'] = [string]$Action['Index']
    $values['OID'] = ConvertTo-RemediationLiteral $Action['ObjectId']
    $values['NAME'] = ConvertTo-RemediationLiteral $Action['DisplayName']
    $values['UPN'] = ConvertTo-RemediationLiteral $Action['UserPrincipalName']
    $values['LABEL'] = ConvertTo-RemediationLiteral $Action['PrivilegeLabel']
    $values['ROLEID'] = ConvertTo-RemediationLiteral $Action['RoleDefinitionId']
    $values['GA'] = if ($Action['IsGlobalAdministrator']) { ' -IsGlobalAdministrator' } else { '' }

    $header = New-RemediationBlockHeader -Action $Action -Title "remove active directory role assignment"
    $body = @'
Write-RemediationAction -Index {{INDEX}} -Title 'Remove active directory role' -Principal {{NAME}} -Privilege {{LABEL}}
if (Test-RemediationGuardrail -ObjectId {{OID}} -DisplayName {{NAME}} -UserPrincipalName {{UPN}} -Privilege {{LABEL}}{{GA}}) {
    # Re-resolved live. The assignment id is NEVER taken from the campaign:
    # if it was already removed by hand this block simply no-ops.
    $current = @(Get-CurrentRoleAssignment -PrincipalId {{OID}} -RoleDefinitionId {{ROLEID}})
    if ($current.Count -eq 0) {
        Write-RemediationSkipped 'the active role assignment is already gone — nothing to do'
    }
    else {
        foreach ($assignment in $current) {
            Add-RemediationLogEntry -ObjectId {{OID}} -DisplayName {{NAME}} -UserPrincipalName {{UPN}} `
                -AssignmentType 'Active' -Privilege {{LABEL}} -Target ([string]$assignment.id) `
                -Detail 'DELETE roleManagement/directory/roleAssignments'
            Invoke-RemediationChange -Method 'DELETE' `
                -Uri ('https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/' + $assignment.id) `
                -Description ('removed active role assignment ' + $assignment.id)
        }
    }
}
'@
    return ($header + [Environment]::NewLine + (Expand-RemediationTemplate -Template $body -Values $values))
}

function New-RemediationEligibleBlock {
    <#
    .SYNOPSIS
        Removes a PIM ELIGIBILITY schedule (AdminRemove request) — a
        different Graph object from an active assignment, deliberately a
        separate builder so the two can never be confused.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Action)

    $values = @{}
    $values['INDEX'] = [string]$Action['Index']
    $values['OID'] = ConvertTo-RemediationLiteral $Action['ObjectId']
    $values['NAME'] = ConvertTo-RemediationLiteral $Action['DisplayName']
    $values['UPN'] = ConvertTo-RemediationLiteral $Action['UserPrincipalName']
    $values['LABEL'] = ConvertTo-RemediationLiteral $Action['PrivilegeLabel']
    $values['ROLEID'] = ConvertTo-RemediationLiteral $Action['RoleDefinitionId']
    $values['GA'] = if ($Action['IsGlobalAdministrator']) { ' -IsGlobalAdministrator' } else { '' }

    $header = New-RemediationBlockHeader -Action $Action -Title "remove PIM eligibility schedule (not an active assignment)"
    $body = @'
Write-RemediationAction -Index {{INDEX}} -Title 'Remove PIM eligibility' -Principal {{NAME}} -Privilege {{LABEL}}
if (Test-RemediationGuardrail -ObjectId {{OID}} -DisplayName {{NAME}} -UserPrincipalName {{UPN}} -Privilege {{LABEL}}{{GA}}) {
    # Re-resolved live: this removes the ELIGIBILITY, not an active
    # assignment. If the eligibility is already gone the block no-ops.
    $current = @(Get-CurrentRoleEligibility -PrincipalId {{OID}} -RoleDefinitionId {{ROLEID}})
    if ($current.Count -eq 0) {
        Write-RemediationSkipped 'the PIM eligibility is already gone — nothing to do'
    }
    else {
        foreach ($schedule in $current) {
            $scope = if ($schedule.directoryScopeId) { [string]$schedule.directoryScopeId } else { '/' }
            Add-RemediationLogEntry -ObjectId {{OID}} -DisplayName {{NAME}} -UserPrincipalName {{UPN}} `
                -AssignmentType 'Eligible (PIM)' -Privilege {{LABEL}} -Target ([string]$schedule.id) `
                -Detail 'POST roleEligibilityScheduleRequests action=AdminRemove'
            $body = @{
                action = 'AdminRemove'
                principalId = {{OID}}
                roleDefinitionId = {{ROLEID}}
                directoryScopeId = $scope
                justification = ('Access review ' + $script:CampaignId + ' — reviewed decision, see remediation-plan.md')
            }
            Invoke-RemediationChange -Method 'POST' `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests' `
                -Body $body `
                -Description ('removed PIM eligibility ' + $schedule.id)
        }
    }
}
'@
    return ($header + [Environment]::NewLine + (Expand-RemediationTemplate -Template $body -Values $values))
}

function New-RemediationOwnerBlock {
    <#
    .SYNOPSIS
        Removes ownership of a privileged service principal. The baseline
        records the app by NAME only, so the block resolves it live and
        refuses when the name is ambiguous rather than guessing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Action)

    $values = @{}
    $values['INDEX'] = [string]$Action['Index']
    $values['OID'] = ConvertTo-RemediationLiteral $Action['ObjectId']
    $values['NAME'] = ConvertTo-RemediationLiteral $Action['DisplayName']
    $values['UPN'] = ConvertTo-RemediationLiteral $Action['UserPrincipalName']
    $values['LABEL'] = ConvertTo-RemediationLiteral $Action['PrivilegeLabel']
    $values['APP'] = ConvertTo-RemediationLiteral $Action['OwnedApplication']

    $header = New-RemediationBlockHeader -Action $Action -Title "remove ownership of a privileged application"
    $body = @'
Write-RemediationAction -Index {{INDEX}} -Title 'Remove application ownership' -Principal {{NAME}} -Privilege {{LABEL}}
if (Test-RemediationGuardrail -ObjectId {{OID}} -DisplayName {{NAME}} -UserPrincipalName {{UPN}} -Privilege {{LABEL}}) {
    # The baseline names the owned application but records no object id, so
    # it is resolved live. An ambiguous name refuses rather than guessing.
    $owned = @(Resolve-OwnedServicePrincipal -DisplayName {{APP}})
    if ($owned.Count -eq 0) {
        Write-RemediationSkipped ('no service principal named ' + {{APP}} + ' exists any more — nothing to do')
    }
    elseif ($owned.Count -gt 1) {
        Write-RemediationRefused ('the name ' + {{APP}} + ' matches ' + $owned.Count + ' service principals — resolve the ownership by hand')
    }
    else {
        $sp = $owned[0]
        $owners = @(Get-CurrentServicePrincipalOwner -ServicePrincipalId ([string]$sp.id))
        if (@($owners | Where-Object { [string]$_.id -eq {{OID}} }).Count -eq 0) {
            Write-RemediationSkipped 'the ownership is already gone — nothing to do'
        }
        else {
            Add-RemediationLogEntry -ObjectId {{OID}} -DisplayName {{NAME}} -UserPrincipalName {{UPN}} `
                -AssignmentType 'Owner' -Privilege {{LABEL}} -Target ([string]$sp.id) `
                -Detail 'DELETE servicePrincipals/{id}/owners/{oid}/$ref'
            Invoke-RemediationChange -Method 'DELETE' `
                -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $sp.id + '/owners/' + {{OID}} + '/$ref') `
                -Description ('removed ownership of ' + $sp.displayName)
        }
    }
}
'@
    return ($header + [Environment]::NewLine + (Expand-RemediationTemplate -Template $body -Values $values))
}

function New-RemediationAppRoleBlock {
    <#
    .SYNOPSIS
        App-role grant removal — emitted COMMENTED OUT on purpose. Pulling
        an app permission out from under a service principal is how an
        integration breaks at 3am; uncommenting is a deliberate act.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Action)

    $values = @{}
    $values['OID'] = ConvertTo-RemediationLiteral $Action['ObjectId']
    $values['NAME'] = ConvertTo-RemediationLiteral $Action['DisplayName']
    $values['UPN'] = ConvertTo-RemediationLiteral $Action['UserPrincipalName']
    $values['LABEL'] = ConvertTo-RemediationLiteral $Action['PrivilegeLabel']
    $values['PERM'] = ConvertTo-RemediationLiteral $Action['Permission']

    $header = New-RemediationBlockHeader -Action $Action -Title "remove app-role grant (COMMENTED OUT — see the warning)"
    $warning = @'
Write-RemediationAppRoleWarning -Principal {{NAME}} -Privilege {{LABEL}}
'@
    $code = @'
if (Test-RemediationGuardrail -ObjectId {{OID}} -DisplayName {{NAME}} -UserPrincipalName {{UPN}} -Privilege {{LABEL}}) {
    $grants = @(Get-CurrentAppRoleGrant -PrincipalId {{OID}} -PermissionValue {{PERM}})
    if ($grants.Count -eq 0) {
        Write-RemediationSkipped 'the app-role grant is already gone — nothing to do'
    }
    else {
        foreach ($grant in $grants) {
            Add-RemediationLogEntry -ObjectId {{OID}} -DisplayName {{NAME}} -UserPrincipalName {{UPN}} `
                -AssignmentType 'AppRole' -Privilege {{LABEL}} -Target ([string]$grant.id) `
                -Detail 'DELETE servicePrincipals/{resourceId}/appRoleAssignedTo/{id}'
            Invoke-RemediationChange -Method 'DELETE' `
                -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $grant.resourceId + '/appRoleAssignedTo/' + $grant.id) `
                -Description ('removed app-role grant ' + $grant.id)
        }
    }
}
'@
    $warning = Expand-RemediationTemplate -Template $warning -Values $values
    $code = Expand-RemediationTemplate -Template $code -Values $values

    # Comment every line of the action itself. The warning above stays live
    # so a run still reports that something was deliberately not done.
    #
    # Split on the full line-break class, not just CRLF: this loop is what
    # keeps the block inert, so a terminator it failed to recognise would
    # leave a live removal line behind an apparently commented-out block.
    # (ConvertTo-RemediationSafeText already strips those from the values
    # above; splitting on the same class means the invariant holds here on
    # its own rather than by depending on a caller two functions away.)
    $commented = (($code -split $script:LineBreakPattern) | ForEach-Object { '# ' + $_ }) -join [Environment]::NewLine
    return ($header + [Environment]::NewLine + $warning + [Environment]::NewLine +
        '# UNCOMMENT DELIBERATELY — removing an app permission can break a live integration.' + [Environment]::NewLine +
        $commented)
}

function New-RemediationManualBlock {
    <#
    .SYNOPSIS
        A '# TODO' block for anything that cannot be derived safely,
        carrying the reviewer's note so the operator has the context.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Action)

    $values = @{}
    $values['INDEX'] = [string]$Action['Index']
    $values['NAME'] = ConvertTo-RemediationLiteral $Action['DisplayName']
    $values['UPN'] = ConvertTo-RemediationLiteral $Action['UserPrincipalName']
    $values['NOTES'] = ConvertTo-RemediationLiteral $Action['Notes']
    $values['REASON'] = ConvertTo-RemediationLiteral $Action['Reason']

    $header = New-RemediationBlockHeader -Action $Action -Title 'MANUAL — no safe automatic action'
    $todo = "# TODO: $(ConvertTo-RemediationComment $Action['Reason'])"
    $body = @'
Write-RemediationManual -Index {{INDEX}} -Principal {{NAME}} -UserPrincipalName {{UPN}} -Reason {{REASON}} -Notes {{NOTES}}
'@
    $body = Expand-RemediationTemplate -Template $body -Values $values
    return ($header + [Environment]::NewLine + $todo + [Environment]::NewLine + $body)
}

function New-RemediationScriptPreamble {
    <#
    .SYNOPSIS
        Everything above the generated action blocks: provenance header,
        parameters, staleness gate, guardrails, logging, and the live
        re-resolution helpers every block calls.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][hashtable]$Provenance
    )

    $template = @'
<#
.SYNOPSIS
    Access-review remediation for campaign {{CampaignId}} — GENERATED BY
    EntraChecks, NOT APPLIED BY IT.

.DESCRIPTION
    EntraChecks generated this script from a closed, hash-verified access
    review. EntraChecks is a read-only assessment toolkit: it did not make
    any of the changes below, and it cannot. Applying them is a deliberate
    human act — read this file first, then run it with -Execute.

    Provenance
      Campaign id      : {{CampaignId}}
      Tenant           : {{TenantName}} ({{TenantId}})
      Bundle SHA-256   : {{BundleHash}}
      Reviewer         : {{ReviewerName}} — {{ReviewerTitle}}
      Sign-off date    : {{SignOffDate}}
      Campaign closed  : {{ClosedAtUtc}}
      Script generated : {{GeneratedAtUtc}} by EntraChecks AccessReviewRemediation v{{ModuleVersion}}

    Safety model
      * Dry run by default: nothing changes without -Execute.
      * Every action re-resolves current state from Microsoft Graph and
        no-ops when the assignment is already gone — idempotent, and honest
        about a tenant that moved on since the campaign closed.
      * Guardrails refuse and continue, never aborting the run: the last
        Global Administrator, any identity matching the break-glass
        patterns PRINTED AT START-UP, and the identity running this script
        are never touched. Two of those are stated rather than assumed —
        the break-glass patterns are listed on screen before any action,
        and if the script cannot establish which identity is running it, it
        says so per action and refuses -Execute outright.
      * Every removal is appended to remediation-log-<utc>.json BEFORE the
        call, so an interrupted run is still reconstructible.
      * Refuses to run at all once the campaign is more than {{StaleDays}}
        days old, unless -Force is passed.

    Graph scopes you must connect with yourself (this script does not
    connect, and EntraChecks never asks for these):
      RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All
      AppRoleAssignment.ReadWrite.All — only if you uncomment an app-role block

.PARAMETER Execute
    Apply the changes. Without it every action is reported, not performed.

.PARAMETER Force
    Run even though the campaign closed more than {{StaleDays}} days ago.

.PARAMETER ConfigFile
    EntraChecks configuration file whose break-glass account list
    (SOC2.BreakGlassAccounts, or
    SOC2.AzureReadiness.BreakGlass.AccountUpnPatterns) is ADDED to the
    built-in emergency-access name patterns. Auto-discovered when omitted.
    Neither key ships populated, which is why the built-in patterns exist
    and always apply — they are printed at start-up, so what is protected
    is stated rather than assumed.

.PARAMETER LogDirectory
    Folder for remediation-log-<utc>.json. Defaults to this script's folder.

.EXAMPLE
    Connect-MgGraph -Scopes RoleManagement.ReadWrite.Directory,Directory.ReadWrite.All
    .\{{ScriptFileName}}

    Dry run: prints every action and changes nothing.

.EXAMPLE
    .\{{ScriptFileName}} -Execute

    Applies the reviewed decisions, guardrails enforced, every removal logged.
#>

[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$Force,
    [string]$ConfigFile,
    [string]$LogDirectory
)

$ErrorActionPreference = 'Stop'

$script:CampaignId = {{CampaignId_LIT}}
$script:BundleHash = {{BundleHash_LIT}}
$script:ReviewerName = {{ReviewerName_LIT}}
$script:ClosedAtUtc = {{ClosedAtUtc_LIT}}
$script:StaleDays = {{StaleDays}}
$script:GlobalAdminRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'

$script:ChangedCount = 0
$script:WouldChangeCount = 0
$script:SkippedCount = 0
$script:RefusedCount = 0
$script:FailedCount = 0
$script:ManualCount = 0
$script:LogEntries = [System.Collections.Generic.List[object]]::new()

if (-not $LogDirectory) { $LogDirectory = $PSScriptRoot }
$script:LogPath = Join-Path $LogDirectory ('remediation-log-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + '.json')

#region ---------------- console ----------------

function Write-RemediationAction {
    param([int]$Index, [string]$Title, [string]$Principal, [string]$Privilege)
    Write-Host ''
    Write-Host ("[$Index] $Title — $Principal") -ForegroundColor Cyan
    if ($Privilege) { Write-Host ("     privilege: $Privilege") -ForegroundColor DarkGray }
}

function Write-RemediationSkipped {
    param([string]$Reason)
    $script:SkippedCount++
    Write-Host ("     [skip] $Reason") -ForegroundColor DarkGray
}

function Write-RemediationRefused {
    param([string]$Reason)
    $script:RefusedCount++
    Write-Host ("     [REFUSED] $Reason") -ForegroundColor Yellow
}

function Write-RemediationManual {
    param([int]$Index, [string]$Principal, [string]$UserPrincipalName, [string]$Reason, [string]$Notes)
    $script:ManualCount++
    Write-Host ''
    Write-Host ("[$Index] MANUAL — $Principal <$UserPrincipalName>") -ForegroundColor Magenta
    Write-Host ("     $Reason") -ForegroundColor Magenta
    if ($Notes) { Write-Host ("     reviewer notes: $Notes") -ForegroundColor DarkGray }
}

function Write-RemediationAppRoleWarning {
    param([string]$Principal, [string]$Privilege)
    $script:ManualCount++
    Write-Host ''
    Write-Host ("[app-role] NOT PERFORMED — $Principal holds $Privilege") -ForegroundColor Yellow
    Write-Host '     Removing an app permission can break a live integration. The removal' -ForegroundColor Yellow
    Write-Host '     is written below this warning, commented out. Uncomment it only after' -ForegroundColor Yellow
    Write-Host '     you know what depends on this service principal.' -ForegroundColor Yellow
}

#endregion

#region ---------------- guardrails ----------------

function Get-BreakGlassPattern {
    <#
        Break-glass accounts are the recovery path of last resort. Whatever
        a review says, this script does not remove their access.

        The BUILT-IN patterns below always apply and configured patterns are
        added to them, never substituted for them. EntraChecks ships no
        populated break-glass list — SOC2.BreakGlassAccounts exists in no
        shipped config and SOC2.AzureReadiness.BreakGlass.AccountUpnPatterns
        ships empty — so a config-only guardrail protects nothing on a stock
        install while the header above promises break-glass access is never
        removed. A guardrail that silently protects nothing is worse than no
        guardrail at all, because it is trusted.

        These names are the common conventions for emergency-access
        accounts, matched with -like against both UPN and display name. They
        are a heuristic and they over-match on purpose: a false refusal
        costs one manual removal, a false negative costs the tenant its
        recovery path. Configure the real list to stop guessing.
    #>
    param([string]$Path)

    $patterns = [System.Collections.Generic.List[string]]::new()
    foreach ($builtin in @(
            '*breakglass*',
            '*break-glass*',
            '*break.glass*',
            '*break_glass*',
            '*emergencyaccess*',
            '*emergency-access*',
            '*emergency access*',
            'bg-admin*')) {
        $patterns.Add($builtin) | Out-Null
    }

    if (-not $Path) {
        $probe = $PSScriptRoot
        for ($i = 0; $i -lt 6 -and $probe; $i++) {
            $candidate = Join-Path $probe 'config/entrachecks.config.json'
            if (Test-Path -LiteralPath $candidate) { $Path = $candidate; break }
            $probe = Split-Path -Parent $probe
        }
    }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $patterns }

    try {
        $cfg = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        Write-Host ("     [warn] could not read $Path — $($_.Exception.Message)") -ForegroundColor Yellow
        return $patterns
    }
    $soc2 = $cfg.PSObject.Properties['SOC2']
    if (-not $soc2) { return $patterns }
    $soc2 = $soc2.Value
    if ($soc2.PSObject.Properties['BreakGlassAccounts']) {
        foreach ($v in @($soc2.BreakGlassAccounts)) { if ($v) { $patterns.Add([string]$v) | Out-Null } }
    }
    if ($soc2.PSObject.Properties['AzureReadiness'] -and $soc2.AzureReadiness.PSObject.Properties['BreakGlass']) {
        foreach ($v in @($soc2.AzureReadiness.BreakGlass.AccountUpnPatterns)) { if ($v) { $patterns.Add([string]$v) | Out-Null } }
    }
    return $patterns
}

function Get-GlobalAdministratorCount {
    <#
        Counted LIVE, immediately before a removal — not from the campaign.
    #>
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$($script:GlobalAdminRoleTemplateId)'"
    $principals = @{}
    $next = $uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        foreach ($a in @($page.value)) { $principals[[string]$a.principalId] = $true }
        $next = $page.'@odata.nextLink'
    }
    return $principals.Count
}

function Test-RemediationGuardrail {
    <#
        Refuse-and-continue. Every refusal prints why and the run carries on
        to the next action.
    #>
    param(
        [string]$ObjectId,
        [string]$DisplayName,
        [string]$UserPrincipalName,
        [string]$Privilege,
        [switch]$IsGlobalAdministrator
    )

    # 1. Never act on the identity running this script — locking yourself
    #    out mid-run is unrecoverable.
    if (-not $script:RunnerIdentified) {
        # Preflight already refused -Execute in this state. Repeat it per
        # action so a dry-run transcript can never be read as evidence that
        # the self-exclusion check ran and passed.
        Write-Host '     [note] the running identity is UNKNOWN — cannot confirm this is not you' -ForegroundColor Yellow
    }
    if ($script:RunnerObjectId -and $ObjectId -eq $script:RunnerObjectId) {
        Write-RemediationRefused 'this is the identity running this script — refusing to remove your own access'
        return $false
    }
    if ($script:RunnerUpn -and $UserPrincipalName -and $UserPrincipalName -eq $script:RunnerUpn) {
        Write-RemediationRefused 'this is the identity running this script — refusing to remove your own access'
        return $false
    }

    # 2. Never a break-glass account.
    foreach ($pattern in $script:BreakGlassAccounts) {
        if (($UserPrincipalName -and $UserPrincipalName -like $pattern) -or ($DisplayName -and $DisplayName -like $pattern)) {
            Write-RemediationRefused ("matches break-glass pattern '$pattern' — break-glass access is never removed by this script")
            return $false
        }
    }

    # 3. Never the last Global Administrator.
    if ($IsGlobalAdministrator) {
        try {
            $gaCount = Get-GlobalAdministratorCount
        }
        catch {
            Write-RemediationRefused ("could not count Global Administrators live ($($_.Exception.Message)) — refusing rather than risk removing the last Global Administrator")
            return $false
        }
        if ($gaCount -le 1) {
            Write-RemediationRefused "only $gaCount Global Administrator remains — refusing to remove the last Global Administrator"
            return $false
        }
    }

    return $true
}

#endregion

#region ---------------- live re-resolution ----------------

function Invoke-RemediationGraphPaged {
    param([Parameter(Mandatory)][string]$Uri)
    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        foreach ($item in @($page.value)) { $results.Add($item) | Out-Null }
        $next = $page.'@odata.nextLink'
    }
    return , $results.ToArray()
}

# Identifiers reach these helpers from the campaign bundle and are
# interpolated into an OData $filter or a URL path segment. They are
# always GUIDs when the bundle is honest; refuse anything else rather
# than let a crafted id alter the query that decides what gets removed.
function Assert-RemediationGuid {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Name
    )
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($Value, [ref]$parsed)) {
        throw "Refusing to query Microsoft Graph: $Name is not a GUID ('$Value'). The campaign bundle may be corrupt - regenerate it from a trusted campaign."
    }
    return $parsed.ToString()
}

function Get-CurrentRoleAssignment {
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$RoleDefinitionId)
    $principalGuid = Assert-RemediationGuid -Value $PrincipalId -Name 'PrincipalId'
    $roleGuid = Assert-RemediationGuid -Value $RoleDefinitionId -Name 'RoleDefinitionId'
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$principalGuid' and roleDefinitionId eq '$roleGuid'"
    return , @(Invoke-RemediationGraphPaged -Uri $uri)
}

function Get-CurrentRoleEligibility {
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$RoleDefinitionId)
    $principalGuid = Assert-RemediationGuid -Value $PrincipalId -Name 'PrincipalId'
    $roleGuid = Assert-RemediationGuid -Value $RoleDefinitionId -Name 'RoleDefinitionId'
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$principalGuid' and roleDefinitionId eq '$roleGuid'"
    return , @(Invoke-RemediationGraphPaged -Uri $uri)
}

function Resolve-OwnedServicePrincipal {
    param([Parameter(Mandatory)][string]$DisplayName)
    $escaped = $DisplayName.Replace("'", "''")
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$escaped'"
    return , @(Invoke-RemediationGraphPaged -Uri $uri)
}

function Get-CurrentServicePrincipalOwner {
    param([Parameter(Mandatory)][string]$ServicePrincipalId)
    return , @(Invoke-RemediationGraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/owners")
}

function Get-CurrentAppRoleGrant {
    param([Parameter(Mandatory)][string]$PrincipalId, [string]$PermissionValue)
    $grants = @(Invoke-RemediationGraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments")
    if (-not $PermissionValue) { return , @($grants) }
    # Match the grant back to the permission NAME the baseline recorded.
    $matched = foreach ($g in $grants) {
        $resource = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $g.resourceId) -ErrorAction Stop
        $role = @($resource.appRoles) | Where-Object { [string]$_.id -eq [string]$g.appRoleId } | Select-Object -First 1
        if ($role -and [string]$role.value -eq $PermissionValue) { $g }
    }
    return , @($matched)
}

#endregion

#region ---------------- change + rollback record ----------------

function Add-RemediationLogEntry {
    <#
        Written to disk BEFORE the removal it describes, so an interrupted
        run is still reconstructible from remediation-log-<utc>.json.
    #>
    param(
        [string]$ObjectId, [string]$DisplayName, [string]$UserPrincipalName,
        [string]$AssignmentType, [string]$Privilege, [string]$Target, [string]$Detail
    )

    $entry = [ordered]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Mode = if ($Execute) { 'Execute' } else { 'WhatIf' }
        ObjectId = $ObjectId
        DisplayName = $DisplayName
        UserPrincipalName = $UserPrincipalName
        AssignmentType = $AssignmentType
        Privilege = $Privilege
        Target = $Target
        Detail = $Detail
    }
    $script:LogEntries.Add([pscustomobject]$entry) | Out-Null

    $envelope = [ordered]@{
        CampaignId = $script:CampaignId
        BundleHash = $script:BundleHash
        Reviewer = $script:ReviewerName
        RunStartedUtc = $script:RunStartedUtc
        Mode = if ($Execute) { 'Execute' } else { 'WhatIf' }
        Entries = @($script:LogEntries.ToArray())
    }
    $envelope | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:LogPath -Encoding UTF8
}

function Invoke-RemediationChange {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        $Body,
        [string]$Description
    )

    if (-not $Execute) {
        $script:WouldChangeCount++
        Write-Host ("     [WhatIf] would $Method $Uri") -ForegroundColor Yellow
        return
    }
    try {
        if ($Body) {
            Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body -ErrorAction Stop | Out-Null
        }
        else {
            Invoke-MgGraphRequest -Method $Method -Uri $Uri -ErrorAction Stop | Out-Null
        }
        $script:ChangedCount++
        Write-Host ("     [done] $Description") -ForegroundColor Green
    }
    catch {
        # Refuse and continue: one failure must not strand the rest.
        $script:FailedCount++
        Write-Host ("     [FAILED] $Description — $($_.Exception.Message)") -ForegroundColor Red
    }
}

#endregion

#region ---------------- preflight ----------------

$script:RunStartedUtc = (Get-Date).ToUniversalTime().ToString('o')

Write-Host ''
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host " Access review remediation — campaign $($script:CampaignId)" -ForegroundColor Cyan
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host (' Reviewer      : ' + {{ReviewerName_LIT}} + ' — ' + {{ReviewerTitle_LIT}} + ' (signed ' + {{SignOffDate_LIT}} + ')')
Write-Host " Bundle SHA-256: $($script:BundleHash)"
Write-Host " Campaign closed: $($script:ClosedAtUtc)"
Write-Host " Actions        : {{ActionCount}} automatic, {{ManualCount}} manual"
Write-Host ' EntraChecks generated this script. It did NOT apply these changes.'

$closedAt = [datetime]::MinValue
if (-not [datetime]::TryParse($script:ClosedAtUtc, [ref]$closedAt)) {
    Write-Host ' Campaign close date is unreadable — refusing to run.' -ForegroundColor Red
    exit 1
}
$ageDays = [int]((Get-Date).ToUniversalTime() - $closedAt.ToUniversalTime()).TotalDays
Write-Host " Campaign age   : $ageDays day(s)"
if ($ageDays -gt $script:StaleDays -and -not $Force) {
    Write-Host ''
    Write-Host " This campaign closed $ageDays days ago (threshold $($script:StaleDays))." -ForegroundColor Red
    Write-Host ' Access granted legitimately since then would be removed on the strength' -ForegroundColor Red
    Write-Host ' of a stale review. Re-run the review, or pass -Force if you are certain.' -ForegroundColor Red
    exit 1
}

if (-not (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue)) {
    Write-Host ' Microsoft.Graph.Authentication is not loaded. Connect-MgGraph first.' -ForegroundColor Red
    exit 1
}
$ctx = Get-MgContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Write-Host ''
    Write-Host ' No Microsoft Graph context. Even a dry run re-resolves live state.' -ForegroundColor Red
    Write-Host ' Connect-MgGraph -Scopes RoleManagement.ReadWrite.Directory,Directory.ReadWrite.All' -ForegroundColor Red
    exit 1
}

$script:RunnerUpn = [string]$ctx.Account
$script:RunnerObjectId = ''
$script:RunnerIdentitySource = ''
try {
    $me = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me' -ErrorAction Stop
    $script:RunnerObjectId = [string]$me.id
    $script:RunnerIdentitySource = 'delegated user (/me)'
}
catch {
    Write-Verbose "Could not resolve the running identity from /me: $($_.Exception.Message)"
}
if (-not $script:RunnerObjectId -and $ctx.ClientId) {
    # App-only (client credentials) has NO /me — it returns 400, and
    # Get-MgContext leaves Account null. Both self-checks in
    # Test-RemediationGuardrail are guarded on these two variables, so
    # without this lookup they short-circuit and guardrail 3 is silently
    # absent for exactly the identity most able to remove its own access:
    # a service principal holding a directory role, which cannot restore
    # it afterwards. The running identity IS the service principal for
    # this client id.
    try {
        $runnerSp = Invoke-MgGraphRequest -Method GET -ErrorAction Stop `
            -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals(appId='" + [string]$ctx.ClientId + "')")
        $script:RunnerObjectId = [string]$runnerSp.id
        if (-not $script:RunnerUpn) { $script:RunnerUpn = [string]$runnerSp.displayName }
        $script:RunnerIdentitySource = 'application (servicePrincipals by appId)'
    }
    catch {
        Write-Verbose "Could not resolve the running service principal: $($_.Exception.Message)"
    }
}
$script:RunnerIdentified = [bool]($script:RunnerObjectId -or $script:RunnerUpn)

if ($script:RunnerIdentified) {
    Write-Host " Running as     : $($script:RunnerUpn) [$($script:RunnerIdentitySource)]"
    if (-not $script:RunnerObjectId) {
        Write-Host '                  object id unresolved — self-exclusion can only match on UPN,' -ForegroundColor Yellow
        Write-Host '                  which no service-principal row in the roster carries.' -ForegroundColor Yellow
    }
}
else {
    Write-Host ' Running as     : UNKNOWN — this script cannot work out who is running it.' -ForegroundColor Red
    Write-Host '                  Get-MgContext returned no account, /me is not available to an' -ForegroundColor Red
    Write-Host '                  app-only token, and the service principal for this client id' -ForegroundColor Red
    Write-Host '                  could not be read. GUARDRAIL 3 (never remove your own access)' -ForegroundColor Red
    Write-Host '                  CANNOT APPLY — the header above promises a check this run is' -ForegroundColor Red
    Write-Host '                  not able to make.' -ForegroundColor Red
    if ($Execute) {
        # Refuse under -Execute, allow the dry run. The dry run changes
        # nothing, so finishing it shows the operator every action AND this
        # banner — more useful than dying at the first block. -Execute is
        # different in kind: it would remove privileged access while unable
        # to tell whether one of those removals targets this very identity,
        # which is the one failure that cannot be undone from inside the
        # script. Grant Application.Read.All, or run delegated, and re-run.
        Write-Host ''
        Write-Host ' Refusing to -Execute without knowing which identity is running. Grant this' -ForegroundColor Red
        Write-Host ' app Application.Read.All so it can resolve itself, or run delegated.' -ForegroundColor Red
        exit 1
    }
    Write-Host '                  Continuing as a DRY RUN only.' -ForegroundColor Yellow
}
$script:BreakGlassAccounts = @(Get-BreakGlassPattern -Path $ConfigFile)

if ($script:BreakGlassAccounts.Count -eq 0) {
    # Only reachable if the built-in list inside Get-BreakGlassPattern was
    # edited away. If it was, the header's promise that break-glass access
    # is never removed is false — stop rather than run a guardrail that
    # protects nothing while claiming to.
    Write-Host ''
    Write-Host ' Break-glass    : NO patterns — the break-glass guardrail would protect NOTHING.' -ForegroundColor Red
    Write-Host '                  This script removes privileged access and its header states that' -ForegroundColor Red
    Write-Host '                  break-glass accounts are never touched. Refusing to run rather' -ForegroundColor Red
    Write-Host '                  than make that statement false.' -ForegroundColor Red
    exit 1
}

Write-Host " Break-glass    : $($script:BreakGlassAccounts.Count) pattern(s) — an identity matching ANY of these is NEVER touched:"
foreach ($pattern in $script:BreakGlassAccounts) {
    Write-Host "                    $pattern"
}
Write-Host '                  Matched with -like against UPN and display name. The built-in' -ForegroundColor DarkGray
Write-Host '                  names are a heuristic: if your emergency-access accounts are not' -ForegroundColor DarkGray
Write-Host '                  named like any of the above they are NOT protected — list them in' -ForegroundColor DarkGray
Write-Host '                  SOC2.AzureReadiness.BreakGlass.AccountUpnPatterns and re-run.' -ForegroundColor DarkGray
Write-Host " Rollback log   : $($script:LogPath)"
if ($Execute) {
    Write-Host ' Mode           : EXECUTE — changes will be applied.' -ForegroundColor Red
}
else {
    Write-Host ' Mode           : dry run (default). Re-run with -Execute to apply.' -ForegroundColor Green
}
Write-Host ''

#endregion

#region ---------------- actions ----------------
'@

    # One pass, not a Replace per key: the old loop iterated an UNORDERED
    # hashtable and rescanned its own output, so a reviewer name containing
    # another key's token was expanded twice, in a non-deterministic order.
    $values = @{}
    foreach ($key in $Provenance.Keys) {
        $values[$key] = ConvertTo-RemediationComment $Provenance[$key]
        $values["${key}_LIT"] = ConvertTo-RemediationLiteral $Provenance[$key]
    }
    return (Expand-RemediationTemplate -Template $template -Values $values)
}

function New-RemediationScriptEpilogue {
    <#
    .SYNOPSIS
        The closing summary the operator sees after every run.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
#endregion

#region ---------------- summary ----------------

Write-Host ''
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host ' Summary' -ForegroundColor Cyan
Write-Host '================================================================' -ForegroundColor Cyan
if ($Execute) {
    Write-Host " Applied        : $($script:ChangedCount)"
    Write-Host " Failed         : $($script:FailedCount)" -ForegroundColor $(if ($script:FailedCount -gt 0) { 'Red' } else { 'Gray' })
}
else {
    Write-Host " Would apply    : $($script:WouldChangeCount)" -ForegroundColor Yellow
}
Write-Host " Already gone   : $($script:SkippedCount)"
Write-Host " Refused        : $($script:RefusedCount)" -ForegroundColor $(if ($script:RefusedCount -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host " Manual / TODO  : $($script:ManualCount)" -ForegroundColor $(if ($script:ManualCount -gt 0) { 'Magenta' } else { 'Gray' })
if ($script:LogEntries.Count -gt 0) {
    Write-Host " Rollback log   : $($script:LogPath)"
}
if (-not $Execute) {
    Write-Host ''
    Write-Host ' Nothing was changed. Re-run with -Execute to apply.' -ForegroundColor Green
}
Write-Host ''

#endregion
'@
}

function New-RemediationPlanMarkdown {
    <#
    .SYNOPSIS
        The human-readable companion to the generated script: counts, a
        per-principal table, and what a human still has to do by hand.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][hashtable]$Provenance,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Actions,
        [Parameter(Mandatory)][int]$SkippedCount,
        [Parameter(Mandatory)][int]$DecisionCount
    )

    $auto = @($Actions | Where-Object { $_['Kind'] -in @('Active', 'Eligible', 'Owner') })
    $manual = @($Actions | Where-Object { $_['Kind'] -in @('Manual', 'AppRole') })

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Remediation plan — $(ConvertTo-RemediationComment $Provenance['CampaignId'])")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('**EntraChecks generated this plan and the script beside it. EntraChecks did not apply any of these changes, and cannot — it is a read-only assessment toolkit.** The script is inert until a human runs it with `-Execute`.')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## Provenance')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Field | Value |')
    [void]$sb.AppendLine('|---|---|')
    foreach ($pair in @(
            @('Campaign', $Provenance['CampaignId']),
            @('Tenant', "$($Provenance['TenantName']) ($($Provenance['TenantId']))"),
            @('Bundle SHA-256', $Provenance['BundleHash']),
            @('Reviewer', "$($Provenance['ReviewerName']) — $($Provenance['ReviewerTitle'])"),
            @('Sign-off date', $Provenance['SignOffDate']),
            @('Campaign closed', $Provenance['ClosedAtUtc']),
            @('Plan generated', $Provenance['GeneratedAtUtc']),
            @('Stale threshold', "$($Provenance['StaleDays']) days"))) {
        [void]$sb.AppendLine("| $($pair[0]) | $(ConvertTo-RemediationMarkdownCell $pair[1]) |")
    }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## Counts')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| | Count |')
    [void]$sb.AppendLine('|---|---|')
    [void]$sb.AppendLine("| Decisions read | $DecisionCount |")
    [void]$sb.AppendLine("| Automatic removals generated | $($auto.Count) |")
    [void]$sb.AppendLine("| Manual / commented-out blocks | $($manual.Count) |")
    [void]$sb.AppendLine("| Decisions producing nothing | $SkippedCount |")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## Per principal')
    [void]$sb.AppendLine()
    if ($Actions.Count -eq 0) {
        [void]$sb.AppendLine('Nothing to do — no in-scope decision produced an action.')
    }
    else {
        [void]$sb.AppendLine('| # | Principal | UPN | Decision | Privilege | Held as | Generated |')
        [void]$sb.AppendLine('|---|---|---|---|---|---|---|')
        foreach ($a in $Actions) {
            $generated = switch ($a['Kind']) {
                'Active' { 'Remove active role assignment' }
                'Eligible' { 'Remove PIM eligibility' }
                'Owner' { 'Remove application ownership' }
                'AppRole' { 'App-role removal, COMMENTED OUT' }
                default { 'Manual `# TODO`' }
            }
            $cells = @(
                $a['Index'],
                (ConvertTo-RemediationMarkdownCell $a['DisplayName']),
                (ConvertTo-RemediationMarkdownCell $a['UserPrincipalName']),
                (ConvertTo-RemediationMarkdownCell $a['Decision']),
                (ConvertTo-RemediationMarkdownCell $a['PrivilegeLabel']),
                (ConvertTo-RemediationMarkdownCell $a['AssignmentType']),
                $generated
            )
            [void]$sb.AppendLine('| ' + ($cells -join ' | ') + ' |')
        }
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## What a human still has to do')
    [void]$sb.AppendLine()
    if ($manual.Count -eq 0) {
        [void]$sb.AppendLine('Nothing was left for manual handling.')
    }
    else {
        foreach ($a in $manual) {
            $reason = if ($a['Kind'] -eq 'AppRole') {
                'App-role grants are emitted commented out — removing an app permission can break a live integration. Uncomment deliberately.'
            }
            else { [string]$a['Reason'] }
            [void]$sb.AppendLine("- **$(ConvertTo-RemediationComment $a['DisplayName']) <$(ConvertTo-RemediationComment $a['UserPrincipalName'])>** — $(ConvertTo-RemediationComment $a['Decision']). $(ConvertTo-RemediationComment $reason)")
            if ($a['Notes']) {
                [void]$sb.AppendLine("  - Reviewer notes: $(ConvertTo-RemediationComment $a['Notes'])")
            }
        }
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## Running it')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('```powershell')
    [void]$sb.AppendLine('Connect-MgGraph -Scopes RoleManagement.ReadWrite.Directory,Directory.ReadWrite.All')
    # The one line in this document that a reader is invited to paste into a
    # shell, so it is quoted by the same escaper the script uses rather than
    # by hand — a path holding any of the five single-quote delimiters would
    # otherwise end the literal and turn the rest of the path into commands.
    [void]$sb.AppendLine('cd ' + (ConvertTo-RemediationLiteral $Provenance['OutputDirectory']))
    [void]$sb.AppendLine("./$(ConvertTo-RemediationComment $Provenance['ScriptFileName'])            # dry run — changes nothing")
    [void]$sb.AppendLine("./$(ConvertTo-RemediationComment $Provenance['ScriptFileName']) -Execute   # apply")
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('The script refuses to run once the campaign is more than ' + $Provenance['StaleDays'] +
        ' days old unless `-Force` is passed, never removes the last Global Administrator, never touches an' +
        ' identity matching the break-glass patterns it prints at start-up, and appends every removal to' +
        ' `remediation-log-<utc>.json` before making it. It refuses `-Execute` outright if it cannot' +
        ' establish which identity is running it, because the self-exclusion check would otherwise be' +
        ' absent rather than passing.')
    [void]$sb.AppendLine()
    return $sb.ToString()
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function New-AccessReviewRemediationScript {
    <#
    .SYNOPSIS
        Generates a remediation script and a human-readable plan from a
        closed, hash-verified access-review campaign. Makes no Graph calls
        and no network calls.

    .DESCRIPTION
        Reads verification.json (who was decided, and how) and
        admins-baseline.json (what each principal holds, and by which
        mechanism), joins them on ObjectId, and writes:

          * remediate-<CampaignId>.ps1 — one block per action, each
            re-resolving current state at run time, defaulting to a dry run
            and requiring -Execute to act;
          * remediation-plan.md — counts, a per-principal table, and what
            still has to be done by hand.

        Refuses and writes nothing unless campaign.json says Status=Closed
        AND every file listed in manifest.json still hashes to its recorded
        SHA-256. The reviewer's sign-off over a sealed bundle IS the
        authorization; a tampered or half-written bundle produces nothing.

        Output lands in <campaign root>/remediation/<CampaignId>/ — a
        SIBLING of the campaign folder. Writing inside it would invalidate
        manifest.json or force a re-seal of a bundle that changed after
        sign-off; both destroy the evidence property.

        EntraChecks never applies these changes. Running the generated
        script is a deliberate human act.

    .PARAMETER CampaignDirectory
        A CLOSED campaign folder produced by Complete-AccessReviewCampaign.

    .PARAMETER OutputDirectory
        Where to write. Defaults to
        <parent of CampaignDirectory>/remediation/<CampaignId>.

    .PARAMETER IncludeRemediated
        Also generate actions for decisions whose verdict was already
        'Remediated'. By default only 'NotRemediated' rows produce actions.

    .PARAMETER StaleDays
        Age in days past which the GENERATED script refuses to run without
        -Force. Default 30.

    .OUTPUTS
        Hashtable: Success, FailureReason, ScriptPath, PlanPath,
        ActionCount, ManualCount, SkippedCount.

    .EXAMPLE
        New-AccessReviewRemediationScript -CampaignDirectory .\Output\AccessReview\2026-Q3-20260803-141500

        Generates the script and plan; applies nothing.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$CampaignDirectory,
        [string]$OutputDirectory = '',
        [switch]$IncludeRemediated,
        [int]$StaleDays = $script:DefaultStaleDays
    )

    # ----- 1. Integrity gate: nothing is generated from an unsealed bundle -----

    if (-not (Test-Path -LiteralPath $CampaignDirectory)) {
        return @{ Success = $false; FailureReason = "Campaign folder not found: $CampaignDirectory" }
    }
    $metaPath = Join-Path $CampaignDirectory 'campaign.json'
    if (-not (Test-Path -LiteralPath $metaPath)) {
        return @{ Success = $false; FailureReason = "Not a campaign folder (campaign.json missing): $CampaignDirectory" }
    }
    try {
        $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
    }
    catch {
        return @{ Success = $false; FailureReason = "campaign.json is unreadable: $($_.Exception.Message)" }
    }
    if ([string]$meta.Status -ne 'Closed') {
        return @{ Success = $false; FailureReason = "Campaign $($meta.CampaignId) has status '$($meta.Status)' — remediation can only be generated from a Closed campaign. The reviewer's sign-off is the authorization." }
    }

    $manifestPath = Join-Path $CampaignDirectory 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        return @{ Success = $false; FailureReason = "manifest.json missing — the campaign bundle cannot be verified, so nothing will be generated." }
    }
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    }
    catch {
        return @{ Success = $false; FailureReason = "manifest.json is unreadable: $($_.Exception.Message)" }
    }
    $integrity = Test-AccessReviewBundleIntegrity -CampaignDirectory $CampaignDirectory -Manifest $manifest
    if (-not $integrity.Valid) {
        return @{
            Success = $false
            FailureReason = "Campaign bundle failed SHA-256 verification — refusing to generate remediation from a tampered or incomplete bundle. $($integrity.Errors -join ' | ')"
            Errors = $integrity.Errors
        }
    }

    # ----- 2. Inputs -----

    $verificationPath = Join-Path $CampaignDirectory 'verification.json'
    $baselinePath = Join-Path $CampaignDirectory 'admins-baseline.json'
    foreach ($required in @($verificationPath, $baselinePath)) {
        if (-not (Test-Path -LiteralPath $required)) {
            return @{ Success = $false; FailureReason = "Required campaign artifact missing: $(Split-Path -Leaf $required)" }
        }
    }
    try {
        $verification = Get-Content -LiteralPath $verificationPath -Raw | ConvertFrom-Json
        $baseline = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
    }
    catch {
        return @{ Success = $false; FailureReason = "Campaign artifact is unreadable: $($_.Exception.Message)" }
    }

    $decisions = @($verification.Decisions)
    $roster = @($baseline.Roster)
    $inScope = if ($IncludeRemediated) { @('NotRemediated', 'Remediated') } else { @('NotRemediated') }

    # ----- 3. Join decisions with what each principal actually holds -----

    $plan = Get-RemediationActionList -Decisions $decisions -Roster $roster -InScopeVerdicts $inScope
    $actions = @($plan.Actions)

    # ----- 4. Provenance -----

    $campaignId = [string]$meta.CampaignId
    # CampaignId is read from campaign.json and then becomes a directory
    # name and a file name. The integrity gate proves the bundle is
    # self-consistent, not that nobody authored it - a resealed bundle
    # could carry '..\..\Startup' and steer both the output folder and
    # the script name outside the campaign root. Constrain it to what a
    # generated id can legitimately contain before it touches a path.
    if ($campaignId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
        return @{
            Success = $false
            FailureReason = "campaign.json CampaignId is not a usable identifier ('$campaignId'). Expected letters, digits, dot, underscore or hyphen."
        }
    }
    if (-not $OutputDirectory) {
        $campaignRoot = Split-Path -Parent (Convert-Path -LiteralPath $CampaignDirectory)
        $OutputDirectory = Join-Path (Join-Path $campaignRoot 'remediation') $campaignId
    }
    elseif (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
        # .NET file APIs below resolve relative paths against the process
        # working directory, which is not PowerShell's current location.
        $OutputDirectory = Join-Path (Get-Location).Path $OutputDirectory
    }
    $scriptFileName = "remediate-$campaignId.ps1"

    $provenance = @{}
    $provenance['CampaignId'] = $campaignId
    $provenance['TenantName'] = [string]$meta.TenantName
    $provenance['TenantId'] = [string]$meta.TenantId
    $provenance['BundleHash'] = [string]$manifest.BundleHash
    $provenance['ReviewerName'] = if ($meta.SignOff) { [string]$meta.SignOff.ReviewerName } else { '' }
    $provenance['ReviewerTitle'] = if ($meta.SignOff) { [string]$meta.SignOff.ReviewerTitle } else { '' }
    $provenance['SignOffDate'] = if ($meta.SignOff) { Format-RemediationTimestamp $meta.SignOff.SignOffDate } else { '' }
    $provenance['ClosedAtUtc'] = Format-RemediationTimestamp $meta.ClosedAtUtc
    $provenance['GeneratedAtUtc'] = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $provenance['ModuleVersion'] = $script:ModuleVersion
    $provenance['StaleDays'] = [string]$StaleDays
    $provenance['ScriptFileName'] = $scriptFileName
    $provenance['OutputDirectory'] = $OutputDirectory
    $provenance['ActionCount'] = [string]@($actions | Where-Object { $_['Kind'] -in @('Active', 'Eligible', 'Owner') }).Count
    $provenance['ManualCount'] = [string]@($actions | Where-Object { $_['Kind'] -in @('Manual', 'AppRole') }).Count

    # ----- 5. Render -----

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine((New-RemediationScriptPreamble -Provenance $provenance))
    if ($actions.Count -eq 0) {
        [void]$sb.AppendLine('Write-Host '' No in-scope decision produced an action — nothing to remediate.'' -ForegroundColor Green')
    }
    foreach ($action in $actions) {
        $block = switch ($action['Kind']) {
            'Active' { New-RemediationActiveBlock -Action $action }
            'Eligible' { New-RemediationEligibleBlock -Action $action }
            'Owner' { New-RemediationOwnerBlock -Action $action }
            'AppRole' { New-RemediationAppRoleBlock -Action $action }
            default { New-RemediationManualBlock -Action $action }
        }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine($block)
    }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine((New-RemediationScriptEpilogue))

    $markdown = New-RemediationPlanMarkdown -Provenance $provenance -Actions $actions `
        -SkippedCount ([int]$plan.SkippedCount) -DecisionCount $decisions.Count

    # ----- 6. Write, outside the sealed campaign folder -----

    $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
    $scriptPath = Join-Path $OutputDirectory $scriptFileName
    $planPath = Join-Path $OutputDirectory 'remediation-plan.md'

    # UTF-8 WITH BOM, written explicitly. Windows PowerShell 5.1 reads a
    # BOM-less file as ANSI and mangles every non-ASCII character in it —
    # including the em dashes in this script's own banners, which makes it
    # unparseable. Set-Content -Encoding UTF8 emits the BOM on 5.1 but NOT
    # on PowerShell 7, so a script generated on 7 would break on 5.1.
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($scriptPath, $sb.ToString(), $utf8Bom)
    [System.IO.File]::WriteAllText($planPath, $markdown, $utf8Bom)

    return @{
        Success = $true
        FailureReason = $null
        CampaignId = $campaignId
        OutputDirectory = $OutputDirectory
        ScriptPath = $scriptPath
        PlanPath = $planPath
        ActionCount = [int]$provenance['ActionCount']
        ManualCount = [int]$provenance['ManualCount']
        SkippedCount = [int]$plan.SkippedCount
        BundleHash = $provenance['BundleHash']
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'New-AccessReviewRemediationScript'
)

#endregion
