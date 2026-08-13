<#
.SYNOPSIS
    Pester 5 test suite for the access-review remediation script generator
    (PR 1 of the Access Review Remediation plan).

.DESCRIPTION
    Entirely fixture-driven: campaign bundles are built on disk in
    $TestDrive and read back. No tenant, no Graph, no network — which is
    the point, since the generator itself makes no calls.

    Covers:
    1. Integrity gate — an Open campaign and a hash mismatch each refuse
       and write nothing.
    2. Mapping — Active / Eligible (PIM) / Owner / AppRole / Unclassified
       each produce their own shape; Certify and Investigate produce none;
       Modify and non-privileged Revoke produce manual TODO blocks carrying
       the reviewer's Notes.
    3. Default scope — only NotRemediated acts; -IncludeRemediated widens.
    4. Guardrails — last-GA, break-glass, self-exclusion, rollback log.
    5. Safety posture — dry run by default, AppRole commented out.
    6. Output location — nothing written inside the campaign folder and the
       bundle still verifies against its original manifest afterwards.
    7. Syntax — the generated .ps1 parses, asserted in every mapping test.

    Run: Invoke-Pester -Path Tests/AccessReview-Remediation.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AccessReviewRemediation.psm1') -Force -DisableNameChecking

    # ---- fixture builders -------------------------------------------------

    function New-TestDecision {
        param(
            [Parameter(Mandatory)][string]$ObjectId,
            [string]$DisplayName = 'Test Principal',
            [string]$UserPrincipalName = 'test@contoso.com',
            [string]$PrincipalType = 'User',
            [string]$IsPrivileged = 'True',
            [string]$Decision = 'Revoke',
            [string]$Notes = '',
            [string]$Verdict = 'NotRemediated'
        )
        @{
            ObjectId = $ObjectId
            UserPrincipalName = $UserPrincipalName
            DisplayName = $DisplayName
            PrincipalType = $PrincipalType
            IsPrivileged = $IsPrivileged
            Decision = $Decision
            Notes = $Notes
            Verdict = $Verdict
            ObservedChanges = ''
        }
    }
    $script:MakeDecision = ${function:New-TestDecision}

    function New-TestRosterRow {
        param(
            [Parameter(Mandatory)][string]$ObjectId,
            [string]$DisplayName = 'Test Principal',
            [string]$Upn = 'test@contoso.com',
            [string]$PrincipalType = 'User',
            [object[]]$Privileges = @()
        )
        @{
            ObjectId = $ObjectId
            PrincipalType = $PrincipalType
            Upn = $Upn
            DisplayName = $DisplayName
            Enabled = $true
            LastSignIn = $null
            HighestTier = 0
            Privileges = @($Privileges)
            Sources = @('fixture')
        }
    }
    $script:MakeRosterRow = ${function:New-TestRosterRow}

    function New-TestPrivilege {
        param(
            [Parameter(Mandatory)][string]$Key,
            [Parameter(Mandatory)][string]$Label,
            [Parameter(Mandatory)][string]$AssignmentType,
            [string]$RoleDefinitionId = ''
        )
        $p = @{}
        $p['Key'] = $Key
        $p['Path'] = @($Label)
        $p['AssignmentType'] = $AssignmentType
        $p['DiscoveredAt'] = '2026-08-01T00:00:00.0000000Z'
        $p['Source'] = 'fixture'
        if ($RoleDefinitionId) { $p['RoleDefinitionId'] = $RoleDefinitionId }
        $p
    }
    $script:MakePrivilege = ${function:New-TestPrivilege}

    # Builds a campaign folder that looks exactly like one
    # Complete-AccessReviewCampaign produced: artifacts plus a manifest.json
    # whose SHA-256 entries cover every file.
    function New-TestCampaign {
        param(
            [Parameter(Mandatory)][string]$Root,
            [string]$CampaignId = '2026-Q3-20260801-120000',
            [string]$Status = 'Closed',
            [object[]]$Decisions = @(),
            [object[]]$Roster = @(),
            [string]$ClosedAtUtc = '',
            [switch]$SkipManifest
        )

        if (-not $ClosedAtUtc) { $ClosedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        $dir = Join-Path $Root $CampaignId
        $null = New-Item -Path $dir -ItemType Directory -Force

        $meta = [ordered]@{
            SchemaVersion = '1.0'
            CampaignId = $CampaignId
            PeriodLabel = '2026-Q3'
            Status = $Status
            GeneratedAtUtc = '2026-08-01T12:00:00Z'
            TenantId = 'tenant-0'
            TenantName = 'Contoso'
            EntraChecksVersion = '1.1.0'
            ClosedAtUtc = $ClosedAtUtc
            SignOff = [ordered]@{
                ReviewerName = 'Jane Reviewer'
                ReviewerTitle = 'CISO'
                SignOffDate = '2026-08-03'
            }
        }
        $meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $dir 'campaign.json') -Encoding UTF8

        [ordered]@{
            SchemaVersion = '1.0'
            CampaignId = $CampaignId
            GeneratedAtUtc = $ClosedAtUtc
            TenantId = 'tenant-0'
            Decisions = @($Decisions)
            Delta = @()
            Flags = @()
            Summary = [ordered]@{ Certified = 0; Revoked = @($Decisions).Count }
        } | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $dir 'verification.json') -Encoding UTF8

        @{
            Available = $true
            FailureReason = $null
            Roster = @($Roster)
            Statistics = @{ TotalPrincipals = @($Roster).Count }
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $dir 'admins-baseline.json') -Encoding UTF8

        'RowType,ObjectId,Decision,Notes' | Set-Content -LiteralPath (Join-Path $dir 'review-worksheet.csv') -Encoding UTF8

        if (-not $SkipManifest) {
            $entries = foreach ($f in (Get-ChildItem -LiteralPath $dir -File | Sort-Object Name)) {
                [ordered]@{
                    RelativePath = $f.Name
                    SHA256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
                }
            }
            $concat = (@($entries) | ForEach-Object { "$($_.RelativePath)|$($_.SHA256)" }) -join "`n"
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concat)) } finally { $sha.Dispose() }
            $bundleHash = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
            [ordered]@{
                SchemaVersion = '1.0'
                CampaignId = $CampaignId
                TenantId = 'tenant-0'
                HashAlgorithm = 'SHA256'
                BundleHash = $bundleHash
                Files = @($entries)
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $dir 'manifest.json') -Encoding UTF8
        }

        return $dir
    }
    $script:MakeCampaign = ${function:New-TestCampaign}

    # The assertion that matters most: a generator emitting unparseable
    # PowerShell fails at the worst possible moment.
    function Get-ScriptParseError {
        param([Parameter(Mandatory)][string]$Path)
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        return @($errors)
    }
    $script:ParseErrors = ${function:Get-ScriptParseError}

    function Test-ManifestStillValid {
        param([Parameter(Mandatory)][string]$Directory)
        $manifest = Get-Content -LiteralPath (Join-Path $Directory 'manifest.json') -Raw | ConvertFrom-Json
        foreach ($entry in @($manifest.Files)) {
            $p = Join-Path $Directory $entry.RelativePath
            if (-not (Test-Path -LiteralPath $p)) { return $false }
            if ((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() -ne $entry.SHA256) { return $false }
        }
        return $true
    }
    $script:VerifyBundle = ${function:Test-ManifestStillValid}

    # The assertion the parse-error count cannot make. 'It parses' is not a
    # safety property — an injected payload followed by '#' parses perfectly.
    # What matters is what the script would RUN, so look at the CommandAsts.
    function Get-GeneratedCommandName {
        param([Parameter(Mandatory)][string]$Path)
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        return @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } |
                Where-Object { $_ } |
                Sort-Object -Unique)
    }
    $script:GeneratedCommands = ${function:Get-GeneratedCommandName}

    # Pulls named function definitions back out of the GENERATED script so a
    # guardrail can be executed instead of grepped for. Greping the emitted
    # text proves the words are present, not that the check works.
    function Get-GeneratedFunctionSource {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][string[]]$Name
        )
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $found = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                Where-Object { $Name -contains $_.Name })
        return (@($found | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine)
    }
    $script:GeneratedFunction = ${function:Get-GeneratedFunctionSource}

    function Get-GeneratedIfStatement {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][string]$ConditionPattern
        )
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $matching = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] }, $true) |
                Where-Object { $_.Clauses[0].Item1.Extent.Text -match $ConditionPattern })
        return ($matching | Select-Object -First 1)
    }
    $script:GeneratedIf = ${function:Get-GeneratedIfStatement}

    # Same construction New-AccessReviewManifest uses, so a test can re-seal
    # a manifest it edited.
    function Get-TestBundleHash {
        param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries)
        $concat = (@($Entries) | ForEach-Object { "$($_.RelativePath)|$($_.SHA256)" }) -join "`n"
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concat)) } finally { $sha.Dispose() }
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    $script:BundleHash = ${function:Get-TestBundleHash}
}

Describe 'New-AccessReviewRemediationScript — integrity gate' {

    BeforeEach {
        $script:Root = Join-Path $TestDrive ('gate-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $script:Priv = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' -Label 'Helpdesk Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        $script:Decisions = @(& $script:MakeDecision -ObjectId 'u1' -DisplayName 'Alice Admin' -UserPrincipalName 'alice@contoso.com')
        $script:Roster = @(& $script:MakeRosterRow -ObjectId 'u1' -DisplayName 'Alice Admin' -Upn 'alice@contoso.com' -Privileges @($script:Priv))
    }

    It 'refuses an Open campaign and writes nothing' {
        $dir = & $script:MakeCampaign -Root $script:Root -Status 'Open' -Decisions $script:Decisions -Roster $script:Roster
        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match "status 'Open'"
        $r.FailureReason | Should -Match 'Closed campaign'
        Test-Path (Join-Path $script:Root 'remediation') | Should -BeFalse
    }

    It 'refuses when a campaign file changed after the manifest was sealed' {
        $dir = & $script:MakeCampaign -Root $script:Root -Decisions $script:Decisions -Roster $script:Roster
        # Tamper: rewrite a decision after the bundle was sealed.
        $v = Get-Content -LiteralPath (Join-Path $dir 'verification.json') -Raw
        ($v -replace 'alice@contoso.com', 'mallory@contoso.com') |
            Set-Content -LiteralPath (Join-Path $dir 'verification.json') -Encoding UTF8

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'SHA-256'
        $r.FailureReason | Should -Match 'verification.json'
        Test-Path (Join-Path $script:Root 'remediation') | Should -BeFalse
    }

    It 'refuses when an artifact covered by the manifest was deleted' {
        $dir = & $script:MakeCampaign -Root $script:Root -Decisions $script:Decisions -Roster $script:Roster
        Remove-Item -LiteralPath (Join-Path $dir 'review-worksheet.csv') -Force
        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'missing artifact'
        Test-Path (Join-Path $script:Root 'remediation') | Should -BeFalse
    }

    It 'refuses when there is no manifest at all' {
        $dir = & $script:MakeCampaign -Root $script:Root -Decisions $script:Decisions -Roster $script:Roster -SkipManifest
        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'manifest.json missing'
        Test-Path (Join-Path $script:Root 'remediation') | Should -BeFalse
    }

    It 'refuses a folder that is not a campaign' {
        $null = New-Item -Path $script:Root -ItemType Directory -Force
        $r = New-AccessReviewRemediationScript -CampaignDirectory $script:Root
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'campaign.json missing'
    }
}

Describe 'New-AccessReviewRemediationScript — the manifest must cover itself' {
    <#
        Hashing only the files a manifest chooses to list proves nothing
        about the choice. Removing an entry from Files[] un-covers that
        artifact, and the generator went on stamping the ORIGINAL BundleHash
        into the script and the plan as provenance — an artifact asserting
        an integrity property it no longer had.
    #>

    BeforeEach {
        $script:MRoot = Join-Path $TestDrive ('manifest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $priv = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' -Label 'Helpdesk Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        $script:MDir = & $script:MakeCampaign -Root $script:MRoot `
            -Decisions @(& $script:MakeDecision -ObjectId 'u1' -DisplayName 'Alice Admin' -UserPrincipalName 'alice@contoso.com') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u1' -DisplayName 'Alice Admin' -Upn 'alice@contoso.com' -Privileges @($priv))
        $script:MPath = Join-Path $script:MDir 'manifest.json'
    }

    It 'refuses when an entry was dropped from Files[] and the bundle hash left alone' {
        # The whole exploit: drop verification.json from the file list, then
        # rewrite it freely. Every remaining entry still verifies.
        $manifest = Get-Content -LiteralPath $script:MPath -Raw | ConvertFrom-Json
        $manifest.Files = @($manifest.Files | Where-Object { $_.RelativePath -ne 'verification.json' })
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:MPath -Encoding UTF8

        $v = Join-Path $script:MDir 'verification.json'
        ((Get-Content -LiteralPath $v -Raw) -replace 'Alice Admin', 'Mallory') |
            Set-Content -LiteralPath $v -Encoding UTF8

        $r = New-AccessReviewRemediationScript -CampaignDirectory $script:MDir
        $r.Success | Should -BeFalse -Because 'decisions no reviewer signed must not become removal commands'
        $r.FailureReason | Should -Match 'BundleHash mismatch'
        Test-Path (Join-Path $script:MRoot 'remediation') | Should -BeFalse
    }

    It 'refuses when a required artifact is uncovered even if the bundle hash is re-sealed' {
        # Re-seal after dropping the entry, so the hash chain is internally
        # consistent. Coverage of the three files the generator READS is a
        # separate property from the list hashing correctly.
        $manifest = Get-Content -LiteralPath $script:MPath -Raw | ConvertFrom-Json
        $kept = @($manifest.Files | Where-Object { $_.RelativePath -ne 'admins-baseline.json' })
        $manifest.Files = $kept
        $manifest.BundleHash = & $script:BundleHash -Entries $kept
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:MPath -Encoding UTF8

        $r = New-AccessReviewRemediationScript -CampaignDirectory $script:MDir
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'admins-baseline\.json is not covered by manifest\.json'
        $r.FailureReason | Should -Not -Match 'BundleHash mismatch'
    }

    It 'refuses a manifest that records no bundle hash at all' {
        $manifest = Get-Content -LiteralPath $script:MPath -Raw | ConvertFrom-Json
        $manifest.BundleHash = ''
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:MPath -Encoding UTF8

        $r = New-AccessReviewRemediationScript -CampaignDirectory $script:MDir
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'no BundleHash'
    }

    It 'still tolerates a file written after the manifest was sealed' {
        # Deliberate: New-AccessReviewReport writes the HTML after sealing.
        # Safe because the three artifacts this generator reads are all
        # required to be covered, so an extra file is something it never
        # opens.
        '<html></html>' | Set-Content -LiteralPath (Join-Path $script:MDir 'AccessReview-Report.html') -Encoding UTF8
        $r = New-AccessReviewRemediationScript -CampaignDirectory $script:MDir
        $r.Success | Should -BeTrue
    }
}

Describe 'New-AccessReviewRemediationScript — decision to action mapping' {

    BeforeEach {
        $script:Root = Join-Path $TestDrive ('map-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }

    It 'maps an Active assignment to a live-resolved role assignment removal' {
        $priv = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' -Label 'Helpdesk Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        $dir = & $script:MakeCampaign -Root $script:Root `
            -Decisions @(& $script:MakeDecision -ObjectId 'u1' -DisplayName 'Alice Admin' -UserPrincipalName 'alice@contoso.com') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u1' -DisplayName 'Alice Admin' -Upn 'alice@contoso.com' -Privileges @($priv))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 1
        $r.ManualCount | Should -Be 0

        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0 -Because 'the generated script must parse'
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match 'Get-CurrentRoleAssignment -PrincipalId ''u1'' -RoleDefinitionId ''729827e3-9c14-49f7-bb1b-9608f156bbb8'''
        $text | Should -Match "roleManagement/directory/roleAssignments/"
        $text | Should -Match "-Method 'DELETE'"
        $text | Should -Match 'already gone'
        $text | Should -Not -Match 'roleEligibilityScheduleRequests'
    }

    It 'maps a PIM eligibility to an AdminRemove eligibility request, not a role assignment delete' {
        $priv = & $script:MakePrivilege -Key 'Entra:SecurityAdministrator' -Label 'Security Administrator (PIM-eligible)' `
            -AssignmentType 'Eligible (PIM)' -RoleDefinitionId '194ae4cb-b126-40b2-bd5b-6091b380977d'
        $dir = & $script:MakeCampaign -Root $script:Root `
            -Decisions @(& $script:MakeDecision -ObjectId 'u2' -DisplayName 'Bob Eligible' -UserPrincipalName 'bob@contoso.com') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u2' -DisplayName 'Bob Eligible' -Upn 'bob@contoso.com' -Privileges @($priv))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 1

        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match 'Get-CurrentRoleEligibility -PrincipalId ''u2'''
        $text | Should -Match "action = 'AdminRemove'"
        $text | Should -Match 'roleEligibilityScheduleRequests'
        $text | Should -Match 'Add-RemediationLogEntry[\s\S]*?Eligible \(PIM\)'
        $text | Should -Not -Match 'Get-CurrentRoleAssignment -PrincipalId ''u2'''
    }

    It 'maps an Owner privilege to an ownership removal resolved by application name' {
        $priv = & $script:MakePrivilege -Key 'Entra:OwnerOfPrivilegedApp' `
            -Label "Owner of 'Automation SP' which holds privileged role/permission" -AssignmentType 'Owner'
        $dir = & $script:MakeCampaign -Root $script:Root `
            -Decisions @(& $script:MakeDecision -ObjectId 'u3' -DisplayName 'Carol Owner' -UserPrincipalName 'carol@contoso.com') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u3' -DisplayName 'Carol Owner' -Upn 'carol@contoso.com' -Privileges @($priv))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 1

        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match "Resolve-OwnedServicePrincipal -DisplayName 'Automation SP'"
        $text | Should -Match '/owners/'
        $text | Should -Match 'matches.*service principals'
    }

    It 'emits an AppRole grant commented out, with a live warning naming the service principal' {
        $priv = & $script:MakePrivilege -Key 'MSGraph:Directory.ReadWrite.All' `
            -Label 'App-role: Directory.ReadWrite.All granted on Microsoft Graph' -AssignmentType 'AppRole'
        $dir = & $script:MakeCampaign -Root $script:Root `
            -Decisions @(& $script:MakeDecision -ObjectId 'sp1' -DisplayName 'Legacy Sync SP' `
                -UserPrincipalName '' -PrincipalType 'ServicePrincipal') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'sp1' -DisplayName 'Legacy Sync SP' -Upn '' `
                -PrincipalType 'ServicePrincipal' -Privileges @($priv))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 0 -Because 'a commented-out block is not an automatic action'
        $r.ManualCount | Should -Be 1

        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match "Write-RemediationAppRoleWarning -Principal 'Legacy Sync SP'"
        $text | Should -Match 'UNCOMMENT DELIBERATELY'

        # Every line that would perform the removal must be commented out
        # (the shared helper DEFINITIONS in the preamble are inert on their own).
        $live = @(Get-Content -LiteralPath $r.ScriptPath |
                Where-Object { $_ -match 'Get-CurrentAppRoleGrant -PrincipalId|Invoke-RemediationChange -Method' -and $_ -notmatch '^\s*#' })
        $live.Count | Should -Be 0 -Because 'app-role removals ship inert'
    }

    It 'maps an Unclassified privilege to a manual TODO rather than guessing' {
        $priv = & $script:MakePrivilege -Key 'Entra:Other:Mystery' -Label 'Some unmapped grant' -AssignmentType 'Unclassified'
        $dir = & $script:MakeCampaign -Root $script:Root `
            -Decisions @(& $script:MakeDecision -ObjectId 'u4' -DisplayName 'Dan Unknown' -UserPrincipalName 'dan@contoso.com' `
                -Notes 'Left the company, remove everything') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u4' -DisplayName 'Dan Unknown' -Upn 'dan@contoso.com' -Privileges @($priv))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 0
        $r.ManualCount | Should -Be 1

        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match '# TODO'
        $text | Should -Match 'Left the company, remove everything'
        $text | Should -Not -Match 'Invoke-RemediationChange -Method'
    }

    It 'produces nothing for Certify and Investigate decisions' {
        $priv = & $script:MakePrivilege -Key 'Entra:GlobalAdministrator' -Label 'Global Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '62e90394-69f5-4237-9190-012177145e10'
        $decisions = @(
            (& $script:MakeDecision -ObjectId 'u5' -Decision 'Certify' -Verdict 'Certified'),
            (& $script:MakeDecision -ObjectId 'u6' -Decision 'Investigate' -Verdict 'Investigated'))
        $roster = @(
            (& $script:MakeRosterRow -ObjectId 'u5' -Privileges @($priv)),
            (& $script:MakeRosterRow -ObjectId 'u6' -Privileges @($priv)))
        $dir = & $script:MakeCampaign -Root $script:Root -Decisions $decisions -Roster $roster

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 0
        $r.ManualCount | Should -Be 0
        $r.SkippedCount | Should -Be 2

        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match 'No in-scope decision produced an action'
        $text | Should -Not -Match 'Test-RemediationGuardrail -ObjectId'
    }

    It 'turns a Modify decision into a manual TODO carrying the reviewer note verbatim' {
        $priv = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' -Label 'Helpdesk Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        $note = 'Downgrade to Helpdesk Reader only; keep ticket access'
        $dir = & $script:MakeCampaign -Root $script:Root `
            -Decisions @(& $script:MakeDecision -ObjectId 'u7' -Decision 'Modify' -DisplayName 'Erin Modify' `
                -UserPrincipalName 'erin@contoso.com' -Notes $note) `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u7' -DisplayName 'Erin Modify' -Upn 'erin@contoso.com' -Privileges @($priv))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 0
        $r.ManualCount | Should -Be 1

        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match '# TODO'
        $text | Should -Match ([regex]::Escape($note))
        $text | Should -Match 'does not say WHAT to modify'
        $text | Should -Not -Match 'Get-CurrentRoleAssignment -PrincipalId'
    }

    It 'turns a Revoke on a principal with no privileges into a manual TODO carrying the note' {
        $note = 'Contractor finished 2026-07-31'
        $dir = & $script:MakeCampaign -Root $script:Root `
            -Decisions @(& $script:MakeDecision -ObjectId 'u8' -DisplayName 'Frank Contractor' `
                -UserPrincipalName 'frank@contoso.com' -IsPrivileged 'False' -Notes $note) `
            -Roster @()

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 0
        $r.ManualCount | Should -Be 1

        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match '# TODO'
        $text | Should -Match ([regex]::Escape($note))
        $text | Should -Match 'disabling or deleting the account'
    }

    It 'emits one block per privilege when a principal holds several' {
        $active = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' -Label 'Helpdesk Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        $eligible = & $script:MakePrivilege -Key 'Entra:SecurityAdministrator' -Label 'Security Administrator (PIM-eligible)' `
            -AssignmentType 'Eligible (PIM)' -RoleDefinitionId '194ae4cb-b126-40b2-bd5b-6091b380977d'
        $dir = & $script:MakeCampaign -Root $script:Root `
            -Decisions @(& $script:MakeDecision -ObjectId 'u9' -DisplayName 'Gina Multi' -UserPrincipalName 'gina@contoso.com') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u9' -DisplayName 'Gina Multi' -Upn 'gina@contoso.com' `
                -Privileges @($active, $eligible))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 2
        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0
    }
}

Describe 'New-AccessReviewRemediationScript — scope' {

    BeforeEach {
        $script:Root = Join-Path $TestDrive ('scope-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $priv = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' -Label 'Helpdesk Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        $decisions = @(
            (& $script:MakeDecision -ObjectId 'not-done' -DisplayName 'Not Done' -UserPrincipalName 'nd@contoso.com' -Verdict 'NotRemediated'),
            (& $script:MakeDecision -ObjectId 'already' -DisplayName 'Already Done' -UserPrincipalName 'ad@contoso.com' -Verdict 'Remediated'))
        $roster = @(
            (& $script:MakeRosterRow -ObjectId 'not-done' -DisplayName 'Not Done' -Upn 'nd@contoso.com' -Privileges @($priv)),
            (& $script:MakeRosterRow -ObjectId 'already' -DisplayName 'Already Done' -Upn 'ad@contoso.com' -Privileges @($priv)))
        $script:Dir = & $script:MakeCampaign -Root $script:Root -Decisions $decisions -Roster $roster
    }

    It 'acts only on NotRemediated rows by default' {
        $r = New-AccessReviewRemediationScript -CampaignDirectory $script:Dir
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 1
        $r.SkippedCount | Should -Be 1
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match 'not-done'
        $text | Should -Not -Match "'already'"
        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0
    }

    It 'widens to Remediated rows with -IncludeRemediated' {
        $r = New-AccessReviewRemediationScript -CampaignDirectory $script:Dir -IncludeRemediated `
            -OutputDirectory (Join-Path $script:Root 'wide')
        $r.Success | Should -BeTrue
        $r.ActionCount | Should -Be 2
        $r.SkippedCount | Should -Be 0
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match "'already'"
        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0
    }
}

Describe 'New-AccessReviewRemediationScript — generated script safety' {

    BeforeAll {
        $script:SafetyRoot = Join-Path $TestDrive 'safety'
        $ga = & $script:MakePrivilege -Key 'Entra:GlobalAdministrator' -Label 'Global Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '62e90394-69f5-4237-9190-012177145e10'
        $script:SafetyDir = & $script:MakeCampaign -Root $script:SafetyRoot `
            -Decisions @(& $script:MakeDecision -ObjectId 'ga-1' -DisplayName 'Hank Admin' -UserPrincipalName 'hank@contoso.com') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'ga-1' -DisplayName 'Hank Admin' -Upn 'hank@contoso.com' -Privileges @($ga))
        $script:SafetyResult = New-AccessReviewRemediationScript -CampaignDirectory $script:SafetyDir -StaleDays 45
        $script:SafetyText = Get-Content -LiteralPath $script:SafetyResult.ScriptPath -Raw
    }

    It 'generates a script that parses' {
        (& $script:ParseErrors -Path $script:SafetyResult.ScriptPath).Count | Should -Be 0
    }

    It 'writes the script as UTF-8 with a BOM so Windows PowerShell 5.1 can parse it' {
        # Without the BOM, 5.1 reads the file as ANSI and mangles every
        # em dash in the banners — the script stops parsing.
        $bytes = [System.IO.File]::ReadAllBytes($script:SafetyResult.ScriptPath)
        @($bytes[0], $bytes[1], $bytes[2]) | Should -Be @(0xEF, 0xBB, 0xBF)
    }

    It 'defaults to a dry run and requires -Execute to act' {
        $script:SafetyText | Should -Match '\[switch\]\$Execute'
        $script:SafetyText | Should -Match 'if \(-not \$Execute\)'
        $script:SafetyText | Should -Match '\[WhatIf\] would'
        $script:SafetyText | Should -Match 'Re-run with -Execute to apply'
    }

    It 'refuses to remove the last Global Administrator, counted live' {
        $script:SafetyText | Should -Match 'refusing to remove the last Global Administrator'
        $script:SafetyText | Should -Match 'Get-GlobalAdministratorCount'
        # The GA privilege must actually arm the guardrail on this action.
        $script:SafetyText | Should -Match 'Test-RemediationGuardrail[^\r\n]*-IsGlobalAdministrator'
    }

    It 'refuses to touch a break-glass account' {
        $script:SafetyText | Should -Match 'break-glass access is never removed by this script'
        $script:SafetyText | Should -Match 'SOC2.BreakGlassAccounts'
        $script:SafetyText | Should -Match 'AccountUpnPatterns'
    }

    It 'refuses to act on the identity running the script' {
        $script:SafetyText | Should -Match 'refusing to remove your own access'
        $script:SafetyText | Should -Match '\$script:RunnerObjectId'
        $script:SafetyText | Should -Match '\$script:RunnerUpn'
    }

    It 'writes the rollback record before every removal' {
        $script:SafetyText | Should -Match 'remediation-log-'
        $script:SafetyText | Should -Match 'Add-RemediationLogEntry'
        # The log write must precede the change call in each block.
        $logIndex = $script:SafetyText.IndexOf('Add-RemediationLogEntry -ObjectId')
        $changeIndex = $script:SafetyText.IndexOf('Invoke-RemediationChange -Method')
        $logIndex | Should -BeGreaterThan 0
        $changeIndex | Should -BeGreaterThan $logIndex
    }

    It 'refuses to run on a stale campaign unless -Force is passed' {
        $script:SafetyText | Should -Match '\[switch\]\$Force'
        $script:SafetyText | Should -Match '\$script:StaleDays = 45'
        $script:SafetyText | Should -Match 'ageDays -gt \$script:StaleDays -and -not \$Force'
    }

    It 'stamps the campaign close time as ISO-8601 UTC' {
        # ConvertFrom-Json hands back a [datetime]; [string] on that would
        # yield a culture-formatted LOCAL date and skew the staleness check.
        $script:SafetyText | Should -Match '\$script:ClosedAtUtc = ''\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z'''
        $script:SafetyText | Should -Match 'Campaign closed  : \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z'
    }

    It 're-resolves current state instead of trusting a captured assignment id' {
        $script:SafetyText | Should -Match 'NEVER taken from the campaign'
        $script:SafetyText | Should -Match 'Get-CurrentRoleAssignment -PrincipalId'
        $script:SafetyText | Should -Match 'already gone — nothing to do'
    }

    It 'carries provenance and states that EntraChecks did not apply the changes' {
        $script:SafetyText | Should -Match ([regex]::Escape($script:SafetyResult.CampaignId))
        $script:SafetyText | Should -Match ([regex]::Escape($script:SafetyResult.BundleHash))
        $script:SafetyText | Should -Match 'Jane Reviewer'
        $script:SafetyText | Should -Match 'CISO'
        $script:SafetyText | Should -Match '2026-08-03'
        $script:SafetyText | Should -Match 'Script generated :'
        $script:SafetyText | Should -Match 'did NOT apply these changes'
    }
}

Describe 'New-AccessReviewRemediationScript — guardrails that actually guard' {
    <#
        These execute the generated guardrails instead of grepping the
        emitted text for their wording. The break-glass test at line 532
        passed against a build where the pattern list was empty on every
        shipped config, which is what a text assertion buys you.
    #>

    BeforeAll {
        $script:GRoot = Join-Path $TestDrive 'guard'
        $ga = & $script:MakePrivilege -Key 'Entra:GlobalAdministrator' -Label 'Global Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '62e90394-69f5-4237-9190-012177145e10'
        $dir = & $script:MakeCampaign -Root $script:GRoot `
            -Decisions @(& $script:MakeDecision -ObjectId 'ga-1' -DisplayName 'Hank Admin' -UserPrincipalName 'hank@contoso.com') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'ga-1' -DisplayName 'Hank Admin' -Upn 'hank@contoso.com' -Privileges @($ga))
        $script:GResult = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $script:GText = Get-Content -LiteralPath $script:GResult.ScriptPath -Raw

        # A config shaped exactly like the shipped one: the break-glass key
        # the guardrail reads exists and is EMPTY.
        $script:StockConfig = Join-Path $TestDrive 'stock-entrachecks.config.json'
        @{
            SOC2 = @{
                AzureReadiness = @{
                    BreakGlass = @{ MinimumAccounts = 2; AccountUpnPatterns = @() }
                }
            }
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:StockConfig -Encoding UTF8
    }

    It 'protects break-glass accounts on a stock config, where no pattern is configured' {
        . ([scriptblock]::Create((& $script:GeneratedFunction -Path $script:GResult.ScriptPath -Name 'Get-BreakGlassPattern')))
        $patterns = @(Get-BreakGlassPattern -Path $script:StockConfig)

        $patterns.Count | Should -BeGreaterThan 0 -Because 'an empty pattern list protects nothing while claiming to'
        foreach ($upn in @('breakglass01@contoso.com', 'break-glass@contoso.com', 'emergency-access-1@contoso.com')) {
            @($patterns | Where-Object { $upn -like $_ }).Count |
                Should -BeGreaterThan 0 -Because "$upn is a conventional emergency-access name"
        }
    }

    It 'adds configured patterns to the built-in ones rather than replacing them' {
        $custom = Join-Path $TestDrive 'custom-entrachecks.config.json'
        @{
            SOC2 = @{
                AzureReadiness = @{ BreakGlass = @{ AccountUpnPatterns = @('svc-recovery-*@contoso.com') } }
            }
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $custom -Encoding UTF8

        . ([scriptblock]::Create((& $script:GeneratedFunction -Path $script:GResult.ScriptPath -Name 'Get-BreakGlassPattern')))
        $patterns = @(Get-BreakGlassPattern -Path $custom)
        $patterns | Should -Contain 'svc-recovery-*@contoso.com'
        @($patterns | Where-Object { 'breakglass01@contoso.com' -like $_ }).Count | Should -BeGreaterThan 0
    }

    It 'refuses a break-glass principal when the guardrail is actually run' {
        . ([scriptblock]::Create((& $script:GeneratedFunction -Path $script:GResult.ScriptPath `
                        -Name 'Get-BreakGlassPattern', 'Test-RemediationGuardrail', 'Write-RemediationRefused')))
        $script:RunnerObjectId = 'someone-else'
        $script:RunnerUpn = 'operator@contoso.com'
        $script:RunnerIdentified = $true
        $script:RefusedCount = 0
        $script:BreakGlassAccounts = @(Get-BreakGlassPattern -Path $script:StockConfig)

        $allowed = Test-RemediationGuardrail -ObjectId 'bg-1' -DisplayName 'Break Glass 01' `
            -UserPrincipalName 'breakglass01@contoso.com' -Privilege 'Global Administrator (active)' 6>$null
        $allowed | Should -BeFalse -Because 'break-glass access is never removed by this script'
        $script:RefusedCount | Should -Be 1

        $ordinary = Test-RemediationGuardrail -ObjectId 'u9' -DisplayName 'Ordinary Admin' `
            -UserPrincipalName 'ordinary@contoso.com' -Privilege 'Helpdesk Administrator (active)' 6>$null
        $ordinary | Should -BeTrue -Because 'the default patterns must not refuse everything'
    }

    It 'stops rather than run with a break-glass list that protects nothing' {
        $branch = & $script:GeneratedIf -Path $script:GResult.ScriptPath -ConditionPattern 'BreakGlassAccounts\.Count -eq 0'
        $branch | Should -Not -BeNullOrEmpty
        $branch.Clauses[0].Item2.Extent.Text | Should -Match 'exit 1'
    }

    It 'names every break-glass pattern it will protect before doing anything' {
        $script:GText | Should -Match 'foreach \(\$pattern in \$script:BreakGlassAccounts\)'
        $script:GText | Should -Match 'is NEVER touched'
    }

    It 'resolves its own identity under app-only auth, where /me does not exist' {
        $script:GText | Should -Match ([regex]::Escape("servicePrincipals(appId='"))
        $script:GText | Should -Match '\$script:RunnerIdentified'
    }

    It 'refuses -Execute when it cannot establish which identity is running' {
        # Anchored: the per-action note inside Test-RemediationGuardrail
        # tests '-not $script:RunnerIdentified' and comes first in the file.
        $branch = & $script:GeneratedIf -Path $script:GResult.ScriptPath -ConditionPattern '^\$script:RunnerIdentified$'
        $branch | Should -Not -BeNullOrEmpty
        $branch.ElseClause | Should -Not -BeNullOrEmpty
        $branch.ElseClause.Extent.Text | Should -Match 'if \(\$Execute\)'
        $branch.ElseClause.Extent.Text | Should -Match 'exit 1'
        # A dry run continues, loudly — it changes nothing, and finishing it
        # shows the operator both the plan and the degradation.
        $branch.ElseClause.Extent.Text | Should -Match 'DRY RUN only'
    }

    It 'says per action that it cannot confirm the target is not the runner' {
        . ([scriptblock]::Create((& $script:GeneratedFunction -Path $script:GResult.ScriptPath `
                        -Name 'Test-RemediationGuardrail', 'Write-RemediationRefused')))
        $script:RunnerObjectId = ''
        $script:RunnerUpn = ''
        $script:RunnerIdentified = $false
        $script:BreakGlassAccounts = @()

        $out = Test-RemediationGuardrail -ObjectId 'u9' -DisplayName 'Ordinary Admin' `
            -UserPrincipalName 'ordinary@contoso.com' -Privilege 'Helpdesk Administrator (active)' 6>&1
        ($out | Out-String) | Should -Match 'running identity is UNKNOWN'
    }
}

Describe 'New-AccessReviewRemediationScript — output location and plan' {

    BeforeAll {
        $script:OutRoot = Join-Path $TestDrive 'outloc'
        $priv = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' -Label 'Helpdesk Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        $decisions = @(
            (& $script:MakeDecision -ObjectId 'u1' -DisplayName 'Iris Admin' -UserPrincipalName 'iris@contoso.com'),
            (& $script:MakeDecision -ObjectId 'u2' -DisplayName 'Jack Manual' -UserPrincipalName 'jack@contoso.com' -Decision 'Modify' -Notes 'Reduce to read-only'))
        $roster = @(
            (& $script:MakeRosterRow -ObjectId 'u1' -DisplayName 'Iris Admin' -Upn 'iris@contoso.com' -Privileges @($priv)),
            (& $script:MakeRosterRow -ObjectId 'u2' -DisplayName 'Jack Manual' -Upn 'jack@contoso.com' -Privileges @($priv)))
        $script:OutDir = & $script:MakeCampaign -Root $script:OutRoot -Decisions $decisions -Roster $roster
        $script:BeforeFiles = @(Get-ChildItem -LiteralPath $script:OutDir -File | ForEach-Object { $_.Name } | Sort-Object)
        $script:OutResult = New-AccessReviewRemediationScript -CampaignDirectory $script:OutDir
    }

    It 'writes to a sibling remediation folder, never inside the campaign' {
        $script:OutResult.Success | Should -BeTrue
        $expected = Join-Path (Join-Path $script:OutRoot 'remediation') (Split-Path -Leaf $script:OutDir)
        (Resolve-Path -LiteralPath $script:OutResult.OutputDirectory).Path |
            Should -Be (Resolve-Path -LiteralPath $expected).Path
        $script:OutResult.ScriptPath | Should -Match 'remediate-.*\.ps1$'
        Test-Path $script:OutResult.ScriptPath | Should -BeTrue
        Test-Path $script:OutResult.PlanPath | Should -BeTrue
    }

    It 'writes nothing inside the campaign folder' {
        $after = @(Get-ChildItem -LiteralPath $script:OutDir -Recurse | ForEach-Object { $_.Name } | Sort-Object)
        ($after -join '|') | Should -Be ($script:BeforeFiles -join '|')
    }

    It 'leaves the campaign bundle verifying against its original manifest' {
        (& $script:VerifyBundle -Directory $script:OutDir) | Should -BeTrue
    }

    It 'writes a human-readable plan with counts and the manual work called out' {
        $md = Get-Content -LiteralPath $script:OutResult.PlanPath -Raw
        $md | Should -Match '# Remediation plan'
        $md | Should -Match 'EntraChecks did not apply any of these changes'
        $md | Should -Match 'Automatic removals generated \| 1'
        $md | Should -Match 'Manual / commented-out blocks \| 1'
        $md | Should -Match 'Iris Admin'
        $md | Should -Match 'Remove active role assignment'
        $md | Should -Match 'Reduce to read-only'
        $md | Should -Match 'Jane Reviewer'
        $md | Should -Match 'Campaign closed \| \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z'
    }

    It 'is idempotent — regenerating overwrites in place' {
        $again = New-AccessReviewRemediationScript -CampaignDirectory $script:OutDir
        $again.Success | Should -BeTrue
        $again.ScriptPath | Should -Be $script:OutResult.ScriptPath
        (& $script:ParseErrors -Path $again.ScriptPath).Count | Should -Be 0
        (& $script:VerifyBundle -Directory $script:OutDir) | Should -BeTrue
    }
}

Describe 'New-AccessReviewRemediationScript — hostile input' {

    It 'cannot be broken out of by a reviewer note containing quotes or a comment terminator' {
        $root = Join-Path $TestDrive 'hostile'
        $priv = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' -Label 'Helpdesk Administrator (active)' `
            -AssignmentType 'Active' -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        $nasty = "it's a test #> `$(Write-Host pwned) '; Remove-Item C:\ -Recurse"
        $dir = & $script:MakeCampaign -Root $root `
            -Decisions @(& $script:MakeDecision -ObjectId 'u1' -DisplayName "O'Brien #>" `
                -UserPrincipalName "o'brien@contoso.com" -Decision 'Modify' -Notes $nasty) `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u1' -DisplayName "O'Brien #>" -Upn "o'brien@contoso.com" -Privileges @($priv))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0 -Because 'hostile notes must not break the generated script'

        # Parse the result and look at what it would actually RUN: the note
        # must survive as inert text, never as a command.
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($r.ScriptPath, [ref]$tokens, [ref]$errors)
        $commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() })
        $commands | Should -Not -Contain 'Remove-Item'
        $commands | Should -Not -Contain 'Write-Host pwned'
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match ([regex]::Escape("it's a test"))
    }
}

Describe 'New-AccessReviewRemediationScript — line terminators in attacker-controlled text' {
    <#
        DisplayName is directory data any user or invited guest can set on
        themselves; Notes is free text round-tripped through
        review-worksheet.csv with no validation. Both land in a '#' comment
        banner ABOVE every guardrail and OUTSIDE the -Execute branch, so a
        single character that ends a line there executes on a plain dry run.

        These tests assert on the AST, never on the parse-error count: a
        payload followed by '#' parses cleanly, which is exactly how this
        got through review the first time.

        Measured, not assumed: of the seven characters below only CR and LF
        actually end a '#' comment for [Parser]::ParseInput, so only those
        two rows fail against the pre-fix generator. The other five are
        pinned because they DO break a line in editors, terminals and diff
        viewers — leaving them in lets the script a human reviews differ
        from the script that runs, and this whole design rests on the
        operator reading the file first. Do not delete the passing rows
        thinking they are redundant; they are the read-versus-run pin and
        the guard against a parser that widens the set later.
    #>

    BeforeAll {
        $script:TermPayload = 'Start-Process calc.exe #'

        function New-TerminatorCampaign {
            param(
                [Parameter(Mandatory)][string]$Root,
                [Parameter(Mandatory)][AllowEmptyString()][string]$Injected
            )
            $priv = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' `
                -Label 'Helpdesk Administrator (active)' -AssignmentType 'Active' `
                -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
            $name = 'Mallory' + $Injected
            $notes = 'reviewed' + $Injected
            return (& $script:MakeCampaign -Root $Root `
                    -Decisions @(& $script:MakeDecision -ObjectId 'u1' -DisplayName $name `
                        -UserPrincipalName 'mallory@contoso.com' -Notes $notes) `
                    -Roster @(& $script:MakeRosterRow -ObjectId 'u1' -DisplayName $name `
                        -Upn 'mallory@contoso.com' -Privileges @($priv)))
        }
        $script:MakeTerminatorCampaign = ${function:New-TerminatorCampaign}

        # The command vocabulary a CLEAN campaign of this exact shape emits.
        # Anything a hostile fixture adds to it is injected code.
        $benignDir = & $script:MakeTerminatorCampaign -Root (Join-Path $TestDrive 'term-benign') -Injected ''
        $benign = New-AccessReviewRemediationScript -CampaignDirectory $benignDir
        $script:BenignCommands = @(& $script:GeneratedCommands -Path $benign.ScriptPath)
    }

    It 'keeps an injected payload inert when <Label> is smuggled into DisplayName and Notes' -ForEach @(
        @{ Label = 'CR (U+000D)'; Code = 0x000D }
        @{ Label = 'LF (U+000A)'; Code = 0x000A }
        @{ Label = 'NEL (U+0085)'; Code = 0x0085 }
        @{ Label = 'LINE SEPARATOR (U+2028)'; Code = 0x2028 }
        @{ Label = 'PARAGRAPH SEPARATOR (U+2029)'; Code = 0x2029 }
        @{ Label = 'vertical tab (U+000B)'; Code = 0x000B }
        @{ Label = 'form feed (U+000C)'; Code = 0x000C }
    ) {
        $root = Join-Path $TestDrive ('term-' + $Code.ToString('x4'))
        $dir = & $script:MakeTerminatorCampaign -Root $root -Injected ([char]$Code + $script:TermPayload)

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue

        $commands = @(& $script:GeneratedCommands -Path $r.ScriptPath)
        $commands | Should -Not -Contain 'Start-Process' -Because "$Label must not end the comment line"
        @($commands | Where-Object { $script:BenignCommands -notcontains $_ }) |
            Should -BeNullOrEmpty -Because 'a hostile fixture must emit no command a clean one does not'
    }

    It 'strips NUL and other control characters rather than passing them through' {
        # NUL is stripped, not substituted: it truncates the string in
        # several downstream consumers, and removing it leaves nothing to
        # re-interpret. Stripping happens BEFORE escaping, so it cannot
        # create a block-comment terminator either.
        $injected = [char]0x00 + $script:TermPayload + [char]0x07 + [char]0x1B + '[31m' + [char]0x202E
        $dir = & $script:MakeTerminatorCampaign -Root (Join-Path $TestDrive 'term-nul') -Injected $injected

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue

        $raw = [System.IO.File]::ReadAllText($r.ScriptPath)
        ([regex]::Matches($raw, '[\p{Cc}\p{Cf}-[\t\r\n]]')).Count |
            Should -Be 0 -Because 'no control or format character may reach the generated script'
        @(& $script:GeneratedCommands -Path $r.ScriptPath) | Should -Not -Contain 'Start-Process'
    }

    It 'flattens every terminator at once, in one fixture, without adding a command' {
        $all = -join (@(0x000D, 0x000A, 0x0085, 0x2028, 0x2029, 0x000B, 0x000C) |
                ForEach-Object { [char]$_ + $script:TermPayload })
        $dir = & $script:MakeTerminatorCampaign -Root (Join-Path $TestDrive 'term-all') -Injected $all

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue

        $commands = @(& $script:GeneratedCommands -Path $r.ScriptPath)
        $commands | Should -Not -Contain 'Start-Process'
        @($commands | Where-Object { $script:BenignCommands -notcontains $_ }) | Should -BeNullOrEmpty

        # The note still has to reach the operator — defanged, not deleted.
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match 'Reviewer notes: reviewed'
    }
}

Describe 'New-AccessReviewRemediationScript — template tokens in attacker-controlled text' {
    <#
        Sequential String.Replace over {{NAME}}, {{UPN}}, {{LABEL}}, {{NOTES}}
        rescans its own output: a display name of '{{NOTES}}' is substituted
        first, then the {{NOTES}} pass expands INSIDE it, splicing an
        already-quoted literal into another quoted literal and terminating
        the string. Substitution has to stop rescanning; reordering the
        passes cannot fix it.
    #>

    BeforeAll {
        $script:TokenRoot = Join-Path $TestDrive 'token'
        $script:TokenPriv = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' `
            -Label 'Helpdesk Administrator (active)' -AssignmentType 'Active' `
            -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
    }

    It 'does not re-expand a display name that is itself a template token' {
        $notes = "x'; Start-Process calc.exe; #"
        $dir = & $script:MakeCampaign -Root (Join-Path $script:TokenRoot 'notes') `
            -Decisions @(& $script:MakeDecision -ObjectId 'u1' -DisplayName '{{NOTES}}' `
                -UserPrincipalName 'mallory@contoso.com' -Decision 'Modify' -Notes $notes) `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u1' -DisplayName '{{NOTES}}' `
                -Upn 'mallory@contoso.com' -Privileges @($script:TokenPriv))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue

        @(& $script:GeneratedCommands -Path $r.ScriptPath) |
            Should -Not -Contain 'Start-Process' -Because 'a substituted value must never be substituted into'
        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0

        # The name survives verbatim, as inert text inside the literal.
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match ([regex]::Escape("-Principal '{{NOTES}}'"))
    }

    It 'does not corrupt the script when a display name merely contains a token' {
        # No payload at all — the un-fixed ordering alone produced 18 parse
        # errors here, i.e. a remediation artifact that cannot be run.
        $dir = & $script:MakeCampaign -Root (Join-Path $script:TokenRoot 'label') `
            -Decisions @(& $script:MakeDecision -ObjectId 'u1' -DisplayName 'Mallory {{LABEL}}' `
                -UserPrincipalName 'mallory@contoso.com') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u1' -DisplayName 'Mallory {{LABEL}}' `
                -Upn 'mallory@contoso.com' -Privileges @($script:TokenPriv))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        (& $script:ParseErrors -Path $r.ScriptPath).Count |
            Should -Be 0 -Because 'a token in a display name must not break the generated script'
        $text = Get-Content -LiteralPath $r.ScriptPath -Raw
        $text | Should -Match ([regex]::Escape("-Principal 'Mallory {{LABEL}}'"))
    }

    It 'expands unknown tokens to nothing but leaves them visible' {
        # An unknown token stays verbatim rather than blanking, so a typo in
        # a template shows up instead of silently emitting an empty argument.
        $dir = & $script:MakeCampaign -Root (Join-Path $script:TokenRoot 'unknown') `
            -Decisions @(& $script:MakeDecision -ObjectId 'u1' -DisplayName '{{NOPE}}' `
                -UserPrincipalName 'mallory@contoso.com') `
            -Roster @(& $script:MakeRosterRow -ObjectId 'u1' -DisplayName '{{NOPE}}' `
                -Upn 'mallory@contoso.com' -Privileges @($script:TokenPriv))

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        (Get-Content -LiteralPath $r.ScriptPath -Raw) | Should -Match ([regex]::Escape("'{{NOPE}}'"))
    }
}

Describe 'New-AccessReviewRemediationScript — quote delimiters in attacker-controlled text' {
    <#
        ConvertTo-RemediationLiteral wraps every attacker-influenceable value
        in a literal opened with an ASCII apostrophe. The tokenizer does not
        agree that ASCII is the only way to CLOSE one: U+2018, U+2019, U+201A
        and U+201B end it just as readily. DisplayName is directory data any
        user or invited guest can set on themselves and a curly apostrophe in
        a name is unremarkable — which is exactly what makes it a clean way
        out of the literal and into a script an operator runs with Privileged
        Role Administrator rights.

        The set is MEASURED, not copied from a doc page. 'the delimiter set is
        exactly what the live parser accepts' below re-derives it from
        [Parser] on whichever edition is running, so an edition that adds a
        sixth delimiter fails here rather than in a customer's generated
        script. U+2032 PRIME is in the fixtures on purpose as a look-alike
        that is NOT a delimiter: over-escaping would show the reviewer a name
        that is not the name in the directory, and the reviewer reading the
        file before running it is the whole control.

        Assertions are on the AST, never on the parse-error count — the
        payloads here end in '#', so a successful injection parses perfectly.
    #>

    BeforeAll {
        $script:QuotePayload = '; Start-Process calc.exe; #'
        $script:QuoteDelimiters = @(0x0027, 0x2018, 0x2019, 0x201A, 0x201B)

        function New-QuoteCampaign {
            param(
                [Parameter(Mandatory)][string]$Root,
                [Parameter(Mandatory)][AllowEmptyString()][string]$Injected
            )
            $priv = & $script:MakePrivilege -Key 'Entra:HelpdeskAdministrator' `
                -Label 'Helpdesk Administrator (active)' -AssignmentType 'Active' `
                -RoleDefinitionId '729827e3-9c14-49f7-bb1b-9608f156bbb8'
            $name = 'Mallory' + $Injected
            $upn = 'mallory' + $Injected + '@contoso.com'
            $notes = 'reviewed' + $Injected
            return (& $script:MakeCampaign -Root $Root `
                    -Decisions @(& $script:MakeDecision -ObjectId 'u1' -DisplayName $name `
                        -UserPrincipalName $upn -Notes $notes) `
                    -Roster @(& $script:MakeRosterRow -ObjectId 'u1' -DisplayName $name `
                        -Upn $upn -Privileges @($priv)))
        }
        $script:MakeQuoteCampaign = ${function:New-QuoteCampaign}

        # The command vocabulary a CLEAN campaign of this exact shape emits.
        # Anything a hostile fixture adds to it is injected code.
        $benignDir = & $script:MakeQuoteCampaign -Root (Join-Path $TestDrive 'quote-benign') -Injected ''
        $benign = New-AccessReviewRemediationScript -CampaignDirectory $benignDir
        $script:QuoteBenignCommands = @(& $script:GeneratedCommands -Path $benign.ScriptPath)
    }

    It 'keeps an injected payload inert when <Label> is smuggled into DisplayName, UPN and Notes' -ForEach @(
        @{ Label = 'APOSTROPHE (U+0027)'; Code = 0x0027 }
        @{ Label = 'LEFT SINGLE QUOTATION MARK (U+2018)'; Code = 0x2018 }
        @{ Label = 'RIGHT SINGLE QUOTATION MARK (U+2019)'; Code = 0x2019 }
        @{ Label = 'SINGLE LOW-9 QUOTATION MARK (U+201A)'; Code = 0x201A }
        @{ Label = 'SINGLE HIGH-REVERSED-9 QUOTATION MARK (U+201B)'; Code = 0x201B }
    ) {
        $root = Join-Path $TestDrive ('quote-' + $Code.ToString('x4'))
        $dir = & $script:MakeQuoteCampaign -Root $root -Injected ([char]$Code + $script:QuotePayload)

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue

        $commands = @(& $script:GeneratedCommands -Path $r.ScriptPath)
        $commands | Should -Not -Contain 'Start-Process' -Because "$Label must not close the generated literal"
        @($commands | Where-Object { $script:QuoteBenignCommands -notcontains $_ }) |
            Should -BeNullOrEmpty -Because 'a hostile fixture must emit no command a clean one does not'
    }

    It 'lands every attacker-controlled value in a single-quoted literal and nowhere else' {
        # One fixture carrying all five single-quote delimiters, the whole
        # double-quote family, and the '$' and backtick that make a
        # double-quoted string expand.
        #
        # The load-bearing assertion is structural rather than another payload
        # hunt: if the marker only ever appears inside SingleQuoted string
        # constants, then no expandable string, here-string or bareword path
        # exists for it to escape through — including paths no fixture here
        # thought to try. That is the invariant the escaper's whole design
        # rests on, so it is asserted directly instead of inferred.
        #
        # Each delimiter is separated by an ordinary letter on purpose. Two
        # delimiters side by side ARE the escape sequence, so a run of them
        # pairs off and slips past even a broken escaper — a fixture that
        # concatenates the set proves nothing. Isolating each one is what
        # makes this fail against the pre-fix escaper.
        $marker = 'ZZMARKERZZ'
        $hostileChars = @($script:QuoteDelimiters) + @(0x0022, 0x201C, 0x201D, 0x201E, 0x201F, 0x2032, 0x2033)
        $injected = $marker
        foreach ($cp in $hostileChars) { $injected += [char]$cp + 'x' }
        $injected += '$(Start-Process calc.exe)' + [char]0x60 + $script:QuotePayload
        $dir = & $script:MakeQuoteCampaign -Root (Join-Path $TestDrive 'quote-all') -Injected $injected

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue

        $commands = @(& $script:GeneratedCommands -Path $r.ScriptPath)
        $commands | Should -Not -Contain 'Start-Process'
        @($commands | Where-Object { $script:QuoteBenignCommands -notcontains $_ }) | Should -BeNullOrEmpty

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($r.ScriptPath, [ref]$tokens, [ref]$errors)

        $carriers = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) |
                Where-Object { $_.Value -like "*$marker*" })
        $carriers.Count | Should -BeGreaterThan 0 -Because 'the value still has to reach the operator'

        # WHOLE, not merely present. A literal that a delimiter closed early
        # still leaves a single-quoted node carrying the front of the value,
        # so 'the marker is in a single-quoted string' passes against a broken
        # escaper. Only the full round trip proves nothing closed it.
        @($carriers | Where-Object { $_.Value -eq ('Mallory' + $injected) }) |
            Should -Not -BeNullOrEmpty -Because 'a literal that stops early stopped because something closed it'
        @($carriers | Where-Object { $_.StringConstantType -ne [System.Management.Automation.Language.StringConstantType]::SingleQuoted }) |
            Should -BeNullOrEmpty -Because 'a bareword, a double-quoted string or a here-string would each be a way out'
        $expandable = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true) |
                Where-Object { $_.Extent.Text -like "*$marker*" })
        $expandable | Should -BeNullOrEmpty -Because 'no attacker value may land anywhere $(...) expands'
    }

    It 'the delimiter set is exactly what the live parser accepts' {
        # Re-derives the set from the parser actually running this suite, the
        # same way the shipped set was derived: put the character inside a
        # literal opened with an ASCII apostrophe and see whether it comes
        # back out intact.
        #
        # Scoped to the ASCII, General Punctuation, dingbat-quote,
        # CJK-punctuation and halfwidth/fullwidth neighbourhoods. The full
        # 65,536-code-point sweep that produced the shipped set takes about
        # three minutes per edition and does not belong in a suite; it lives
        # in the comment above $script:SingleQuoteDelimiterPattern, which is
        # what to re-run if this ever fails.
        $candidates = @(0x0000..0x00FF) + @(0x2000..0x20FF) + @(0x2700..0x27BF) + @(0x3000..0x301F) + @(0xFF00..0xFFFF)
        $measured = foreach ($cp in $candidates) {
            $probe = 'A' + [char]$cp + 'B'
            $e = $null
            $t = $null
            $a = [System.Management.Automation.Language.Parser]::ParseInput(
                ('$x = ' + [char]0x27 + $probe + [char]0x27), [ref]$t, [ref]$e)
            $strings = if ($e.Count -eq 0) {
                @($a.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true))
            }
            else { @() }
            if ($strings.Count -ne 1 -or $strings[0].Value -ne $probe) { $cp }
        }

        @($measured) | Should -Not -BeNullOrEmpty -Because 'the apostrophe itself is in range, so an empty result means the probe broke'
        $declared = & (Get-Module EntraChecks-AccessReviewRemediation) { $script:SingleQuoteDelimiterPattern }
        $uncovered = @($measured | Where-Object { ([string][char]$_) -notmatch $declared } |
                ForEach-Object { 'U+{0:X4}' -f $_ })
        $uncovered | Should -BeNullOrEmpty -Because 'the escaper must double every delimiter this parser accepts'
    }

    It 'leaves quote look-alikes that are not delimiters verbatim' {
        # U+2032 PRIME and U+2033 DOUBLE PRIME read like quotes and are not
        # delimiters; U+201C-U+201F close a DOUBLE-quoted string, which the
        # generator never wraps these values in. Doubling any of them would
        # hand the reviewer a name that is not the name in the directory.
        $lookalikes = -join (@(0x2032, 0x2033, 0x201C, 0x201D, 0x201E, 0x201F) | ForEach-Object { [char]$_ })
        $dir = & $script:MakeQuoteCampaign -Root (Join-Path $TestDrive 'quote-lookalike') -Injected $lookalikes

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir
        $r.Success | Should -BeTrue
        (& $script:ParseErrors -Path $r.ScriptPath).Count | Should -Be 0

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($r.ScriptPath, [ref]$tokens, [ref]$errors)
        $intact = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) |
                Where-Object { $_.Value -eq ('Mallory' + $lookalikes) })
        $intact | Should -Not -BeNullOrEmpty -Because 'a character that is not a delimiter must reach the script unchanged'
    }

    It 'quotes the paste-me path in the plan even when the folder name holds a delimiter' {
        # The 'cd' line in remediation-plan.md is the one line the document
        # invites a human to paste into a shell, so it is built by the same
        # escaper rather than by hand-wrapping the path in apostrophes.
        $dir = & $script:MakeQuoteCampaign -Root (Join-Path $TestDrive 'quote-plan') -Injected ''
        $out = Join-Path $TestDrive ('out' + [char]0x2019 + '; Start-Process calc.exe; #')

        $r = New-AccessReviewRemediationScript -CampaignDirectory $dir -OutputDirectory $out
        $r.Success | Should -BeTrue

        $cdLine = @(Get-Content -LiteralPath $r.PlanPath | Where-Object { $_ -like 'cd *' })
        $cdLine.Count | Should -Be 1

        $e = $null
        $t = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($cdLine[0], [ref]$t, [ref]$e)
        $e.Count | Should -Be 0
        $commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
        $commands.Count | Should -Be 1
        $commands[0].GetCommandName() | Should -Be 'cd'
        $arg = $commands[0].CommandElements[1]
        $arg.StringConstantType | Should -Be ([System.Management.Automation.Language.StringConstantType]::SingleQuoted)
        $arg.Value | Should -Be $out
    }
}
