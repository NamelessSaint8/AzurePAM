<#
.SYNOPSIS
    Pester 5 test suite for access-review campaign close
    (PR 2 of the Access Review plan: worksheet ingest + verification delta).

.DESCRIPTION
    Exercises Complete-AccessReviewCampaign against fully-mocked Microsoft
    Graph. Covers:
    1. Worksheet validation: missing decisions, invalid decision values,
       incomplete sign-off, deleted rows — each refuses to close and the
       campaign stays Open with nothing written.
    2. Double-close refusal (Status gate).
    3. Clean close: all-certify + unchanged tenant -> Closed, sign-off
       embedded, final artifacts written, zero flags.
    4. Revoke with an observed privilege removal -> Remediated.
    5. Revoke with no observed change -> NOT_REMEDIATED flag.
    6. Account disable counts as remediation for a Revoke.
    7. Certified principal that changed anyway -> UNEXPLAINED_CHANGE flag.
    8. Investigate tolerates changes without flags.
    9. Refreshed manifest covers final artifacts + the completed worksheet.

    Run: Invoke-Pester -Path Tests/AccessReview-CampaignClose.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AccessReview.psm1') -Force -DisableNameChecking

    function New-MockEnv {
        [pscustomobject]@{
            IsAvailable = $true
            FailureReason = $null
            TenantId = 'tenant-0'
            Account = 'auditor@contoso.onmicrosoft.com'
            AuthType = 'Delegated'
            Scopes = @('Directory.Read.All', 'RoleManagement.Read.Directory')
        }
    }
    $script:MakeEnv = ${function:New-MockEnv}

    function New-BaselineUsers {
        @(
            @{
                id = 'user-priv-1'; displayName = 'Priv User'; userPrincipalName = 'priv@contoso.com'
                accountEnabled = $true; userType = 'Member'; createdDateTime = '2024-01-01T00:00:00Z'
                signInActivity = @{ lastSignInDateTime = '2026-07-30T10:00:00Z' }
            },
            @{
                id = 'user-2'; displayName = 'Normal User'; userPrincipalName = 'normal@contoso.com'
                accountEnabled = $true; userType = 'Member'; createdDateTime = '2024-02-01T00:00:00Z'
            },
            @{
                id = 'guest-1'; displayName = 'Guest User'; userPrincipalName = 'guest_ext#EXT#@contoso.com'
                accountEnabled = $true; userType = 'Guest'; createdDateTime = '2025-05-01T00:00:00Z'
            },
            @{
                id = 'disabled-1'; displayName = 'Disabled User'; userPrincipalName = 'gone@contoso.com'
                accountEnabled = $false; userType = 'Member'; createdDateTime = '2023-01-01T00:00:00Z'
            },
            @{
                id = 'disabled-priv-1'; displayName = 'Disabled Admin'; userPrincipalName = 'oldadmin@contoso.com'
                accountEnabled = $false; userType = 'Member'; createdDateTime = '2022-01-01T00:00:00Z'
            }
        )
    }
    $script:MakeUsers = ${function:New-BaselineUsers}

    function New-EntraRosterFixture {
        @{
            Available = $true
            FailureReason = $null
            Tenant = @{ TenantId = 'tenant-0'; Account = 'auditor@contoso.onmicrosoft.com'; AuthType = 'Delegated' }
            Roster = @(
                @{
                    ObjectId = 'user-priv-1'; PrincipalType = 'User'; Upn = 'priv@contoso.com'
                    DisplayName = 'Priv User'; Enabled = $true; LastSignIn = $null; HighestTier = 0
                    Privileges = @(@{ Key = 'Entra:GlobalAdministrator'; Path = @('Global Administrator (active)'); AssignmentType = 'Active' })
                    Sources = @('Active role assignment')
                },
                @{
                    ObjectId = 'disabled-priv-1'; PrincipalType = 'User'; Upn = 'oldadmin@contoso.com'
                    DisplayName = 'Disabled Admin'; Enabled = $false; LastSignIn = $null; HighestTier = 1
                    Privileges = @(@{ Key = 'Entra:HelpdeskAdministrator'; Path = @('Helpdesk Administrator (active)'); AssignmentType = 'Active' })
                    Sources = @('Active role assignment')
                },
                @{
                    ObjectId = 'sp-1'; PrincipalType = 'ServicePrincipal'; Upn = $null
                    DisplayName = 'Automation SP'; Enabled = $true; LastSignIn = $null; HighestTier = 0
                    Privileges = @(@{ Key = 'MSGraph:Directory.ReadWrite.All'; Path = @('App-role: Directory.ReadWrite.All granted on Microsoft Graph'); AssignmentType = 'AppRole' })
                    Sources = @('MS Graph app-role grant')
                }
            )
            Statistics = @{ TotalPrincipals = 3; PimAvailable = $true }
        }
    }
    $script:MakeRoster = ${function:New-EntraRosterFixture}

    # Fills the seeded worksheet like a human reviewer would: every access
    # row defaults to Certify unless overridden ('' leaves it blank), and
    # the sign-off footer rows get their Notes values.
    function Complete-TestWorksheet {
        param(
            [Parameter(Mandatory)][string]$Directory,
            [hashtable]$Decisions = @{},
            [string]$ReviewerName = 'Jane Reviewer',
            [string]$ReviewerTitle = 'CISO',
            [string]$SignOffDate = '2026-08-03',
            [string[]]$RemoveObjectIds = @()
        )
        $path = Join-Path $Directory 'review-worksheet.csv'
        $rows = @(Import-Csv -LiteralPath $path)
        $out = foreach ($r in $rows) {
            if ($r.RowType -eq 'Access') {
                if ($r.ObjectId -in $RemoveObjectIds) { continue }
                $r.Decision = if ($Decisions.ContainsKey($r.ObjectId)) { $Decisions[$r.ObjectId] } else { 'Certify' }
            }
            elseif ($r.RowType -eq 'SignOff') {
                $r.Notes = switch ($r.ObjectId) {
                    'ReviewerName' { $ReviewerName }
                    'ReviewerTitle' { $ReviewerTitle }
                    'SignOffDate' { $SignOffDate }
                }
            }
            $r
        }
        $out | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    }
    $script:FillWorksheet = ${function:Complete-TestWorksheet}
}

Describe 'Complete-AccessReviewCampaign' {

    BeforeEach {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeEnv
        }
        # The user pull reads whatever $script:CurrentUsers holds — tests
        # mutate it between open and close to simulate tenant changes.
        $script:CurrentUsers = & $script:MakeUsers
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            @{ value = $script:CurrentUsers }
        }

        $script:OutDir = Join-Path $TestDrive ("run-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $script:Campaign = New-AccessReviewCampaign -OutputDirectory $script:OutDir -TenantName 'Contoso' `
            -PeriodLabel '2026-Q3' -EntraRoster (& $script:MakeRoster)
        $script:Campaign.Success | Should -BeTrue
    }

    Context 'worksheet validation (campaign must stay Open)' {

        AfterEach {
            $meta = Get-Content (Join-Path $script:Campaign.Directory 'campaign.json') -Raw | ConvertFrom-Json
            $meta.Status | Should -Be 'Open'
            Test-Path (Join-Path $script:Campaign.Directory 'roster-final.json') | Should -BeFalse
        }

        It 'refuses when a decision is missing' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory -Decisions @{ 'user-2' = '' }
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $r.Success | Should -BeFalse
            $r.FailureReason | Should -Match 'no decision'
            $r.FailureReason | Should -Match 'normal@contoso.com'
        }

        It 'refuses invalid decision values' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory -Decisions @{ 'user-2' = 'Approve' }
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $r.Success | Should -BeFalse
            $r.FailureReason | Should -Match "Invalid decision 'Approve'"
        }

        It 'refuses when the sign-off is incomplete' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory -ReviewerName ''
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $r.Success | Should -BeFalse
            $r.FailureReason | Should -Match 'ReviewerName'
        }

        It 'refuses when access rows were deleted from the worksheet' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory -RemoveObjectIds @('guest-1')
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $r.Success | Should -BeFalse
            $r.FailureReason | Should -Match 'must not be added or removed'
        }
    }

    Context 'close + verification' {

        It 'closes cleanly with all-certify and an unchanged tenant' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $r.Success | Should -BeTrue
            $r.Status | Should -Be 'Closed'
            $r.Summary.NotRemediated | Should -Be 0
            $r.Summary.UnexplainedChanges | Should -Be 0
            $r.Summary.TotalChanges | Should -Be 0
            $r.Summary.Certified | Should -Be 5

            foreach ($f in 'roster-final.json', 'roster-final.csv', 'admins-final.json', 'admins-final.csv', 'verification.json') {
                Test-Path (Join-Path $r.Directory $f) | Should -BeTrue -Because "$f must exist"
            }
            $meta = Get-Content (Join-Path $r.Directory 'campaign.json') -Raw | ConvertFrom-Json
            $meta.Status | Should -Be 'Closed'
            $meta.ClosedAtUtc | Should -Not -BeNullOrEmpty
            $meta.SignOff.ReviewerName | Should -Be 'Jane Reviewer'
            $meta.SignOff.SignOffDate | Should -Be '2026-08-03'
            $meta.VerificationSummary.Certified | Should -Be 5
        }

        It 'refuses to close a campaign twice' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory
            (Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)).Success | Should -BeTrue
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $r.Success | Should -BeFalse
            $r.FailureReason | Should -Match 'only Open campaigns'
        }

        It 'marks a revoke with an observed privilege removal as Remediated' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory -Decisions @{ 'disabled-priv-1' = 'Revoke' }
            $final = & $script:MakeRoster
            $final.Roster = @($final.Roster | Where-Object { $_.ObjectId -ne 'disabled-priv-1' })
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster $final
            $r.Success | Should -BeTrue
            $r.Summary.Remediated | Should -Be 1
            $r.Summary.NotRemediated | Should -Be 0
            $verification = Get-Content (Join-Path $r.Directory 'verification.json') -Raw | ConvertFrom-Json
            $decision = $verification.Decisions | Where-Object { $_.ObjectId -eq 'disabled-priv-1' }
            $decision.Verdict | Should -Be 'Remediated'
            $decision.ObservedChanges | Should -Match 'PrivilegeRemoved'
        }

        It 'flags NOT_REMEDIATED when a revoke saw no change' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory -Decisions @{ 'sp-1' = 'Revoke' }
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $r.Success | Should -BeTrue
            $r.Summary.NotRemediated | Should -Be 1
            $flag = @($r.Flags) | Where-Object { $_.ObjectId -eq 'sp-1' }
            $flag.Flag | Should -Be 'NOT_REMEDIATED'
        }

        It 'counts an account disable as remediation for a revoke' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory -Decisions @{ 'user-2' = 'Revoke' }
            ($script:CurrentUsers | Where-Object { $_.id -eq 'user-2' })['accountEnabled'] = $false
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $r.Success | Should -BeTrue
            $r.Summary.Remediated | Should -Be 1
            $r.Summary.NotRemediated | Should -Be 0
            $r.Summary.UnexplainedChanges | Should -Be 0
        }

        It 'flags UNEXPLAINED_CHANGE when a certified account changes anyway' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory
            ($script:CurrentUsers | Where-Object { $_.id -eq 'user-2' })['accountEnabled'] = $false
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $r.Success | Should -BeTrue
            $r.Summary.UnexplainedChanges | Should -Be 1
            $flag = @($r.Flags) | Where-Object { $_.ObjectId -eq 'user-2' }
            $flag.Flag | Should -Be 'UNEXPLAINED_CHANGE'
            $verification = Get-Content (Join-Path $r.Directory 'verification.json') -Raw | ConvertFrom-Json
            ($verification.Decisions | Where-Object { $_.ObjectId -eq 'user-2' }).Verdict | Should -Be 'UnexplainedChange'
        }

        It 'lets Investigate tolerate changes without flags' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory -Decisions @{ 'user-2' = 'Investigate' }
            ($script:CurrentUsers | Where-Object { $_.id -eq 'user-2' })['accountEnabled'] = $false
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $r.Success | Should -BeTrue
            $r.Summary.UnexplainedChanges | Should -Be 0
            $r.Summary.NotRemediated | Should -Be 0
            $verification = Get-Content (Join-Path $r.Directory 'verification.json') -Raw | ConvertFrom-Json
            ($verification.Decisions | Where-Object { $_.ObjectId -eq 'user-2' }).Verdict | Should -Be 'Investigated'
        }

        It 'refreshes the manifest over final artifacts and the completed worksheet' {
            & $script:FillWorksheet -Directory $script:Campaign.Directory
            $r = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
            $manifest = Get-Content $r.ManifestPath -Raw | ConvertFrom-Json
            @($manifest.Files).Count | Should -Be 11
            @($manifest.Files | Where-Object { $_.RelativePath -eq 'verification.json' }).Count | Should -Be 1
            $wsEntry = $manifest.Files | Where-Object { $_.RelativePath -eq 'review-worksheet.csv' }
            $actual = (Get-FileHash -LiteralPath (Join-Path $r.Directory 'review-worksheet.csv') -Algorithm SHA256).Hash.ToLower()
            $actual | Should -Be $wsEntry.SHA256 -Because 'the completed worksheet (decisions + sign-off) must be covered by the refreshed hash chain'
        }
    }
}
