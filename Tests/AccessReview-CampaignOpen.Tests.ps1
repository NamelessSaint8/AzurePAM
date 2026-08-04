<#
.SYNOPSIS
    Pester 5 test suite for the access-review campaign module
    (PR 1 of the Access Review plan: roster generation + campaign open).

.DESCRIPTION
    Exercises Get-AccessReviewRoster / New-AccessReviewCampaign /
    Get-AccessReviewCampaign against fully-mocked Microsoft Graph. Covers:
    1. Graceful failure when no Graph context exists.
    2. All-user roster via beta endpoint with signInActivity.
    3. Fallback to v1.0 when beta fails (SignInDataAvailable=$false).
    4. Total enumeration failure -> Available=$false.
    5. Campaign open writes all artifacts + manifest.
    6. Worksheet scope: disabled non-privileged excluded, disabled
       privileged INCLUDED, guests toggleable, SPs present, admins first.
    7. Sign-off footer rows present with expected field names.
    8. Fail-closed when the privileged roster is unavailable.
    9. Manifest hashes verify against the files on disk.
   10. Campaign listing returns the open campaign.

    Run: Invoke-Pester -Path Tests/AccessReview-CampaignOpen.Tests.ps1
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

    function New-BetaUsersPage {
        @{
            value = @(
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
    }
    $script:MakeBetaPage = ${function:New-BetaUsersPage}

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
}

Describe 'New-AccessReviewCampaign — environment gating' {

    It 'fails with FailureReason when no Graph context exists' {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            [pscustomobject]@{ IsAvailable = $false; FailureReason = 'No Microsoft Graph context.' }
        }
        $r = New-AccessReviewCampaign -OutputDirectory (Join-Path $TestDrive 'gate')
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'Graph context'
        Test-Path (Join-Path $TestDrive 'gate') | Should -BeFalse
    }
}

Describe 'Get-AccessReviewRoster' {

    It 'returns all users with sign-in data from the beta endpoint' {
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeBetaPage
        }
        $r = Get-AccessReviewRoster
        $r.Available | Should -BeTrue
        $r.SignInDataAvailable | Should -BeTrue
        @($r.Users).Count | Should -Be 5
        $priv = @($r.Users) | Where-Object { $_.ObjectId -eq 'user-priv-1' }
        $priv.LastSignIn | Should -Be '2026-07-30T10:00:00Z'
        $normal = @($r.Users) | Where-Object { $_.ObjectId -eq 'user-2' }
        $normal.LastSignIn | Should -Be ''
    }

    It 'falls back to v1.0 without sign-in data when beta fails' {
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            if ($Uri -like '*graph.microsoft.com/beta/*') { throw 'beta not permitted' }
            $page = & $script:MakeBetaPage
            foreach ($u in $page.value) { $u.Remove('signInActivity') }
            $page
        }
        $r = Get-AccessReviewRoster
        $r.Available | Should -BeTrue
        $r.SignInDataAvailable | Should -BeFalse
        @($r.Users).Count | Should -Be 5
        (@($r.Users) | Where-Object { $_.ObjectId -eq 'user-priv-1' }).LastSignIn | Should -Be ''
    }

    It 'returns Available=$false when both endpoints fail' {
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            throw 'total outage'
        }
        $r = Get-AccessReviewRoster
        $r.Available | Should -BeFalse
        $r.FailureReason | Should -Match 'total outage'
    }
}

Describe 'New-AccessReviewCampaign — artifacts' {

    BeforeEach {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeEnv
        }
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeBetaPage
        }
        $script:OutDir = Join-Path $TestDrive ("run-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }

    It 'writes all campaign artifacts and returns Success' {
        $r = New-AccessReviewCampaign -OutputDirectory $script:OutDir -TenantName 'Contoso' `
            -PeriodLabel '2026-Q3' -EntraRoster (& $script:MakeRoster)
        $r.Success | Should -BeTrue
        $r.CampaignId | Should -Match '^2026-Q3-\d{8}-\d{6}$'
        foreach ($f in 'campaign.json', 'roster-baseline.json', 'roster-baseline.csv',
            'admins-baseline.json', 'admins-baseline.csv', 'review-worksheet.csv', 'manifest.json') {
            Test-Path (Join-Path $r.Directory $f) | Should -BeTrue -Because "$f must exist"
        }
    }

    It 'stamps system-generation evidence into campaign.json' {
        $r = New-AccessReviewCampaign -OutputDirectory $script:OutDir -TenantName 'Contoso' `
            -PeriodLabel '2026-Q3' -EntraRoster (& $script:MakeRoster)
        $meta = Get-Content (Join-Path $r.Directory 'campaign.json') -Raw | ConvertFrom-Json
        $meta.Status | Should -Be 'Open'
        $meta.TenantId | Should -Be 'tenant-0'
        $meta.TenantName | Should -Be 'Contoso'
        $meta.GeneratedBy.Account | Should -Be 'auditor@contoso.onmicrosoft.com'
        $meta.GeneratedBy.AuthType | Should -Be 'Delegated'
        $meta.EntraChecksVersion | Should -Not -BeNullOrEmpty
        $meta.RunId | Should -Match '^[0-9a-f-]{36}$'
        $meta.Counts.TotalUsers | Should -Be 5
        $meta.Counts.Guests | Should -Be 1
        $meta.Counts.DisabledUsers | Should -Be 2
        $meta.Counts.PrivilegedPrincipals | Should -Be 3
    }

    It 'seeds the worksheet with admins first, SPs included, disabled non-privileged excluded' {
        $r = New-AccessReviewCampaign -OutputDirectory $script:OutDir `
            -PeriodLabel '2026-Q3' -EntraRoster (& $script:MakeRoster)
        $rows = @(Import-Csv (Join-Path $r.Directory 'review-worksheet.csv'))
        $access = @($rows | Where-Object { $_.RowType -eq 'Access' })

        # priv user + disabled priv + normal user + guest + SP = 5; disabled-1 excluded
        $access.Count | Should -Be 5
        $access.ObjectId | Should -Not -Contain 'disabled-1'
        $access.ObjectId | Should -Contain 'disabled-priv-1'
        $access.ObjectId | Should -Contain 'sp-1'
        $access.ObjectId | Should -Contain 'guest-1'

        # Privileged rows sort before non-privileged rows
        $firstThree = $access[0..2]
        ($firstThree | ForEach-Object { $_.IsPrivileged }) | Should -Not -Contain 'False'

        $privRow = $access | Where-Object { $_.ObjectId -eq 'user-priv-1' }
        $privRow.IsPrivileged | Should -Be 'True'
        $privRow.HighestTier | Should -Be 'Tier 0'
        $privRow.Roles | Should -Match 'Global Administrator'

        $spRow = $access | Where-Object { $_.ObjectId -eq 'sp-1' }
        $spRow.PrincipalType | Should -Be 'ServicePrincipal'
        $spRow.Roles | Should -Match 'Directory\.ReadWrite\.All'

        # Every access row starts undecided
        ($access | Where-Object { $_.Decision -ne '' }).Count | Should -Be 0
    }

    It 'appends the three sign-off footer rows' {
        $r = New-AccessReviewCampaign -OutputDirectory $script:OutDir `
            -PeriodLabel '2026-Q3' -EntraRoster (& $script:MakeRoster)
        $rows = @(Import-Csv (Join-Path $r.Directory 'review-worksheet.csv'))
        $signOff = @($rows | Where-Object { $_.RowType -eq 'SignOff' })
        $signOff.Count | Should -Be 3
        $signOff.ObjectId | Should -Be @('ReviewerName', 'ReviewerTitle', 'SignOffDate')
        # Footer rows follow all access rows
        $rows[-3..-1].RowType | Should -Be @('SignOff', 'SignOff', 'SignOff')
    }

    It 'excludes guests from the worksheet when IncludeGuests is false but keeps them in the roster' {
        $r = New-AccessReviewCampaign -OutputDirectory $script:OutDir `
            -PeriodLabel '2026-Q3' -IncludeGuests $false -EntraRoster (& $script:MakeRoster)
        $worksheet = @(Import-Csv (Join-Path $r.Directory 'review-worksheet.csv') |
                Where-Object { $_.RowType -eq 'Access' })
        $worksheet.ObjectId | Should -Not -Contain 'guest-1'
        $roster = @(Import-Csv (Join-Path $r.Directory 'roster-baseline.csv'))
        $roster.ObjectId | Should -Contain 'guest-1'
    }

    It 'defaults the period label to the current quarter' {
        $r = New-AccessReviewCampaign -OutputDirectory $script:OutDir -EntraRoster (& $script:MakeRoster)
        $r.CampaignId | Should -Match '^\d{4}-Q[1-4]-\d{8}-\d{6}$'
    }

    It 'fails closed when the privileged roster is unavailable' {
        $r = New-AccessReviewCampaign -OutputDirectory $script:OutDir `
            -EntraRoster @{ Available = $false; FailureReason = 'No Graph context'; Roster = @() }
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'administrators'
        Test-Path $script:OutDir | Should -BeFalse
    }

    It 'writes a manifest whose hashes verify against the files on disk' {
        $r = New-AccessReviewCampaign -OutputDirectory $script:OutDir `
            -PeriodLabel '2026-Q3' -EntraRoster (& $script:MakeRoster)
        $manifest = Get-Content $r.ManifestPath -Raw | ConvertFrom-Json
        $manifest.HashAlgorithm | Should -Be 'SHA256'
        $manifest.BundleHash | Should -Match '^[0-9a-f]{64}$'
        @($manifest.Files).Count | Should -Be 6
        foreach ($entry in $manifest.Files) {
            $path = Join-Path $r.Directory $entry.RelativePath
            $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
            $actual | Should -Be $entry.SHA256 -Because "$($entry.RelativePath) must match its manifest hash"
        }
    }

    It 'lists the open campaign via Get-AccessReviewCampaign' {
        $r = New-AccessReviewCampaign -OutputDirectory $script:OutDir `
            -PeriodLabel '2026-Q3' -EntraRoster (& $script:MakeRoster)
        $list = @(Get-AccessReviewCampaign -OutputDirectory $script:OutDir)
        $list.Count | Should -Be 1
        $list[0].CampaignId | Should -Be $r.CampaignId
        $list[0].Status | Should -Be 'Open'
    }
}
