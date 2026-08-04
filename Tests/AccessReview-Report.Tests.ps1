<#
.SYNOPSIS
    Pester 5 test suite for the access-review report renderer and the
    SOC 2 evidence-matrix reference (PR 3 of the Access Review plan).

.DESCRIPTION
    Covers:
    1. Closed campaign renders all seven report sections, no DRAFT banner.
    2. Cover carries system-generation evidence (tenant, principal,
       version, bundle hash).
    3. Administrators section lists privileged users AND service
       principals with their decisions.
    4. No-changes close renders the explicit "no changes required" and
       "baseline remains list of record" statements.
    5. Changes render the delta table plus NOT_REMEDIATED /
       UNEXPLAINED_CHANGE flag rows, and the updated-list table.
    6. Open campaign renders DRAFT banner + pending sign-off.
    7. Tenant data is HTML-encoded (script injection in a display name).
    8. MaxUserRows caps the users table with a truncation note.
    9. Get-SOC2EvidenceMatrix cites the latest closed campaign as
       CC6.1-CC6.3 evidence when -AccessReviewDirectory is passed, and
       adds nothing when it is omitted.

    Run: Invoke-Pester -Path Tests/AccessReview-Report.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AccessReview.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AccessReviewReport.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2Reporting.psm1') -Force -DisableNameChecking

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
                id = 'xss-1'; displayName = '<script>alert(1)</script>'; userPrincipalName = 'xss@contoso.com'
                accountEnabled = $true; userType = 'Member'; createdDateTime = '2025-06-01T00:00:00Z'
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

    function Complete-TestWorksheet {
        param(
            [Parameter(Mandatory)][string]$Directory,
            [hashtable]$Decisions = @{}
        )
        $path = Join-Path $Directory 'review-worksheet.csv'
        $rows = @(Import-Csv -LiteralPath $path)
        foreach ($r in $rows) {
            if ($r.RowType -eq 'Access') {
                $r.Decision = if ($Decisions.ContainsKey($r.ObjectId)) { $Decisions[$r.ObjectId] } else { 'Certify' }
            }
            elseif ($r.RowType -eq 'SignOff') {
                $r.Notes = switch ($r.ObjectId) {
                    'ReviewerName' { 'Jane Reviewer' }
                    'ReviewerTitle' { 'CISO' }
                    'SignOffDate' { '2026-08-04' }
                }
            }
        }
        $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    }
    $script:FillWorksheet = ${function:Complete-TestWorksheet}
}

Describe 'New-AccessReviewReport' {

    BeforeEach {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeEnv
        }
        $script:CurrentUsers = & $script:MakeUsers
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            @{ value = $script:CurrentUsers }
        }
        $script:OutDir = Join-Path $TestDrive ("run-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $script:Campaign = New-AccessReviewCampaign -OutputDirectory $script:OutDir -TenantName 'Contoso' `
            -PeriodLabel '2026-Q3' -EntraRoster (& $script:MakeRoster)
        $script:Campaign.Success | Should -BeTrue
    }

    It 'renders all seven sections for a closed campaign with no DRAFT banner' {
        & $script:FillWorksheet -Directory $script:Campaign.Directory
        $null = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
        $r = New-AccessReviewReport -CampaignDirectory $script:Campaign.Directory
        $r.Success | Should -BeTrue
        $r.IsDraft | Should -BeFalse
        $html = Get-Content $r.ReportPath -Raw
        foreach ($id in 'cover', 'summary', 'admins', 'users', 'changes', 'updated', 'signoff') {
            $html | Should -Match "id=""$id""" -Because "section $id must render"
        }
        # The stylesheet always defines .ar-draft-banner; absence of the
        # rendered element means no class="ar-draft-banner" div.
        $html | Should -Not -Match 'class="ar-draft-banner"'
    }

    It 'carries system-generation evidence and sign-off on the cover and sign-off sections' {
        & $script:FillWorksheet -Directory $script:Campaign.Directory
        $null = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
        $r = New-AccessReviewReport -CampaignDirectory $script:Campaign.Directory
        $html = Get-Content $r.ReportPath -Raw
        $html | Should -Match 'tenant-0'
        $html | Should -Match 'auditor@contoso\.onmicrosoft\.com'
        $html | Should -Match 'EntraChecks AccessReview v'
        $html | Should -Match 'Jane Reviewer'
        $html | Should -Match '2026-08-04'
        # Worksheet + bundle hashes render as 64-char hex
        $html | Should -Match '[0-9a-f]{64}'
    }

    It 'lists privileged users and service principals with decisions in the admins section' {
        & $script:FillWorksheet -Directory $script:Campaign.Directory -Decisions @{ 'sp-1' = 'Investigate' }
        $null = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
        $r = New-AccessReviewReport -CampaignDirectory $script:Campaign.Directory
        $html = Get-Content $r.ReportPath -Raw
        $adminsSection = ($html -split 'id="admins"')[1] -split 'id="users"' | Select-Object -First 1
        $adminsSection | Should -Match 'Priv User'
        $adminsSection | Should -Match 'Automation SP'
        $adminsSection | Should -Match 'Investigate'
        $adminsSection | Should -Match 'Tier 0'
    }

    It 'states no-changes explicitly when the review required none' {
        & $script:FillWorksheet -Directory $script:Campaign.Directory
        $null = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
        $r = New-AccessReviewReport -CampaignDirectory $script:Campaign.Directory
        $html = Get-Content $r.ReportPath -Raw
        $html | Should -Match 'No access changes were required'
        $html | Should -Match 'baseline user list above remains the list of record'
    }

    It 'renders the delta, flags, and updated list when changes occurred' {
        & $script:FillWorksheet -Directory $script:Campaign.Directory -Decisions @{ 'sp-1' = 'Revoke' }
        # user-2 gets disabled without any decision driving it
        ($script:CurrentUsers | Where-Object { $_.id -eq 'user-2' })['accountEnabled'] = $false
        $null = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
        $r = New-AccessReviewReport -CampaignDirectory $script:Campaign.Directory
        $html = Get-Content $r.ReportPath -Raw
        $html | Should -Match 'NOT_REMEDIATED'
        $html | Should -Match 'UNEXPLAINED_CHANGE'
        $html | Should -Match 'AccountDisabled'
        $html | Should -Not -Match 'No access changes were required'
        $updatedSection = ($html -split 'id="updated"')[1] -split 'id="signoff"' | Select-Object -First 1
        $updatedSection | Should -Match 'normal@contoso\.com'
    }

    It 'renders an open campaign as DRAFT with pending sign-off' {
        $r = New-AccessReviewReport -CampaignDirectory $script:Campaign.Directory
        $r.Success | Should -BeTrue
        $r.IsDraft | Should -BeTrue
        $html = Get-Content $r.ReportPath -Raw
        $html | Should -Match 'ar-draft-banner'
        $html | Should -Match 'NOT VALID AS AUDIT EVIDENCE'
        $html | Should -Match 'Pending review sign-off'
    }

    It 'HTML-encodes tenant-controlled data' {
        & $script:FillWorksheet -Directory $script:Campaign.Directory
        $null = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
        $r = New-AccessReviewReport -CampaignDirectory $script:Campaign.Directory
        $html = Get-Content $r.ReportPath -Raw
        $html | Should -Not -Match '<script>alert\(1\)</script>'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
    }

    It 'caps the users table at MaxUserRows with a truncation note' {
        & $script:FillWorksheet -Directory $script:Campaign.Directory
        $null = Complete-AccessReviewCampaign -CampaignDirectory $script:Campaign.Directory -EntraRoster (& $script:MakeRoster)
        $r = New-AccessReviewReport -CampaignDirectory $script:Campaign.Directory -MaxUserRows 2
        $html = Get-Content $r.ReportPath -Raw
        $html | Should -Match 'additional row\(s\) not shown'
    }

    It 'fails with a reason when pointed at a non-campaign folder' {
        $r = New-AccessReviewReport -CampaignDirectory $TestDrive
        $r.Success | Should -BeFalse
        $r.FailureReason | Should -Match 'campaign\.json missing'
    }
}

Describe 'Get-SOC2EvidenceMatrix — access-review reference' {

    BeforeEach {
        Mock -CommandName Test-AccessReviewEnvironment -ModuleName EntraChecks-AccessReview -MockWith {
            & $script:MakeEnv
        }
        $script:CurrentUsers = & $script:MakeUsers
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-AccessReview -MockWith {
            @{ value = $script:CurrentUsers }
        }
        $script:OutDir = Join-Path $TestDrive ("soc2-" + [guid]::NewGuid().ToString('N').Substring(0, 8))

        # Minimal SOC 2 bundle so the matrix takes its main path
        $script:BundleDir = Join-Path $TestDrive ("bundle-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -Path $script:BundleDir -ItemType Directory -Force
        $script:BundleManifest = Join-Path $script:BundleDir 'manifest.json'
        '{ "GeneratedAt": "2026-08-04T00:00:00Z", "Files": [] }' | Set-Content -LiteralPath $script:BundleManifest -Encoding UTF8
        $script:Bundle = [pscustomobject]@{ ManifestPath = $script:BundleManifest }
        $script:Catalog = @([pscustomobject]@{ Id = 'CC6.1'; Family = 'CC' })
    }

    It 'adds CC6.1-CC6.3 rows for the latest closed campaign' {
        $c = New-AccessReviewCampaign -OutputDirectory $script:OutDir -TenantName 'Contoso' `
            -PeriodLabel '2026-Q3' -EntraRoster (& $script:MakeRoster)
        & $script:FillWorksheet -Directory $c.Directory
        $closed = Complete-AccessReviewCampaign -CampaignDirectory $c.Directory -EntraRoster (& $script:MakeRoster)
        $closed.Success | Should -BeTrue

        # Assign-then-wrap (the production consumption pattern): the matrix
        # emits one comma-protected collection; @(<command>) would nest it.
        $rows = Get-SOC2EvidenceMatrix -EvidenceBundle $script:Bundle -ControlCatalog $script:Catalog -AccessReviewDirectory $script:OutDir
        $rows = @($rows)
        $uar = @($rows | Where-Object { $_.Source -like 'Access review campaign*' })
        $uar.Count | Should -Be 3
        ($uar | ForEach-Object ControlId) | Should -Be @('CC6.1', 'CC6.2', 'CC6.3')
        $uar[0].Hash | Should -Be $closed.BundleHash
        $uar[0].TscFamily | Should -Be 'CC6'
        $uar[0].EvidenceArtifact | Should -Match 'AccessReview-Report\.html'
    }

    It 'adds nothing for open campaigns or when the directory is omitted' {
        $c = New-AccessReviewCampaign -OutputDirectory $script:OutDir -TenantName 'Contoso' `
            -PeriodLabel '2026-Q3' -EntraRoster (& $script:MakeRoster)
        $c.Success | Should -BeTrue

        # Open campaign only -> no reference
        $rows = Get-SOC2EvidenceMatrix -EvidenceBundle $script:Bundle -ControlCatalog $script:Catalog -AccessReviewDirectory $script:OutDir
        @(@($rows) | Where-Object { $_.Source -like 'Access review campaign*' }).Count | Should -Be 0

        # Directory omitted -> unchanged behavior
        $rows = Get-SOC2EvidenceMatrix -EvidenceBundle $script:Bundle -ControlCatalog $script:Catalog
        @(@($rows) | Where-Object { $_.Source -like 'Access review campaign*' }).Count | Should -Be 0
    }
}
