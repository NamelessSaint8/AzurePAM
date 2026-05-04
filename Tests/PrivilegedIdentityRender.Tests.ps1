<#
.SYNOPSIS
    Pester 5 test suite for the Privileged Identity Roster rendering layer
    (PR 5 of the Privileged Identity Roster work).

.DESCRIPTION
    Renders a synthetic unified roster through the helpers and asserts the
    structural pieces an auditor relies on:
    1. Get-PrivilegedIdentityRosterCss returns a non-trivial CSS block.
    2. Get-PrivilegedIdentityDashboardTile renders the count + Tier 0 badge
       and links to #privileged-identities.
    3. Get-PrivilegedIdentityHtmlSection renders one card per identity,
       embeds the catalog WhyPrivileged paragraph, and links to the
       reference URL.
    4. Get-PrivilegedIdentityRows produces one row per identity with the
       expected schema columns.
    5. Get-PrivilegeDetailRows produces one row per (identity, privilege)
       pair, joining catalog metadata.
    6. Empty/missing roster renders an "Run with -EmitPrivilegedRoster"
       placeholder rather than failing.

    Run: Invoke-Pester -Path Tests/PrivilegedIdentityRender.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-PrivilegedIdentityRender.psm1') -Force -DisableNameChecking

    $script:syntheticUnified = @{
        UnifiedRoster = @(
            @{
                CanonicalId = 'jdoe@contoso.com'
                DisplayName = 'John Doe'
                AdSid = 'S-1-5-21-1-1-1001'
                AdSamAccountName = 'jdoe'
                EntraObjectId = 'oid-jdoe'
                EntraUpn = 'jdoe@contoso.com'
                PrincipalType = 'User'
                MatchConfidence = 'Strong'
                MatchedBy = 'OnPremisesSecurityIdentifier'
                CrossSurface = $true
                AdEnabled = $true
                EntraEnabled = $true
                AdLastLogonDays = 1
                EntraLastSignIn = '2026-04-30T08:00:00Z'
                InProtectedUsers = $false
                SmartCardRequired = $true
                Privileges = @(
                    @{ Key = 'AD:DomainAdmins'; Path = @('Domain Admins'); AssignmentType = 'Group (direct)'; DiscoveredAt = '2026-04-30T05:00:00Z' }
                    @{ Key = 'Entra:GlobalAdministrator'; Path = @('Global Administrator (active)'); AssignmentType = 'Active'; DiscoveredAt = '2026-04-30T05:00:00Z' }
                )
                HighestTier = 0
                Sources = @('Get-ADGroupMember', 'Get-MgRoleManagementDirectoryRoleAssignment')
            }
            @{
                CanonicalId = 'svc-prov'
                DisplayName = 'Provisioning Service'
                EntraObjectId = 'oid-sp-a'
                EntraUpn = $null
                PrincipalType = 'ServicePrincipal'
                MatchConfidence = 'None'
                MatchedBy = 'EntraOnly'
                CrossSurface = $false
                EntraEnabled = $true
                Privileges = @(
                    @{ Key = 'MSGraph:Directory.ReadWrite.All'; Path = @('App-role: Directory.ReadWrite.All'); AssignmentType = 'AppRole'; DiscoveredAt = '2026-04-30T05:00:00Z' }
                )
                HighestTier = 0
                Sources = @('Get-MgServicePrincipalAppRoleAssignedTo (Microsoft Graph)')
            }
        )
        Statistics = @{
            Total = 2; CrossSurface = 1; Tier0 = 2; Tier0CrossSurface = 1
            StrongMatches = 1; ProbableMatches = 0; WeakMatches = 0
        }
    }
}

Describe 'Get-PrivilegedIdentityRosterCss' {

    It 'returns a non-trivial CSS block' {
        $css = Get-PrivilegedIdentityRosterCss
        $css.Length          | Should -BeGreaterThan 1000
        $css                 | Should -Match '\.pi-card'
        $css                 | Should -Match '\.pi-tier-0'
        $css                 | Should -Match '\.pi-cross-badge'
    }
}

Describe 'Get-PrivilegedIdentityDashboardTile' {

    It 'renders the count, Tier 0 count, and cross-surface count' {
        $tile = Get-PrivilegedIdentityDashboardTile -RosterInput $script:syntheticUnified
        $tile | Should -Match '2 total'
        $tile | Should -Match '2 Tier 0'
        $tile | Should -Match '1 cross-surface'
    }

    It 'links to the #privileged-identities anchor' {
        $tile = Get-PrivilegedIdentityDashboardTile -RosterInput $script:syntheticUnified
        $tile | Should -Match 'href="#privileged-identities"'
    }

    It 'returns empty string for an empty roster' {
        Get-PrivilegedIdentityDashboardTile -RosterInput @{ UnifiedRoster = @() } | Should -BeNullOrEmpty
    }
}

Describe 'Get-PrivilegedIdentityHtmlSection' {

    It 'emits a section anchored at id="privileged-identities"' {
        $section = Get-PrivilegedIdentityHtmlSection -RosterInput $script:syntheticUnified
        $section | Should -Match 'id="privileged-identities"'
    }

    It 'renders one pi-card per identity' {
        $section = Get-PrivilegedIdentityHtmlSection -RosterInput $script:syntheticUnified
        $cardCount = ([regex]::Matches($section, 'class="pi-card[^"]*"')).Count
        $cardCount | Should -Be 2
    }

    It 'embeds catalog WhyPrivileged text for catalogued privileges' {
        $section = Get-PrivilegedIdentityHtmlSection -RosterInput $script:syntheticUnified
        $section | Should -Match 'DCSync'                                  # AD:DomainAdmins WhyPrivileged
        $section | Should -Match 'tenant-wide super-user'                  # Entra:GlobalAdministrator WhyPrivileged
        $section | Should -Match 'Application-level read and write'        # MSGraph:Directory.ReadWrite.All WhyPrivileged
    }

    It 'shows the cross-surface badge on cross-surface rows' {
        $section = Get-PrivilegedIdentityHtmlSection -RosterInput $script:syntheticUnified
        $section | Should -Match 'class="pi-cross-badge">Cross<'
    }

    It 'embeds reference links for catalogued privileges' {
        $section = Get-PrivilegedIdentityHtmlSection -RosterInput $script:syntheticUnified
        $section | Should -Match 'learn.microsoft.com'
    }

    It 'renders a placeholder when the roster is empty' {
        $section = Get-PrivilegedIdentityHtmlSection -RosterInput @{ UnifiedRoster = @() }
        $section | Should -Match 'No privileged-identity roster was collected'
    }
}

Describe 'Get-PrivilegedIdentityRows' {

    It 'produces one row per identity with the expected schema' {
        $rows = Get-PrivilegedIdentityRows -RosterInput $script:syntheticUnified
        @($rows).Count | Should -Be 2
        $jdoe = $rows | Where-Object CanonicalId -eq 'jdoe@contoso.com' | Select-Object -First 1
        $jdoe.HighestTier      | Should -Be 0
        $jdoe.CrossSurface     | Should -BeTrue
        $jdoe.PrivilegeCount   | Should -Be 2
        $jdoe.PSObject.Properties.Name | Should -Contain 'AdSamAccountName'
        $jdoe.PSObject.Properties.Name | Should -Contain 'EntraObjectId'
        $jdoe.PSObject.Properties.Name | Should -Contain 'MatchConfidence'
    }

    It 'joins multi-privilege summaries with semicolons' {
        $rows = Get-PrivilegedIdentityRows -RosterInput $script:syntheticUnified
        $jdoe = $rows | Where-Object CanonicalId -eq 'jdoe@contoso.com' | Select-Object -First 1
        $jdoe.Privileges | Should -Match ';'
    }
}

Describe 'Get-PrivilegeDetailRows' {

    It 'produces one row per (identity, privilege) pair' {
        $rows = Get-PrivilegeDetailRows -RosterInput $script:syntheticUnified
        # jdoe has 2 privileges, svc-prov has 1 = 3 detail rows
        @($rows).Count | Should -Be 3
    }

    It 'joins catalog metadata into each row' {
        $rows = Get-PrivilegeDetailRows -RosterInput $script:syntheticUnified
        $daRow = $rows | Where-Object PrivilegeKey -eq 'AD:DomainAdmins' | Select-Object -First 1
        $daRow.PrivilegeTier | Should -Be 0
        $daRow.WhyPrivileged | Should -Match 'DCSync'
        $daRow.AttackPaths   | Should -Match 'krbtgt'
        $daRow.ReferenceUrl  | Should -Match '^https://'
    }

    It 'records the assignment Path as a joined string' {
        $rows = Get-PrivilegeDetailRows -RosterInput $script:syntheticUnified
        $rows[0].PSObject.Properties.Name | Should -Contain 'Path'
    }
}
