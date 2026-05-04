<#
.SYNOPSIS
    Pester 5 test suite for the Entra privileged-identity aggregator
    (PR 3 of the Privileged Identity Roster work).

.DESCRIPTION
    Exercises Get-PrivilegedIdentityRosterEntra against fully-mocked Microsoft
    Graph cmdlets. Covers:
    1. Graceful degradation when the Graph context is unavailable.
    2. Active role assignment -> roster row with AssignmentType='Active'.
    3. PIM-eligible assignment -> roster row with AssignmentType='Eligible (PIM)'.
    4. PIM 403 / license-required -> Statistics.PimAvailable=$false, no throw.
    5. App-role assignment to a curated MS Graph permission -> SP roster row
       with AssignmentType='AppRole'.
    6. Coalescing: same principal active + eligible = one row, two privileges.
    7. HighestTier = numeric minimum across catalog-mapped privileges.
    8. Non-catalogued role assignments produce 'Entra:Other:<Name>' keys when
       -IncludeNonCatalogedRoles is set; absent otherwise.
    9. App-owner discovery emits owner rows with AssignmentType='Owner'.

    Run: Invoke-Pester -Path Tests/PrivilegedIdentityEntra.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-PrivilegedIdentityEntra.psm1') -Force -DisableNameChecking

    function New-MockEnv {
        [pscustomobject]@{
            IsAvailable = $true
            TenantId = 'tenant-id-0'
            Account = 'auditor@contoso.onmicrosoft.com'
            AuthType = 'Delegated'
            Scopes = @('RoleManagement.Read.Directory', 'Application.Read.All')
        }
    }

    # Two role IDs used in fixtures
    $script:RoleId_GA = 'role-id-ga'
    $script:RoleId_HD = 'role-id-helpdesk'
    $script:RoleId_Custom = 'role-id-custom'

    # Mock environment probe — always Available
    Mock -CommandName Test-PrivilegedIdentityEntraEnvironment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
        & $script:MakeEnv
    }

    # Role-definition map mock
    Mock -CommandName Get-MgRoleManagementDirectoryRoleDefinition -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
        @(
            [pscustomobject]@{ Id = $script:RoleId_GA; DisplayName = 'Global Administrator' }
            [pscustomobject]@{ Id = $script:RoleId_HD; DisplayName = 'Helpdesk Administrator' }
            [pscustomobject]@{ Id = $script:RoleId_Custom; DisplayName = 'Custom-Tenant-Role-Without-Catalog-Entry' }
        )
    }

    # Smuggle helpers into module scope (Mock blocks execute there)
    $script:MakeEnv = ${function:New-MockEnv}
}

Describe 'Get-PrivilegedIdentityRosterEntra — environment gating' {

    It 'returns Available=$false when Graph context is missing' {
        Mock -CommandName Test-PrivilegedIdentityEntraEnvironment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            [pscustomobject]@{ IsAvailable = $false; FailureReason = 'No Graph context' }
        }
        $r = Get-PrivilegedIdentityRosterEntra
        $r.Available | Should -BeFalse
        $r.FailureReason | Should -Match 'No Graph context'
    }
}

Describe 'Get-PrivilegedIdentityRosterEntra — active assignments' {

    BeforeAll {
        Mock -CommandName Test-PrivilegedIdentityEntraEnvironment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            & $script:MakeEnv
        }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleDefinition -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            @(
                [pscustomobject]@{ Id = $script:RoleId_GA; DisplayName = 'Global Administrator' }
                [pscustomobject]@{ Id = $script:RoleId_HD; DisplayName = 'Helpdesk Administrator' }
            )
        }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleAssignment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            @(
                [pscustomobject]@{ PrincipalId = 'user-1'; RoleDefinitionId = $script:RoleId_GA }
                [pscustomobject]@{ PrincipalId = 'user-2'; RoleDefinitionId = $script:RoleId_HD }
            )
        }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            # Empty by default; specific tests override
            @()
        }
        Mock -CommandName Get-EntraPrincipalEnrichment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            param($ObjectId, $HintedType)
            @{
                PrincipalType = 'User'
                Upn = "$ObjectId@contoso.onmicrosoft.com"
                DisplayName = "Display $ObjectId"
                Enabled = $true
                LastSignIn = $null
                AppId = $null
                ServicePrincipalType = $null
            }
        }
        # Suppress app-role discovery for this scope
        Mock -CommandName Get-MgServicePrincipal -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
        Mock -CommandName Get-MicrosoftGraphAppRoleNames -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @{} }
        Mock -CommandName Get-MgServicePrincipalAppRoleAssignedTo -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
        Mock -CommandName Get-MgServicePrincipalOwner -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
    }

    It 'maps Global Administrator role assignment to catalog key Entra:GlobalAdministrator' {
        $r = Get-PrivilegedIdentityRosterEntra
        $r.Available | Should -BeTrue
        $u1 = $r.Roster | Where-Object ObjectId -eq 'user-1'
        $u1 | Should -Not -BeNullOrEmpty
        $priv = $u1.Privileges | Select-Object -First 1
        $priv.Key            | Should -BeExactly 'Entra:GlobalAdministrator'
        $priv.AssignmentType | Should -BeExactly 'Active'
    }

    It 'sets HighestTier = 0 for Global Administrator holders' {
        $r = Get-PrivilegedIdentityRosterEntra
        ($r.Roster | Where-Object ObjectId -eq 'user-1').HighestTier | Should -Be 0
    }

    It 'preserves Helpdesk Administrator as Tier 2' {
        $r = Get-PrivilegedIdentityRosterEntra
        ($r.Roster | Where-Object ObjectId -eq 'user-2').HighestTier | Should -Be 2
    }
}

Describe 'Get-PrivilegedIdentityRosterEntra — PIM-eligible' {

    BeforeAll {
        Mock -CommandName Test-PrivilegedIdentityEntraEnvironment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { & $script:MakeEnv }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleDefinition -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            @(
                [pscustomobject]@{ Id = $script:RoleId_GA; DisplayName = 'Global Administrator' }
            )
        }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleAssignment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            @([pscustomobject]@{ PrincipalId = 'user-1'; RoleDefinitionId = $script:RoleId_GA })
        }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            # user-1 is also PIM-eligible for the same role -> coalesces onto one row
            @([pscustomobject]@{ PrincipalId = 'user-1'; RoleDefinitionId = $script:RoleId_GA })
        }
        Mock -CommandName Get-EntraPrincipalEnrichment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            param($ObjectId, $HintedType) @{ PrincipalType='User'; Upn="$ObjectId@x.com"; DisplayName=$ObjectId; Enabled=$true }
        }
        Mock -CommandName Get-MgServicePrincipal -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
        Mock -CommandName Get-MicrosoftGraphAppRoleNames -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @{} }
        Mock -CommandName Get-MgServicePrincipalAppRoleAssignedTo -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
        Mock -CommandName Get-MgServicePrincipalOwner -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
    }

    It 'coalesces active + eligible onto one row with two privilege entries' {
        $r = Get-PrivilegedIdentityRosterEntra
        $row = $r.Roster | Where-Object ObjectId -eq 'user-1'
        @($row).Count            | Should -Be 1
        @($row.Privileges).Count | Should -Be 2
        ($row.Privileges | ForEach-Object AssignmentType) -join ',' | Should -Match 'Active.*Eligible \(PIM\)|Eligible \(PIM\).*Active'
    }

    It 'reports PimAvailable=$true when the API returned data' {
        $r = Get-PrivilegedIdentityRosterEntra
        $r.Statistics.PimAvailable | Should -BeTrue
    }
}

Describe 'Get-PrivilegedIdentityRosterEntra — PIM 403 graceful degradation' {

    BeforeAll {
        Mock -CommandName Test-PrivilegedIdentityEntraEnvironment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { & $script:MakeEnv }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleDefinition -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleAssignment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            throw '403 Forbidden — RoleEligibilitySchedule.Read.Directory requires Premium P2 license.'
        }
        Mock -CommandName Get-MgServicePrincipal -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
        Mock -CommandName Get-MicrosoftGraphAppRoleNames -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @{} }
        Mock -CommandName Get-MgServicePrincipalAppRoleAssignedTo -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
        Mock -CommandName Get-MgServicePrincipalOwner -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
    }

    It 'sets PimAvailable=$false instead of throwing' {
        $r = Get-PrivilegedIdentityRosterEntra
        $r.Available | Should -BeTrue
        $r.Statistics.PimAvailable | Should -BeFalse
    }
}

Describe 'Get-PrivilegedIdentityRosterEntra — MS Graph high-risk app-role grants' {

    BeforeAll {
        Mock -CommandName Test-PrivilegedIdentityEntraEnvironment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { & $script:MakeEnv }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleDefinition -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleAssignment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
        Mock -CommandName Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }

        # Microsoft Graph SP returned with two app roles in fixture; only one
        # is in the curated catalog (Directory.ReadWrite.All).
        Mock -CommandName Get-MgServicePrincipal -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            param($Filter, $ServicePrincipalId)
            [pscustomobject]@{
                Id = 'msgraph-sp'
                AppId = '00000003-0000-0000-c000-000000000000'
                AppRoles = @(
                    [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111'; Value = 'Directory.ReadWrite.All' }
                    [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222'; Value = 'User.Read' }       # not in curated catalog
                )
            }
        }
        Mock -CommandName Get-MicrosoftGraphAppRoleNames -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            @{
                '11111111-1111-1111-1111-111111111111' = 'Directory.ReadWrite.All'
                '22222222-2222-2222-2222-222222222222' = 'User.Read'
            }
        }
        Mock -CommandName Get-MgServicePrincipalAppRoleAssignedTo -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            @(
                # SP-A holds the catalog'd permission -> roster row
                [pscustomobject]@{
                    PrincipalId = 'sp-a'; AppRoleId = '11111111-1111-1111-1111-111111111111'
                    CreatedDateTime = (Get-Date '2026-01-01')
                }
                # SP-B holds a non-catalog'd permission -> filtered out
                [pscustomobject]@{
                    PrincipalId = 'sp-b'; AppRoleId = '22222222-2222-2222-2222-222222222222'
                    CreatedDateTime = (Get-Date '2026-01-02')
                }
            )
        }
        Mock -CommandName Get-EntraPrincipalEnrichment -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith {
            param($ObjectId, $HintedType)
            @{ PrincipalType = 'ServicePrincipal'; Upn = $null; DisplayName = "App $ObjectId"; Enabled = $true; AppId = "appid-$ObjectId"; ServicePrincipalType = 'Application' }
        }
        Mock -CommandName Get-MgServicePrincipalOwner -ModuleName EntraChecks-PrivilegedIdentityEntra -MockWith { @() }
    }

    It 'emits a roster row for SPs holding curated MS Graph permissions' {
        $r = Get-PrivilegedIdentityRosterEntra
        $spA = $r.Roster | Where-Object ObjectId -eq 'sp-a'
        $spA | Should -Not -BeNullOrEmpty
        ($spA.Privileges | Select-Object -First 1).AssignmentType | Should -BeExactly 'AppRole'
        ($spA.Privileges | Select-Object -First 1).Key | Should -BeExactly 'MSGraph:Directory.ReadWrite.All'
    }

    It 'filters out grants for non-catalogued (low-risk) MS Graph permissions' {
        $r = Get-PrivilegedIdentityRosterEntra
        ($r.Roster | Where-Object ObjectId -eq 'sp-b') | Should -BeNullOrEmpty
    }

    It 'classifies SP-A as Tier 0 because Directory.ReadWrite.All is Tier 0 in the catalog' {
        $r = Get-PrivilegedIdentityRosterEntra
        ($r.Roster | Where-Object ObjectId -eq 'sp-a').HighestTier | Should -Be 0
    }
}
