<#
.SYNOPSIS
    Pester 5 test suite for the tenant-level MFA enforcement probe (PR 2 of
    the MFA Detection work).

.DESCRIPTION
    Exercises Get-TenantMfaEnforcement against fully-mocked Microsoft Graph
    cmdlets. Covers:
    1. Graceful degradation when Graph context is missing.
    2. Security Defaults Enabled vs Disabled — correct state + finding emission.
    3. CA policy materialisation: Includes/Excludes (users, groups, roles)
       captured per policy.
    4. CA policy state classification (enabled / report-only / disabled).
    5. Conditions.IsConditional set $true when narrowing conditions present.
    6. Grant controls — RequiresMfa, Blocks, RequiresCompliantDevice flags.
    7. Findings:
       - SecurityDefaults_Disabled when Security Defaults are off.
       - OnlyReportOnlyMfa when all MFA-grant policies are report-only.
       - NoUniversalMfaPolicy when no enabled unconditional MFA-for-all policy.
    8. Statistics.UnconditionalMfaForAllPolicies counts only policies that
       actually unconditionally require MFA for all users.

    Run: Invoke-Pester -Path Tests/MFAEnforcement.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AuthMethodCatalog.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-MFAEnforcement.psm1') -Force -DisableNameChecking

    function New-MockEnvironment {
        [pscustomobject]@{
            IsAvailable = $true
            TenantId = 'tenant-id-0'
            Account = 'auditor@contoso.onmicrosoft.com'
            AuthType = 'Delegated'
        }
    }
    $script:MakeEnv = ${function:New-MockEnvironment}

    # Synthetic CA policies covering the cases PR 3 will need to handle.
    function New-MockCaPolicies {
        @(
            # 1. Universal MFA-for-all policy (the gold-standard baseline)
            [pscustomobject]@{
                id = 'pol-universal-mfa'
                displayName = 'Require MFA for all users'
                state = 'enabled'
                conditions = [pscustomobject]@{
                    users = [pscustomobject]@{
                        includeUsers = @('All')
                        excludeUsers = @('break-glass-1')
                        includeGroups = @()
                        excludeGroups = @()
                        includeRoles = @()
                        excludeRoles = @()
                    }
                    applications = [pscustomobject]@{
                        includeApplications = @('All')
                        excludeApplications = @()
                    }
                    clientAppTypes = @('all')
                    platforms = $null
                    locations = $null
                    signInRiskLevels = @()
                    userRiskLevels = @()
                }
                grantControls = [pscustomobject]@{
                    'operator' = 'OR'
                    builtInControls = @('mfa')
                }
            }
            # 2. Report-only MFA-for-admins policy
            [pscustomobject]@{
                id = 'pol-admins-mfa-reportonly'
                displayName = 'Admins MFA (Report-Only)'
                state = 'enabledForReportingButNotEnforced'
                conditions = [pscustomobject]@{
                    users = [pscustomobject]@{
                        includeUsers = @()
                        excludeUsers = @()
                        includeGroups = @()
                        excludeGroups = @()
                        includeRoles = @('62e90394-69f5-4237-9190-012177145e10')   # Global Administrator
                        excludeRoles = @()
                    }
                    applications = [pscustomobject]@{
                        includeApplications = @('All')
                    }
                    clientAppTypes = @('all')
                }
                grantControls = [pscustomobject]@{
                    'operator' = 'OR'
                    builtInControls = @('mfa')
                }
            }
            # 3. Disabled policy
            [pscustomobject]@{
                id = 'pol-disabled'
                displayName = 'Old policy'
                state = 'disabled'
                conditions = [pscustomobject]@{
                    users = [pscustomobject]@{ includeUsers = @('All') }
                    applications = [pscustomobject]@{ includeApplications = @('All') }
                    clientAppTypes = @('all')
                }
                grantControls = [pscustomobject]@{
                    'operator' = 'OR'
                    builtInControls = @('mfa')
                }
            }
            # 4. Conditional MFA policy (narrowed by location)
            [pscustomobject]@{
                id = 'pol-conditional'
                displayName = 'Require MFA outside trusted locations'
                state = 'enabled'
                conditions = [pscustomobject]@{
                    users = [pscustomobject]@{ includeUsers = @('All') }
                    applications = [pscustomobject]@{ includeApplications = @('All') }
                    clientAppTypes = @('all')
                    locations = [pscustomobject]@{
                        includeLocations = @('All')
                        excludeLocations = @('AllTrusted')
                    }
                }
                grantControls = [pscustomobject]@{
                    'operator' = 'OR'
                    builtInControls = @('mfa')
                }
            }
            # 5. Block-legacy-auth policy (no MFA grant, just block)
            [pscustomobject]@{
                id = 'pol-block-legacy'
                displayName = 'Block legacy auth'
                state = 'enabled'
                conditions = [pscustomobject]@{
                    users = [pscustomobject]@{ includeUsers = @('All') }
                    applications = [pscustomobject]@{ includeApplications = @('All') }
                    clientAppTypes = @('exchangeActiveSync', 'other')
                }
                grantControls = [pscustomobject]@{
                    'operator' = 'OR'
                    builtInControls = @('block')
                }
            }
        )
    }
    $script:MakeCaPolicies = ${function:New-MockCaPolicies}
}

Describe 'Get-TenantMfaEnforcement — environment gating' {

    It 'returns Available=$false when Graph context is missing' {
        Mock -CommandName Test-MFAEnforcementEnvironment -ModuleName EntraChecks-MFAEnforcement -MockWith {
            [pscustomobject]@{ IsAvailable = $false; FailureReason = 'No Graph context (test)' }
        }
        $r = Get-TenantMfaEnforcement
        $r.Available     | Should -BeFalse
        $r.FailureReason | Should -Match 'No Graph context'
    }
}

Describe 'Get-TenantMfaEnforcement — Security Defaults state' {

    BeforeAll {
        Mock -CommandName Test-MFAEnforcementEnvironment -ModuleName EntraChecks-MFAEnforcement -MockWith { & $script:MakeEnv }
        Mock -CommandName Get-CaPoliciesMaterialised -ModuleName EntraChecks-MFAEnforcement -MockWith {
            @{ Available = $true; Policies = @(); FailureReason = $null }
        }
    }

    It 'reports Security Defaults Enabled=$true when isEnabled=true' {
        Mock -CommandName Get-SecurityDefaultsState -ModuleName EntraChecks-MFAEnforcement -MockWith {
            @{ Available = $true; Enabled = $true; Source = 'test'; DisplayName = 'Security Defaults'; FailureReason = $null; Note = '' }
        }
        $r = Get-TenantMfaEnforcement
        $r.SecurityDefaults.Enabled | Should -BeTrue
        ($r.Findings | Where-Object CheckName -match 'SecurityDefaultsEnabled' | Select-Object -First 1).Severity | Should -BeExactly 'Info'
    }

    It 'emits a High finding when Security Defaults are disabled' {
        Mock -CommandName Get-SecurityDefaultsState -ModuleName EntraChecks-MFAEnforcement -MockWith {
            @{ Available = $true; Enabled = $false; Source = 'test'; DisplayName = 'Security Defaults'; FailureReason = $null; Note = '' }
        }
        $r = Get-TenantMfaEnforcement
        $f = $r.Findings | Where-Object CheckName -match 'SecurityDefaultsDisabled' | Select-Object -First 1
        $f          | Should -Not -BeNullOrEmpty
        $f.Severity | Should -BeExactly 'High'
    }

    It 'does NOT emit a SecurityDefaults finding when the API was unreachable' {
        Mock -CommandName Get-SecurityDefaultsState -ModuleName EntraChecks-MFAEnforcement -MockWith {
            @{ Available = $false; Enabled = $null; FailureReason = 'forbidden'; Note = '' }
        }
        $r = Get-TenantMfaEnforcement
        ($r.Findings | Where-Object CheckName -match 'SecurityDefaults' ) | Should -BeNullOrEmpty
    }
}

Describe 'Get-TenantMfaEnforcement — CA policy materialisation' {

    BeforeAll {
        Mock -CommandName Test-MFAEnforcementEnvironment -ModuleName EntraChecks-MFAEnforcement -MockWith { & $script:MakeEnv }
        Mock -CommandName Get-SecurityDefaultsState -ModuleName EntraChecks-MFAEnforcement -MockWith {
            @{ Available = $true; Enabled = $true; Source = 'test'; FailureReason = $null; Note = '' }
        }
        # Convert one mocked raw policy at a time via the real ConvertTo-MaterialisedCaPolicy
        # (we intercept only the fetch, not the materialiser itself)
        Mock -CommandName Get-MgIdentityConditionalAccessPolicy -ModuleName EntraChecks-MFAEnforcement -MockWith {
            & $script:MakeCaPolicies
        }
    }

    It 'materialises every policy with Includes / Excludes captured' {
        $r = Get-TenantMfaEnforcement
        @($r.ConditionalAccess.Policies).Count | Should -Be 5
        $universal = $r.ConditionalAccess.Policies | Where-Object Id -eq 'pol-universal-mfa' | Select-Object -First 1
        @($universal.Includes.Users) -contains 'All'           | Should -BeTrue
        @($universal.Excludes.Users) -contains 'break-glass-1' | Should -BeTrue
    }

    It 'classifies state correctly across enabled / report-only / disabled' {
        $r = Get-TenantMfaEnforcement
        $universal = $r.ConditionalAccess.Policies | Where-Object Id -eq 'pol-universal-mfa' | Select-Object -First 1
        $reportOnly = $r.ConditionalAccess.Policies | Where-Object Id -eq 'pol-admins-mfa-reportonly' | Select-Object -First 1
        $disabled = $r.ConditionalAccess.Policies | Where-Object Id -eq 'pol-disabled' | Select-Object -First 1

        $universal.Enabled    | Should -BeTrue
        $universal.ReportOnly | Should -BeFalse
        $reportOnly.Enabled   | Should -BeFalse
        $reportOnly.ReportOnly | Should -BeTrue
        $disabled.State       | Should -BeExactly 'disabled'
    }

    It 'sets IsConditional=$true when narrowing conditions are present' {
        $r = Get-TenantMfaEnforcement
        $unconditional = $r.ConditionalAccess.Policies | Where-Object Id -eq 'pol-universal-mfa' | Select-Object -First 1
        $conditional = $r.ConditionalAccess.Policies | Where-Object Id -eq 'pol-conditional' | Select-Object -First 1

        $unconditional.Conditions.IsConditional | Should -BeFalse
        $conditional.Conditions.IsConditional   | Should -BeTrue
    }

    It 'captures grant control booleans' {
        $r = Get-TenantMfaEnforcement
        $universal = $r.ConditionalAccess.Policies | Where-Object Id -eq 'pol-universal-mfa' | Select-Object -First 1
        $blockLegacy = $r.ConditionalAccess.Policies | Where-Object Id -eq 'pol-block-legacy' | Select-Object -First 1

        $universal.GrantControls.RequiresMfa | Should -BeTrue
        $universal.GrantControls.Blocks      | Should -BeFalse
        $blockLegacy.GrantControls.Blocks    | Should -BeTrue
        $blockLegacy.GrantControls.RequiresMfa | Should -BeFalse
    }
}

Describe 'Get-TenantMfaEnforcement — finding emission' {

    BeforeAll {
        Mock -CommandName Test-MFAEnforcementEnvironment -ModuleName EntraChecks-MFAEnforcement -MockWith { & $script:MakeEnv }
        Mock -CommandName Get-SecurityDefaultsState -ModuleName EntraChecks-MFAEnforcement -MockWith {
            @{ Available = $true; Enabled = $true; Source = 'test'; FailureReason = $null; Note = '' }
        }
    }

    It 'flags OnlyReportOnlyMfa when every MFA-grant policy is report-only' {
        Mock -CommandName Get-CaPoliciesMaterialised -ModuleName EntraChecks-MFAEnforcement -MockWith {
            @{
                Available = $true
                Policies = @(
                    @{ Id = 'p1'; State = 'enabledForReportingButNotEnforced'; Enabled = $false; ReportOnly = $true
                       Includes = @{ Users = @('All'); Groups = @(); Roles = @() }
                       Excludes = @{ Users = @(); Groups = @(); Roles = @() }
                       Conditions = @{ IsConditional = $false }
                       GrantControls = @{ RequiresMfa = $true; Blocks = $false; BuiltInControls = @('mfa'); Operator = 'OR' }
                    }
                )
                FailureReason = $null
            }
        }
        $r = Get-TenantMfaEnforcement
        $f = $r.Findings | Where-Object CheckName -match 'OnlyReportOnlyMfa' | Select-Object -First 1
        $f          | Should -Not -BeNullOrEmpty
        $f.Severity | Should -BeExactly 'High'
    }

    It 'flags NoUniversalMfaPolicy when no enabled unconditional MFA-for-all policy exists' {
        Mock -CommandName Get-CaPoliciesMaterialised -ModuleName EntraChecks-MFAEnforcement -MockWith {
            @{
                Available = $true
                Policies = @(
                    @{ Id = 'p1'; State = 'enabled'; Enabled = $true; ReportOnly = $false
                       Includes = @{ Users = @('All'); Groups = @(); Roles = @() }
                       Excludes = @{ Users = @(); Groups = @(); Roles = @() }
                       Conditions = @{ IsConditional = $true }     # narrowed -> doesn't count
                       GrantControls = @{ RequiresMfa = $true; Blocks = $false; BuiltInControls = @('mfa'); Operator = 'OR' }
                    }
                )
                FailureReason = $null
            }
        }
        $r = Get-TenantMfaEnforcement
        $f = $r.Findings | Where-Object CheckName -match 'NoUniversalMfaPolicy' | Select-Object -First 1
        $f          | Should -Not -BeNullOrEmpty
        $f.Severity | Should -BeExactly 'Medium'
    }

    It 'does NOT flag NoUniversalMfaPolicy when an enabled unconditional MFA-for-all policy exists' {
        Mock -CommandName Get-CaPoliciesMaterialised -ModuleName EntraChecks-MFAEnforcement -MockWith {
            @{
                Available = $true
                Policies = @(
                    @{ Id = 'p1'; State = 'enabled'; Enabled = $true; ReportOnly = $false
                       Includes = @{ Users = @('All'); Groups = @(); Roles = @() }
                       Excludes = @{ Users = @(); Groups = @(); Roles = @() }
                       Conditions = @{ IsConditional = $false }
                       GrantControls = @{ RequiresMfa = $true; Blocks = $false; BuiltInControls = @('mfa'); Operator = 'OR' }
                    }
                )
                FailureReason = $null
            }
        }
        $r = Get-TenantMfaEnforcement
        $r.Statistics.UnconditionalMfaForAllPolicies | Should -BeGreaterOrEqual 1
        $r.Findings | Where-Object CheckName -match 'NoUniversalMfaPolicy' | Should -BeNullOrEmpty
    }
}
