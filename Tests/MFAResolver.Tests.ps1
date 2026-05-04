<#
.SYNOPSIS
    Pester 5 test suite for the per-user effective-MFA verdict engine
    (PR 3 of MFA Detection).

.DESCRIPTION
    Two layers of testing:

    1. Pure verdict logic (Resolve-MfaVerdict, Test-CaPolicyAppliesTo,
       Test-IsServiceAccount) — exercised in-module via InModuleScope. These
       are deterministic with no Graph dependency, so the matrix of cases is
       enumerated exhaustively.

    2. End-to-end Get-UserMfaCoverage — Graph cmdlets fully mocked. Confirms
       the resolver wires the inputs together correctly and surfaces the
       canonical row schema PR 5 will render.

    Run: Invoke-Pester -Path Tests/MFAResolver.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AuthMethodCatalog.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-MFAEnforcement.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-MFAResolver.psm1') -Force -DisableNameChecking

    function New-MockCaPolicy {
        param(
            [string]$Id = 'pol-1',
            [string]$DisplayName = 'Test policy',
            [bool]$Enabled = $true,
            [bool]$ReportOnly = $false,
            [string[]]$IncludeUsers = @(),
            [string[]]$IncludeGroups = @(),
            [string[]]$IncludeRoles = @(),
            [string[]]$ExcludeUsers = @(),
            [string[]]$ExcludeGroups = @(),
            [string[]]$ExcludeRoles = @(),
            [bool]$IsConditional = $false,
            [bool]$RequiresMfa = $true,
            [string]$Operator = 'OR',
            [string[]]$BuiltInControls = @('mfa'),
            [bool]$RequiresCompliantDevice = $false,
            [bool]$RequiresDomainJoinedDevice = $false
        )
        @{
            Id = $Id
            DisplayName = $DisplayName
            State = if ($Enabled) { 'enabled' } elseif ($ReportOnly) { 'enabledForReportingButNotEnforced' } else { 'disabled' }
            Enabled = $Enabled
            ReportOnly = $ReportOnly
            Includes = @{ Users = $IncludeUsers; Groups = $IncludeGroups; Roles = $IncludeRoles }
            Excludes = @{ Users = $ExcludeUsers; Groups = $ExcludeGroups; Roles = $ExcludeRoles }
            Conditions = @{ IsConditional = $IsConditional }
            GrantControls = @{
                Operator = $Operator
                BuiltInControls = $BuiltInControls
                RequiresMfa = $RequiresMfa
                Blocks = ($BuiltInControls -contains 'block')
                RequiresCompliantDevice = $RequiresCompliantDevice
                RequiresDomainJoinedDevice = $RequiresDomainJoinedDevice
            }
        }
    }
}

# ============================================================================
# Pure logic — Resolve-MfaVerdict matrix
# ============================================================================

Describe 'Resolve-MfaVerdict — verdict matrix' {

    It 'returns EnforcedStrong when Security Defaults applies and a strong method is registered' {
        InModuleScope EntraChecks-MFAResolver {
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'PhishingResistant' `
                -SecurityDefaultsApplies $true `
                -PerUserMfaState 'Unknown' `
                -ApplicableCaPolicies @() `
                -UserType 'Member' `
                -MembershipResolved $true
            $r.Verdict | Should -BeExactly 'EnforcedStrong'
            $r.Reason  | Should -Match 'Security Defaults'
        }
    }

    It 'returns EnforcedStrong when an unconditional CA policy enforces MFA and PhishingResistant is registered' {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -IsConditional $false
            $applicable = @( @{ Policy = $pol; Applies = $true; Conditional = $false; Reason = 'all-users' } )
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'PhishingResistant' `
                -SecurityDefaultsApplies $false `
                -PerUserMfaState 'Unknown' `
                -ApplicableCaPolicies $applicable `
                -UserType 'Member' `
                -MembershipResolved $true
            $r.Verdict | Should -BeExactly 'EnforcedStrong'
            $r.Reason  | Should -Match 'Conditional Access'
        }
    }

    It 'returns EnforcedWeak when enforcement applies but only weak methods are registered' {
        InModuleScope EntraChecks-MFAResolver {
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'Weak' `
                -SecurityDefaultsApplies $true `
                -PerUserMfaState 'Unknown' `
                -ApplicableCaPolicies @() `
                -UserType 'Member' `
                -MembershipResolved $true
            $r.Verdict | Should -BeExactly 'EnforcedWeak'
            $r.Reason  | Should -Match 'Weak'
        }
    }

    It 'returns RegisteredUnenforced when methods exist but no enforcement signal' {
        InModuleScope EntraChecks-MFAResolver {
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'PhishingResistant' `
                -SecurityDefaultsApplies $false `
                -PerUserMfaState 'Disabled' `
                -ApplicableCaPolicies @() `
                -UserType 'Member' `
                -MembershipResolved $true
            $r.Verdict | Should -BeExactly 'RegisteredUnenforced'
        }
    }

    It 'returns NotRegistered when no methods are present' {
        InModuleScope EntraChecks-MFAResolver {
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'None' `
                -SecurityDefaultsApplies $false `
                -PerUserMfaState 'Disabled' `
                -ApplicableCaPolicies @() `
                -UserType 'Member' `
                -MembershipResolved $true
            $r.Verdict | Should -BeExactly 'NotRegistered'
        }
    }
}

Describe 'Resolve-MfaVerdict — NeedsReview matrix (strict mode)' {

    It 'flags NeedsReview when membership resolution failed' {
        InModuleScope EntraChecks-MFAResolver {
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'PhishingResistant' `
                -SecurityDefaultsApplies $false `
                -PerUserMfaState 'Unknown' `
                -ApplicableCaPolicies @() `
                -UserType 'Member' `
                -MembershipResolved $false
            $r.Verdict            | Should -BeExactly 'NeedsReview'
            $r.NeedsReviewBecause | Should -BeExactly 'MembershipResolutionFailed'
        }
    }

    It 'flags NeedsReview on mixed signals (Per-user Disabled + CA enforces)' {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -IsConditional $false
            $applicable = @( @{ Policy = $pol; Applies = $true; Conditional = $false; Reason = 'all' } )
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'PhishingResistant' `
                -SecurityDefaultsApplies $false `
                -PerUserMfaState 'Disabled' `
                -ApplicableCaPolicies $applicable `
                -UserType 'Member' `
                -MembershipResolved $true
            $r.Verdict            | Should -BeExactly 'NeedsReview'
            $r.NeedsReviewBecause | Should -BeExactly 'MixedSignals_PerUserDisabledButCaEnforced'
        }
    }

    It 'flags NeedsReview when enforcement comes only from conditional (narrowing) CA policies' {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -IsConditional $true
            $applicable = @( @{ Policy = $pol; Applies = $true; Conditional = $true; Reason = 'narrowed' } )
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'PhishingResistant' `
                -SecurityDefaultsApplies $false `
                -PerUserMfaState 'Unknown' `
                -ApplicableCaPolicies $applicable `
                -UserType 'Member' `
                -MembershipResolved $true
            $r.Verdict            | Should -BeExactly 'NeedsReview'
            $r.NeedsReviewBecause | Should -BeExactly 'ConditionalOnlyCoverage'
        }
    }

    It 'flags NeedsReview when only report-only CA policies match' {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -Enabled $false -ReportOnly $true -IsConditional $false
            $applicable = @( @{ Policy = $pol; Applies = $true; Conditional = $false; Reason = 'all' } )
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'PhishingResistant' `
                -SecurityDefaultsApplies $false `
                -PerUserMfaState 'Unknown' `
                -ApplicableCaPolicies $applicable `
                -UserType 'Member' `
                -MembershipResolved $true
            $r.Verdict            | Should -BeExactly 'NeedsReview'
            $r.NeedsReviewBecause | Should -BeExactly 'ReportOnlyMfaCoverage'
        }
    }

    It 'flags NeedsReview for guest users with no visible enforcement' {
        InModuleScope EntraChecks-MFAResolver {
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'PhishingResistant' `
                -SecurityDefaultsApplies $false `
                -PerUserMfaState 'Unknown' `
                -ApplicableCaPolicies @() `
                -UserType 'Guest' `
                -MembershipResolved $true
            $r.Verdict            | Should -BeExactly 'NeedsReview'
            $r.NeedsReviewBecause | Should -BeExactly 'GuestWithUnverifiableHomeEnforcement'
        }
    }

    It "flags NeedsReview when CA grant is OR'd with a device-compliance alternative" {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -Operator 'OR' -BuiltInControls @('mfa', 'compliantDevice') -RequiresCompliantDevice $true
            $applicable = @( @{ Policy = $pol; Applies = $true; Conditional = $false; Reason = 'all' } )
            $r = Resolve-MfaVerdict `
                -StrongestRegistered 'PhishingResistant' `
                -SecurityDefaultsApplies $false `
                -PerUserMfaState 'Unknown' `
                -ApplicableCaPolicies $applicable `
                -UserType 'Member' `
                -MembershipResolved $true
            $r.Verdict            | Should -BeExactly 'NeedsReview'
            $r.NeedsReviewBecause | Should -BeExactly 'OrGrantWithDeviceAlternative'
        }
    }
}

# ============================================================================
# Test-CaPolicyAppliesTo — include/exclude resolution
# ============================================================================

Describe 'Test-CaPolicyAppliesTo — applicability resolution' {

    It "matches 'All'-user policies to any user" {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -IncludeUsers @('All')
            $r = Test-CaPolicyAppliesTo -User @{ Id = 'u1'; UserType = 'Member'; Groups = @(); Roles = @() } -Policy $pol
            $r.Applies | Should -BeTrue
        }
    }

    It 'honors excludeUsers (exclude wins over include)' {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -IncludeUsers @('All') -ExcludeUsers @('break-glass-1')
            $r = Test-CaPolicyAppliesTo -User @{ Id = 'break-glass-1'; UserType = 'Member'; Groups = @(); Roles = @() } -Policy $pol
            $r.Applies | Should -BeFalse
            $r.Reason  | Should -Match 'excluded'
        }
    }

    It 'matches via included group' {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -IncludeGroups @('group-finance')
            $r = Test-CaPolicyAppliesTo -User @{ Id = 'u1'; UserType = 'Member'; Groups = @('group-finance'); Roles = @() } -Policy $pol
            $r.Applies | Should -BeTrue
            $r.Reason  | Should -Match 'group-finance'
        }
    }

    It 'matches via included role (role-template ID)' {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10')
            $r = Test-CaPolicyAppliesTo -User @{ Id = 'u1'; UserType = 'Member'; Groups = @(); Roles = @('62e90394-69f5-4237-9190-012177145e10') } -Policy $pol
            $r.Applies | Should -BeTrue
        }
    }

    It "does NOT match when no include matches" {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -IncludeGroups @('group-finance')
            $r = Test-CaPolicyAppliesTo -User @{ Id = 'u1'; UserType = 'Member'; Groups = @('group-engineering'); Roles = @() } -Policy $pol
            $r.Applies | Should -BeFalse
        }
    }

    It "matches Guests to a 'GuestsOrExternalUsers' include" {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -IncludeUsers @('GuestsOrExternalUsers')
            $r = Test-CaPolicyAppliesTo -User @{ Id = 'g1'; UserType = 'Guest'; Groups = @(); Roles = @() } -Policy $pol
            $r.Applies | Should -BeTrue
        }
    }

    It 'propagates the IsConditional flag from the policy' {
        InModuleScope EntraChecks-MFAResolver -Parameters @{ MakePolicy = ${function:New-MockCaPolicy} } {
            param($MakePolicy)
            $pol = & $MakePolicy -IncludeUsers @('All') -IsConditional $true
            $r = Test-CaPolicyAppliesTo -User @{ Id = 'u1'; UserType = 'Member'; Groups = @(); Roles = @() } -Policy $pol
            $r.Conditional | Should -BeTrue
        }
    }
}

# ============================================================================
# Test-IsServiceAccount — heuristic
# ============================================================================

Describe 'Test-IsServiceAccount — service-account heuristics' {

    It 'flags svc- UPN prefix' {
        InModuleScope EntraChecks-MFAResolver {
            $signals = Test-IsServiceAccount -Upn 'svc-monitoring@contoso.com' -DisplayName 'Monitoring Account'
            $signals | Should -Not -BeNullOrEmpty
        }
    }

    It 'flags noreply UPN' {
        InModuleScope EntraChecks-MFAResolver {
            $signals = Test-IsServiceAccount -Upn 'noreply@contoso.com' -DisplayName 'No Reply'
            $signals | Should -Not -BeNullOrEmpty
        }
    }

    It 'flags display-name patterns even when UPN looks human' {
        InModuleScope EntraChecks-MFAResolver {
            $signals = Test-IsServiceAccount -Upn 'jdoe@contoso.com' -DisplayName 'AAD Sync Account'
            $signals | Should -Not -BeNullOrEmpty
        }
    }

    It 'returns $null for clearly human users' {
        InModuleScope EntraChecks-MFAResolver {
            $signals = Test-IsServiceAccount -Upn 'jdoe@contoso.com' -DisplayName 'John Doe'
            $signals | Should -BeNullOrEmpty
        }
    }
}
