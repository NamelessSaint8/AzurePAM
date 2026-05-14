<#
.SYNOPSIS
    Pester 5 test suite for the MFA sign-in evidence layer (PR 4).

.DESCRIPTION
    Two layers:
    1. Resolve-MfaDrift — pure logic. Verifies the drift matrix:
       - Phishing-resistant registered but only Strong/Weak observed -> drift
       - Strong+Weak registered but only Weak observed -> drift
       - Registered methods but no MFA challenge in window -> drift
       - No registered methods -> no drift (verdict layer handles it)
       - No evidence at all -> no drift (silent)
    2. Get-MfaSignInEvidence — graceful 403 + bulk-fetch happy path with
       mocked Invoke-MgGraphRequest.

    Run: Invoke-Pester -Path Tests/MFASignInEvidence.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    # Stubs must be in scope before the module imports — see Helpers file.
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AuthMethodCatalog.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-MFASignInEvidence.psm1') -Force -DisableNameChecking
}

Describe 'Resolve-MfaDrift — drift matrix' {

    It 'flags PhishingResistantRegisteredButUnused when fido2 is registered but never observed' {
        $registered = @('fido2', 'mobilePhone')
        $evidence = @{
            UserId = 'u1'; SignInsCount = 5; MfaChallengeOccurred = $true
            LastMfaMethodUsed = 'mobilePhone'
            MethodsObserved = @('mobilePhone')
        }
        $r = Resolve-MfaDrift -RegisteredMethods $registered -Evidence $evidence
        $r          | Should -Not -BeNullOrEmpty
        $r.Code     | Should -BeExactly 'PhishingResistantRegisteredButUnused'
        $r.Severity | Should -BeExactly 'Medium'
    }

    It 'flags StrongRegisteredButOnlyWeakUsed when softwareOath is registered but only SMS observed' {
        $registered = @('softwareOath', 'mobilePhone')
        $evidence = @{
            UserId = 'u2'; SignInsCount = 3; MfaChallengeOccurred = $true
            LastMfaMethodUsed = 'mobilePhone'
            MethodsObserved = @('mobilePhone')
        }
        $r = Resolve-MfaDrift -RegisteredMethods $registered -Evidence $evidence
        $r          | Should -Not -BeNullOrEmpty
        $r.Code     | Should -BeExactly 'StrongRegisteredButOnlyWeakUsed'
    }

    It 'flags NoMfaChallengeDespiteRegistration when MFA registered but no challenge in window' {
        $registered = @('fido2')
        $evidence = @{
            UserId = 'u3'; SignInsCount = 12; MfaChallengeOccurred = $false
            LastMfaMethodUsed = $null
            MethodsObserved = @()
        }
        $r = Resolve-MfaDrift -RegisteredMethods $registered -Evidence $evidence
        $r       | Should -Not -BeNullOrEmpty
        $r.Code  | Should -BeExactly 'NoMfaChallengeDespiteRegistration'
    }

    It 'returns $null when phishing-resistant is BOTH registered and observed (happy path)' {
        $registered = @('fido2', 'mobilePhone')
        $evidence = @{
            UserId = 'u4'; SignInsCount = 7; MfaChallengeOccurred = $true
            LastMfaMethodUsed = 'fido2'
            MethodsObserved = @('fido2')
        }
        $r = Resolve-MfaDrift -RegisteredMethods $registered -Evidence $evidence
        $r | Should -BeNullOrEmpty
    }

    It 'returns $null when no registered methods (verdict layer owns NotRegistered)' {
        Resolve-MfaDrift -RegisteredMethods @() -Evidence @{ UserId='u5'; SignInsCount = 1 } | Should -BeNullOrEmpty
    }

    It 'returns $null when evidence is unavailable for the user (silent)' {
        Resolve-MfaDrift -RegisteredMethods @('fido2') -Evidence $null | Should -BeNullOrEmpty
    }

    It 'returns $null when SignInsCount = 0 (no sign-ins to compare against)' {
        $r = Resolve-MfaDrift -RegisteredMethods @('fido2') -Evidence @{ UserId='u6'; SignInsCount = 0; MfaChallengeOccurred = $false; MethodsObserved = @() }
        $r | Should -BeNullOrEmpty
    }
}

Describe 'Get-MfaSignInEvidence — environment gating' {

    It 'returns Available=$false when Graph context is missing' {
        Mock -CommandName Test-MFASignInEvidenceEnvironment -ModuleName EntraChecks-MFASignInEvidence -MockWith {
            [pscustomobject]@{ IsAvailable = $false; FailureReason = 'No Graph context (test)' }
        }
        $r = Get-MfaSignInEvidence
        $r.Available     | Should -BeFalse
        $r.FailureReason | Should -Match 'No Graph context'
        $r.Evidence.Count | Should -Be 0
    }

    It 'returns Available=$false on Invoke-MgGraphRequest 403 (license / permission gap)' {
        Mock -CommandName Test-MFASignInEvidenceEnvironment -ModuleName EntraChecks-MFASignInEvidence -MockWith {
            [pscustomobject]@{ IsAvailable = $true; TenantId = 'tid' }
        }
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-MFASignInEvidence -MockWith {
            throw '403 Forbidden — AuditLog.Read.All requires Premium P1 license.'
        }
        $r = Get-MfaSignInEvidence -LookbackDays 7
        $r.Available     | Should -BeFalse
        $r.FailureReason | Should -Match 'P1|403|Forbidden|Premium'
    }
}

Describe 'Get-MfaSignInEvidence — bulk fetch + per-user aggregation' {

    BeforeAll {
        Mock -CommandName Test-MFASignInEvidenceEnvironment -ModuleName EntraChecks-MFASignInEvidence -MockWith {
            [pscustomobject]@{ IsAvailable = $true; TenantId = 'tid' }
        }
        # Single page with three sign-ins for two users.
        Mock -CommandName Invoke-MgGraphRequest -ModuleName EntraChecks-MFASignInEvidence -MockWith {
            @{
                value = @(
                    [pscustomobject]@{
                        userId = 'u1'
                        createdDateTime = '2026-04-30T10:00:00Z'
                        authenticationDetails = @(
                            [pscustomobject]@{ authenticationMethod = 'Password'; succeeded = $true }
                            [pscustomobject]@{ authenticationMethod = 'FIDO2 security key'; succeeded = $true }
                        )
                    }
                    [pscustomobject]@{
                        userId = 'u1'
                        createdDateTime = '2026-04-29T10:00:00Z'
                        authenticationDetails = @(
                            [pscustomobject]@{ authenticationMethod = 'Password'; succeeded = $true }
                            [pscustomobject]@{ authenticationMethod = 'FIDO2 security key'; succeeded = $true }
                        )
                    }
                    [pscustomobject]@{
                        userId = 'u2'
                        createdDateTime = '2026-04-30T08:00:00Z'
                        authenticationDetails = @(
                            [pscustomobject]@{ authenticationMethod = 'Password'; succeeded = $true }
                            [pscustomobject]@{ authenticationMethod = 'SMS'; succeeded = $true }
                        )
                    }
                )
                # No nextLink -> single-page
            }
        }
    }

    It 'aggregates sign-ins per userId' {
        $r = Get-MfaSignInEvidence -LookbackDays 30
        $r.Available       | Should -BeTrue
        $r.Evidence.Count  | Should -Be 2
        $r.Evidence['u1'].SignInsCount | Should -Be 2
        $r.Evidence['u2'].SignInsCount | Should -Be 1
    }

    It "captures LastMfaMethodUsed = 'fido2' for the user with FIDO2 sign-ins" {
        $r = Get-MfaSignInEvidence -LookbackDays 30
        $r.Evidence['u1'].LastMfaMethodUsed   | Should -BeExactly 'fido2'
        $r.Evidence['u1'].MfaChallengeOccurred | Should -BeTrue
        @($r.Evidence['u1'].MethodsObserved) -contains 'fido2' | Should -BeTrue
    }

    It "maps 'SMS' display string to canonical 'mobilePhone'" {
        $r = Get-MfaSignInEvidence -LookbackDays 30
        $r.Evidence['u2'].LastMfaMethodUsed | Should -BeExactly 'mobilePhone'
    }

    It 'restricts the returned evidence map when -UserIds is supplied' {
        $r = Get-MfaSignInEvidence -LookbackDays 30 -UserIds @('u1')
        $r.Evidence.ContainsKey('u1') | Should -BeTrue
        $r.Evidence.ContainsKey('u2') | Should -BeFalse
    }
}
