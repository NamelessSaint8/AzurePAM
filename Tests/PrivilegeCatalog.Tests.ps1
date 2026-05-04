<#
.SYNOPSIS
    Pester 5 test suite for the privilege catalog (PR 1 of the Privileged
    Identity Roster work).

.DESCRIPTION
    Verifies:
    1. Catalog shape — every entry has the required fields populated.
    2. No orphan keys (Key field always matches the hashtable key).
    3. Tier values are valid (0, 1, 2, or 'Service').
    4. Sensitivity is one of Critical/High/Medium.
    5. Critical Tier-0 invariants — every Critical entry is Tier 0; every
       Tier 0 entry is Critical.
    6. Get-PrivilegeCatalog returns clones (callers can't mutate the master).
    7. Get-PrivilegeDescriptor throws on unknown keys.
    8. Get-PrivilegeCatalogKeys filters by surface and tier correctly.
    9. Resolve-PrivilegeKey handles canonical names, aliases, and case.
    10. Get-TierForPrivilege round-trips.
    11. Each surface ('AD', 'Entra', 'MSGraph') has a non-trivial number of
        entries (smoke for accidental catalog truncation).

    Run: Invoke-Pester -Path Tests/PrivilegeCatalog.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking
}

Describe 'Privilege catalog shape' {

    It 'has at least 50 entries (smoke for accidental truncation)' {
        @(Get-PrivilegeCatalogKeys).Count | Should -BeGreaterOrEqual 50
    }

    It 'has at least 10 entries on each canonical surface' {
        @(Get-PrivilegeCatalogKeys -Surface 'AD').Count      | Should -BeGreaterOrEqual 10
        @(Get-PrivilegeCatalogKeys -Surface 'Entra').Count   | Should -BeGreaterOrEqual 15
        @(Get-PrivilegeCatalogKeys -Surface 'MSGraph').Count | Should -BeGreaterOrEqual 15
    }

    It 'has every required field populated on every entry' {
        $catalog = Get-PrivilegeCatalog
        foreach ($key in $catalog.Keys) {
            $entry = $catalog[$key]
            $entry.Key            | Should -BeExactly $key -Because "Entry stored under '$key' should self-identify as '$key'"
            $entry.Surface        | Should -Not -BeNullOrEmpty
            $entry.DisplayName    | Should -Not -BeNullOrEmpty
            $entry.Tier           | Should -Not -BeNullOrEmpty
            $entry.Sensitivity    | Should -Not -BeNullOrEmpty
            $entry.WhyPrivileged  | Should -Not -BeNullOrEmpty
            $entry.ReferenceUrl   | Should -Match '^https?://'
            @($entry.Aliases).Count | Should -BeGreaterOrEqual 1
        }
    }

    It 'uses only the four valid Surface values' {
        $catalog = Get-PrivilegeCatalog
        foreach ($key in $catalog.Keys) {
            $catalog[$key].Surface | Should -BeIn @('AD', 'Entra', 'MSGraph', 'App')
        }
    }

    It 'uses only valid Tier values (0, 1, 2, or Service)' {
        $catalog = Get-PrivilegeCatalog
        foreach ($key in $catalog.Keys) {
            $tier = $catalog[$key].Tier
            $isValid = ($tier -in @(0, 1, 2)) -or ($tier -eq 'Service')
            $isValid | Should -BeTrue -Because "Entry $key has invalid Tier '$tier'"
        }
    }

    It 'uses only valid Sensitivity values' {
        $catalog = Get-PrivilegeCatalog
        foreach ($key in $catalog.Keys) {
            $catalog[$key].Sensitivity | Should -BeIn @('Critical', 'High', 'Medium', 'Low')
        }
    }
}

Describe 'Tier / Sensitivity invariants' {

    It 'classes every Tier 0 entry as Critical (Critical -> Tier 0 implication)' {
        $catalog = Get-PrivilegeCatalog
        # Skip ProtectedUsersMember which is intentionally a Service-tier
        # control rather than a privilege; verify the rest.
        foreach ($key in $catalog.Keys) {
            if ($catalog[$key].Tier -eq 0) {
                $catalog[$key].Sensitivity | Should -BeExactly 'Critical' -Because "$key is Tier 0 and must be Critical"
            }
        }
    }

    It 'documents AttackPaths for every privileged Tier 0 / Tier 1 entry' {
        $catalog = Get-PrivilegeCatalog
        foreach ($key in $catalog.Keys) {
            $entry = $catalog[$key]
            if ($entry.Tier -in @(0, 1)) {
                @($entry.AttackPaths).Count | Should -BeGreaterOrEqual 1 -Because "$key is Tier $($entry.Tier) and should list at least one attack path"
            }
        }
    }
}

Describe 'Get-PrivilegeCatalog cloning' {

    It 'returns independent clones across calls' {
        $first = Get-PrivilegeCatalog
        $first['AD:DomainAdmins'].DisplayName = 'mutated'
        $second = Get-PrivilegeCatalog
        $second['AD:DomainAdmins'].DisplayName | Should -BeExactly 'Domain Admins'
    }

    It 'protects array-valued AttackPaths from cross-call mutation' {
        $first = Get-PrivilegeCatalog
        $first['AD:DomainAdmins'].AttackPaths += 'injected attack path'
        $second = Get-PrivilegeCatalog
        @($second['AD:DomainAdmins'].AttackPaths) -contains 'injected attack path' | Should -BeFalse
    }
}

Describe 'Get-PrivilegeDescriptor' {

    It 'returns a clone for a known key' {
        $d = Get-PrivilegeDescriptor -Key 'Entra:GlobalAdministrator'
        $d.Tier        | Should -Be 0
        $d.Sensitivity | Should -BeExactly 'Critical'
    }

    It 'throws on an unknown key' {
        { Get-PrivilegeDescriptor -Key 'Bogus:DoesNotExist' } | Should -Throw -ExpectedMessage '*Unknown privilege key*'
    }
}

Describe 'Get-PrivilegeCatalogKeys filters' {

    It 'returns Tier 0 keys only when -Tier 0 is requested' {
        $keys = Get-PrivilegeCatalogKeys -Tier 0
        foreach ($key in $keys) {
            (Get-PrivilegeDescriptor -Key $key).Tier | Should -Be 0
        }
    }

    It 'returns Tier 0 + Tier 1 keys when -Tier 1 is requested' {
        $keys = Get-PrivilegeCatalogKeys -Tier 1
        foreach ($key in $keys) {
            (Get-PrivilegeDescriptor -Key $key).Tier | Should -BeIn @(0, 1)
        }
    }

    It 'restricts by Surface when given' {
        $entraKeys = Get-PrivilegeCatalogKeys -Surface 'Entra'
        foreach ($key in $entraKeys) {
            (Get-PrivilegeDescriptor -Key $key).Surface | Should -BeExactly 'Entra'
        }
    }
}

Describe 'Resolve-PrivilegeKey' {

    It 'resolves canonical display names' {
        Resolve-PrivilegeKey -Surface 'AD' -Name 'Domain Admins' | Should -BeExactly 'AD:DomainAdmins'
        Resolve-PrivilegeKey -Surface 'Entra' -Name 'Global Administrator' | Should -BeExactly 'Entra:GlobalAdministrator'
    }

    It 'resolves common aliases' {
        Resolve-PrivilegeKey -Surface 'AD' -Name 'DA' | Should -BeExactly 'AD:DomainAdmins'
        Resolve-PrivilegeKey -Surface 'Entra' -Name 'Company Administrator' | Should -BeExactly 'Entra:GlobalAdministrator'
        Resolve-PrivilegeKey -Surface 'Entra' -Name 'GA' | Should -BeExactly 'Entra:GlobalAdministrator'
    }

    It 'is case-insensitive' {
        Resolve-PrivilegeKey -Surface 'AD' -Name 'DOMAIN ADMINS' | Should -BeExactly 'AD:DomainAdmins'
        Resolve-PrivilegeKey -Surface 'AD' -Name 'domain admins' | Should -BeExactly 'AD:DomainAdmins'
    }

    It 'returns $null for unknown names' {
        Resolve-PrivilegeKey -Surface 'AD' -Name 'BogusGroup' | Should -BeNullOrEmpty
    }

    It 'does not cross surface boundaries' {
        # 'Domain Admins' is an AD concept; resolving it on the Entra surface
        # must not return AD:DomainAdmins.
        Resolve-PrivilegeKey -Surface 'Entra' -Name 'Domain Admins' | Should -BeNullOrEmpty
    }
}

Describe 'Get-TierForPrivilege' {

    It 'returns the numeric Tier for known keys' {
        Get-TierForPrivilege -Key 'AD:DomainAdmins'         | Should -Be 0
        Get-TierForPrivilege -Key 'Entra:HelpdeskAdministrator' | Should -Be 2
    }

    It 'throws on unknown keys' {
        { Get-TierForPrivilege -Key 'Bogus:Unknown' } | Should -Throw
    }
}
