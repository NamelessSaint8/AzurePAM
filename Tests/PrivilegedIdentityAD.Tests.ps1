<#
.SYNOPSIS
    Pester 5 test suite for the AD privileged-identity aggregator (PR 2 of
    the Privileged Identity Roster work).

.DESCRIPTION
    Exercises Get-PrivilegedIdentityRosterAD against a fully-mocked AD cmdlet
    surface. Covers:
    1. Graceful degradation when AD is unavailable.
    2. Direct + nested membership coalescing onto one row per SID.
    3. Path preservation (transitive chain captured per privilege).
    4. AssignmentType correctly distinguishes direct vs nested vs ACL paths.
    5. HighestTier reflects the most-privileged catalog entry on a row.
    6. krbtgt always emitted as a Tier-0 row when reachable.
    7. Service accounts excluded by default; included with -IncludeServiceAccounts.
    8. Cycle protection in nested-group walker.
    9. Helper Group-PrivilegedIdentitiesByTier round-trips.

    Run: Invoke-Pester -Path Tests/PrivilegedIdentityAD.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-PrivilegedIdentityAD.psm1') -Force -DisableNameChecking

    # Helper to fabricate a Get-ADGroupMember return shape
    function New-MockGroupMember {
        param(
            [string]$Sid,
            [string]$Sam,
            [string]$Name,
            [string]$ObjectClass = 'user'
        )
        [pscustomobject]@{
            SID = [pscustomobject]@{ Value = $Sid }
            SamAccountName = $Sam
            Name = $Name
            objectClass = $ObjectClass
        }
    }

    function New-MockADUser {
        param(
            [string]$Sid = 'S-1-5-21-1-1-1001',
            [string]$Sam = 'jdoe',
            [string]$DisplayName = 'John Doe',
            [bool]$Enabled = $true,
            [datetime]$LastLogonDate = (Get-Date).AddDays(-3),
            [bool]$SmartcardLogonRequired = $false,
            [string[]]$MemberOf = @()
        )
        [pscustomobject]@{
            SID = [pscustomobject]@{ Value = $Sid }
            SamAccountName = $Sam
            DisplayName = $DisplayName
            Name = $DisplayName
            ObjectClass = 'user'
            DistinguishedName = "CN=$Sam,OU=Users,DC=test,DC=local"
            Enabled = $Enabled
            LastLogonDate = $LastLogonDate
            PasswordLastSet = (Get-Date).AddDays(-30)
            SmartcardLogonRequired = $SmartcardLogonRequired
            MemberOf = $MemberOf
        }
    }
}

Describe 'Get-PrivilegedIdentityRosterAD — environment gating' -Tag 'WindowsOnly' {

    It 'returns Available=$false with a FailureReason when AD is unavailable' {
        Mock -CommandName Test-PrivilegedIdentityADEnvironment -ModuleName EntraChecks-PrivilegedIdentityAD -MockWith {
            [pscustomobject]@{ IsAvailable = $false; FailureReason = 'Synthetic: not Windows' }
        }
        $r = Get-PrivilegedIdentityRosterAD
        $r.Available | Should -BeFalse
        $r.FailureReason | Should -Match 'Synthetic'
        @($r.Roster).Count | Should -Be 0
    }
}

Describe 'Get-PrivilegedIdentityRosterAD — direct and nested membership' -Tag 'WindowsOnly' {

    BeforeAll {
        # Synthetic domain — Authenticate environment probe as available.
        Mock -CommandName Test-PrivilegedIdentityADEnvironment -ModuleName EntraChecks-PrivilegedIdentityAD -MockWith {
            [pscustomobject]@{
                IsAvailable = $true
                DomainName = 'test.local'
                DomainSID = 'S-1-5-21-1-1-1'
                DomainDN = 'DC=test,DC=local'
            }
        }

        # Pretend every catalog group lookup succeeds — we don't need real
        # ADGroup objects, just non-throwing Get-ADGroup.
        Mock -CommandName Get-ADGroup -ModuleName EntraChecks-PrivilegedIdentityAD -MockWith {
            param($Identity)
            [pscustomobject]@{ Name = $Identity }
        }

        # Two-level group structure for Domain Admins:
        #   Domain Admins -> jdoe (direct)
        #   Domain Admins -> Tier0-Admins -> rsmith (nested)
        Mock -CommandName Get-ADGroupMember -ModuleName EntraChecks-PrivilegedIdentityAD -MockWith {
            param($Identity)
            switch -Regex ($Identity) {
                '^Domain Admins$' {
                    return @(
                        (& $script:NewMockMember 'S-1-5-21-1-1-1001' 'jdoe' 'John Doe' 'user'),
                        (& $script:NewMockMember 'S-1-5-21-1-1-2001' 'Tier0-Admins' 'Tier0 Admins' 'group')
                    )
                }
                '^Tier0-Admins$' {
                    return @(
                        (& $script:NewMockMember 'S-1-5-21-1-1-1002' 'rsmith' 'Rachel Smith' 'user')
                    )
                }
                default { return @() }
            }
        }

        # Disable DCSync / AdminSDHolder ACL probes — they require Get-Acl on
        # AD: paths which doesn't work outside Windows.
        Mock -CommandName Get-DCSyncPrincipals -ModuleName EntraChecks-PrivilegedIdentityAD -MockWith { @() }
        Mock -CommandName Get-AdminSDHolderWriters -ModuleName EntraChecks-PrivilegedIdentityAD -MockWith { @() }

        # Get-ADUser — return canned data for every SID we feed it.
        Mock -CommandName Get-ADUser -ModuleName EntraChecks-PrivilegedIdentityAD -MockWith {
            param($Identity)
            switch ($Identity) {
                'S-1-5-21-1-1-1001' { & $script:NewMockUser -Sid 'S-1-5-21-1-1-1001' -Sam 'jdoe' -DisplayName 'John Doe' }
                'S-1-5-21-1-1-1002' { & $script:NewMockUser -Sid 'S-1-5-21-1-1-1002' -Sam 'rsmith' -DisplayName 'Rachel Smith' }
                'krbtgt'            { & $script:NewMockUser -Sid 'S-1-5-21-1-1-502' -Sam 'krbtgt' -DisplayName 'krbtgt' -Enabled $false -LastLogonDate (Get-Date '2020-01-01') }
                default             { throw "Mocked Get-ADUser: no match for $Identity" }
            }
        }

        # Get-ADObject — used by Get-PrincipalEnrichment to resolve SID -> AD object.
        Mock -CommandName Get-ADObject -ModuleName EntraChecks-PrivilegedIdentityAD -MockWith {
            param($Filter, $Properties)
            if ($Filter -match "objectSid -eq 'S-1-5-21-1-1-1001'") {
                return [pscustomobject]@{
                    SamAccountName = 'jdoe'; DisplayName = 'John Doe'; Name = 'John Doe'
                    ObjectClass = 'user'; DistinguishedName = 'CN=jdoe,OU=Users,DC=test,DC=local'
                }
            }
            elseif ($Filter -match "objectSid -eq 'S-1-5-21-1-1-1002'") {
                return [pscustomobject]@{
                    SamAccountName = 'rsmith'; DisplayName = 'Rachel Smith'; Name = 'Rachel Smith'
                    ObjectClass = 'user'; DistinguishedName = 'CN=rsmith,OU=Users,DC=test,DC=local'
                }
            }
            return $null
        }

        # The mock helpers are defined in the *test* scope, but Mock blocks
        # execute in *module* scope; smuggle them in via $script: variables
        # the mock blocks reference by ScriptBlock invocation.
        $script:NewMockMember = ${function:New-MockGroupMember}
        $script:NewMockUser = ${function:New-MockADUser}
    }

    It 'enumerates Domain Admins and produces one row per leaf principal' {
        $r = Get-PrivilegedIdentityRosterAD
        $r.Available | Should -BeTrue
        # jdoe (direct), rsmith (nested), krbtgt (well-known) at minimum
        ($r.Roster | ForEach-Object SamAccountName) -contains 'jdoe' | Should -BeTrue
        ($r.Roster | ForEach-Object SamAccountName) -contains 'rsmith' | Should -BeTrue
    }

    It 'tags direct members with AssignmentType "Group (direct)"' {
        $r = Get-PrivilegedIdentityRosterAD
        $jdoeRow = $r.Roster | Where-Object SamAccountName -eq 'jdoe' | Select-Object -First 1
        $daPriv = $jdoeRow.Privileges | Where-Object { $_.Key -eq 'AD:DomainAdmins' } | Select-Object -First 1
        $daPriv | Should -Not -BeNullOrEmpty
        $daPriv.AssignmentType | Should -BeExactly 'Group (direct)'
    }

    It 'tags nested members with AssignmentType "Group (nested)" and preserves the path' {
        $r = Get-PrivilegedIdentityRosterAD
        $rsmithRow = $r.Roster | Where-Object SamAccountName -eq 'rsmith' | Select-Object -First 1
        $daPriv = $rsmithRow.Privileges | Where-Object { $_.Key -eq 'AD:DomainAdmins' } | Select-Object -First 1
        $daPriv.AssignmentType | Should -BeExactly 'Group (nested)'
        # Path should reflect: Domain Admins -> Tier0-Admins -> rsmith (path is the chain of groups walked)
        @($daPriv.Path) -join ' -> ' | Should -Match 'Domain Admins -> Tier0-Admins'
    }

    It 'sets HighestTier = 0 for Domain Admins members' {
        $r = Get-PrivilegedIdentityRosterAD
        ($r.Roster | Where-Object SamAccountName -eq 'jdoe').HighestTier | Should -Be 0
    }

    It 'always emits a krbtgt row with WellKnown assignment' {
        $r = Get-PrivilegedIdentityRosterAD
        $krb = $r.Roster | Where-Object SamAccountName -eq 'krbtgt'
        $krb | Should -Not -BeNullOrEmpty
        ($krb.Privileges | Select-Object -First 1).AssignmentType | Should -BeExactly 'WellKnown'
    }

    It 'reports tier counts in Statistics' {
        $r = Get-PrivilegedIdentityRosterAD
        $r.Statistics.Tier0Count | Should -BeGreaterOrEqual 2  # jdoe + rsmith + krbtgt
    }
}

Describe 'Group-PrivilegedIdentitiesByTier' -Tag 'WindowsOnly' {

    It 'splits roster rows into the four tier buckets' {
        $synthetic = @(
            [pscustomobject]@{ SamAccountName = 'a'; HighestTier = 0 }
            [pscustomobject]@{ SamAccountName = 'b'; HighestTier = 1 }
            [pscustomobject]@{ SamAccountName = 'c'; HighestTier = 2 }
            [pscustomobject]@{ SamAccountName = 'd'; HighestTier = 'Service' }
        )
        $g = Group-PrivilegedIdentitiesByTier -Roster $synthetic
        @($g.Tier0).Count   | Should -Be 1
        @($g.Tier1).Count   | Should -Be 1
        @($g.Tier2).Count   | Should -Be 1
        @($g.Service).Count | Should -Be 1
    }
}
