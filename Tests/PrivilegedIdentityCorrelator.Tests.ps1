<#
.SYNOPSIS
    Pester 5 test suite for the cross-surface privileged-identity correlator
    (PR 4 of the Privileged Identity Roster work).

.DESCRIPTION
    Merge-PrivilegedIdentityRosters is pure data-in / data-out — no AD or
    Entra cmdlets — so tests use synthetic rosters directly. Covers:
    1. OnPremisesSecurityIdentifier match (Strong + MatchedBy='OnPremisesSecurityIdentifier').
    2. Mail-attribute match (Probable).
    3. UPN local-part match (Weak).
    4. Identity override file resolves both sides as Strong.
    5. Override file precedence over auto-match signals.
    6. AD-only and Entra-only rows pass through with MatchConfidence='None'.
    7. CrossSurface flag set correctly on matched rows.
    8. HighestTier = numeric minimum of both sides.
    9. Findings emitted for cross-surface Tier 0, half-disabled accounts,
       privileged synced accounts, weak-match privileged.
    10. Override file loader rejects malformed entries.

    Run: Invoke-Pester -Path Tests/PrivilegedIdentityCorrelator.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-PrivilegeCatalog.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-PrivilegedIdentityCorrelator.psm1') -Force -DisableNameChecking

    function New-AdRoster {
        param([object[]]$Rows = @())
        @{
            Available = $true
            Domain = @{ Name = 'test.local'; SID = 'S-1-5-21-1-1-1'; DN = 'DC=test,DC=local' }
            Roster = @($Rows)
            Statistics = @{ TotalPrincipals = @($Rows).Count; ScannedAt = (Get-Date).ToUniversalTime().ToString('o') }
        }
    }
    function New-EntraRoster {
        param([object[]]$Rows = @())
        @{
            Available = $true
            Tenant = @{ TenantId = 'tenant-id-0'; Account = 'auditor@x'; AuthType = 'Delegated' }
            Roster = @($Rows)
            Statistics = @{ TotalPrincipals = @($Rows).Count; PimAvailable = $true; ScannedAt = (Get-Date).ToUniversalTime().ToString('o') }
        }
    }
    function New-AdRow {
        param(
            [string]$Sid, [string]$Sam, [string]$Display,
            [bool]$Enabled = $true, [int]$LastLogonDays = 5,
            [object]$HighestTier = 0,
            [object[]]$Privileges = @(@{ Key = 'AD:DomainAdmins'; Path = @('Domain Admins'); AssignmentType = 'Group (direct)'; DiscoveredAt = '2026-01-01T00:00:00Z' })
        )
        @{
            Sid = $Sid
            SamAccountName = $Sam
            DisplayName = $Display
            PrincipalType = 'User'
            Enabled = $Enabled
            LastLogonDays = $LastLogonDays
            SmartCardRequired = $false
            InProtectedUsers = $false
            DistinguishedName = "CN=$Sam,OU=Users,DC=test,DC=local"
            Privileges = @($Privileges)
            HighestTier = $HighestTier
            Sources = @('Get-ADGroupMember')
        }
    }
    function New-EntraRow {
        param(
            [string]$ObjectId, [string]$Upn, [string]$Display,
            [bool]$Enabled = $true,
            [string]$OnPremSid = $null, [string]$Mail = $null,
            [object]$HighestTier = 0,
            [object[]]$Privileges = @(@{ Key = 'Entra:GlobalAdministrator'; Path = @('Global Administrator (active)'); AssignmentType = 'Active'; DiscoveredAt = '2026-01-01T00:00:00Z' })
        )
        @{
            ObjectId = $ObjectId
            PrincipalType = 'User'
            Upn = $Upn
            DisplayName = $Display
            Enabled = $Enabled
            LastSignIn = $null
            AppId = $null
            ServicePrincipalType = $null
            OnPremisesSecurityIdentifier = $OnPremSid
            Mail = $Mail
            Privileges = @($Privileges)
            HighestTier = $HighestTier
            Sources = @('Get-MgRoleManagementDirectoryRoleAssignment')
        }
    }
}

Describe 'Merge-PrivilegedIdentityRosters — match-confidence ladder' {

    It 'classifies an OnPremisesSecurityIdentifier match as Strong' {
        $ad = New-AdRoster -Rows @(New-AdRow -Sid 'S-1-5-21-1-1-1001' -Sam 'jdoe' -Display 'John Doe')
        $entra = New-EntraRoster -Rows @(
            New-EntraRow -ObjectId 'oid-jdoe' -Upn 'jdoe@contoso.com' -Display 'John Doe' -OnPremSid 'S-1-5-21-1-1-1001'
        )
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra
        $row = $r.UnifiedRoster | Where-Object DisplayName -eq 'John Doe' | Select-Object -First 1
        $row.MatchConfidence | Should -BeExactly 'Strong'
        $row.MatchedBy       | Should -BeExactly 'OnPremisesSecurityIdentifier'
        $row.CrossSurface    | Should -BeTrue
        $row.AdSid           | Should -BeExactly 'S-1-5-21-1-1-1001'
        $row.EntraObjectId   | Should -BeExactly 'oid-jdoe'
    }

    It 'classifies a Mail-attribute match as Probable when no OnPremSid is present' {
        # AD row has Mail (we synthesise it for the test); Entra row has same Mail
        $adRow = New-AdRow -Sid 'S-1-5-21-1-1-2001' -Sam 'rsmith' -Display 'Rachel Smith'
        $adRow['Mail'] = 'rsmith@contoso.com'
        $ad = New-AdRoster -Rows @($adRow)
        $entra = New-EntraRoster -Rows @(
            New-EntraRow -ObjectId 'oid-rsmith' -Upn 'rsmith@contoso.com' -Display 'Rachel Smith' -Mail 'rsmith@contoso.com'
        )
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra
        $row = $r.UnifiedRoster | Where-Object DisplayName -eq 'Rachel Smith' | Select-Object -First 1
        $row.MatchConfidence | Should -BeExactly 'Probable'
        $row.MatchedBy       | Should -BeExactly 'Mail'
    }

    It 'classifies a UPN-local-part match as Weak when no stronger signal is available' {
        $ad = New-AdRoster -Rows @(New-AdRow -Sid 'S-1-5-21-1-1-3001' -Sam 'tlee' -Display 'Tom Lee')
        $entra = New-EntraRoster -Rows @(
            New-EntraRow -ObjectId 'oid-tlee' -Upn 'tlee@contoso.com' -Display 'Tom Lee'
        )
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra
        $row = $r.UnifiedRoster | Where-Object DisplayName -eq 'Tom Lee' | Select-Object -First 1
        $row.MatchConfidence | Should -BeExactly 'Weak'
        $row.MatchedBy       | Should -BeExactly 'UpnLocalPart'
    }

    It 'leaves single-surface rows with MatchConfidence None' {
        $ad = New-AdRoster -Rows @(New-AdRow -Sid 'S-1-5-21-1-1-9001' -Sam 'adonly' -Display 'AD Only')
        $entra = New-EntraRoster -Rows @(
            New-EntraRow -ObjectId 'oid-entraonly' -Upn 'entraonly@contoso.com' -Display 'Entra Only'
        )
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra
        $adOnly = $r.UnifiedRoster | Where-Object DisplayName -eq 'AD Only' | Select-Object -First 1
        $entraOnly = $r.UnifiedRoster | Where-Object DisplayName -eq 'Entra Only' | Select-Object -First 1
        $adOnly.MatchConfidence    | Should -BeExactly 'None'
        $adOnly.CrossSurface       | Should -BeFalse
        $entraOnly.MatchConfidence | Should -BeExactly 'None'
        $entraOnly.CrossSurface    | Should -BeFalse
    }
}

Describe 'Merge-PrivilegedIdentityRosters — identity override file' {

    It 'honors override entries as Strong matches regardless of other signals' {
        $overridePath = Join-Path $TestDrive 'overrides.json'
        @(@{
            AdSid = 'S-1-5-21-1-1-4001'
            EntraObjectId = 'oid-cusotmer'
            CanonicalId = 'manual@example.com'
            Note = 'unit test'
        }) | ConvertTo-Json | Set-Content -Path $overridePath

        # Note: AD has SAM = 'manual', Entra UPN's local-part is 'manual2' — the
        # name-based fallback would NOT match. Only the override does.
        $ad = New-AdRoster -Rows @(New-AdRow -Sid 'S-1-5-21-1-1-4001' -Sam 'manual' -Display 'Manual Override')
        $entra = New-EntraRoster -Rows @(
            New-EntraRow -ObjectId 'oid-cusotmer' -Upn 'manual2@example.com' -Display 'Manual Override'
        )
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra -IdentityOverridesPath $overridePath
        $row = $r.UnifiedRoster | Where-Object CanonicalId -eq 'manual@example.com' | Select-Object -First 1
        $row | Should -Not -BeNullOrEmpty
        $row.MatchConfidence | Should -BeExactly 'Strong'
        $row.MatchedBy       | Should -BeExactly 'IdentityOverride'
        $row.CrossSurface    | Should -BeTrue
    }

    It 'throws when the override file has malformed entries' {
        $bad = Join-Path $TestDrive 'bad.json'
        @(@{ AdSid = 'no-canonical-id' }) | ConvertTo-Json | Set-Content -Path $bad
        {
            Merge-PrivilegedIdentityRosters -AdRoster (New-AdRoster) -EntraRoster (New-EntraRoster) -IdentityOverridesPath $bad
        } | Should -Throw -ExpectedMessage '*missing CanonicalId*'
    }

    It 'silently proceeds when the override file does not exist' {
        $r = Merge-PrivilegedIdentityRosters -AdRoster (New-AdRoster) -EntraRoster (New-EntraRoster) -IdentityOverridesPath 'C:\does-not-exist.json'
        $r.Statistics.OverrideCount | Should -Be 0
    }
}

Describe 'Merge-PrivilegedIdentityRosters — coalesced privileges and tier' {

    It 'concatenates AD and Entra privileges on the matched row' {
        $ad = New-AdRoster -Rows @(New-AdRow -Sid 'S-1-5-21-1-1-1001' -Sam 'jdoe' -Display 'John Doe')
        $entra = New-EntraRoster -Rows @(
            New-EntraRow -ObjectId 'oid-jdoe' -Upn 'jdoe@contoso.com' -Display 'John Doe' -OnPremSid 'S-1-5-21-1-1-1001'
        )
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra
        $row = $r.UnifiedRoster | Where-Object DisplayName -eq 'John Doe' | Select-Object -First 1
        @($row.Privileges).Count | Should -Be 2
        ($row.Privileges | ForEach-Object Key) | Should -Contain 'AD:DomainAdmins'
        ($row.Privileges | ForEach-Object Key) | Should -Contain 'Entra:GlobalAdministrator'
    }

    It 'computes HighestTier as the minimum of AD and Entra tiers' {
        $adRow = New-AdRow -Sid 'S-1-5-21-1-1-7001' -Sam 'mixed' -Display 'Mixed' -HighestTier 1
        $adRow.Privileges = @(@{ Key = 'AD:AccountOperators'; Path = @('Account Operators'); AssignmentType = 'Group (direct)'; DiscoveredAt = '2026-01-01T00:00:00Z' })
        $entraRow = New-EntraRow -ObjectId 'oid-mixed' -Upn 'mixed@x.com' -Display 'Mixed' -OnPremSid 'S-1-5-21-1-1-7001' -HighestTier 0
        $r = Merge-PrivilegedIdentityRosters -AdRoster (New-AdRoster -Rows @($adRow)) -EntraRoster (New-EntraRoster -Rows @($entraRow))
        $row = $r.UnifiedRoster | Where-Object DisplayName -eq 'Mixed' | Select-Object -First 1
        $row.HighestTier | Should -Be 0
    }
}

Describe 'Merge-PrivilegedIdentityRosters — finding emission' {

    It 'emits a Critical finding for cross-surface Tier 0 identities' {
        $ad = New-AdRoster -Rows @(New-AdRow -Sid 'S-1-5-21-1-1-1001' -Sam 'jdoe' -Display 'John Doe')
        $entra = New-EntraRoster -Rows @(
            New-EntraRow -ObjectId 'oid-jdoe' -Upn 'jdoe@contoso.com' -Display 'John Doe' -OnPremSid 'S-1-5-21-1-1-1001'
        )
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra
        $crit = $r.Findings | Where-Object Severity -eq 'Critical'
        @($crit).Count | Should -BeGreaterOrEqual 1
        ($crit[0].CheckName) | Should -Match 'CrossSurfaceTier0'
    }

    It 'emits a High finding when AD is disabled but Entra is enabled' {
        $ad = New-AdRoster -Rows @(New-AdRow -Sid 'S-1-5-21-1-1-1001' -Sam 'jdoe' -Display 'John Doe' -Enabled $false)
        $entra = New-EntraRoster -Rows @(
            New-EntraRow -ObjectId 'oid-jdoe' -Upn 'jdoe@contoso.com' -Display 'John Doe' -OnPremSid 'S-1-5-21-1-1-1001' -Enabled $true
        )
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra
        $f = $r.Findings | Where-Object CheckName -match 'AdDisabledEntraEnabled'
        @($f).Count | Should -Be 1
        $f[0].Severity | Should -BeExactly 'High'
    }

    It 'emits a High finding for privileged synced accounts (matched by OnPremSid + Tier 0)' {
        $ad = New-AdRoster -Rows @(New-AdRow -Sid 'S-1-5-21-1-1-1001' -Sam 'jdoe' -Display 'John Doe')
        $entra = New-EntraRoster -Rows @(
            New-EntraRow -ObjectId 'oid-jdoe' -Upn 'jdoe@contoso.com' -Display 'John Doe' -OnPremSid 'S-1-5-21-1-1-1001'
        )
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra
        $f = $r.Findings | Where-Object CheckName -match 'PrivilegedSyncedAccount'
        @($f).Count | Should -BeGreaterOrEqual 1
    }

    It 'emits a Medium finding for weak-match privileged identities' {
        # No OnPremSid, no Mail — falls through to Weak (UPN local-part)
        $ad = New-AdRoster -Rows @(New-AdRow -Sid 'S-1-5-21-1-1-1001' -Sam 'jdoe' -Display 'John Doe')
        $entra = New-EntraRoster -Rows @(
            New-EntraRow -ObjectId 'oid-jdoe' -Upn 'jdoe@contoso.com' -Display 'John Doe'
        )
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra
        $f = $r.Findings | Where-Object CheckName -match 'WeakMatchPrivileged'
        @($f).Count | Should -BeGreaterOrEqual 1
        $f[0].Severity | Should -BeExactly 'Medium'
    }
}

Describe 'Merge-PrivilegedIdentityRosters — graceful degradation' {

    It 'works with a single-side roster (Entra unavailable)' {
        $ad = New-AdRoster -Rows @(New-AdRow -Sid 'S-1-5-21-1-1-1001' -Sam 'jdoe' -Display 'John Doe')
        $entra = @{ Available = $false; FailureReason = 'no graph'; Roster = @(); Statistics = @{} }
        $r = Merge-PrivilegedIdentityRosters -AdRoster $ad -EntraRoster $entra
        $r.Statistics.Total      | Should -Be 1
        $r.Statistics.AdOnly     | Should -Be 1
        $r.Statistics.EntraOnly  | Should -Be 0
    }
}
