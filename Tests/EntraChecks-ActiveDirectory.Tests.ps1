<#
.SYNOPSIS
    Pester 5 suite for EntraChecks-ActiveDirectory.psm1.

.DESCRIPTION
    Fixture-driven tests. AD cmdlets are stubbed globally before the module
    loads so tests run on non-domain-joined CI machines without RSAT.

    Coverage:
      1. Test-ADEnvironment — all four degradation paths
      2. Invoke-ActiveDirectoryAssessment — early-exit, include filter,
         exclude filter, schema compliance
      3. Representative Test-* functions across all 5 categories

    Run:
      Invoke-Pester -Path Tests/EntraChecks-ActiveDirectory.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot

    # AD cmdlet stubs — declared in the global scope so they exist on
    # machines that don't have RSAT. Pester mocks replace these.
    function Global:Get-ADDomain { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADForest { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADDomainController { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADUser { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADComputer { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADGroup { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADGroupMember { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADObject { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADTrust { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADServiceAccount { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADOrganizationalUnit { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADDefaultDomainPasswordPolicy { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADRootDSE { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-GPO { param([Parameter(ValueFromRemainingArguments = $true)]$args) }

    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-ActiveDirectory.psm1') -Force

    function New-TestDomain {
        [pscustomobject]@{
            DNSRoot = 'test.local'
            NetBIOSName = 'TEST'
            DomainMode = 'Windows2016Domain'
            DistinguishedName = 'DC=test, DC=local'
            DomainSID = [pscustomobject]@{ Value = 'S-1-5-21-1234567890-1234567890-1234567890' }
        }
    }

    function New-TestADUser {
        param(
            [string]$Name = 'testuser',
            [bool]$Enabled = $true,
            [datetime]$LastLogonDate = (Get-Date).AddDays(-10),
            [datetime]$PasswordLastSet = (Get-Date).AddDays(-30),
            [bool]$PasswordNeverExpires = $false,
            [bool]$DoesNotRequirePreAuth = $false,
            [bool]$TrustedForDelegation = $false,
            [bool]$SmartcardLogonRequired = $false,
            $SIDHistory = $null,
            [string[]]$ServicePrincipalName = @(),
            [string]$Description = '',
            [datetime]$whenCreated = (Get-Date).AddDays(-100)
        )
        [pscustomobject]@{
            SamAccountName = $Name
            Name = $Name
            Enabled = $Enabled
            LastLogonDate = $LastLogonDate
            PasswordLastSet = $PasswordLastSet
            PasswordNeverExpires = $PasswordNeverExpires
            DoesNotRequirePreAuth = $DoesNotRequirePreAuth
            TrustedForDelegation = $TrustedForDelegation
            SmartcardLogonRequired = $SmartcardLogonRequired
            SIDHistory = $SIDHistory
            ServicePrincipalName = $ServicePrincipalName
            ObjectClass = 'user'
            Description = $Description
            whenCreated = $whenCreated
            SID = [pscustomobject]@{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-1001' }
            MemberOf = @()
        }
    }
}

Describe 'Test-ADEnvironment degradation paths' -Tag 'WindowsOnly' {

    It 'returns IsAvailable=$false when ActiveDirectory module is not present' {
        InModuleScope EntraChecks-ActiveDirectory {
            Mock Get-Module { $null } -ParameterFilter { $ListAvailable -and $Name -eq 'ActiveDirectory' }
            $result = Test-ADEnvironment
            $result.IsAvailable | Should -Be $false
            $result.FailureReason | Should -Match 'not installed'
        }
    }

    It 'returns IsAvailable=$false when Get-ADDomain throws' {
        InModuleScope EntraChecks-ActiveDirectory {
            Mock Get-Module { [pscustomobject]@{ Name = 'ActiveDirectory' } } -ParameterFilter { $ListAvailable -and $Name -eq 'ActiveDirectory' }
            Mock Import-Module { }
            Mock Get-ADDomain { throw 'Unable to contact AD' }
            $result = Test-ADEnvironment
            $result.IsAvailable | Should -Be $false
            $result.FailureReason | Should -Match 'Unable to query Active Directory|not domain-joined'
        }
    }

    It 'returns IsAvailable=$true when everything works' {
        InModuleScope EntraChecks-ActiveDirectory {
            Mock Get-Module { [pscustomobject]@{ Name = 'ActiveDirectory' } } -ParameterFilter { $ListAvailable -and $Name -eq 'ActiveDirectory' }
            Mock Import-Module { }
            Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'test.local' } }
            $result = Test-ADEnvironment
            $result.IsAvailable | Should -Be $true
            $result.DomainName | Should -Be 'test.local'
        }
    }
}

Describe 'Invoke-ActiveDirectoryAssessment entry point' -Tag 'WindowsOnly' {

    It 'returns a single INFO finding when environment is unavailable' {
        InModuleScope EntraChecks-ActiveDirectory {
            Mock Test-ADEnvironment {
                [pscustomobject]@{
                    IsAvailable = $false
                    FailureReason = 'Simulated failure for test'
                    IsDomainAdmin = $false
                    DomainName = $null
                    ModulePresent = $false
                    Platform = 'Windows'
                }
            }
            $findings = Invoke-ActiveDirectoryAssessment
            $findings.Count | Should -Be 1
            $findings[0].Status | Should -Be 'INFO'
            $findings[0].Description | Should -Match 'Simulated failure for test'
        }
    }

    It 'honors -IncludeChecks to scope which Test-* functions run' {
        InModuleScope EntraChecks-ActiveDirectory {
            Mock Test-ADEnvironment {
                [pscustomobject]@{
                    IsAvailable = $true; FailureReason = $null; IsDomainAdmin = $true
                    DomainName = 'test.local'; ModulePresent = $true; Platform = 'Windows'
                }
            }
            Mock Test-KerberosPreAuthDisabled {
                $script:Findings += [pscustomobject]@{
                    CheckName = 'Test-KerberosPreAuthDisabled'; Status = 'PASS'
                    Severity = 'Low'; Category = 'Authentication'; Object = 'x'
                    Description = 'd'; Remediation = 'r'; ComplianceFrameworks = @()
                    ComplianceReference = ''; RiskScore = 10; Type = 'AD_Test'; Source = 'ActiveDirectory'
                    Time = Get-Date
                }
            }
            Mock Test-UnconstrainedDelegation {
                $script:Findings += [pscustomobject]@{
                    CheckName = 'Test-UnconstrainedDelegation'; Status = 'PASS'
                    Severity = 'Low'; Category = 'Delegation'; Object = 'y'
                    Description = 'd'; Remediation = 'r'; ComplianceFrameworks = @()
                    ComplianceReference = ''; RiskScore = 10; Type = 'AD_Test'; Source = 'ActiveDirectory'
                    Time = Get-Date
                }
            }
            $findings = Invoke-ActiveDirectoryAssessment -IncludeChecks @('Test-KerberosPreAuthDisabled')
            @($findings.CheckName | Where-Object { $_ -eq 'Test-KerberosPreAuthDisabled' }).Count | Should -Be 1
            @($findings.CheckName | Where-Object { $_ -eq 'Test-UnconstrainedDelegation' }).Count | Should -Be 0
        }
    }

    It 'honors -ExcludeChecks to skip specific Test-* functions' {
        InModuleScope EntraChecks-ActiveDirectory {
            Mock Test-ADEnvironment {
                [pscustomobject]@{
                    IsAvailable = $true; FailureReason = $null; IsDomainAdmin = $true
                    DomainName = 'test.local'; ModulePresent = $true; Platform = 'Windows'
                }
            }
            # Stub every single check function with an empty body so nothing actually calls AD.
            $all = @(
                'Test-ADForestAndDomain', 'Test-DomainControllers', 'Test-ADPasswordPolicy',
                'Test-ADStaleAccounts', 'Test-PrivilegedGroupMembership', 'Test-ProtectedUsersAdoption',
                'Test-DomainTrusts', 'Test-ADServiceAccounts', 'Test-KrbTgtAccountAge',
                'Test-DelegationOverview', 'Test-GPOInventory', 'Test-DuplicateSPNs',
                'Test-PrivilegedObjectACLs', 'Test-GPPPasswords', 'Test-KerberosPreAuthDisabled',
                'Test-UnconstrainedDelegation', 'Test-PasswordNeverExpires', 'Test-SIDHistory',
                'Test-PrivilegedSmartcardRequirement', 'Test-PrivilegedGroupCreep', 'Test-AdminSDHolderDrift',
                'Test-DangerousSIDsInPrivilegedGroups', 'Test-PasswordsInDescription', 'Test-UserAccountsWithSPN',
                'Test-OUAndGPODelegation', 'Test-RecentPrivilegedAccounts', 'Test-NestedGroupPrivilegePaths',
                'Test-SensitiveObjectACLDrift', 'Test-ShadowGroupNames'
            )
            foreach ($fn in $all) { Mock $fn { } }
            # Mock one check so it DOES emit a finding when allowed to run.
            Mock Test-KrbTgtAccountAge {
                $script:Findings += [pscustomobject]@{
                    CheckName = 'Test-KrbTgtAccountAge'; Status = 'PASS'
                    Severity = 'Low'; Category = 'Authentication'; Object = 'krbtgt'
                    Description = 'd'; Remediation = 'r'; ComplianceFrameworks = @()
                    ComplianceReference = ''; RiskScore = 10; Type = 'AD_Test'; Source = 'ActiveDirectory'
                    Time = Get-Date
                }
            }

            $findings = Invoke-ActiveDirectoryAssessment -ExcludeChecks @('Test-KrbTgtAccountAge')
            @($findings.CheckName | Where-Object { $_ -eq 'Test-KrbTgtAccountAge' }).Count | Should -Be 0
        }
    }
}

Describe 'Finding schema compliance' -Tag 'WindowsOnly' {

    It 'every finding carries the 13 required fields' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Add-ADFinding -CheckName 'Test-KerberosPreAuthDisabled' -Status 'FAIL' `
                -Object 'testuser' -Description 'd' -Remediation 'r'
            $f = $script:Findings[0]
            'Time', 'CheckName', 'Status', 'Severity', 'Category', 'Object', 'Description',
            'Remediation', 'ComplianceFrameworks', 'ComplianceReference', 'RiskScore', 'Type', 'Source' |
                ForEach-Object { $f.PSObject.Properties.Name | Should -Contain $_ }
        }
    }

    It 'maps OK status to PASS for migration from legacy script' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Add-ADFinding -CheckName 'Test-KerberosPreAuthDisabled' -Status 'OK' `
                -Object 'x' -Description 'd' -Remediation 'r'
            $script:Findings[0].Status | Should -Be 'PASS'
        }
    }

    It 'escalates to Critical severity for checks on the critical list' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Add-ADFinding -CheckName 'Test-UnconstrainedDelegation' -Status 'FAIL' `
                -Object 'x' -Description 'd' -Remediation 'r'
            $script:Findings[0].Severity | Should -Be 'Critical'
        }
    }

    It 'defaults to High severity for FAIL on non-critical checks' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Add-ADFinding -CheckName 'Test-PasswordNeverExpires' -Status 'FAIL' `
                -Object 'x' -Description 'd' -Remediation 'r'
            $script:Findings[0].Severity | Should -Be 'High'
        }
    }

    It 'populates ComplianceFrameworks from metadata table' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Add-ADFinding -CheckName 'Test-KrbTgtAccountAge' -Status 'FAIL' `
                -Object 'krbtgt' -Description 'd' -Remediation 'r'
            $script:Findings[0].ComplianceFrameworks | Should -Contain 'CIS-AD'
            $script:Findings[0].ComplianceFrameworks | Should -Contain 'SOC2-CC6.1'
        }
    }
}

Describe 'Test-KerberosPreAuthDisabled' -Tag 'WindowsOnly' {

    It 'emits FAIL for each enabled user with DoesNotRequirePreAuth=$true' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            # Can't reference outer-scope functions from inside InModuleScope without a workaround.
            Mock Get-ADUser {
                @(
                    [pscustomobject]@{ SamAccountName = 'roastable'; Enabled = $true; DoesNotRequirePreAuth = $true },
                    [pscustomobject]@{ SamAccountName = 'normal'; Enabled = $true; DoesNotRequirePreAuth = $false },
                    [pscustomobject]@{ SamAccountName = 'disabled'; Enabled = $false; DoesNotRequirePreAuth = $true }
                )
            }
            Test-KerberosPreAuthDisabled
            $roast = $script:Findings | Where-Object { $_.Object -eq 'roastable' }
            $roast | Should -Not -BeNullOrEmpty
            $roast.Status | Should -Be 'FAIL'
        }
    }

    It 'emits PASS when no users have the flag set' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                @(
                    [pscustomobject]@{ SamAccountName = 'alice'; Enabled = $true; DoesNotRequirePreAuth = $false }
                )
            }
            Test-KerberosPreAuthDisabled
            $script:Findings[0].Status | Should -Be 'PASS'
            $script:Findings[0].Object | Should -Be 'All Users'
        }
    }
}

Describe 'Test-UnconstrainedDelegation' -Tag 'WindowsOnly' {

    It 'escalates to Critical severity when a FAIL is emitted' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADComputer {
                @([pscustomobject]@{ DNSHostName = 'dc01.test.local'; Enabled = $true; TrustedForDelegation = $true })
            }
            Mock Get-ADUser { @() }
            Test-UnconstrainedDelegation
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
        }
    }
}

Describe 'Test-PasswordNeverExpires' -Tag 'WindowsOnly' {

    It 'flags enabled users with PasswordNeverExpires and PASSes otherwise' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                @(
                    [pscustomobject]@{ SamAccountName = 'svc1'; Enabled = $true; PasswordNeverExpires = $true },
                    [pscustomobject]@{ SamAccountName = 'user1'; Enabled = $true; PasswordNeverExpires = $false }
                )
            }
            Test-PasswordNeverExpires
            @($script:Findings | Where-Object { $_.Object -eq 'svc1' -and $_.Status -eq 'FAIL' }).Count | Should -Be 1
            @($script:Findings | Where-Object { $_.Object -eq 'user1' }).Count | Should -Be 0
        }
    }
}

Describe 'Test-DuplicateSPNs' -Tag 'WindowsOnly' {

    It 'flags SPN values assigned to more than one object' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADObject {
                @(
                    [pscustomobject]@{ DistinguishedName = 'CN=a, DC=test, DC=local'; ServicePrincipalName = @('HTTP/shared') },
                    [pscustomobject]@{ DistinguishedName = 'CN=b, DC=test, DC=local'; ServicePrincipalName = @('HTTP/shared') },
                    [pscustomobject]@{ DistinguishedName = 'CN=c, DC=test, DC=local'; ServicePrincipalName = @('HTTP/unique') }
                )
            }
            Test-DuplicateSPNs
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -Be 1
            $fails[0].Object | Should -Be 'HTTP/shared'
        }
    }

    It 'emits PASS when no duplicate SPNs exist' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADObject {
                @(
                    [pscustomobject]@{ DistinguishedName = 'CN=a'; ServicePrincipalName = @('HTTP/a') },
                    [pscustomobject]@{ DistinguishedName = 'CN=b'; ServicePrincipalName = @('HTTP/b') }
                )
            }
            Test-DuplicateSPNs
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -Be 1
        }
    }
}

Describe 'Test-KrbTgtAccountAge' -Tag 'WindowsOnly' {

    It 'emits FAIL when KRBTGT password is older than threshold' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                [pscustomobject]@{
                    SamAccountName = 'krbtgt'
                    Enabled = $true
                    PasswordLastSet = (Get-Date).AddDays(-365)
                    'msds-keyversionnumber' = 3
                    whenCreated = (Get-Date).AddYears(-5)
                }
            }
            Test-KrbTgtAccountAge -MaxAgeDays 180
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
        }
    }

    It 'emits FAIL when KRBTGT is disabled' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                [pscustomobject]@{
                    SamAccountName = 'krbtgt'
                    Enabled = $false
                    PasswordLastSet = (Get-Date).AddDays(-5)
                    'msds-keyversionnumber' = 3
                    whenCreated = (Get-Date).AddYears(-5)
                }
            }
            Test-KrbTgtAccountAge
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Description -match 'disabled' }).Count | Should -Be 1
        }
    }
}

Describe 'Test-ADStaleAccounts' -Tag 'WindowsOnly' {

    It 'flags inactive and stale-password accounts' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                @(
                    [pscustomobject]@{ SamAccountName = 'stale'; Enabled = $true; LastLogonDate = (Get-Date).AddDays(-200); PasswordLastSet = (Get-Date).AddDays(-10) },
                    [pscustomobject]@{ SamAccountName = 'staleOpwd'; Enabled = $true; LastLogonDate = (Get-Date).AddDays(-10); PasswordLastSet = (Get-Date).AddDays(-400) },
                    [pscustomobject]@{ SamAccountName = 'fresh'; Enabled = $true; LastLogonDate = (Get-Date).AddDays(-5); PasswordLastSet = (Get-Date).AddDays(-5) }
                )
            }
            Test-ADStaleAccounts -UserLogonInactivityDays 180 -UserPasswordAgeDays 180
            @($script:Findings | Where-Object { $_.Object -eq 'stale' -and $_.Status -eq 'WARNING' }).Count | Should -Be 1
            @($script:Findings | Where-Object { $_.Object -eq 'staleOpwd' -and $_.Status -eq 'WARNING' }).Count | Should -Be 1
            @($script:Findings | Where-Object { $_.Object -eq 'fresh' }).Count | Should -Be 0
        }
    }
}

Describe 'Test-ADPasswordPolicy' -Tag 'WindowsOnly' {

    It 'FAILs when complexity is disabled or reversible encryption is on' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDefaultDomainPasswordPolicy {
                [pscustomobject]@{
                    MinPasswordLength = 8
                    PasswordHistoryCount = 24
                    ComplexityEnabled = $false
                    LockoutThreshold = 5
                    LockoutDuration = 30
                    LockoutObservationWindow = 30
                    MaxPasswordAge = (New-TimeSpan -Days 90)
                    MinPasswordAge = (New-TimeSpan -Days 1)
                    ReversibleEncryptionEnabled = $true
                }
            }
            Test-ADPasswordPolicy
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Description -match 'complexity' }).Count  | Should -BeGreaterThan 0
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Description -match 'Reversible encryption' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'WARNs on short minimum password length' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDefaultDomainPasswordPolicy {
                [pscustomobject]@{
                    MinPasswordLength = 8
                    PasswordHistoryCount = 24
                    ComplexityEnabled = $true
                    LockoutThreshold = 5
                    LockoutDuration = 30
                    LockoutObservationWindow = 30
                    MaxPasswordAge = (New-TimeSpan -Days 90)
                    MinPasswordAge = (New-TimeSpan -Days 1)
                    ReversibleEncryptionEnabled = $false
                }
            }
            Test-ADPasswordPolicy
            @($script:Findings | Where-Object { $_.Status -eq 'WARNING' -and $_.Description -match 'MinPasswordLength' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-UserAccountsWithSPN' -Tag 'WindowsOnly' {

    It 'WARNs for enabled users with SPNs set' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                @(
                    [pscustomobject]@{ SamAccountName = 'svcA'; Enabled = $true; ServicePrincipalName = @('HTTP/app'); ObjectClass = 'user' },
                    [pscustomobject]@{ SamAccountName = 'userB'; Enabled = $true; ServicePrincipalName = @(); ObjectClass = 'user' }
                )
            }
            Test-UserAccountsWithSPN
            @($script:Findings | Where-Object { $_.Object -eq 'svcA' -and $_.Status -eq 'WARNING' }).Count | Should -Be 1
            @($script:Findings | Where-Object { $_.Object -eq 'userB' }).Count | Should -Be 0
        }
    }
}

Describe 'Test-ShadowGroupNames' -Tag 'WindowsOnly' {

    It 'flags suspicious lookalike group names' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroup {
                @(
                    [pscustomobject]@{ Name = 'DomianAdmins'; DistinguishedName = 'CN=DomianAdmins, CN=Users, DC=test' },
                    [pscustomobject]@{ Name = 'HR Read Only'; DistinguishedName = 'CN=HR, CN=Users, DC=test' },
                    [pscustomobject]@{ Name = 'Domain Admins'; DistinguishedName = 'CN=Domain Admins, CN=Users, DC=test' }
                )
            }
            Mock Get-Acl { [pscustomobject]@{ Access = @() } }
            Test-ShadowGroupNames
            @($script:Findings | Where-Object { $_.Object -eq 'DomianAdmins' -and $_.Status -eq 'WARNING' }).Count | Should -Be 1
            @($script:Findings | Where-Object { $_.Object -eq 'HR Read Only' }).Count | Should -Be 0
        }
    }
}

# ============================================================================
# PR 2 additions — LAPS, DCSecurity, Kerberoastable, DirSync
# ============================================================================

Describe 'Test-LAPSDeployment' -Tag 'WindowsOnly' {

    It 'FAILs when neither legacy nor Windows LAPS schema is present' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADRootDSE { [pscustomobject]@{ schemaNamingContext = 'CN=Schema, CN=Configuration, DC=test' } }
            Mock Get-ADObject {
                [pscustomobject]@{ mayContain = @('cn', 'dnsHostName'); systemMayContain = @('sAMAccountName') }
            }
            Test-LAPSDeployment
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Description | Should -Match 'Neither legacy LAPS'
        }
    }

    It 'PASSes when Windows LAPS schema is present and coverage is >=90%' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADRootDSE { [pscustomobject]@{ schemaNamingContext = 'CN=Schema, CN=Configuration, DC=test' } }
            Mock Get-ADObject {
                [pscustomobject]@{ mayContain = @('msLAPS-Password', 'msLAPS-PasswordExpirationTime'); systemMayContain = @() }
            }
            # 10 computers, all with passwords, none expired.
            $future = [DateTime]::UtcNow.AddDays(30).ToFileTimeUtc()
            Mock Get-ADComputer {
                1..10 | ForEach-Object {
                    [pscustomobject]@{
                        DNSHostName = "host$_.test.local"
                        Enabled = $true
                        'msLAPS-Password' = 'enc-blob'
                        'msLAPS-PasswordExpirationTime' = $future
                    }
                }
            }
            Test-LAPSDeployment
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' -and $_.Object -eq 'LAPS Coverage' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'FAILs when coverage is below 50%' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADRootDSE { [pscustomobject]@{ schemaNamingContext = 'CN=Schema, CN=Configuration, DC=test' } }
            Mock Get-ADObject {
                [pscustomobject]@{ mayContain = @('msLAPS-Password'); systemMayContain = @() }
            }
            # 10 computers, 2 have passwords.
            Mock Get-ADComputer {
                $list = @()
                1..10 | ForEach-Object {
                    $hasPwd = $_ -le 2
                    $list += [pscustomobject]@{
                        DNSHostName = "host$_.test.local"
                        Enabled = $true
                        'msLAPS-Password' = if ($hasPwd) { 'enc-blob' } else { $null }
                        'msLAPS-PasswordExpirationTime' = $null
                    }
                }
                $list
            }
            Test-LAPSDeployment
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Object -eq 'LAPS Coverage' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-KerberoastableAccounts' -Tag 'WindowsOnly' {

    It 'escalates to Critical severity for privileged SPN-bearer with RC4-capable hash' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                @([pscustomobject]@{
                        SamAccountName = 'svcDA'
                        Enabled = $true
                        ServicePrincipalName = @('MSSQLSvc/app.test.local:1433')
                        PasswordLastSet = (Get-Date).AddDays(-5)
                        'msDS-SupportedEncryptionTypes' = 0  # no AES flags
                        MemberOf = @('CN=Domain Admins, CN=Users, DC=test')
                    })
            }
            Test-KerberoastableAccounts
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
            $fails[0].Description | Should -Match 'Privileged'
        }
    }

    It 'PASSes when all SPN-bearing accounts are AES-only' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                @([pscustomobject]@{
                        SamAccountName = 'svcAES'
                        Enabled = $true
                        ServicePrincipalName = @('HTTP/app.test.local')
                        PasswordLastSet = (Get-Date).AddDays(-5)
                        'msDS-SupportedEncryptionTypes' = 0x18  # AES128 + AES256
                        MemberOf = @()
                    })
            }
            Test-KerberoastableAccounts
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'FAILs on stale password + RC4 for non-privileged account' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                @([pscustomobject]@{
                        SamAccountName = 'svcStale'
                        Enabled = $true
                        ServicePrincipalName = @('HTTP/app.test.local')
                        PasswordLastSet = (Get-Date).AddDays(-365)
                        'msDS-SupportedEncryptionTypes' = 0
                        MemberOf = @()
                    })
            }
            Test-KerberoastableAccounts -PasswordAgeDays 90
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-DirSyncAccountSecurity' -Tag 'WindowsOnly' {

    It 'FAILs when MSOL_ account is a member of a disallowed group' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                @([pscustomobject]@{
                        SamAccountName = 'MSOL_abc123'
                        Enabled = $true
                        MemberOf = @('CN=Domain Admins, CN=Users, DC=test')
                        PasswordLastSet = (Get-Date).AddDays(-5)
                        whenCreated = (Get-Date).AddYears(-2)
                    })
            }
            Test-DirSyncAccountSecurity
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
        }
    }

    It 'PASSes when MSOL_ account has no disallowed group memberships' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser {
                @([pscustomobject]@{
                        SamAccountName = 'MSOL_abc123'
                        Enabled = $true
                        MemberOf = @()
                        PasswordLastSet = (Get-Date).AddDays(-5)
                        whenCreated = (Get-Date).AddYears(-2)
                    })
            }
            Test-DirSyncAccountSecurity
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'emits INFO when no MSOL_ accounts are found' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADUser { @() }
            Test-DirSyncAccountSecurity
            @($script:Findings | Where-Object { $_.Status -eq 'INFO' -and $_.Description -match 'MSOL_' }).Count | Should -Be 1
        }
    }
}

# ============================================================================
# PR 4a additions - Credential Hygiene (Group A) + ACL Abuse Paths (Group B)
# ============================================================================

Describe 'Test-LMHashStorage' -Tag 'WindowsOnly' {

    It 'FAILs when NoLMHash is 0 on a DC' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command { 0 }
            Test-LMHashStorage
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'High'
        }
    }

    It 'PASSes when NoLMHash is 1 on every DC' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command { 1 }
            Test-LMHashStorage
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'WARNs when PSRemoting fails' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command { throw 'Access denied' }
            Test-LMHashStorage
            @($script:Findings | Where-Object { $_.Status -eq 'WARNING' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-NTLMv1Allowed' -Tag 'WindowsOnly' {

    It 'FAILs when LmCompatibilityLevel is 2' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command { 2 }
            Test-NTLMv1Allowed
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'WARNs when LmCompatibilityLevel is 3 (partial refusal)' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command { 3 }
            Test-NTLMv1Allowed
            @($script:Findings | Where-Object { $_.Status -eq 'WARNING' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'PASSes when LmCompatibilityLevel is 5' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command { 5 }
            Test-NTLMv1Allowed
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-DCLegacyEncryption' -Tag 'WindowsOnly' {

    It 'FAILs when DES bits are set in the encryption-types mask' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command { 0x3 }  # DES bits only
            Test-DCLegacyEncryption
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Description -match 'DES' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'FAILs when mask is RC4-only' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command { 0x4 }  # RC4 only
            Test-DCLegacyEncryption
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'WARNs when RC4 is set alongside AES' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command { 0x1C }  # RC4 + AES128 + AES256
            Test-DCLegacyEncryption
            @($script:Findings | Where-Object { $_.Status -eq 'WARNING' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'PASSes when AES-only' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command { 0x18 }  # AES128 + AES256 only
            Test-DCLegacyEncryption
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-NullSessionShares' -Tag 'WindowsOnly' {

    It 'FAILs when RestrictAnonymous is 0 on a DC' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command {
                [pscustomobject]@{
                    NullSessionPipes = @()
                    NullSessionShares = @()
                    RestrictAnonymous = 0
                    RestrictAnonymousSAM = 1
                    EveryoneIncludesAnonymous = 0
                }
            }
            Test-NullSessionShares
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'PASSes when all five settings are compliant' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Invoke-Command {
                [pscustomobject]@{
                    NullSessionPipes = @()
                    NullSessionShares = @()
                    RestrictAnonymous = 1
                    RestrictAnonymousSAM = 1
                    EveryoneIncludesAnonymous = 0
                }
            }
            Test-NullSessionShares
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-DomainEncryptionTypesPolicy' -Tag 'WindowsOnly' {

    It 'FAILs when domain msDS-SupportedEncryptionTypes is RC4-only' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomain {
                [pscustomobject]@{
                    DistinguishedName = 'DC=test,DC=local'
                    'msDS-SupportedEncryptionTypes' = 0x4
                }
            }
            Mock Get-ADTrust { @() }
            Test-DomainEncryptionTypesPolicy
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Object -eq 'Domain' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'PASSes when domain policy is AES-only' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomain {
                [pscustomobject]@{
                    DistinguishedName = 'DC=test,DC=local'
                    'msDS-SupportedEncryptionTypes' = 0x18
                }
            }
            Mock Get-ADTrust { @() }
            Test-DomainEncryptionTypesPolicy
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-IsAuthorizedPrincipal' -Tag 'WindowsOnly' {

    It 'returns $true for Domain Admins' {
        InModuleScope EntraChecks-ActiveDirectory {
            Test-IsAuthorizedPrincipal -IdentityReference 'TEST\Domain Admins' | Should -Be $true
        }
    }

    It 'returns $false for an arbitrary non-admin' {
        InModuleScope EntraChecks-ActiveDirectory {
            Test-IsAuthorizedPrincipal -IdentityReference 'TEST\helpdesk' | Should -Be $false
        }
    }

    It 'honors AuthorizedPrincipalsExtra' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:AuthorizedPrincipalsExtra = @('ContosoADAdmins')
            Test-IsAuthorizedPrincipal -IdentityReference 'TEST\ContosoADAdmins' | Should -Be $true
            $script:AuthorizedPrincipalsExtra = @()
        }
    }
}

Describe 'Test-WritablePrivilegedACLs' -Tag 'WindowsOnly' {

    It 'FAILs when a non-admin has GenericAll on a privileged container' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomain { [pscustomobject]@{ DistinguishedName = 'DC=test,DC=local' } }
            Mock Get-ADDomainController { @() }
            Mock Get-Acl {
                [pscustomobject]@{
                    Access = @(
                        [pscustomobject]@{
                            IdentityReference = 'TEST\helpdesk'
                            ActiveDirectoryRights = 'GenericAll'
                        }
                    )
                }
            }
            Test-WritablePrivilegedACLs
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
        }
    }

    It 'PASSes when only admins hold write rights' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomain { [pscustomobject]@{ DistinguishedName = 'DC=test,DC=local' } }
            Mock Get-ADDomainController { @() }
            Mock Get-Acl {
                [pscustomobject]@{
                    Access = @(
                        [pscustomobject]@{
                            IdentityReference = 'TEST\Domain Admins'
                            ActiveDirectoryRights = 'GenericAll'
                        }
                    )
                }
            }
            Test-WritablePrivilegedACLs
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-ShadowCredentialsVulnerable' -Tag 'WindowsOnly' {

    It 'FAILs when a non-admin has WriteProperty on a privileged user (all-properties scope)' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember {
                @([pscustomobject]@{
                        SamAccountName = 'da1'
                        DistinguishedName = 'CN=da1,CN=Users,DC=test,DC=local'
                        objectClass = 'user'
                    })
            }
            Mock Get-ADUser {
                [pscustomobject]@{
                    SamAccountName = 'krbtgt'
                    DistinguishedName = 'CN=krbtgt,CN=Users,DC=test,DC=local'
                }
            }
            Mock Get-ADDomainController { @() }
            Mock Get-Acl {
                [pscustomobject]@{
                    Access = @(
                        [pscustomobject]@{
                            IdentityReference = 'TEST\helpdesk'
                            ActiveDirectoryRights = 'WriteProperty'
                            ObjectType = [Guid]::Empty  # all-properties scope
                        }
                    )
                }
            }
            Test-ShadowCredentialsVulnerable
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
        }
    }

    It 'PASSes when no non-admin write rights exist on msDS-KeyCredentialLink' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember { @() }
            Mock Get-ADUser { $null }
            Mock Get-ADDomainController { @() }
            Mock Get-Acl { [pscustomobject]@{ Access = @() } }
            Test-ShadowCredentialsVulnerable
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-RBCDConfigured' -Tag 'WindowsOnly' {

    It 'FAILs when RBCD is set on a DC' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            # Create a minimal self-relative security descriptor. SID S-1-5-32-544 (Administrators)
            # allowed. The binary format is well-defined; easier to just craft an empty DACL SD.
            $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                'O:BAG:BAD:(A;;GA;;;BA)')
            $sdBytes = New-Object byte[] $sd.BinaryLength
            $sd.GetBinaryForm($sdBytes, 0)

            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            # Default mock returns the fixture. Pass 3 also calls Get-ADComputer
            # with -Identity, but since our Tier0OUDNs is empty and Pass 3 only
            # iterates DCs (which we already returned), the extra calls don't
            # produce additional findings we care about here.
            Mock Get-ADComputer {
                [pscustomobject]@{
                    Name = 'dc1'
                    DistinguishedName = 'CN=dc1,OU=Domain Controllers,DC=test,DC=local'
                    'msDS-AllowedToActOnBehalfOfOtherIdentity' = $sdBytes
                }
            }
            Mock Get-Acl { [pscustomobject]@{ Access = @() } }
            Test-RBCDConfigured
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' })
            $fails.Count | Should -BeGreaterThan 0
        }
    }

    It 'emits INFO for RBCD on a non-DC, non-Tier0 computer' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                'O:BAG:BAD:(A;;GA;;;BA)')
            $sdBytes = New-Object byte[] $sd.BinaryLength
            $sd.GetBinaryForm($sdBytes, 0)

            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Get-ADComputer {
                [pscustomobject]@{
                    Name = 'app01'
                    DistinguishedName = 'CN=app01,OU=Servers,DC=test,DC=local'
                    'msDS-AllowedToActOnBehalfOfOtherIdentity' = $sdBytes
                }
            }
            Mock Get-Acl { [pscustomobject]@{ Access = @() } }
            Test-RBCDConfigured
            @($script:Findings | Where-Object { $_.Status -eq 'INFO' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'PASSes when no RBCD is configured anywhere' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local'; Name = 'dc1' }) }
            Mock Get-ADComputer { @() }
            Mock Get-Acl { [pscustomobject]@{ Access = @() } }
            Test-RBCDConfigured
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-GenericWriteToSensitive' -Tag 'WindowsOnly' {

    It 'FAILs when a non-admin has GenericWrite on a Domain Admin user' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember {
                @([pscustomobject]@{
                        SamAccountName = 'da1'
                        DistinguishedName = 'CN=da1,CN=Users,DC=test,DC=local'
                        objectClass = 'user'
                    })
            }
            Mock Get-Acl {
                [pscustomobject]@{
                    Access = @(
                        [pscustomobject]@{
                            IdentityReference = 'TEST\helpdesk'
                            ActiveDirectoryRights = 'GenericWrite'
                        }
                    )
                }
            }
            Test-GenericWriteToSensitive
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
        }
    }

    It 'PASSes when no non-admin write rights on privileged-group members' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember {
                @([pscustomobject]@{
                        SamAccountName = 'da1'
                        DistinguishedName = 'CN=da1,CN=Users,DC=test,DC=local'
                        objectClass = 'user'
                    })
            }
            Mock Get-Acl {
                [pscustomobject]@{
                    Access = @(
                        [pscustomobject]@{
                            IdentityReference = 'TEST\Domain Admins'
                            ActiveDirectoryRights = 'GenericWrite'
                        }
                    )
                }
            }
            Test-GenericWriteToSensitive
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }
}

# ---------------------------------------------------------------------------
# PR 4b additions - Attack path lite + DnsAdmins + audit hygiene + DFSR
# ---------------------------------------------------------------------------

Describe 'Test-AuthenticatedUsersDACLReach' -Tag 'WindowsOnly' {

    It 'FAILs Critical on direct (1-hop) non-admin write rights to a DA member' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember {
                @([pscustomobject]@{
                        SamAccountName = 'da1'
                        DistinguishedName = 'CN=da1,CN=Users,DC=test,DC=local'
                        objectClass = 'user'
                    })
            }
            Mock Get-Acl {
                [pscustomobject]@{
                    Access = @(
                        [pscustomobject]@{
                            IdentityReference = 'TEST\helpdesk'
                            ActiveDirectoryRights = 'GenericAll'
                        }
                    )
                }
            }
            Test-AuthenticatedUsersDACLReach -MaxDepth 1
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
            $fails[0].Description | Should -Match 'DIRECT reach'
        }
    }

    It 'PASSes when only authorized principals hold write rights' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember {
                @([pscustomobject]@{
                        SamAccountName = 'da1'
                        DistinguishedName = 'CN=da1,CN=Users,DC=test,DC=local'
                        objectClass = 'user'
                    })
            }
            Mock Get-Acl {
                [pscustomobject]@{
                    Access = @(
                        [pscustomobject]@{
                            IdentityReference = 'TEST\Domain Admins'
                            ActiveDirectoryRights = 'GenericAll'
                        }
                    )
                }
            }
            Test-AuthenticatedUsersDACLReach -MaxDepth 1
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -Be 0
        }
    }

    It 'PASSes (no privileged members enumerated) when DA group resolution fails' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember { throw 'no group' }
            Test-AuthenticatedUsersDACLReach -MaxDepth 1
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-DNSAdminsPrivilege' -Tag 'WindowsOnly' {

    It 'PASSes when DnsAdmins has no members' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember { @() }
            Test-DNSAdminsPrivilege
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'FAILs Critical when a legacy DC OS is present and DnsAdmins is populated' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember {
                @([pscustomobject]@{ Name = 'helpdesk_user'; objectClass = 'user' })
            }
            Mock Get-ADDomainController {
                @([pscustomobject]@{ HostName = 'dc1.test.local'; OperatingSystem = 'Windows Server 2016 Standard' })
            }
            Test-DNSAdminsPrivilege
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Match 'Critical'
        }
    }

    It 'WARNs (not Critical) when only modern DCs are present' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember {
                @([pscustomobject]@{ Name = 'helpdesk_user'; objectClass = 'user' })
            }
            Mock Get-ADDomainController {
                @([pscustomobject]@{ HostName = 'dc1.test.local'; OperatingSystem = 'Windows Server 2022 Standard' })
            }
            Test-DNSAdminsPrivilege
            @($script:Findings | Where-Object { $_.Status -eq 'WARNING' }).Count | Should -BeGreaterThan 0
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -Be 0
        }
    }

    It 'INFOs when the DnsAdmins group does not exist' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADGroupMember { throw 'group not found' }
            Test-DNSAdminsPrivilege
            @($script:Findings | Where-Object { $_.Status -eq 'INFO' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-EventAuditPolicy' -Tag 'WindowsOnly' {

    It 'PASSes when every required subcategory is enabled' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local' }) }
            $csv = @(
                '"Machine Name","Policy Target","Subcategory","Subcategory GUID","Inclusion Setting","Exclusion Setting"'
                '"DC1","System","Kerberos Authentication Service","{0CCE9242-69AE-11D9-BED3-505054503030}","Success and Failure",""'
                '"DC1","System","Kerberos Service Ticket Operations","{0CCE9240-69AE-11D9-BED3-505054503030}","Success and Failure",""'
                '"DC1","System","Credential Validation","{0CCE923F-69AE-11D9-BED3-505054503030}","Success and Failure",""'
                '"DC1","System","Directory Service Access","{0CCE923B-69AE-11D9-BED3-505054503030}","Success and Failure",""'
                '"DC1","System","Directory Service Changes","{0CCE923C-69AE-11D9-BED3-505054503030}","Success",""'
                '"DC1","System","User Account Management","{0CCE9235-69AE-11D9-BED3-505054503030}","Success",""'
                '"DC1","System","Security Group Management","{0CCE9237-69AE-11D9-BED3-505054503030}","Success",""'
            )
            Mock Invoke-Command { $csv }
            Test-EventAuditPolicy
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'FAILs when a required subcategory is missing' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local' }) }
            $csv = @(
                '"Machine Name","Policy Target","Subcategory","Subcategory GUID","Inclusion Setting","Exclusion Setting"'
                '"DC1","System","Kerberos Authentication Service","{0CCE9242-69AE-11D9-BED3-505054503030}","No Auditing",""'
            )
            Mock Invoke-Command { $csv }
            Test-EventAuditPolicy
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'WARNs when PSRemoting fails' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-ADDomainController { @([pscustomobject]@{ HostName = 'dc1.test.local' }) }
            Mock Invoke-Command { throw 'Access denied' }
            Test-EventAuditPolicy
            @($script:Findings | Where-Object { $_.Status -eq 'WARNING' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-DFSRSYSVOLHealth' -Tag 'WindowsOnly' {

    It 'INFOs when the DFSR module is not available' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-Module { $null } -ParameterFilter { $ListAvailable -and $Name -eq 'DFSR' }
            Test-DFSRSYSVOLHealth
            @($script:Findings | Where-Object { $_.Status -eq 'INFO' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'INFOs when SYSVOL is on legacy FRS (Get-DfsrMembership unavailable)' {
        InModuleScope EntraChecks-ActiveDirectory {
            $script:Findings = @()
            Mock Get-Module { [pscustomobject]@{ Name = 'DFSR' } } -ParameterFilter { $ListAvailable -and $Name -eq 'DFSR' }
            Mock Import-Module { }
            Mock Get-ADDomainController { @([pscustomobject]@{ Name = 'dc1'; HostName = 'dc1.test.local' }) }
            function Global:Get-DfsrMembership { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
            Mock Get-DfsrMembership { throw 'No replication group' }
            Test-DFSRSYSVOLHealth
            @($script:Findings | Where-Object { $_.Status -eq 'INFO' }).Count | Should -BeGreaterThan 0
        }
    }
}
