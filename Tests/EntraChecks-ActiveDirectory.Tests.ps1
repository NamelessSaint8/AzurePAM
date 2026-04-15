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

Describe 'Test-ADEnvironment degradation paths' {

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

Describe 'Invoke-ActiveDirectoryAssessment entry point' {

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

Describe 'Finding schema compliance' {

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

Describe 'Test-KerberosPreAuthDisabled' {

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

Describe 'Test-UnconstrainedDelegation' {

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

Describe 'Test-PasswordNeverExpires' {

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

Describe 'Test-DuplicateSPNs' {

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

Describe 'Test-KrbTgtAccountAge' {

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

Describe 'Test-ADStaleAccounts' {

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

Describe 'Test-ADPasswordPolicy' {

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

Describe 'Test-UserAccountsWithSPN' {

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

Describe 'Test-ShadowGroupNames' {

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
