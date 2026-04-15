<#
.SYNOPSIS
    Pester 5 suite for EntraChecks-ADCS.psm1 (AD CS ESC1-8 audit).

.DESCRIPTION
    Fixture-driven. AD cmdlets and Invoke-Command are mocked so the suite
    runs on non-domain-joined CI machines without RSAT and without live
    AD CS infrastructure.

    Run:
      Invoke-Pester -Path Tests/EntraChecks-ADCS.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot

    # Global stubs for cmdlets the ADCS module touches.
    function Global:Get-ADRootDSE { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-ADObject { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Get-Acl { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Invoke-Command { param([Parameter(ValueFromRemainingArguments = $true)]$args) }
    function Global:Invoke-WebRequest { param([Parameter(ValueFromRemainingArguments = $true)]$args) }

    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-ADCS.psm1') -Force

    # Fixture builders.
    function New-TestCA {
        param(
            [string]$Name = 'TestCA',
            [string]$Host = 'ca.test.local'
        )
        [pscustomobject]@{
            cn = $Name
            dNSHostName = $Host
            DistinguishedName = "CN=$Name,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local"
            certificateTemplates = @('User', 'Computer')
            flags = 10
        }
    }

    function New-TestTemplate {
        param(
            [string]$Name = 'TestTemplate',
            [int]$CertificateNameFlag = 0,
            [int]$EnrollmentFlag = 2,  # Default: manager approval required (PEND_ALL_REQUESTS)
            [int]$RASignature = 0,
            [string[]]$EKU = @('1.3.6.1.5.5.7.3.2')  # Client Auth
        )
        [pscustomobject]@{
            cn = $Name
            displayName = $Name
            DistinguishedName = "CN=$Name,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local"
            'msPKI-Certificate-Name-Flag' = $CertificateNameFlag
            'msPKI-Enrollment-Flag' = $EnrollmentFlag
            'msPKI-RA-Signature' = $RASignature
            pKIExtendedKeyUsage = $EKU
            'msPKI-Template-Schema-Version' = 2
            flags = 0
        }
    }

    function New-TestACL {
        param([array]$ACEs)
        [pscustomobject]@{
            Access = $ACEs
            Owner = 'TEST\Domain Admins'
        }
    }

    function New-TestACE {
        param(
            [string]$Identity = 'TEST\Domain Users',
            [string]$Rights = 'ExtendedRight'
        )
        [pscustomobject]@{
            IdentityReference = $Identity
            ActiveDirectoryRights = $Rights
        }
    }
}

Describe 'Test-ADCSEnvironment' {

    It 'returns HasADCS=$false when no Enterprise CA is found' {
        InModuleScope EntraChecks-ADCS {
            Mock Get-ADRootDSE { [pscustomobject]@{ configurationNamingContext = 'CN=Configuration,DC=test,DC=local' } }
            Mock Get-ADObject { @() }
            $env = Test-ADCSEnvironment
            $env.HasADCS | Should -Be $false
        }
    }

    It 'returns HasADCS=$true when at least one Enterprise CA exists' {
        InModuleScope EntraChecks-ADCS {
            Mock Get-ADRootDSE { [pscustomobject]@{ configurationNamingContext = 'CN=Configuration,DC=test,DC=local' } }
            # Mock returns the CA on the first invocation (pKIEnrollmentService) and empty thereafter.
            $script:adCallCount = 0
            Mock Get-ADObject {
                $script:adCallCount++
                if ($script:adCallCount -eq 1) {
                    return , @([pscustomobject]@{
                            cn = 'TestCA'
                            dNSHostName = 'ca.test.local'
                            certificateTemplates = @('User')
                            flags = 10
                        })
                }
                return , @()
            }
            $env = Test-ADCSEnvironment
            $env.HasADCS | Should -Be $true
            @($env.CAs).Count | Should -Be 1
        }
    }
}

Describe 'Invoke-ADCSAssessment — gating' {

    It 'emits a single INFO finding when no Enterprise CA is detected' {
        InModuleScope EntraChecks-ADCS {
            Mock Test-ADCSEnvironment {
                [pscustomobject]@{
                    HasADCS = $false
                    CAs = @()
                    Templates = @()
                    FailureReason = $null
                }
            }
            $findings = Invoke-ADCSAssessment
            $findings.Count | Should -Be 1
            $findings[0].Status | Should -Be 'INFO'
            $findings[0].Description | Should -Match 'No Enterprise Certificate Authority'
        }
    }
}

Describe 'Test-ADCSEscalation1 — SAN abuse' {

    It 'FAILs on a template that allows enrollee-supplied SAN + client auth + no manager approval + non-admin enrollment' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @()
                Templates = @(
                    [pscustomobject]@{
                        cn = 'VulnUser'
                        displayName = 'VulnUser'
                        DistinguishedName = 'CN=VulnUser,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local'
                        'msPKI-Certificate-Name-Flag' = 0x1  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                        'msPKI-Enrollment-Flag' = 0  # NOT requiring manager approval
                        'msPKI-RA-Signature' = 0
                        pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')  # Client Auth
                    }
                )
            }
            Mock Get-Acl {
                [pscustomobject]@{
                    Owner = 'TEST\Domain Admins'
                    Access = @(
                        [pscustomobject]@{
                            IdentityReference = 'TEST\Domain Users'
                            ActiveDirectoryRights = 'ExtendedRight'
                        }
                    )
                }
            }
            $script:Findings = @()
            Test-ADCSEscalation1 -Environment $env
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
            $fails[0].Description | Should -Match 'ESC1'
        }
    }

    It 'PASSes when manager approval is required (CT_FLAG_PEND_ALL_REQUESTS set)' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @()
                Templates = @(
                    [pscustomobject]@{
                        cn = 'SafeTemplate'
                        DistinguishedName = 'CN=SafeTemplate,DC=test'
                        'msPKI-Certificate-Name-Flag' = 0x1
                        'msPKI-Enrollment-Flag' = 0x2  # PEND_ALL_REQUESTS
                        'msPKI-RA-Signature' = 0
                        pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
                    }
                )
            }
            Mock Get-Acl {
                [pscustomobject]@{ Owner = 'x'; Access = @(
                        [pscustomobject]@{ IdentityReference = 'TEST\Domain Users'; ActiveDirectoryRights = 'ExtendedRight' }
                    )
                }
            }
            $script:Findings = @()
            Test-ADCSEscalation1 -Environment $env
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -Be 0
        }
    }

    It 'PASSes when enrollment is restricted to admins' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @()
                Templates = @(
                    [pscustomobject]@{
                        cn = 'AdminOnly'
                        DistinguishedName = 'CN=AdminOnly,DC=test'
                        'msPKI-Certificate-Name-Flag' = 0x1
                        'msPKI-Enrollment-Flag' = 0
                        'msPKI-RA-Signature' = 0
                        pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
                    }
                )
            }
            # Only admin principal has the right.
            Mock Get-Acl {
                [pscustomobject]@{ Owner = 'x'; Access = @(
                        [pscustomobject]@{ IdentityReference = 'TEST\Domain Admins'; ActiveDirectoryRights = 'ExtendedRight' }
                    )
                }
            }
            $script:Findings = @()
            Test-ADCSEscalation1 -Environment $env
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -Be 0
        }
    }
}

Describe 'Test-ADCSEscalation2 — Any Purpose / SubCA' {

    It 'FAILs when an Any-Purpose template is enrollable by non-admins' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @()
                Templates = @(
                    [pscustomobject]@{
                        cn = 'AnyPurposeTemplate'
                        DistinguishedName = 'CN=AnyPurposeTemplate,DC=test'
                        pKIExtendedKeyUsage = @('2.5.29.37.0')  # Any Purpose
                        'msPKI-Certificate-Name-Flag' = 0
                        'msPKI-Enrollment-Flag' = 0
                        'msPKI-RA-Signature' = 0
                    }
                )
            }
            Mock Get-Acl {
                [pscustomobject]@{ Owner = 'x'; Access = @(
                        [pscustomobject]@{ IdentityReference = 'TEST\Domain Users'; ActiveDirectoryRights = 'ExtendedRight' }
                    )
                }
            }
            $script:Findings = @()
            Test-ADCSEscalation2 -Environment $env
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-ADCSEscalation3 — Enrollment Agent' {

    It 'FAILs when an Enrollment Agent template is enrollable by non-admins' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @()
                Templates = @(
                    [pscustomobject]@{
                        cn = 'EnrollAgent'
                        DistinguishedName = 'CN=EnrollAgent,DC=test'
                        pKIExtendedKeyUsage = @('1.3.6.1.4.1.311.20.2.1')  # Certificate Request Agent
                        'msPKI-Certificate-Name-Flag' = 0
                        'msPKI-Enrollment-Flag' = 0
                        'msPKI-RA-Signature' = 0
                    }
                )
            }
            Mock Get-Acl {
                [pscustomobject]@{ Owner = 'x'; Access = @(
                        [pscustomobject]@{ IdentityReference = 'TEST\Domain Users'; ActiveDirectoryRights = 'ExtendedRight' }
                    )
                }
            }
            $script:Findings = @()
            Test-ADCSEscalation3 -Environment $env
            @($script:Findings | Where-Object { $_.Status -eq 'FAIL' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Test-ADCSEscalation4 — template ACL abuse' {

    It 'FAILs when a template ACL grants GenericAll to a non-admin' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @()
                Templates = @(
                    [pscustomobject]@{
                        cn = 'WritableTemplate'
                        DistinguishedName = 'CN=WritableTemplate,DC=test'
                        pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
                        'msPKI-Certificate-Name-Flag' = 0
                        'msPKI-Enrollment-Flag' = 2
                        'msPKI-RA-Signature' = 0
                    }
                )
            }
            Mock Get-Acl {
                [pscustomobject]@{ Owner = 'x'; Access = @(
                        [pscustomobject]@{ IdentityReference = 'TEST\helpdesk'; ActiveDirectoryRights = 'GenericAll' }
                    )
                }
            }
            $script:Findings = @()
            Test-ADCSEscalation4 -Environment $env
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
        }
    }
}

Describe 'Test-ADCSEscalation6 — EDITF_ATTRIBUTESUBJECTALTNAME2' {

    It 'FAILs when CA registry has the EDITF flag set' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @(
                    [pscustomobject]@{ cn = 'TestCA'; dNSHostName = 'ca.test.local'; certificateTemplates = @() }
                )
                Templates = @()
            }
            Mock Invoke-Command { 0x40000 }  # EDITF_ATTRIBUTESUBJECTALTNAME2 set
            $script:Findings = @()
            Test-ADCSEscalation6 -Environment $env
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
            $fails[0].Description | Should -Match 'ESC6'
        }
    }

    It 'PASSes when CA registry does not have the EDITF flag' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @(
                    [pscustomobject]@{ cn = 'TestCA'; dNSHostName = 'ca.test.local'; certificateTemplates = @() }
                )
                Templates = @()
            }
            Mock Invoke-Command { 0x2 }  # Some other EditFlags value
            $script:Findings = @()
            Test-ADCSEscalation6 -Environment $env
            @($script:Findings | Where-Object { $_.Status -eq 'PASS' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'WARNs when PSRemoting to the CA fails' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @(
                    [pscustomobject]@{ cn = 'TestCA'; dNSHostName = 'ca.test.local'; certificateTemplates = @() }
                )
                Templates = @()
            }
            Mock Invoke-Command { throw 'Access denied' }
            $script:Findings = @()
            Test-ADCSEscalation6 -Environment $env
            $warns = @($script:Findings | Where-Object { $_.Status -eq 'WARNING' })
            $warns.Count | Should -BeGreaterThan 0
            $warns[0].Description | Should -Match 'Unable to read EditFlags'
        }
    }
}

Describe 'Test-ADCSEscalation8 — HTTP web enrollment' {

    It 'FAILs when the HTTP probe returns a response' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @(
                    [pscustomobject]@{ cn = 'TestCA'; dNSHostName = 'ca.test.local'; certificateTemplates = @() }
                )
                Templates = @()
            }
            Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200 } }
            $script:Findings = @()
            Test-ADCSEscalation8 -Environment $env -ProbeHTTP $true
            $fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
            $fails[0].Severity | Should -Be 'Critical'
        }
    }

    It 'emits INFO when ProbeHTTP is $false' {
        InModuleScope EntraChecks-ADCS {
            $env = [pscustomobject]@{
                HasADCS = $true
                CAs = @(
                    [pscustomobject]@{ cn = 'TestCA'; dNSHostName = 'ca.test.local'; certificateTemplates = @() }
                )
                Templates = @()
            }
            $script:Findings = @()
            Test-ADCSEscalation8 -Environment $env -ProbeHTTP $false
            @($script:Findings | Where-Object { $_.Status -eq 'INFO' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Finding schema compliance (ADCS)' {

    It 'ADCS findings carry all required schema fields + Source=ActiveDirectory' {
        InModuleScope EntraChecks-ADCS {
            $script:Findings = @()
            Add-ADCSFinding -CheckName 'Test-ADCSEscalation1' -Status 'FAIL' `
                -Object 'TestTemplate' -Description 'd' -Remediation 'r'
            $f = $script:Findings[0]
            'Time', 'CheckName', 'Status', 'Severity', 'Category', 'Object', 'Description',
            'Remediation', 'ComplianceFrameworks', 'ComplianceReference', 'RiskScore', 'Type', 'Source' |
                ForEach-Object { $f.PSObject.Properties.Name | Should -Contain $_ }
            $f.Source | Should -Be 'ActiveDirectory'
            $f.Severity | Should -Be 'Critical'
        }
    }
}
