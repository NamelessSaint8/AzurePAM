<#
.SYNOPSIS
    Pester 5 test suite for SOC 2 Phase 2 synthetic checks and helpers.

.DESCRIPTION
    Fixture-driven tests covering the six new Phase 2 checks plus the
    licensing-gap factory. Mocks Invoke-SOC2AzureRestRequest,
    Invoke-MgGraphRequest, and Get-SOC2TargetSubscriptions so tests run
    hermetically without Graph / Azure credentials.

    Run: Invoke-Pester -Path Tests/SOC2-Phase2.Tests.ps1

.NOTES
    Requires Pester 5.0+. Install with:
        Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    $soc2Module = Join-Path $repoRoot 'Modules\EntraChecks-SOC2.psm1'
    $mappingModule = Join-Path $repoRoot 'Modules\EntraChecks-ComplianceMapping.psm1'
    $defenderModule = Join-Path $repoRoot 'Modules\EntraChecks-DefenderCompliance.psm1'
    $fixturesRoot = Join-Path $PSScriptRoot 'Fixtures\SOC2-Phase2'

    Import-Module $mappingModule -Force
    # Defender module is imported so tests can Mock Get-DefenderComplianceAssessments.
    # Its initialization prints warnings but doesn't affect test correctness.
    Import-Module $defenderModule -Force -WarningAction SilentlyContinue
    Import-Module $soc2Module -Force

    function Get-SOC2Fixture {
        param([Parameter(Mandatory)][string]$Name)
        $path = Join-Path $fixturesRoot $Name
        if (-not (Test-Path $path)) { throw "Fixture not found: $path" }
        return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    }

    $script:TestFixturesRoot = $fixturesRoot
    $script:FakeSubscription = [pscustomobject]@{
        Id = '00000000-0000-0000-0000-000000000001'
        Name = 'test-subscription'
        TenantId = '00000000-0000-0000-0000-000000000099'
        State = 'Enabled'
    }
}

Describe 'Test-SOC2BackupConfiguration' {

    Context 'When Az.RecoveryServices is not installed' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-Module { $null } -ParameterFilter { $Name -eq 'Az.RecoveryServices' }
        }

        It 'emits a single INFO finding about missing prereq' {
            $result = @(Test-SOC2BackupConfiguration)
            $result.Count | Should -Be 1
            $result[0].Status | Should -Be 'INFO'
            $result[0].Type | Should -Be 'SOC2_Phase2_PrereqMissing'
            $result[0].TSCReferences | Should -Contain 'A1.2'
        }
    }

    Context 'When no vaults exist' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-Module { @{ Name = 'Az.RecoveryServices' } } -ParameterFilter { $Name -eq 'Az.RecoveryServices' }
            Mock -ModuleName EntraChecks-SOC2 Get-SOC2TargetSubscriptions { @($script:FakeSubscription) }
            Mock -ModuleName EntraChecks-SOC2 Set-AzContext { }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest { Get-SOC2Fixture 'recoveryServicesVaults-empty.json' } -ParameterFilter { $Uri -like '*/vaults*' }
        }

        It 'emits FAIL with SOC2_BackupConfigurationGap type' {
            $result = Test-SOC2BackupConfiguration
            $fails = @($result | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterOrEqual 1
            $fails[0].Type | Should -Be 'SOC2_BackupConfigurationGap'
            $fails[0].TSCReferences | Should -Contain 'A1.2'
        }
    }

    Context 'When vaults exist but protected items are empty' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-Module { @{ Name = 'Az.RecoveryServices' } } -ParameterFilter { $Name -eq 'Az.RecoveryServices' }
            Mock -ModuleName EntraChecks-SOC2 Get-SOC2TargetSubscriptions { @($script:FakeSubscription) }
            Mock -ModuleName EntraChecks-SOC2 Set-AzContext { }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest {
                if ($Uri -like '*backupProtectedItems*') { Get-SOC2Fixture 'backupProtectedItems-empty.json' }
                else { Get-SOC2Fixture 'recoveryServicesVaults-healthy.json' }
            }
        }

        It 'emits FAIL about zero protected items' {
            $result = Test-SOC2BackupConfiguration
            $fails = @($result | Where-Object { $_.Status -eq 'FAIL' })
            $fails.Count | Should -BeGreaterOrEqual 1
            $fails[0].Description | Should -BeLike '*none have protected items*'
        }
    }

    Context 'When vaults are LRS-only' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-Module { @{ Name = 'Az.RecoveryServices' } } -ParameterFilter { $Name -eq 'Az.RecoveryServices' }
            Mock -ModuleName EntraChecks-SOC2 Get-SOC2TargetSubscriptions { @($script:FakeSubscription) }
            Mock -ModuleName EntraChecks-SOC2 Set-AzContext { }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest {
                if ($Uri -like '*backupProtectedItems*') { Get-SOC2Fixture 'backupProtectedItems-present.json' }
                else { Get-SOC2Fixture 'recoveryServicesVaults-lrs-only.json' }
            }
        }

        It 'emits WARNING about redundancy when minimum is GRS' {
            $result = Test-SOC2BackupConfiguration -MinRedundancyTier 'GRS'
            $warn = @($result | Where-Object { $_.Status -eq 'WARNING' })
            $warn.Count | Should -BeGreaterOrEqual 1
            $warn[0].Description | Should -BeLike '*redundancy*'
        }
    }

    Context 'When vaults + items + GRS all present' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-Module { @{ Name = 'Az.RecoveryServices' } } -ParameterFilter { $Name -eq 'Az.RecoveryServices' }
            Mock -ModuleName EntraChecks-SOC2 Get-SOC2TargetSubscriptions { @($script:FakeSubscription) }
            Mock -ModuleName EntraChecks-SOC2 Set-AzContext { }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest {
                if ($Uri -like '*backupProtectedItems*') { Get-SOC2Fixture 'backupProtectedItems-present.json' }
                else { Get-SOC2Fixture 'recoveryServicesVaults-healthy.json' }
            }
        }

        It 'emits OK with SOC2_BackupConfigurationHealthy type' {
            $result = Test-SOC2BackupConfiguration -MinRedundancyTier 'GRS'
            $ok = @($result | Where-Object { $_.Status -eq 'OK' })
            $ok.Count | Should -Be 1
            $ok[0].Type | Should -Be 'SOC2_BackupConfigurationHealthy'
        }
    }
}

Describe 'Test-SOC2ServiceHealthBaseline' {

    Context 'When no subscriptions are accessible' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-SOC2TargetSubscriptions { @() }
        }

        It 'emits SOC2_Phase2_AzContextMissing INFO' {
            $result = Test-SOC2ServiceHealthBaseline
            $result[0].Type | Should -Be 'SOC2_Phase2_AzContextMissing'
            $result[0].Status | Should -Be 'INFO'
        }
    }

    Context 'When resources report Available at or above threshold' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-SOC2TargetSubscriptions { @($script:FakeSubscription) }
            Mock -ModuleName EntraChecks-SOC2 Set-AzContext { }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest { Get-SOC2Fixture 'resourceHealth-healthy.json' }
        }

        It 'emits OK with SOC2_ServiceHealthHealthy' {
            $result = Test-SOC2ServiceHealthBaseline -AvailabilityThresholdPercent 98
            $result[0].Status | Should -Be 'OK'
            $result[0].Type | Should -Be 'SOC2_ServiceHealthHealthy'
        }
    }

    Context 'When availability is below threshold' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-SOC2TargetSubscriptions { @($script:FakeSubscription) }
            Mock -ModuleName EntraChecks-SOC2 Set-AzContext { }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest { Get-SOC2Fixture 'resourceHealth-degraded.json' }
        }

        It 'emits WARNING with SOC2_ServiceHealthGap' {
            $result = Test-SOC2ServiceHealthBaseline -AvailabilityThresholdPercent 98
            $result[0].Status | Should -Be 'WARNING'
            $result[0].Type | Should -Be 'SOC2_ServiceHealthGap'
        }
    }
}

Describe 'Test-SOC2DiagnosticSettingsExport' {

    Context 'When all required categories are exported' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-Command { @{ Name = 'Get-AzContext' } } -ParameterFilter { $Name -eq 'Get-AzContext' }
            Mock -ModuleName EntraChecks-SOC2 Get-AzContext { [pscustomobject]@{ Account = 'test@example.invalid' } }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest { Get-SOC2Fixture 'aadiam-diagnosticSettings-complete.json' }
        }

        It 'emits OK with SOC2_DiagnosticSettingsHealthy' {
            $result = Test-SOC2DiagnosticSettingsExport
            $result[0].Status | Should -Be 'OK'
            $result[0].Type | Should -Be 'SOC2_DiagnosticSettingsHealthy'
        }
    }

    Context 'When SignInLogs are not exported' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-Command { @{ Name = 'Get-AzContext' } } -ParameterFilter { $Name -eq 'Get-AzContext' }
            Mock -ModuleName EntraChecks-SOC2 Get-AzContext { [pscustomobject]@{ Account = 'test@example.invalid' } }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest { Get-SOC2Fixture 'aadiam-diagnosticSettings-missing-signin.json' }
        }

        It 'emits FAIL with SOC2_DiagnosticSettingsGap' {
            $result = Test-SOC2DiagnosticSettingsExport
            $result[0].Status | Should -Be 'FAIL'
            $result[0].Type | Should -Be 'SOC2_DiagnosticSettingsGap'
            $result[0].Description | Should -BeLike '*SignInLogs*'
        }
    }

    Context 'When no diagnostic settings exist' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-Command { @{ Name = 'Get-AzContext' } } -ParameterFilter { $Name -eq 'Get-AzContext' }
            Mock -ModuleName EntraChecks-SOC2 Get-AzContext { [pscustomobject]@{ Account = 'test@example.invalid' } }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest { Get-SOC2Fixture 'aadiam-diagnosticSettings-none.json' }
        }

        It 'emits FAIL about zero settings' {
            $result = Test-SOC2DiagnosticSettingsExport
            $result[0].Status | Should -Be 'FAIL'
            $result[0].Description | Should -BeLike '*No diagnostic settings*'
        }
    }
}

Describe 'Test-SOC2EncryptionPosture' {
    # Note: encryption check re-uses Get-DefenderComplianceAssessments from the
    # Defender module, which is cross-module-mocked awkwardly under Pester 5.
    # We test the degraded paths here; the happy/fail paths are exercised by
    # the Phase 2 PR 2 smoke test against live Defender fixtures.

    Context 'When Defender module is not loaded' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-Command { $null } -ParameterFilter { $Name -eq 'Get-DefenderComplianceAssessments' }
        }

        It 'emits SOC2_Phase2_PrereqMissing INFO finding' {
            $result = @(Test-SOC2EncryptionPosture)
            $result.Count | Should -Be 1
            $result[0].Status | Should -Be 'INFO'
            $result[0].Type | Should -Be 'SOC2_Phase2_PrereqMissing'
            $result[0].TSCReferences | Should -Contain 'CC6.7'
        }
    }

    Context 'When no subscriptions are accessible' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-Command { @{ Name = 'Get-DefenderComplianceAssessments' } } -ParameterFilter { $Name -eq 'Get-DefenderComplianceAssessments' }
            Mock -ModuleName EntraChecks-SOC2 Get-SOC2TargetSubscriptions { @() }
        }

        It 'emits SOC2_Phase2_AzContextMissing INFO finding' {
            $result = @(Test-SOC2EncryptionPosture)
            $result.Count | Should -Be 1
            $result[0].Status | Should -Be 'INFO'
            $result[0].Type | Should -Be 'SOC2_Phase2_AzContextMissing'
        }
    }
}

Describe 'Test-SOC2MalwareProtection' {

    Context 'When WDATP connector is disabled on all subs' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-SOC2TargetSubscriptions { @($script:FakeSubscription) }
            Mock -ModuleName EntraChecks-SOC2 Set-AzContext { }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest { Get-SOC2Fixture 'defenderSettings-wdatp-disabled.json' }
        }

        It 'emits FAIL with SOC2_MalwareProtectionGaps' {
            $result = Test-SOC2MalwareProtection
            $result[0].Status | Should -Be 'FAIL'
            $result[0].Type | Should -Be 'SOC2_MalwareProtectionGaps'
        }
    }

    Context 'When WDATP connector is enabled' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Get-SOC2TargetSubscriptions { @($script:FakeSubscription) }
            Mock -ModuleName EntraChecks-SOC2 Set-AzContext { }
            Mock -ModuleName EntraChecks-SOC2 Invoke-SOC2AzureRestRequest { Get-SOC2Fixture 'defenderSettings-wdatp-enabled.json' }
            Mock -ModuleName EntraChecks-SOC2 Get-Command { $null } -ParameterFilter { $Name -eq 'Get-DefenderComplianceAssessments' }
        }

        It 'emits OK with SOC2_MalwareProtectionHealthy' {
            $result = Test-SOC2MalwareProtection
            $result[-1].Status | Should -Be 'OK'
            $result[-1].Type | Should -Be 'SOC2_MalwareProtectionHealthy'
        }
    }
}

# Drift resolved: these tests failed on stubbed (no-Graph) machines because
# the param-less Invoke-MgGraphRequest stub meant $Uri never bound inside the
# Mock bodies, so every fixture branch fell through to $null and the check
# hit the "GA role not found" INFO path. The stub now declares a real
# parameter block (Tests/Helpers/Stub-CloudCmdlets.ps1), so the URI
# discrimination works everywhere and the KnownAssertionDrift tag is gone.
Describe 'Test-SOC2BreakGlassAccountsConfigured' {

    Context 'When there is only one Global Administrator' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Invoke-MgGraphRequest {
                if ($Uri -like '*directoryRoles/role-object-id-ga/members*') { Get-SOC2Fixture 'directoryRoles-ga-members-one.json' }
                elseif ($Uri -like '*directoryRoles*') { Get-SOC2Fixture 'directoryRoles-ga.json' }
                elseif ($Uri -like '*conditionalAccess*') { Get-SOC2Fixture 'conditionalAccess-breakglass-one-excluded.json' }
                else { $null }
            }
        }

        It 'emits FAIL Critical about single-point-of-failure' {
            $result = Test-SOC2BreakGlassAccountsConfigured -MinimumAccounts 2
            $result[0].Status | Should -Be 'FAIL'
            $result[0].Severity | Should -Be 'Critical'
            $result[0].Description | Should -BeLike '*Single point of failure*'
        }
    }

    Context 'When 3 GAs exist but only one is CA-excluded (below minimum)' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Invoke-MgGraphRequest {
                if ($Uri -like '*directoryRoles/role-object-id-ga/members*') { Get-SOC2Fixture 'directoryRoles-ga-members-three.json' }
                elseif ($Uri -like '*directoryRoles*' -and $Method -eq 'GET' -and $Uri -notlike '*members*') { Get-SOC2Fixture 'directoryRoles-ga.json' }
                elseif ($Uri -like '*conditionalAccess*') { Get-SOC2Fixture 'conditionalAccess-breakglass-one-excluded.json' }
                else { $null }
            }
        }

        It 'emits FAIL SOC2_BreakGlassMissing' {
            $result = Test-SOC2BreakGlassAccountsConfigured -MinimumAccounts 2
            $result[0].Status | Should -Be 'FAIL'
            $result[0].Type | Should -Be 'SOC2_BreakGlassMissing'
        }
    }

    Context 'When 3 GAs exist and 2 are excluded from every enabled policy' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Invoke-MgGraphRequest {
                if ($Uri -like '*directoryRoles/role-object-id-ga/members*') { Get-SOC2Fixture 'directoryRoles-ga-members-three.json' }
                elseif ($Uri -like '*directoryRoles*' -and $Uri -notlike '*members*') { Get-SOC2Fixture 'directoryRoles-ga.json' }
                elseif ($Uri -like '*conditionalAccess*') { Get-SOC2Fixture 'conditionalAccess-breakglass-two-excluded.json' }
                else { $null }
            }
        }

        It 'emits OK with SOC2_BreakGlassConfigured' {
            $result = Test-SOC2BreakGlassAccountsConfigured -MinimumAccounts 2
            $ok = @($result | Where-Object { $_.Status -eq 'OK' })
            $ok.Count | Should -Be 1
            $ok[0].Type | Should -Be 'SOC2_BreakGlassConfigured'
        }
    }

    Context 'When no Conditional Access policies exist' {
        BeforeEach {
            Mock -ModuleName EntraChecks-SOC2 Invoke-MgGraphRequest {
                if ($Uri -like '*directoryRoles/role-object-id-ga/members*') { Get-SOC2Fixture 'directoryRoles-ga-members-three.json' }
                elseif ($Uri -like '*directoryRoles*' -and $Uri -notlike '*members*') { Get-SOC2Fixture 'directoryRoles-ga.json' }
                elseif ($Uri -like '*conditionalAccess*') { Get-SOC2Fixture 'conditionalAccess-none.json' }
                else { $null }
            }
        }

        It 'emits WARNING referencing both CC6.1 and CC7.5' {
            $result = Test-SOC2BreakGlassAccountsConfigured
            $result[0].Status | Should -Be 'WARNING'
            $result[0].TSCReferences | Should -Contain 'CC6.1'
            $result[0].TSCReferences | Should -Contain 'CC7.5'
        }
    }
}

Describe 'New-SOC2LicensingGapFindings' {

    Context 'When all capabilities are absent' {
        It 'emits exactly 6 INFO findings with SOC2_LicensingGap_* types' {
            $caps = @{
                HasP2 = $false
                HasIntune = $false
                HasPurviewE5 = $false
                HasDefenderForCloud = $false
                HasDefenderForEndpoint = $false
                HasPriva = $false
                HasAzContext = $false
            }
            $result = New-SOC2LicensingGapFindings -Capabilities $caps
            $result.Count | Should -Be 6
            foreach ($f in $result) {
                $f.Status | Should -Be 'INFO'
                $f.Severity | Should -Be 'Low'
                $f.Type | Should -BeLike 'SOC2_LicensingGap_*'
            }
        }
    }

    Context 'When IdentityProtection override is set to WARNING' {
        It 'escalates that finding to WARNING Medium' {
            $caps = @{
                HasP2 = $false
                HasIntune = $true
                HasPurviewE5 = $true
                HasDefenderForCloud = $true
                HasDefenderForEndpoint = $true
                HasPriva = $true
                HasAzContext = $true
            }
            $overrides = @{ 'IdentityProtection' = 'WARNING' }
            $result = @(New-SOC2LicensingGapFindings -Capabilities $caps -Overrides $overrides)
            $result.Count | Should -Be 1
            $result[0].Type | Should -Be 'SOC2_LicensingGap_IdentityProtection'
            $result[0].Status | Should -Be 'WARNING'
            $result[0].Severity | Should -Be 'Medium'
        }
    }

    Context 'When all capabilities are present' {
        It 'emits zero findings' {
            $caps = @{
                HasP2 = $true
                HasIntune = $true
                HasPurviewE5 = $true
                HasDefenderForCloud = $true
                HasDefenderForEndpoint = $true
                HasPriva = $true
                HasAzContext = $true
            }
            $result = @(New-SOC2LicensingGapFindings -Capabilities $caps)
            $result.Count | Should -Be 0
        }
    }
}
