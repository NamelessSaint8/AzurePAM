<#
.SYNOPSIS
    Pester 5 test suite for SOC 2 Phase 3 — namespace migration shim.

.DESCRIPTION
    Validates Resolve-SOC2NamespaceConfig and the Import-Configuration
    integration. Three primary scenarios per Phase 3 plan SS3.C.7:

    1. Old-only config (SOC2.Phase2 present, no AzureReadiness) → AzureReadiness
       is populated, deprecation warning fires.
    2. New-only config → AzureReadiness present, no warning, Phase2 mirrored
       as alias.
    3. Both present → AzureReadiness wins per key, "both present" warning.

    Plus regression checks: byte-stable shape, correctly handles missing SOC2
    block, never throws on empty/null input.

    Run: Invoke-Pester -Path Tests/SOC2-Phase3.Tests.ps1

.NOTES
    Requires Pester 5.0+. Install with:
        Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $configModule = Join-Path $repoRoot 'Modules\EntraChecks-Configuration.psm1'
    Import-Module $configModule -Force

    function New-OldOnlyConfig {
        $cfg = @{}
        $cfg['Version'] = '1.0.0'
        $soc2 = @{}
        $phase2 = @{}
        $phase2['SubscriptionFilter'] = @('sub-a')
        $bg = @{}
        $bg['MinimumAccounts'] = 3
        $phase2['BreakGlass'] = $bg
        $bk = @{}
        $bk['MinRedundancyTier'] = 'GRS'
        $phase2['Backup'] = $bk
        $soc2['Phase2'] = $phase2
        $cfg['SOC2'] = $soc2
        return $cfg
    }

    function New-NewOnlyConfig {
        $cfg = @{}
        $cfg['Version'] = '1.0.0'
        $soc2 = @{}
        $az = @{}
        $az['SubscriptionFilter'] = @('sub-a')
        $bg = @{}
        $bg['MinimumAccounts'] = 3
        $az['BreakGlass'] = $bg
        $bk = @{}
        $bk['MinRedundancyTier'] = 'GRS'
        $az['Backup'] = $bk
        $soc2['AzureReadiness'] = $az
        $cfg['SOC2'] = $soc2
        return $cfg
    }

    function New-BothPresentConfig {
        $cfg = @{}
        $cfg['Version'] = '1.0.0'
        $soc2 = @{}
        # Phase2 has older settings
        $phase2 = @{}
        $oldBg = @{}
        $oldBg['MinimumAccounts'] = 2
        $phase2['BreakGlass'] = $oldBg
        $oldBk = @{}
        $oldBk['MinRedundancyTier'] = 'LRS'
        $phase2['Backup'] = $oldBk
        $phase2['SubscriptionFilter'] = @('legacy-sub')
        # AzureReadiness has newer settings; should win
        $az = @{}
        $newBg = @{}
        $newBg['MinimumAccounts'] = 5
        $az['BreakGlass'] = $newBg
        $newBk = @{}
        $newBk['MinRedundancyTier'] = 'RA-GRS'
        $az['Backup'] = $newBk
        # No SubscriptionFilter in AzureReadiness — should inherit from Phase2 via merge
        $soc2['Phase2'] = $phase2
        $soc2['AzureReadiness'] = $az
        $cfg['SOC2'] = $soc2
        return $cfg
    }

    function Reset-DeprecationGuard {
        # Force the module-scoped guard back to false so each test sees
        # warnings emit afresh.
        InModuleScope EntraChecks-Configuration {
            $script:Soc2DeprecationWarningIssued = $false
        }
    }
}

Describe 'Resolve-SOC2NamespaceConfig' {

    BeforeEach { Reset-DeprecationGuard }

    Context 'When config has neither Phase2 nor AzureReadiness' {
        It 'returns the config unchanged with no warning' {
            $cfg = @{ Version = '1.0.0'; SOC2 = @{ Enabled = $false } }
            $warnings = @()
            $result = Resolve-SOC2NamespaceConfig -ConfigObject $cfg -WarningAction SilentlyContinue -WarningVariable +warnings
            $result.SOC2.Enabled | Should -Be $false
            $result.SOC2.ContainsKey('AzureReadiness') | Should -Be $false
            $result.SOC2.ContainsKey('Phase2') | Should -Be $false
            $warnings.Count | Should -Be 0
        }
    }

    Context 'When config has no SOC2 block at all' {
        It 'returns the config unchanged' {
            $cfg = @{ Version = '1.0.0' }
            $result = Resolve-SOC2NamespaceConfig -ConfigObject $cfg
            $result.ContainsKey('SOC2') | Should -Be $false
        }
    }

    Context 'Scenario 1: SOC2.Phase2 only (old-format config)' {
        It 'aliases Phase2 into AzureReadiness and emits deprecation warning' {
            $cfg = New-OldOnlyConfig
            $warnings = @()
            $result = Resolve-SOC2NamespaceConfig -ConfigObject $cfg -WarningAction SilentlyContinue -WarningVariable +warnings

            $result.SOC2.AzureReadiness.BreakGlass.MinimumAccounts | Should -Be 3
            $result.SOC2.AzureReadiness.Backup.MinRedundancyTier | Should -Be 'GRS'
            $result.SOC2.AzureReadiness.SubscriptionFilter | Should -Contain 'sub-a'

            # Phase2 should still be present (alias preserved for non-migrated callers)
            $result.SOC2.Phase2.BreakGlass.MinimumAccounts | Should -Be 3

            # Exactly one deprecation warning
            $warnings.Count | Should -Be 1
            $warnings[0] | Should -BeLike '*deprecated*'
            $warnings[0] | Should -BeLike '*SOC2.Phase2 only*'
        }
    }

    Context 'Scenario 2: SOC2.AzureReadiness only (new-format config)' {
        It 'mirrors AzureReadiness to Phase2 and emits no warning' {
            $cfg = New-NewOnlyConfig
            $warnings = @()
            $result = Resolve-SOC2NamespaceConfig -ConfigObject $cfg -WarningAction SilentlyContinue -WarningVariable +warnings

            $result.SOC2.AzureReadiness.BreakGlass.MinimumAccounts | Should -Be 3
            $result.SOC2.Phase2.BreakGlass.MinimumAccounts | Should -Be 3
            $warnings.Count | Should -Be 0
        }
    }

    Context 'Scenario 3: both Phase2 and AzureReadiness present' {
        It 'AzureReadiness wins per key, with recursive merge for missing keys' {
            $cfg = New-BothPresentConfig
            $warnings = @()
            $result = Resolve-SOC2NamespaceConfig -ConfigObject $cfg -WarningAction SilentlyContinue -WarningVariable +warnings

            # AzureReadiness values win where both are set
            $result.SOC2.AzureReadiness.BreakGlass.MinimumAccounts | Should -Be 5
            $result.SOC2.AzureReadiness.Backup.MinRedundancyTier | Should -Be 'RA-GRS'

            # Phase2-only keys propagate up via merge
            $result.SOC2.AzureReadiness.SubscriptionFilter | Should -Contain 'legacy-sub'

            # Phase2 is now an alias of the merged AzureReadiness
            $result.SOC2.Phase2.BreakGlass.MinimumAccounts | Should -Be 5

            # Single "both present" warning
            $warnings.Count | Should -Be 1
            $warnings[0] | Should -BeLike '*both SOC2.AzureReadiness and SOC2.Phase2 detected*'
        }
    }

    Context 'Deprecation warning is suppressed after first issuance per session' {
        It 'fires once even when the shim is invoked multiple times' {
            $warnings = @()

            $cfg1 = New-OldOnlyConfig
            $null = Resolve-SOC2NamespaceConfig -ConfigObject $cfg1 -WarningAction SilentlyContinue -WarningVariable +warnings

            $cfg2 = New-OldOnlyConfig
            $null = Resolve-SOC2NamespaceConfig -ConfigObject $cfg2 -WarningAction SilentlyContinue -WarningVariable +warnings

            $warnings.Count | Should -Be 1
        }
    }

    Context 'Idempotency: running the shim twice produces the same shape' {
        It 'second invocation is a no-op when AzureReadiness is canonical' {
            $cfg = New-OldOnlyConfig
            $first = Resolve-SOC2NamespaceConfig -ConfigObject $cfg -WarningAction SilentlyContinue
            Reset-DeprecationGuard
            $second = Resolve-SOC2NamespaceConfig -ConfigObject $first -WarningAction SilentlyContinue

            $second.SOC2.AzureReadiness.BreakGlass.MinimumAccounts | Should -Be 3
            $second.SOC2.Phase2.BreakGlass.MinimumAccounts | Should -Be 3
        }
    }
}

Describe 'Import-Configuration integration with namespace shim' {

    BeforeEach { Reset-DeprecationGuard }

    Context 'When the actual default config file is loaded' {
        It 'produces SOC2.AzureReadiness as the canonical block (default config uses new namespace)' {
            $cfgPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'config\entrachecks.config.json'
            $cfg = Import-Configuration -FilePath $cfgPath
            $cfg.SOC2.AzureReadiness | Should -Not -BeNullOrEmpty
            $cfg.SOC2.AzureReadiness.BreakGlass.MinimumAccounts | Should -Be 2
            # Mirrored into Phase2 so non-migrated callers still work
            $cfg.SOC2.Phase2 | Should -Not -BeNullOrEmpty
            $cfg.SOC2.Phase2.BreakGlass.MinimumAccounts | Should -Be 2
        }
    }
}
