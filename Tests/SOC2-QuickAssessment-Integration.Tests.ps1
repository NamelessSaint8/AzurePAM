<#
.SYNOPSIS
    Pester 5 test suite for the SOC 2 / Quick Assessment integration.

.DESCRIPTION
    Validates the SOC2.Enabled config-flag reading logic in
    Get-SOC2EnabledFromConfig (which gates the Quick-Assessment auto-run).

    Uses PowerShell AST to extract just the helper function definition
    from Start-EntraChecks.ps1 without executing the script's main loop.
    This lets us unit-test the pure logic without spinning up the full
    orchestrator.

    Full end-to-end coverage (config flag triggers SOC 2 run, browser-open
    toggles with mode, error recovery) is covered by manual smoke test
    against a real tenant — noted in the plan's acceptance criteria.

    Run: Invoke-Pester -Path Tests/SOC2-QuickAssessment-Integration.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    # Native App Plan Phase 1 (4/4): the orchestration function definitions
    # moved out of Start-EntraChecks.ps1 into the dot-sourceable
    # EntraChecks.Orchestration.ps1 include. Fall back to the old location
    # so this test works before and after the split.
    $scriptPath = Join-Path $repoRoot 'EntraChecks.Orchestration.ps1'
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        $scriptPath = Join-Path $repoRoot 'Start-EntraChecks.ps1'
    }

    # Extract Get-SOC2EnabledFromConfig function definition via AST — avoids
    # sourcing the whole script (which would launch the interactive menu).
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    $functions = $ast.FindAll(
        { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] },
        $true
    )
    $fnAst = $functions | Where-Object { $_.Name -eq 'Get-SOC2EnabledFromConfig' } | Select-Object -First 1
    if (-not $fnAst) { throw "Get-SOC2EnabledFromConfig not found in $scriptPath" }

    # Define the function in this scope via dot-sourced scriptblock so tests
    # can invoke it directly. (Avoids Invoke-Expression per PSScriptAnalyzer.)
    . ([scriptblock]::Create($fnAst.Extent.Text))

    function New-TempConfig {
        param([object]$SOC2Value)
        $cfg = @{
            Version = '1.0.0'
            Assessment = @{ Scope = @('Core') }
            SOC2 = $SOC2Value
        }
        $path = Join-Path $env:TEMP "soc2-quickint-$((Get-Random)).json"
        $cfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }
}

Describe 'Get-SOC2EnabledFromConfig' {

    Context 'When the config file does not exist' {
        It 'returns $false' {
            $result = Get-SOC2EnabledFromConfig -ConfigPath (Join-Path $env:TEMP "does-not-exist-$((Get-Random)).json")
            $result | Should -Be $false
        }
    }

    Context 'When SOC2.Enabled is $false' {
        It 'returns $false' {
            $path = New-TempConfig -SOC2Value @{ Enabled = $false; Categories = @('CC') }
            try {
                Get-SOC2EnabledFromConfig -ConfigPath $path | Should -Be $false
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'When SOC2.Enabled is $true' {
        It 'returns $true' {
            $path = New-TempConfig -SOC2Value @{ Enabled = $true; Categories = @('CC') }
            try {
                Get-SOC2EnabledFromConfig -ConfigPath $path | Should -Be $true
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'When SOC2 block is absent entirely' {
        It 'returns $false (no config means no auto-run)' {
            $path = Join-Path $env:TEMP "soc2-quickint-nosoc2-$((Get-Random)).json"
            @{ Version = '1.0.0'; Assessment = @{ Scope = @('Core') } } | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding UTF8
            try {
                Get-SOC2EnabledFromConfig -ConfigPath $path | Should -Be $false
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'When SOC2 block exists but Enabled key is missing' {
        It 'returns $false (missing flag treated as disabled)' {
            $path = New-TempConfig -SOC2Value @{ Categories = @('CC') }  # no Enabled
            try {
                Get-SOC2EnabledFromConfig -ConfigPath $path | Should -Be $false
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'When the config file is malformed JSON' {
        It 'returns $false and emits a yellow warning (no crash)' {
            $path = Join-Path $env:TEMP "soc2-quickint-bad-$((Get-Random)).json"
            Set-Content -LiteralPath $path -Value '{ not valid json' -Encoding UTF8
            try {
                # The function writes a yellow warning via Write-Host — we only
                # assert the return value for non-flakiness across PowerShell
                # hosts. Warning appearance is a UX signal, not a correctness one.
                $result = Get-SOC2EnabledFromConfig -ConfigPath $path
                $result | Should -Be $false
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Uses the real default config file' {
        It 'returns $false for the shipped default config (SOC2.Enabled defaults to false)' {
            $defaultCfg = Join-Path $repoRoot 'config\entrachecks.config.json'
            (Test-Path $defaultCfg) | Should -Be $true
            Get-SOC2EnabledFromConfig -ConfigPath $defaultCfg | Should -Be $false
        }
    }
}
