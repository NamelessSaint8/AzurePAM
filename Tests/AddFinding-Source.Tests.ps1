<#
.SYNOPSIS
    Pester 5 test suite for the Source field added to Add-Finding (Phase 2).

.DESCRIPTION
    Verifies:
    1. A finding emitted with no -Source argument carries Source = 'Internal'
       when no module frame is on the call stack.
    2. A finding emitted from a recognised source-module file (per
       $script:ModuleToSource in EntraChecks-DataSources.psm1) is auto-tagged
       with the matching key.
    3. An explicit -Source override wins over auto-derive.
    4. An invalid -Source override falls back to auto-derive (and warns).
    5. The finding object exposes the field as a property the reporting layer
       can read.

    Add-Finding is defined in Scripts/Invoke-EntraChecks.ps1 alongside other
    orchestration code. We extract just the function definition via the AST
    parser so tests don't dot-source the full orchestrator (which would try
    to Connect-MgGraph). The script-scope variables Add-Finding consumes
    ($script:Findings, $script:CheckNameToType) are seeded in BeforeAll.

    Run: Invoke-Pester -Path Tests/AddFinding-Source.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-DataSources.psm1') -Force -DisableNameChecking

    # Pull just Add-Finding out of the orchestrator script via AST parsing
    $orchestrator = Join-Path $repoRoot 'Scripts/Invoke-EntraChecks.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($orchestrator, [ref]$tokens, [ref]$errors)
    $fnAst = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Add-Finding' }, $true) | Select-Object -First 1
    if (-not $fnAst) { throw 'Could not locate Add-Finding in Scripts/Invoke-EntraChecks.ps1' }

    # Stub Write-Log/Write-AuditLog so the function doesn't fail on the
    # logging module not being initialised.
    function Write-Log { param([string]$Level, [string]$Message, [string]$Category, [hashtable]$Properties) }
    function Write-AuditLog { param([string]$EventType, [string]$Description, [string]$TargetObject, [string]$Result) }

    Invoke-Expression $fnAst.Extent.Text

    # Seed the script-scope variables Add-Finding reads
    $script:Findings = @()
    $script:CheckNameToType = @{}

    function Reset-FindingsList { $script:Findings = @() }
}

Describe 'Add-Finding -Source field' {

    BeforeEach {
        Reset-FindingsList
    }

    It 'tags findings with Source = Internal when no module frame matches' {
        Add-Finding -Status 'OK' -Object 'unit-test' -Description 'Plain default'
        $script:Findings | Should -HaveCount 1
        $script:Findings[0].PSObject.Properties.Name | Should -Contain 'Source'
        $script:Findings[0].Source | Should -BeExactly 'Internal'
    }

    It 'honors an explicit -Source override' {
        Add-Finding -Status 'WARNING' -Object 'unit-test' -Description 'Override' -Source 'SecureScore'
        $script:Findings[0].Source | Should -BeExactly 'SecureScore'
    }

    It 'falls back to auto-derive when an unknown -Source is passed' {
        Add-Finding -Status 'INFO' -Object 'unit-test' -Description 'Bogus override' -Source 'NotARealSource' -WarningAction SilentlyContinue
        $script:Findings[0].Source | Should -BeExactly 'Internal'
    }

    It 'auto-derives the source from a module-scoped caller frame' {
        $modulePath = Join-Path $TestDrive 'EntraChecks-AzurePolicy.psm1'
        Set-Content -Path $modulePath -Value @"
function Test-FakeAzurePolicyCheck {
    Add-Finding -Status 'FAIL' -Object 'sub-1' -Description 'Synthetic AzurePolicy finding'
}
Export-ModuleMember -Function Test-FakeAzurePolicyCheck
"@
        Import-Module $modulePath -Force
        try {
            Test-FakeAzurePolicyCheck
        }
        finally {
            Remove-Module 'EntraChecks-AzurePolicy' -Force -ErrorAction SilentlyContinue
        }
        $script:Findings | Should -HaveCount 1
        $script:Findings[0].Source | Should -BeExactly 'AzurePolicy'
    }

    It 'preserves all existing finding fields alongside Source' {
        Add-Finding -Status 'FAIL' -Object 'tenant' -Description 'Has all fields' -Remediation 'Do the thing' -Source 'PurviewCompliance'
        $f = $script:Findings[0]
        $f.Status      | Should -BeExactly 'FAIL'
        $f.Object      | Should -BeExactly 'tenant'
        $f.Description | Should -BeExactly 'Has all fields'
        $f.Remediation | Should -BeExactly 'Do the thing'
        $f.Source      | Should -BeExactly 'PurviewCompliance'
        $f.PSObject.Properties.Name | Should -Contain 'Time'
        $f.PSObject.Properties.Name | Should -Contain 'CheckName'
        $f.PSObject.Properties.Name | Should -Contain 'Type'
    }
}
