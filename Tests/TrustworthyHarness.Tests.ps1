<#
.SYNOPSIS
    Pester 5 tests for the "trustworthy harness" PR — guards three
    correctness bugs that previously masked failures.

.DESCRIPTION
    Each Describe block locks in one fix:

      1. Config schema Mode enum must match Start-EntraChecks.ps1's
         ValidateSet (Interactive | Quick | Scheduled | Hybrid). Previous
         enum only allowed Interactive | Scheduled | CI/CD so config-driven
         Quick or Hybrid runs failed validation even though the orchestrator
         param accepted them.

      2. Scripts/Invoke-EntraChecks.ps1 resolves Modules/ at the repo root
         even when invoked directly (Split-Path Parent of the script's
         own dir). Previously it joined Scripts/Modules which doesn't
         exist, silently skipping the logging / schema / data-source
         imports.

      3. Scripts/test-syntax.ps1 exits non-zero on syntax error and covers
         every script + module (Get-ChildItem instead of a hand-curated
         list whose comma-array construction silently threw). The old
         version reported "OK" on a project where only modules were
         actually parsed and a broken script slipped through.

    Run: Invoke-Pester -Path Tests/TrustworthyHarness.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'Modules/EntraChecks-Configuration.psm1') -Force
}

Describe 'Config schema — Mode enum matches Start-EntraChecks.ps1 ValidateSet' {

    BeforeAll {
        $script:Schema = Get-ConfigurationSchema
        $script:ModeEnum = $script:Schema.properties.Assessment.properties.Mode.enum
        # Pull the orchestrator's ValidateSet so the test fails the moment
        # the two drift apart again.
        $script:Orchestrator = Join-Path $script:RepoRoot 'Start-EntraChecks.ps1'
        $orchestratorText = Get-Content -Raw -LiteralPath $script:Orchestrator
        $match = [regex]::Match(
            $orchestratorText,
            '\[ValidateSet\(([^\)]*)\)\][\s\r\n]*\[string\]\$Mode')
        $script:OrchestratorModes = if ($match.Success) {
            ($match.Groups[1].Value -split ',' | ForEach-Object { $_.Trim().Trim('"') })
        } else { @() }
    }

    It 'orchestrator ValidateSet is non-empty (sanity check on regex extraction)' {
        $script:OrchestratorModes.Count | Should -BeGreaterThan 0
    }

    It 'every orchestrator mode is accepted by the schema' {
        foreach ($mode in $script:OrchestratorModes) {
            $script:ModeEnum | Should -Contain $mode -Because "Start-EntraChecks.ps1 accepts -Mode $mode; schema must too"
        }
    }

    It 'schema accepts Quick' { $script:ModeEnum | Should -Contain 'Quick' }
    It 'schema accepts Hybrid' { $script:ModeEnum | Should -Contain 'Hybrid' }
    It 'schema still accepts Interactive (default)' { $script:ModeEnum | Should -Contain 'Interactive' }
    It 'schema still accepts Scheduled' { $script:ModeEnum | Should -Contain 'Scheduled' }

    It 'Test-Configuration validates a Quick-mode config without errors' {
        $cfg = @{
            Version    = '1.0.0'
            Assessment = @{
                Scope = @('Core')
                Mode  = 'Quick'
            }
            Authentication = @{ Method = 'Interactive' }
            Logging        = @{ MinimumLevel = 'INFO' }
            ErrorHandling  = @{ MaxRetries = 3 }
        }
        $result = Test-Configuration -ConfigObject $cfg
        $modeErrors = @($result.Errors | Where-Object { $_ -match "Invalid Mode" })
        $modeErrors.Count | Should -Be 0
    }

    It 'Test-Configuration validates a Hybrid-mode config without errors' {
        $cfg = @{
            Version    = '1.0.0'
            Assessment = @{
                Scope = @('Core')
                Mode  = 'Hybrid'
            }
            Authentication = @{ Method = 'Interactive' }
            Logging        = @{ MinimumLevel = 'INFO' }
            ErrorHandling  = @{ MaxRetries = 3 }
        }
        $result = Test-Configuration -ConfigObject $cfg
        $modeErrors = @($result.Errors | Where-Object { $_ -match "Invalid Mode" })
        $modeErrors.Count | Should -Be 0
    }

    It 'Test-Configuration rejects an unknown Mode' {
        $cfg = @{
            Version    = '1.0.0'
            Assessment = @{
                Scope = @('Core')
                Mode  = 'NotARealMode'
            }
            Authentication = @{ Method = 'Interactive' }
            Logging        = @{ MinimumLevel = 'INFO' }
            ErrorHandling  = @{ MaxRetries = 3 }
        }
        $result = Test-Configuration -ConfigObject $cfg
        $modeErrors = @($result.Errors | Where-Object { $_ -match "Invalid Mode 'NotARealMode'" })
        $modeErrors.Count | Should -BeGreaterThan 0
    }
}

Describe 'Scripts/Invoke-EntraChecks.ps1 — modules-path resolution' {

    BeforeAll {
        $script:InvokeScript = Join-Path $script:RepoRoot 'Scripts/Invoke-EntraChecks.ps1'
        $script:ScriptText = Get-Content -Raw -LiteralPath $script:InvokeScript
    }

    It 'falls back to parent directory when Scripts/Modules does not exist' {
        # The fallback is the load-bearing line that fixes the bug.
        $script:ScriptText | Should -Match 'Split-Path -Parent \$scriptRoot'
        $script:ScriptText | Should -Match 'Join-Path \$parentRoot "Modules"'
    }

    It 'still attempts the sibling Modules folder first (legacy layouts)' {
        # Don't break installs where Scripts/ has been collapsed into repo root.
        $script:ScriptText | Should -Match 'Join-Path \$scriptRoot "Modules"'
    }

    It 'imports EntraChecks-FindingSchema.psm1 as a fallback' {
        $script:ScriptText | Should -Match "EntraChecks-FindingSchema.psm1"
    }

    It 'imports EntraChecks-DataSources.psm1 as a fallback' {
        $script:ScriptText | Should -Match "EntraChecks-DataSources.psm1"
    }
}

Describe 'Scripts/test-syntax.ps1 — exit code reflects reality' {

    BeforeAll {
        $script:HelperScript = Join-Path $script:RepoRoot 'Scripts/test-syntax.ps1'
    }

    It 'exits 0 when every file parses' {
        $pwshExe = (Get-Process -Id $PID).Path
        $proc = Start-Process -FilePath $pwshExe `
            -ArgumentList @('-NoProfile', '-File', $script:HelperScript) `
            -PassThru -Wait -RedirectStandardOutput (Join-Path $TestDrive 'ok.out') -RedirectStandardError (Join-Path $TestDrive 'ok.err')
        $proc.ExitCode | Should -Be 0
    }

    It 'exits non-zero when a script has a syntax error' {
        $brokenPath = Join-Path (Join-Path $script:RepoRoot 'Scripts') '_pester-broken.ps1'
        try {
            'function broken { if ($true {  }' | Set-Content -LiteralPath $brokenPath -Encoding UTF8
            $pwshExe = (Get-Process -Id $PID).Path
            $proc = Start-Process -FilePath $pwshExe `
                -ArgumentList @('-NoProfile', '-File', $script:HelperScript) `
                -PassThru -Wait -RedirectStandardOutput (Join-Path $TestDrive 'bad.out') -RedirectStandardError (Join-Path $TestDrive 'bad.err')
            $proc.ExitCode | Should -Be 1
        }
        finally {
            if (Test-Path $brokenPath) { Remove-Item -LiteralPath $brokenPath -Force }
        }
    }

    It 'covers Scripts/*.ps1, not just repo-root scripts and Modules/*.psm1' {
        # Regression guard for the old bug: only modules were actually
        # checked. The Scripts/ glob must be in the source.
        $helperText = Get-Content -Raw -LiteralPath $script:HelperScript
        $helperText | Should -Match 'Scripts'
        $helperText | Should -Match "Filter '\*\.ps1'"
        $helperText | Should -Match "Filter '\*\.psm1'"
    }
}
