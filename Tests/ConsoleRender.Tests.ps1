<#
.SYNOPSIS
    Pester 5 tests for Show-EcfRunStream — the Phase 2 console renderer
    (plans/Native-App-Phase2-TUI-Replatform-Plan.md §4, §8 item 3).

.DESCRIPTION
    Feeds each v1.0 runner event type to Show-EcfRunStream and asserts
    the exact console string + ForegroundColor it produces (Write-Host
    mocked in the module scope). Plus: forward-compat (unknown type is
    ignored), run.result duration math, and pipeline consumption (the
    shape the menu's -EventSink uses).

    Run: Invoke-Pester -Path Tests/ConsoleRender.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ConsoleRender.psm1') -Force

    function script:Evt { param([hashtable]$H) [pscustomobject]$H }
}

Describe 'Show-EcfRunStream — §4 event → console mapping' {

    BeforeEach { Mock -ModuleName EntraChecks-ConsoleRender Write-Host {} }

    It 'run.started → magenta starting header' {
        Show-EcfRunStream -Event (Evt @{ type = 'run.started' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '[+] Starting assessment' -and $ForegroundColor -eq 'Magenta'
        } -Times 1
    }

    It 'phase.started → cyan [+] <Phase>' {
        Show-EcfRunStream -Event (Evt @{ type = 'phase.started'; phase = 'Modules' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '[+] Modules' -and $ForegroundColor -eq 'Cyan'
        } -Times 1
    }

    It 'phase.progress → gray counter line' {
        Show-EcfRunStream -Event (Evt @{ type = 'phase.progress'; phase = 'Core'; current = 12; total = 25; message = 'Conditional Access' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '   -> [12/25] Conditional Access' -and $ForegroundColor -eq 'Gray'
        } -Times 1
    }

    It 'phase.progress with no total omits the counter' {
        Show-EcfRunStream -Event (Evt @{ type = 'phase.progress'; phase = 'Core'; message = 'starting' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '   -> starting' -and $ForegroundColor -eq 'Gray'
        } -Times 1
    }

    It 'log info → gray [i]' {
        Show-EcfRunStream -Event (Evt @{ type = 'log'; level = 'info'; message = 'hello' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '    [i] hello' -and $ForegroundColor -eq 'Gray'
        } -Times 1
    }

    It 'log warn → yellow [!]' {
        Show-EcfRunStream -Event (Evt @{ type = 'log'; level = 'warn'; message = 'careful' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '    [!] careful' -and $ForegroundColor -eq 'Yellow'
        } -Times 1
    }

    It 'log error → red [!]' {
        Show-EcfRunStream -Event (Evt @{ type = 'log'; level = 'error'; message = 'boom' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '    [!] boom' -and $ForegroundColor -eq 'Red'
        } -Times 1
    }

    It 'warning → yellow [!]' {
        Show-EcfRunStream -Event (Evt @{ type = 'warning'; code = 'W1'; message = 'a warning' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '    [!] a warning' -and $ForegroundColor -eq 'Yellow'
        } -Times 1
    }

    It 'phase.completed ok → green [OK]' {
        Show-EcfRunStream -Event (Evt @{ type = 'phase.completed'; phase = 'Report'; status = 'ok' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '    [OK] Report' -and $ForegroundColor -eq 'Green'
        } -Times 1
    }

    It 'phase.completed skipped → dark-gray [skip]' {
        Show-EcfRunStream -Event (Evt @{ type = 'phase.completed'; phase = 'Snapshot'; status = 'skipped' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '    [skip] Snapshot' -and $ForegroundColor -eq 'DarkGray'
        } -Times 1
    }

    It 'phase.completed failed → red [!]' {
        Show-EcfRunStream -Event (Evt @{ type = 'phase.completed'; phase = 'Modules'; status = 'failed' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '    [!] Modules failed' -and $ForegroundColor -eq 'Red'
        } -Times 1
    }

    It 'run.result Succeeded → green completion block with duration + artifacts' {
        $evt = Evt @{
            type = 'run.result'; status = 'Succeeded'
            startedUtc = '2026-05-18T10:00:00Z'; endedUtc = '2026-05-18T10:02:30Z'
            artifacts = @([pscustomobject]@{ kind = 'cockpit-html'; path = '/tmp/r/c.html' })
            errors = @()
        }
        Show-EcfRunStream -Event $evt
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '[+] Assessment Complete - Succeeded' -and $ForegroundColor -eq 'Green'
        } -Times 1
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '    Duration: 2.5 minutes' -and $ForegroundColor -eq 'Cyan'
        } -Times 1
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '    Report (cockpit-html): /tmp/r/c.html' -and $ForegroundColor -eq 'Cyan'
        } -Times 1
    }

    It 'run.result Failed → red header + error lines' {
        $evt = Evt @{
            type = 'run.result'; status = 'Failed'
            startedUtc = '2026-05-18T10:00:00Z'; endedUtc = '2026-05-18T10:00:10Z'
            artifacts = @(); errors = @([pscustomobject]@{ code = 'E1'; message = 'fatal thing' })
        }
        Show-EcfRunStream -Event $evt
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '[+] Assessment Complete - Failed' -and $ForegroundColor -eq 'Red'
        } -Times 1
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '    [!] E1: fatal thing' -and $ForegroundColor -eq 'Red'
        } -Times 1
    }
}

Describe 'Show-EcfRunStream — robustness' {

    It 'an unknown/future event type is ignored (forward-compat)' {
        Mock -ModuleName EntraChecks-ConsoleRender Write-Host {}
        Show-EcfRunStream -Event (Evt @{ type = 'something.new.in.v1.9'; foo = 'bar' })
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -Times 0
    }

    It 'consumes a piped stream the way the -EventSink will' {
        Mock -ModuleName EntraChecks-ConsoleRender Write-Host {}
        @(
            (Evt @{ type = 'run.started' })
            (Evt @{ type = 'phase.started'; phase = 'Core' })
            (Evt @{ type = 'phase.completed'; phase = 'Core'; status = 'ok' })
            (Evt @{ type = 'run.result'; status = 'Succeeded'; startedUtc = '2026-05-18T10:00:00Z'; endedUtc = '2026-05-18T10:01:00Z'; artifacts = @(); errors = @() })
        ) | Show-EcfRunStream
        Should -Invoke -ModuleName EntraChecks-ConsoleRender Write-Host -ParameterFilter {
            $Object -eq '[+] Assessment Complete - Succeeded'
        } -Times 1
    }

    It 'null event is a no-op' {
        Mock -ModuleName EntraChecks-ConsoleRender Write-Host {}
        { Show-EcfRunStream -Event $null } | Should -Not -Throw
    }
}
