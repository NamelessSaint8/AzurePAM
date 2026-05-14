<#
.SYNOPSIS
    Parse-only syntax sweep for every top-level script and module in the repo.

.DESCRIPTION
    Quick local sanity check before pushing. Walks the repo and parses each
    .ps1 / .psm1 file with the language tokenizer; any tokenizer error fails
    the script (exit 1) so it can be wired into a pre-commit hook or CI
    without lying about success.

    Previous implementation bug: the file list was built with
        $files = @(
            Join-Path $root "A.ps1",
            Join-Path $root "B.ps1"
        )
    which made the comma part of Join-Path's -AdditionalChildPath argument
    instead of an array element separator. Join-Path threw, the script
    silently caught nothing, the file loop iterated zero times, and the
    bottom of the script (module loop) ran clean — giving exit 0 even
    though scripts were never checked. Each Join-Path is now wrapped in
    parentheses, the catch records a failure, and Get-ChildItem replaces
    the hand-curated list so new scripts are picked up automatically.
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path $PSScriptRoot -Parent

# Wrap every Join-Path in parens so the comma is array-separator, not
# AdditionalChildPath. Globs cover both repo-root scripts and Scripts/.
$rootScripts = @(
    (Join-Path $projectRoot 'Install-Prerequisites.ps1'),
    (Join-Path $projectRoot 'Start-EntraChecks.ps1'),
    (Join-Path $projectRoot 'Grant-AdminConsent.ps1')
) | Where-Object { Test-Path $_ }

$scriptsDirScripts = @()
$scriptsDir = Join-Path $projectRoot 'Scripts'
if (Test-Path $scriptsDir) {
    $scriptsDirScripts = Get-ChildItem -Path $scriptsDir -Filter '*.ps1' -File |
        Where-Object { $_.Name -ne (Split-Path -Leaf $PSCommandPath) } |
        ForEach-Object { $_.FullName }
}

$moduleFiles = @()
$modulesDir = Join-Path $projectRoot 'Modules'
if (Test-Path $modulesDir) {
    $moduleFiles = Get-ChildItem -Path $modulesDir -Filter '*.psm1' -File |
        ForEach-Object { $_.FullName }
}

$failures = New-Object System.Collections.Generic.List[string]

function Invoke-SyntaxCheck {
    param(
        [Parameter(Mandatory)][string]$Path,
        # AllowEmptyCollection: PowerShell's default Mandatory check rejects
        # an empty List<T>, but we expect callers to pass a fresh empty list.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Failures
    )
    $label = $Path -replace [regex]::Escape($projectRoot + [IO.Path]::DirectorySeparatorChar), ''
    Write-Host "Checking: $label" -ForegroundColor Yellow
    try {
        $tokenErrors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize(
            (Get-Content -Raw -LiteralPath $Path),
            [ref]$tokenErrors)
        if ($tokenErrors -and $tokenErrors.Count -gt 0) {
            Write-Host "  ERRORS FOUND:" -ForegroundColor Red
            foreach ($err in $tokenErrors) {
                $line = if ($err.Token) { $err.Token.StartLine } else { '?' }
                Write-Host "    Line ${line}: $($err.Message)" -ForegroundColor Red
                $Failures.Add("${label}:${line}: $($err.Message)") | Out-Null
            }
        }
        else {
            Write-Host "  OK - No syntax errors" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
        $Failures.Add("${label}: $($_.Exception.Message)") | Out-Null
    }
}

Write-Host "`n=== Testing repo-root scripts ===" -ForegroundColor Cyan
foreach ($f in $rootScripts) { Invoke-SyntaxCheck -Path $f -Failures $failures }

Write-Host "`n=== Testing Scripts/*.ps1 ===" -ForegroundColor Cyan
foreach ($f in $scriptsDirScripts) { Invoke-SyntaxCheck -Path $f -Failures $failures }

Write-Host "`n=== Testing Modules/*.psm1 ===" -ForegroundColor Cyan
foreach ($f in $moduleFiles) { Invoke-SyntaxCheck -Path $f -Failures $failures }

$totalChecked = $rootScripts.Count + $scriptsDirScripts.Count + $moduleFiles.Count
Write-Host "`n=== Validation Complete ===" -ForegroundColor Cyan
Write-Host "Files checked: $totalChecked"
Write-Host "Failures: $($failures.Count)" -ForegroundColor $(if ($failures.Count -eq 0) { 'Green' } else { 'Red' })

if ($failures.Count -gt 0) {
    Write-Host "`nFailures:" -ForegroundColor Red
    foreach ($entry in $failures) { Write-Host "  - $entry" -ForegroundColor Red }
    exit 1
}
exit 0
