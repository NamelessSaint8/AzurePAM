<#
.SYNOPSIS
    Cross-platform Pester runner for the EntraChecks test suite.

.DESCRIPTION
    Wraps Invoke-Pester with sensible defaults for this repo:
      * On Windows: run everything (including the WindowsOnly AD/ACL tests
        that depend on Active Directory and System.Security.AccessControl).
      * On Linux/macOS: exclude the WindowsOnly tag (those tests cannot run)
        and the KnownAssertionDrift tag (pre-existing test/code drift that's
        being tracked separately; would mask real regressions in CI).
      * Tags can be overridden via parameters so a developer can run the
        skipped tests when they're working on those specific files.

    Quick examples:

        # Default run for the current platform
        pwsh Tests/Invoke-Tests.ps1

        # Run a subset on macOS, including known-drift tests
        pwsh Tests/Invoke-Tests.ps1 -Path Tests/SOC2-Phase2.Tests.ps1 -RunDriftTests

        # Run a specific Describe by name
        pwsh Tests/Invoke-Tests.ps1 -FullNameFilter '*BreakGlass*'

    Exit code is the Pester FailedCount so the script is CI-safe.

.PARAMETER Path
    Specific test file or directory. Defaults to ./Tests.

.PARAMETER FullNameFilter
    Wildcard filter on test full name (Describe.Context.It).

.PARAMETER IncludeTag
    Additional tags to require. Empty = include everything.

.PARAMETER ExcludeTag
    Override the default exclusion list entirely. Use with care.

.PARAMETER RunDriftTests
    Also run the KnownAssertionDrift tests (they will likely fail).

.PARAMETER Output
    Pester output verbosity (None | Minimal | Normal | Detailed).
#>

[CmdletBinding()]
param(
    [string[]]$Path = @('./Tests'),
    [string[]]$FullNameFilter,
    [string[]]$IncludeTag,
    [string[]]$ExcludeTag,
    [switch]$RunDriftTests,
    [ValidateSet('None', 'Minimal', 'Normal', 'Detailed', 'Diagnostic')]
    [string]$Output = 'Normal'
)

# Several tests use $env:TEMP for one-off output paths. That env var only
# exists on Windows; on Linux/macOS the convention is TMPDIR. Set TEMP to
# TMPDIR (or /tmp as a last resort) so those tests can write somewhere
# valid. TODO: migrate the tests to $TestDrive — Pester's built-in
# isolated path — and remove this shim.
if (-not $env:TEMP) {
    $env:TEMP = if ($env:TMPDIR) { $env:TMPDIR.TrimEnd('/') } else { '/tmp' }
}

# Build the exclusion list unless the caller passed an explicit override.
if (-not $PSBoundParameters.ContainsKey('ExcludeTag')) {
    $exclusions = [System.Collections.Generic.List[string]]::new()
    # Pester runs cross-platform but most CI hosts other than Windows can't
    # load the ActiveDirectory module and can't instantiate
    # System.Security.AccessControl ACL objects (those are Windows-only).
    # Tests under those Describes are tagged 'WindowsOnly'.
    $isOnWindows = $IsWindows -or ($PSVersionTable.PSVersion.Major -lt 6)
    if (-not $isOnWindows) {
        $exclusions.Add('WindowsOnly') | Out-Null
    }
    if (-not $RunDriftTests) {
        $exclusions.Add('KnownAssertionDrift') | Out-Null
    }
    $ExcludeTag = $exclusions.ToArray()
}

$cfg = New-PesterConfiguration
$cfg.Run.Path = $Path
$cfg.Run.PassThru = $true
$cfg.Run.Exit = $false
$cfg.Output.Verbosity = $Output

if ($IncludeTag) { $cfg.Filter.Tag = $IncludeTag }
if ($ExcludeTag) { $cfg.Filter.ExcludeTag = $ExcludeTag }
if ($FullNameFilter) { $cfg.Filter.FullName = $FullNameFilter }

Write-Host ''
Write-Host "Platform: $($PSVersionTable.OS)" -ForegroundColor Cyan
Write-Host "PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
if ($ExcludeTag) {
    Write-Host "Excluded tags: $($ExcludeTag -join ', ')" -ForegroundColor Yellow
}
Write-Host ''

$result = Invoke-Pester -Configuration $cfg

Write-Host ''
Write-Host "Passed:  $($result.PassedCount)"  -ForegroundColor Green
Write-Host "Failed:  $($result.FailedCount)"  -ForegroundColor $(if ($result.FailedCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "Skipped: $($result.SkippedCount)" -ForegroundColor DarkGray
Write-Host "Total:   $($result.TotalCount)"   -ForegroundColor Cyan

exit $result.FailedCount
