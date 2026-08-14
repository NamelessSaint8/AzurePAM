<#
.SYNOPSIS
    Invoke-CodeQualityCheck.ps1
    Runs PSScriptAnalyzer against the EntraChecks codebase

.DESCRIPTION
    This script performs comprehensive code quality analysis using PSScriptAnalyzer.
    It checks all PowerShell files (.ps1, .psm1, .psd1) for:
    - Best practice violations
    - Potential bugs
    - Code style issues
    - Security concerns
    - Performance issues

    Results are displayed in the console and optionally exported to files.

.PARAMETER Path
    Path to analyze. Defaults to the script's directory.

.PARAMETER Recurse
    Analyze all subdirectories recursively.

.PARAMETER Severity
    Minimum severity level to report. Options: Error, Warning, Information
    Default: Warning (includes both Error and Warning)

.PARAMETER ExportResults
    Export results to JSON and HTML files.

.PARAMETER OutputDirectory
    Directory for exported results. Default: .\CodeQualityReports

.PARAMETER FailOnErrors
    Exit with non-zero code if errors are found. Useful for CI/CD.

.PARAMETER FailOnWarnings
    Exit with non-zero code if warnings are found. Useful for CI/CD.

.PARAMETER ExcludeRules
    Additional rules to exclude from analysis.

.PARAMETER SettingsPath
    Path to PSScriptAnalyzer settings file. Default: PSScriptAnalyzerSettings.psd1

.EXAMPLE
    .\Invoke-CodeQualityCheck.ps1
    # Run analysis with default settings

.EXAMPLE
    .\Invoke-CodeQualityCheck.ps1 -ExportResults -FailOnErrors
    # Run analysis, export results, and fail if errors found (for CI/CD)

.EXAMPLE
    .\Invoke-CodeQualityCheck.ps1 -Severity Information -ExportResults
    # Include informational messages and export results

.NOTES
    Version: 1.0.0
    Author: NamelessSaint
    Requires: PSScriptAnalyzer module
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Path,

    [switch]$Recurse,

    [Parameter()]
    [ValidateSet('Error', 'Warning', 'Information')]
    [string]$Severity = 'Warning',

    [switch]$ExportResults,

    [Parameter()]
    [string]$OutputDirectory = ".\CodeQualityReports",

    [switch]$FailOnErrors,

    [switch]$FailOnWarnings,

    [Parameter()]
    [string[]]$ExcludeRules = @(),

    [Parameter()]
    [string]$SettingsPath
)

# Default to recursive scan
if (-not $PSBoundParameters.ContainsKey('Recurse')) {
    $Recurse = [switch]::new($true)
}

# Set default path to project root (parent of Scripts/)
if (-not $Path) {
    $projectRoot = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { Get-Location }
    $Path = $projectRoot
}

# Set default settings path if not provided
if (-not $SettingsPath) {
    $projectRoot = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { Get-Location }
    $SettingsPath = Join-Path $projectRoot "PSScriptAnalyzerSettings.psd1"
}

#region ==================== INITIALIZATION ====================

$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "              EntraChecks Code Quality Analysis                         " -ForegroundColor Cyan
Write-Host "                 Powered by PSScriptAnalyzer                            " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# Check if PSScriptAnalyzer is installed
Write-Host "[1/6] Checking PSScriptAnalyzer module..." -ForegroundColor Cyan
$psaModule = Get-Module -Name PSScriptAnalyzer -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if (-not $psaModule) {
    Write-Host "  PSScriptAnalyzer not found. Installing..." -ForegroundColor Yellow
    try {
        Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber
        $psaModule = Get-Module -Name PSScriptAnalyzer -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        Write-Host "  [OK] PSScriptAnalyzer $($psaModule.Version) installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install PSScriptAnalyzer: $_"
        exit 1
    }
}
else {
    Write-Host "  [OK] PSScriptAnalyzer $($psaModule.Version) found" -ForegroundColor Green
}

Import-Module PSScriptAnalyzer -ErrorAction Stop

#endregion

#region ==================== CONFIGURATION ====================

Write-Host "[2/6] Loading configuration..." -ForegroundColor Cyan

# Load settings file if it exists
$analyzerSettings = @{}
if (Test-Path $SettingsPath) {
    Write-Host "  [OK] Loading settings from: $SettingsPath" -ForegroundColor Green
    $analyzerSettings['Settings'] = $SettingsPath
}
else {
    Write-Host "  [!] Settings file not found, using default rules" -ForegroundColor Yellow
}

# Configure severity
$severityLevels = switch ($Severity) {
    'Error' { @('Error') }
    'Warning' { @('Error', 'Warning') }
    'Information' { @('Error', 'Warning', 'Information') }
}
$analyzerSettings['Severity'] = $severityLevels

# Add additional excluded rules
if ($ExcludeRules.Count -gt 0) {
    $analyzerSettings['ExcludeRule'] = $ExcludeRules
    Write-Host "  Additional excluded rules: $($ExcludeRules -join ', ')" -ForegroundColor Gray
}

Write-Host "  Analysis severity: $($severityLevels -join ', ')" -ForegroundColor Gray
Write-Host "  Recursive scan: $Recurse" -ForegroundColor Gray

#endregion

#region ==================== FILE DISCOVERY ====================

Write-Host "[3/6] Discovering PowerShell files..." -ForegroundColor Cyan

$filesParams = @{
    Path = $Path
    Include = @('*.ps1', '*.psm1', '*.psd1')
    File = $true
}

if ($Recurse) {
    $filesParams['Recurse'] = $true
}

$files = Get-ChildItem @filesParams | Where-Object {
    # Exclude common directories
    $_.FullName -notmatch '\\(node_modules|\.git|\.vscode|bin|obj)\\' -and
    # Exclude test artifacts
    $_.FullName -notmatch '\\(TestResults|Coverage)\\' -and
    # Exclude package directories
    $_.FullName -notmatch '\\packages\\'
}

Write-Host "  [OK] Found $($files.Count) PowerShell files to analyze" -ForegroundColor Green

if ($files.Count -eq 0) {
    Write-Host "  [!] No PowerShell files found in: $Path" -ForegroundColor Yellow
    exit 0
}

# Display file breakdown
$fileTypes = $files | Group-Object Extension
foreach ($type in $fileTypes) {
    Write-Host "    - $($type.Name): $($type.Count) files" -ForegroundColor Gray
}

#endregion

#region ==================== ANALYSIS ====================

Write-Host "[4/6] Running PSScriptAnalyzer..." -ForegroundColor Cyan

$allResults = @()
$fileResults = @{}
$progressCount = 0

foreach ($file in $files) {
    $progressCount++
    $percentComplete = [math]::Round(($progressCount / $files.Count) * 100)

    Write-Progress -Activity "Analyzing PowerShell files" `
        -Status ("Processing: {0} ({1} of {2})" -f $file.Name, $progressCount, $files.Count) `
        -PercentComplete $percentComplete

    try {
        $results = Invoke-ScriptAnalyzer -Path $file.FullName @analyzerSettings -ErrorAction Stop

        if ($results) {
            $allResults += $results
            $fileResults[$file.FullName] = $results
        }
    }
    catch {
        Write-Host ("    [X] Error analyzing {0}: {1}" -f $file.Name, $_) -ForegroundColor Red
    }
}

Write-Progress -Activity "Analyzing PowerShell files" -Completed

Write-Host "  [OK] Analysis complete" -ForegroundColor Green

#endregion

#region ==================== RESULTS SUMMARY ====================

Write-Host "[5/6] Generating summary..." -ForegroundColor Cyan
Write-Host ""

# Group by severity
$errorCount = ($allResults | Where-Object { $_.Severity -eq 'Error' }).Count
$warningCount = ($allResults | Where-Object { $_.Severity -eq 'Warning' }).Count
$infoCount = ($allResults | Where-Object { $_.Severity -eq 'Information' }).Count

# Display summary
Write-Host "========================================================================" -ForegroundColor Gray
Write-Host "                        ANALYSIS SUMMARY                               " -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Gray
Write-Host ""
Write-Host "  Files Analyzed:        $($files.Count)" -ForegroundColor Cyan
Write-Host "  Files with Issues:     $($fileResults.Count)" -ForegroundColor $(if ($fileResults.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ""
Write-Host "  Errors:                $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Warnings:              $warningCount" -ForegroundColor $(if ($warningCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Informational:         $infoCount" -ForegroundColor $(if ($infoCount -gt 0) { 'Cyan' } else { 'Green' })
Write-Host ""
Write-Host "  Total Issues:          $($allResults.Count)" -ForegroundColor $(if ($allResults.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ""
Write-Host "========================================================================" -ForegroundColor Gray
Write-Host ""

# Display issues by rule
if ($allResults.Count -gt 0) {
    Write-Host "Issues by Rule:" -ForegroundColor Yellow
    Write-Host ""

    $ruleGroups = $allResults | Group-Object RuleName | Sort-Object Count -Descending

    foreach ($ruleGroup in $ruleGroups) {
        $severities = $ruleGroup.Group | Group-Object Severity
        $severityText = ($severities | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ', '

        $color = switch ($ruleGroup.Group[0].Severity) {
            'Error' { 'Red' }
            'Warning' { 'Yellow' }
            'Information' { 'Cyan' }
            default { 'Gray' }
        }

        Write-Host "  [$($ruleGroup.Count.ToString().PadLeft(3))] " -NoNewline -ForegroundColor $color
        Write-Host "$($ruleGroup.Name)" -ForegroundColor White
        Write-Host "        $severityText" -ForegroundColor Gray
    }

    Write-Host ""
}

# Display top offending files
if ($fileResults.Count -gt 0) {
    Write-Host "Files with Most Issues:" -ForegroundColor Yellow
    Write-Host ""

    $topFiles = $fileResults.GetEnumerator() |
        Sort-Object { $_.Value.Count } -Descending |
        Select-Object -First 10

    foreach ($fileEntry in $topFiles) {
        $fileName = Split-Path $fileEntry.Key -Leaf
        $fileErrors = ($fileEntry.Value | Where-Object { $_.Severity -eq 'Error' }).Count
        $fileWarnings = ($fileEntry.Value | Where-Object { $_.Severity -eq 'Warning' }).Count

        Write-Host "  [$($fileEntry.Value.Count.ToString().PadLeft(3))] " -NoNewline -ForegroundColor Yellow
        Write-Host "$fileName" -ForegroundColor White

        if ($fileErrors -gt 0 -or $fileWarnings -gt 0) {
            Write-Host "        Errors: $fileErrors, Warnings: $fileWarnings" -ForegroundColor Gray
        }
    }

    Write-Host ""
}

# Display detailed issues
if ($allResults.Count -gt 0 -and $allResults.Count -le 50) {
    Write-Host "Detailed Issues:" -ForegroundColor Yellow
    Write-Host ""

    foreach ($result in ($allResults | Sort-Object Severity, RuleName, ScriptName, Line)) {
        $color = switch ($result.Severity) {
            'Error' { 'Red' }
            'Warning' { 'Yellow' }
            'Information' { 'Cyan' }
            default { 'Gray' }
        }

        $fileName = Split-Path $result.ScriptName -Leaf
        Write-Host "  [$($result.Severity)] " -NoNewline -ForegroundColor $color
        Write-Host "$fileName" -NoNewline -ForegroundColor White
        Write-Host ":$($result.Line):$($result.Column)" -ForegroundColor Gray
        Write-Host "    Rule: $($result.RuleName)" -ForegroundColor Gray
        Write-Host "    $($result.Message)" -ForegroundColor Gray
        Write-Host ""
    }
}
elseif ($allResults.Count -gt 50) {
    Write-Host "  [!] Too many issues to display ($($allResults.Count) total)" -ForegroundColor Yellow
    Write-Host "    Use -ExportResults to generate detailed reports" -ForegroundColor Gray
    Write-Host ""
}

#endregion

#region ==================== EXPORT RESULTS ====================

if ($ExportResults) {
    Write-Host "[6/6] Exporting results..." -ForegroundColor Cyan

    # Create output directory
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $baseFileName = "CodeQuality_$timestamp"

    # Export to JSON
    $jsonPath = Join-Path $OutputDirectory "$baseFileName.json"
    $exportData = @{
        Timestamp = Get-Date -Format "o"
        Summary = @{
            FilesAnalyzed = $files.Count
            FilesWithIssues = $fileResults.Count
            TotalIssues = $allResults.Count
            Errors = $errorCount
            Warnings = $warningCount
            Informational = $infoCount
        }
        Settings = @{
            Severity = $Severity
            SettingsFile = $SettingsPath
            ExcludeRules = $ExcludeRules
        }
        Results = $allResults
    }
    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "  [OK] JSON report: $jsonPath" -ForegroundColor Green

    # Export to CSV
    $csvPath = Join-Path $OutputDirectory "$baseFileName.csv"
    $allResults | Select-Object Severity, RuleName, ScriptName, Line, Column, Message |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  [OK] CSV report: $csvPath" -ForegroundColor Green

    Write-Host ""
}
else {
    Write-Host "[6/6] Export skipped (use -ExportResults to generate reports)" -ForegroundColor Gray
    Write-Host ""
}

#endregion

#region ==================== EXIT CODE ====================

$duration = (Get-Date) - $script:StartTime
Write-Host "Analysis completed in $($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Cyan
Write-Host ""

# Determine exit code
$exitCode = 0

if ($FailOnErrors -and $errorCount -gt 0) {
    Write-Host "[X] FAILED: $errorCount error(s) found (FailOnErrors enabled)" -ForegroundColor Red
    $exitCode = 1
}
elseif ($FailOnWarnings -and ($errorCount -gt 0 -or $warningCount -gt 0)) {
    Write-Host "[X] FAILED: $errorCount error(s) and $warningCount warning(s) found (FailOnWarnings enabled)" -ForegroundColor Red
    $exitCode = 1
}
elseif ($allResults.Count -eq 0) {
    Write-Host "[OK] SUCCESS: No issues found! Code quality is excellent." -ForegroundColor Green
}
else {
    Write-Host "[OK] Analysis complete. Review issues above." -ForegroundColor Yellow
}

Write-Host ""

exit $exitCode

#endregion
