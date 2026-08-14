<#
.SYNOPSIS
    EntraChecks-DeltaReporting.psm1
    Module for comparing compliance assessments over time

.DESCRIPTION
    This module provides delta/trend reporting capabilities for EntraChecks
    compliance assessments. It enables:

    - Comparison of two assessment snapshots
    - Identification of improvements and regressions
    - New issues and resolved issues tracking
    - Score trend analysis over time
    - Historical compliance tracking
    - Executive summary of changes
    
.NOTES
    Version: 1.0.0
    Author: NamelessSaint
    
.LINK
    Main Script: Invoke-EntraChecks.ps1
#>

#Requires -Version 5.1

# Module version
$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-DeltaReporting"

#region ==================== MODULE INITIALIZATION ====================

<#
.SYNOPSIS
    Initializes the delta reporting module for compliance snapshot comparison.
#>
function Initialize-DeltaReportingModule {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Loading module: $script:ModuleName v$script:ModuleVersion" -ForegroundColor Magenta
    Write-Host "    [OK] Module loaded successfully" -ForegroundColor Green
    
    return @{
        Name = $script:ModuleName
        Version = $script:ModuleVersion
        Type = "Reporting"
    }
}

#endregion

#region ==================== SNAPSHOT MANAGEMENT ====================

<#
.SYNOPSIS
    Saves current assessment data as a snapshot for future comparison.

.DESCRIPTION
    Creates a timestamped snapshot file containing all assessment data
    from the current session. This can be used for delta comparisons.

.PARAMETER OutputDirectory
    Directory to save the snapshot file.

.PARAMETER SnapshotName
    Optional name for the snapshot (default: timestamp-based).

.PARAMETER Findings
    EntraChecks findings array.

.PARAMETER SecureScoreData
    Secure Score data.

.PARAMETER DefenderComplianceData
    Defender for Cloud compliance data.

.PARAMETER AzurePolicyData
    Azure Policy compliance data.

.PARAMETER PurviewComplianceData
    Purview Compliance Manager data.

.OUTPUTS
    Path to the saved snapshot file.
#>
function Save-ComplianceSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputDirectory,
        
        [Parameter()]
        [string]$SnapshotName,
        
        [Parameter()]
        [string]$TenantName = "Unknown",
        
        [Parameter()]
        [array]$Findings,
        
        [Parameter()]
        $SecureScoreData,
        
        [Parameter()]
        $DefenderComplianceData,
        
        [Parameter()]
        $AzurePolicyData,
        
        [Parameter()]
        $PurviewComplianceData
    )
    
    Write-Host "`n[+] Saving compliance snapshot..." -ForegroundColor Cyan
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $snapshotId = if ($SnapshotName) { $SnapshotName } else { $timestamp }
    
    # Build snapshot object
    $snapshot = @{
        SnapshotId = $snapshotId
        TenantName = $TenantName
        CreatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        CreatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Version = $script:ModuleVersion
        
        # Data sources
        Sources = @{
            Findings = @{
                Available = $false
                Count = 0
                Data = $null
            }
            SecureScore = @{
                Available = $false
                Score = $null
                Data = $null
            }
            DefenderCompliance = @{
                Available = $false
                Summary = $null
                Data = $null
            }
            AzurePolicy = @{
                Available = $false
                Summary = $null
                Data = $null
            }
            PurviewCompliance = @{
                Available = $false
                Summary = $null
                Data = $null
            }
        }
        
        # Aggregated scores for quick comparison
        Scores = @{
            SecureScore = $null
            CIS_M365 = $null
            NIST_800_53 = $null
            DefenderOverall = $null
            AzurePolicyOverall = $null
            PurviewOverall = $null
        }
        
        # Summary counts
        Summary = @{
            TotalFindings = 0
            FailCount = 0
            WarningCount = 0
            OKCount = 0
            InfoCount = 0
        }
    }
    
    # Process Findings
    if ($Findings -and $Findings.Count -gt 0) {
        $snapshot.Sources.Findings.Available = $true
        $snapshot.Sources.Findings.Count = $Findings.Count
        # Schema v1.7+ (Phase 3 PR 2): added Type and TSCReferences so SOC 2
        # Type 2 period-coverage analysis can map findings to TSC controls
        # without re-running Add-ComplianceMapping. Additive — older
        # consumers ignore the new fields.
        $snapshot.Sources.Findings.Data = $Findings | ForEach-Object {
            $entry = @{
                CheckName = $_.CheckName
                Status = $_.Status
                Object = $_.Object
                Description = $_.Description
                Category = $_.Category
                Severity = $_.Severity
            }
            if ($null -ne $_.PSObject.Properties['Type'] -and $_.Type) {
                $entry['Type'] = $_.Type
            }
            if ($null -ne $_.PSObject.Properties['TSCReferences'] -and $_.TSCReferences) {
                $entry['TSCReferences'] = @($_.TSCReferences)
            }
            $entry
        }
        
        $snapshot.Summary.TotalFindings = $Findings.Count
        $snapshot.Summary.FailCount = ($Findings | Where-Object { $_.Status -eq "FAIL" }).Count
        $snapshot.Summary.WarningCount = ($Findings | Where-Object { $_.Status -eq "WARNING" }).Count
        $snapshot.Summary.OKCount = ($Findings | Where-Object { $_.Status -eq "OK" }).Count
        $snapshot.Summary.InfoCount = ($Findings | Where-Object { $_.Status -eq "INFO" }).Count
        
        Write-Host "    [OK] Findings: $($Findings.Count)" -ForegroundColor Green
    }
    
    # Process Secure Score
    if ($SecureScoreData) {
        $snapshot.Sources.SecureScore.Available = $true
        $snapshot.Sources.SecureScore.Score = $SecureScoreData.ScorePercent
        $snapshot.Sources.SecureScore.Data = @{
            CurrentScore = $SecureScoreData.CurrentScore
            MaxScore = $SecureScoreData.MaxScore
            ScorePercent = $SecureScoreData.ScorePercent
            ControlScores = $SecureScoreData.ControlScores | ForEach-Object {
                @{
                    ControlName = $_.ControlName
                    Score = $_.Score
                    MaxScore = $_.MaxScore
                    ScorePercent = $_.ScorePercent
                }
            }
        }
        $snapshot.Scores.SecureScore = $SecureScoreData.ScorePercent
        
        Write-Host "    [OK] Secure Score: $($SecureScoreData.ScorePercent)%" -ForegroundColor Green
    }
    
    # Process Defender Compliance
    if ($DefenderComplianceData) {
        $snapshot.Sources.DefenderCompliance.Available = $true
        $snapshot.Sources.DefenderCompliance.Summary = $DefenderComplianceData.Summary
        
        # Store controls in simplified format
        $snapshot.Sources.DefenderCompliance.Data = @{
            Standards = $DefenderComplianceData.Standards.Keys | ForEach-Object {
                $std = $DefenderComplianceData.Standards[$_]
                @{
                    Id = $_
                    Name = $std.Name
                    ShortName = $std.ShortName
                    CompliancePercent = if ($std.Subscriptions.Count -gt 0) {
                        [math]::Round(($std.Subscriptions | Measure-Object -Property CompliancePercent -Average).Average, 1)
                    } else { 0 }
                }
            }
            Controls = $DefenderComplianceData.Controls | ForEach-Object {
                @{
                    ControlId = $_.ControlId
                    Framework = $_.Framework
                    Status = $_.Status
                    SubscriptionName = $_.SubscriptionName
                }
            }
        }
        
        # Calculate overall Defender score
        $totalControls = $DefenderComplianceData.Summary.TotalControls
        $passedControls = $DefenderComplianceData.Summary.PassedControls
        $snapshot.Scores.DefenderOverall = if ($totalControls -gt 0) {
            [math]::Round(($passedControls / $totalControls) * 100, 1)
        } else { $null }
        
        Write-Host "    [OK] Defender Compliance: $($snapshot.Scores.DefenderOverall)%" -ForegroundColor Green
    }
    
    # Process Azure Policy
    if ($AzurePolicyData) {
        $snapshot.Sources.AzurePolicy.Available = $true
        $snapshot.Sources.AzurePolicy.Summary = $AzurePolicyData.Summary
        $snapshot.Sources.AzurePolicy.Data = @{
            Initiatives = $AzurePolicyData.Initiatives
            Policies = $AzurePolicyData.Policies | ForEach-Object {
                @{
                    ControlId = $_.ControlId
                    ControlTitle = $_.ControlTitle
                    Status = $_.Status
                    CompliancePercent = $_.CompliancePercent
                    SubscriptionName = $_.SubscriptionName
                }
            }
        }
        
        $snapshot.Scores.AzurePolicyOverall = if ($AzurePolicyData.Summary.TotalPolicies -gt 0) {
            [math]::Round(($AzurePolicyData.Summary.CompliantPolicies / $AzurePolicyData.Summary.TotalPolicies) * 100, 1)
        } else { $null }
        
        Write-Host "    [OK] Azure Policy: $($snapshot.Scores.AzurePolicyOverall)%" -ForegroundColor Green
    }
    
    # Process Purview Compliance
    if ($PurviewComplianceData) {
        $snapshot.Sources.PurviewCompliance.Available = $true
        $snapshot.Sources.PurviewCompliance.Summary = $PurviewComplianceData.Summary
        $snapshot.Sources.PurviewCompliance.Data = @{
            Assessments = $PurviewComplianceData.ComplianceManager.Assessments | ForEach-Object {
                @{
                    DisplayName = $_.DisplayName
                    Framework = $_.Framework
                    ScorePercent = $_.ScorePercent
                }
            }
            Controls = $PurviewComplianceData.Controls | ForEach-Object {
                @{
                    ControlId = $_.ControlId
                    ControlTitle = $_.ControlTitle
                    Framework = $_.Framework
                    Status = $_.Status
                    CompliancePercent = $_.CompliancePercent
                }
            }
        }
        
        $snapshot.Scores.PurviewOverall = $PurviewComplianceData.Summary.ComplianceScore
        
        Write-Host "    [OK] Purview Compliance: $($snapshot.Scores.PurviewOverall)%" -ForegroundColor Green
    }
    
    # Save snapshot to JSON
    $snapshotPath = Join-Path $OutputDirectory "Snapshot-$snapshotId.json"
    $snapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath $snapshotPath -Encoding UTF8 -Force
    
    Write-Host "`n[+] Snapshot saved: $snapshotPath" -ForegroundColor Magenta
    
    return $snapshotPath
}

<#
.SYNOPSIS
    Loads a previously saved compliance snapshot.

.PARAMETER SnapshotPath
    Path to the snapshot JSON file.

.OUTPUTS
    Snapshot object.
#>
function Import-ComplianceSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SnapshotPath
    )
    
    if (-not (Test-Path $SnapshotPath)) {
        Write-Host "[!] Snapshot file not found: $SnapshotPath" -ForegroundColor Red
        return $null
    }
    
    try {
        $snapshot = Get-Content -Path $SnapshotPath -Raw | ConvertFrom-Json
        Write-Host "[+] Loaded snapshot: $($snapshot.SnapshotId) from $($snapshot.CreatedAt)" -ForegroundColor Green
        return $snapshot
    }
    catch {
        Write-Host "[!] Error loading snapshot: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

<#
.SYNOPSIS
    Lists available snapshots in a directory.

.PARAMETER SnapshotDirectory
    Directory containing snapshot files.

.OUTPUTS
    Array of snapshot metadata.
#>
function Get-ComplianceSnapshots {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SnapshotDirectory
    )
    
    if (-not (Test-Path $SnapshotDirectory)) {
        Write-Host "[!] Directory not found: $SnapshotDirectory" -ForegroundColor Red
        return $null
    }
    
    $snapshots = @()
    $snapshotFiles = Get-ChildItem -Path $SnapshotDirectory -Filter "Snapshot-*.json" | Sort-Object LastWriteTime -Descending
    
    foreach ($file in $snapshotFiles) {
        try {
            $content = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
            $snapshots += [PSCustomObject]@{
                SnapshotId = $content.SnapshotId
                TenantName = $content.TenantName
                CreatedAt = $content.CreatedAt
                FilePath = $file.FullName
                FileSize = "{0:N2} KB" -f ($file.Length / 1KB)
                SecureScore = $content.Scores.SecureScore
                DefenderScore = $content.Scores.DefenderOverall
                PolicyScore = $content.Scores.AzurePolicyOverall
                PurviewScore = $content.Scores.PurviewOverall
                FindingsCount = $content.Summary.TotalFindings
                FailCount = $content.Summary.FailCount
            }
        }
        catch {
            Write-Verbose "Error reading snapshot: $($file.Name)"
        }
    }
    
    return $snapshots
}

#endregion

#region ==================== DELTA COMPARISON ====================

<#
.SYNOPSIS
    Compares two compliance snapshots and generates a delta report.

.DESCRIPTION
    Analyzes differences between two assessment snapshots to identify:
    - Score changes (improvements/regressions)
    - New issues introduced
    - Issues that were resolved
    - Controls that changed status
    - Overall trend direction

.PARAMETER BaselineSnapshot
    The earlier/baseline snapshot for comparison.

.PARAMETER CurrentSnapshot
    The current/newer snapshot to compare against baseline.

.OUTPUTS
    Delta analysis object.
#>
function Compare-ComplianceSnapshots {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $BaselineSnapshot,
        
        [Parameter(Mandatory)]
        $CurrentSnapshot
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host " Compliance Delta Analysis" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Magenta
    
    Write-Host "`n[+] Comparing snapshots..." -ForegroundColor Cyan
    Write-Host "    Baseline: $($BaselineSnapshot.SnapshotId) ($($BaselineSnapshot.CreatedAt))" -ForegroundColor Gray
    Write-Host "    Current:  $($CurrentSnapshot.SnapshotId) ($($CurrentSnapshot.CreatedAt))" -ForegroundColor Gray
    
    $delta = @{
        BaselineSnapshot = $BaselineSnapshot.SnapshotId
        BaselineDate = $BaselineSnapshot.CreatedAt
        CurrentSnapshot = $CurrentSnapshot.SnapshotId
        CurrentDate = $CurrentSnapshot.CreatedAt
        TenantName = $CurrentSnapshot.TenantName
        AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Score changes
        ScoreChanges = @{
            SecureScore = @{ Baseline = $null; Current = $null; Change = $null; Direction = "unchanged" }
            DefenderCompliance = @{ Baseline = $null; Current = $null; Change = $null; Direction = "unchanged" }
            AzurePolicy = @{ Baseline = $null; Current = $null; Change = $null; Direction = "unchanged" }
            PurviewCompliance = @{ Baseline = $null; Current = $null; Change = $null; Direction = "unchanged" }
        }
        
        # Finding changes
        FindingChanges = @{
            NewIssues = @()
            ResolvedIssues = @()
            StatusChanges = @()
            Unchanged = @()
            # REVIEW status (PR 4 of Review-Status-Plan): WARNING<->REVIEW
            # transitions for the same CheckName+Object are recategorisations,
            # not improvements/regressions. Tracked separately to keep the
            # Issues counters meaningful.
            RecategorisedFindings = @()
            NewReviewItems = @()
            ResolvedReviewItems = @()
        }
        
        # Control changes by source
        ControlChanges = @{
            Defender = @{ Improved = @(); Regressed = @(); New = @(); Removed = @() }
            AzurePolicy = @{ Improved = @(); Regressed = @(); New = @(); Removed = @() }
            Purview = @{ Improved = @(); Regressed = @(); New = @(); Removed = @() }
        }
        
        # Summary
        Summary = @{
            OverallTrend = "unchanged"
            ImprovementCount = 0
            RegressionCount = 0
            NewIssueCount = 0
            ResolvedIssueCount = 0
            ScoreImprovements = 0
            ScoreRegressions = 0
            # PR 4 of Review-Status-Plan
            RecategorisedCount = 0
            NewReviewCount = 0
            ResolvedReviewCount = 0
        }
    }
    
    # Compare scores
    Write-Host "`n[+] Analyzing score changes..." -ForegroundColor Cyan
    
    # Secure Score
    if ($null -ne $BaselineSnapshot.Scores.SecureScore -and $null -ne $CurrentSnapshot.Scores.SecureScore) {
        $change = $CurrentSnapshot.Scores.SecureScore - $BaselineSnapshot.Scores.SecureScore
        $delta.ScoreChanges.SecureScore = @{
            Baseline = $BaselineSnapshot.Scores.SecureScore
            Current = $CurrentSnapshot.Scores.SecureScore
            Change = $change
            Direction = if ($change -gt 0) { "improved" } elseif ($change -lt 0) { "regressed" } else { "unchanged" }
        }
        
        $color = if ($change -gt 0) { "Green" } elseif ($change -lt 0) { "Red" } else { "Gray" }
        $symbol = if ($change -gt 0) { "^" } elseif ($change -lt 0) { "v" } else { "->" }
        Write-Host "    Secure Score: $($BaselineSnapshot.Scores.SecureScore)% $symbol $($CurrentSnapshot.Scores.SecureScore)% ($([math]::Round($change, 1)))" -ForegroundColor $color
        
        if ($change -gt 0) { $delta.Summary.ScoreImprovements++ }
        elseif ($change -lt 0) { $delta.Summary.ScoreRegressions++ }
    }
    
    # Defender Compliance
    if ($null -ne $BaselineSnapshot.Scores.DefenderOverall -and $null -ne $CurrentSnapshot.Scores.DefenderOverall) {
        $change = $CurrentSnapshot.Scores.DefenderOverall - $BaselineSnapshot.Scores.DefenderOverall
        $delta.ScoreChanges.DefenderCompliance = @{
            Baseline = $BaselineSnapshot.Scores.DefenderOverall
            Current = $CurrentSnapshot.Scores.DefenderOverall
            Change = $change
            Direction = if ($change -gt 0) { "improved" } elseif ($change -lt 0) { "regressed" } else { "unchanged" }
        }
        
        $color = if ($change -gt 0) { "Green" } elseif ($change -lt 0) { "Red" } else { "Gray" }
        $symbol = if ($change -gt 0) { "^" } elseif ($change -lt 0) { "v" } else { "->" }
        Write-Host "    Defender:     $($BaselineSnapshot.Scores.DefenderOverall)% $symbol $($CurrentSnapshot.Scores.DefenderOverall)% ($([math]::Round($change, 1)))" -ForegroundColor $color
        
        if ($change -gt 0) { $delta.Summary.ScoreImprovements++ }
        elseif ($change -lt 0) { $delta.Summary.ScoreRegressions++ }
    }
    
    # Azure Policy
    if ($null -ne $BaselineSnapshot.Scores.AzurePolicyOverall -and $null -ne $CurrentSnapshot.Scores.AzurePolicyOverall) {
        $change = $CurrentSnapshot.Scores.AzurePolicyOverall - $BaselineSnapshot.Scores.AzurePolicyOverall
        $delta.ScoreChanges.AzurePolicy = @{
            Baseline = $BaselineSnapshot.Scores.AzurePolicyOverall
            Current = $CurrentSnapshot.Scores.AzurePolicyOverall
            Change = $change
            Direction = if ($change -gt 0) { "improved" } elseif ($change -lt 0) { "regressed" } else { "unchanged" }
        }
        
        $color = if ($change -gt 0) { "Green" } elseif ($change -lt 0) { "Red" } else { "Gray" }
        $symbol = if ($change -gt 0) { "^" } elseif ($change -lt 0) { "v" } else { "->" }
        Write-Host "    Azure Policy: $($BaselineSnapshot.Scores.AzurePolicyOverall)% $symbol $($CurrentSnapshot.Scores.AzurePolicyOverall)% ($([math]::Round($change, 1)))" -ForegroundColor $color
        
        if ($change -gt 0) { $delta.Summary.ScoreImprovements++ }
        elseif ($change -lt 0) { $delta.Summary.ScoreRegressions++ }
    }
    
    # Purview Compliance
    if ($null -ne $BaselineSnapshot.Scores.PurviewOverall -and $null -ne $CurrentSnapshot.Scores.PurviewOverall) {
        $change = $CurrentSnapshot.Scores.PurviewOverall - $BaselineSnapshot.Scores.PurviewOverall
        $delta.ScoreChanges.PurviewCompliance = @{
            Baseline = $BaselineSnapshot.Scores.PurviewOverall
            Current = $CurrentSnapshot.Scores.PurviewOverall
            Change = $change
            Direction = if ($change -gt 0) { "improved" } elseif ($change -lt 0) { "regressed" } else { "unchanged" }
        }
        
        $color = if ($change -gt 0) { "Green" } elseif ($change -lt 0) { "Red" } else { "Gray" }
        $symbol = if ($change -gt 0) { "^" } elseif ($change -lt 0) { "v" } else { "->" }
        Write-Host "    Purview:      $($BaselineSnapshot.Scores.PurviewOverall)% $symbol $($CurrentSnapshot.Scores.PurviewOverall)% ($([math]::Round($change, 1)))" -ForegroundColor $color
        
        if ($change -gt 0) { $delta.Summary.ScoreImprovements++ }
        elseif ($change -lt 0) { $delta.Summary.ScoreRegressions++ }
    }
    
    # Compare findings
    Write-Host "`n[+] Analyzing finding changes..." -ForegroundColor Cyan
    
    if ($BaselineSnapshot.Sources.Findings.Data -and $CurrentSnapshot.Sources.Findings.Data) {
        $baselineFindings = @{}
        $currentFindings = @{}

        # PR 2 of Central-Finding-Schema-GRC-Plan: prefer FindingId for
        # snapshot keying when both sides carry it. Falls back to the legacy
        # CheckName|Object key when either side is missing FindingId, so
        # pre-PR2 snapshots still diff correctly. A FindingId of the form
        # ECF-<20 hex chars> is the stable identity across casing/rename
        # changes that CheckName|Object can't survive.
        $useFindingIdKey = $true
        foreach ($finding in $BaselineSnapshot.Sources.Findings.Data) {
            if (-not $finding.FindingId) { $useFindingIdKey = $false; break }
        }
        if ($useFindingIdKey) {
            foreach ($finding in $CurrentSnapshot.Sources.Findings.Data) {
                if (-not $finding.FindingId) { $useFindingIdKey = $false; break }
            }
        }

        # Index by chosen key
        $keyFor = if ($useFindingIdKey) {
            { param($f) [string]$f.FindingId }
        } else {
            { param($f) "$($f.CheckName)|$($f.Object)" }
        }

        foreach ($finding in $BaselineSnapshot.Sources.Findings.Data) {
            $baselineFindings[(& $keyFor $finding)] = $finding
        }
        foreach ($finding in $CurrentSnapshot.Sources.Findings.Data) {
            $currentFindings[(& $keyFor $finding)] = $finding
        }
        
        # Find new issues (in current but not baseline, or status changed to worse)
        foreach ($key in $currentFindings.Keys) {
            $current = $currentFindings[$key]

            if (-not $baselineFindings.ContainsKey($key)) {
                # New finding
                if ($current.Status -in @("FAIL", "WARNING")) {
                    $delta.FindingChanges.NewIssues += [PSCustomObject]@{
                        CheckName = $current.CheckName
                        Object = $current.Object
                        Status = $current.Status
                        Description = $current.Description
                        Type = "New"
                    }
                    $delta.Summary.NewIssueCount++
                }
                elseif ($current.Status -eq 'REVIEW') {
                    # New REVIEW item — tracked separately from issues
                    $delta.FindingChanges.NewReviewItems += [PSCustomObject]@{
                        CheckName = $current.CheckName
                        Object = $current.Object
                        Description = $current.Description
                        Type = "NewReview"
                    }
                    $delta.Summary.NewReviewCount++
                }
            }
            else {
                $baseline = $baselineFindings[$key]

                if ($current.Status -ne $baseline.Status) {
                    # PR 4: WARNING<->REVIEW transitions are recategorisations,
                    # not improvements/regressions. Don't pollute the trend
                    # counters with the global PR 3 reclassification or with
                    # an admin promoting a REVIEW item to a clear violation.
                    $isRecategorisation = (
                        ($baseline.Status -eq 'WARNING' -and $current.Status -eq 'REVIEW') -or
                        ($baseline.Status -eq 'REVIEW' -and $current.Status -eq 'WARNING')
                    )

                    if ($isRecategorisation) {
                        $delta.FindingChanges.RecategorisedFindings += [PSCustomObject]@{
                            CheckName = $current.CheckName
                            Object = $current.Object
                            OldStatus = $baseline.Status
                            NewStatus = $current.Status
                            Description = $current.Description
                            Type = "Recategorised"
                        }
                        $delta.Summary.RecategorisedCount++
                    }
                    else {
                        # Status changed in the severity dimension. REVIEW is
                        # placed between INFO and WARNING in the rank — not a
                        # severity itself but a sortable position so transitions
                        # to/from FAIL/OK still register direction correctly.
                        $statusRank = @{ "OK" = 0; "INFO" = 1; "REVIEW" = 2; "WARNING" = 3; "FAIL" = 4 }
                        $improved = $statusRank[$current.Status] -lt $statusRank[$baseline.Status]

                        $delta.FindingChanges.StatusChanges += [PSCustomObject]@{
                            CheckName = $current.CheckName
                            Object = $current.Object
                            OldStatus = $baseline.Status
                            NewStatus = $current.Status
                            Direction = if ($improved) { "improved" } else { "regressed" }
                        }

                        if ($improved) {
                            $delta.Summary.ImprovementCount++
                        }
                        else {
                            $delta.Summary.RegressionCount++
                        }
                    }
                }
            }
        }

        # Find resolved issues (in baseline but not current, or status improved to OK)
        foreach ($key in $baselineFindings.Keys) {
            $baseline = $baselineFindings[$key]

            if (-not $currentFindings.ContainsKey($key)) {
                if ($baseline.Status -in @("FAIL", "WARNING")) {
                    $delta.FindingChanges.ResolvedIssues += [PSCustomObject]@{
                        CheckName = $baseline.CheckName
                        Object = $baseline.Object
                        PreviousStatus = $baseline.Status
                        Description = $baseline.Description
                        Type = "Resolved"
                    }
                    $delta.Summary.ResolvedIssueCount++
                }
                elseif ($baseline.Status -eq 'REVIEW') {
                    # REVIEW item disappeared — tracked separately
                    $delta.FindingChanges.ResolvedReviewItems += [PSCustomObject]@{
                        CheckName = $baseline.CheckName
                        Object = $baseline.Object
                        Description = $baseline.Description
                        Type = "ResolvedReview"
                    }
                    $delta.Summary.ResolvedReviewCount++
                }
            }
        }
        
        Write-Host "    New issues:      $($delta.Summary.NewIssueCount)" -ForegroundColor $(if ($delta.Summary.NewIssueCount -gt 0) { "Red" } else { "Green" })
        Write-Host "    Resolved issues: $($delta.Summary.ResolvedIssueCount)" -ForegroundColor $(if ($delta.Summary.ResolvedIssueCount -gt 0) { "Green" } else { "Gray" })
        Write-Host "    Improvements:    $($delta.Summary.ImprovementCount)" -ForegroundColor $(if ($delta.Summary.ImprovementCount -gt 0) { "Green" } else { "Gray" })
        Write-Host "    Regressions:     $($delta.Summary.RegressionCount)" -ForegroundColor $(if ($delta.Summary.RegressionCount -gt 0) { "Red" } else { "Gray" })
    }
    
    # Determine overall trend
    $improvementScore = $delta.Summary.ScoreImprovements + $delta.Summary.ImprovementCount + $delta.Summary.ResolvedIssueCount
    $regressionScore = $delta.Summary.ScoreRegressions + $delta.Summary.RegressionCount + $delta.Summary.NewIssueCount
    
    $delta.Summary.OverallTrend = if ($improvementScore -gt $regressionScore) { "improving" }
    elseif ($regressionScore -gt $improvementScore) { "declining" }
    else { "stable" }
    
    Write-Host "`n[+] Overall Trend: " -NoNewline -ForegroundColor Magenta
    $trendColor = switch ($delta.Summary.OverallTrend) {
        "improving" { "Green" }
        "declining" { "Red" }
        default { "Yellow" }
    }
    Write-Host $delta.Summary.OverallTrend.ToUpper() -ForegroundColor $trendColor
    
    return $delta
}

#endregion

#region ==================== DELTA REPORTING ====================

<#
.SYNOPSIS
    Exports a delta comparison report.

.DESCRIPTION
    Generates HTML and CSV reports showing changes between two snapshots.

.PARAMETER DeltaData
    Delta analysis from Compare-ComplianceSnapshots.

.PARAMETER OutputDirectory
    Directory for output files.
#>
function Export-DeltaReport {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $DeltaData,
        
        [Parameter(Mandatory)]
        [string]$OutputDirectory
    )
    
    Write-Host "`n[+] Generating delta report..." -ForegroundColor Cyan
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    
    # Generate HTML Report
    $htmlPath = Join-Path $OutputDirectory "DeltaReport-$timestamp.html"
    
    # Determine trend indicators
    $trendIcon = switch ($DeltaData.Summary.OverallTrend) {
        "improving" { "/\" }
        "declining" { "\/" }
        default { "-->" }
    }
    
    $trendColor = switch ($DeltaData.Summary.OverallTrend) {
        "improving" { "#107c10" }
        "declining" { "#d13438" }
        default { "#ff8c00" }
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Delta Report</title>
    <style>
        :root {
            --primary: #0078d4;
            --success: #107c10;
            --warning: #ff8c00;
            --danger: #d13438;
            --gray-100: #f3f2f1;
            --gray-200: #e1dfdd;
            --gray-600: #605e5c;
            --gray-800: #323130;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', Tahoma, sans-serif;
            line-height: 1.6;
            color: var(--gray-800);
            background: var(--gray-100);
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        header {
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: white;
            padding: 40px;
            margin-bottom: 30px;
            border-radius: 8px;
        }
        
        header h1 { font-size: 2rem; margin-bottom: 10px; }
        
        .comparison-meta {
            display: flex;
            gap: 40px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .snapshot-box {
            background: rgba(255,255,255,0.1);
            padding: 15px 20px;
            border-radius: 6px;
            flex: 1;
            min-width: 200px;
        }
        
        .snapshot-box label { font-size: 0.75rem; text-transform: uppercase; opacity: 0.8; }
        .snapshot-box .date { font-size: 1.1rem; font-weight: 600; margin-top: 5px; }
        
        .trend-hero {
            text-align: center;
            padding: 30px;
            margin: -20px 0 0 0;
        }
        
        .trend-icon { font-size: 4rem; }
        .trend-label { 
            font-size: 1.5rem; 
            font-weight: 700; 
            text-transform: uppercase;
            color: $trendColor;
            margin-top: 10px;
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .stat-value { font-size: 2rem; font-weight: 700; }
        .stat-label { color: var(--gray-600); font-size: 0.85rem; }
        
        .stat-value.up { color: var(--success); }
        .stat-value.down { color: var(--danger); }
        .stat-value.neutral { color: var(--warning); }
        
        .section-title {
            font-size: 1.3rem;
            margin: 30px 0 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--primary);
        }
        
        .card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .card-header {
            background: var(--gray-100);
            padding: 15px 20px;
            border-bottom: 1px solid var(--gray-200);
            font-weight: 600;
        }
        
        .card-body { padding: 20px; }
        
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--gray-200); }
        th { background: var(--gray-100); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }
        tr:hover { background: var(--gray-100); }
        
        .score-change {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 15px 20px;
            background: white;
            border-radius: 8px;
            margin-bottom: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .score-change .name { flex: 1; font-weight: 600; }
        .score-change .values { display: flex; align-items: center; gap: 10px; }
        .score-change .arrow { font-size: 1.5rem; }
        .score-change .arrow.up { color: var(--success); }
        .score-change .arrow.down { color: var(--danger); }
        .score-change .change { 
            padding: 4px 10px; 
            border-radius: 12px; 
            font-weight: 600;
            font-size: 0.85rem;
        }
        .score-change .change.positive { background: #dff6dd; color: var(--success); }
        .score-change .change.negative { background: #fde7e9; color: var(--danger); }
        .score-change .change.neutral { background: var(--gray-200); color: var(--gray-600); }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .badge-success { background: #dff6dd; color: var(--success); }
        .badge-warning { background: #fff4ce; color: var(--warning); }
        .badge-danger { background: #fde7e9; color: var(--danger); }
        .badge-info { background: #e8f4fd; color: var(--primary); }
        
        .issue-item {
            padding: 15px 20px;
            margin-bottom: 10px;
            border-radius: 8px;
            background: white;
        }
        
        .issue-item.new { border-left: 4px solid var(--danger); }
        .issue-item.resolved { border-left: 4px solid var(--success); }
        .issue-item.improved { border-left: 4px solid var(--success); }
        .issue-item.regressed { border-left: 4px solid var(--danger); }
        
        .issue-header { display: flex; justify-content: space-between; margin-bottom: 5px; }
        .issue-title { font-weight: 600; }
        .issue-meta { font-size: 0.85rem; color: var(--gray-600); }
        
        footer {
            text-align: center;
            padding: 30px;
            color: var(--gray-600);
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Compliance Delta Report</h1>
            <p>Changes between assessments for $($DeltaData.TenantName)</p>
            <div class="comparison-meta">
                <div class="snapshot-box">
                    <label>Baseline</label>
                    <div class="date">$($DeltaData.BaselineDate)</div>
                    <small>$($DeltaData.BaselineSnapshot)</small>
                </div>
                <div class="trend-hero">
                    <div class="trend-icon">$trendIcon</div>
                    <div class="trend-label">$($DeltaData.Summary.OverallTrend)</div>
                </div>
                <div class="snapshot-box">
                    <label>Current</label>
                    <div class="date">$($DeltaData.CurrentDate)</div>
                    <small>$($DeltaData.CurrentSnapshot)</small>
                </div>
            </div>
        </header>

        <!-- Summary Stats -->
        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-value up">$($DeltaData.Summary.ResolvedIssueCount)</div>
                <div class="stat-label">Issues Resolved</div>
            </div>
            <div class="stat-card">
                <div class="stat-value down">$($DeltaData.Summary.NewIssueCount)</div>
                <div class="stat-label">New Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value up">$($DeltaData.Summary.ImprovementCount)</div>
                <div class="stat-label">Improvements</div>
            </div>
            <div class="stat-card">
                <div class="stat-value down">$($DeltaData.Summary.RegressionCount)</div>
                <div class="stat-label">Regressions</div>
            </div>
        </div>

        <!-- Score Changes -->
        <h2 class="section-title">Score Changes</h2>
"@

    # Add score changes
    foreach ($scoreKey in @("SecureScore", "DefenderCompliance", "AzurePolicy", "PurviewCompliance")) {
        $score = $DeltaData.ScoreChanges[$scoreKey]
        if ($null -ne $score.Baseline -and $null -ne $score.Current) {
            $arrowClass = switch ($score.Direction) {
                "improved" { "up" }
                "regressed" { "down" }
                default { "" }
            }
            $arrow = switch ($score.Direction) {
                "improved" { "^" }
                "regressed" { "v" }
                default { "->" }
            }
            $changeClass = switch ($score.Direction) {
                "improved" { "positive" }
                "regressed" { "negative" }
                default { "neutral" }
            }
            $changeText = if ($score.Change -gt 0) { "+$([math]::Round($score.Change, 1))%" } 
            elseif ($score.Change -lt 0) { "$([math]::Round($score.Change, 1))%" }
            else { "0%" }
            
            $displayName = switch ($scoreKey) {
                "SecureScore" { "Microsoft Secure Score" }
                "DefenderCompliance" { "Defender for Cloud" }
                "AzurePolicy" { "Azure Policy" }
                "PurviewCompliance" { "Purview Compliance" }
            }
            
            $html += @"
        <div class="score-change">
            <span class="name">$displayName</span>
            <div class="values">
                <span>$($score.Baseline)%</span>
                <span class="arrow $arrowClass">$arrow</span>
                <span>$($score.Current)%</span>
                <span class="change $changeClass">$changeText</span>
            </div>
        </div>
"@
        }
    }

    # New Issues
    if ($DeltaData.FindingChanges.NewIssues.Count -gt 0) {
        $html += @"
        
        <h2 class="section-title">New Issues ($($DeltaData.FindingChanges.NewIssues.Count))</h2>
"@
        foreach ($issue in $DeltaData.FindingChanges.NewIssues) {
            $html += @"
        <div class="issue-item new">
            <div class="issue-header">
                <span class="issue-title">$($issue.Object)</span>
                <span class="badge badge-danger">$($issue.Status)</span>
            </div>
            <div class="issue-meta">$($issue.CheckName)</div>
        </div>
"@
        }
    }

    # Resolved Issues
    if ($DeltaData.FindingChanges.ResolvedIssues.Count -gt 0) {
        $html += @"
        
        <h2 class="section-title">Resolved Issues ($($DeltaData.FindingChanges.ResolvedIssues.Count))</h2>
"@
        foreach ($issue in $DeltaData.FindingChanges.ResolvedIssues) {
            $html += @"
        <div class="issue-item resolved">
            <div class="issue-header">
                <span class="issue-title">$($issue.Object)</span>
                <span class="badge badge-success">Resolved</span>
            </div>
            <div class="issue-meta">$($issue.CheckName) - Previously: $($issue.PreviousStatus)</div>
        </div>
"@
        }
    }

    # Status Changes
    if ($DeltaData.FindingChanges.StatusChanges.Count -gt 0) {
        $html += @"
        
        <h2 class="section-title">Status Changes ($($DeltaData.FindingChanges.StatusChanges.Count))</h2>
        <div class="card">
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Check</th>
                            <th>Object</th>
                            <th>Previous</th>
                            <th>Current</th>
                            <th>Direction</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($change in $DeltaData.FindingChanges.StatusChanges) {
            $dirBadge = if ($change.Direction -eq "improved") { 
                '<span class="badge badge-success">Improved</span>' 
            } else { 
                '<span class="badge badge-danger">Regressed</span>' 
            }
            
            $html += @"
                        <tr>
                            <td>$($change.CheckName)</td>
                            <td>$($change.Object)</td>
                            <td><span class="badge badge-warning">$($change.OldStatus)</span></td>
                            <td><span class="badge badge-info">$($change.NewStatus)</span></td>
                            <td>$dirBadge</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
"@
    }

    # Footer
    $html += @"
        
        <footer>
            <p>Generated by EntraChecks Delta Reporting Module v$script:ModuleVersion</p>
            <p>Analysis Date: $($DeltaData.AnalysisDate)</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Host "    [OK] HTML report: $htmlPath" -ForegroundColor Green
    
    # Export CSV - Summary
    $csvSummaryPath = Join-Path $OutputDirectory "DeltaReport-Summary-$timestamp.csv"
    @([PSCustomObject]@{
            BaselineSnapshot = $DeltaData.BaselineSnapshot
            BaselineDate = $DeltaData.BaselineDate
            CurrentSnapshot = $DeltaData.CurrentSnapshot
            CurrentDate = $DeltaData.CurrentDate
            OverallTrend = $DeltaData.Summary.OverallTrend
            NewIssues = $DeltaData.Summary.NewIssueCount
            ResolvedIssues = $DeltaData.Summary.ResolvedIssueCount
            Improvements = $DeltaData.Summary.ImprovementCount
            Regressions = $DeltaData.Summary.RegressionCount
            SecureScore_Baseline = $DeltaData.ScoreChanges.SecureScore.Baseline
            SecureScore_Current = $DeltaData.ScoreChanges.SecureScore.Current
            SecureScore_Change = $DeltaData.ScoreChanges.SecureScore.Change
            Defender_Baseline = $DeltaData.ScoreChanges.DefenderCompliance.Baseline
            Defender_Current = $DeltaData.ScoreChanges.DefenderCompliance.Current
            Defender_Change = $DeltaData.ScoreChanges.DefenderCompliance.Change
            AzurePolicy_Baseline = $DeltaData.ScoreChanges.AzurePolicy.Baseline
            AzurePolicy_Current = $DeltaData.ScoreChanges.AzurePolicy.Current
            AzurePolicy_Change = $DeltaData.ScoreChanges.AzurePolicy.Change
            Purview_Baseline = $DeltaData.ScoreChanges.PurviewCompliance.Baseline
            Purview_Current = $DeltaData.ScoreChanges.PurviewCompliance.Current
            Purview_Change = $DeltaData.ScoreChanges.PurviewCompliance.Change
        }) | Export-Csv -Path $csvSummaryPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] Summary CSV: $csvSummaryPath" -ForegroundColor Green
    
    # Export CSV - All Changes
    $csvChangesPath = Join-Path $OutputDirectory "DeltaReport-Changes-$timestamp.csv"
    $allChanges = @()
    
    foreach ($issue in $DeltaData.FindingChanges.NewIssues) {
        $allChanges += [PSCustomObject]@{
            Type = "New Issue"
            CheckName = $issue.CheckName
            Object = $issue.Object
            OldStatus = ""
            NewStatus = $issue.Status
            Direction = "New"
        }
    }
    
    foreach ($issue in $DeltaData.FindingChanges.ResolvedIssues) {
        $allChanges += [PSCustomObject]@{
            Type = "Resolved"
            CheckName = $issue.CheckName
            Object = $issue.Object
            OldStatus = $issue.PreviousStatus
            NewStatus = "Resolved"
            Direction = "Improved"
        }
    }
    
    foreach ($change in $DeltaData.FindingChanges.StatusChanges) {
        $allChanges += [PSCustomObject]@{
            Type = "Status Change"
            CheckName = $change.CheckName
            Object = $change.Object
            OldStatus = $change.OldStatus
            NewStatus = $change.NewStatus
            Direction = $change.Direction
        }
    }
    
    if ($allChanges.Count -gt 0) {
        $allChanges | Export-Csv -Path $csvChangesPath -NoTypeInformation -Encoding UTF8
        Write-Host "    [OK] Changes CSV: $csvChangesPath" -ForegroundColor Green
    }
    
    return @{
        HTMLReport = $htmlPath
        SummaryCSV = $csvSummaryPath
        ChangesCSV = $csvChangesPath
        OutputDirectory = $OutputDirectory
    }
}

#endregion

#region ==================== TREND ANALYSIS ====================

<#
.SYNOPSIS
    Analyzes compliance trends across multiple snapshots.

.DESCRIPTION
    Loads multiple snapshots and generates trend analysis showing
    compliance scores over time.

.PARAMETER SnapshotDirectory
    Directory containing snapshot files.

.PARAMETER MaxSnapshots
    Maximum number of snapshots to analyze (default: 10).

.OUTPUTS
    Trend analysis object.
#>
function Get-ComplianceTrend {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SnapshotDirectory,
        
        [Parameter()]
        [int]$MaxSnapshots = 10
    )
    
    Write-Host "`n[+] Analyzing compliance trends..." -ForegroundColor Cyan
    
    $snapshots = Get-ComplianceSnapshots -SnapshotDirectory $SnapshotDirectory | 
        Select-Object -First $MaxSnapshots |
        Sort-Object CreatedAt
    
    if ($snapshots.Count -lt 2) {
        Write-Host "    [!] Need at least 2 snapshots for trend analysis" -ForegroundColor Yellow
        return $null
    }
    
    Write-Host "    [OK] Analyzing $($snapshots.Count) snapshots" -ForegroundColor Green
    
    $trend = @{
        SnapshotCount = $snapshots.Count
        DateRange = @{
            Start = $snapshots[0].CreatedAt
            End = $snapshots[-1].CreatedAt
        }
        DataPoints = @()
        Trends = @{
            SecureScore = @{ Direction = "stable"; Change = 0 }
            DefenderCompliance = @{ Direction = "stable"; Change = 0 }
            AzurePolicy = @{ Direction = "stable"; Change = 0 }
            PurviewCompliance = @{ Direction = "stable"; Change = 0 }
            FailCount = @{ Direction = "stable"; Change = 0 }
        }
    }
    
    foreach ($snapshot in $snapshots) {
        $trend.DataPoints += [PSCustomObject]@{
            Date = $snapshot.CreatedAt
            SnapshotId = $snapshot.SnapshotId
            SecureScore = $snapshot.SecureScore
            DefenderScore = $snapshot.DefenderScore
            PolicyScore = $snapshot.PolicyScore
            PurviewScore = $snapshot.PurviewScore
            FailCount = $snapshot.FailCount
        }
    }
    
    # Calculate trends
    $first = $trend.DataPoints[0]
    $last = $trend.DataPoints[-1]
    
    if ($first.SecureScore -and $last.SecureScore) {
        $change = $last.SecureScore - $first.SecureScore
        $trend.Trends.SecureScore.Change = $change
        $trend.Trends.SecureScore.Direction = if ($change -gt 1) { "improving" } elseif ($change -lt -1) { "declining" } else { "stable" }
    }
    
    if ($first.DefenderScore -and $last.DefenderScore) {
        $change = $last.DefenderScore - $first.DefenderScore
        $trend.Trends.DefenderCompliance.Change = $change
        $trend.Trends.DefenderCompliance.Direction = if ($change -gt 1) { "improving" } elseif ($change -lt -1) { "declining" } else { "stable" }
    }
    
    if ($first.PolicyScore -and $last.PolicyScore) {
        $change = $last.PolicyScore - $first.PolicyScore
        $trend.Trends.AzurePolicy.Change = $change
        $trend.Trends.AzurePolicy.Direction = if ($change -gt 1) { "improving" } elseif ($change -lt -1) { "declining" } else { "stable" }
    }
    
    if ($null -ne $first.FailCount -and $null -ne $last.FailCount) {
        $change = $last.FailCount - $first.FailCount
        $trend.Trends.FailCount.Change = $change
        $trend.Trends.FailCount.Direction = if ($change -lt 0) { "improving" } elseif ($change -gt 0) { "declining" } else { "stable" }
    }
    
    return $trend
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Initialize-DeltaReportingModule',
    'Save-ComplianceSnapshot',
    'Import-ComplianceSnapshot',
    'Get-ComplianceSnapshots',
    'Compare-ComplianceSnapshots',
    'Export-DeltaReport',
    'Get-ComplianceTrend'
)

#endregion

# Auto-initialize when module is imported
$null = Initialize-DeltaReportingModule
