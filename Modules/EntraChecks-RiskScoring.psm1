# EntraChecks Risk Scoring and Prioritization Module
# Calculates risk scores and prioritizes findings for remediation

<#
.SYNOPSIS
    Provides risk scoring and prioritization for EntraChecks findings.

.DESCRIPTION
    This module calculates risk scores based on multiple factors:
    - Security impact (confidentiality, integrity, availability)
    - Exploitability (ease of attack, attack surface)
    - Business impact (scope, user count, data sensitivity)
    - Compliance requirements (regulatory mandates)
    - Remediation effort (time, complexity, risk)

.NOTES
    Author: NamelessSaint
    Version: 1.0.0
#>

#region Risk Scoring Configuration

# Base risk scores by finding type (0-100 scale)
$Script:BaseRiskScores = @{
    # Critical Risk (80-100)
    'MFA_AdminDisabled' = 95
    'GlobalAdmin_Multiple' = 90
    'LegacyAuth_Enabled' = 85
    'AuditLog_NotEnabled' = 85
    'ConditionalAccess_Missing' = 80

    # High Risk (60-79)
    'MFA_Disabled' = 75
    'AdminRoles_Excessive' = 70
    'AppConsent_UserAllowed' = 70
    'SecurityDefaults_Disabled' = 65
    'PasswordExpiry_Disabled' = 65
    'RiskySignIn_NoPolicy' = 65

    # Medium Risk (40-59)
    'AppPermissions_Excessive' = 55
    'GuestAccess_Unrestricted' = 55
    'MailboxAudit_Disabled' = 50
    'SelfServicePasswordReset_Disabled' = 45
    'DLP_NotConfigured' = 50

    # Low Risk (20-39)
    'PasswordPolicy_Weak' = 35
    'SessionTimeout_NotConfigured' = 30

    # Default for unmapped findings
    'Default' = 50
}

# Impact multipliers
$Script:ImpactFactors = @{
    # Scope multipliers
    'Organization' = 1.3
    'AllUsers' = 1.2
    'MultipleUsers' = 1.1
    'AdminUsers' = 1.25
    'SingleUser' = 0.9

    # Data sensitivity multipliers
    'HighlySensitive' = 1.3
    'Sensitive' = 1.2
    'Internal' = 1.0
    'Public' = 0.8

    # Exploitability multipliers
    'EasyExploit' = 1.3
    'ModerateExploit' = 1.1
    'DifficultExploit' = 0.9
}

# Remediation effort scores (1-10 scale, where 1 is easy, 10 is hard)
$Script:RemediationEffort = @{
    'MFA_Disabled' = 3
    'MFA_AdminDisabled' = 2
    'SecurityDefaults_Disabled' = 1
    'ConditionalAccess_Missing' = 7
    'LegacyAuth_Enabled' = 4
    'PasswordExpiry_Disabled' = 2
    'SelfServicePasswordReset_Disabled' = 3
    'AdminRoles_Excessive' = 5
    'GlobalAdmin_Multiple' = 4
    'GuestAccess_Unrestricted' = 6
    'AppPermissions_Excessive' = 6
    'AppConsent_UserAllowed' = 3
    'DLP_NotConfigured' = 8
    'AuditLog_NotEnabled' = 2
    'MailboxAudit_Disabled' = 2
    'RiskySignIn_NoPolicy' = 6
    'Default' = 5
}

#endregion

#region Risk Score Calculation

function Get-BaseRiskScore {
    <#
    .SYNOPSIS
        Gets the base risk score for a finding type.

    .PARAMETER FindingType
        The type of finding

    .OUTPUTS
        Base risk score (0-100)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FindingType
    )

    if ($Script:BaseRiskScores.ContainsKey($FindingType)) {
        return $Script:BaseRiskScores[$FindingType]
    }
    return $Script:BaseRiskScores['Default']
}

function Get-RemediationEffort {
    <#
    .SYNOPSIS
        Gets the remediation effort score for a finding type.

    .PARAMETER FindingType
        The type of finding

    .OUTPUTS
        Effort score (1-10, where 1 is easy, 10 is hard)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FindingType
    )

    if ($Script:RemediationEffort.ContainsKey($FindingType)) {
        return $Script:RemediationEffort[$FindingType]
    }
    return $Script:RemediationEffort['Default']
}

function Measure-RiskScore {
    <#
    .SYNOPSIS
        Calculates the risk score for a finding.

    .DESCRIPTION
        Computes a comprehensive risk score based on:
        - Base risk (finding type)
        - Scope (number of users/resources affected)
        - Data sensitivity
        - Exploitability
        - Compliance requirements

    .PARAMETER Finding
        The finding object to score

    .OUTPUTS
        Risk score (0-100)

    .EXAMPLE
        Measure-RiskScore -Finding $finding
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Finding
    )

    process {
        # OK and INFO findings represent passing checks - assign minimal risk
        if ($Finding.Status -eq 'OK') { return 0 }
        if ($Finding.Status -eq 'INFO') { return 5 }

        # Get finding type
        $findingType = if ($null -ne $Finding.Type) { $Finding.Type } elseif ($null -ne $Finding.CheckType) { $Finding.CheckType } elseif ($null -ne $Finding.Category) { $Finding.Category } else { 'Default' }

        # WARNING findings get reduced base score (less severe than FAIL)
        $statusMultiplier = if ($Finding.Status -eq 'WARNING') { 0.7 } else { 1.0 }

        # Start with base risk score
        $baseScore = Get-BaseRiskScore -FindingType $findingType

        # Apply scope multiplier
        $scopeMultiplier = 1.0
        if ($Finding.Scope) {
            $scopeMultiplier = if ($Script:ImpactFactors.ContainsKey($Finding.Scope)) { $Script:ImpactFactors[$Finding.Scope] } else { 1.0 }
        } elseif ($Finding.AffectedCount) {
            # Calculate scope based on affected count
            $count = [int]$Finding.AffectedCount
            if ($count -gt 1000) { $scopeMultiplier = 1.3 }
            elseif ($count -gt 100) { $scopeMultiplier = 1.2 }
            elseif ($count -gt 10) { $scopeMultiplier = 1.1 }
            else { $scopeMultiplier = 1.0 }
        }

        # Apply data sensitivity multiplier
        $sensitivityMultiplier = 1.0
        if ($Finding.DataSensitivity) {
            $sensitivityMultiplier = if ($Script:ImpactFactors.ContainsKey($Finding.DataSensitivity)) { $Script:ImpactFactors[$Finding.DataSensitivity] } else { 1.0 }
        }

        # Apply exploitability multiplier
        $exploitMultiplier = 1.0
        if ($Finding.Exploitability) {
            $exploitMultiplier = if ($Script:ImpactFactors.ContainsKey($Finding.Exploitability)) { $Script:ImpactFactors[$Finding.Exploitability] } else { 1.0 }
        } else {
            # Assign default exploitability based on finding type
            $exploitMultiplier = switch -Regex ($findingType) {
                'Auth|MFA|Password' { 1.3; break } # Authentication issues are easily exploited
                'Admin|Privilege' { 1.2; break }   # Privilege escalation opportunities
                'Audit|Log' { 0.9; break }         # Detection issues are harder to exploit directly
                default { 1.0 }
            }
        }

        # Apply compliance requirement boost
        $complianceBoost = 0
        if ($Finding.ComplianceMappings -and $Finding.ComplianceMappings.Count -gt 2) {
            $complianceBoost = 5 # Add 5 points if multiple frameworks affected
        }

        # Calculate final risk score
        $riskScore = ($baseScore * $statusMultiplier * $scopeMultiplier * $sensitivityMultiplier * $exploitMultiplier) + $complianceBoost

        # Cap at 100
        $riskScore = [Math]::Min(100, $riskScore)
        $riskScore = [Math]::Round($riskScore, 1)

        return $riskScore
    }
}

function Get-RiskLevel {
    <#
    .SYNOPSIS
        Converts a risk score to a risk level.

    .PARAMETER RiskScore
        The risk score (0-100)

    .OUTPUTS
        Risk level string: 'Critical', 'High', 'Medium', 'Low', 'Info'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [double]$RiskScore
    )

    if ($RiskScore -ge 80) { return 'Critical' }
    elseif ($RiskScore -ge 60) { return 'High' }
    elseif ($RiskScore -ge 40) { return 'Medium' }
    elseif ($RiskScore -ge 20) { return 'Low' }
    else { return 'Info' }
}

function Add-RiskScoring {
    <#
    .SYNOPSIS
        Adds risk scoring information to a finding object.

    .DESCRIPTION
        Enhances a finding with calculated risk score, risk level, and remediation effort.

    .PARAMETER Finding
        The finding object to enhance

    .EXAMPLE
        $finding | Add-RiskScoring
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Finding
    )

    process {
        # Calculate risk score
        $riskScore = Measure-RiskScore -Finding $Finding

        # Determine risk level. REVIEW-status findings are human-judgment items
        # that don't fit on the severity axis — override to 'Review' so they
        # land in the Review Queue rather than the severity-banded triage list.
        # RiskScore is left intact so the queue can be sorted by underlying
        # risk magnitude.
        $riskLevel = if ($Finding.Status -eq 'REVIEW') {
            'Review'
        }
        else {
            Get-RiskLevel -RiskScore $riskScore
        }

        # Get remediation effort
        $findingType = if ($null -ne $Finding.Type) { $Finding.Type } elseif ($null -ne $Finding.CheckType) { $Finding.CheckType } elseif ($null -ne $Finding.Category) { $Finding.Category } else { 'Default' }
        $effort = Get-RemediationEffort -FindingType $findingType

        # Calculate priority score (risk / effort = ROI)
        $priorityScore = if ($effort -gt 0) { [Math]::Round($riskScore / $effort, 2) } else { $riskScore }

        # Add properties to finding
        $Finding | Add-Member -NotePropertyName 'RiskScore' -NotePropertyValue $riskScore -Force
        $Finding | Add-Member -NotePropertyName 'RiskLevel' -NotePropertyValue $riskLevel -Force
        $Finding | Add-Member -NotePropertyName 'RemediationEffort' -NotePropertyValue $effort -Force
        $Finding | Add-Member -NotePropertyName 'PriorityScore' -NotePropertyValue $priorityScore -Force

        # Add effort description
        $effortDescription = switch ($effort) {
            { $_ -le 2 } { 'Quick Win (< 1 hour)'; break }
            { $_ -le 4 } { 'Easy (1-4 hours)'; break }
            { $_ -le 6 } { 'Moderate (1-2 days)'; break }
            { $_ -le 8 } { 'Complex (3-5 days)'; break }
            default { 'Very Complex (> 1 week)' }
        }
        $Finding | Add-Member -NotePropertyName 'RemediationEffortDescription' -NotePropertyValue $effortDescription -Force

        return $Finding
    }
}

#endregion

#region Prioritization

function Get-PrioritizedFindings {
    <#
    .SYNOPSIS
        Prioritizes findings for remediation.

    .DESCRIPTION
        Sorts findings by priority score (risk / effort) to identify quick wins and critical issues.
        Groups findings into priority tiers.

    .PARAMETER Findings
        Array of findings to prioritize

    .PARAMETER GroupByPriority
        If specified, groups findings by priority tier

    .EXAMPLE
        $prioritized = Get-PrioritizedFindings -Findings $allFindings
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [switch]$GroupByPriority
    )

    # Ensure all findings have risk scoring
    $scoredFindings = @()
    foreach ($finding in $Findings) {
        if (-not $finding.RiskScore) {
            $finding = $finding | Add-RiskScoring
        }
        $scoredFindings += $finding
    }

    if ($GroupByPriority) {
        # Group by priority tiers
        $priorityGroups = @{
            'Priority 1 - Critical & Quick Wins' = @($scoredFindings | Where-Object {
                    ($_.RiskLevel -eq 'Critical' -or $_.PriorityScore -ge 30) -and $_.RemediationEffort -le 3
                })
            'Priority 2 - High Risk' = @($scoredFindings | Where-Object {
                    $_.RiskLevel -eq 'Critical' -or $_.RiskLevel -eq 'High'
                } | Where-Object { $_.RemediationEffort -gt 3 })
            'Priority 3 - Medium Risk Quick Wins' = @($scoredFindings | Where-Object {
                    $_.RiskLevel -eq 'Medium' -and $_.RemediationEffort -le 4
                })
            'Priority 4 - Medium Risk' = @($scoredFindings | Where-Object {
                    $_.RiskLevel -eq 'Medium' -and $_.RemediationEffort -gt 4
                })
            'Priority 5 - Low Risk' = @($scoredFindings | Where-Object {
                    $_.RiskLevel -eq 'Low' -or $_.RiskLevel -eq 'Info'
                })
            'Priority 6 - Review Queue' = @($scoredFindings | Where-Object {
                    $_.RiskLevel -eq 'Review'
                })
        }

        return $priorityGroups
    } else {
        # Sort by priority score (descending)
        return $scoredFindings | Sort-Object -Property PriorityScore -Descending
    }
}

function Get-QuickWins {
    <#
    .SYNOPSIS
        Identifies "quick win" findings - high impact, low effort.

    .DESCRIPTION
        Returns findings that provide significant risk reduction with minimal effort.
        Criteria: Risk score >= 50 AND Remediation effort <= 3

    .PARAMETER Findings
        Array of findings to analyze

    .PARAMETER MaxEffort
        Maximum remediation effort for quick wins (default: 3)

    .PARAMETER MinRisk
        Minimum risk score for quick wins (default: 50)

    .EXAMPLE
        $quickWins = Get-QuickWins -Findings $allFindings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [int]$MaxEffort = 3,

        [double]$MinRisk = 50
    )

    # Ensure all findings have risk scoring
    $scoredFindings = @()
    foreach ($finding in $Findings) {
        if (-not $finding.RiskScore) {
            $finding = $finding | Add-RiskScoring
        }
        $scoredFindings += $finding
    }

    # Filter for quick wins
    $quickWins = $scoredFindings | Where-Object {
        $_.RiskScore -ge $MinRisk -and $_.RemediationEffort -le $MaxEffort
    } | Sort-Object -Property PriorityScore -Descending

    return $quickWins
}

function Get-RiskSummary {
    <#
    .SYNOPSIS
        Generates a risk summary for all findings.

    .DESCRIPTION
        Provides statistical analysis of risk across all findings.

    .PARAMETER Findings
        Array of findings to analyze

    .OUTPUTS
        Hashtable with risk statistics

    .EXAMPLE
        $summary = Get-RiskSummary -Findings $allFindings
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [array]$Findings
    )

    # Ensure all findings have risk scoring
    $scoredFindings = @()
    foreach ($finding in $Findings) {
        if (-not $finding.RiskScore) {
            $finding = $finding | Add-RiskScoring
        }
        $scoredFindings += $finding
    }

    # Calculate statistics
    $summary = @{
        TotalFindings = $scoredFindings.Count
        AverageRiskScore = [Math]::Round(($scoredFindings | Measure-Object -Property RiskScore -Average).Average, 1)
        MaxRiskScore = ($scoredFindings | Measure-Object -Property RiskScore -Maximum).Maximum
        MinRiskScore = ($scoredFindings | Measure-Object -Property RiskScore -Minimum).Minimum

        # Risk level distribution
        CriticalCount = @($scoredFindings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
        HighCount = @($scoredFindings | Where-Object { $_.RiskLevel -eq 'High' }).Count
        MediumCount = @($scoredFindings | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
        LowCount = @($scoredFindings | Where-Object { $_.RiskLevel -eq 'Low' }).Count
        InfoCount = @($scoredFindings | Where-Object { $_.RiskLevel -eq 'Info' }).Count
        # REVIEW = human-judgment items, separate from severity bands
        ReviewCount = @($scoredFindings | Where-Object { $_.RiskLevel -eq 'Review' }).Count

        # Remediation effort
        QuickWinsCount = @($scoredFindings | Where-Object { $_.RemediationEffort -le 3 }).Count
        ComplexCount = @($scoredFindings | Where-Object { $_.RemediationEffort -ge 7 }).Count

        # Priority insights
        TopPriorityCount = @($scoredFindings | Where-Object { $_.PriorityScore -ge 20 }).Count
    }

    # Calculate risk distribution percentage
    $total = [Math]::Max(1, $summary.TotalFindings) # Avoid division by zero
    $summary['CriticalPercent'] = [Math]::Round(($summary.CriticalCount / $total) * 100, 1)
    $summary['HighPercent'] = [Math]::Round(($summary.HighCount / $total) * 100, 1)
    $summary['MediumPercent'] = [Math]::Round(($summary.MediumCount / $total) * 100, 1)
    $summary['LowPercent'] = [Math]::Round(($summary.LowCount / $total) * 100, 1)
    $summary['ReviewPercent'] = [Math]::Round(($summary.ReviewCount / $total) * 100, 1)

    return $summary
}

function Format-PriorityRecommendation {
    <#
    .SYNOPSIS
        Generates prioritized remediation recommendations.

    .DESCRIPTION
        Creates a formatted list of top priority findings with actionable recommendations.

    .PARAMETER Findings
        Array of findings to analyze

    .PARAMETER TopN
        Number of top findings to include (default: 10)

    .PARAMETER Format
        Output format: 'Text', 'HTML', 'Markdown'

    .EXAMPLE
        Format-PriorityRecommendation -Findings $allFindings -TopN 5 -Format 'HTML'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [int]$TopN = 10,

        [ValidateSet('Text', 'HTML', 'Markdown')]
        [string]$Format = 'Text'
    )

    # Get prioritized findings
    $prioritized = Get-PrioritizedFindings -Findings $Findings
    $topFindings = $prioritized | Select-Object -First $TopN

    $output = @()

    switch ($Format) {
        'Text' {
            $output += "=" * 80
            $output += "TOP $TopN PRIORITY FINDINGS - RECOMMENDED REMEDIATION ORDER"
            $output += "=" * 80
            $output += ""

            $rank = 1
            foreach ($finding in $topFindings) {
                $output += "[$rank] $(if ($null -ne $finding.Check) { $finding.Check } else { $finding.Name })"
                $output += "    Risk Score: $($finding.RiskScore) ($($finding.RiskLevel))"
                $output += "    Remediation Effort: $($finding.RemediationEffortDescription)"
                $output += "    Priority Score: $($finding.PriorityScore) (Risk/Effort Ratio)"
                if ($finding.ComplianceReference) {
                    $output += "    Compliance: $($finding.ComplianceReference)"
                }
                $output += ""
                $rank++
            }
        }
        'HTML' {
            $output += "<div class='priority-recommendations'>"
            $output += "<h2>Top $TopN Priority Findings - Recommended Remediation Order</h2>"
            $output += "<table class='priority-table'>"
            $output += "<thead><tr><th>Rank</th><th>Finding</th><th>Risk</th><th>Effort</th><th>Priority Score</th></tr></thead>"
            $output += "<tbody>"

            $rank = 1
            foreach ($finding in $topFindings) {
                $riskClass = $finding.RiskLevel.ToLower()
                $output += "<tr class='risk-$riskClass'>"
                $output += "<td>$rank</td>"
                $output += "<td>$(if ($null -ne $finding.Check) { $finding.Check } else { $finding.Name })</td>"
                $output += "<td><span class='risk-badge risk-$riskClass'>$($finding.RiskLevel)</span> $($finding.RiskScore)</td>"
                $output += "<td>$($finding.RemediationEffortDescription)</td>"
                $output += "<td><strong>$($finding.PriorityScore)</strong></td>"
                $output += "</tr>"
                $rank++
            }

            $output += "</tbody></table></div>"
        }
        'Markdown' {
            $output += "# Top $TopN Priority Findings - Recommended Remediation Order"
            $output += ""
            $output += "| Rank | Finding | Risk Level | Risk Score | Effort | Priority Score |"
            $output += "|------|---------|------------|------------|--------|----------------|"

            $rank = 1
            foreach ($finding in $topFindings) {
                $output += "| $rank | $(if ($null -ne $finding.Check) { $finding.Check } else { $finding.Name }) | $($finding.RiskLevel) | $($finding.RiskScore) | $($finding.RemediationEffortDescription) | **$($finding.PriorityScore)** |"
                $rank++
            }
            $output += ""
        }
    }

    return ($output -join "`n")
}

#endregion

#region Export Module Members

Export-ModuleMember -Function @(
    'Measure-RiskScore',
    'Get-RiskLevel',
    'Add-RiskScoring',
    'Get-PrioritizedFindings',
    'Get-QuickWins',
    'Get-RiskSummary',
    'Format-PriorityRecommendation'
)

#endregion
