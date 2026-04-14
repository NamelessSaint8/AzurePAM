<#
.SYNOPSIS
    Pester 5 test suite for unified-report PR 2 (wire dead data).

.DESCRIPTION
    Verifies that the unified HTML and Excel/CSV reports surface the
    Secure Score, Azure Policy, and Purview Compliance Manager data that
    the orchestrator already collects.

    Covers two paths per data source:
    1. Graceful degradation — when the parameter is null, the section
       renders a "Not collected" placeholder (HTML) or is silently
       omitted (Excel/CSV).
    2. Happy path — when synthetic fixture data is supplied, the section
       renders the expected card values and table rows.

    Run: Invoke-Pester -Path Tests/UnifiedReport-PR2.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-RiskScoring.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-RemediationGuidance.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-ExcelReporting.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-HTMLReporting.psm1') -Force

    function New-PR2TestFinding {
        [pscustomobject]@{
            Time = (Get-Date)
            Status = 'FAIL'
            Object = 'user-1'
            Description = 'Synthetic finding'
            Remediation = 'Synthetic remediation'
            RiskLevel = 'High'
            RiskScore = 60
            PriorityScore = 30
            RemediationEffortDescription = 'Easy'
            ComplianceReference = 'CIS 1.1'
            Type = 'MFA_Disabled'
        }
    }

    $script:tenantInfo = [pscustomobject]@{
        TenantName = 'Test-Tenant'
        TenantId = '00000000-0000-0000-0000-000000000000'
    }

    # Synthetic Secure Score fixture mimicking Get-SecureScore output (hashtable).
    $script:secureScoreFixture = @{
        TenantId = '00000000-0000-0000-0000-000000000000'
        CurrentScore = 412
        MaxScore = 600
        ScorePercent = 68.7
        ActiveUserCount = 95
        LicensedUserCount = 100
        ControlScores = @(
            [pscustomobject]@{ ControlName = 'mfa_for_admins'; ControlCategory = 'Identity'; Score = 9; ScorePercent = 90; Description = 'MFA for admin roles'; ImplementationStatus = 'Implemented' },
            [pscustomobject]@{ ControlName = 'block_legacy_auth'; ControlCategory = 'Identity'; Score = 0; ScorePercent = 0; Description = 'Block legacy authentication'; ImplementationStatus = 'NotImplemented' }
        )
        ImprovementActions = @(
            [pscustomobject]@{
                Title = 'Block legacy authentication'
                ControlName = 'block_legacy_auth'
                Category = 'Identity'
                Service = 'EntraID'
                CurrentScore = 0
                MaxScore = 9
                PotentialImprovement = 9
                ImplementationStatus = 'NotImplemented'
                ImplementationCost = 'Low'
                UserImpact = 'Low'
                PriorityScore = 96
                Threats = 'AccountBreach'
                ActionUrl = 'https://security.microsoft.com/securescore'
            }
        )
    }

    # Synthetic Azure Policy fixture.
    $script:azurePolicyFixture = @{
        Source = 'AzurePolicy'
        AssessmentDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Subscriptions = @(
            @{
                SubscriptionId = '11111111-1111-1111-1111-111111111111'
                SubscriptionName = 'Production'
                Assignments = @(@{ DisplayName = 'CIS' }, @{ DisplayName = 'NIST' })
                ComplianceSummary = @{
                    CompliantPolicies = 42
                    NonCompliantPolicies = 8
                    CompliantResources = 250
                    NonCompliantResources = 12
                }
            }
        )
        Initiatives = @{
            'CIS Microsoft Azure Foundations Benchmark v2.0.0' = @{
                DisplayName = 'CIS Microsoft Azure Foundations Benchmark v2.0.0'
                ShortName = 'CIS-Azure-2.0'
                Framework = 'CIS'
                Subscriptions = @('Production')
            }
        }
        Summary = @{
            TotalSubscriptions = 1
            TotalAssignments = 2
            TotalPolicies = 50
            CompliantPolicies = 42
            NonCompliantPolicies = 8
            TotalResources = 262
            NonCompliantResources = 12
        }
    }

    # Synthetic Purview fixture.
    $script:purviewFixture = @{
        Source = 'PurviewCompliance'
        Summary = @{
            ComplianceManagerAvailable = $true
            ComplianceScore = 76
            TotalAssessments = 5
            TotalActions = 120
            CompletedActions = 84
            DLPPoliciesCount = 7
            SensitivityLabelsCount = 12
            RetentionPoliciesCount = 4
        }
        Controls = @(
            [pscustomobject]@{
                Framework = 'NIST 800-53'
                ControlId = 'CM-NIST-1'
                ControlTitle = 'Synthetic NIST control'
                Status = 'Partial'
                Severity = 'Medium'
                Score = 14
                MaxScore = 25
                CompliancePercent = 56
                Description = 'Synthetic'
                Remediation = 'Synthetic remediation'
            }
        )
    }
}

Describe 'New-EnhancedHTMLReport — Secure Score wiring' {

    It 'renders a Not-collected placeholder when -SecureScore is not provided' {
        $f = New-PR2TestFinding
        $out = Join-Path $env:TEMP "pr2-ss-omitted-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'id="secure-score"'
            $html | Should -Match 'Not collected'
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }

    It 'renders the Secure Score card and improvement actions when data is supplied' {
        $f = New-PR2TestFinding
        $out = Join-Path $env:TEMP "pr2-ss-happy-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo `
                -SecureScore $script:secureScoreFixture | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'Microsoft Secure Score'
            $html | Should -Match '412 / 600'
            $html | Should -Match 'Block legacy authentication'
            $html | Should -Match 'Open in portal'
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'New-EnhancedHTMLReport — Azure Policy wiring' {

    It 'renders a Not-collected placeholder when -AzurePolicy is not provided' {
        $f = New-PR2TestFinding
        $out = Join-Path $env:TEMP "pr2-ap-omitted-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'id="azure-policy"'
            $html | Should -Match 'Azure Policy'
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }

    It 'renders compliance % and initiative table when data is supplied' {
        $f = New-PR2TestFinding
        $out = Join-Path $env:TEMP "pr2-ap-happy-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo `
                -AzurePolicy $script:azurePolicyFixture | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'Resource Compliance'
            $html | Should -Match 'CIS Microsoft Azure Foundations Benchmark'
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'New-EnhancedHTMLReport — Purview wiring' {

    It 'renders a Not-collected placeholder when -PurviewCompliance is not provided' {
        $f = New-PR2TestFinding
        $out = Join-Path $env:TEMP "pr2-pv-omitted-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'id="purview"'
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }

    It 'renders Compliance Manager score and protection counts when data is supplied' {
        $f = New-PR2TestFinding
        $out = Join-Path $env:TEMP "pr2-pv-happy-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo `
                -PurviewCompliance $script:purviewFixture | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'Compliance Manager score'
            $html | Should -Match '76%'
            $html | Should -Match 'DLP Policies'
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'CSV workbook — new optional sheets' {

    It 'omits the new CSVs when no optional data is supplied' {
        $f = New-PR2TestFinding
        $tempDir = Join-Path $env:TEMP "pr2-csv-omit-$((Get-Random))"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        $outPath = Join-Path $tempDir 'report.xlsx'
        try {
            & (Get-Module EntraChecks-ExcelReporting) {
                param($findings, $path, $tenant)
                $enhanced = @($findings | ForEach-Object { $_ | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance })
                New-CSVWorkbook -Findings $enhanced -OutputPath $path -TenantInfo $tenant
            } @($f) $outPath $script:tenantInfo

            $csvDir = Join-Path $tempDir 'report-CSV'
            (Test-Path (Join-Path $csvDir '10-SecureScore.csv')) | Should -Be $false
            (Test-Path (Join-Path $csvDir '11-AzurePolicy.csv')) | Should -Be $false
            (Test-Path (Join-Path $csvDir '12-Purview.csv'))     | Should -Be $false
        }
        finally { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'produces all 3 new CSVs when all optional data is supplied' {
        $f = New-PR2TestFinding
        $tempDir = Join-Path $env:TEMP "pr2-csv-happy-$((Get-Random))"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        $outPath = Join-Path $tempDir 'report.xlsx'
        try {
            & (Get-Module EntraChecks-ExcelReporting) {
                param($findings, $path, $tenant, $ss, $ap, $pv)
                $enhanced = @($findings | ForEach-Object { $_ | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance })
                New-CSVWorkbook -Findings $enhanced -OutputPath $path -TenantInfo $tenant `
                    -SecureScore $ss -AzurePolicy $ap -PurviewCompliance $pv
            } @($f) $outPath $script:tenantInfo $script:secureScoreFixture $script:azurePolicyFixture $script:purviewFixture

            $csvDir = Join-Path $tempDir 'report-CSV'
            (Test-Path (Join-Path $csvDir '10-SecureScore.csv')) | Should -Be $true
            (Test-Path (Join-Path $csvDir '11-AzurePolicy.csv')) | Should -Be $true
            (Test-Path (Join-Path $csvDir '12-Purview.csv'))     | Should -Be $true

            # Spot-check Secure Score CSV picked up the improvement action.
            $ssRows = Import-Csv -LiteralPath (Join-Path $csvDir '10-SecureScore.csv')
            ($ssRows.Title -contains 'Block legacy authentication') | Should -Be $true

            # Azure Policy CSV has the subscription summary row.
            $apRows = Import-Csv -LiteralPath (Join-Path $csvDir '11-AzurePolicy.csv')
            ($apRows.Subscription -contains 'Production') | Should -Be $true

            # Purview CSV has the synthetic control.
            $pvRows = Import-Csv -LiteralPath (Join-Path $csvDir '12-Purview.csv')
            ($pvRows.ControlId -contains 'CM-NIST-1') | Should -Be $true
        }
        finally { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
