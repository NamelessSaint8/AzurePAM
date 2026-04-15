<#
.SYNOPSIS
    Pester 5 suite for EntraChecks-HybridCorrelation.psm1.

.DESCRIPTION
    Synthetic finding arrays. Verifies the correlation logic matches
    principals across cloud and on-prem findings by UPN (Exact) and by
    sAMAccountName (Inferred), and correctly excludes infrastructure /
    INFO / PASS findings.

    Run:
      Invoke-Pester -Path Tests/EntraChecks-HybridCorrelation.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-HybridCorrelation.psm1') -Force

    function New-CloudFinding {
        param(
            [string]$Upn,
            [string]$Status = 'FAIL',
            [string]$Severity = 'High',
            [string]$Category = 'Identity',
            [string]$Source = 'IdentityProtection'
        )
        [pscustomobject]@{
            Time = Get-Date
            Status = $Status
            Severity = $Severity
            Category = $Category
            Object = $Upn
            Description = "Synthetic cloud finding for $Upn"
            Remediation = 'Synthetic'
            Source = $Source
        }
    }

    function New-OnPremFinding {
        param(
            [string]$Sam,
            [string]$Status = 'WARNING',
            [string]$Severity = 'Medium',
            [string]$Category = 'Privileged Access'
        )
        [pscustomobject]@{
            Time = Get-Date
            Status = $Status
            Severity = $Severity
            Category = $Category
            Object = $Sam
            Description = "Synthetic on-prem finding for $Sam"
            Remediation = 'Synthetic'
            Source = 'ActiveDirectory'
        }
    }
}

Describe 'Get-HybridIdentityCorrelation — empty input' {

    It 'returns zero counts for an empty findings array' {
        $result = Get-HybridIdentityCorrelation -Findings @()
        $result.CorrelationCount | Should -Be 0
        $result.CorrelatedPrincipals.Count | Should -Be 0
        $result.CloudOnlyPrincipals.Count | Should -Be 0
        $result.OnPremOnlyPrincipals.Count | Should -Be 0
    }

    It 'returns zero counts for null input without crashing' {
        $result = Get-HybridIdentityCorrelation -Findings $null
        $result.CorrelationCount | Should -Be 0
    }
}

Describe 'Get-HybridIdentityCorrelation — UPN exact matching' {

    It 'correlates a principal flagged in both planes by UPN' {
        $findings = @(
            (New-CloudFinding -Upn 'alice@contoso.com' -Source 'IdentityProtection' -Severity 'High'),
            (New-OnPremFinding -Sam 'alice@contoso.com' -Severity 'Medium')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 1
        $result.CorrelatedPrincipals[0].Confidence | Should -Be 'Exact'
        $result.CorrelatedPrincipals[0].Principal | Should -Be 'alice@contoso.com'
    }

    It 'surfaces the maximum severity per plane' {
        $findings = @(
            (New-CloudFinding -Upn 'bob@contoso.com' -Severity 'Medium'),
            (New-CloudFinding -Upn 'bob@contoso.com' -Severity 'Critical'),
            (New-OnPremFinding -Sam 'bob@contoso.com' -Severity 'Low'),
            (New-OnPremFinding -Sam 'bob@contoso.com' -Severity 'High')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelatedPrincipals[0].MaxCloudSeverity | Should -Be 'Critical'
        $result.CorrelatedPrincipals[0].MaxOnPremSeverity | Should -Be 'High'
    }
}

Describe 'Get-HybridIdentityCorrelation — sAMAccountName inferred matching' {

    It 'correlates when cloud has UPN and on-prem has only sAMAccountName' {
        $findings = @(
            (New-CloudFinding -Upn 'carol@contoso.com' -Severity 'High'),
            (New-OnPremFinding -Sam 'carol' -Severity 'Medium')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 1
        $result.CorrelatedPrincipals[0].Confidence | Should -Be 'Inferred'
        $result.CorrelatedPrincipals[0].MatchKey | Should -Be 'sAMAccountName'
    }

    It 'does not double-count when a UPN match and a SAM match both exist' {
        $findings = @(
            (New-CloudFinding -Upn 'dave@contoso.com' -Severity 'High'),
            (New-OnPremFinding -Sam 'dave@contoso.com' -Severity 'Medium'),
            (New-OnPremFinding -Sam 'dave' -Severity 'Low')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 1
        $result.CorrelatedPrincipals[0].Confidence | Should -Be 'Exact'
    }
}

Describe 'Get-HybridIdentityCorrelation — buckets' {

    It 'separates cloud-only and on-prem-only principals' {
        $findings = @(
            (New-CloudFinding -Upn 'cloudonly@contoso.com' -Severity 'High'),
            (New-OnPremFinding -Sam 'onpremonly' -Severity 'Medium')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 0
        @($result.CloudOnlyPrincipals | Where-Object { $_.Principal -eq 'cloudonly@contoso.com' }).Count | Should -Be 1
    }
}

Describe 'Get-HybridIdentityCorrelation — exclusion filters' {

    It 'excludes Infrastructure-category findings' {
        $findings = @(
            (New-CloudFinding -Upn 'eve@contoso.com' -Category 'Infrastructure'),
            (New-OnPremFinding -Sam 'eve@contoso.com' -Category 'Infrastructure')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 0
    }

    It 'excludes INFO and PASS status findings' {
        $findings = @(
            (New-CloudFinding -Upn 'frank@contoso.com' -Status 'INFO'),
            (New-OnPremFinding -Sam 'frank@contoso.com' -Status 'PASS')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 0
    }

    It 'includes WARNING findings' {
        $findings = @(
            (New-CloudFinding -Upn 'grace@contoso.com' -Status 'WARNING' -Severity 'Medium'),
            (New-OnPremFinding -Sam 'grace@contoso.com' -Status 'WARNING' -Severity 'Medium')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 1
    }
}

Describe 'Get-HybridIdentityCorrelation — totals' {

    It 'tracks total identity-bearing findings per plane' {
        $findings = @(
            (New-CloudFinding -Upn 'a@contoso.com'),
            (New-CloudFinding -Upn 'b@contoso.com'),
            (New-OnPremFinding -Sam 'a@contoso.com'),
            (New-OnPremFinding -Sam 'c'),
            (New-OnPremFinding -Sam 'd')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.TotalCloudFindings | Should -Be 2
        $result.TotalOnPremFindings | Should -Be 3
    }
}
