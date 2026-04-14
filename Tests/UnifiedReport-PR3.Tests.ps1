<#
.SYNOPSIS
    Pester 5 test suite for unified-report PR 3 (SOC 2 feature backports).

.DESCRIPTION
    Verifies the SOC 2-pattern features ported into the unified report:
    1. Executive digest with verdict
    2. Integrity badge (SHA-256 footer + .findings.json sidecar)
    3. Test-EntraChecksReportIntegrity round-trips
    4. Anchor IDs + copy-link affordance
    5. Low-confidence banner + per-finding tag
    6. White-label branding overrides
    7. Print stylesheet present

    Run: Invoke-Pester -Path Tests/UnifiedReport-PR3.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-RiskScoring.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-RemediationGuidance.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-Branding.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-HTMLReporting.psm1') -Force

    function New-PR3TestFinding {
        param(
            [string]$Description = 'Synthetic finding',
            [string]$Object = 'user-1',
            [string]$Status = 'FAIL',
            [string]$RiskLevel = 'High',
            [int]$RiskScore = 60,
            [string]$CheckName = 'Test-Synthetic',
            [string]$Category = 'Identity'
        )
        [pscustomobject]@{
            Time = (Get-Date)
            Status = $Status
            Object = $Object
            Description = $Description
            Remediation = 'Synthetic remediation'
            RiskLevel = $RiskLevel
            RiskScore = $RiskScore
            PriorityScore = 30
            RemediationEffortDescription = 'Easy'
            ComplianceReference = 'CIS 1.1'
            Type = 'MFA_Disabled'
            CheckName = $CheckName
            Category = $Category
        }
    }

    $script:tenantInfo = [pscustomobject]@{
        TenantName = 'Test-Tenant'
        TenantId = '00000000-0000-0000-0000-000000000000'
    }
}

Describe 'Executive digest' {

    It 'renders the digest section by default with a verdict badge' {
        $f = New-PR3TestFinding -RiskLevel 'Critical' -RiskScore 90
        $out = Join-Path $env:TEMP "pr3-digest-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'id="exec-digest"'
            $html | Should -Match 'Executive Digest'
            $html | Should -Match 'exec-verdict'
            $html | Should -Match 'GAPS IDENTIFIED'
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }

    It 'returns STRONG verdict when all findings are pass-only / low-risk' {
        $f = New-PR3TestFinding -Status 'OK' -RiskLevel 'Low' -RiskScore 5
        $out = Join-Path $env:TEMP "pr3-strong-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'STRONG'
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }

    It 'omits the digest when -IncludeExecutiveDigest:$false is supplied' {
        $f = New-PR3TestFinding
        $out = Join-Path $env:TEMP "pr3-nodigest-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo -IncludeExecutiveDigest:$false | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Not -Match 'id="exec-digest"'
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Integrity badge + Test-EntraChecksReportIntegrity' {

    It 'emits the badge by default and writes a .findings.json sidecar' {
        $f = New-PR3TestFinding
        $out = Join-Path $env:TEMP "pr3-integrity-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'id="integrity"'
            $html | Should -Match '<span class="hash">[a-f0-9]{64}</span>'
            (Test-Path -LiteralPath "$out.findings.json") | Should -Be $true
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$out.findings.json" -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Test-EntraChecksReportIntegrity returns IsValid=$true on an unmodified report' {
        $f = New-PR3TestFinding
        $out = Join-Path $env:TEMP "pr3-verify-ok-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            $verdict = Test-EntraChecksReportIntegrity -ReportPath $out
            $verdict.IsValid | Should -Be $true
            $verdict.ExpectedHash | Should -Be $verdict.ActualHash
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$out.findings.json" -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Test-EntraChecksReportIntegrity returns IsValid=$false when sidecar is tampered' {
        $f = New-PR3TestFinding
        $out = Join-Path $env:TEMP "pr3-verify-bad-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            # Tamper with the sidecar.
            'tampered content' | Set-Content -LiteralPath "$out.findings.json" -Encoding UTF8
            $verdict = Test-EntraChecksReportIntegrity -ReportPath $out
            $verdict.IsValid | Should -Be $false
            $verdict.Reason | Should -Match 'does not match'
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$out.findings.json" -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Test-EntraChecksReportIntegrity returns IsValid=$false when sidecar is missing' {
        $f = New-PR3TestFinding
        $out = Join-Path $env:TEMP "pr3-verify-nosidecar-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            Remove-Item -LiteralPath "$out.findings.json" -Force -ErrorAction SilentlyContinue
            $verdict = Test-EntraChecksReportIntegrity -ReportPath $out
            $verdict.IsValid | Should -Be $false
            $verdict.Reason | Should -Match 'Sidecar not found'
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }

    It 'omits the integrity footer and sidecar when -IncludeIntegrityBadge:$false' {
        $f = New-PR3TestFinding
        $out = Join-Path $env:TEMP "pr3-no-integrity-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo -IncludeIntegrityBadge:$false | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Not -Match 'id="integrity"'
            (Test-Path -LiteralPath "$out.findings.json") | Should -Be $false
        }
        finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Anchor IDs + copy-link affordance' {

    It 'emits a stable id="finding-XXXXXXXXXX" on each detailed finding' {
        $f = New-PR3TestFinding
        $out = Join-Path $env:TEMP "pr3-anchor-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'id="finding-[a-f0-9]{10}"'
            $html | Should -Match 'class=''finding-anchor'''
            $html | Should -Match 'copyFindingLink'
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$out.findings.json" -Force -ErrorAction SilentlyContinue
        }
    }

    It 'produces the same id for the same finding across runs (stable hash)' {
        $f = New-PR3TestFinding -Description 'Same description' -Object 'same-object'
        $out1 = Join-Path $env:TEMP "pr3-stable-1-$((Get-Random)).html"
        $out2 = Join-Path $env:TEMP "pr3-stable-2-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out1 -TenantInfo $script:tenantInfo | Out-Null
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out2 -TenantInfo $script:tenantInfo | Out-Null
            $html1 = Get-Content -LiteralPath $out1 -Raw
            $html2 = Get-Content -LiteralPath $out2 -Raw
            $id1 = [regex]::Match($html1, 'id="(finding-[a-f0-9]{10})"').Groups[1].Value
            $id2 = [regex]::Match($html2, 'id="(finding-[a-f0-9]{10})"').Groups[1].Value
            $id1 | Should -Be $id2
            $id1 | Should -Not -BeNullOrEmpty
        }
        finally {
            Remove-Item -LiteralPath $out1, $out2, "$out1.findings.json", "$out2.findings.json" -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Low-confidence banner + per-finding tag' {

    It 'omits the banner when no rendered findings match the configured list' {
        $f = New-PR3TestFinding -CheckName 'Test-NotOnList'
        $out = Join-Path $env:TEMP "pr3-lc-clean-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo -LowConfidenceCheckNames @('Test-Other') | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            # The CSS rule .low-confidence-banner is always present; what we
            # really want to know is that no <div class="low-confidence-banner">
            # was emitted into the body.
            $html | Should -Not -Match '<div class="low-confidence-banner">'
            $html | Should -Not -Match 'fixture-verified'
        }
        finally {
            Remove-Item -LiteralPath $out, "$out.findings.json" -Force -ErrorAction SilentlyContinue
        }
    }

    It 'emits the banner AND the per-finding tag when a hit is configured' {
        $f = New-PR3TestFinding -CheckName 'Test-LowConfidence'
        $out = Join-Path $env:TEMP "pr3-lc-hit-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo -LowConfidenceCheckNames @('Test-LowConfidence') | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'low-confidence-banner'
            $html | Should -Match 'Low-confidence checks present'
            $html | Should -Match 'fixture-verified'
            $html | Should -Match 'Test-LowConfidence'
        }
        finally {
            Remove-Item -LiteralPath $out, "$out.findings.json" -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'White-label branding' {

    It 'overrides the report title when a Branding context is supplied' {
        $f = New-PR3TestFinding
        $out = Join-Path $env:TEMP "pr3-brand-$((Get-Random)).html"
        $brandingCfg = @{
            WhiteLabel = $true
            OrganizationName = 'Acme Security Co'
            PrimaryColor = '#aa00aa'
            SuppressEntraChecksBranding = $true
        }
        $branding = Get-ReportBrandingContext -Config $brandingCfg -ReportTitle 'Acme Quarterly Security Review'
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo -Branding $branding | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'Acme Quarterly Security Review'
            $html | Should -Match 'Acme Security Co'
            $html | Should -Match '#aa00aa'
        }
        finally {
            Remove-Item -LiteralPath $out, "$out.findings.json" -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Print stylesheet' {

    It 'includes an @media print block in the head CSS' {
        $f = New-PR3TestFinding
        $out = Join-Path $env:TEMP "pr3-print-$((Get-Random)).html"
        try {
            New-EnhancedHTMLReport -Findings @($f) -OutputPath $out -TenantInfo $script:tenantInfo | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match '@media print'
            $html | Should -Match '\.nav-bar.*display:\s*none'
        }
        finally {
            Remove-Item -LiteralPath $out, "$out.findings.json" -Force -ErrorAction SilentlyContinue
        }
    }
}
