<#
.SYNOPSIS
    Pester 5 test suite for the unified-report Findings flyout (Phase 2).

.DESCRIPTION
    Verifies that Export-UnifiedComplianceReport produces an HTML report
    where:
    1. Each finding row is a <details> element (expandable card layout).
    2. FAIL/WARNING findings carry a finding body with the rich remediation
       block (Portal steps + PowerShell + Impact/Considerations).
    3. OK/INFO findings render as static (uf-finding-static) without a body.
    4. The Source column renders a clickable badge pointing at #data-source-{key}.
    5. The Data Sources section is anchored at id=data-sources and contains
       cards with id=data-source-{Key} matching the badge anchors above.

    Run: Invoke-Pester -Path Tests/UnifiedReport-RemediationFlyout.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-DataSources.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-RemediationGuidance.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Compliance.psm1') -Force

    $script:reportDir = Join-Path $TestDrive 'unified'
    New-Item -Path $script:reportDir -ItemType Directory -Force | Out-Null

    $script:syntheticFindings = @(
        [pscustomobject]@{
            Time = (Get-Date)
            CheckName = 'Check-MFA-1'
            Type = 'MFA_Disabled'
            Status = 'FAIL'
            Object = 'user-1@contoso.com'
            Description = 'MFA not enforced for privileged user'
            Remediation = 'Enable MFA via Conditional Access'
            Source = 'Internal'
        }
        [pscustomobject]@{
            Time = (Get-Date)
            CheckName = 'Check-SecureScore-1'
            Type = 'Default'
            Status = 'WARNING'
            Object = 'tenant'
            Description = 'Secure Score below recommended threshold'
            Remediation = 'Implement top improvement actions'
            Source = 'SecureScore'
        }
        [pscustomobject]@{
            Time = (Get-Date)
            CheckName = 'Check-OK-1'
            Type = 'Default'
            Status = 'OK'
            Object = 'tenant'
            Description = 'Conditional Access policies in place'
            Remediation = ''
            Source = 'Internal'
        }
    )

    Export-UnifiedComplianceReport `
        -OutputDirectory $script:reportDir `
        -TenantName 'TestTenant' `
        -Findings $script:syntheticFindings | Out-Null

    $script:html = Get-ChildItem $script:reportDir -Filter 'UnifiedCompliance-Report-*.html' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 |
        Get-Content -Raw
}

Describe 'Unified report — Findings flyout' {

    It 'renders each finding as a <details class="uf-finding"> element' {
        $script:html | Should -Match '<details class="uf-finding"'
    }

    It 'marks OK/INFO findings as uf-finding-static (no flyout)' {
        $script:html | Should -Match 'uf-finding-static'
    }

    It 'emits a Status column header in the findings list header row' {
        $script:html | Should -Match '<div class="uf-headers">'
        $script:html | Should -Match '>Status<'
        $script:html | Should -Match '>Source<'
    }

    It 'emits the rich remediation block for FAIL findings (when guidance exists)' {
        # MFA_Disabled has built-in guidance in EntraChecks-RemediationGuidance.psm1
        $script:html | Should -Match 'uf-remediation-steps'
        $script:html | Should -Match 'Remediation Steps \(Azure Portal\)'
        $script:html | Should -Match 'PowerShell Remediation'
    }

    It 'omits the remediation block from OK findings' {
        # The OK row is uf-finding-static and should not have a uf-finding-body div.
        # We assert that the static row's <summary> is followed by </details>
        # without intervening uf-finding-body.
        $okSnippet = $script:html -split 'uf-finding-static' | Select-Object -Last 1
        ($okSnippet -split '</details>')[0] | Should -Not -Match 'uf-finding-body'
    }
}

Describe 'Unified report — Source badge link' {

    It 'wraps the Source badge in an anchor pointing at #data-source-{Key}' {
        $script:html | Should -Match 'href="#data-source-Internal"'
        $script:html | Should -Match 'href="#data-source-SecureScore"'
    }
}

Describe 'Unified report — Data Sources section anchors' {

    It 'anchors the section heading at id="data-sources"' {
        $script:html | Should -Match 'id="data-sources"'
    }

    It 'renders one card per source with id="data-source-{Key}"' {
        foreach ($key in @('Internal', 'SecureScore', 'DefenderCompliance', 'AzurePolicy', 'PurviewCompliance')) {
            $script:html | Should -Match "id=`"data-source-$key`""
        }
    }

    It 'emits the collapsed accordion reference table' {
        $script:html | Should -Match '<details class="ds-table-flyout">'
        $script:html | Should -Match 'Source reference table'
    }
}
