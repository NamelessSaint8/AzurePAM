<#
.SYNOPSIS
    Pester 5 tests for Saved Views (SOC 2 Audit-Readiness Plan §11.5).

.DESCRIPTION
    Saved Views are one-click presets over the *existing* filter
    machinery — no new filter engine. They live on the two filterable
    surfaces:

      1. Cockpit Full Findings (EntraChecks-HTMLReporting): a
         .cockpit-saved-views bar driving the data-filter-key controls.
         Views: Owner queue (review-state=actionrequired), Expired
         exceptions (exception-status=expired), Due within 7 days
         (due-bucket=due-0-7), Clear.
      2. SOC 2 Evidence Matrix (EntraChecks-SOC2Reporting): a
         .em-saved-views bar driving the data-em-filter selects.
         View: Stale evidence (fresh=Stale), Clear.

    The filter engines themselves are already covered by
    CockpitFilterExpansion / SOC2-EvidenceMatrix tests, so these tests
    assert the saved-view markup, the preset specs, and the JS wiring
    that resets + drives the existing filters (string/structural
    assertions — there is no JS runtime in the harness).

    Run: Invoke-Pester -Path Tests/SavedViews.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    if (-not $env:TEMP) {
        $env:TEMP = if ($env:TMPDIR) { $env:TMPDIR.TrimEnd('/') } else { '/tmp' }
    }
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ComplianceMapping.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Branding.psm1') -Force -WarningAction SilentlyContinue
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2.psm1') -Force -WarningAction SilentlyContinue
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2Reporting.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force
}

Describe 'Cockpit Full Findings — Saved Views bar' {

    BeforeAll {
        $script:Tmp = Join-Path $env:TEMP "sv-cockpit-$((Get-Random))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $findings = @(
            [pscustomobject]@{ Time = Get-Date; CheckName = 'A'; Type = 'MFA_Disabled'; Status = 'FAIL'; Severity = 'High'; Object = 'o1'; Description = 'd'; Remediation = 'r'; Source = 'Internal' }
            [pscustomobject]@{ Time = Get-Date; CheckName = 'B'; Type = 'X'; Status = 'OK'; Severity = 'Info'; Object = 'o2'; Description = 'd'; Remediation = 'r'; Source = 'Internal' }
        )
        $tenant = [pscustomobject]@{ TenantName = 'SV'; TenantId = '00000000-0000-0000-0000-000000000001' }
        $out = Join-Path $script:Tmp 'cockpit.html'
        $null = New-EntraChecksAnalystHtmlReport -Findings $findings -OutputPath $out -TenantInfo $tenant
        $script:Html = Get-Content -LiteralPath $out -Raw
        $script:FF = ($script:Html -split 'id="full-findings"', 2)[1] -split '</section>', 2 | Select-Object -First 1
    }
    AfterAll {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'renders the saved-views bar inside Full Findings, before the filters' {
        $script:FF | Should -Match 'class="cockpit-saved-views"'
        $svIdx = $script:FF.IndexOf('cockpit-saved-views')
        $filterIdx = $script:FF.IndexOf('cockpit-filters')
        $svIdx | Should -BeLessThan $filterIdx
    }

    It 'ships the four plan-named presets with correct filter specs' {
        $script:FF | Should -Match 'data-view-set="review-state=actionrequired"[^>]*>Owner queue<'
        $script:FF | Should -Match 'data-view-set="exception-status=expired"[^>]*>Expired exceptions<'
        $script:FF | Should -Match 'data-view-set="due-bucket=due-0-7"[^>]*>Due within 7 days<'
        $script:FF | Should -Match 'cockpit-saved-view-clear[^>]*data-view-set=""'
    }

    It 'every preset key matches a real data-filter-key control in the section' {
        foreach ($key in @('review-state', 'exception-status', 'due-bucket')) {
            $script:FF | Should -Match ([regex]::Escape("data-filter-key=`"$key`""))
        }
    }

    It 'preset values are lowercased to match the row data-* attributes' {
        # applyFilters lowercases needle + haystack; option values + row
        # attrs are emitted lowercased, so the preset must be too. -match
        # is case-insensitive, so assert casing with a case-sensitive
        # .Contains instead.
        $script:FF.Contains('data-view-set="due-bucket=due-0-7"') | Should -BeTrue
        $script:FF.Contains('data-view-set="due-bucket=Due-0-7"') | Should -BeFalse
        $script:FF.Contains('data-view-set="review-state=actionrequired"') | Should -BeTrue
    }

    It 'JS resets all filters then applies the preset and re-runs applyFilters' {
        $script:Html | Should -Match "querySelectorAll\('\.cockpit-saved-view'\)"
        $script:Html | Should -Match "getAttribute\('data-view-set'\)"
        # reset loop, then applyFilters(section.id), then active class
        $script:Html | Should -Match 'for \(var x = 0; x < fe\.length; x\+\+\) \{ fe\[x\]\.value = '''';'
        $script:Html | Should -Match 'applyFilters\(section\.id\)'
        $script:Html | Should -Match "b\.classList\.add\('active'\)"
    }

    It 'the saved-views bar is print-hidden' {
        $script:Html | Should -Match '\.cockpit-filters, \.cockpit-saved-views, \.cockpit-show-more'
    }
}

Describe 'SOC 2 Evidence Matrix — Stale evidence saved view' {

    BeforeAll {
        $script:Tmp = Join-Path $env:TEMP "sv-em-$((Get-Random))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $f = @([pscustomobject]@{ Type = 'SOC2_X'; Status = 'FAIL'; Severity = 'High'; Object = 't'; Description = 'd'; Remediation = 'r'; CheckName = 'Test-X'; Category = 'SOC2'; TSCReferences = @('CC6.1') })
        $cat = Get-SOC2TSCCatalog -Categories @('CC')
        $sum = Get-SOC2Summary -Findings $f -Catalog $cat
        $bundle = New-SOC2EvidenceBundle -Findings $f -Catalog $cat -TenantId 't1' -Categories @('CC') -Summary $sum -OutputDirectory $script:Tmp
        $res = [pscustomobject]@{ Findings = $f; Catalog = $cat; Summary = $sum; Evidence = $bundle }
        $out = Join-Path $script:Tmp 'r.html'
        $null = New-SOC2AuditReport -AssessmentResult $res -OutputPath $out
        $script:Html = Get-Content -LiteralPath $out -Raw
        $script:EM = ($script:Html -split 'id="evidence-matrix"', 2)[1] -split '</section>', 2 | Select-Object -First 1
    }
    AfterAll {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'renders the saved-views bar before the freshness filters' {
        $script:EM | Should -Match 'class="em-saved-views"'
        ($script:EM.IndexOf('em-saved-views')) | Should -BeLessThan ($script:EM.IndexOf('em-filters'))
    }

    It 'ships the Stale evidence preset matching the fresh filter value' {
        # Get-SOC2EvidenceMatrix emits Freshness = 'Stale' verbatim, and the
        # fresh <select> options use that exact casing — so the preset must
        # be "fresh=Stale" (not lowercased, unlike the cockpit).
        $script:EM | Should -Match 'data-em-view="fresh=Stale"[^>]*>Stale evidence<'
        $script:EM | Should -Match "data-em-filter='fresh'"
        $script:EM | Should -Match 'em-saved-view-clear[^>]*data-em-view=""'
    }

    It 'JS resets the selects, applies the preset, and reuses apply()' {
        $script:EM | Should -Match "querySelectorAll\('\.em-saved-view'\)"
        $script:EM | Should -Match "getAttribute\('data-em-view'\)"
        $script:EM | Should -Match 'selects\.forEach\(function \(s\) \{ s\.value = '''';'
        $script:EM | Should -Match 'apply\(\);'
        $script:EM | Should -Match "b\.classList\.add\('active'\)"
    }

    It 'the saved-views bar is print-hidden' {
        $script:Html | Should -Match '\.em-filters, \.em-saved-views \{ display: none; \}'
    }
}
