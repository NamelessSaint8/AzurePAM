<#
.SYNOPSIS
    Pester 5 tests for the accessibility polish follow-up to
    HTML-Reporting-Consolidation §14.

.DESCRIPTION
    Plan §14 calls for:
      * Expandable row headers expose aria-expanded state
        (false at render time, flipped to true on toggle).
      * aria-controls on each header points at the row body's DOM id so
        screen readers know which content is being revealed.
      * Visible keyboard focus beyond the browser default outline
        (:focus-visible rule in the cockpit CSS).
      * Semantic landmark: a single <main> element + skip link.
      * Semantic heading hierarchy preserved (h1 once, h2 for sections).

    These tests render a small cockpit report into TestDrive and grep
    the resulting HTML / CSS / JS for the markers above.

    Run: Invoke-Pester -Path Tests/CockpitAccessibility.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force
}

Describe 'Cockpit accessibility — semantic landmarks and skip link' {

    BeforeAll {
        $schemaMod = Get-Module EntraChecks-FindingSchema
        $raw = @(
            [pscustomobject]@{ CheckName = 'A'; Status = 'FAIL'; Severity = 'High'; Category = 'Identity'; Object = 'objA'; Description = 'fail a'; Remediation = 'fix a'; Source = 'Graph' }
            [pscustomobject]@{ CheckName = 'B'; Status = 'REVIEW'; Severity = 'Medium'; Category = 'Devices'; Object = 'objB'; Description = 'review b'; Remediation = 'fix b'; Source = 'Defender' }
            [pscustomobject]@{ CheckName = 'C'; Status = 'OK'; Severity = 'Low'; Category = 'Identity'; Object = 'objC'; Description = 'pass c'; Remediation = ''; Source = 'Graph' }
        )
        $script:Findings = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $raw
        $tenant = [pscustomobject]@{ TenantName = 'A11y-Test'; TenantId = '00000000-0000-0000-0000-000000000099' }
        $script:Output = Join-Path $TestDrive 'cockpit-a11y.html'
        New-EntraChecksAnalystHtmlReport `
            -Findings $script:Findings `
            -OutputPath $script:Output `
            -TenantInfo $tenant | Out-Null
        $script:Html = Get-Content $script:Output -Raw
    }

    It 'renders a skip link as the first element inside <body>' {
        $script:Html | Should -Match '<body>\s*<a class="skip-link" href="#main-content">Skip to main content</a>'
    }

    It 'wraps page content in a <main> landmark with id="main-content"' {
        $script:Html | Should -Match '<main id="main-content" class="container">'
        # Closing </main> must replace the legacy </div> at end of container.
        $script:Html | Should -Match '</main>'
    }

    It 'has exactly one h1 (report title)' {
        $h1Count = ([regex]::Matches($script:Html, '<h1[\s>]')).Count
        $h1Count | Should -Be 1
    }

    It 'uses h2 for cockpit section titles' {
        $script:Html | Should -Match '<h2 class="cockpit-section-title">Action Queue'
        $script:Html | Should -Match '<h2 class="cockpit-section-title">Review Queue'
        $script:Html | Should -Match '<h2 class="cockpit-section-title">Full Findings'
    }
}

Describe 'Cockpit accessibility — expandable row buttons' {

    BeforeAll {
        $schemaMod = Get-Module EntraChecks-FindingSchema
        $raw = @(
            [pscustomobject]@{ CheckName = 'A'; Status = 'FAIL'; Severity = 'High'; Category = 'Identity'; Object = 'objA'; Description = 'fail a'; Remediation = 'fix a'; Source = 'Graph' }
            [pscustomobject]@{ CheckName = 'B'; Status = 'REVIEW'; Severity = 'Medium'; Category = 'Compliance'; Object = 'objB'; Description = 'review b'; Remediation = 'fix b'; Source = 'Defender' }
        )
        $script:Findings = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $raw
        $tenant = [pscustomobject]@{ TenantName = 'A11y-Test'; TenantId = '00000000-0000-0000-0000-000000000099' }
        $script:Output = Join-Path $TestDrive 'cockpit-a11y-buttons.html'
        New-EntraChecksAnalystHtmlReport `
            -Findings $script:Findings `
            -OutputPath $script:Output `
            -TenantInfo $tenant | Out-Null
        $script:Html = Get-Content $script:Output -Raw
    }

    It 'renders row headers as <button type="button"> (not <div>)' {
        # All three queue sections share the row header shape — any plain
        # <div class="cockpit-row-header"> would be a regression.
        $script:Html | Should -Not -Match '<div class="cockpit-row-header">'
        $script:Html | Should -Match '<button type="button" class="cockpit-row-header"'
    }

    It 'sets aria-expanded="false" by default on every row header' {
        $matches = [regex]::Matches($script:Html, '<button type="button" class="cockpit-row-header"[^>]*>')
        $matches.Count | Should -BeGreaterThan 0
        foreach ($m in $matches) {
            $m.Value | Should -Match 'aria-expanded="false"'
        }
    }

    It 'sets aria-controls that points at a body with a matching id' {
        $headerMatches = [regex]::Matches($script:Html, 'aria-controls="(cockpit-body-[a-z0-9]+)"')
        $headerMatches.Count | Should -BeGreaterThan 0
        foreach ($m in $headerMatches) {
            $bodyId = $m.Groups[1].Value
            $script:Html | Should -Match ([regex]::Escape("id=`"$bodyId`""))
        }
    }

    It 'hides the decorative caret from assistive tech (aria-hidden="true")' {
        $script:Html | Should -Match '<span class="cockpit-caret" aria-hidden="true">'
    }
}

Describe 'Cockpit accessibility — Get-CockpitFindingRowBodyId determinism' {

    BeforeAll {
        $script:HtmlModule = Get-Module EntraChecks-HTMLReporting
    }

    It 'produces a stable id for the same FindingId across calls' {
        $f = [pscustomobject]@{ FindingId = 'abc123def4567890'; Description = 'd'; Object = 'o' }
        $id1 = & $script:HtmlModule { param($x) Get-CockpitFindingRowBodyId -Finding $x } $f
        $id2 = & $script:HtmlModule { param($x) Get-CockpitFindingRowBodyId -Finding $x } $f
        $id1 | Should -BeExactly $id2
        $id1 | Should -Match '^cockpit-body-'
    }

    It 'falls back to Description|Object when FindingId is missing' {
        $f1 = [pscustomobject]@{ Description = 'x'; Object = 'y' }
        $f2 = [pscustomobject]@{ Description = 'x'; Object = 'y' }
        $id1 = & $script:HtmlModule { param($x) Get-CockpitFindingRowBodyId -Finding $x } $f1
        $id2 = & $script:HtmlModule { param($x) Get-CockpitFindingRowBodyId -Finding $x } $f2
        $id1 | Should -BeExactly $id2
    }

    It 'produces distinct ids for distinct findings' {
        $f1 = [pscustomobject]@{ FindingId = 'aaaaaaaaaaaaaaaa' }
        $f2 = [pscustomobject]@{ FindingId = 'bbbbbbbbbbbbbbbb' }
        $id1 = & $script:HtmlModule { param($x) Get-CockpitFindingRowBodyId -Finding $x } $f1
        $id2 = & $script:HtmlModule { param($x) Get-CockpitFindingRowBodyId -Finding $x } $f2
        $id1 | Should -Not -BeExactly $id2
    }
}

Describe 'Cockpit accessibility — CSS focus + skip-link styles' {

    BeforeAll {
        $script:HtmlModule = Get-Module EntraChecks-HTMLReporting
        $script:Css = & $script:HtmlModule { Get-CockpitCss }
    }

    It 'declares a :focus-visible rule for the row header button' {
        $script:Css | Should -Match '\.cockpit-row-header:focus-visible'
    }

    It 'resets default button chrome on .cockpit-row-header' {
        # Without these, browsers paint a bordered grey button that breaks
        # the row layout. Verify each reset is present.
        $script:Css | Should -Match '\.cockpit-row-header\s*\{[^}]*background:\s*transparent'
        $script:Css | Should -Match '\.cockpit-row-header\s*\{[^}]*border:\s*0'
        $script:Css | Should -Match '\.cockpit-row-header\s*\{[^}]*text-align:\s*left'
    }
}

Describe 'Cockpit accessibility — JS toggles aria-expanded' {

    BeforeAll {
        $script:HtmlModule = Get-Module EntraChecks-HTMLReporting
        $script:Js = & $script:HtmlModule { Get-CockpitJavaScript }
    }

    It 'calls setAttribute(''aria-expanded'') inside toggleRow' {
        $script:Js | Should -Match "setAttribute\('aria-expanded'"
    }

    It 'flips between ''true'' and ''false'' string values' {
        $script:Js | Should -Match "expanded \? 'true' : 'false'"
    }
}
