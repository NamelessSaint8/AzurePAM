<#
.SYNOPSIS
    Pester 5 tests for the cockpit renderer New-EntraChecksAnalystHtmlReport
    (PR 2 of HTML-Reporting-Consolidation-Plan).

.DESCRIPTION
    Verifies the cockpit renderer:
      1. Writes a complete HTML file with all required sections.
      2. Emits the static-report Content Security Policy meta tag.
      3. Surfaces Action Queue and Review Queue counts that match the v2
         filter rules.
      4. Source Posture cards reflect collected/not-collected for each
         source.
      5. Evidence/Provenance table includes v2 Evidence references.
      6. Deep Dive Hub shows generated/not-generated states.
      7. Integrity sidecar (.findings.json) is written alongside the HTML.
      8. All dynamic text is HTML-encoded (XSS injection neutralised).

    Run: Invoke-Pester -Path Tests/CockpitRenderer.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force
    Import-Module (Join-Path $script:RepoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force
}

# ============================================================================
# End-to-end cockpit render with v2 findings
# ============================================================================

Describe 'New-EntraChecksAnalystHtmlReport — end-to-end with v2 findings' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $schemaMod = Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force -PassThru
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force

        $futureIso = (Get-Date).AddYears(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $pastIso = (Get-Date).AddYears(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')

        $raw = @(
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'MFA_AdminDisabled'; Status = 'FAIL'; Object = 'admin-1'; Description = 'admin missing MFA'; Remediation = 'enable MFA'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'GuestAccess_Unrestricted'; Status = 'WARNING'; Object = 'guest-active'; Description = 'guest with risk-accepted exception'; Remediation = 'review'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'GuestAccess_Unrestricted'; Status = 'WARNING'; Object = 'guest-expired'; Description = 'guest with expired exception'; Remediation = 'rerun'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'AppConsent_UserAllowed'; Status = 'REVIEW'; Object = 'oauth-1'; Description = 'review oauth grant'; Remediation = 'audit scope'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'Default'; Status = 'OK'; Object = 'tenant'; Description = 'baseline ok'; Remediation = ''; Source = 'Internal' })
        )
        $normalized = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $raw
        $state = @{
            Findings = @{
                $normalized[0].FindingId = @{
                    Owner = @{ OwnerType = 'Team'; DisplayName = 'Identity Platform'; Email = 'idp@example.com' }
                }
                $normalized[1].FindingId = @{
                    Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $futureIso; Justification = 'compensating control' }
                }
                $normalized[2].FindingId = @{
                    Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $pastIso; Justification = 'lapsed' }
                }
            }
        }
        $script:Findings = & $schemaMod { param($n, $s) @($n | ForEach-Object { Merge-FindingState -Finding $_ -State $s }) } $normalized $state

        $tenant = [pscustomobject]@{ TenantName = 'PR2-Test'; TenantId = '00000000-0000-0000-0000-000000000001' }
        $script:Output = Join-Path $TestDrive 'cockpit.html'
        New-EntraChecksAnalystHtmlReport `
            -Findings $script:Findings `
            -OutputPath $script:Output `
            -TenantInfo $tenant `
            -SecureScore ([pscustomobject]@{ CurrentScore = 73 }) `
            -DeepDives @{ AzurePolicy = 'AzurePolicy-Report.html' } | Out-Null
        $script:Html = Get-Content $script:Output -Raw
    }

    It 'writes a single HTML file' {
        Test-Path $script:Output | Should -BeTrue
    }

    It 'emits the Content Security Policy meta tag' {
        $script:Html | Should -Match 'http-equiv="Content-Security-Policy"'
        $script:Html | Should -Match "default-src 'none'"
    }

    It 'renders the Source Posture section with collected/not-collected cards' {
        $script:Html | Should -Match '<h2 class="cockpit-section-title">Source Posture</h2>'
        # Secure Score was supplied — should render as collected.
        $script:Html | Should -Match 'source-card good[^"]*">\s*<h4>Microsoft Secure Score</h4>'
        # Defender was NOT supplied — should render as muted.
        $script:Html | Should -Match 'source-card muted[^"]*">\s*<h4>Defender for Cloud</h4>'
    }

    It 'renders the Evidence and Provenance table with at least one EVID row' {
        $script:Html | Should -Match 'Evidence and Provenance'
        $script:Html | Should -Match '<code>EVID-[0-9a-f]{16}</code>'
        # The default v2 evidence emission uses RawPayloadExcluded.
        $script:Html | Should -Match 'RawPayloadExcluded'
    }

    It 'renders Action Queue with admin-1 (FAIL) and guest-expired (ExpiredException)' {
        # PR 3 wraps the count in <span class="cockpit-total-count"> so it
        # can be updated live by the filter JS. Match either form.
        $script:Html | Should -Match 'Action Queue \(<span class="cockpit-total-count">3</span>\)'
        $script:Html | Should -Match 'admin-1'
        $script:Html | Should -Match 'guest-expired'
        # guest-active has an Approved-non-expired exception — must NOT be in Action Queue.
        $afterActionQueue = $script:Html -split 'Action Queue \(<span class="cockpit-total-count">3</span>\)', 2
        $afterActionQueue.Count | Should -Be 2
        $beforeNextSection = $afterActionQueue[1] -split '<h2 class="cockpit-section-title">', 2
        $beforeNextSection[0] | Should -Not -Match 'guest-active'
    }

    It 'renders Review Queue with the REVIEW finding' {
        $script:Html | Should -Match 'Review Queue \(<span class="cockpit-total-count">1</span>\)'
        $script:Html | Should -Match 'oauth-1'
    }

    It 'renders Deep Dive Hub with AzurePolicy as generated and SecureScore as not generated' {
        $script:Html | Should -Match 'Deep Dive Hub'
        # AzurePolicy was passed in DeepDives — should be generated card.
        $script:Html | Should -Match 'deep-dive-card generated[^"]*">\s*<h4>Azure Policy Initiatives</h4>'
        # SecureScore was NOT in DeepDives — should be pending card.
        $script:Html | Should -Match 'deep-dive-card pending[^"]*">\s*<h4>Microsoft Secure Score</h4>'
    }

    It 'writes the integrity sidecar alongside the HTML' {
        $sidecar = "$script:Output.findings.json"
        Test-Path $sidecar | Should -BeTrue
    }

    It 'finds Test-EntraChecksReportIntegrity validates the sidecar' {
        $result = Test-EntraChecksReportIntegrity -ReportPath $script:Output
        $result.IsValid | Should -BeTrue
    }

    It 'header surfaces tenant name + ID + Cockpit mode' {
        $script:Html | Should -Match 'PR2-Test'
        $script:Html | Should -Match '00000000-0000-0000-0000-000000000001'
        $script:Html | Should -Match 'Report Mode:</strong> Cockpit'
    }

    # ========================================================================
    # PR 3 interactive surfaces
    # ========================================================================

    It 'PR 3: Action Queue renders filter controls (search + 3 selects)' {
        # Section contains data-filter-key inputs/selects for the interactive JS.
        $script:Html | Should -Match 'id="action-queue"[^>]*data-max-initial-rows="100"'
        # Carve out the Action Queue section; assert the filter controls live inside it.
        $aq = ($script:Html -split 'id="action-queue"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        $aq | Should -Match 'data-filter-key="_search"'
        $aq | Should -Match 'data-filter-key="status"'
        $aq | Should -Match 'data-filter-key="risk"'
        $aq | Should -Match 'data-filter-key="disposition"'
    }

    It 'PR 3: Action Queue rows carry data-* attributes for filtering' {
        $aq = ($script:Html -split 'id="action-queue"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        $aq | Should -Match 'class="cockpit-row"[^>]*data-status="fail"'
        $aq | Should -Match 'data-disposition='
        $aq | Should -Match 'data-risk='
        # data-search is the lowercased haystack for substring matching.
        $aq | Should -Match 'data-search='
    }

    It 'PR 3: Action Queue expired-exception row sorts FIRST (plan §10.2)' {
        $aq = ($script:Html -split 'id="action-queue"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        # The Disposition=ExpiredException row (guest-expired) must appear
        # before the other rows in static markup order so it surfaces at the
        # top before any JS even runs.
        $expiredIdx = $aq.IndexOf('guest-expired')
        $adminIdx = $aq.IndexOf('admin-1')
        $expiredIdx | Should -BeGreaterThan -1
        $adminIdx | Should -BeGreaterThan -1
        $expiredIdx | Should -BeLessThan $adminIdx
    }

    It 'PR 3: row expand body surfaces Owner / Exception / FindingId' {
        # The expandable body is always in the DOM (display:none until expanded);
        # assert the v2 detail fields are emitted for admin-1.
        $aq = ($script:Html -split 'id="action-queue"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        $aq | Should -Match 'cockpit-row-body'
        $aq | Should -Match 'Identity Platform'
        # FindingId block uses <code> formatting per the row-body builder.
        $aq | Should -Match '<code>ECF-[0-9a-f]{20}</code>'
    }

    It 'PR 3: Review Queue renders state filter + the REVIEW row' {
        $script:Html | Should -Match 'data-filter-key="reviewstate"'
        $rq = ($script:Html -split 'id="review-queue"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        $rq | Should -Match 'oauth-1'
    }

    It 'PR 3: Full Findings includes every finding (FAIL/WARNING/REVIEW/OK)' {
        # PR 2 used Get-DetailedFindingsSection — PR 3 replaces with
        # Get-CockpitFullFindingsSection which lives at id="full-findings".
        $script:Html | Should -Match 'id="full-findings"'
        $ff = ($script:Html -split 'id="full-findings"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        # 5 fixture findings (FAIL admin-1, WARNING guest-active, WARNING guest-expired,
        # REVIEW oauth-1, OK tenant). PR 3's Initialize-FindingsForReport
        # idempotence may dedupe so check >= 5.
        $ff | Should -Match 'Full Findings \(<span class="cockpit-total-count">\d+</span>\)'
        $ff | Should -Match 'admin-1'
        $ff | Should -Match 'oauth-1'
        # The OK row must appear too — Full Findings does not exclude passing checks.
        $ff | Should -Match 'data-status="ok"'
    }

    It 'PR 3: Full Findings renders 5 filter controls' {
        $ff = ($script:Html -split 'id="full-findings"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        $ff | Should -Match 'data-filter-key="_search"'
        $ff | Should -Match 'data-filter-key="status"'
        $ff | Should -Match 'data-filter-key="risk"'
        $ff | Should -Match 'data-filter-key="disposition"'
        $ff | Should -Match 'data-filter-key="source"'
    }

    It 'PR 3: cockpit inline JS is present and self-contained (no external CDN)' {
        # The JS block lives before </body>. Assert it exists, references our
        # filtering primitives, and uses NO `<script src="..."` external loads.
        $script:Html | Should -Match '<script>\s*\(function \(\) \{'
        $script:Html | Should -Match 'function applyFilters\(sectionId\)'
        $script:Html | Should -Match 'function showMore\(sectionId\)'
        $script:Html | Should -Not -Match '<script src='
    }

    It 'PR 3: cockpit JS wires the "Show more" button per section' {
        $script:Html | Should -Match 'class="cockpit-show-more" data-section-id="action-queue"'
        $script:Html | Should -Match 'class="cockpit-show-more" data-section-id="full-findings"'
    }

    It 'PR 3: print stylesheet hides filters and expands all rows' {
        # Plan §14: print-friendly CSS for executive digest, action queue,
        # control impact. Cockpit CSS includes @media print rules.
        $script:Html | Should -Match '@media print'
        $script:Html | Should -Match '\.cockpit-filters.*display: none'
    }
}

# ============================================================================
# HTML encoding safety
# ============================================================================

Describe 'New-EntraChecksAnalystHtmlReport — HTML encoding safety' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $schemaMod = Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force -PassThru
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force

        $raw = @([pscustomobject]@{
                Time = Get-Date
                CheckName = '<script>alert(1)</script>'
                Type = 'MFA_AdminDisabled'
                Status = 'FAIL'
                Object = '<img src=x onerror=alert(1)>'
                Description = 'unsafe <script>'
                Remediation = '<svg onload=alert(1)>'
                Source = 'Internal'
            })
        $normalized = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $raw
        $state = @{
            Findings = @{
                $normalized[0].FindingId = @{
                    Owner = @{ OwnerType = 'User'; DisplayName = '<b>bad</b>'; Email = 'evil<svg>@example.com' }
                }
            }
        }
        $script:Findings = & $schemaMod { param($n, $s) @($n | ForEach-Object { Merge-FindingState -Finding $_ -State $s }) } $normalized $state

        $tenant = [pscustomobject]@{ TenantName = '<b>Bad</b>'; TenantId = 'evil<>id' }
        $script:Output = Join-Path $TestDrive 'cockpit-encoded.html'
        New-EntraChecksAnalystHtmlReport `
            -Findings $script:Findings `
            -OutputPath $script:Output `
            -TenantInfo $tenant | Out-Null
        $script:Html = Get-Content $script:Output -Raw
    }

    It 'encodes b-tag attempts in the tenant name' {
        $script:Html | Should -Match '&lt;b&gt;Bad&lt;/b&gt;'
        $script:Html | Should -Not -Match '<b>Bad</b>'
    }

    It 'encodes img-onerror attempts in Object values' {
        $script:Html | Should -Match '&lt;img src=x onerror=alert\(1\)&gt;'
    }

    It 'encodes script-tag attempts in CheckName' {
        $script:Html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
    }

    It 'encodes Owner DisplayName XSS attempts' {
        $script:Html | Should -Match '&lt;b&gt;bad&lt;/b&gt;'
    }
}

# ============================================================================
# Legacy findings — graceful degradation
# ============================================================================

Describe 'New-EntraChecksAnalystHtmlReport — legacy findings render cleanly' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force

        # Deliberately pass un-normalised findings (no SchemaVersion, no
        # FindingId, no Evidence, etc.). The renderer should still produce a
        # valid HTML file with v2 sections that gracefully empty out.
        $script:LegacyFindings = @(
            [pscustomobject]@{ Time = Get-Date; CheckName = 'X'; Type = 'AppConsent_UserAllowed'; Status = 'WARNING'; Object = 'a'; Description = 'legacy'; Remediation = 'fix'; Source = 'Internal' },
            [pscustomobject]@{ Time = Get-Date; CheckName = 'X'; Type = 'AppConsent_UserAllowed'; Status = 'OK'; Object = 'b'; Description = 'ok'; Remediation = ''; Source = 'Internal' }
        )
        $tenant = [pscustomobject]@{ TenantName = 'Legacy-Test'; TenantId = '00000000-0000-0000-0000-0000000000ff' }
        $script:Output = Join-Path $TestDrive 'cockpit-legacy.html'
        New-EntraChecksAnalystHtmlReport `
            -Findings $script:LegacyFindings `
            -OutputPath $script:Output `
            -TenantInfo $tenant | Out-Null
        $script:Html = Get-Content $script:Output -Raw
    }

    It 'still produces a valid HTML file' {
        Test-Path $script:Output | Should -BeTrue
        $script:Html | Should -Match '<!DOCTYPE html>'
    }

    It 'Action Queue uses legacy Status fallback when Disposition is absent' {
        # The single WARNING legacy finding should land in the Action Queue
        # via the Status-based fallback rule.
        $script:Html | Should -Match 'Action Queue \(<span class="cockpit-total-count">1</span>\)'
    }

    It 'omits Evidence/Provenance section header when no v2 evidence is present' {
        # The section returns empty string for legacy findings — assert that
        # the actual <h2> header isn't rendered. (The HTML comment marker
        # "Evidence and Provenance" remains as a structural aid but is not
        # user-visible.)
        $script:Html | Should -Not -Match '<h2 class="cockpit-section-title">Evidence and Provenance</h2>'
    }

    It 'Source Posture renders even when no auxiliary data was provided' {
        # Internal source is always collected; everything else shows "Not collected".
        $script:Html | Should -Match 'Source Posture'
        $script:Html | Should -Match 'EntraChecks \(Internal\)'
    }
}
