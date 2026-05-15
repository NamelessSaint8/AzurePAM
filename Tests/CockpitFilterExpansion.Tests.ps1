<#
.SYNOPSIS
    Pester 5 tests for the Full Findings filter expansion follow-up to
    HTML-Reporting-Consolidation PR 3.

.DESCRIPTION
    PR 3 of the consolidation plan landed 5 Full Findings filters (text
    search, status, risk, disposition, source). Plan §10.7 specifies a
    larger filter set; this follow-up adds the remaining six:

      - owner             (dropdown from resolved Owner.DisplayName)
      - frameworks        (dropdown; substring/contains-mode for multi-value rows)
      - controls          (text input; substring/contains-mode)
      - exception-status  (dropdown from Exception.Status)
      - review-state      (dropdown from ReviewStatus.State)
      - due-bucket        (fixed dropdown: overdue / due-0-7 / due-8-30 / due-31+ / no-due)

    Tests confirm:
      * Each filter control renders inside the full-findings section.
      * Each row carries the corresponding data-* attribute.
      * Multi-value attributes (frameworks/controls) are space-padded so
        the JS contains-mode match is whole-token.
      * Get-CockpitDueDateBucket computes the right bucket for each cutoff.
      * Legacy findings (no v2 Owner/Exception/ReviewStatus) get safe
        defaults in the new attributes (empty owner, no-due bucket).

    Run: Invoke-Pester -Path Tests/CockpitFilterExpansion.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force
}

# ============================================================================
# Get-CockpitDueDateBucket — bucket boundary math
# ============================================================================

Describe 'Get-CockpitDueDateBucket — bucket math' {

    BeforeAll {
        # The helper is private to EntraChecks-HTMLReporting; invoke through
        # its module instance.
        $script:HtmlModule = Get-Module EntraChecks-HTMLReporting
    }

    It 'returns "no-due" for empty input' {
        & $script:HtmlModule { Get-CockpitDueDateBucket -IsoDate '' } | Should -BeExactly 'no-due'
        & $script:HtmlModule { Get-CockpitDueDateBucket -IsoDate $null } | Should -BeExactly 'no-due'
    }

    It 'returns "no-due" for unparseable input' {
        & $script:HtmlModule { Get-CockpitDueDateBucket -IsoDate 'not-a-date' } | Should -BeExactly 'no-due'
    }

    It 'returns "overdue" for a date in the past' {
        $past = (Get-Date).AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        & $script:HtmlModule { param($d) Get-CockpitDueDateBucket -IsoDate $d } $past | Should -BeExactly 'overdue'
    }

    It 'returns "due-0-7" for a date today or within a week' {
        $soon = (Get-Date).AddDays(3).ToString('yyyy-MM-ddTHH:mm:ssZ')
        & $script:HtmlModule { param($d) Get-CockpitDueDateBucket -IsoDate $d } $soon | Should -BeExactly 'due-0-7'
    }

    It 'returns "due-8-30" for a date in the 8-30 day window' {
        $later = (Get-Date).AddDays(15).ToString('yyyy-MM-ddTHH:mm:ssZ')
        & $script:HtmlModule { param($d) Get-CockpitDueDateBucket -IsoDate $d } $later | Should -BeExactly 'due-8-30'
    }

    It 'returns "due-31+" for a date past the 30-day window' {
        $farOut = (Get-Date).AddDays(60).ToString('yyyy-MM-ddTHH:mm:ssZ')
        & $script:HtmlModule { param($d) Get-CockpitDueDateBucket -IsoDate $d } $farOut | Should -BeExactly 'due-31+'
    }
}

# ============================================================================
# Filter controls present + row attributes correct
# ============================================================================

Describe 'Full Findings filter expansion — controls and row attributes' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $schemaMod = Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force -PassThru
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force

        $futureIso = (Get-Date).AddDays(15).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $pastIso = (Get-Date).AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')

        # Mix of finding shapes the new filters need to handle:
        #   - admin-1: FAIL with Owner + DueDate in 8-30 day window
        #   - guest-active: WARNING with approved-non-expired Exception
        #   - guest-expired: WARNING with expired Exception (ExpiredException disposition)
        #   - oauth-1: REVIEW with NeedsReview state
        #   - tenant: OK baseline, no v2 overlay
        $raw = @(
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'MFA_AdminDisabled'; Status = 'FAIL'; Object = 'admin-1'; Description = 'admin missing MFA'; Remediation = 'enable MFA'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'GuestAccess_Unrestricted'; Status = 'WARNING'; Object = 'guest-active'; Description = 'guest with active exception'; Remediation = 'review'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'GuestAccess_Unrestricted'; Status = 'WARNING'; Object = 'guest-expired'; Description = 'guest with expired exception'; Remediation = 'rerun'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'AppConsent_UserAllowed'; Status = 'REVIEW'; Object = 'oauth-1'; Description = 'review oauth grant'; Remediation = 'audit'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'Default'; Status = 'OK'; Object = 'tenant'; Description = 'baseline'; Remediation = ''; Source = 'Internal' })
        )
        $normalized = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $raw
        $state = @{
            Findings = @{
                $normalized[0].FindingId = @{
                    Owner = @{ OwnerType = 'Team'; DisplayName = 'Identity Platform'; Email = 'idp@example.com'; DueDate = $futureIso }
                }
                $normalized[1].FindingId = @{
                    Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = (Get-Date).AddYears(1).ToString('yyyy-MM-ddTHH:mm:ssZ') }
                }
                $normalized[2].FindingId = @{
                    Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $pastIso }
                }
                $normalized[3].FindingId = @{
                    ReviewStatus = @{ State = 'NeedsReview' }
                }
            }
        }
        $script:Findings = & $schemaMod { param($n, $s) @($n | ForEach-Object { Merge-FindingState -Finding $_ -State $s }) } $normalized $state

        $tenant = [pscustomobject]@{ TenantName = 'FilterExp-Test'; TenantId = '00000000-0000-0000-0000-000000000001' }
        $script:Output = Join-Path $TestDrive 'cockpit-filter-expansion.html'
        New-EntraChecksAnalystHtmlReport `
            -Findings $script:Findings `
            -OutputPath $script:Output `
            -TenantInfo $tenant | Out-Null
        $script:Html = Get-Content $script:Output -Raw
        # Isolate the Full Findings section so assertions don't accidentally
        # match attributes from other sections.
        $script:Ff = ($script:Html -split 'id="full-findings"', 2)[1] -split '</section>', 2 | Select-Object -First 1
    }

    It 'renders all six new filter controls inside the full-findings section' {
        $script:Ff | Should -Match 'data-filter-key="owner"'
        $script:Ff | Should -Match 'data-filter-key="frameworks"'
        $script:Ff | Should -Match 'data-filter-key="controls"'
        $script:Ff | Should -Match 'data-filter-key="exception-status"'
        $script:Ff | Should -Match 'data-filter-key="review-state"'
        $script:Ff | Should -Match 'data-filter-key="due-bucket"'
    }

    It 'frameworks + controls inputs declare data-filter-mode="contains"' {
        # These two attributes use multi-value substring matching in the JS.
        $script:Ff | Should -Match 'data-filter-key="frameworks" data-filter-mode="contains"'
        $script:Ff | Should -Match 'data-filter-key="controls" data-filter-mode="contains"'
    }

    It 'due-bucket dropdown lists the 5 fixed buckets' {
        $script:Ff | Should -Match 'value="overdue">Overdue'
        $script:Ff | Should -Match 'value="due-0-7">Due in 0-7 days'
        $script:Ff | Should -Match 'value="due-8-30">Due in 8-30 days'
        $script:Ff | Should -Match 'value="due-31\+">Due in 31\+ days'
        $script:Ff | Should -Match 'value="no-due">No due date'
    }

    It 'owner dropdown is populated from resolved owners in the data' {
        # admin-1 has Owner.DisplayName = "Identity Platform"; the dropdown
        # is lowercased for value attributes (existing convention).
        $script:Ff | Should -Match 'value="identity platform">Identity Platform'
    }

    It 'rows carry the new data-* attributes' {
        $script:Ff | Should -Match 'data-owner='
        $script:Ff | Should -Match 'data-frameworks='
        $script:Ff | Should -Match 'data-controls='
        $script:Ff | Should -Match 'data-exception-status='
        $script:Ff | Should -Match 'data-review-state='
        $script:Ff | Should -Match 'data-due-bucket='
    }

    It 'admin-1 row carries the team owner name and due-8-30 bucket' {
        # admin-1 has Owner DisplayName 'Identity Platform' and a DueDate 15
        # days from now. Encoded lowercase for the data-owner attribute.
        $adminRow = ($script:Ff -split 'admin-1', 2)[0]
        # The row's data attributes appear BEFORE the cell content "admin-1".
        # Carve the row div out by searching backwards to the previous <div class="cockpit-row".
        $rowStart = $adminRow.LastIndexOf('<div class="cockpit-row"')
        $adminRow = $adminRow.Substring($rowStart)
        $adminRow | Should -Match 'data-owner="identity platform"'
        $adminRow | Should -Match 'data-due-bucket="due-8-30"'
    }

    It 'guest-active row carries data-exception-status="approved"' {
        $row = ($script:Ff -split 'guest-active', 2)[0]
        $rowStart = $row.LastIndexOf('<div class="cockpit-row"')
        $row = $row.Substring($rowStart)
        $row | Should -Match 'data-exception-status="approved"'
    }

    It 'guest-expired row carries data-exception-status="expired" (auto-flipped by merge)' {
        # Merge-FindingState detects approved-with-past-ExpiresAt and flips
        # Exception.Status to 'Expired'. The cockpit attribute reflects that.
        $row = ($script:Ff -split 'guest-expired', 2)[0]
        $rowStart = $row.LastIndexOf('<div class="cockpit-row"')
        $row = $row.Substring($rowStart)
        $row | Should -Match 'data-exception-status="expired"'
    }

    It 'oauth-1 row carries data-review-state="needsreview"' {
        $row = ($script:Ff -split 'oauth-1', 2)[0]
        $rowStart = $row.LastIndexOf('<div class="cockpit-row"')
        $row = $row.Substring($rowStart)
        $row | Should -Match 'data-review-state="needsreview"'
    }

    It 'legacy-style baseline row (OK, no overlays) gets safe defaults' {
        $row = ($script:Ff -split '>tenant<', 2)[0]
        $rowStart = $row.LastIndexOf('<div class="cockpit-row"')
        $row = $row.Substring($rowStart)
        # No Owner overlay → data-owner is empty
        $row | Should -Match 'data-owner=""'
        # No Exception overlay → data-exception-status="none"
        $row | Should -Match 'data-exception-status="none"'
        # No DueDate → no-due bucket
        $row | Should -Match 'data-due-bucket="no-due"'
    }

    It 'framework attribute is space-padded for whole-token JS matching' {
        # MFA_AdminDisabled maps to CIS_M365 controls (among other
        # frameworks). The attribute must (a) start with a space, (b) end
        # with a space, (c) contain " cis_m365 " as a whole-word token.
        # Framework iteration order is hashtable-key order — NOT guaranteed
        # (ConvertTo-ControlMappings enumerates $ComplianceMappings.Keys).
        # The assertion must therefore be position-independent: a padded
        # attribute always wraps every token in spaces, so " cis_m365 "
        # appears as a whole-token substring regardless of where the
        # framework lands in the enumeration. (A previous regex required a
        # token *before* cis_m365 and went flaky whenever it enumerated
        # first — see SOC2 Audit-Readiness PR 1.)
        $row = ($script:Ff -split 'admin-1', 2)[0]
        $rowStart = $row.LastIndexOf('<div class="cockpit-row"')
        $row = $row.Substring($rowStart)
        $row | Should -Match 'data-frameworks=" [^"]*"'
        $row | Should -Match 'data-frameworks="[^"]* cis_m365 [^"]*"'
    }

    It 'controls attribute is space-padded and contains Framework:ControlId tokens' {
        $row = ($script:Ff -split 'admin-1', 2)[0]
        $rowStart = $row.LastIndexOf('<div class="cockpit-row"')
        $row = $row.Substring($rowStart)
        # At least one cis_m365:<control> token present somewhere in the
        # padded attribute.
        $row | Should -Match 'data-controls="[^"]* cis_m365:'
    }
}

# ============================================================================
# JS filter mode wiring — the script block accepts data-filter-mode
# ============================================================================

Describe 'Cockpit JS — data-filter-mode support' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force

        $tenant = [pscustomobject]@{ TenantName = 'JsModeTest'; TenantId = '00000000-0000-0000-0000-000000000001' }
        $script:Output = Join-Path $TestDrive 'cockpit-jsmode.html'
        # Minimal fixture — JS block is independent of finding count.
        $findings = @([pscustomobject]@{ Time = Get-Date; CheckName = 'X'; Type = 'Default'; Status = 'OK'; Object = 'a'; Description = 'd'; Remediation = ''; Source = 'Internal' })
        New-EntraChecksAnalystHtmlReport -Findings $findings -OutputPath $script:Output -TenantInfo $tenant | Out-Null
        $script:Html = Get-Content $script:Output -Raw
    }

    It 'JS reads data-filter-mode for each filter element' {
        $script:Html | Should -Match "getAttribute\('data-filter-mode'\)"
    }

    It 'JS implements the contains-mode whole-token match (space-wrapped indexOf)' {
        # The implementation: rowMulti.indexOf(' ' + needle + ' ') !== -1
        # Pattern below tolerates whitespace variation in the rendered script.
        $script:Html | Should -Match "indexOf\(\s*' '\s*\+\s*needle\s*\+\s*' '\s*\)"
    }
}
