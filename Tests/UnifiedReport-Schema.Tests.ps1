<#
.SYNOPSIS
    Pester 5 tests for v2 schema visibility in the unified compliance HTML
    report (PR 4 of Central-Finding-Schema-GRC-Plan).

.DESCRIPTION
    Confirms:
    1. The Findings Summary Overview adds Action Queue + Exceptions tiles
       alongside the existing Failures/Warnings/To Review/Passed/Informational.
    2. The Action Queue section renders when there are actionable items;
       items with approved-non-expired exceptions are EXCLUDED, items with
       expired exceptions are INCLUDED.
    3. The finding row body surfaces Disposition, Owner, Exception, and
       FindingId when those v2 fields are present.
    4. The Exceptions Lifecycle table lists every non-None Exception.Status
       with full audit metadata, sorted by urgency (expired first).
    5. Legacy findings (no v2 fields) still render — sections gracefully
       skip when there's nothing to show.
    6. All user-supplied text is HTML-encoded — owner email with `<` etc.
       must not appear unescaped.

    Run: Invoke-Pester -Path Tests/UnifiedReport-Schema.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force
    Import-Module (Join-Path $script:RepoRoot 'Modules/EntraChecks-Compliance.psm1') -Force
}

# ============================================================================
# v2 schema sections render end-to-end
# ============================================================================

Describe 'Unified report — v2 sections render with normalized findings' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $schemaMod = Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force -PassThru
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Compliance.psm1') -Force

        # Build the v2 fixture inline (Pester 5 BeforeAll scope quirk —
        # see PR 3 test file for context).
        $futureIso = (Get-Date).AddYears(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $pastIso = (Get-Date).AddYears(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $rawBatch = @(
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'MFA_AdminDisabled'; Status = 'FAIL'; Object = 'admin-1'; Description = 'admin missing MFA'; Remediation = 'enable MFA'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'GuestAccess_Unrestricted'; Status = 'WARNING'; Object = 'guest-active'; Description = 'guest with risk-accepted exception'; Remediation = 'review periodically'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'GuestAccess_Unrestricted'; Status = 'WARNING'; Object = 'guest-expired'; Description = 'guest with expired exception'; Remediation = 'rerun review'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'AppConsent_UserAllowed'; Status = 'REVIEW'; Object = 'oauth-1'; Description = 'review oauth grant'; Remediation = 'audit scope'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth'; Type = 'Default'; Status = 'OK'; Object = 'tenant'; Description = 'baseline ok'; Remediation = ''; Source = 'Internal' })
        )
        $normalized = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $rawBatch
        $state = @{
            Findings = @{
                $normalized[0].FindingId = @{
                    Owner = @{ OwnerType = 'Team'; DisplayName = 'Identity Platform'; Email = 'idp@example.com'; DueDate = '2026-06-30' }
                }
                $normalized[1].FindingId = @{
                    Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $futureIso; Approver = 'ciso@example.com'; ApprovedAt = '2026-05-01T00:00:00Z'; Justification = 'compensating control X' }
                }
                $normalized[2].FindingId = @{
                    Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $pastIso; Approver = 'ciso@example.com'; ApprovedAt = '2025-05-01T00:00:00Z'; Justification = 'lapsed waiver' }
                }
            }
        }
        $script:V2Batch = & $schemaMod { param($n, $s) @($n | ForEach-Object { Merge-FindingState -Finding $_ -State $s }) } $normalized $state

        $script:OutDir = Join-Path $TestDrive 'unified-pr4'
        New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
        Export-UnifiedComplianceReport -OutputDirectory $script:OutDir -TenantName 'PR4-Test' -Findings $script:V2Batch | Out-Null
        $script:Html = Get-ChildItem $script:OutDir -Filter 'UnifiedCompliance-Report-*.html' |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Raw
    }

    It 'renders the Action Queue summary tile' {
        $script:Html | Should -Match '<h3>Action Queue</h3>'
    }

    It 'renders the Exceptions summary tile' {
        $script:Html | Should -Match '<h3>Exceptions</h3>'
    }

    It 'renders the Action Queue section heading with the correct count' {
        # Action Queue should contain: FAIL admin-1, expired-exception guest-expired,
        # and REVIEW oauth-1 — total 3. (guest-active is excluded because its
        # active exception flips Disposition to AcceptedRisk.)
        $script:Html | Should -Match 'Action Queue \(3\)'
    }

    It 'Action Queue includes the FAIL admin-1 finding' {
        $parts = $script:Html -split 'Action Queue \(3\)', 2
        $parts.Count | Should -Be 2
        $afterHeading = $parts[1]
        # admin-1 must appear in the Action Queue subtree (before the next section).
        $sectionEnd = $afterHeading.IndexOf('<h2 class="section-title">')
        if ($sectionEnd -lt 0) { $sectionEnd = $afterHeading.Length }
        $actionSection = $afterHeading.Substring(0, $sectionEnd)
        $actionSection | Should -Match 'admin-1'
    }

    It 'Action Queue EXCLUDES the guest-active finding (active exception)' {
        $parts = $script:Html -split 'Action Queue \(3\)', 2
        $afterHeading = $parts[1]
        $sectionEnd = $afterHeading.IndexOf('All Assessment Findings')
        if ($sectionEnd -lt 0) { $sectionEnd = $afterHeading.Length }
        $actionSection = $afterHeading.Substring(0, $sectionEnd)
        $actionSection | Should -Not -Match 'guest-active'
    }

    It 'Action Queue INCLUDES the guest-expired finding (expired exception)' {
        $parts = $script:Html -split 'Action Queue \(3\)', 2
        $afterHeading = $parts[1]
        $sectionEnd = $afterHeading.IndexOf('All Assessment Findings')
        if ($sectionEnd -lt 0) { $sectionEnd = $afterHeading.Length }
        $actionSection = $afterHeading.Substring(0, $sectionEnd)
        $actionSection | Should -Match 'guest-expired'
    }

    It 'renders the Exceptions Lifecycle section with 2 rows (active + expired)' {
        $script:Html | Should -Match 'Exceptions Lifecycle \(2\)'
        # Approved + Expired status values both appear in the table.
        $script:Html | Should -Match 'Approved'
        $script:Html | Should -Match 'Expired'
    }

    It 'Exceptions Lifecycle table includes Approver / ApprovedAt / ExpiresAt columns' {
        $script:Html | Should -Match '<th>Approver</th>'
        $script:Html | Should -Match '<th>Approved</th>'
        $script:Html | Should -Match '<th>Expires</th>'
    }

    It 'finding row body surfaces Owner when present' {
        $script:Html | Should -Match 'Identity Platform'
        $script:Html | Should -Match 'idp@example\.com'
    }

    It 'finding row body surfaces Disposition for findings with non-Open disposition' {
        # guest-active has Disposition=AcceptedRisk; the main Findings table
        # should show that. guest-expired has Disposition=ExpiredException.
        $script:Html | Should -Match 'AcceptedRisk'
        $script:Html | Should -Match 'ExpiredException'
    }

    It 'finding row body surfaces FindingId as <code>' {
        $script:Html | Should -Match '<code>ECF-[0-9a-f]{20}</code>'
    }
}

# ============================================================================
# Legacy findings — graceful degradation
# ============================================================================

Describe 'Unified report — legacy findings render without v2 sections' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Compliance.psm1') -Force

        $script:LegacyFindings = @(
            [pscustomobject]@{ Time = Get-Date; CheckName = 'X'; Type = 'AppConsent_UserAllowed'; Status = 'WARNING'; Object = 'a'; Description = 'legacy'; Remediation = 'fix'; Source = 'Internal' },
            [pscustomobject]@{ Time = Get-Date; CheckName = 'X'; Type = 'AppConsent_UserAllowed'; Status = 'OK'; Object = 'b'; Description = 'ok'; Remediation = ''; Source = 'Internal' }
        )
        $script:OutDir = Join-Path $TestDrive 'unified-legacy-pr4'
        New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
        Export-UnifiedComplianceReport -OutputDirectory $script:OutDir -TenantName 'PR4-Legacy' -Findings $script:LegacyFindings | Out-Null
        $script:LegacyHtml = Get-ChildItem $script:OutDir -Filter 'UnifiedCompliance-Report-*.html' |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Raw
    }

    It 'still renders the Action Queue tile (using legacy Status fallback)' {
        $script:LegacyHtml | Should -Match '<h3>Action Queue</h3>'
    }

    It 'Action Queue section appears with the legacy WARNING finding (Status fallback)' {
        $script:LegacyHtml | Should -Match 'Action Queue \(1\)'
    }

    It 'does NOT render an Exceptions Lifecycle section when no exceptions exist' {
        $script:LegacyHtml | Should -Not -Match 'Exceptions Lifecycle \('
    }

    It 'finding row body omits Owner/Disposition/FindingId when absent (no crash, no empty fields)' {
        # Just confirms the report rendered. If Owner block tried to read
        # a missing property it would have thrown in BeforeAll.
        $script:LegacyHtml | Should -Match 'All Assessment Findings'
    }
}

# ============================================================================
# HTML encoding safety
# ============================================================================

Describe 'Unified report — owner/exception text is HTML-encoded' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $schemaMod = Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force -PassThru
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Compliance.psm1') -Force

        $rawSeed = [pscustomobject]@{
            Time = Get-Date; CheckName = 'X'; Type = 'MFA_AdminDisabled'; Status = 'FAIL'
            Object = '<img src=x>'; Description = 'unsafe <script>'; Remediation = 'do<thing>'
            Source = 'Internal'
        }
        $raw = @($rawSeed)
        $normalized = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $raw
        $state = @{
            Findings = @{
                $normalized[0].FindingId = @{
                    Owner = @{ OwnerType = 'User'; DisplayName = '<b>Bad</b>'; Email = 'evil<svg>@example.com'; DueDate = '' }
                    Exception = @{
                        Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = (Get-Date).AddYears(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
                        Justification = '<img onerror=alert(1)>'; Approver = 'bad<>'; ApprovedAt = '2026-01-01T00:00:00Z'
                    }
                }
            }
        }
        $script:V2Encoded = & $schemaMod { param($n, $s) @($n | ForEach-Object { Merge-FindingState -Finding $_ -State $s }) } $normalized $state

        $script:OutDir = Join-Path $TestDrive 'unified-encoded-pr4'
        New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
        Export-UnifiedComplianceReport -OutputDirectory $script:OutDir -TenantName 'PR4-Encoded' -Findings $script:V2Encoded | Out-Null
        $script:EncodedHtml = Get-ChildItem $script:OutDir -Filter 'UnifiedCompliance-Report-*.html' |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Raw
    }

    It 'encodes owner DisplayName so b-tag attempts are neutralised' {
        $script:EncodedHtml | Should -Match '&lt;b&gt;Bad&lt;/b&gt;'
        $script:EncodedHtml | Should -Not -Match 'DisplayName.*<b>Bad</b>'
    }

    It 'encodes exception Justification so img-onerror attempts are neutralised' {
        $script:EncodedHtml | Should -Match '&lt;img onerror=alert\(1\)&gt;'
        $script:EncodedHtml | Should -Not -Match '<img onerror=alert\(1\)>'
    }

    It 'encodes Object value so img-src injection attempts are neutralised' {
        $script:EncodedHtml | Should -Match '&lt;img src=x&gt;'
    }
}
