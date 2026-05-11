<#
.SYNOPSIS
    Pester 5 tests for the v2 schema sheets in the Excel workbook
    (PR 3 of Central-Finding-Schema-GRC-Plan).

.DESCRIPTION
    Verifies:
    1. All Findings sheet includes the new v2 columns (FindingId,
       Disposition, Owner, Exception, Review State, Tags).
    2. Analyst Queue sheet contains actionable items only and excludes
       approved-non-expired exceptions, OK, INFO.
    3. Review Queue sheet contains REVIEW-status findings and any with
       ReviewStatus.State in {NeedsReview, InReview, ActionRequired}.
    4. Control Register sheet emits one row per (finding, framework, control).
    5. Evidence Register sheet flattens Evidence rows with redaction status.
    6. Exceptions sheet captures all non-None exception states.
    7. Remediation Plan sheet sorts by PriorityScore desc.
    8. Legacy findings (no v2 fields) degrade gracefully.

    Run: Invoke-Pester -Path Tests/ExcelReporting-Schema.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force
    Import-Module (Join-Path $script:RepoRoot 'Modules/EntraChecks-ExcelReporting.psm1') -Force

    # ImportExcel is required by the workbook builder. End-to-end tests skip
    # when it's not installed.
    $script:HaveImportExcel = $null -ne (Get-Module -ListAvailable ImportExcel)
    if ($script:HaveImportExcel) {
        Import-Module ImportExcel -Force
    }

    # Note: Describe BeforeAlls build the v2 fixture inline rather than via
    # a file-level helper function. Pester 5 doesn't reliably resolve
    # module-imported commands when called from a function defined in a
    # parent BeforeAll — even with re-imports.
}

# ============================================================================
# Helper unit tests — invoked through the module's instance scope. The
# correct call pattern is `& $module { ... } <positional args>`. Note that
# `-ArgumentList` does NOT bind through `& $module` reliably — pass args
# positionally after the script block instead.
# ============================================================================

Describe 'Get-EcfAnyProp / Format-EcfOwnerLabel / Format-EcfExceptionLabel' {

    BeforeAll {
        $script:ExcelModule = Get-Module EntraChecks-ExcelReporting
    }

    It 'Get-EcfAnyProp returns the property value from a pscustomobject' {
        $obj = [pscustomobject]@{ Foo = 'bar' }
        & $script:ExcelModule { param($o) Get-EcfAnyProp $o 'Foo' } $obj | Should -BeExactly 'bar'
    }

    It 'Get-EcfAnyProp returns $null for missing properties (no error)' {
        $obj = [pscustomobject]@{ Foo = 'bar' }
        & $script:ExcelModule { param($o) Get-EcfAnyProp $o 'Baz' } $obj | Should -BeNullOrEmpty
    }

    It 'Get-EcfAnyProp tolerates $null input' {
        & $script:ExcelModule { Get-EcfAnyProp $null 'Anything' } | Should -BeNullOrEmpty
    }

    It 'Format-EcfOwnerLabel returns empty string for Unknown owner' {
        $owner = [pscustomobject]@{ OwnerType = 'Unknown'; DisplayName = ''; Source = 'Unknown' }
        & $script:ExcelModule { param($o) Format-EcfOwnerLabel $o } $owner | Should -BeExactly ''
    }

    It 'Format-EcfOwnerLabel formats a Team owner with email and source' {
        $owner = [pscustomobject]@{ OwnerType = 'Team'; DisplayName = 'IDP'; Email = 'idp@example.com'; UserPrincipalName = ''; Team = ''; Source = 'StateOverride'; Confidence = 'High'; DueDate = '' }
        & $script:ExcelModule { param($o) Format-EcfOwnerLabel $o } $owner | Should -BeExactly 'IDP (idp@example.com) [StateOverride]'
    }

    It 'Format-EcfExceptionLabel returns empty string for None state' {
        $ex = [pscustomobject]@{ Status = 'None'; Type = ''; ExpiresAt = '' }
        & $script:ExcelModule { param($e) Format-EcfExceptionLabel $e } $ex | Should -BeExactly ''
    }

    It 'Format-EcfExceptionLabel formats an Approved exception with expiry' {
        $ex = [pscustomobject]@{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = '2026-08-08T00:00:00Z' }
        & $script:ExcelModule { param($e) Format-EcfExceptionLabel $e } $ex |
            Should -BeExactly 'Approved / AcceptedRisk / expires 2026-08-08T00:00:00Z'
    }
}

# ============================================================================
# Queue filter unit tests
# ============================================================================

Describe 'Test-EcfIsAnalystQueue / Test-EcfIsReviewQueue filters' {

    BeforeAll {
        # Pester 5 + module-imported cmdlets in BeforeAll: the cmdlet IS
        # available via Get-Command but pipe-style calls inside BeforeAll
        # don't always resolve. Workaround: invoke through the module's
        # scope explicitly via `& $module { ... }`.
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $schemaMod = Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force -PassThru
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ExcelReporting.psm1') -Force
        $script:ExcelModule = Get-Module EntraChecks-ExcelReporting
        # schemaMod already captured above via Import-Module -PassThru

        $futureIso = (Get-Date).AddYears(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $pastIso = (Get-Date).AddYears(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $rawBatch = @(
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'MFA_AdminDisabled'; Status = 'FAIL'; Object = 'admin-1'; Description = 'FAIL on admin-1'; Remediation = 'fix'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'GuestAccess_Unrestricted'; Status = 'WARNING'; Object = 'guest-1'; Description = 'WARNING on guest-1'; Remediation = 'fix'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'GuestAccess_Unrestricted'; Status = 'WARNING'; Object = 'guest-2'; Description = 'WARNING on guest-2'; Remediation = 'fix'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'AppConsent_UserAllowed'; Status = 'REVIEW'; Object = 'oauth-1'; Description = 'REVIEW on oauth-1'; Remediation = 'review'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'Default'; Status = 'OK'; Object = 'tenant'; Description = 'OK'; Remediation = ''; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'Default'; Status = 'INFO'; Object = 'info-1'; Description = 'INFO'; Remediation = ''; Source = 'Internal' })
        )
        $normalized = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $rawBatch
        $state = @{
            Findings = @{
                $normalized[1].FindingId = @{ Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $futureIso } }
                $normalized[2].FindingId = @{ Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $pastIso } }
                $normalized[5].FindingId = @{ Tags = @('inventory', 'tier-3') }
            }
        }
        $script:V2Batch = & $schemaMod { param($n, $s) @($n | ForEach-Object { Merge-FindingState -Finding $_ -State $s }) } $normalized $state
    }

    It 'Analyst Queue excludes OK / INFO findings' {
        $okFinding = $script:V2Batch | Where-Object { $_.Status -eq 'OK' } | Select-Object -First 1
        & $script:ExcelModule { param($f) Test-EcfIsAnalystQueue $f } $okFinding | Should -BeFalse
    }

    It 'Analyst Queue excludes findings with approved non-expired exceptions' {
        $excepted = $script:V2Batch | Where-Object { $_.Object -eq 'guest-1' } | Select-Object -First 1
        $excepted.Disposition | Should -BeExactly 'AcceptedRisk'
        & $script:ExcelModule { param($f) Test-EcfIsAnalystQueue $f } $excepted | Should -BeFalse
    }

    It 'Analyst Queue includes findings with EXPIRED exceptions (re-actionable)' {
        $expired = $script:V2Batch | Where-Object { $_.Object -eq 'guest-2' } | Select-Object -First 1
        $expired.Disposition | Should -BeExactly 'ExpiredException'
        & $script:ExcelModule { param($f) Test-EcfIsAnalystQueue $f } $expired | Should -BeTrue
    }

    It 'Analyst Queue includes FAIL findings without exceptions' {
        $failFinding = $script:V2Batch | Where-Object { $_.Status -eq 'FAIL' } | Select-Object -First 1
        & $script:ExcelModule { param($f) Test-EcfIsAnalystQueue $f } $failFinding | Should -BeTrue
    }

    It 'Review Queue includes Status=REVIEW findings' {
        $review = $script:V2Batch | Where-Object { $_.Status -eq 'REVIEW' } | Select-Object -First 1
        & $script:ExcelModule { param($f) Test-EcfIsReviewQueue $f } $review | Should -BeTrue
    }

    It 'Review Queue excludes FAIL findings without ReviewStatus' {
        $failFinding = $script:V2Batch | Where-Object { $_.Status -eq 'FAIL' } | Select-Object -First 1
        & $script:ExcelModule { param($f) Test-EcfIsReviewQueue $f } $failFinding | Should -BeFalse
    }
}

# ============================================================================
# Workbook end-to-end (requires ImportExcel)
# ============================================================================

Describe 'New-EnhancedExcelReport — v2 sheets render end-to-end' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $schemaMod = Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force -PassThru
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ExcelReporting.psm1') -Force

        $script:HaveImportExcel = $null -ne (Get-Module -ListAvailable ImportExcel)
        if (-not $script:HaveImportExcel) { return }
        Import-Module ImportExcel -Force

        # schemaMod already captured above via Import-Module -PassThru
        $futureIso = (Get-Date).AddYears(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $pastIso = (Get-Date).AddYears(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $rawBatch = @(
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'MFA_AdminDisabled'; Status = 'FAIL'; Object = 'admin-1'; Description = 'FAIL on admin-1'; Remediation = 'fix'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'GuestAccess_Unrestricted'; Status = 'WARNING'; Object = 'guest-1'; Description = 'WARNING on guest-1'; Remediation = 'fix'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'GuestAccess_Unrestricted'; Status = 'WARNING'; Object = 'guest-2'; Description = 'WARNING on guest-2'; Remediation = 'fix'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'AppConsent_UserAllowed'; Status = 'REVIEW'; Object = 'oauth-1'; Description = 'REVIEW on oauth-1'; Remediation = 'review'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'Default'; Status = 'OK'; Object = 'tenant'; Description = 'OK'; Remediation = ''; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'Default'; Status = 'INFO'; Object = 'info-1'; Description = 'INFO'; Remediation = ''; Source = 'Internal' })
        )
        $normalized = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $rawBatch
        $state = @{
            Findings = @{
                $normalized[1].FindingId = @{ Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $futureIso } }
                $normalized[2].FindingId = @{ Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $pastIso } }
                $normalized[5].FindingId = @{ Tags = @('inventory', 'tier-3') }
            }
        }
        $script:V2Batch = & $schemaMod { param($n, $s) @($n | ForEach-Object { Merge-FindingState -Finding $_ -State $s }) } $normalized $state

        $tenantInfo = [pscustomobject]@{ TenantName = 'PR3-Test'; TenantId = '00000000-0000-0000-0000-000000000001' }
        $script:OutputPath = Join-Path $TestDrive 'pr3-workbook.xlsx'
        New-EnhancedExcelReport `
            -Findings $script:V2Batch `
            -OutputPath $script:OutputPath `
            -TenantInfo $tenantInfo `
            -UseImportExcel | Out-Null
        $script:Sheets = (Get-ExcelSheetInfo -Path $script:OutputPath).Name
    }

    It 'writes the All Findings sheet' {
        if (-not $script:HaveImportExcel) { Set-ItResult -Skipped -Because 'ImportExcel module not installed'; return }
        $script:Sheets | Should -Contain 'All Findings'
    }

    It 'writes the Analyst Queue sheet with FAIL + expired-exception items' {
        if (-not $script:HaveImportExcel) { Set-ItResult -Skipped -Because 'ImportExcel module not installed'; return }
        $script:Sheets | Should -Contain 'Analyst Queue'
        $rows = Import-Excel -Path $script:OutputPath -WorksheetName 'Analyst Queue'
        @($rows).Count | Should -BeGreaterOrEqual 2
        ($rows | Where-Object { $_.Object -eq 'admin-1' }) | Should -Not -BeNullOrEmpty
        ($rows | Where-Object { $_.Object -eq 'guest-2' }) | Should -Not -BeNullOrEmpty
        ($rows | Where-Object { $_.Object -eq 'guest-1' }) | Should -BeNullOrEmpty
    }

    It 'writes the Review Queue sheet with REVIEW findings' {
        if (-not $script:HaveImportExcel) { Set-ItResult -Skipped -Because 'ImportExcel module not installed'; return }
        $script:Sheets | Should -Contain 'Review Queue'
        $rows = Import-Excel -Path $script:OutputPath -WorksheetName 'Review Queue'
        ($rows | Where-Object { $_.Object -eq 'oauth-1' }) | Should -Not -BeNullOrEmpty
    }

    It 'writes the Control Register sheet with mapped CIS controls' {
        if (-not $script:HaveImportExcel) { Set-ItResult -Skipped -Because 'ImportExcel module not installed'; return }
        $script:Sheets | Should -Contain 'Control Register'
        $rows = Import-Excel -Path $script:OutputPath -WorksheetName 'Control Register'
        @($rows).Count | Should -BeGreaterThan 0
        ($rows | Where-Object { $_.Framework -eq 'CIS_M365' }) | Should -Not -BeNullOrEmpty
    }

    It 'writes the Evidence Register sheet with RedactionStatus column' {
        if (-not $script:HaveImportExcel) { Set-ItResult -Skipped -Because 'ImportExcel module not installed'; return }
        $script:Sheets | Should -Contain 'Evidence Register'
        $rows = Import-Excel -Path $script:OutputPath -WorksheetName 'Evidence Register'
        @($rows).Count | Should -BeGreaterOrEqual @($script:V2Batch).Count
        ($rows | Where-Object { $_.RedactionStatus -eq 'RawPayloadExcluded' }) | Should -Not -BeNullOrEmpty
    }

    It 'writes the Exceptions sheet for non-None exception states' {
        if (-not $script:HaveImportExcel) { Set-ItResult -Skipped -Because 'ImportExcel module not installed'; return }
        $script:Sheets | Should -Contain 'Exceptions'
        $rows = Import-Excel -Path $script:OutputPath -WorksheetName 'Exceptions'
        @($rows).Count | Should -Be 2
    }

    It 'writes the Remediation Plan sheet sorted by Priority Score desc' {
        if (-not $script:HaveImportExcel) { Set-ItResult -Skipped -Because 'ImportExcel module not installed'; return }
        $script:Sheets | Should -Contain 'Remediation Plan'
        $rows = Import-Excel -Path $script:OutputPath -WorksheetName 'Remediation Plan'
        @($rows).Count | Should -BeGreaterOrEqual 1
        $scores = @($rows | ForEach-Object { [double]$_.'Priority Score' })
        $scores[0] | Should -BeGreaterOrEqual $scores[-1]
    }

    It 'All Findings sheet exposes FindingId / Disposition / Owner / Exception / Review State / Tags columns' {
        if (-not $script:HaveImportExcel) { Set-ItResult -Skipped -Because 'ImportExcel module not installed'; return }
        $rows = Import-Excel -Path $script:OutputPath -WorksheetName 'All Findings'
        $headers = $rows[0].PSObject.Properties.Name
        $headers | Should -Contain 'FindingId'
        $headers | Should -Contain 'Disposition'
        $headers | Should -Contain 'Owner'
        $headers | Should -Contain 'Exception'
        $headers | Should -Contain 'Review State'
        $headers | Should -Contain 'Tags'
    }
}

# ============================================================================
# Legacy graceful degradation
# ============================================================================

Describe 'Workbook degrades gracefully for legacy findings' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ExcelReporting.psm1') -Force
        $script:HaveImportExcel = $null -ne (Get-Module -ListAvailable ImportExcel)
        if (-not $script:HaveImportExcel) { return }
        Import-Module ImportExcel -Force

        $tenantInfo = [pscustomobject]@{ TenantName = 'PR3-Test'; TenantId = '00000000-0000-0000-0000-000000000001' }
        $script:LegacyOutput = Join-Path $TestDrive 'legacy.xlsx'
        # Deliberately bypass Initialize-FindingsForReport — simulate an
        # external caller invoking New-EnhancedExcelReport with raw findings.
        $script:LegacyFindings = @(
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'AppConsent_UserAllowed'; Status = 'FAIL'; Object = 'a'; Description = 'FAIL on a'; Remediation = 'fix'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'OAuth Consent'; Type = 'AppConsent_UserAllowed'; Status = 'WARNING'; Object = 'b'; Description = 'WARNING on b'; Remediation = 'fix'; Source = 'Internal' })
        )
        New-EnhancedExcelReport `
            -Findings $script:LegacyFindings `
            -OutputPath $script:LegacyOutput `
            -TenantInfo $tenantInfo `
            -UseImportExcel | Out-Null
        $script:LegacySheets = (Get-ExcelSheetInfo -Path $script:LegacyOutput).Name
    }

    It 'still writes the All Findings sheet without v2 fields' {
        if (-not $script:HaveImportExcel) { Set-ItResult -Skipped -Because 'ImportExcel module not installed'; return }
        $script:LegacySheets | Should -Contain 'All Findings'
    }

    It 'does not error when v2 fields are absent (no exception thrown in BeforeAll)' {
        # If BeforeAll had thrown, this It would fail with a setup error.
        # Reaching here is the assertion.
        $true | Should -BeTrue
    }
}
