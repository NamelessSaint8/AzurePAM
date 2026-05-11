<#
.SYNOPSIS
    Pester 5 tests for v2 schema flattening into CSV and depth-preserved JSON
    (PR 5 of Central-Finding-Schema-GRC-Plan).

.DESCRIPTION
    Confirms:
    1. ConvertTo-FindingFlatRow produces a stable, flat pscustomobject with
       one scalar column per atomic v2 field plus semicolon-joined columns
       for ControlMappings, Evidence, Tags, and Links.
    2. Export-Csv on the flat-row output produces a usable analyst CSV
       (no `@{...}` cells, deterministic header set).
    3. JSON round-trip preserves the full v2 nested structure
       (Owner, Exception, ReviewStatus, ControlMappings, Evidence,
       RemediationDetail) when emitted with -Depth 15.
    4. Legacy findings (no v2 fields) flatten cleanly to rows with empty
       cells in the v2 columns.

    Run: Invoke-Pester -Path Tests/FlatRow-CsvJson.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force
}

# ============================================================================
# ConvertTo-FindingFlatRow — unit
# ============================================================================

Describe 'ConvertTo-FindingFlatRow — shape and content' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $schemaMod = Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force -PassThru

        $raw = @([pscustomobject]@{
                Time = Get-Date
                CheckName = 'OAuth Consent'
                Type = 'MFA_AdminDisabled'
                Status = 'FAIL'
                Object = 'admin-1'
                Description = 'admin missing MFA'
                Remediation = 'enable MFA'
                Source = 'Internal'
            })
        $normalized = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 'tenant-X' } $raw
        $state = @{
            Findings = @{
                $normalized[0].FindingId = @{
                    Owner = @{ OwnerType = 'Team'; DisplayName = 'Identity Platform'; Email = 'idp@example.com'; DueDate = '2026-06-30' }
                    Exception = @{
                        Status = 'Approved'; Type = 'AcceptedRisk'
                        Approver = 'ciso@example.com'; ApprovedAt = '2026-05-01T00:00:00Z'
                        ExpiresAt = '2027-05-01T00:00:00Z'; Justification = 'compensating control X'
                    }
                    Tags = @('tier-1', 'quarterly-review')
                    Links = @('https://wiki.example.com/finding/ECF-1234')
                }
            }
        }
        $script:V2 = (& $schemaMod { param($n, $s) @($n | ForEach-Object { Merge-FindingState -Finding $_ -State $s }) } $normalized $state)[0]
        $script:FlatRow = ConvertTo-FindingFlatRow -Finding $script:V2
    }

    It 'returns a single pscustomobject' {
        $script:FlatRow | Should -BeOfType [pscustomobject]
    }

    It 'includes the canonical scalar columns (FindingId, Status, Disposition, Source)' {
        $cols = $script:FlatRow.PSObject.Properties.Name
        $cols | Should -Contain 'FindingId'
        $cols | Should -Contain 'Status'
        $cols | Should -Contain 'Disposition'
        $cols | Should -Contain 'Source'
        $cols | Should -Contain 'SchemaVersion'
    }

    It 'flattens Owner into OwnerType / OwnerDisplayName / OwnerEmail / OwnerSource / OwnerDueDate columns' {
        $script:FlatRow.OwnerType | Should -BeExactly 'Team'
        $script:FlatRow.OwnerDisplayName | Should -BeExactly 'Identity Platform'
        $script:FlatRow.OwnerEmail | Should -BeExactly 'idp@example.com'
        $script:FlatRow.OwnerSource | Should -BeExactly 'StateOverride'
        $script:FlatRow.OwnerDueDate | Should -BeExactly '2026-06-30'
    }

    It 'flattens Exception into individual lifecycle columns' {
        $script:FlatRow.ExceptionStatus | Should -BeExactly 'Approved'
        $script:FlatRow.ExceptionType | Should -BeExactly 'AcceptedRisk'
        $script:FlatRow.ExceptionApprover | Should -BeExactly 'ciso@example.com'
        $script:FlatRow.ExceptionApprovedAt | Should -BeExactly '2026-05-01T00:00:00Z'
        $script:FlatRow.ExceptionExpiresAt | Should -BeExactly '2027-05-01T00:00:00Z'
        $script:FlatRow.ExceptionJustification | Should -BeExactly 'compensating control X'
    }

    It 'flattens ReviewStatus into ReviewState / Reviewer / ReviewNotes / NextReviewDate columns' {
        $cols = $script:FlatRow.PSObject.Properties.Name
        $cols | Should -Contain 'ReviewState'
        $cols | Should -Contain 'Reviewer'
        $cols | Should -Contain 'ReviewNotes'
        $cols | Should -Contain 'NextReviewDate'
    }

    It 'semicolon-joins ControlMappings into ControlMappingsFlat (Framework:ControlId pairs)' {
        # MFA_AdminDisabled maps to multiple CIS controls. The flat column
        # should join them with ; — at minimum one CIS_M365 entry.
        $script:FlatRow.ControlMappingsFlat | Should -Match 'CIS_M365:'
    }

    It 'semicolon-joins Evidence into EvidenceIds + EvidenceSources + EvidenceRedactionStatuses' {
        $script:FlatRow.EvidenceIds | Should -Match '^EVID-[0-9a-f]{16}'
        $script:FlatRow.EvidenceSources | Should -BeExactly 'Internal'
        $script:FlatRow.EvidenceRedactionStatuses | Should -BeExactly 'RawPayloadExcluded'
    }

    It 'joins Tags + Links with semicolons' {
        $script:FlatRow.TagsFlat | Should -BeExactly 'tier-1;quarterly-review'
        $script:FlatRow.LinksFlat | Should -BeExactly 'https://wiki.example.com/finding/ECF-1234'
    }

    It 'contains zero nested objects (no @{...} stringification when CSV-exported)' {
        # Every property value must be a scalar (string / int / datetime).
        # If any are PSCustomObject/Hashtable, Export-Csv would render @{...}.
        foreach ($p in $script:FlatRow.PSObject.Properties) {
            if ($null -eq $p.Value) { continue }
            $t = $p.Value.GetType().Name
            $t | Should -Not -BeIn @('PSCustomObject', 'Hashtable', 'OrderedDictionary')
            # Arrays would also CSV-stringify to System.Object[] — must not
            # be present (the flat row joins them with `;` instead).
            ($p.Value -is [array]) | Should -BeFalse
        }
    }
}

# ============================================================================
# ConvertTo-FindingFlatRow — legacy findings
# ============================================================================

Describe 'ConvertTo-FindingFlatRow — legacy findings degrade cleanly' {

    BeforeAll {
        $legacy = [pscustomobject]@{
            Time = Get-Date
            CheckName = 'X'
            Type = 'Default'
            Status = 'WARNING'
            Object = 'legacy-1'
            Description = 'no v2 fields'
            Remediation = 'fix'
            Source = 'Internal'
        }
        $script:LegacyRow = ConvertTo-FindingFlatRow -Finding $legacy
    }

    It 'still returns a flat row with all v2 columns populated as empty strings' {
        $cols = $script:LegacyRow.PSObject.Properties.Name
        $cols | Should -Contain 'OwnerDisplayName'
        $cols | Should -Contain 'ExceptionStatus'
        $cols | Should -Contain 'ControlMappingsFlat'
        $script:LegacyRow.OwnerDisplayName | Should -BeExactly ''
        $script:LegacyRow.ExceptionStatus | Should -BeExactly ''
        $script:LegacyRow.ControlMappingsFlat | Should -BeExactly ''
    }
}

# ============================================================================
# Export-Csv end-to-end
# ============================================================================

Describe 'Export-Csv on flat rows produces an analyst-grade CSV' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $schemaMod = Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force -PassThru

        $raw = @(
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'O'; Type = 'MFA_AdminDisabled'; Status = 'FAIL'; Object = 'admin-1'; Description = 'd1'; Remediation = 'r'; Source = 'Internal' }),
            ([pscustomobject]@{ Time = Get-Date; CheckName = 'O'; Type = 'AppConsent_UserAllowed'; Status = 'REVIEW'; Object = 'oauth-1'; Description = 'd2'; Remediation = 'r'; Source = 'Internal' })
        )
        $normalized = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $raw
        $script:CsvPath = Join-Path $TestDrive 'flat.csv'
        $normalized | ConvertTo-FindingFlatRow | Export-Csv -Path $script:CsvPath -NoTypeInformation -Encoding UTF8
        $script:CsvText = Get-Content $script:CsvPath -Raw
        $script:CsvRows = Import-Csv $script:CsvPath
    }

    It 'writes both rows with the expected FindingId pattern' {
        @($script:CsvRows).Count | Should -Be 2
        $script:CsvRows[0].FindingId | Should -Match '^ECF-[0-9a-f]{20}$'
    }

    It 'contains no "@{" sequences (no nested-object stringification)' {
        $script:CsvText | Should -Not -Match '@\{'
    }

    It 'has stable header set including v2 flattened columns' {
        $headers = $script:CsvRows[0].PSObject.Properties.Name
        $headers | Should -Contain 'Disposition'
        $headers | Should -Contain 'OwnerType'
        $headers | Should -Contain 'ExceptionStatus'
        $headers | Should -Contain 'ControlMappingsFlat'
        $headers | Should -Contain 'EvidenceIds'
    }
}

# ============================================================================
# JSON round-trip
# ============================================================================

Describe 'JSON emission preserves v2 nested structure at depth 15' {

    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $schemaMod = Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force -PassThru

        $raw = @([pscustomobject]@{ Time = Get-Date; CheckName = 'O'; Type = 'MFA_AdminDisabled'; Status = 'FAIL'; Object = 'admin-1'; Description = 'd'; Remediation = 'r'; Source = 'Internal' })
        $normalized = & $schemaMod { param($b) $b | ConvertTo-EntraFindingV2 -DefaultTenantId 't' } $raw
        $state = @{
            Findings = @{
                $normalized[0].FindingId = @{
                    Owner = @{ OwnerType = 'Team'; DisplayName = 'IDP'; Email = 'idp@example.com' }
                    Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = '2027-01-01T00:00:00Z'; Justification = 'rationale' }
                }
            }
        }
        $script:V2 = (& $schemaMod { param($n, $s) @($n | ForEach-Object { Merge-FindingState -Finding $_ -State $s }) } $normalized $state)
        $script:JsonText = $script:V2 | ConvertTo-Json -Depth 15
        $script:Roundtrip = $script:JsonText | ConvertFrom-Json
    }

    It 'preserves Owner.DisplayName through round-trip' {
        $script:Roundtrip.Owner.DisplayName | Should -BeExactly 'IDP'
        $script:Roundtrip.Owner.Email | Should -BeExactly 'idp@example.com'
    }

    It 'preserves Exception lifecycle metadata through round-trip' {
        $script:Roundtrip.Exception.Status | Should -BeExactly 'Approved'
        $script:Roundtrip.Exception.Type | Should -BeExactly 'AcceptedRisk'
        $script:Roundtrip.Exception.Justification | Should -BeExactly 'rationale'
    }

    It 'preserves ControlMappings array (length > 0 for a mapped finding)' {
        @($script:Roundtrip.ControlMappings).Count | Should -BeGreaterThan 0
    }

    It 'preserves Evidence array with EvidenceId + Hash + RedactionStatus' {
        $ev = @($script:Roundtrip.Evidence)
        $ev.Count | Should -BeGreaterOrEqual 1
        $ev[0].EvidenceId | Should -Match '^EVID-[0-9a-f]{16}$'
        $ev[0].RedactionStatus | Should -BeExactly 'RawPayloadExcluded'
    }

    It 'includes SchemaVersion=2.0 on the finding' {
        $script:Roundtrip.SchemaVersion | Should -BeExactly '2.0'
    }
}
