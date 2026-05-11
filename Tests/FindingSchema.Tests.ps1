<#
.SYNOPSIS
    Pester 5 unit tests for EntraChecks-FindingSchema.psm1 (PR 1 of
    Central-Finding-Schema-GRC-Plan).

.DESCRIPTION
    Exercises:
    - Identity (New-EntraFindingId): determinism, case-stability, FindingKey
      uniqueness, format guarantees.
    - Normalization (ConvertTo-EntraFindingV2): legacy -> v2 fill, idempotence,
      preserves immutable fields, derives Disposition.
    - ControlMappings (ConvertTo-ControlMappings): legacy ComplianceMappings
      shape -> flat row array; empty mappings -> empty array (not $null).
    - Evidence (ConvertTo-EvidenceReference): default RawPayloadExcluded,
      secret pattern detection on opt-in raw sample.
    - Owner (Resolve-FindingOwner): full precedence ladder.
    - Disposition (Get-FindingDisposition): all branches in the documented
      derivation order.
    - State merge (Merge-FindingState): allowlisted analyst-owned merge,
      cannot mutate immutable fields, expired exception auto-flips.
    - Validation (Test-EntraFindingV2): structured Errors/Warnings.

    Run: Invoke-Pester -Path Tests/FindingSchema.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force

    function New-LegacyFinding {
        param(
            [string]$Status = 'WARNING',
            [string]$Type = 'AppConsent_UserAllowed',
            [string]$Object = 'app-1',
            [string]$ObjectId = '',
            [string]$Source = 'Internal'
        )
        [pscustomobject]@{
            Time = Get-Date
            CheckName = 'OAuth Consent'
            Type = $Type
            Status = $Status
            Object = $Object
            ObjectId = $ObjectId
            Description = 'synthetic'
            Remediation = 'review or fix'
            Source = $Source
        }
    }
}

# ============================================================================
# Identity
# ============================================================================

Describe 'New-EntraFindingId' {

    It 'returns an ECF-prefixed identifier with 20 lowercase hex chars' {
        $id = New-EntraFindingId -TenantId 'tenant-A' -Source 'Internal' -CheckName 'OAuth Consent' -Type 'AppConsent_UserAllowed' -Object 'app-1'
        $id | Should -Match '^ECF-[0-9a-f]{20}$'
    }

    It 'is deterministic across repeated calls with the same inputs' {
        $a = New-EntraFindingId -TenantId 't' -Source 'Internal' -CheckName 'C' -Type 'T' -Object 'O'
        $b = New-EntraFindingId -TenantId 't' -Source 'Internal' -CheckName 'C' -Type 'T' -Object 'O'
        $a | Should -BeExactly $b
    }

    It 'is case-stable (lowercases tenant/source/casing-insensitive components)' {
        $a = New-EntraFindingId -TenantId 'tenant-A' -Source 'Internal' -CheckName 'OAuth Consent' -Type 'AppConsent_UserAllowed' -Object 'app-1'
        $b = New-EntraFindingId -TenantId 'TENANT-A' -Source 'INTERNAL' -CheckName 'oauth consent' -Type 'AppConsent_UserAllowed' -Object 'APP-1'
        $a | Should -BeExactly $b
    }

    It 'collapses whitespace in CheckName so trivial formatting changes do not fragment IDs' {
        $a = New-EntraFindingId -TenantId 't' -Source 'Internal' -CheckName 'OAuth   Consent' -Type 'T' -Object 'O'
        $b = New-EntraFindingId -TenantId 't' -Source 'Internal' -CheckName ' OAuth Consent ' -Type 'T' -Object 'O'
        $a | Should -BeExactly $b
    }

    It 'differentiates findings with different FindingKey values for the same object/check' {
        $a = New-EntraFindingId -TenantId 't' -Source 'Internal' -CheckName 'C' -Type 'T' -Object 'O' -FindingKey 'k1'
        $b = New-EntraFindingId -TenantId 't' -Source 'Internal' -CheckName 'C' -Type 'T' -Object 'O' -FindingKey 'k2'
        $a | Should -Not -Be $b
    }

    It 'prefers ObjectId over ResourceId over Object for stable identity' {
        # If ObjectId is supplied, ResourceId/Object should not affect the ID.
        $a = New-EntraFindingId -TenantId 't' -Source 'Internal' -CheckName 'C' -Type 'T' -ObjectId '00000000-0000-0000-0000-000000000001' -ResourceId '/sub/x' -Object 'display-A'
        $b = New-EntraFindingId -TenantId 't' -Source 'Internal' -CheckName 'C' -Type 'T' -ObjectId '00000000-0000-0000-0000-000000000001' -ResourceId '/sub/y' -Object 'display-B'
        $a | Should -BeExactly $b
    }

    It 'does NOT include timestamps or risk score (re-runs produce same ID)' {
        # Synthetic: New-EntraFindingId has no -Time / -RiskScore parameters,
        # so this is structurally guaranteed. Confirm by calling twice with a
        # noticeable delay between calls.
        $a = New-EntraFindingId -TenantId 't' -Source 'Internal' -CheckName 'C' -Type 'T' -Object 'O'
        Start-Sleep -Milliseconds 50
        $b = New-EntraFindingId -TenantId 't' -Source 'Internal' -CheckName 'C' -Type 'T' -Object 'O'
        $a | Should -BeExactly $b
    }
}

# ============================================================================
# Normalization
# ============================================================================

Describe 'ConvertTo-EntraFindingV2' {

    It 'fills SchemaVersion=2.0 and ECF FindingId on a legacy finding' {
        $f = New-LegacyFinding | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $f.SchemaVersion | Should -BeExactly '2.0'
        $f.FindingId | Should -Match '^ECF-[0-9a-f]{20}$'
    }

    It 'is idempotent — re-normalizing does not change FindingId' {
        $f = New-LegacyFinding | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $idBefore = $f.FindingId
        $f = $f | ConvertTo-EntraFindingV2
        $f.FindingId | Should -BeExactly $idBefore
    }

    It 'preserves all legacy fields (Time, CheckName, Type, Status, Object, Description, Remediation, Source)' {
        $orig = New-LegacyFinding -Status 'FAIL' -Object 'specific-object'
        $copyTime = $orig.Time
        $f = $orig | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $f.Time        | Should -Be $copyTime
        $f.CheckName   | Should -BeExactly 'OAuth Consent'
        $f.Type        | Should -BeExactly 'AppConsent_UserAllowed'
        $f.Status      | Should -BeExactly 'FAIL'
        $f.Object      | Should -BeExactly 'specific-object'
        $f.Description | Should -BeExactly 'synthetic'
        $f.Remediation | Should -BeExactly 'review or fix'
        $f.Source      | Should -BeExactly 'Internal'
    }

    It 'populates Owner with OwnerType=Unknown when no hint/state provided' {
        $f = New-LegacyFinding | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $f.Owner.OwnerType  | Should -BeExactly 'Unknown'
        $f.Owner.Source     | Should -BeExactly 'Unknown'
        $f.Owner.Confidence | Should -BeExactly 'Unknown'
    }

    It 'sets ReviewStatus.State=NeedsReview for Status=REVIEW findings, New otherwise' {
        $review = New-LegacyFinding -Status 'REVIEW' | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $review.ReviewStatus.State | Should -BeExactly 'NeedsReview'

        $warn = New-LegacyFinding -Status 'WARNING' | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $warn.ReviewStatus.State | Should -BeExactly 'New'
    }

    It 'always emits ControlMappings as an array property (empty for unmapped finding types)' {
        $f = New-LegacyFinding -Type 'UnknownTypeXYZ' | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        # ConvertTo-ControlMappings returns @() for unmapped types — the
        # property exists and is array-shaped, even when zero rows.
        $f.PSObject.Properties.Name | Should -Contain 'ControlMappings'
        , @($f.ControlMappings) | Should -BeOfType [array]
    }

    It 'emits at least one Evidence row by default' {
        $f = New-LegacyFinding | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $f.Evidence.Count | Should -BeGreaterOrEqual 1
        $f.Evidence[0].EvidenceId | Should -Match '^EVID-[0-9a-f]{16}$'
        $f.Evidence[0].RedactionStatus | Should -BeExactly 'RawPayloadExcluded'
    }
}

# ============================================================================
# ControlMappings conversion
# ============================================================================

Describe 'ConvertTo-ControlMappings' {

    It 'returns an empty array for $null input (not $null)' {
        $rows = ConvertTo-ControlMappings -ComplianceMappings $null
        , $rows | Should -BeOfType [array]
        $rows.Count | Should -Be 0
    }

    It 'flattens a CIS_M365 mapping with multiple Controls into one row per control' {
        $cm = @{
            CIS_M365 = @{
                Controls = @('1.1.1', '1.2.3')
                Title = 'Sample title'
                Description = 'Sample desc'
            }
        }
        # ConvertTo-ControlMappings returns the array via -NoEnumerate-style
        # single-item emission (see module). Direct assignment is what the
        # downstream code uses; do not wrap with @().
        $rows = ConvertTo-ControlMappings -ComplianceMappings $cm
        $rows.Count | Should -Be 2
        $rows[0].Framework    | Should -BeExactly 'CIS_M365'
        $rows[0].ControlId    | Should -BeIn @('1.1.1', '1.2.3')
        $rows[0].ControlTitle | Should -BeExactly 'Sample title'
        $rows[0].MappingSource | Should -BeExactly 'EntraChecks'
    }

    It 'maps NIST_CSF.Functions, SOC2.Criteria, PCI_DSS_4.Requirements onto ControlId' {
        $cm = @{
            NIST_CSF = @{ Functions = @('PR.AC-1') }
            SOC2 = @{ Criteria = @('CC6.1') }
            PCI_DSS_4 = @{ Requirements = @('8.3.1') }
        }
        $rows = ConvertTo-ControlMappings -ComplianceMappings $cm
        $byFw = @{}
        foreach ($r in $rows) { $byFw[$r.Framework] = $r }
        $byFw['NIST_CSF'].ControlId  | Should -BeExactly 'PR.AC-1'
        $byFw['SOC2'].ControlId      | Should -BeExactly 'CC6.1'
        $byFw['PCI_DSS_4'].ControlId | Should -BeExactly '8.3.1'
    }

    It 'lifts Description into Requirement when Title is absent' {
        $cm = @{ CIS_M365 = @{ Controls = @('9.9.9'); Description = 'desc-only' } }
        $rows = ConvertTo-ControlMappings -ComplianceMappings $cm
        $rows[0].Requirement | Should -BeExactly 'desc-only'
    }
}

# ============================================================================
# Evidence
# ============================================================================

Describe 'ConvertTo-EvidenceReference' {

    It 'defaults RedactionStatus=RawPayloadExcluded when no RawSample is provided' {
        $ev = ConvertTo-EvidenceReference -Source 'Internal' -TenantId 't'
        $ev.RedactionStatus | Should -BeExactly 'RawPayloadExcluded'
    }

    It 'discards RawSample by default (no opt-in flag) and sets RawPayloadExcluded' {
        $ev = ConvertTo-EvidenceReference -Source 'Internal' -TenantId 't' -RawSample 'Authorization: Bearer abc123def456ghijklmnop'
        $ev.RedactionStatus | Should -BeExactly 'RawPayloadExcluded'
    }

    It 'flips to Redacted when -AllowRawSample is set AND a secret pattern matches' {
        $ev = ConvertTo-EvidenceReference -Source 'Internal' -TenantId 't' `
            -RawSample 'Authorization: Bearer abc123def456ghijklmnop' -AllowRawSample
        $ev.RedactionStatus | Should -BeExactly 'Redacted'
    }

    It 'reports NotRequired when -AllowRawSample is set AND the sample contains no secret' {
        $ev = ConvertTo-EvidenceReference -Source 'Internal' -TenantId 't' `
            -RawSample 'Just a benign description with no token' -AllowRawSample
        $ev.RedactionStatus | Should -BeExactly 'NotRequired'
    }

    It 'sets a stable EvidenceId in the EVID-hex16 format' {
        $ev = ConvertTo-EvidenceReference -Source 'Internal' -TenantId 't' -ResourceId 'r'
        $ev.EvidenceId | Should -Match '^EVID-[0-9a-f]{16}$'
    }

    It 'CapturedAtUtc is ISO-8601 UTC' {
        $ev = ConvertTo-EvidenceReference -Source 'Internal'
        $ev.CapturedAtUtc | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
    }
}

Describe 'Test-EvidenceContainsSecret' {

    It 'detects bearer tokens' {
        Test-EvidenceContainsSecret -Text 'Header: Bearer abcdefghij1234567890mnopqr' | Should -BeTrue
    }

    It 'detects JWT-shaped tokens' {
        Test-EvidenceContainsSecret -Text 'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdef' | Should -BeTrue
    }

    It 'detects PEM private key blocks' {
        Test-EvidenceContainsSecret -Text '-----BEGIN RSA PRIVATE KEY-----' | Should -BeTrue
    }

    It 'detects client_secret-style assignments' {
        Test-EvidenceContainsSecret -Text 'client_secret=abcdefghij1234567890' | Should -BeTrue
    }

    It 'returns false for benign text' {
        Test-EvidenceContainsSecret -Text 'A normal sentence about a configuration value.' | Should -BeFalse
    }

    It 'returns false for empty text' {
        Test-EvidenceContainsSecret -Text '' | Should -BeFalse
    }
}

# ============================================================================
# Owner resolution
# ============================================================================

Describe 'Resolve-FindingOwner — precedence' {

    It 'StateOverride wins over OwnerHint, ResourceTags, and EntraOwners' {
        $state = @{ DisplayName = 'Analyst Pick'; OwnerType = 'User' }
        $hint = 'Hinted Owner'
        $tags = @{ Owner = 'Tag Owner' }
        $entra = @([pscustomobject]@{ DisplayName = 'Entra Owner' })
        $owner = Resolve-FindingOwner -StateOverride $state -OwnerHint $hint -ResourceTags $tags -EntraOwners $entra
        $owner.DisplayName | Should -BeExactly 'Analyst Pick'
        $owner.Source      | Should -BeExactly 'StateOverride'
    }

    It 'OwnerHint wins over ResourceTags and EntraOwners' {
        $owner = Resolve-FindingOwner -OwnerHint 'Hinted' -ResourceTags @{ Owner = 'Tag' } -EntraOwners @([pscustomobject]@{ DisplayName = 'E' })
        $owner.DisplayName | Should -BeExactly 'Hinted'
        $owner.Source      | Should -BeExactly 'OwnerHint'
    }

    It 'ResourceTags wins over EntraOwners' {
        $owner = Resolve-FindingOwner -ResourceTags @{ Owner = 'TagOwner' } -EntraOwners @([pscustomobject]@{ DisplayName = 'E' })
        $owner.DisplayName | Should -BeExactly 'TagOwner'
        $owner.Source      | Should -BeExactly 'AzureTag'
    }

    It 'falls through to Entra owners when only EntraOwners is supplied' {
        $owner = Resolve-FindingOwner -EntraOwners @([pscustomobject]@{ DisplayName = 'E1'; UserPrincipalName = 'e1@x' })
        $owner.DisplayName       | Should -BeExactly 'E1'
        $owner.UserPrincipalName | Should -BeExactly 'e1@x'
        $owner.Source            | Should -BeExactly 'EntraOwner'
    }

    It 'returns Unknown owner when no inputs are supplied' {
        $owner = Resolve-FindingOwner
        $owner.OwnerType | Should -BeExactly 'Unknown'
        $owner.Source    | Should -BeExactly 'Unknown'
    }

    It 'maps CostCenter / BusinessUnit tags to Team OwnerType' {
        $owner = Resolve-FindingOwner -ResourceTags @{ CostCenter = 'CC-1234' }
        $owner.OwnerType | Should -BeExactly 'Team'
        $owner.Team      | Should -BeExactly 'CC-1234'
    }
}

# ============================================================================
# Disposition
# ============================================================================

Describe 'Get-FindingDisposition — derivation order' {

    It 'Status=OK -> Passing' {
        Get-FindingDisposition -Status 'OK' | Should -BeExactly 'Passing'
    }

    It 'Status=INFO -> Informational' {
        Get-FindingDisposition -Status 'INFO' | Should -BeExactly 'Informational'
    }

    It 'approved + non-expired exception -> exception type' {
        $future = (Get-Date).AddYears(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $ex = [pscustomobject]@{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $future }
        Get-FindingDisposition -Status 'FAIL' -Exception $ex | Should -BeExactly 'AcceptedRisk'

        $ex2 = [pscustomobject]@{ Status = 'Approved'; Type = 'CompensatingControl'; ExpiresAt = $future }
        Get-FindingDisposition -Status 'FAIL' -Exception $ex2 | Should -BeExactly 'CompensatingControl'
    }

    It 'approved + expired exception -> ExpiredException' {
        $past = (Get-Date).AddYears(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $ex = [pscustomobject]@{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $past }
        Get-FindingDisposition -Status 'FAIL' -Exception $ex | Should -BeExactly 'ExpiredException'
    }

    It 'ReviewStatus.State=Resolved -> Resolved (overrides Status=FAIL)' {
        $rs = [pscustomobject]@{ State = 'Resolved' }
        Get-FindingDisposition -Status 'FAIL' -ReviewStatus $rs | Should -BeExactly 'Resolved'
    }

    It 'ReviewStatus.State=Suppressed -> Suppressed' {
        $rs = [pscustomobject]@{ State = 'Suppressed' }
        Get-FindingDisposition -Status 'FAIL' -ReviewStatus $rs | Should -BeExactly 'Suppressed'
    }

    It 'Status=REVIEW with no analyst state -> Review' {
        Get-FindingDisposition -Status 'REVIEW' | Should -BeExactly 'Review'
    }

    It 'Status=FAIL/WARNING with no other state -> ActionRequired' {
        Get-FindingDisposition -Status 'FAIL'    | Should -BeExactly 'ActionRequired'
        Get-FindingDisposition -Status 'WARNING' | Should -BeExactly 'ActionRequired'
    }
}

# ============================================================================
# State merge
# ============================================================================

Describe 'Merge-FindingState — analyst-owned merge' {

    BeforeAll {
        $script:NormalizedFinding = New-LegacyFinding -Status 'WARNING' -Object 'app-1' -ObjectId '00000000-0000-0000-0000-000000000001' |
            ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $script:FindingId = $script:NormalizedFinding.FindingId
    }

    It 'applies an Owner override from state' {
        $f = $script:NormalizedFinding.PSObject.Copy()
        $state = @{
            Findings = @{
                $script:FindingId = @{
                    Owner = @{ OwnerType = 'Team'; DisplayName = 'Identity Platform'; Email = 'idp@example.com' }
                }
            }
        }
        $f = Merge-FindingState -Finding $f -State $state
        $f.Owner.OwnerType   | Should -BeExactly 'Team'
        $f.Owner.DisplayName | Should -BeExactly 'Identity Platform'
        $f.Owner.Source      | Should -BeExactly 'StateOverride'
    }

    It 'applies an approved Exception and updates Disposition to AcceptedRisk' {
        $f = $script:NormalizedFinding.PSObject.Copy()
        $future = (Get-Date).AddYears(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $state = @{
            Findings = @{
                $script:FindingId = @{
                    Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $future; Justification = 'compensating detection active' }
                }
            }
        }
        $f = Merge-FindingState -Finding $f -State $state
        $f.Exception.Status | Should -BeExactly 'Approved'
        $f.Disposition      | Should -BeExactly 'AcceptedRisk'
    }

    It 'auto-flips an expired Approved exception to Status=Expired and Disposition=ExpiredException' {
        $f = $script:NormalizedFinding.PSObject.Copy()
        $past = (Get-Date).AddYears(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $state = @{
            Findings = @{
                $script:FindingId = @{
                    Exception = @{ Status = 'Approved'; Type = 'AcceptedRisk'; ExpiresAt = $past }
                }
            }
        }
        $f = Merge-FindingState -Finding $f -State $state
        $f.Exception.Status | Should -BeExactly 'Expired'
        $f.Disposition      | Should -BeExactly 'ExpiredException'
    }

    It 'cannot overwrite raw assessment facts (Status, RiskScore, Source, Description)' {
        $f = $script:NormalizedFinding.PSObject.Copy()
        $beforeStatus = $f.Status
        $beforeSource = $f.Source
        $beforeDescription = $f.Description
        # Malicious state attempts to mutate immutables — only allowlisted
        # sections (Owner/Exception/ReviewStatus/Tags/Links) are read.
        $state = @{
            Findings = @{
                $script:FindingId = @{
                    Status = 'OK'
                    Source = 'TamperedSource'
                    Description = 'tampered'
                    RiskScore = 0
                    Owner = @{ OwnerType = 'User'; DisplayName = 'real' }
                }
            }
        }
        $f = Merge-FindingState -Finding $f -State $state
        $f.Status      | Should -BeExactly $beforeStatus
        $f.Source      | Should -BeExactly $beforeSource
        $f.Description | Should -BeExactly $beforeDescription
        # But the Owner inside the allowlisted section did apply.
        $f.Owner.DisplayName | Should -BeExactly 'real'
    }

    It 'is a no-op when the FindingId has no entry in state' {
        $f = $script:NormalizedFinding.PSObject.Copy()
        $beforeOwnerType = $f.Owner.OwnerType
        $state = @{ Findings = @{ 'ECF-deadbeef00000000abcd' = @{ Owner = @{ OwnerType = 'Team'; DisplayName = 'X' } } } }
        $f = Merge-FindingState -Finding $f -State $state
        $f.Owner.OwnerType | Should -BeExactly $beforeOwnerType
    }
}

# ============================================================================
# Validation
# ============================================================================

Describe 'Test-EntraFindingV2' {

    It 'returns IsValid=$true for a fully normalized finding' {
        $f = New-LegacyFinding | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $r = Test-EntraFindingV2 -Finding $f
        $r.IsValid | Should -BeTrue
        $r.Errors.Count | Should -Be 0
    }

    It 'flags a missing SchemaVersion as an Error' {
        $f = New-LegacyFinding
        $r = Test-EntraFindingV2 -Finding $f
        $r.IsValid | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match 'SchemaVersion'
    }

    It 'flags a malformed FindingId as an Error' {
        $f = New-LegacyFinding | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $f.FindingId = 'BAD-FORMAT'
        $r = Test-EntraFindingV2 -Finding $f
        $r.IsValid | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match 'FindingId'
    }

    It 'flags an out-of-set Status as an Error' {
        $f = New-LegacyFinding | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $f.Status = 'INVALID'
        $r = Test-EntraFindingV2 -Finding $f
        $r.IsValid | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match 'Status'
    }

    It 'emits a Warning (not Error) for empty TenantId' {
        $f = New-LegacyFinding | ConvertTo-EntraFindingV2
        $r = Test-EntraFindingV2 -Finding $f
        ($r.Warnings -join ' ') | Should -Match 'TenantId'
    }
}
