<#
.SYNOPSIS
    Pester 5 integration tests for PR 2 of Central-Finding-Schema-GRC-Plan
    (orchestrator normalization + analyst-state loading + snapshot keying).

.DESCRIPTION
    Exercises the integration seams between the schema module and the rest
    of EntraChecks:

    1. Import-FindingState
       - returns $null when the file is missing
       - returns $null + emits a warning when the file is malformed
       - parses a valid JSON state file and reshapes Findings into a hashtable

    2. Initialize-FindingsForReport
       - normalizes a batch of legacy findings to v2 in one pass
       - idempotent: re-running keeps FindingId stable
       - applies state from -StateFilePath when provided
       - applies state from -ConfigGrc.FindingStatePath when -StateFilePath omitted
       - empty/null inputs return an empty array, not $null
       - failures on individual findings emit warnings but don't abort the batch

    3. Compare-ComplianceSnapshots — FindingId keying upgrade
       - when both snapshots have FindingId, snapshot diff keys by FindingId
       - when either snapshot lacks FindingId, falls back to CheckName|Object
       - FindingId keying survives display-name changes that would break
         the legacy CheckName|Object key

    Run: Invoke-Pester -Path Tests/FindingSchema-Integration.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-DeltaReporting.psm1') -Force

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

    function New-TestSnapshot {
        param(
            [string]$Id,
            [object[]]$Findings
        )
        @{
            SnapshotId = $Id
            CreatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            TenantName = 'IntegrationTest'
            Scores = @{
                SecureScore = $null
                DefenderOverall = $null
                AzurePolicyOverall = $null
                PurviewOverall = $null
            }
            Sources = @{ Findings = @{ Data = $Findings } }
        }
    }
}

# ============================================================================
# Import-FindingState
# ============================================================================

Describe 'Import-FindingState' {

    It 'returns $null when the file path is empty' {
        Import-FindingState -Path '' | Should -BeNullOrEmpty
    }

    It 'returns $null when the file does not exist' {
        $missing = Join-Path $TestDrive ('nope-{0}.json' -f (Get-Random))
        Import-FindingState -Path $missing | Should -BeNullOrEmpty
    }

    It 'returns $null and emits a warning when the file is malformed' {
        $bad = Join-Path $TestDrive 'bad-state.json'
        Set-Content -LiteralPath $bad -Value '{ this is not json'
        $warnings = @()
        $result = Import-FindingState -Path $bad -WarningVariable warnings -WarningAction SilentlyContinue
        $result | Should -BeNullOrEmpty
        $warnings.Count | Should -BeGreaterThan 0
    }

    It 'parses a valid state file and reshapes Findings into a hashtable keyed by FindingId' {
        $good = Join-Path $TestDrive 'good-state.json'
        $payload = @{
            Version = '1.0'
            Findings = @{
                'ECF-1234567890abcdef1234' = @{
                    Owner = @{ OwnerType = 'Team'; DisplayName = 'Identity Platform' }
                }
            }
        } | ConvertTo-Json -Depth 6
        Set-Content -LiteralPath $good -Value $payload

        $result = Import-FindingState -Path $good
        $result | Should -Not -BeNullOrEmpty
        $result.Findings.ContainsKey('ECF-1234567890abcdef1234') | Should -BeTrue
        $entry = $result.Findings['ECF-1234567890abcdef1234']
        $entry.Owner.DisplayName | Should -BeExactly 'Identity Platform'
    }
}

# ============================================================================
# Initialize-FindingsForReport
# ============================================================================

Describe 'Initialize-FindingsForReport' {

    It 'normalizes a batch of legacy findings to v2 in one pass' {
        $batch = @(
            (New-LegacyFinding -Status 'FAIL' -Object 'a'),
            (New-LegacyFinding -Status 'WARNING' -Object 'b'),
            (New-LegacyFinding -Status 'REVIEW' -Object 'c')
        )
        $result = Initialize-FindingsForReport -Findings $batch -DefaultTenantId 't'
        $result.Count | Should -Be 3
        foreach ($f in $result) {
            $f.SchemaVersion | Should -BeExactly '2.0'
            $f.FindingId | Should -Match '^ECF-[0-9a-f]{20}$'
        }
    }

    It 'is idempotent — FindingId is preserved across re-runs' {
        $batch = @((New-LegacyFinding -Object 'app-x'))
        $pass1 = Initialize-FindingsForReport -Findings $batch -DefaultTenantId 't'
        $pass2 = Initialize-FindingsForReport -Findings @($pass1[0]) -DefaultTenantId 't'
        $pass2[0].FindingId | Should -BeExactly $pass1[0].FindingId
    }

    It 'returns an empty array (not $null) for null/empty input' {
        $empty = Initialize-FindingsForReport -Findings @()
        , $empty | Should -BeOfType [array]
        $empty.Count | Should -Be 0
    }

    It 'applies analyst state from -StateFilePath' {
        # Normalize once to obtain a stable FindingId, then write state targeting it.
        $finding = New-LegacyFinding -Object 'state-target'
        $normalized = Initialize-FindingsForReport -Findings @($finding) -DefaultTenantId 't'
        $id = $normalized[0].FindingId
        $statePath = Join-Path $TestDrive 'state.json'
        $payload = @{
            Version = '1.0'
            Findings = @{ $id = @{ Owner = @{ OwnerType = 'Team'; DisplayName = 'IDP' } } }
        } | ConvertTo-Json -Depth 6
        Set-Content -LiteralPath $statePath -Value $payload

        $withState = Initialize-FindingsForReport -Findings @($finding) -DefaultTenantId 't' -StateFilePath $statePath
        $withState[0].Owner.DisplayName | Should -BeExactly 'IDP'
        $withState[0].Owner.Source | Should -BeExactly 'StateOverride'
    }

    It 'falls back to -ConfigGrc.FindingStatePath when -StateFilePath is omitted' {
        $finding = New-LegacyFinding -Object 'cfg-target'
        $normalized = Initialize-FindingsForReport -Findings @($finding) -DefaultTenantId 't'
        $id = $normalized[0].FindingId
        $statePath = Join-Path $TestDrive 'cfg-state.json'
        $payload = @{
            Version = '1.0'
            Findings = @{ $id = @{ Owner = @{ OwnerType = 'User'; DisplayName = 'analyst@example.com' } } }
        } | ConvertTo-Json -Depth 6
        Set-Content -LiteralPath $statePath -Value $payload

        # GRC config block carries the state path
        $grc = [pscustomobject]@{ FindingStatePath = $statePath }
        $result = Initialize-FindingsForReport -Findings @($finding) -DefaultTenantId 't' -ConfigGrc $grc
        $result[0].Owner.DisplayName | Should -BeExactly 'analyst@example.com'
    }

    It 'explicit -StateFilePath wins over -ConfigGrc.FindingStatePath' {
        $finding = New-LegacyFinding -Object 'precedence-target'
        $normalized = Initialize-FindingsForReport -Findings @($finding) -DefaultTenantId 't'
        $id = $normalized[0].FindingId

        $explicitPath = Join-Path $TestDrive 'explicit.json'
        $cfgPath = Join-Path $TestDrive 'cfg.json'
        (@{ Version = '1.0'; Findings = @{ $id = @{ Owner = @{ OwnerType = 'User'; DisplayName = 'Explicit' } } } } | ConvertTo-Json -Depth 6) |
            Set-Content -LiteralPath $explicitPath
        (@{ Version = '1.0'; Findings = @{ $id = @{ Owner = @{ OwnerType = 'User'; DisplayName = 'FromConfig' } } } } | ConvertTo-Json -Depth 6) |
            Set-Content -LiteralPath $cfgPath

        $grc = [pscustomobject]@{ FindingStatePath = $cfgPath }
        $result = Initialize-FindingsForReport -Findings @($finding) -DefaultTenantId 't' -StateFilePath $explicitPath -ConfigGrc $grc
        $result[0].Owner.DisplayName | Should -BeExactly 'Explicit'
    }
}

# ============================================================================
# Snapshot FindingId keying
# ============================================================================

Describe 'Compare-ComplianceSnapshots — FindingId keying (PR 2)' {

    It 'keys by FindingId when both snapshots carry it' {
        $f = (New-LegacyFinding -Object 'shared-app') | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        # Same FindingId in both snapshots, but display Object differs slightly
        # (e.g. a Graph display-name change between runs). Legacy CheckName|Object
        # keying would see this as a remove+add pair; FindingId keying does not.
        $baseline = New-TestSnapshot -Id 'B' -Findings @($f)
        $renamed = $f.PSObject.Copy()
        $renamed.Object = 'shared-app-renamed'
        $current = New-TestSnapshot -Id 'C' -Findings @($renamed)

        $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baseline -CurrentSnapshot $current

        $delta.FindingChanges.NewIssues.Count | Should -Be 0
        $delta.FindingChanges.ResolvedIssues.Count | Should -Be 0
        $delta.Summary.NewIssueCount | Should -Be 0
        $delta.Summary.ResolvedIssueCount | Should -Be 0
    }

    It 'falls back to CheckName|Object when either snapshot is missing FindingId' {
        # Baseline carries FindingId; current snapshot is legacy (no FindingId).
        # Comparator must still produce a sensible diff via the legacy key.
        $v2 = (New-LegacyFinding -Status 'FAIL' -Object 'legacy-app') | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $legacy = [pscustomobject]@{
            CheckName = 'OAuth Consent'
            Object = 'legacy-app'
            Status = 'FAIL'
            Description = 'synthetic'
        }
        $baseline = New-TestSnapshot -Id 'B' -Findings @($v2)
        $current = New-TestSnapshot -Id 'C' -Findings @($legacy)

        $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baseline -CurrentSnapshot $current

        # Fallback keys are equal (same CheckName|Object) — neither new nor resolved.
        $delta.FindingChanges.NewIssues.Count | Should -Be 0
        $delta.FindingChanges.ResolvedIssues.Count | Should -Be 0
    }

    It 'still detects new FAIL findings across snapshots when FindingId differs' {
        $baselineFinding = (New-LegacyFinding -Object 'old') | ConvertTo-EntraFindingV2 -DefaultTenantId 't'
        $brandNew = (New-LegacyFinding -Status 'FAIL' -Object 'new-failure') | ConvertTo-EntraFindingV2 -DefaultTenantId 't'

        $baseline = New-TestSnapshot -Id 'B' -Findings @($baselineFinding)
        $current = New-TestSnapshot -Id 'C' -Findings @($baselineFinding, $brandNew)

        $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baseline -CurrentSnapshot $current

        $delta.FindingChanges.NewIssues.Count | Should -Be 1
        $delta.Summary.NewIssueCount | Should -Be 1
        $delta.FindingChanges.NewIssues[0].Object | Should -BeExactly 'new-failure'
    }
}
