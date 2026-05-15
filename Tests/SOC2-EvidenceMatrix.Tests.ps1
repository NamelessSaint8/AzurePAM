<#
.SYNOPSIS
    Pester 5 tests for the SOC 2 Evidence Matrix
    (plans/SOC2-Audit-Readiness-Plan.md PR 3, §10).

.DESCRIPTION
    Covers:
      * Get-SOC2EvidenceFreshness boundary math (29/30/89/90 days,
        empty/unparseable, clock skew).
      * Get-SOC2EvidenceMatrix pivot correctness: one manifest file
        entry → one row, ControlId parsed from the relative path,
        TscFamily joined from the catalog, manifest.json excluded,
        null/missing bundle → empty.
      * RedactionStatus passthrough from the identity-resolution map.
      * HTML report emits <section id="evidence-matrix"> with the
        filter <select> controls and per-row data-em-* attributes.
      * CSV fallback writes 01c-Evidence-Matrix.csv; legacy
        01a/01b/02/03 numbering unchanged.

    Run: Invoke-Pester -Path Tests/SOC2-EvidenceMatrix.Tests.ps1
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

    # UTC-pinned reference time so the freshness boundary asserts are
    # deterministic regardless of the runner's local zone.
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-05-15T00:00:00', [System.DateTimeKind]::Utc)

    function script:New-SyntheticFinding {
        param(
            [string]$Type = 'SOC2_Synthetic',
            [string]$Status = 'FAIL',
            [string]$Severity = 'High',
            [string[]]$TSCReferences = @('CC6.1')
        )
        [pscustomobject]@{
            Type = $Type; Status = $Status; Severity = $Severity
            Description = "synthetic $Type"; Remediation = 'Fix it'
            Object = 'tenant'; CheckName = "Test-$Type"; Category = 'SOC2'
            TSCReferences = $TSCReferences
        }
    }

    # Builds a real evidence bundle on disk (manifest.json) so the matrix
    # exercises the production read path, not a synthetic stub.
    function script:New-RealBundle {
        param([string]$Dir, [string[]]$Categories = @('CC'))
        $findings = @(New-SyntheticFinding -TSCReferences @('CC6.1'))
        $catalog = Get-SOC2TSCCatalog -Categories $Categories
        $summary = Get-SOC2Summary -Findings $findings -Catalog $catalog
        $bundle = New-SOC2EvidenceBundle -Findings $findings -Catalog $catalog `
            -TenantId 't-evmatrix' -Categories $Categories -Summary $summary `
            -OutputDirectory $Dir
        [pscustomobject]@{ Bundle = $bundle; Catalog = $catalog; Summary = $summary; Findings = $findings }
    }

    function script:Get-Matrix {
        param($EvidenceBundle, $ControlCatalog, $IdentityMapPath)
        $m = Get-SOC2EvidenceMatrix -EvidenceBundle $EvidenceBundle -ControlCatalog $ControlCatalog -IdentityMapPath $IdentityMapPath -AsOf $script:Now
        return @($m)
    }
}

Describe 'Get-SOC2EvidenceFreshness — boundary math' {

    It 'is Fresh below 30 days (29d)' {
        Get-SOC2EvidenceFreshness -CollectionTime $script:Now.AddDays(-29).ToString('o') -AsOf $script:Now | Should -BeExactly 'Fresh'
    }
    It 'is Aging at exactly 30 days' {
        Get-SOC2EvidenceFreshness -CollectionTime $script:Now.AddDays(-30).ToString('o') -AsOf $script:Now | Should -BeExactly 'Aging'
    }
    It 'is Aging at 89 days' {
        Get-SOC2EvidenceFreshness -CollectionTime $script:Now.AddDays(-89).ToString('o') -AsOf $script:Now | Should -BeExactly 'Aging'
    }
    It 'is Stale at exactly 90 days' {
        Get-SOC2EvidenceFreshness -CollectionTime $script:Now.AddDays(-90).ToString('o') -AsOf $script:Now | Should -BeExactly 'Stale'
    }
    It 'is Unknown for empty / unparseable input' {
        Get-SOC2EvidenceFreshness -CollectionTime '' -AsOf $script:Now | Should -BeExactly 'Unknown'
        Get-SOC2EvidenceFreshness -CollectionTime 'not-a-date' -AsOf $script:Now | Should -BeExactly 'Unknown'
        Get-SOC2EvidenceFreshness -CollectionTime $null -AsOf $script:Now | Should -BeExactly 'Unknown'
    }
    It 'treats future timestamps (clock skew) as Fresh, not negative' {
        Get-SOC2EvidenceFreshness -CollectionTime $script:Now.AddDays(5).ToString('o') -AsOf $script:Now | Should -BeExactly 'Fresh'
    }
    It 'is timezone-kind safe (Local-kind AsOf vs UTC timestamp)' {
        $localAsOf = [datetime]::SpecifyKind([datetime]'2026-05-15T00:00:00', [System.DateTimeKind]::Local)
        # 40 days old → Aging regardless of the runner's offset.
        Get-SOC2EvidenceFreshness -CollectionTime '2026-04-05T00:00:00Z' -AsOf $localAsOf | Should -BeExactly 'Aging'
    }
}

Describe 'Get-SOC2EvidenceMatrix — pivot correctness' {

    BeforeEach {
        $script:Tmp = Join-Path $env:TEMP "em-pivot-$((Get-Random))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
    }
    AfterEach {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'returns empty for a null bundle' {
        $cat = Get-SOC2TSCCatalog -Categories @('CC')
        (Get-Matrix -EvidenceBundle $null -ControlCatalog $cat).Count | Should -Be 0
    }

    It 'returns empty when the manifest path does not exist' {
        $cat = Get-SOC2TSCCatalog -Categories @('CC')
        $fake = [pscustomobject]@{ ManifestPath = (Join-Path $script:Tmp 'nope/manifest.json') }
        (Get-Matrix -EvidenceBundle $fake -ControlCatalog $cat).Count | Should -Be 0
    }

    It 'emits one row per manifest file entry, ControlId parsed from the path' {
        $b = New-RealBundle -Dir $script:Tmp
        $matrix = Get-Matrix -EvidenceBundle $b.Bundle -ControlCatalog $b.Catalog
        $matrix.Count | Should -BeGreaterThan 0
        # Every CC control gets a controls/<Id>.json artifact.
        $cc61 = $matrix | Where-Object { $_.ControlId -eq 'CC6.1' -and $_.Source -eq 'Automated control capture' }
        @($cc61).Count | Should -Be 1
        $cc61.EvidenceArtifact | Should -BeLike '*CC6.1.json'
        $cc61.TscFamily | Should -BeExactly 'CC'
        $cc61.Hash | Should -Match '^[0-9a-f]{64}$'
        $cc61.AnchorId | Should -BeLike 'soc2-evidence-*'
    }

    It 'never emits a row for manifest.json itself' {
        $b = New-RealBundle -Dir $script:Tmp
        $matrix = Get-Matrix -EvidenceBundle $b.Bundle -ControlCatalog $b.Catalog
        @($matrix | Where-Object { $_.EvidenceArtifact -match 'manifest\.json$' }).Count | Should -Be 0
    }

    It 'maps manual-attestation templates to the Manual source' {
        $b = New-RealBundle -Dir $script:Tmp
        $matrix = Get-Matrix -EvidenceBundle $b.Bundle -ControlCatalog $b.Catalog
        # CC1.1 is a Manual control → has a manual-attestation/.md artifact.
        $manual = $matrix | Where-Object { $_.Source -eq 'Manual attestation template' }
        @($manual).Count | Should -BeGreaterThan 0
        $manual[0].EvidenceArtifact | Should -BeLike '*manual-attestation*'
    }

    It 'reports "Not redacted" when no identity map is supplied' {
        $b = New-RealBundle -Dir $script:Tmp
        $matrix = Get-Matrix -EvidenceBundle $b.Bundle -ControlCatalog $b.Catalog
        ($matrix | Select-Object -First 1).RedactionStatus | Should -BeExactly 'Not redacted'
    }

    It 'reflects the identity-map hash algorithm when redaction ran' {
        $b = New-RealBundle -Dir $script:Tmp
        $idMapPath = Join-Path $script:Tmp 'identity-resolution.json'
        @{ SchemaVersion = '1.0'; HashAlgorithm = 'SHA256'; TenantId = 't'; Entries = @() } |
            ConvertTo-Json | Set-Content -LiteralPath $idMapPath -Encoding UTF8
        $matrix = Get-Matrix -EvidenceBundle $b.Bundle -ControlCatalog $b.Catalog -IdentityMapPath $idMapPath
        ($matrix | Select-Object -First 1).RedactionStatus | Should -BeExactly 'Redacted (SHA256, salted)'
    }

    It 'projects the PR 3 §10.1 column set' {
        $b = New-RealBundle -Dir $script:Tmp
        $row = (Get-Matrix -EvidenceBundle $b.Bundle -ControlCatalog $b.Catalog)[0]
        foreach ($col in @('ControlId', 'TscFamily', 'EvidenceArtifact', 'Source', 'CollectionTime', 'Hash', 'RedactionStatus', 'Freshness', 'AnchorId')) {
            $row.PSObject.Properties.Name | Should -Contain $col
        }
    }
}

Describe 'New-SOC2AuditReport — HTML evidence-matrix section' {

    BeforeEach {
        $script:Tmp = Join-Path $env:TEMP "em-html-$((Get-Random))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
    }
    AfterEach {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'emits <section id="evidence-matrix"> with filter selects + data-em-* rows' {
        $bundleDir = Join-Path $script:Tmp 'bundle'
        $null = New-Item -Path $bundleDir -ItemType Directory -Force
        $b = New-RealBundle -Dir $bundleDir
        $result = [pscustomobject]@{
            Findings = $b.Findings; Catalog = $b.Catalog; Summary = $b.Summary
            Evidence = $b.Bundle; IdentityMapPath = $null
        }
        $htmlPath = Join-Path $script:Tmp 'r.html'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $htmlPath
        $html = Get-Content -LiteralPath $htmlPath -Raw
        $html | Should -Match 'id="evidence-matrix"'
        $section = ($html -split 'id="evidence-matrix"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        $section | Should -Match "data-em-filter='fam'"
        $section | Should -Match "data-em-filter='fresh'"
        $section | Should -Match "data-em-filter='red'"
        $section | Should -Match 'data-em-fam='
        $section | Should -Match 'data-em-fresh='
        $section | Should -Match 'class=.fresh-badge'
    }

    It 'omits the section when there is no evidence bundle' {
        $cat = Get-SOC2TSCCatalog -Categories @('CC')
        $sum = Get-SOC2Summary -Findings @(New-SyntheticFinding) -Catalog $cat
        $result = [pscustomobject]@{
            Findings = @(New-SyntheticFinding); Catalog = $cat; Summary = $sum
            Evidence = $null; IdentityMapPath = $null
        }
        $htmlPath = Join-Path $script:Tmp 'r2.html'
        $null = New-SOC2AuditReport -AssessmentResult $result -OutputPath $htmlPath
        (Get-Content -LiteralPath $htmlPath -Raw) | Should -Not -Match 'id="evidence-matrix"'
    }
}

Describe 'New-SOC2AuditWorkbook — CSV fallback writes 01c-Evidence-Matrix.csv' {

    BeforeEach {
        $script:Tmp = Join-Path $env:TEMP "em-csv-$((Get-Random))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        Mock -ModuleName EntraChecks-SOC2Reporting Get-Module {} -ParameterFilter { $Name -eq 'ImportExcel' -and $ListAvailable }
    }
    AfterEach {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'writes 01c next to 01a/01b; legacy 02/03 numbering unchanged' {
        $bundleDir = Join-Path $script:Tmp 'bundle'
        $null = New-Item -Path $bundleDir -ItemType Directory -Force
        $b = New-RealBundle -Dir $bundleDir
        $result = [pscustomobject]@{
            Findings = $b.Findings; Catalog = $b.Catalog; Summary = $b.Summary
            Evidence = $b.Bundle; IdentityMapPath = $null
        }
        $outDir = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath (Join-Path $script:Tmp 'wb.xlsx')
        (Test-Path (Join-Path $outDir '01a-Control-Conclusions.csv')) | Should -Be $true
        (Test-Path (Join-Path $outDir '01b-Remediation-Plan.csv')) | Should -Be $true
        (Test-Path (Join-Path $outDir '01c-Evidence-Matrix.csv')) | Should -Be $true
        (Test-Path (Join-Path $outDir '02-Summary-by-Category.csv')) | Should -Be $true
        (Test-Path (Join-Path $outDir '03-Control-Register.csv')) | Should -Be $true
    }

    It '01c columns match the Get-SOC2EvidenceMatrix projection' {
        $bundleDir = Join-Path $script:Tmp 'bundle'
        $null = New-Item -Path $bundleDir -ItemType Directory -Force
        $b = New-RealBundle -Dir $bundleDir
        $result = [pscustomobject]@{
            Findings = $b.Findings; Catalog = $b.Catalog; Summary = $b.Summary
            Evidence = $b.Bundle; IdentityMapPath = $null
        }
        $outDir = New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath (Join-Path $script:Tmp 'wb.xlsx')
        $rows = Import-Csv (Join-Path $outDir '01c-Evidence-Matrix.csv')
        $rows[0].PSObject.Properties.Name | Should -Contain 'ControlId'
        $rows[0].PSObject.Properties.Name | Should -Contain 'Freshness'
        $rows[0].PSObject.Properties.Name | Should -Contain 'RedactionStatus'
    }
}
