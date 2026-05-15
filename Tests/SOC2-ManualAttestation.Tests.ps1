<#
.SYNOPSIS
    Pester 5 tests for the SOC 2 Manual Attestation Workflow
    (plans/SOC2-Audit-Readiness-Plan.md §11.1).

.DESCRIPTION
    Coverage:
      * State machine: valid/invalid transitions, idempotent same-state,
        re-entry edges (Rejected→Requested, Accepted→Requested).
      * Set-SOC2AttestationRecord: purity, auto-stamped dates, field
        overrides, throws on invalid transition.
      * Persistence: import (missing/empty/malformed → empty bucket),
        save round-trip, ControlId keying.
      * v2 mapping: attestation State → ReviewStatus.State, Reviewer /
        Notes / NextReviewDate passthrough.
      * Add-SOC2AttestationToFindings: only MANUAL stubs touched,
        NotStarted default, owner reflected onto v2 Owner.
      * Get-SOC2ManualAttestationRows: tracked state populates columns,
        NotStarted default, owner-hint fallback.
      * End-to-end through Invoke-SOC2Assessment + the SOC 2 report
        (manual-attestation-register section, state badges).
      * Cockpit integration: a non-accepted manual finding appears in
        the analyst cockpit Review Queue; an Accepted one does not.

    Run: Invoke-Pester -Path Tests/SOC2-ManualAttestation.Tests.ps1
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
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2Attestation.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-SOC2Reporting.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force

    function script:Step {
        # Walk a record through a chain of states.
        param([pscustomobject]$Record, [string[]]$States)
        $r = $Record
        foreach ($s in $States) { $r = Set-SOC2AttestationRecord -Record $r -State $s }
        return $r
    }

    # Get-SOC2ManualAttestationRows returns a comma-wrapped array (module
    # convention); @() straight around the call double-wraps a
    # multi-element result. Direct-assign first, then normalise.
    function script:Get-ManualRows {
        param($Catalog, $AttestationState)
        $rows = if ($PSBoundParameters.ContainsKey('AttestationState')) {
            Get-SOC2ManualAttestationRows -Catalog $Catalog -AttestationState $AttestationState
        } else {
            Get-SOC2ManualAttestationRows -Catalog $Catalog
        }
        return @($rows)
    }
}

Describe 'State machine — Test-SOC2AttestationTransition' {

    It 'permits the canonical forward path' {
        Test-SOC2AttestationTransition -From NotStarted -To Requested | Should -BeTrue
        Test-SOC2AttestationTransition -From Requested -To Received  | Should -BeTrue
        Test-SOC2AttestationTransition -From Received -To Reviewed   | Should -BeTrue
        Test-SOC2AttestationTransition -From Reviewed -To Accepted   | Should -BeTrue
        Test-SOC2AttestationTransition -From Reviewed -To Rejected   | Should -BeTrue
    }

    It 'rejects skips and backward jumps' {
        Test-SOC2AttestationTransition -From NotStarted -To Accepted | Should -BeFalse
        Test-SOC2AttestationTransition -From NotStarted -To Received | Should -BeFalse
        Test-SOC2AttestationTransition -From Requested -To Accepted  | Should -BeFalse
        Test-SOC2AttestationTransition -From Accepted -To Reviewed   | Should -BeFalse
    }

    It 'allows idempotent same-state' {
        Test-SOC2AttestationTransition -From Requested -To Requested | Should -BeTrue
    }

    It 'allows re-entry edges (Rejected→Requested, Accepted→Requested)' {
        Test-SOC2AttestationTransition -From Rejected -To Requested | Should -BeTrue
        Test-SOC2AttestationTransition -From Accepted -To Requested | Should -BeTrue
    }

    It 'rejects unknown states' {
        Test-SOC2AttestationTransition -From Bogus -To Requested | Should -BeFalse
        Test-SOC2AttestationTransition -From Requested -To Bogus | Should -BeFalse
    }

    It 'exposes the six canonical states in order' {
        (Get-SOC2AttestationStates) | Should -Be @('NotStarted', 'Requested', 'Received', 'Reviewed', 'Accepted', 'Rejected')
    }
}

Describe 'Set-SOC2AttestationRecord' {

    It 'is pure — input record is not mutated' {
        $r = Get-SOC2DefaultAttestation -ControlId CC1.1
        $null = Set-SOC2AttestationRecord -Record $r -State Requested
        $r.State | Should -BeExactly 'NotStarted'
    }

    It 'auto-stamps RequestedDate / ReceivedDate on entry' {
        $r = Set-SOC2AttestationRecord -Record (Get-SOC2DefaultAttestation -ControlId CC1.1) -State Requested
        $r.RequestedDate | Should -Not -BeNullOrEmpty
        $r2 = Set-SOC2AttestationRecord -Record $r -State Received
        $r2.ReceivedDate | Should -Not -BeNullOrEmpty
        $r2.RequestedDate | Should -BeExactly $r.RequestedDate
    }

    It 'honours explicit field overrides' {
        $r = Set-SOC2AttestationRecord -Record (Get-SOC2DefaultAttestation -ControlId CC1.1) -State Requested -RequestedDate '2026-01-01' -ControlOwner 'HR'
        $r.RequestedDate | Should -BeExactly '2026-01-01'
        $r.ControlOwner | Should -BeExactly 'HR'
    }

    It 'carries reviewer / evidence / next-review through to Accepted' {
        $r = Step -Record (Get-SOC2DefaultAttestation -ControlId CC1.1) -States @('Requested', 'Received')
        $r = Set-SOC2AttestationRecord -Record $r -State Reviewed -Reviewer 'Auditor A' -EvidenceLocation 'sp://x'
        $r = Set-SOC2AttestationRecord -Record $r -State Accepted -NextReviewDate '2027-01-01'
        $r.State | Should -BeExactly 'Accepted'
        $r.Reviewer | Should -BeExactly 'Auditor A'
        $r.EvidenceLocation | Should -BeExactly 'sp://x'
        $r.NextReviewDate | Should -BeExactly '2027-01-01'
    }

    It 'throws on an invalid transition' {
        { Set-SOC2AttestationRecord -Record (Get-SOC2DefaultAttestation -ControlId CC1.1) -State Accepted } |
            Should -Throw -ExpectedMessage '*Invalid attestation transition*'
    }
}

Describe 'Persistence — Import / Save' {

    BeforeEach {
        $script:Tmp = Join-Path $env:TEMP "att-persist-$((Get-Random))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
    }
    AfterEach {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'returns an empty bucket for empty path / missing file' {
        (Import-SOC2AttestationState -Path '').Attestations.Count | Should -Be 0
        (Import-SOC2AttestationState -Path (Join-Path $script:Tmp 'nope.json')).Attestations.Count | Should -Be 0
    }

    It 'returns an empty bucket (and warns) for a malformed file' {
        $bad = Join-Path $script:Tmp 'bad.json'
        'not json {' | Set-Content -LiteralPath $bad
        (Import-SOC2AttestationState -Path $bad -WarningAction SilentlyContinue).Attestations.Count | Should -Be 0
    }

    It 'round-trips a record keyed by ControlId' {
        $path = Join-Path $script:Tmp 'st.json'
        $rec = Set-SOC2AttestationRecord -Record (Get-SOC2DefaultAttestation -ControlId CC1.1 -ControlOwner HR) -State Requested
        Save-SOC2AttestationState -State @{ Attestations = @{ 'CC1.1' = $rec } } -Path $path | Out-Null
        $loaded = Import-SOC2AttestationState -Path $path
        $loaded.Attestations.Count | Should -Be 1
        $loaded.Attestations['CC1.1'].State | Should -BeExactly 'Requested'
        $loaded.Attestations['CC1.1'].ControlOwner | Should -BeExactly 'HR'
    }

    It 'creates the parent directory on save' {
        $nested = Join-Path $script:Tmp 'a/b/st.json'
        Save-SOC2AttestationState -State @{ Attestations = @{} } -Path $nested | Out-Null
        Test-Path $nested | Should -BeTrue
    }
}

Describe 'v2 mapping — ConvertTo-SOC2ReviewStatusFromAttestation' {

    It 'maps lifecycle states to ReviewStatus.State' {
        $map = @{
            NotStarted = 'NeedsReview'; Requested = 'InReview'; Received = 'InReview'
            Reviewed = 'ActionRequired'; Accepted = 'Accepted'; Rejected = 'ActionRequired'
        }
        foreach ($state in $map.Keys) {
            $att = Get-SOC2DefaultAttestation -ControlId CC1.1
            $att.State = $state
            (ConvertTo-SOC2ReviewStatusFromAttestation -Attestation $att).State | Should -BeExactly $map[$state]
        }
    }

    It 'passes Reviewer / NextReviewDate through and embeds evidence in Notes' {
        $att = Get-SOC2DefaultAttestation -ControlId CC1.1
        $att.State = 'Reviewed'; $att.Reviewer = 'Auditor A'; $att.NextReviewDate = '2027-02-01'
        $att.EvidenceLocation = 'sp://evidence'; $att.Notes = 'looks good'
        $rs = ConvertTo-SOC2ReviewStatusFromAttestation -Attestation $att
        $rs.Reviewer | Should -BeExactly 'Auditor A'
        $rs.NextReviewDate | Should -BeExactly '2027-02-01'
        $rs.Notes | Should -BeLike '*sp://evidence*'
        $rs.Notes | Should -BeLike '*looks good*'
    }
}

Describe 'Add-SOC2AttestationToFindings' {

    BeforeAll {
        $script:Catalog = Get-SOC2TSCCatalog -Categories @('CC')
        $script:Stubs = @(Get-SOC2ManualAttestationStubs -Catalog $script:Catalog) |
            ForEach-Object { $_ | ConvertTo-EntraFindingV2 -DefaultTenantId t -DefaultSource SOC2 }
    }

    It 'only touches MANUAL findings' {
        $nonManual = [pscustomobject]@{ CheckName = 'Test-NM'; Type = 'X'; Status = 'FAIL'; Severity = 'High'; Object = 'o'; Description = 'd'; Remediation = 'r'; Category = 'Identity' } | ConvertTo-EntraFindingV2 -DefaultTenantId t
        $before = if ($nonManual.PSObject.Properties['ReviewStatus']) { $nonManual.ReviewStatus.State } else { '' }
        $null = Add-SOC2AttestationToFindings -Findings @($nonManual) -State @{ Attestations = @{} }
        $after = if ($nonManual.PSObject.Properties['ReviewStatus']) { $nonManual.ReviewStatus.State } else { '' }
        $after | Should -BeExactly $before
    }

    It 'defaults missing controls to NotStarted → ReviewStatus NeedsReview' {
        $stubs = $script:Stubs | ForEach-Object { $_.PSObject.Copy() }
        $null = Add-SOC2AttestationToFindings -Findings $stubs -State @{ Attestations = @{} }
        ($stubs | Select-Object -First 1).ReviewStatus.State | Should -BeExactly 'NeedsReview'
    }

    It 'applies recorded state and reflects owner onto the v2 Owner block' {
        $stubs = $script:Stubs | ForEach-Object { $_.PSObject.Copy() }
        $rec = Set-SOC2AttestationRecord -Record (Get-SOC2DefaultAttestation -ControlId CC1.1 -ControlOwner 'HR Lead') -State Requested
        $null = Add-SOC2AttestationToFindings -Findings $stubs -State @{ Attestations = @{ 'CC1.1' = $rec } }
        $cc11 = $stubs | Where-Object { @($_.TSCReferences)[0] -eq 'CC1.1' } | Select-Object -First 1
        $cc11.ReviewStatus.State | Should -BeExactly 'InReview'
        $cc11.Owner.DisplayName | Should -BeExactly 'HR Lead'
    }
}

Describe 'Get-SOC2ManualAttestationRows — tracked state' {

    BeforeAll { $script:Catalog = Get-SOC2TSCCatalog -Categories @('CC') }

    It 'defaults every manual control to NotStarted with no state supplied' {
        $rows = Get-ManualRows -Catalog $script:Catalog
        $rows.Count | Should -BeGreaterThan 0
        ($rows | Where-Object { $_.State -ne 'NotStarted' }).Count | Should -Be 0
        # Owner-hint fallback fills the owner column.
        ($rows | Where-Object { -not $_.ControlOwner }).Count | Should -Be 0
    }

    It 'reflects recorded lifecycle + reviewer/dates' {
        $rec = Step -Record (Get-SOC2DefaultAttestation -ControlId CC1.1 -ControlOwner HR) -States @('Requested', 'Received')
        $rec = Set-SOC2AttestationRecord -Record $rec -State Reviewed -Reviewer 'Auditor A'
        $state = @{ Attestations = @{ 'CC1.1' = $rec } }
        $rows = Get-ManualRows -Catalog $script:Catalog -AttestationState $state
        $cc11 = $rows | Where-Object ControlId -eq 'CC1.1' | Select-Object -First 1
        $cc11.State | Should -BeExactly 'Reviewed'
        $cc11.ControlOwner | Should -BeExactly 'HR'
        $cc11.Reviewer | Should -BeExactly 'Auditor A'
        $cc11.RequestedDate | Should -Not -BeNullOrEmpty
        $cc11.ReceivedDate | Should -Not -BeNullOrEmpty
    }
}

Describe 'End-to-end — Invoke-SOC2Assessment + SOC 2 report' {

    BeforeAll {
        $script:Tmp = Join-Path $env:TEMP "att-e2e-$((Get-Random))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $cc11 = Get-SOC2DefaultAttestation -ControlId CC1.1 -ControlOwner 'HR Lead'
        $cc11 = Step -Record $cc11 -States @('Requested', 'Received', 'Reviewed')
        $cc11 = Set-SOC2AttestationRecord -Record $cc11 -State Accepted -Reviewer 'Auditor A' -NextReviewDate '2027-01-01'
        $cc12 = Set-SOC2AttestationRecord -Record (Get-SOC2DefaultAttestation -ControlId CC1.2 -ControlOwner 'IT Ops') -State Requested
        $stPath = Join-Path $script:Tmp 'st.json'
        Save-SOC2AttestationState -State @{ Attestations = @{ 'CC1.1' = $cc11; 'CC1.2' = $cc12 } } -Path $stPath | Out-Null
        $raw = @([pscustomobject]@{ CheckName = 'Test-X'; Type = 'MFA_Disabled'; Status = 'FAIL'; Severity = 'High'; Object = 'tenant'; Description = 'd'; Remediation = 'r'; Category = 'Identity' })
        $script:Result = Invoke-SOC2Assessment -ExistingFindings $raw -TenantId 't1' -Categories @('CC') `
            -OutputDirectory $script:Tmp -AttestationStatePath $stPath -WarningAction SilentlyContinue
    }
    AfterAll {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'exposes AttestationState on the assessment result' {
        $script:Result.PSObject.Properties.Name | Should -Contain 'AttestationState'
        $script:Result.AttestationState.Attestations.Count | Should -Be 2
    }

    It 'manual findings carry attestation-derived ReviewStatus' {
        $m = @($script:Result.Findings | Where-Object { $_.Status -eq 'MANUAL' })
        $m.Count | Should -BeGreaterThan 1
        $cc11 = $m | Where-Object { @($_.TSCReferences)[0] -eq 'CC1.1' } | Select-Object -First 1
        $cc12 = $m | Where-Object { @($_.TSCReferences)[0] -eq 'CC1.2' } | Select-Object -First 1
        $cc13 = $m | Where-Object { @($_.TSCReferences)[0] -eq 'CC1.3' } | Select-Object -First 1
        $cc11.ReviewStatus.State | Should -BeExactly 'Accepted'      # drops out of queue
        $cc11.Owner.DisplayName  | Should -BeExactly 'HR Lead'
        $cc12.ReviewStatus.State | Should -BeExactly 'InReview'      # in queue
        $cc13.ReviewStatus.State | Should -BeExactly 'NeedsReview'   # in queue (no record)
    }

    It 'SOC 2 report renders the manual-attestation-register with state badges' {
        $htmlPath = Join-Path $script:Tmp 'r.html'
        $null = New-SOC2AuditReport -AssessmentResult $script:Result -OutputPath $htmlPath
        $html = Get-Content -LiteralPath $htmlPath -Raw
        $html | Should -Match 'id="manual-attestation-register"'
        $section = ($html -split 'id="manual-attestation-register"', 2)[1] -split '</section>', 2 | Select-Object -First 1
        $section | Should -Match 'att-badge att-accepted'
        $section | Should -Match 'att-badge att-requested'
        $section | Should -Match 'att-badge att-notstarted'
        $section | Should -Match 'HR Lead'
    }

    It 'manual-attestation register rows (Excel/CSV source) reflect tracked state' {
        $rows = Get-ManualRows -Catalog $script:Result.Catalog -AttestationState $script:Result.AttestationState
        $rows = @($rows)
        ($rows | Where-Object ControlId -eq 'CC1.1' | Select-Object -First 1).State | Should -BeExactly 'Accepted'
        ($rows | Where-Object ControlId -eq 'CC1.2' | Select-Object -First 1).State | Should -BeExactly 'Requested'
    }
}

Describe 'Cockpit Review Queue integration' {

    BeforeAll {
        $script:Tmp = Join-Path $env:TEMP "att-cockpit-$((Get-Random))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $cc11 = Get-SOC2DefaultAttestation -ControlId CC1.1 -ControlOwner 'HR Lead'
        $cc11 = Step -Record $cc11 -States @('Requested', 'Received', 'Reviewed')
        $cc11 = Set-SOC2AttestationRecord -Record $cc11 -State Accepted
        $cc12 = Set-SOC2AttestationRecord -Record (Get-SOC2DefaultAttestation -ControlId CC1.2 -ControlOwner 'IT Ops') -State Requested
        $stPath = Join-Path $script:Tmp 'st.json'
        Save-SOC2AttestationState -State @{ Attestations = @{ 'CC1.1' = $cc11; 'CC1.2' = $cc12 } } -Path $stPath | Out-Null
        $raw = @([pscustomobject]@{ CheckName = 'Test-X'; Type = 'MFA_Disabled'; Status = 'FAIL'; Severity = 'High'; Object = 'tenant'; Description = 'd'; Remediation = 'r'; Category = 'Identity' })
        $r = Invoke-SOC2Assessment -ExistingFindings $raw -TenantId 't1' -Categories @('CC') `
            -OutputDirectory $script:Tmp -AttestationStatePath $stPath -WarningAction SilentlyContinue
        # Render the *analyst cockpit* (the main report) over the SOC 2
        # findings and isolate its Review Queue section.
        $cockpitPath = Join-Path $script:Tmp 'cockpit.html'
        $tenant = [pscustomobject]@{ TenantName = 'AttTest'; TenantId = '00000000-0000-0000-0000-000000000001' }
        $null = New-EntraChecksAnalystHtmlReport -Findings $r.Findings -OutputPath $cockpitPath -TenantInfo $tenant
        $cockpit = Get-Content -LiteralPath $cockpitPath -Raw
        $script:ReviewQueue = ($cockpit -split 'id="review-queue"', 2)[1]
        if ($script:ReviewQueue) { $script:ReviewQueue = ($script:ReviewQueue -split '</section>', 2)[0] }
    }
    AfterAll {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'a non-accepted manual control appears in the cockpit Review Queue' {
        $script:ReviewQueue | Should -Not -BeNullOrEmpty
        # CC1.2 (Requested → InReview) and CC1.3 (NotStarted → NeedsReview)
        # both satisfy the Review Queue predicate.
        $script:ReviewQueue | Should -Match 'CC1\.2'
    }

    It 'an Accepted manual control does NOT appear in the Review Queue' {
        # CC1.1 mapped to ReviewStatus.State=Accepted → excluded by the
        # queue predicate (NeedsReview/InReview/ActionRequired only).
        $script:ReviewQueue | Should -Not -Match 'SOC2_Manual_CC1\.1'
    }
}
