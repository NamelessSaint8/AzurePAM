<#
.SYNOPSIS
    End-to-end walkthrough of the v2 finding schema's analyst-state workflow.

.DESCRIPTION
    Demonstrates the lifecycle an analyst follows when working with the
    central finding schema:

      1. Run / load a set of findings.
      2. Normalize to v2 (FindingId, Disposition, defaults).
      3. Read each finding's FindingId — the stable handle used in the state file.
      4. Author a local state file assigning Owner, Exception, ReviewStatus
         entries by FindingId.
      5. Re-run the normalizer with the state file path, observe the overlays.
      6. Confirm raw assessment fields (Status, Source, Description) are
         unchanged — only analyst-owned fields update.
      7. Show what Get-FindingDisposition computes for each derived case.

    This is a synthetic demo — it runs entirely on locally constructed
    findings, no Graph / Azure calls. Safe to execute on any machine with the
    EntraChecks repo cloned.

.NOTES
    Module: EntraChecks-FindingSchema.psm1
    Plan:   plans/Central-Finding-Schema-GRC-Plan.md
    Guide:  docs/Finding-Schema-Guide.md

.EXAMPLE
    pwsh -File Examples/Example-FindingState.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Locate the repo root from this script's path.
$repoRoot = Split-Path -Parent $PSScriptRoot

Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-FindingSchema.psm1') -Force

Write-Host "`n=== Step 1: Build a synthetic batch of legacy findings ===" -ForegroundColor Cyan

$legacyBatch = @(
    [pscustomobject]@{
        Time = Get-Date
        CheckName = 'OAuth Consent'
        Type = 'MFA_AdminDisabled'
        Status = 'FAIL'
        Object = 'admin-1@contoso.example'
        ObjectId = '00000000-0000-0000-0000-000000000001'
        Description = 'Admin account has no MFA registered'
        Remediation = 'Enable MFA for this admin'
        Source = 'Internal'
    },
    [pscustomobject]@{
        Time = Get-Date
        CheckName = 'OAuth Consent'
        Type = 'AppConsent_UserAllowed'
        Status = 'REVIEW'
        Object = 'app-oauth-1'
        ObjectId = '00000000-0000-0000-0000-000000000002'
        Description = 'Third-party app has high-risk Graph scopes'
        Remediation = 'Review whether this application requires these permissions'
        Source = 'Internal'
    },
    [pscustomobject]@{
        Time = Get-Date
        CheckName = 'OAuth Consent'
        Type = 'GuestAccess_Unrestricted'
        Status = 'WARNING'
        Object = 'guest-cleanup-needed'
        ObjectId = '00000000-0000-0000-0000-000000000003'
        Description = 'Guest user inactive 180+ days'
        Remediation = 'Disable or remove stale guest'
        Source = 'Internal'
    }
)

Write-Host "  Constructed $($legacyBatch.Count) legacy findings (no v2 fields yet)." -ForegroundColor Gray

Write-Host "`n=== Step 2: Normalize the batch to v2 ===" -ForegroundColor Cyan

$normalized = $legacyBatch | ConvertTo-EntraFindingV2 -DefaultTenantId 'tenant-A'

foreach ($f in $normalized) {
    "{0,-32} -> {1}  (Status={2}, Disposition={3})" -f $f.Object, $f.FindingId, $f.Status, $f.Disposition | Write-Host
}

Write-Host "`n=== Step 3: Author a synthetic state file ===" -ForegroundColor Cyan

# Use the FindingIds we just generated to target the right entries. In a real
# workflow, the analyst gets these from the previous run's CSV/Excel/JSON
# export (every report surface emits FindingId).
$adminId = $normalized[0].FindingId
$reviewId = $normalized[1].FindingId
$guestId = $normalized[2].FindingId

$futureIso = (Get-Date).AddMonths(3).ToString('yyyy-MM-ddTHH:mm:ssZ')

$statePayload = [ordered]@{
    Version = '1.0'
    Findings = [ordered]@{
        $adminId = [ordered]@{
            Owner = @{
                OwnerType = 'Team'
                DisplayName = 'Identity Platform'
                Email = 'idp@example.com'
                DueDate = '2026-06-30'
            }
            Tags = @('tier-1')
        }
        $reviewId = [ordered]@{
            ReviewStatus = @{
                State = 'InReview'
                Reviewer = 'analyst@example.com'
                Notes = 'Confirming app owner.'
                NextReviewDate = '2026-05-22'
            }
        }
        $guestId = [ordered]@{
            Exception = @{
                Status = 'Approved'
                Type = 'AcceptedRisk'
                Approver = 'ciso@example.com'
                ApprovedAt = '2026-05-08T20:00:00Z'
                ExpiresAt = $futureIso
                Justification = 'Compensating detection in Defender for Identity covers this.'
            }
        }
    }
}

# Use the cross-platform temp dir — $env:TEMP is Windows-only.
$tempDir = [System.IO.Path]::GetTempPath()
$statePath = Join-Path $tempDir 'finding-state-example.json'
$statePayload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $statePath -Encoding UTF8
Write-Host "  State file written: $statePath" -ForegroundColor Gray

Write-Host "`n=== Step 4: Re-normalize with the state file applied ===" -ForegroundColor Cyan

$withState = Initialize-FindingsForReport -Findings $legacyBatch -DefaultTenantId 'tenant-A' -StateFilePath $statePath

foreach ($f in $withState) {
    "{0,-32} Disposition={1,-18} Owner={2,-30} ExceptionStatus={3}" -f `
        $f.Object, $f.Disposition, $f.Owner.DisplayName, $f.Exception.Status | Write-Host
}

Write-Host "`n=== Step 5: Confirm raw assessment fields are immutable ===" -ForegroundColor Cyan

# Even though we just merged state, every finding's Status/Source/Description
# matches the original. Merge-FindingState's allowlist refuses to overwrite
# raw assessment data.
for ($i = 0; $i -lt $legacyBatch.Count; $i++) {
    $orig = $legacyBatch[$i]
    $now = $withState[$i]
    $sameStatus = ($orig.Status -eq $now.Status)
    $sameSource = ($orig.Source -eq $now.Source)
    $sameDesc = ($orig.Description -eq $now.Description)
    "  {0,-32} immutable: Status={1} Source={2} Description={3}" -f `
        $orig.Object, $sameStatus, $sameSource, $sameDesc | Write-Host
}

Write-Host "`n=== Step 6: Disposition derivation in action ===" -ForegroundColor Cyan

"  admin-1     FAIL + Owner overlay              -> $($withState[0].Disposition)" | Write-Host
"  oauth-1     REVIEW + InReview ReviewStatus    -> $($withState[1].Disposition)" | Write-Host
"  guest       WARNING + Approved Exception      -> $($withState[2].Disposition)" | Write-Host

Write-Host "`n=== Step 7: Inspect a single finding in full v2 form ===" -ForegroundColor Cyan
$withState[2] | ConvertTo-Json -Depth 8 | Write-Host

Write-Host "`nDone. To use this workflow for real:" -ForegroundColor Green
Write-Host "  1. Run an assessment and emit the JSON export (Start-EntraChecks)." -ForegroundColor Gray
Write-Host "  2. Copy config/finding-state.example.json to config/finding-state.local.json (gitignored)." -ForegroundColor Gray
Write-Host "  3. Add Owner / Exception / ReviewStatus entries keyed by FindingId from the JSON export." -ForegroundColor Gray
Write-Host "  4. Re-run the assessment. The next report picks up your overlays automatically." -ForegroundColor Gray
Write-Host "  5. See docs/Finding-Schema-Guide.md for the full reference." -ForegroundColor Gray
