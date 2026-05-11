# Central Finding Schema (v2.0) Guide

**Module:** `Modules/EntraChecks-FindingSchema.psm1`
**Status:** Stable (PRs 1-5 of `plans/Central-Finding-Schema-GRC-Plan.md`)
**Schema version:** `2.0`

---

## 1. Why does this exist?

Before v2.0, every EntraChecks finding was a thin `[pscustomobject]` with eight fields: `Time`, `CheckName`, `Type`, `Status`, `Object`, `Description`, `Remediation`, `Source`. That was enough to render a status table, but it left every analyst doing the same offline work each audit cycle:

- Re-identifying findings across runs (`CheckName|Object` is unstable across display-name changes).
- Recording who owns a finding outside the tool (Excel + email).
- Tracking risk-acceptance and exception lifecycle by hand.
- Mapping findings to specific framework controls when the auto-mapping is opaque.
- Documenting *which API call produced this finding* for SOC 2 / ISO evidence bundles.

The v2 schema captures all of this in a single, deterministic structure that every report format (Excel, HTML, JSON, CSV) consumes uniformly. Local analyst state (owner / exception / review state) is overlaid at report time without mutating the raw assessment record — audit facts stay immutable.

---

## 2. Schema at a glance

A v2 finding is a `[pscustomobject]` with the legacy eight fields **plus** the new top-level fields below. Legacy code paths that read only the old fields still work — v2 is additive.

| Top-level field | Type | Purpose |
|---|---|---|
| `SchemaVersion` | string `'2.0'` | Identifies the shape |
| `FindingId` | `ECF-<20 hex>` | Deterministic identity (see §3) |
| `FindingKey` | string | Per-check disambiguator for multi-finding objects |
| `ObjectType` / `ObjectId` / `ResourceId` | string | Stable identifiers preferred over display `Object` |
| `TenantId` / `SubscriptionId` | string | Scope context |
| `ControlMappings` | array | Flattened framework rows (see §4) |
| `Evidence` | array | Source / cmdlet / scope / hash / redaction status (see §5) |
| `Owner` | object | Analyst routing metadata (see §6) |
| `Exception` | object | Risk-acceptance workflow (see §7) |
| `ReviewStatus` | object | Human-judgment workflow (see §8) |
| `RemediationDetail` | object | Portal / PowerShell / impact / automation safety (see §9) |
| `Disposition` | string | Derived bucket (see §10) |
| `Tags` / `Links` | arrays | Analyst-supplied labels and links |

The full schema reference lives in [plans/Central-Finding-Schema-GRC-Plan.md](../plans/Central-Finding-Schema-GRC-Plan.md) §5; this guide focuses on what a user / operator needs to know.

---

## 3. FindingId — deterministic identity

`FindingId` is the canonical handle for a finding across runs. It survives display-name renames, casing changes, and trivial formatting differences in `CheckName` — anything that the legacy `CheckName|Object` snapshot key would fragment.

**Format:** `ECF-<first 20 lowercase hex chars of SHA-256>`

**Hash inputs** (lowercased + whitespace-collapsed, then joined with `|`):
1. `TenantId`
2. `Source`
3. `CheckName`
4. `Type`
5. `ObjectType`
6. Most stable object identifier (`ObjectId` if present, else `ResourceId`, else `Object`)
7. `FindingKey` (optional)

**Excluded** — must never affect identity:
- Timestamps (`Time`, evidence `CapturedAtUtc`)
- Risk score
- Remediation text / description
- Owner / Exception / ReviewStatus (analyst workflow doesn't change identity)

**Generating one yourself:**

```powershell
Import-Module .\Modules\EntraChecks-FindingSchema.psm1
$id = New-EntraFindingId `
    -TenantId 'tenant-A' `
    -Source 'Internal' `
    -CheckName 'OAuth Consent' `
    -Type 'AppConsent_UserAllowed' `
    -ObjectId '00000000-0000-0000-0000-000000000001'
# ECF-d8bbd4ad379dae12ef62
```

Two findings differ in identity only when their hash inputs differ. `FindingKey` is the documented escape hatch for checks that legitimately emit multiple findings per object/check pair (e.g. one per credential on the same app).

---

## 4. ControlMappings

The legacy `ComplianceMappings` hashtable groups controls by framework:

```powershell
@{ CIS_M365 = @{ Controls = @('1.1.1', '1.2.3'); Title = ...; Description = ... } }
```

That's opaque to anything wanting a flat list of `(framework, control)` rows. `ControlMappings` is the flattened view:

```powershell
@(
    [pscustomobject]@{ Framework = 'CIS_M365'; ControlId = '1.1.1'; ControlTitle = '...'; Requirement = '...'; AssessmentRole = 'Automated'; MappingSource = 'EntraChecks'; MappingConfidence = 'High' }
    [pscustomobject]@{ Framework = 'CIS_M365'; ControlId = '1.2.3'; ... }
    [pscustomobject]@{ Framework = 'NIST_CSF'; ControlId = 'PR.AC-1'; ... }
)
```

One row per `(finding × framework × control)` tuple. Always an array, even when empty. The legacy `ComplianceMappings` field remains populated for backward compatibility — `ControlMappings` is derived from it.

---

## 5. Evidence

Each Evidence row describes **where the assessor looked**, not what was found. References, not raw payloads.

```powershell
[pscustomobject]@{
    EvidenceId         = 'EVID-<16 hex>'
    Source             = 'Internal' | 'SecureScore' | 'DefenderCompliance' | ...
    Provider           = 'Microsoft.Graph' | 'Az.Resources' | ...
    Endpoint           = 'https://graph.microsoft.com/v1.0/...'
    Cmdlet             = 'Get-MgUser'
    TenantId / SubscriptionId / ResourceId
    CapturedAtUtc      = ISO-8601 UTC
    QueryScope         = check or operation name
    DataClassification = 'Public' | 'Internal' | 'Confidential' | 'Restricted'
    Reference          = path to sidecar artifact, if any
    HashAlgorithm      = 'SHA256'
    Hash               = hex digest of artifact (or canonical descriptor when no artifact)
    RedactionStatus    = 'NotRequired' | 'Redacted' | 'RawPayloadExcluded'
}
```

**Security defaults:**
- `RawPayloadExcluded` is the default — `ConvertTo-EvidenceReference` never embeds raw API payloads unless the caller explicitly passes `-RawSample $value -AllowRawSample`.
- When `-AllowRawSample` is set, the sample is scanned against the secret pattern library (`bearer ...`, JWTs, PEM private keys, `client_secret=...`, SAS tokens, storage account keys, connection strings, auth headers, password assignments). Any match flips `RedactionStatus = 'Redacted'`.
- Even when sources are sensitive, the **hash** is always emitted. That gives auditors a verifiable fingerprint for the artifact without exposing it.

---

## 6. Owner

Analyst routing metadata. Resolved at report time via `Resolve-FindingOwner` with this precedence:

1. **`StateOverride`** — set in the local state file (analyst-authored).
2. **`OwnerHint`** — supplied by the check itself when emitting the finding.
3. **`AzureTag`** — read from `Owner` / `ServiceOwner` / `ApplicationOwner` / `CostCenter` / `BusinessUnit` tags on the affected resource.
4. **`EntraOwner`** — Entra application or service-principal owners list.
5. **`Subscription`** / **`ResourceGroup`** — falls through when nothing more specific is known.
6. **`Unknown`** — empty defaults.

The resolved owner's `Source` field always reflects the tier that produced it, so reports can distinguish "an analyst chose this person" from "the tool guessed from a tag."

---

## 7. Exception

Risk acceptance and scoping workflow. Lifecycle states:

| `Status` | Meaning |
|---|---|
| `None` | No exception (default) |
| `Requested` | An exception has been proposed but not yet decided |
| `Approved` | Accepted — Disposition flips to the exception type |
| `Rejected` | Decided "no" — finding remains actionable |
| `Expired` | Was approved but `ExpiresAt` has passed |
| `Revoked` | Approval was withdrawn |

Approved exceptions automatically transition to `Expired` (and `Disposition='ExpiredException'`) the moment `ExpiresAt` passes — no manual state-file edit required. Expired exceptions reappear in the Action Queue so they don't slip through.

Key principle: **approved exceptions never remove a finding from complete exports**. They change its disposition. Analysts can filter to "Action Queue" for the daily-driver view, but the audit trail in `All Findings` / `Exceptions Lifecycle` always shows them.

---

## 8. ReviewStatus

Human-judgment workflow, separate from the deterministic `Status` value:

| `State` | Meaning |
|---|---|
| `New` | Default for non-REVIEW findings |
| `NeedsReview` | Default for `Status='REVIEW'` findings |
| `InReview` | Analyst has started but not concluded |
| `ActionRequired` | Analyst concluded "fix this" |
| `Accepted` | Analyst accepts the current state (paired with an Exception for the audit trail) |
| `Resolved` | Analyst confirmed the underlying issue is fixed |
| `Suppressed` | Analyst hides the finding (paired with a Justification) |

Like Owner and Exception, ReviewStatus is overlaid from local state — it never overwrites raw assessment fields.

---

## 9. RemediationDetail

Structured remediation guidance — fed from `EntraChecks-RemediationGuidance.psm1` when available:

```powershell
[pscustomobject]@{
    Summary            = short string (mirrors legacy Remediation)
    PortalSteps        = @('1. Open ...', '2. Click ...', ...)
    PowerShell         = code block string
    AzureCli           = code block string
    ValidationSteps    = @('Verify ...', ...)
    RollbackSteps      = @(...)
    Impact             = 'Positive consequences of remediating'
    Considerations     = 'Negative or risky consequences'
    Effort             = human-readable label
    RequiresApproval   = $true / $false
    AutomationSafety   = 'ManualOnly' | 'DryRunRecommended' | 'SafeToAutomate' | 'Destructive'
    DocumentationLinks = @('https://...')
}
```

**Important:** the v1 toolkit does not auto-run any of these. PowerShell snippets render as text only — text only, not executable code. Anything destructive or tenant-wide stays `ManualOnly` or `DryRunRecommended` by design.

---

## 10. Disposition — derived buckets

`Disposition` is derived from `(Status, ReviewStatus, Exception)` via `Get-FindingDisposition`. **Never author it directly.** Derivation order (first match wins):

1. `Status='OK'` → `Passing`
2. `Status='INFO'` → `Informational`
3. Exception status is `Expired` (or `Approved` with past `ExpiresAt`) → `ExpiredException`
4. Exception status is `Approved` → exception's `Type` (`AcceptedRisk` / `CompensatingControl` / `FalsePositive` / `OutOfScope`)
5. `ReviewStatus.State='Resolved'` → `Resolved`
6. `ReviewStatus.State='Suppressed'` → `Suppressed`
7. `Status='REVIEW'` or `ReviewStatus.State` ∈ {NeedsReview, InReview} → `Review`
8. `Status` ∈ {FAIL, WARNING} → `ActionRequired`
9. Fallback → `Open`

Reports key off `Disposition` for queue inclusion (e.g. the HTML Action Queue and the Excel `Analyst Queue` sheet exclude `Passing` / `Informational` / accepted-exception states).

---

## 11. Local analyst state file

Workflow state lives in JSON, not in the codebase. Default path is `config/finding-state.local.json` (gitignored). The shipped example is [`config/finding-state.example.json`](../config/finding-state.example.json).

**Shape:**

```json
{
  "Version": "1.0",
  "Findings": {
    "ECF-1234567890abcdef1234": {
      "Owner": {
        "OwnerType": "Team",
        "DisplayName": "Identity Platform",
        "Email": "identity-platform@example.com",
        "Source": "StateOverride",
        "Confidence": "High",
        "DueDate": "2026-06-30"
      },
      "ReviewStatus": {
        "State": "InReview",
        "Reviewer": "analyst@example.com",
        "Notes": "Waiting for app owner confirmation.",
        "NextReviewDate": "2026-05-22"
      },
      "Exception": {
        "Status": "Approved",
        "Type": "AcceptedRisk",
        "Justification": "Compensating detection is active.",
        "Approver": "ciso@example.com",
        "ApprovedAt": "2026-05-08T20:00:00Z",
        "ExpiresAt": "2026-08-08T20:00:00Z"
      },
      "Tags": ["quarterly-review", "tier-1"],
      "Links": ["https://wiki.example.com/findings/ECF-1234567890abcdef1234"]
    }
  }
}
```

**Configuration:** the path is read from `GRC.FindingStatePath` in `config/entrachecks.config.json`. Set it to an empty string to disable state merging entirely.

**What state CAN do:**
- Set / change `Owner`, `Exception`, `ReviewStatus`, `Tags`, `Links` for a finding by `FindingId`.

**What state CANNOT do:**
- Change `Status`, `RiskScore`, `RiskLevel`, `Source`, `Description`, `Remediation`, or any other raw assessment field. The `Merge-FindingState` allowlist silently ignores any such attempt — audit facts stay immutable.

**Behavior on errors:**
- Missing state file → no state, defaults apply, no warning.
- Malformed JSON → `Write-Warning` once, defaults apply, assessment continues. (Analyst workflow is advisory; it must never abort an audit run.)

---

## 12. Snapshot comparison

`Compare-ComplianceSnapshots` prefers `FindingId` as the snapshot key when both snapshots carry it, falling back to the legacy `CheckName|Object` for pre-v2 snapshots. That means a finding whose display `Object` was renamed in Graph (common — UPNs change, display names get edited) is still recognised as the same finding across snapshots when the underlying `ObjectId` is stable.

WARNING↔REVIEW status transitions are also recategorisations (not improvements/regressions) so the Review-Status-Plan's global reclassification doesn't pollute trend signals.

---

## 13. Where the schema shows up

| Surface | What v2 surfaces |
|---|---|
| **Excel** (Comprehensive Assessment workbook) | All Findings gains FindingId / Disposition / Owner / Exception / Review State / Tags columns. New sheets: Analyst Queue, Review Queue, Control Register, Evidence Register, Exceptions, Remediation Plan. |
| **HTML** (Unified Compliance Report) | Action Queue + Exceptions tiles in the Findings Summary Overview. New sections: Action Queue (above All Findings), Exceptions Lifecycle (after Review Queue). Finding row body surfaces Owner / Disposition / Exception / Evidence count / FindingId. All values HTML-encoded. |
| **CSV** | Flat-row format via `ConvertTo-FindingFlatRow` — one column per atomic v2 field plus semicolon-joined columns (`ControlMappingsFlat`, `EvidenceIds`, `TagsFlat`, etc.). No more `@{...}` cells. |
| **JSON** | Full v2 finding objects emitted at `-Depth 15` so nested ControlMappings / Evidence / RemediationDetail round-trip cleanly. `Metadata.SchemaVersion='2.0'` on the envelope. |

---

## 14. Compatibility

The schema is intentionally **additive**:

- Existing tests that inspect legacy fields (Status, Object, Description, etc.) continue passing.
- Pre-v2 snapshots still diff correctly via the `CheckName|Object` keying fallback in `Compare-ComplianceSnapshots`.
- Reports render for legacy findings (rows simply have empty cells in v2 columns).
- The legacy `ComplianceMappings` field stays populated alongside the new `ControlMappings` array.
- `Status='REVIEW'` semantics from the Review-Status-Plan remain unchanged.

If you're integrating a custom check, the only "must-do" is calling `Add-Finding` (or `Add-ModuleFinding` in identity modules) the same way you always have. The normalizer fills the rest at report time. If you can supply richer metadata (`-ObjectId`, `-ResourceId`, `-OwnerHint`, `-Evidence`), v2 columns get populated for that check too.

---

## 15. Security requirements

The schema is designed for shared / external consumption. Implementers must respect:

- **HTML encoding everywhere user-supplied text appears.** Both the unified report and the standalone HTML emitter pass every dynamic value through `[System.Net.WebUtility]::HtmlEncode`. The PR 4 test suite asserts that `<img onerror=...>`, `<b>`, and similar injection attempts are escaped to `&lt;...&gt;`.
- **No raw API payloads in evidence by default.** `RawPayloadExcluded` is the default `RedactionStatus`. Opt-in only with `-AllowRawSample`, and even then the sample is scanned against the secret pattern library before being stored.
- **No auto-run of remediation snippets.** PowerShell and CLI strings are rendered as text. `AutomationSafety` defaults to `ManualOnly`.
- **State files are local by default.** `config/finding-state.local.json` is gitignored; the example is tracked but does not contain real data.
- **External URLs use safe link generation** (`rel="noopener noreferrer"` where rendered as `<a>`).

---

## 16. Reference

| Function | Purpose |
|---|---|
| `New-EntraFindingId` | Compute the deterministic ECF-prefixed identity |
| `ConvertTo-EntraFindingV2` | Normalize a legacy finding to v2 (idempotent) |
| `Initialize-FindingsForReport` | Batch-normalize + apply analyst state from a JSON file |
| `Import-FindingState` | Load + validate the analyst state JSON |
| `Merge-FindingState` | Apply analyst state to a single finding (allowlisted) |
| `Get-FindingDisposition` | Compute Disposition from `(Status, ReviewStatus, Exception)` |
| `Resolve-FindingOwner` | Apply the 6-tier owner resolution ladder |
| `ConvertTo-ControlMappings` | Flatten legacy `ComplianceMappings` to v2 `ControlMappings` rows |
| `ConvertTo-EvidenceReference` | Build an Evidence row (with optional secret-pattern scan) |
| `ConvertTo-FindingFlatRow` | Flatten a v2 finding for CSV emission |
| `Test-EntraFindingV2` | Validate required fields + enum values |
| `Test-EvidenceContainsSecret` | Standalone secret-pattern test (exposed for testing) |

All are exported from [Modules/EntraChecks-FindingSchema.psm1](../Modules/EntraChecks-FindingSchema.psm1).

---

## 17. See also

- [`plans/Central-Finding-Schema-GRC-Plan.md`](../plans/Central-Finding-Schema-GRC-Plan.md) — full plan with phasing, acceptance criteria, and security rules
- [`docs/Reporting-Guide.md`](Reporting-Guide.md) — what the v2 fields look like in Excel and HTML
- [`Examples/Example-FindingState.ps1`](../Examples/Example-FindingState.ps1) — minimal state-file workflow walkthrough
- [`config/finding-state.example.json`](../config/finding-state.example.json) — copy-and-edit starter for analyst state
