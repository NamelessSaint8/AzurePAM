# SOC 2 Internal Readiness Guide

**Status:** Phase 1 (MVP — Type 1, full TSC skeleton)
**TSC revision:** AICPA TSC 2017 (revised 2022)
**Primary use case:** Internal readiness check (NOT an auditor deliverable).

This guide explains how to run SOC 2 assessments with EntraChecks, how to read
the resulting report, and how to use the companion identity-resolution map for
internal remediation without losing PII redaction on the distributed HTML.

---

## 1. What EntraChecks can and cannot assess

EntraChecks is a read-only Microsoft 365 / Azure assessment tool. Its SOC 2
coverage reflects that: we automate every Trust Services Criteria (TSC) control
whose evidence is observable through Microsoft Graph or Azure ARM; everything
else is rendered as a `MANUAL` finding with an attestation template so the
internal team sees the *complete* TSC landscape and records attestations outside
the tool.

### Automated coverage (data-available via Graph / Azure)
- **CC4.1, CC4.2** — monitoring controls, alerting readiness
- **CC6.1 – CC6.8** — logical and physical access (full category, primary coverage)
- **CC7.1 – CC7.5** — system operations, incident response readiness
- **CC8.1** — change management
- **A1.1, A1.2** — availability (Phase 2 for backup/service-health signals)
- **C1.1, C1.2** — confidentiality (DLP, sensitivity labels, retention)

### Supporting evidence (automation + attestation)
- **CC2.1, CC2.3** — communication (admin/security contacts)
- **CC3.1 – CC3.4** — risk assessment (Secure Score, Defender Secure Score)
- **CC9.1, CC9.2** — risk mitigation (vendor/partner controls)

### Manual attestation only
- **CC1.1 – CC1.5** — control environment (HR, integrity, org structure)
- **CC5.1 – CC5.3** — control activities (policy design)
- **A1.3** — recovery testing
- **PI1.1 – PI1.5** — processing integrity (application-layer)
- **P1 – P8** — privacy (Priva licensing required for automation; Phase 4)

---

## 2. Running a SOC 2 assessment

### Reducing authentication prompts

A SOC 2-enabled run authenticates against **two distinct identity planes**:
Microsoft Graph (for Entra/M365 evidence) and Azure Resource Manager (for
Defender, Backup, and diagnostic-settings evidence). Tokens for these planes
have different audiences and **cannot be shared** — at minimum you will see
**two browser sign-ins**.

You can eliminate the third prompt — the Graph "Permissions requested"
consent dialog — by pre-granting admin consent **once per tenant**:

```powershell
# Run as a Global Administrator, once per tenant.
.\Grant-AdminConsent.ps1
```

Tick **"Consent on behalf of your organization"** in the consent screen.
Subsequent runs by any user with the appropriate read role will not see
the consent dialog. The Graph and Azure sign-in surfaces remain (they are
unavoidable for delegated read-only auth), but they are usually silent
SSO when the user is already signed in to Windows or Edge.

If you prefer to skip the Azure prompt as well, run `Connect-AzAccount`
in the same PowerShell session **before** launching `Start-EntraChecks.ps1`
— the cached Az context will be reused. For fully non-interactive runs
(CI / scheduled tasks), use a service-principal certificate stored in
Azure Key Vault — see `docs/KeyVault-Guide.md`.

### Option A — Interactive menu

```powershell
.\Start-EntraChecks.ps1
# Select [6] SOC 2 Readiness
```

The menu handler will:
1. Load SOC 2 modules.
2. Read `config\entrachecks.config.json` for SOC 2 settings (or use defaults).
3. Ensure baseline findings exist (runs the Core assessment first if needed).
4. Invoke `Invoke-SOC2Assessment` for a Type 1 run across all configured TSC categories.
5. Produce the standalone HTML report, Excel workbook, and evidence bundle.
6. Open the HTML report in your default browser.

### Option A.1 — Automatic run after Quick Assessment

Set `SOC2.Enabled = true` in `config\entrachecks.config.json` (top-level
under `SOC2`). When Quick Assessment (`[1]` in the interactive menu or
`-Mode Quick` on the CLI) completes, the SOC 2 readiness pass runs
automatically against the just-collected findings — one invocation
produces both the unified report and the SOC 2 report.

```json
"SOC2": {
  "Enabled": true,
  ...
}
```

When `SOC2.Enabled = false` (the shipped default), Quick Assessment
behaves exactly as before — no SOC 2 overhead. The menu option `[6]`
remains the canonical manual-trigger path regardless of this flag.

Behavior details:
- Interactive `[1]`: HTML opens in browser after both reports are produced.
- `-Mode Quick` / `-Mode Scheduled`: HTML is NOT auto-opened (automation friendly).
- SOC 2 failure during the auto-run never fails the primary Quick Assessment — errors surface as a yellow warning.

### Option B — Scripted (recommended for automation)

```powershell
Import-Module .\Modules\EntraChecks-ComplianceMapping.psm1 -Force
Import-Module .\Modules\EntraChecks-Branding.psm1 -Force
Import-Module .\Modules\EntraChecks-SOC2.psm1 -Force
Import-Module .\Modules\EntraChecks-SOC2Reporting.psm1 -Force

# $findings = your existing EntraChecks findings array (from a prior run)
$result = Invoke-SOC2Assessment `
    -ExistingFindings $findings `
    -TenantId (Get-MgContext).TenantId `
    -TenantName 'Contoso' `
    -Categories @('CC', 'A', 'C', 'PI', 'P') `
    -OutputDirectory '.\Output\SOC2\2026-04-14' `
    -RedactUsers `
    -RedactDevices `
    -IncludeManualAttestation $true `
    -Assessor $env:USERNAME

$branding = Get-ReportBrandingContext -Config $null -ReportTitle 'SOC 2 Readiness'
New-SOC2AuditReport -AssessmentResult $result -OutputPath '.\Output\SOC2\2026-04-14\Report.html' -Branding $branding -IdentityResolutionMapPath $result.IdentityMapPath
New-SOC2AuditWorkbook -AssessmentResult $result -OutputPath '.\Output\SOC2\2026-04-14\Workbook.xlsx'
```

---

## 3. Configuration

The `SOC2` block in `config\entrachecks.config.json` controls SOC 2 behavior.
It is **disabled by default**. See the schema in
`Modules\EntraChecks-Configuration.psm1` (`Get-ConfigurationSchema`) for the
authoritative property list. Key fields:

| Field | Default | Notes |
|---|---|---|
| `Enabled` | `false` | Set `true` to surface SOC 2 in scheduled runs. |
| `Type` | `"Type1"` | `Type2` requires snapshot history (Phase 3). |
| `Categories` | all 5 (CC, A, C, PI, P) | Limit if you need a narrower readiness view. |
| `IncludeManualAttestation` | `true` | Emits `MANUAL` findings for non-automatable TSCs. |
| `Redaction.RedactUserPII` | `true` | UPNs hashed with a per-tenant salt. |
| `Redaction.RedactDeviceNames` | `true` | Device names hashed identically. |
| `Redaction.EmitIdentityResolutionMap` | `true` | Writes a separate, ACL-locked map enabling internal lookup. |
| `Evidence.HashAlgorithm` | `"SHA256"` | Manifest algorithm; SHA384/512 also accepted. |
| `Evidence.RetentionYears` | `7` | Guidance for downstream retention automation. |
| `Branding.WhiteLabel` | `false` | If `true`, `OrganizationName` is required; logo/colors swap in. |

---

## 4. Understanding the outputs

Each run creates `Output\SOC2\<timestamp>\` containing:

```
Output\SOC2\20260414-142301\
├── SOC2-Report.html              # Standalone TSC-structured HTML
├── SOC2-Workbook.xlsx            # Multi-sheet Excel (or CSV fallback dir)
└── evidence-bundle\
    ├── manifest.json             # Tenant, UTC, SHA-256 bundle hash, file list
    ├── controls\
    │   ├── CC6.1.json            # Per-TSC evidence (findings, metadata)
    │   ├── CC6.2.json
    │   └── ...
    └── manual-attestation\
        ├── CC1.1.md              # Fill-in-the-blank attestation templates
        └── ...
```

Separate, ACL-restricted:
```
Output\SOC2\identity-resolution\identity-resolution-<tenant>-<timestamp>.json
```

### Report structure

The HTML report opens with an **Executive Summary** that gives a one-page
view before any detail:
- Readiness verdict (STRONG / MINOR DEFICIENCIES / GAPS IDENTIFIED / INSUFFICIENT DATA)
- Headline numbers: total controls, pass, fail, warnings, licensing gaps, total findings
- Top 3 failing TSC controls (by finding count)
- Top 3 licensing-gap features (by TSC coverage count)
- Jump-to links into each per-family section

If any finding originates from a fixture-verified-only Phase 2 check
(`Test-SOC2DiagnosticSettingsExport`, `Test-SOC2BreakGlassAccountsConfigured`),
an amber **verification-note banner** renders near the top calling that out,
and the affected findings carry an inline `fixture-verified` tag in the
Check column. Spot-check those against your live tenant before relying on
the output for audit evidence.

The Cover panel carries an **Evidence integrity — verifiable** badge when a
bundle was produced. The side-panel "Evidence integrity — verifiable"
subtitle mirrors it with a check-icon SVG. Run
`Test-SOC2EvidenceBundle -ManifestPath <path>` to recompute and verify.

Each per-family section has an anchor ID (`#family-CC`, `#family-A`, etc.)
so the Summary-by-Category cards and the Jump-to links in the Executive
Summary both navigate directly to the relevant section.

A print stylesheet (`@media print`) hides the interactive side panel,
preserves status colors, and forces page-breaks between per-family sections
so printing / save-as-PDF produces a usable document.

### CSV and Excel output

When the `ImportExcel` PowerShell module is installed, the workbook emits
`.xlsx` with multiple sheets (Cover, Summary by Category, Control Register,
Findings - CC6/CC7/CC8/Other CC/Availability/Confidentiality, Findings -
Licensing Gaps, Manual Attestation, Evidence Register).

When `ImportExcel` is **not** installed, the CSV fallback produces the same
data surface as numbered files in a directory:

```
01-Cover.csv
02-Summary-by-Category.csv
03-Control-Register.csv
04-Findings-CC6.csv
05-Findings-CC7.csv
06-Findings-CC8.csv
07-Findings-Other-CC.csv
08-Findings-Availability.csv
09-Findings-Confidentiality.csv
10-Findings-Licensing-Gaps.csv
11-Manual-Attestation.csv
12-Evidence-Register.csv
```

Files are only written when their data exists (e.g., no licensing-gap
findings → no `10-` file).

---

## 5. Redaction and internal remediation workflow

By default, user UPNs and device names are replaced with salted SHA-256 hashes
in all rendered output. The corresponding plaintext is written to a separate,
ACL-locked `identity-resolution-*.json` file inside
`Output\SOC2\identity-resolution\`.

### Why the map is separate

Reports are safe to share internally (Teams, SharePoint) without exposing PII,
but remediation teams still need to identify accounts. Keeping the resolution
map as a sibling file — never embedded in the report — lets you:
- Distribute the report freely to leadership / compliance.
- Keep the mapping on a restricted share (the file's ACL locks it down to the
  current user + `BUILTIN\Administrators` on creation).
- Re-resolve hashes on demand using `Resolve-SOC2Identity`.

### Using the identity-lookup side panel in HTML

The sidebar exposes a text field where you can paste a hash prefix (12+ chars
is usually unique) to get back the UPN and display name. The resolution map
itself is loaded **into the browser tab only** — it is never embedded in the
HTML, so the report file remains safe to distribute.

Two load paths, in order:

1. **Auto-load** — if the report is served over `http://` (e.g.,
   `python -m http.server` from the report folder), the sidebar fetches the
   resolution map automatically using the absolute path baked into the report.
2. **File-picker fallback** — if the report is opened directly from the file
   system (`file://`), browsers block automatic local-file fetches for security
   reasons. The sidebar then shows a file picker; select the
   `identity-resolution-*.json` file shown in the panel and the lookup activates.
   Data is read with the browser's `FileReader` API and stays in tab memory.

For batch lookups or scripted workflows, use `Resolve-SOC2Identity` (below)
instead of the HTML widget.

### Using Resolve-SOC2Identity from PowerShell

```powershell
Resolve-SOC2Identity -Hash '9a8b7c6d5e4f3a2b...' `
    -ResolutionMapDirectory '.\Output\SOC2\identity-resolution'
```

Returns:
```
Hash       : 9a8b7c6d5e4f3a2b...
UPN        : alice@contoso.com
ObjectId   :
DisplayName:
SourceFile : C:\...\identity-resolution-contoso-20260414-142301.json
```

### Salt lifetime

The per-tenant salt is stored under `<OutputDirectory>\SOC2\<timestamp>\salt\<tenant>.salt`.
To enable referential integrity across snapshots (same UPN → same hash across
runs, required for Type 2), copy the salt file from the first run into all
subsequent run directories, or point `SaltDirectory` in the call to a stable
location.

---

## 6. Evidence integrity

Every file in the evidence bundle is hashed with SHA-256. The manifest records:
- Per-file `RelativePath` and `SHA256`
- A rolling `BundleHash` computed deterministically over the sorted file list

Verify a bundle hasn't been tampered with:

```powershell
Test-SOC2EvidenceBundle -ManifestPath '.\Output\SOC2\20260414-142301\evidence-bundle\manifest.json'
```

Returns `Valid = $true` only if every file still matches its recorded hash and
the rolling bundle hash still matches.

Signing the bundle (CMS / Authenticode) is available as a deferred Phase 4
enhancement and is only expected for eventual auditor deliverables.

---

## 7. Manual attestation workflow

Controls that cannot be automated (CC1 Control Environment, CC5 Control
Activities, PI Processing Integrity, most Privacy criteria) are emitted as
`MANUAL` findings and each gets a template at
`evidence-bundle\manual-attestation\<TSC-ID>.md`.

Fill in:
- Control owner (name + title)
- Description of how the control operates
- Frequency of operation
- Evidence location (link to SharePoint, ticket, HR record, etc.)
- Period of coverage
- Attested by / attested on (UTC)

Retain these alongside the evidence bundle in your internal readiness archive.
Recommended retention: **7 years** (configurable via `Evidence.RetentionYears`).

---

## 8. Type 2 and period coverage

Type 2 reports cover **how each control operated across a period of coverage**
(e.g., 90 days), not a single point in time. The implementation lives in
`Modules/EntraChecks-SOC2TypeTwo.psm1` and consumes the existing snapshot
system from `Modules/EntraChecks-DeltaReporting.psm1`.

### Prerequisites

1. **Snapshot history.** Take regular snapshots throughout the coverage
   period using `Save-ComplianceSnapshot` (option [1] Quick Assessment with
   `-SaveSnapshot`, or scheduled mode). Default cadence: weekly.
2. **Snapshot format v1.7+.** Phase 3 PR 2 added `Type` and `TSCReferences`
   per finding to the snapshot projection. Older snapshots fall back to
   compliance-mapping lookup via `Category` — works but slightly less
   precise. For new snapshots, this is automatic.
3. **Configuration.** Set `SOC2.AzureReadiness.TypeTwo.*` in
   `config/entrachecks.config.json`. Default values are sensible
   (Weekly cadence, 12-snapshot minimum, 10-day max gap, strict 0
   exception tolerance).

### Running Type 2

**Interactive:** menu option `[7] SOC 2 Type 2`. Prompts for period start/end
dates if not pre-configured in `SOC2.TypeTwoPeriod.{StartDate,EndDate}`.

**Scripted:**

```powershell
Import-Module .\Modules\EntraChecks-ComplianceMapping.psm1 -Force
Import-Module .\Modules\EntraChecks-Branding.psm1 -Force
Import-Module .\Modules\EntraChecks-SOC2.psm1 -Force
Import-Module .\Modules\EntraChecks-SOC2TypeTwo.psm1 -Force

$coverage = Get-SOC2PeriodCoverage `
    -SnapshotDirectory .\Snapshots `
    -StartDate '2026-01-01' `
    -EndDate '2026-04-01' `
    -MinSnapshotsRequired 12 `
    -MaxGapDays 10 `
    -ExceptionsAllowed 0

$evidence = New-SOC2TypeTwoEvidenceBundle `
    -Coverage $coverage `
    -OutputDirectory .\Output\SOC2-TypeTwo\evidence-bundle `
    -TenantId (Get-MgContext).TenantId `
    -TenantName 'Contoso' `
    -Assessor $env:USERNAME

$branding = Get-ReportBrandingContext -Config $null -ReportTitle 'SOC 2 Type 2 Period Coverage'
New-SOC2TypeTwoReport -Coverage $coverage -Evidence $evidence -Branding $branding `
    -OutputPath .\Output\SOC2-TypeTwo\SOC2-TypeTwo-Report.html
```

### Per-control consistency states

Each TSC control is classified into one of these states based on its
worst-status across snapshots in the period:

| State | Meaning |
|---|---|
| `ConsistentlyPassing` | Every snapshot saw a PASS/OK — control operated throughout the period |
| `DegradedButOperating` | Mix of PASS + WARNING (no FAIL) — control operated with deficiencies |
| `Inconsistent` | At least one FAIL anywhere in the period — SOC 2 "exception" |
| `ConsistentlyFailing` | Every snapshot saw a FAIL — control did not operate |
| `Unobserved` | No findings mapped to the control in any snapshot |
| `ManualAttestationRequired` | Control is non-automatable; out-of-band attestation needed |

Override the strictness with `SOC2.AzureReadiness.TypeTwo.ConsistencyExceptionsAllowed`
(default 0). Setting it to 1 means "tolerate one FAIL in the period before
classifying as Inconsistent."

### Coverage threshold (`MeetsTypeTwoThreshold`)

A Type 2 claim requires:
- **Snapshot count ≥ MinSnapshotsRequired** (default 12)
- **Largest gap between consecutive snapshots ≤ MaxGapDays** (default 10 for Weekly)
- **Leading gap (start of period → first snapshot) ≤ MaxGapDays**
- **Trailing gap (last snapshot → end of period) ≤ MaxGapDays**

If any of these fails, the report still generates but prominently displays
"Type 2 coverage NOT MET" and lists the reasons. The per-control analysis is
still shown — treat it as Type 1-equivalent over whatever snapshots exist.

### Evidence bundle and chain-of-custody

Type 2 produces a separate evidence bundle from Phase 1's Type 1 bundle:

```
Output/SOC2-TypeTwo/<timestamp>/
├── SOC2-TypeTwo-Report.html
└── evidence-bundle/
    ├── manifest.json              # Type='Type2', Period.{StartUtc,EndUtc,Days}, BundleHash, ...
    ├── snapshots-manifest.json    # SnapshotId + SourceSHA256 for each consumed snapshot
    ├── period-coverage/
    │   ├── CC6.1.json             # per-control state, occurrences, per-snapshot trace
    │   └── ...
    └── manual-attestation/
        └── CC1.1.md               # period-annotated attestation templates
```

Verify integrity with `Test-SOC2TypeTwoBundle -ManifestPath ...` — recomputes
all file hashes, the rolling bundle hash, AND validates that every source
snapshot still hashes to its recorded SHA-256 (chain-of-custody check across
the snapshot → report flow).

---

## 9. Limitations and caveats

- **Read-only only.** EntraChecks never modifies tenant configuration. Remediation
  is the operator's responsibility; SOC 2 findings link to the unified EntraChecks
  report's remediation guidance.
- **Internal readiness, not auditor deliverable.** Phase 1 is explicitly scoped
  for internal use. Auditor-grade features (CMS signing, TSA timestamping,
  white-labeled cover pages) are Phase 4.
- **Licensing gaps surface as INFO findings.** Identity Protection (P2), Intune
  (EMS E3+), Purview DLP/retention (E5), Priva — if not licensed, the
  corresponding TSCs surface as `INFO` rather than silently passing.
- **Process controls require attestation.** Any TSC describing organizational
  process (ethics, training, change boards) will always be `MANUAL`.

---

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "No prior findings; running Core assessment to seed SOC 2 mapping..." | No EntraChecks run happened first in this session | Run option [1] Quick Assessment first, or let the menu auto-run Core. |
| Identity lookup sidebar shows the file picker instead of auto-loading | Browsers block `fetch()` of local files when the report is opened over `file://` (expected) | Click the picker and select the `identity-resolution-*.json` shown in the sidebar — the path is displayed there. Or serve the folder over `python -m http.server` for auto-load. |
| Every TSC shows `MANUAL` | No mapped EntraChecks findings yet | Ensure the Core assessment ran; check that `Add-ComplianceMapping` resolved your findings' `Type`. |
| `Invalid white-label branding configuration` at startup | `WhiteLabel = true` but `OrganizationName` is blank | Fill in `SOC2.Branding.OrganizationName` in the config. |
| `Test-SOC2EvidenceBundle` reports mismatches | Someone edited a file in the bundle | Investigate; never hand-edit evidence files — regenerate instead. |

---

## 11. Phase 2 coverage (shipped)

Phase 2 added six synthetic Azure-readiness checks and a licensing
graceful-degradation layer. All Phase 2 code lives alongside Phase 1 in
`Modules/EntraChecks-SOC2.psm1`; no new module imports needed.

### New checks

| TSC | Check | Data source | Required permissions |
|---|---|---|---|
| A1.1 | `Test-SOC2ServiceHealthBaseline` | Azure Resource Health | `Reader` on each in-scope subscription |
| A1.2 | `Test-SOC2BackupConfiguration` | Recovery Services vaults + protected items | Azure RBAC `Backup Reader` (or `Reader` with limitations) |
| CC4.1, CC7.2 | `Test-SOC2DiagnosticSettingsExport` | Entra `microsoft.aadiam` + Log Analytics workspace | Azure RBAC `Monitoring Reader` at tenant root (`/providers/microsoft.aadiam`) |
| CC6.7 | `Test-SOC2EncryptionPosture` | Defender for Cloud assessments (encryption keywords) | Defender `Security Reader` (already Phase 1) |
| CC6.8 | `Test-SOC2MalwareProtection` | Defender for Endpoint connector (`WDATP` setting) + assessments | Defender `Security Reader` |
| CC7.5 | `Test-SOC2BreakGlassAccountsConfigured` | GA role members + Conditional Access exclusions | Graph `Directory.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory` (Phase 1 scopes) |

### New Az modules

Installed by `Install-Prerequisites.ps1` (skippable via `-GraphOnly`):

- `Az.RecoveryServices` ≥ 6.0.0
- `Az.Monitor` ≥ 4.0.0
- `Az.OperationalInsights`

### Phase 2 configuration keys

All optional and under `SOC2.Phase2`:

```json
"Phase2": {
  "SubscriptionFilter": [],
  "Backup": { "MinRedundancyTier": "GRS" },
  "ServiceHealth": { "AvailabilityThresholdPercent": 98 },
  "DiagnosticSettings": {
    "RequiredWorkspaceId": "",
    "RequiredCategories": ["AuditLogs", "SignInLogs"]
  },
  "BreakGlass": {
    "MinimumAccounts": 2,
    "AccountUpnPatterns": []
  },
  "Licensing": {
    "Overrides": {
      "IdentityProtection": "INFO",
      "Intune": "INFO",
      "PurviewE5": "INFO",
      "DefenderForCloud": "INFO",
      "DefenderForEndpoint": "INFO",
      "Priva": "INFO"
    }
  }
}
```

### Licensing gaps: "control not assessed" rows

Phase 2 introduces `SOC2_LicensingGap_*` findings for features your tenant is
not licensed for:

- `SOC2_LicensingGap_IdentityProtection` (requires P2) → affects CC7.3
- `SOC2_LicensingGap_Intune` (requires EMS E3+) → affects CC6.4
- `SOC2_LicensingGap_PurviewE5` (requires E5 / Compliance) → affects CC6.7, C1.1, C1.2
- `SOC2_LicensingGap_DefenderForCloud` (requires paid Defender plan) → affects CC4.2, CC6.7, CC6.8
- `SOC2_LicensingGap_DefenderForEndpoint` → affects CC6.8
- `SOC2_LicensingGap_Priva` → affects P1.1, P2.1, P3.1

By default these render as `INFO / Severity=Low`, so the affected TSCs show
a visible **"control not assessed due to licensing"** row in the audit report
rather than silently passing. For internal readiness where the org has
committed to procuring a license, escalate via
`SOC2.Phase2.Licensing.Overrides.<Feature> = "WARNING"` (or `"FAIL"`) so the
gap is tracked as a deficiency until procurement closes.

### Capability probing

`Get-SOC2LicensingCapabilities` runs once per assessment, caches results for
the module lifetime. Call with `-Refresh` to re-probe. Returns a hashtable
with keys `HasP2`, `HasIntune`, `HasPurviewE5`, `HasDefenderForCloud`,
`HasDefenderForEndpoint`, `HasPriva`, `HasAzContext`.

### Per-check verification confidence (honest assessment)

Phase 2 ships **fixture-verified** for all six checks (see
`Tests/SOC2-Phase2.Tests.ps1`). Live-tenant verification status varies:

| Check | Confidence | Why |
|---|---|---|
| `Test-SOC2ServiceHealthBaseline` | **High** | Stable REST API, simple shape |
| `Test-SOC2EncryptionPosture` | **High** | Reuses Phase 1's Defender data path (live-verified) |
| `Test-SOC2MalwareProtection` | **High** | Same — Defender path stable |
| `Test-SOC2BackupConfiguration` | **Medium** | Vault API-version variability cannot be fully fixtured |
| `Test-SOC2DiagnosticSettingsExport` | **Low — fixture-verified only** | `microsoft.aadiam` is preview API; cross-subscription workspace refs and permission asymmetries are hard to simulate |
| `Test-SOC2BreakGlassAccountsConfigured` | **Low — fixture-verified only** | Nested group membership + CA exclusion semantics are edge-case heavy; Global Reader is sufficient to live-verify this one when available |

Spot-check the two low-confidence checks against your own tenant before
relying on their output for audit evidence.

### Azure RBAC roles to grant beyond Phase 1

For Phase 2 to evaluate Azure-side controls, grant the assessment identity:

- `Reader` on each in-scope subscription (already needed for Phase 1's Defender)
- `Backup Reader` on each in-scope subscription (A1.2)
- `Monitoring Reader` at the tenant root scope `/providers/microsoft.aadiam` (CC4.1, CC7.2)

## 12. What's next (Phase 3+)

- Type 2 period coverage reporting from snapshot history (`New-SOC2TypeTwoReport`) — Phase 3 PR 2
- Executive dashboard "X controls not assessed due to licensing" tile — Phase 3 PR 3
- Optional CMS signing of evidence bundles via Azure Key Vault — Phase 4
- Priva-based privacy automation (when Priva licensing is in scope) — Phase 4

Track the current roadmap in
`plans\SOC2-Implementation-Plan.md`, `plans\SOC2-Phase2-Implementation-Plan.md`,
and `plans\SOC2-Phase3-Implementation-Plan.md`.

## 13. Config namespace migration (v1.7.0 → v1.8.0)

Phase 3 renamed the Phase 2 config block from `SOC2.Phase2.*` to a semantic
namespace, `SOC2.AzureReadiness.*`. The schema is identical — only the key
name changed.

### What you need to do

If your `entrachecks.config.json` (or any `.dev.json` / `.prod.json`
override) uses the old key, **rename it now**:

```json
"SOC2": {
  "AzureReadiness": {           // <-- was "Phase2"
    "BreakGlass": { "MinimumAccounts": 2 },
    "Backup":     { "MinRedundancyTier": "GRS" },
    "ServiceHealth": { "AvailabilityThresholdPercent": 98 },
    "DiagnosticSettings": { "RequiredCategories": ["AuditLogs", "SignInLogs"] },
    "Licensing": { "Overrides": { "IdentityProtection": "INFO" } }
  }
}
```

### Backwards compatibility (v1.7.0 through v1.7.x)

Old `SOC2.Phase2.*` keys continue to work. A one-time deprecation warning
fires per session when the old name is detected. The shim
(`Resolve-SOC2NamespaceConfig`) automatically aliases Phase2 into
AzureReadiness so all downstream code reads the canonical name.

If both keys are present, `SOC2.AzureReadiness` wins per key (recursive
merge). A separate "both present" warning fires.

### Removal: v1.8.0

In v1.8.0 the shim is removed and `SOC2.Phase2.*` produces a hard validation
error directing the user to rename. Plan accordingly: schedule the rename
into your next config maintenance window.

### Why the rename

`Phase2` was an implementation-phase anchor that ages poorly. Future SOC 2
phases get their own semantic blocks (e.g., `SOC2.TypeTwo.*` for Phase 3
period reporting, `SOC2.Signing.*` for Phase 4 CMS signing). See decision 4
in `plans/SOC2-Phase2-Implementation-Plan.md` for the full rationale.
