# Analyst Cockpit HTML Report Guide

**Module:** `Modules/EntraChecks-HTMLReporting.psm1` (function `New-EntraChecksAnalystHtmlReport`)
**Status:** Default since PR 4 of `plans/HTML-Reporting-Consolidation-Plan.md`
**Output:** `Reports/<timestamp>/EntraChecks-Analyst-Cockpit-<timestamp>.html`

---

## 1. What changed

Before, every assessment generated up to nine overlapping HTML files (comprehensive, unified, executive summary, Secure Score, Defender, Azure Policy, Purview, Delta, plus SOC 2 reports). Auditors and analysts had to open multiple tabs to understand a tenant.

Now, a normal assessment generates **one primary HTML file** — the analyst cockpit. Deep-dive reports for individual data sources are still available but are **opt-in**.

- Default `Reports/<timestamp>/` contents:
  ```
  EntraChecks-Analyst-Cockpit-<timestamp>.html
  EntraChecks-Analyst-Cockpit-<timestamp>.html.findings.json   ← integrity sidecar
  Assessment-Data-<timestamp>.json
  CSV/                                                          ← when ImportExcel missing
  EntraChecks-Comprehensive-Assessment-<timestamp>.xlsx         ← when ImportExcel present
  ```
- When deep dives are requested, they land under `Reports/<timestamp>/DeepDives/` to keep the primary cockpit at the root of the report folder.
- SOC 2 Type 1 and Type 2 reports remain separate when `SOC2.Enabled = true` — they're audit-package artefacts, not normal-assessment clutter.
- The pre-PR-4 multi-report behavior is preserved via `-HtmlReportSet LegacyAll` for users with workflows that depend on the old layout.

---

## 2. The four modes

Pick the mode that matches what you're doing. Default: `Cockpit`.

| Mode | What it generates | When to use |
|---|---|---|
| `Cockpit` | One cockpit HTML, no deep dives. | Normal assessment runs. Daily-driver default. |
| `CockpitAndDeepDives` | Cockpit + only the deep dives you listed in `-HtmlDeepDiveDomains`. | When you need cockpit *plus* a specific drill-down (e.g. Azure Policy auditor wants the framework-mapped view). |
| `DeepDivesOnly` | Only the listed deep dives. No cockpit. | Pipeline runs that consume just one upstream report (e.g. exporting only Defender for Cloud HTML). |
| `LegacyAll` | Comprehensive + unified + every available domain HTML — the pre-PR-4 layout. | Compatibility mode. Use this if you have an existing automation that depends on the old file set. |

### Command-line invocations

```powershell
# Default — produces just the cockpit
.\Start-EntraChecks.ps1

# Cockpit + Azure Policy + Defender deep dives
.\Start-EntraChecks.ps1 -HtmlReportSet CockpitAndDeepDives `
    -HtmlDeepDiveDomains AzurePolicy,DefenderCompliance

# Just the Secure Score deep dive (no cockpit)
.\Start-EntraChecks.ps1 -HtmlReportSet DeepDivesOnly `
    -HtmlDeepDiveDomains SecureScore

# Old multi-report behavior (compatibility mode)
.\Start-EntraChecks.ps1 -HtmlReportSet LegacyAll
```

### Config-file equivalent

```json
{
  "Assessment": {
    "Output": {
      "Html": {
        "ReportSet": "CockpitAndDeepDives",
        "DeepDiveDomains": ["AzurePolicy", "DefenderCompliance"],
        "OpenPrimaryReport": true,
        "MaxInitialRows": 100
      }
    }
  }
}
```

Precedence: command-line param > config-file `Assessment.Output.Html.*` > hard default (`Cockpit`, `[]`, 100).

---

## 3. Deep-dive domains

Valid values for `-HtmlDeepDiveDomains`:

| Value | Detailed report |
|---|---|
| `SecureScore` | Microsoft Secure Score per-action breakdown |
| `DefenderCompliance` | Defender for Cloud regulatory standards |
| `AzurePolicy` | Azure Policy initiative compliance |
| `PurviewCompliance` | Purview Compliance Manager scores |
| `Delta` | Snapshot delta vs the previous run |
| `PrivilegedIdentity` | Privileged Identity Roster (AD + Entra) |

Rules (per plan §12, enforced by `Get-HtmlReportPlan`):

- **Cockpit mode ignores `-HtmlDeepDiveDomains`** with a warning. The cockpit's Deep Dive Hub still shows status cards for every domain, with "Not generated this run" + how-to hint.
- **CockpitAndDeepDives** with empty `-HtmlDeepDiveDomains` does not infer "all domains" — it emits cockpit alone. This guards against accidental expansion.
- **DeepDivesOnly** with empty `-HtmlDeepDiveDomains` warns and emits no HTML.
- **LegacyAll** ignores `-HtmlDeepDiveDomains` and infers from `AvailableSources` (every collector that produced data gets a report).
- A deep-dive requested for a domain whose data wasn't collected this run produces a warning and is skipped.
- Invalid domain names produce a warning and are skipped; valid neighbours still emit.

---

## 4. Cockpit sections (top to bottom)

The cockpit is organised for analyst workflow — operational sections first, audit / inventory sections further down.

1. **Header and Executive Digest** — posture verdict (`Strong` / `Minor Deficiencies` / `Gaps Identified` / `High Risk` / `Collection Incomplete`), tenant info, total / critical / high / review / quick-wins counts, since-last-assessment delta.
2. **Action Queue** — actionable items only. Filter rule: `Disposition ∈ {Open, ActionRequired, Review, ExpiredException}`. Excludes approved non-expired exceptions, OK, INFO. Sort order: ExpiredException first → Critical/High risk → earliest DueDate → -PriorityScore desc → Owner DisplayName. Interactive: text search + status/risk/disposition selects + expandable rows + "Show more" pagination.
3. **Review Queue** — items needing human judgment. Filter: `Status='REVIEW'` OR `ReviewStatus.State ∈ {NeedsReview, InReview, ActionRequired}`. Same interactive controls as Action Queue.
4. **Source Posture** — cards summarising what was collected. Each source (EntraChecks, Secure Score, Defender, Azure Policy, Purview, Hybrid Correlation, Privileged Identity) renders as a `Collected` (green-bordered) or `Not collected` (gray-bordered) card with a short metric.
5. **Evidence and Provenance** — flat audit table: every v2 Evidence reference with `EvidenceId`, `Source`, `Provider`, `Cmdlet`, `Scope`, `ResourceId`, `Hash`, `RedactionStatus`. Section is suppressed for legacy findings with no v2 Evidence.
6. **Full Findings** — every finding regardless of disposition: FAIL, WARNING, REVIEW, INFO, OK, accepted risks, false positives, out-of-scope, resolved. Filters: text search + status + risk level + disposition + source. Pagination at `MaxInitialRows` (default 100) with a "Show more (100 at a time)" button.
7. **Deep Dive Hub** — status cards for each on-demand domain. Generated cards link directly to the deep-dive file under `DeepDives/`; pending cards show the exact command to generate them.
8. **Integrity Footer** — SHA-256 of canonical findings JSON + sidecar location + the `Test-EntraChecksReportIntegrity` command to verify.

Every dynamic value rendered into the cockpit passes through `ConvertTo-SafeHtml` so injection attempts (`<script>`, `<img onerror=...>`, scheme-relative URLs, etc.) are neutralised.

---

## 5. Row interactivity

Each row in the Action Queue / Review Queue / Full Findings sections is expandable. Click the row header to reveal:

- **Object** (full identifier), **Source** badge, **Check** name
- **Description**, **Remediation summary**
- **Owner** — `DisplayName (Email) · Due: YYYY-MM-DD` when a v2 Owner has been resolved
- **Exception** — `Status / Type · expires YYYY-MM-DD` plus the Justification
- **Evidence** count — pointer to the Evidence and Provenance section for full detail
- **FindingId** — the deterministic `ECF-<20 hex>` identifier (in a `<code>` block) for cross-referencing with snapshots, state files, and CSV exports

### Filtering

The filter controls above each section are wired in via inline JavaScript. No external CDN; works under `file://`. Each row carries `data-*` attributes (`data-status`, `data-disposition`, `data-risk`, `data-source`, `data-search`); the filter handler toggles a `filtered-out` CSS class on non-matching rows.

- **Text search** (`data-search`) is a case-insensitive substring match across Description, Object, Remediation, CheckName, Type, Source, FindingId, Owner DisplayName, and Owner Email.
- **Dropdown filters** are exact-match on the matching `data-*` attribute.
- **Pagination** is per-section. The visible window starts at `MaxInitialRows`; "Show more" adds 100 rows each click. "Showing X of Y" counter updates live.
- **Print stylesheet** hides filter controls and the "Show more" button, and force-expands all row bodies for clean printable output.

### Keyboard and screen-reader access

- Every row header is a real `<button>` — Space/Enter toggles expand, Tab navigates between rows, no separate keydown handler required.
- Buttons publish state via `aria-expanded` (`"false"` collapsed → `"true"` expanded) and `aria-controls="cockpit-body-<hash>"` pointing at the matching body region, so screen readers can jump straight to the revealed detail.
- A "Skip to main content" link is the first focusable element on the page; visible only while focused, it jumps past the report header straight to the cockpit sections.
- Page content lives inside a single `<main id="main-content">` landmark.
- The keyboard focus ring uses `:focus-visible` (3px Microsoft-blue outline) so it only appears for keyboard users — mouse users see no extra chrome.
- Severity is conveyed via badge text **and** color, never color alone.

---

## 6. SOC 2 reports are still separate

SOC 2 readiness and SOC 2 Type 2 reports are NOT part of the cockpit. They remain dedicated audit-package artefacts at:

```
Reports/SOC2/<timestamp>/SOC2-Report.html
Reports/SOC2-TypeTwo/<timestamp>/SOC2-TypeTwo-Report.html
```

Rationale: different audience, different structure, different evidence period, different retention. See [SOC2-Guide.md](SOC2-Guide.md).

---

## 7. Migration from pre-PR-4 behavior

If your workflow depended on the multi-report layout:

| Old file | Cockpit equivalent / migration path |
|---|---|
| `Comprehensive-Assessment-Report-<ts>.html` | Cockpit's Executive Digest + Full Findings + Action Queue. For exact same view → `-HtmlReportSet LegacyAll`. |
| `UnifiedCompliance-Report-<ts>.html` | Cockpit's Source Posture + Evidence and Provenance + Full Findings. For exact same view → `-HtmlReportSet LegacyAll`. |
| `Executive-Summary-<ts>.html` | Cockpit's Executive Digest section. |
| `SecureScore-Report-<ts>.html` | `-HtmlReportSet CockpitAndDeepDives -HtmlDeepDiveDomains SecureScore`. |
| `DefenderCompliance-Report-<ts>.html` | `-HtmlReportSet CockpitAndDeepDives -HtmlDeepDiveDomains DefenderCompliance`. |
| `AzurePolicy-Report-<ts>.html` | `-HtmlReportSet CockpitAndDeepDives -HtmlDeepDiveDomains AzurePolicy`. |
| `PurviewCompliance-Report-<ts>.html` | `-HtmlReportSet CockpitAndDeepDives -HtmlDeepDiveDomains PurviewCompliance`. |
| `DeltaReport-<ts>.html` | `-HtmlReportSet CockpitAndDeepDives -HtmlDeepDiveDomains Delta` (when comparing snapshots). |
| `SOC2-Report.html`, `SOC2-TypeTwo-Report.html` | **Unchanged** — see §6. |

`-GenerateComprehensiveReport`, `-GenerateExecutiveSummary`, `-GenerateExcelReport`, and `-GenerateRemediationScripts` remain accepted. Under Cockpit modes their HTML side-effects are subsumed by the cockpit; under `LegacyAll` they behave as before. Direct calls to `Export-SecureScoreReport`, `Export-DefenderComplianceReport`, etc. still work and are unaffected by the routing.

---

## 8. Integrity verification

Every cockpit run writes a sidecar:

```
Reports/<ts>/EntraChecks-Analyst-Cockpit-<ts>.html
Reports/<ts>/EntraChecks-Analyst-Cockpit-<ts>.html.findings.json   ← canonical findings JSON
```

The HTML footer carries the SHA-256 of the canonical findings JSON. To verify the report wasn't modified after generation:

```powershell
Import-Module .\Modules\EntraChecks-HTMLReporting.psm1 -Force
Test-EntraChecksReportIntegrity -ReportPath .\Reports\<ts>\EntraChecks-Analyst-Cockpit-*.html
```

Returns `IsValid = $true` when the sidecar's recomputed hash matches the hash baked into the report.

---

## 9. Static-report Content Security Policy

The cockpit emits a CSP meta tag in `<head>`:

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none';">
```

- `default-src 'none'` — block everything by default
- `img-src 'self' data:` — allow inline data-URL icons + same-origin images
- `style-src 'unsafe-inline'` — required for the inline `<style>` block (no external CSS — works under `file://`)
- `script-src 'unsafe-inline'` — required for the inline `<script>` block that powers filtering/pagination/expand
- `base-uri 'none'; form-action 'none'` — block tags that could redirect/repurpose the page

No external CDNs, no remote scripts/styles. The report functions identically whether opened over `http://`, `https://`, or `file://`.

---

## 10. Performance budget

The cockpit is designed to stay responsive at typical assessment sizes. Benchmarks on a moderately-spec'd machine (PowerShell 7, macOS):

| Findings | Initialize (normalize + state merge) | Cockpit render | Total |
|---:|---:|---:|---:|
| 500   | 2.4s  | 1.2s | **3.7s** |
| 1,200 | 3.1s  | 1.3s | **4.3s** |
| 5,000 | 12.4s | 6.0s | **18.4s** |

Notable optimizations:

- **Pre-enriched findings pass through** — when the orchestrator runs `Initialize-FindingsForReport` upstream (the default code path), the cockpit detects findings that already have `RiskScore` / `ComplianceMappings` / `RemediationGuidance` populated and skips the `Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance` pipeline. Saves roughly half the wall-clock time on the default code path. External callers that bypass `Initialize-FindingsForReport` still get enrichment as before.
- **List<object> + HashSet** for the cockpit's internal enrichment + dedupe collections instead of array `+=`. Avoids O(n²) memory copies at 1,000+ findings.

Browser interactivity: filter changes are O(n) class toggles. Tested fluid at 1,200 rows.

Pagination is the primary lever for very large tenants — start at `MaxInitialRows=100` (configurable via `Assessment.Output.Html.MaxInitialRows`) and click "Show more" only when you need to.

---

## 11. See also

- [`plans/HTML-Reporting-Consolidation-Plan.md`](../plans/HTML-Reporting-Consolidation-Plan.md) — full plan with goals, non-goals, decisions, security rules
- [`docs/Reporting-Guide.md`](Reporting-Guide.md) — broader reporting overview (Excel + CSV + JSON formats)
- [`docs/Finding-Schema-Guide.md`](Finding-Schema-Guide.md) — the v2 schema that powers the cockpit's rich row content
- [`docs/SOC2-Guide.md`](SOC2-Guide.md) — separate SOC 2 audit reports
