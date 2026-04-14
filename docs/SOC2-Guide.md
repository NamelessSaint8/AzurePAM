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

The HTML report groups findings by TSC family (CC, A, C, PI, P) and lists every
control in scope. Each control shows its:
- Automation status (Automated / Supporting / Manual)
- Control owner hint (Security, Identity, IT Ops, Compliance, etc.)
- Findings table with status, severity, object, description, remediation

The Excel workbook provides a Cover sheet, Summary by Category, Control
Register, per-family Findings sheets, Manual Attestation register, and Evidence
Register.

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

Open the report directly from the file system (not over `http://`). The
sidebar will automatically load the resolution map and expose a text field
where you can paste a hash prefix (12+ chars is usually unique) to get back the
UPN and display name.

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

Type 2 reporting (control operated consistently over a period of coverage)
requires a snapshot history. This is planned for Phase 3. Until then, use
`Type = "Type1"` for point-in-time readiness.

To prepare for Type 2:
1. Start taking weekly snapshots now (Save-ComplianceSnapshot in scheduled mode).
2. Use a stable `SaltDirectory` across runs so redacted hashes are referentially
   consistent.
3. When Phase 3 ships, `New-SOC2TypeTwoReport` will consume the snapshot
   history and emit a period-coverage report.

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
| Identity lookup sidebar shows "Could not load resolution map" | HTML opened over `http://` (browsers block local-file fetch) | Open the report directly from the file system (`file://`). |
| Every TSC shows `MANUAL` | No mapped EntraChecks findings yet | Ensure the Core assessment ran; check that `Add-ComplianceMapping` resolved your findings' `Type`. |
| `Invalid white-label branding configuration` at startup | `WhiteLabel = true` but `OrganizationName` is blank | Fill in `SOC2.Branding.OrganizationName` in the config. |
| `Test-SOC2EvidenceBundle` reports mismatches | Someone edited a file in the bundle | Investigate; never hand-edit evidence files — regenerate instead. |

---

## 11. What's next (Phase 2+)

- Deeper A / C automation (backup, service health, encryption posture).
- Break-glass verification for CC7.5.
- Type 2 period coverage and consistency evidence.
- Optional CMS signing of evidence bundles via Azure Key Vault.
- Priva-based privacy signals when licensed.

Track the current roadmap in
`plans\SOC2-Implementation-Plan.md`.
