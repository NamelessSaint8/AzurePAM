# EntraChecks — Microsoft Cloud Compliance Assessment Toolkit

**Version 1.7.0** · Windows desktop app + PowerShell 5.1+ CLI · Windows 10/11 or Server 2016+
**Author:** David Stells

EntraChecks runs read-only security and compliance checks across your Microsoft 365
and Azure environment, then produces actionable HTML/CSV/JSON/Excel reports you can
hand to auditors, leadership, or your remediation team.

## Two ways to run

| | Use this if you want… |
|---|---|
| **🖥️ Desktop app** (new in 1.7.0) | A point-and-click GUI. Module / deep-dive selection via checkboxes, live streaming output, auto-install of missing PowerShell modules. Best for most users. |
| **⌨️ PowerShell CLI / TUI** | Headless / scheduled / CI use, or the menu-driven console. The CLI is unchanged from 1.6.0 and remains fully supported. |

Both surfaces drive the same assessment engine and produce the same reports.

---

## What Gets Assessed

| Module               | What It Checks                                                        | License Needed            |
|----------------------|-----------------------------------------------------------------------|---------------------------|
| **Core**             | Conditional Access, MFA, password policies, admin roles, guest access | Azure AD Free (or higher) |
| **IdentityProtection** | Risky users, risky sign-ins, risk-based CA policies                 | Azure AD Premium P2       |
| **Devices**          | Intune compliance, BitLocker, device encryption, stale devices        | Microsoft Intune          |
| **SecureScore**      | Microsoft Secure Score breakdown and improvement actions               | Any M365 plan             |
| **Defender**         | Defender for Cloud regulatory compliance (CIS, NIST, PCI-DSS, etc.)  | Defender for Cloud        |
| **AzurePolicy**      | Azure Policy compliance state across subscriptions                    | Any Azure subscription    |
| **Purview**          | Compliance Manager assessment scores and improvement actions           | M365 E5 Compliance        |
| **SOC 2**            | AICPA TSC 2017 (revised 2022) readiness — Type 1 + Type 2 period coverage, evidence bundle with SHA-256 chain-of-custody, PII redaction, white-label branding | Any M365 plan (Premium tier unlocks more controls) |
| **Active Directory** | **On-premises AD** — 33 checks covering privileged access (including LAPS, DirSync account audit), authentication (KRBTGT, Kerberos pre-auth, Kerberoastable accounts with password-age correlation), delegation, account lifecycle, and DC security settings (LDAP signing, channel binding, SMB signing) | Domain-joined Windows + RSAT |

> **All checks are read-only.** EntraChecks never modifies your tenant.

### Running modes

| Mode | What runs | When to use |
|---|---|---|
| **Desktop app** | GUI-driven; full module + deep-dive choice via checkboxes | Most users; live streaming output |
| `-Mode Interactive` (default CLI) | Menu-driven console | Ad-hoc exploration from a shell |
| `-Mode Quick` | All cloud modules | Fast full cloud assessment |
| `-Mode Scheduled` | All cloud modules, silent | CI/CD, scheduled tasks |
| `-Mode Hybrid` | Cloud + on-prem AD + cross-plane correlation | Hybrid-identity environments; see [docs/Hybrid-Analysis-Guide.md](docs/Hybrid-Analysis-Guide.md) |

---

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/K3K71U9F55)

## Desktop App — Quick Start (Windows)

1. Download **`EntraChecks_<version>_x64-setup.exe`** from the
   [latest release](https://github.com/f8l124/AzurePAM/releases/latest).
2. Run the installer. The first time you launch it Windows SmartScreen will
   show **"Windows protected your PC"** — this is expected for unsigned
   installers from small projects. Click **More info → Run anyway**.
   (The installer is built unsigned by design; see
   [Code signing](#code-signing-smartscreen-warning) below for the rationale
   and how to flip CI to signed if you ever add a code-signing cert.)
3. Launch EntraChecks from the Start menu. On first run it'll check for the
   PowerShell modules it needs (Microsoft.Graph, Az.\*, ImportExcel) and
   offer to install anything missing — one click, no shell required.
4. Enter your tenant, pick an auth method (device code, browser sign-in, or
   "use existing session"), tick which modules and deep-dives to run, and
   click **Run assessment**.
5. Output streams live in the log pane. When the run finishes, the **Result**
   card shows finding counts plus direct **Open cockpit-html** / **Open json**
   buttons pointing at the generated reports under your temp folder.

The desktop app is a thin Tauri shell that spawns the same PowerShell engine
the CLI uses, so anything you can do in the CLI you can do from the GUI
(module selection, deep-dive opt-in, auth-method choice, etc.).

### Installing via a package manager

If you prefer not to download the `.exe` by hand, EntraChecks is listed in:

**Scoop**

```powershell
# Add this repo as a Scoop bucket (one-time setup)
scoop bucket add entrachecks https://github.com/f8l124/AzurePAM

# Then install (needs an elevated shell — the NSIS installer writes to
# Program Files)
scoop install entrachecks
```

**WinGet** (after the first manifest is accepted into `microsoft/winget-pkgs` — see [Packaging](#packaging) for status)

```powershell
winget install Stells.EntraChecks
```

Both channels pull the same NSIS installer that lives on the GitHub
release; the package manager just handles the download + invocation +
later upgrades for you.

---

## PowerShell CLI Quick Start (5 Minutes)

### Step 1 — Install Prerequisites

Open **PowerShell as Administrator** and run:

```powershell
# Install the Microsoft Graph SDK (required for all modules)
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber

# Install Azure modules (only if you plan to run AzurePolicy or Defender modules)
Install-Module Az.Accounts       -Scope CurrentUser -Force
Install-Module Az.PolicyInsights  -Scope CurrentUser -Force
Install-Module Az.Resources       -Scope CurrentUser -Force
Install-Module Az.Security        -Scope CurrentUser -Force

# Optional: Excel report generation
Install-Module ImportExcel -Scope CurrentUser -Force
```

Or just run the included helper script:

```powershell
.\Install-Prerequisites.ps1
```

### Step 2 — Unblock the Scripts (Windows Security)

After extracting the zip, Windows may block the downloaded scripts. Run this once
from the `EntraChecks` folder:

```powershell
Get-ChildItem -Recurse -Include *.ps1,*.psm1 | Unblock-File
```

### Step 3 — Grant Admin Consent (First Time Only)

EntraChecks requests 11 admin-level Graph permissions. A **Global Administrator**
needs to grant consent once:

```powershell
.\Grant-AdminConsent.ps1
```

They must check **"Consent on behalf of your organization"** in the consent screen.
After consent, any user with a **Global Reader** (or higher) role can run EntraChecks.

### Step 4 — Run EntraChecks

```powershell
.\Start-EntraChecks.ps1
```

The interactive menu walks you through everything from here — authentication, module
selection, and report generation.

---

## Running Modes

### Interactive (Default)

```powershell
.\Start-EntraChecks.ps1
```

A menu lets you pick individual modules, view reports, manage snapshots, and compare
results over time.

### Quick Mode

```powershell
.\Start-EntraChecks.ps1 -Mode Quick -TenantName "Contoso" -Modules All
```

Runs every module with minimal prompts. Great for a one-shot full assessment.

### Scheduled / CI-CD Mode

```powershell
.\Start-EntraChecks.ps1 -Mode Scheduled -Modules Core,SecureScore -SaveSnapshot
```

Silent execution with no prompts. Ideal for Task Scheduler or Azure DevOps pipelines.
Returns exit code 1 if any FAIL findings are detected.

### Using a Configuration File

```powershell
.\Start-EntraChecks.ps1 -ConfigFile ".\config\entrachecks.config.json"
```

### SOC 2 Readiness

EntraChecks runs a TSC-structured SOC 2 readiness pass that complements the
core security checks. Two ways to invoke it:

```powershell
# From the interactive menu: select [6] SOC 2 Readiness, [7] SOC 2 Type 2 (period coverage)
.\Start-EntraChecks.ps1

# Or auto-run alongside Quick Assessment by setting SOC2.Enabled = true in
# config\entrachecks.config.json — the SOC 2 report is then produced as
# part of every Quick / Scheduled run.
.\Start-EntraChecks.ps1 -Mode Quick -Modules All
```

The SOC 2 pass produces a standalone TSC report (HTML + Excel + CSV) plus an
evidence bundle with SHA-256 chain-of-custody and an optional ACL-locked
identity-resolution map for re-resolving redacted hashes. See
[docs/SOC2-Guide.md](docs/SOC2-Guide.md) for the full workflow.

### Reducing Authentication Prompts

A SOC 2-enabled run authenticates against **two distinct identity planes**
(Microsoft Graph + Azure Resource Manager). Their tokens cannot be shared,
so the floor is two browser sign-ins. Pre-grant admin consent once via
`Grant-AdminConsent.ps1` to eliminate the consent dialog. To skip the Azure
prompt as well, run `Connect-AzAccount` in the same shell before launching
`Start-EntraChecks.ps1` — the cached Az context is reused.

---

## Parameters Reference

| Parameter            | Type       | Default         | Description                                           |
|----------------------|------------|-----------------|-------------------------------------------------------|
| `-Mode`              | String     | `Interactive`   | `Interactive`, `Quick`, or `Scheduled`                |
| `-TenantName`        | String     | *(prompted)*    | Friendly label for the tenant (used in report names)  |
| `-OutputDirectory`   | String     | `.\Reports`     | Where reports are written                             |
| `-Modules`           | String[]   | *(all)*         | Which modules to run (see table above)                |
| `-ConfigFile`        | String     | *(none)*        | Path to a JSON configuration file                     |
| `-SkipAuthentication`| Switch     | `$false`        | Reuse an existing Graph/Azure session                 |
| `-SaveSnapshot`      | Switch     | `$false`        | Save results for later comparison                     |
| `-CompareWithLast`   | Switch     | `$false`        | Auto-compare with the most recent snapshot            |
| `-ExportFormat`      | String     | `All`           | `HTML`, `CSV`, `JSON`, `Excel`, or `All`              |

---

## Folder Structure

```
EntraChecks/
├── Start-EntraChecks.ps1          # Main entry point (run this)
├── Install-Prerequisites.ps1      # One-click dependency installer
├── Grant-AdminConsent.ps1         # Admin consent helper
├── Scripts/                       # Support scripts
│   ├── Invoke-EntraChecks.ps1             # Core assessment engine (25+ checks)
│   ├── New-ComprehensiveAssessmentReport.ps1  # Full report generator
│   ├── New-ExecutiveSummary.ps1           # Executive summary generator
│   └── Invoke-CodeQualityCheck.ps1        # PSScriptAnalyzer runner
├── Modules/                       # PowerShell modules
│   ├── EntraChecks-Connection.psm1         # Authentication & permissions
│   ├── EntraChecks-Compliance.psm1         # Compliance framework engine
│   ├── EntraChecks-IdentityProtection.psm1 # Identity risk checks
│   ├── EntraChecks-Devices.psm1            # Intune & device checks
│   ├── EntraChecks-SecureScore.psm1        # Secure Score integration
│   ├── EntraChecks-DefenderCompliance.psm1 # Defender for Cloud
│   ├── EntraChecks-AzurePolicy.psm1        # Azure Policy compliance
│   ├── EntraChecks-PurviewCompliance.psm1  # Purview Compliance Manager
│   ├── EntraChecks-RiskScoring.psm1        # Risk calculation engine
│   ├── EntraChecks-HTMLReporting.psm1      # HTML report generation
│   ├── EntraChecks-ExcelReporting.psm1     # Excel report generation
│   ├── EntraChecks-DeltaReporting.psm1     # Snapshot comparison engine
│   ├── EntraChecks-RemediationGuidance.psm1 # Remediation instructions
│   ├── EntraChecks-Hybrid.psm1             # Hybrid identity checks
│   ├── EntraChecks-SOC2.psm1               # SOC 2 TSC catalog + assessment engine
│   ├── EntraChecks-SOC2Reporting.psm1      # SOC 2 HTML/Excel/CSV renderer
│   ├── EntraChecks-SOC2TypeTwo.psm1        # SOC 2 Type 2 period coverage
│   ├── EntraChecks-ActiveDirectory.psm1    # On-prem AD (33 checks, 5 categories)
│   ├── EntraChecks-HybridCorrelation.psm1  # Cross-plane principal correlation
│   └── EntraChecks-Branding.psm1           # White-label branding helper
├── config/                        # Configuration files
│   ├── entrachecks.config.json             # Default configuration
│   └── entrachecks.config.prod.json        # Production overrides
├── docs/                          # Detailed documentation
├── Examples/                      # Usage examples and sample scripts
├── Tests/                         # Test scripts
├── Reports/                       # Generated reports (auto-created)
├── Snapshots/                     # Saved assessment snapshots
├── Logs/                          # Log files
├── PSScriptAnalyzerSettings.psd1  # Code quality rules
├── README.md                      # This file
└── LICENSE                        # MIT License
```

---

## Permissions Required

EntraChecks requests **read-only** Microsoft Graph permissions. The exact scopes
depend on which modules you run:

| Module               | Graph Scopes                                                                 |
|----------------------|------------------------------------------------------------------------------|
| Core                 | `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`                |
| IdentityProtection   | `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All`                  |
| Devices              | `Device.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All` |
| SecureScore          | `SecurityEvents.Read.All`                                                    |
| Purview              | `InformationProtectionPolicy.Read`                                           |

For the **AzurePolicy** and **Defender** modules, you also need an Azure session
(`Connect-AzAccount`) with **Reader** access on the subscriptions you want to assess.

### Minimum Role

**Global Reader** is sufficient for all read-only checks. If you use an account with
fewer permissions, EntraChecks will still run — it simply skips checks it can't access
and tells you which ones were skipped.

---

## Understanding the Output

After an assessment, look in the `Reports/` folder. You'll find a timestamped subfolder. **By default** (since the cockpit consolidation work), you'll get:

```
Reports/<timestamp>/
  EntraChecks-Analyst-Cockpit-<timestamp>.html        ← primary HTML
  EntraChecks-Analyst-Cockpit-<timestamp>.html.findings.json   (integrity sidecar)
  Assessment-Data-<timestamp>.json                    (machine-readable v2 findings)
  CSV/                                                (when ImportExcel is missing)
  EntraChecks-Comprehensive-Assessment-<timestamp>.xlsx   (when ImportExcel is present)
```

### Analyst Cockpit HTML (primary)

The cockpit is a single self-contained HTML file with 8 sections in workflow order:

1. **Executive Digest** — posture verdict (`Strong` / `Minor Deficiencies` / `Gaps Identified` / `High Risk` / `Collection Incomplete`), key counts, since-last-assessment delta.
2. **Action Queue** — actionable items only. Excludes approved exceptions, OK, INFO. Sorted with expired exceptions first, then by risk → due date → priority. Text search + status / risk / disposition filters + pagination + expandable rows.
3. **Review Queue** — items needing human judgment (`Status='REVIEW'` or `ReviewStatus.State` in NeedsReview / InReview / ActionRequired).
4. **Source Posture** — cards summarising what was collected (Secure Score, Defender, Azure Policy, Purview, etc.) with collected vs not-collected state.
5. **Evidence and Provenance** — flat audit table of every v2 Evidence reference (EvidenceId, Source, Provider, Cmdlet, Scope, Hash, RedactionStatus).
6. **Full Findings** — every finding regardless of disposition (FAIL/WARNING/REVIEW/OK/INFO/accepted-risks/etc.). 5 filters + pagination.
7. **Deep Dive Hub** — status cards for each on-demand domain. Generated reports link directly to files under `DeepDives/`; pending reports show the exact command to generate them.
8. **Integrity Footer** — SHA-256 of canonical findings JSON + verification command.

All values HTML-encoded; static-report Content Security Policy in `<head>`; no external CDNs (works under `file://`). Filter / pagination JS is inlined.

### Switching to multi-report mode

The pre-cockpit multi-report layout is preserved via:

```powershell
.\Start-EntraChecks.ps1 -HtmlReportSet LegacyAll
```

That restores the comprehensive + unified + per-domain HTML files at the root of the report folder.

### Generating deep dives selectively

```powershell
# Cockpit + just the deep dives you want, under DeepDives/
.\Start-EntraChecks.ps1 -HtmlReportSet CockpitAndDeepDives `
    -HtmlDeepDiveDomains AzurePolicy,DefenderCompliance,SecureScore
```

Valid domains: `SecureScore`, `DefenderCompliance`, `AzurePolicy`, `PurviewCompliance`, `Delta`, `PrivilegedIdentity`.

Full reference: [docs/Cockpit-Report-Guide.md](docs/Cockpit-Report-Guide.md).

### Other outputs

- **SOC 2 reports** — Stay separate when `SOC2.Enabled = true`. Different audience, retention, and evidence-period semantics. See [docs/SOC2-Guide.md](docs/SOC2-Guide.md).
- **Excel report** — Multi-sheet workbook with the v2 schema sheets (Analyst Queue / Review Queue / Control Register / Evidence Register / Exceptions / Remediation Plan). Requires `ImportExcel` module; renderer falls back to numbered CSVs when not installed.
- **CSV exports** — Flat-row format via `ConvertTo-FindingFlatRow`. Owner / Exception / ReviewStatus flattened to prefixed scalar columns; ControlMappings / Evidence / Tags / Links semicolon-joined.
- **JSON export** — Full v2 finding objects at `-Depth 15`. `Metadata.SchemaVersion='2.0'`. Round-trips Owner / Exception / ControlMappings / Evidence / RemediationDetail cleanly.

### Finding Severities

| Status    | Meaning                                                       |
|-----------|---------------------------------------------------------------|
| **FAIL**  | Security control is missing or misconfigured. Fix this.       |
| **WARNING** | Partial implementation or best-practice deviation. Review.  |
| **REVIEW** | Needs human judgment (e.g. OAuth grants, stale accounts).    |
| **OK**    | Control is properly configured. No action needed.             |
| **INFO**  | Informational finding. No security impact.                    |

### Risk Levels

| Level        | Score Range | Meaning                                              |
|--------------|-------------|------------------------------------------------------|
| **Critical** | 80-100      | Immediate action required — active security risk     |
| **High**     | 60-79       | Fix within days — significant exposure               |
| **Medium**   | 40-59       | Fix within weeks — moderate concern                  |
| **Low**      | 0-39        | Address during next review cycle                     |
| **Review**   | n/a         | Human-judgment items; sorted by underlying RiskScore |

---

## Central Finding Schema & GRC Workflow

Every finding is normalised to a stable v2 schema (`SchemaVersion='2.0'`) before reports are emitted. Each finding carries a deterministic `FindingId` (`ECF-<20 hex>`), derived `Disposition`, framework-flattened `ControlMappings`, and an `Evidence` chain of provenance references.

Analyst workflow state (Owner / Exception / ReviewStatus / Tags) lives in a local JSON file (`config/finding-state.local.json`, gitignored) and is overlaid onto findings at report time **without** mutating the raw assessment record. Audit facts stay immutable; analyst overlays show up in the Excel `Analyst Queue` / `Exceptions` sheets and the HTML `Action Queue` / `Exceptions Lifecycle` sections.

- **Full reference:** [docs/Finding-Schema-Guide.md](docs/Finding-Schema-Guide.md)
- **Reporting surfaces:** [docs/Reporting-Guide.md](docs/Reporting-Guide.md)
- **Example state file:** [config/finding-state.example.json](config/finding-state.example.json)
- **Example workflow:** [Examples/Example-FindingState.ps1](Examples/Example-FindingState.ps1)

---

## Verifying Report Integrity

The unified HTML report ships with a SHA-256 hash of its canonical findings
JSON in the footer, plus a sibling `<report>.html.findings.json` sidecar.
Verify the report wasn't modified after generation:

```powershell
Import-Module .\Modules\EntraChecks-HTMLReporting.psm1 -Force
Test-EntraChecksReportIntegrity -ReportPath .\Reports\<timestamp>\Comprehensive-Assessment-*.html
```

Returns `IsValid = $true` when the sidecar's recomputed hash matches the
hash baked into the report. Useful for chain-of-custody when handing
reports to auditors or storing them long-term.

(For the SOC 2 evidence bundle's separate hash chain, see
`Test-SOC2EvidenceBundle` in [docs/SOC2-Guide.md](docs/SOC2-Guide.md).)

---

## Snapshots & Delta Reporting

EntraChecks can save assessment results as **snapshots** so you can track your
security posture over time:

```powershell
# Save a snapshot after running
.\Start-EntraChecks.ps1 -Mode Quick -Modules All -SaveSnapshot

# Compare with the last snapshot on the next run
.\Start-EntraChecks.ps1 -Mode Quick -Modules All -SaveSnapshot -CompareWithLast
```

The delta report highlights what improved, what regressed, and what's new since the
last assessment. This is invaluable for demonstrating progress to auditors.

The unified HTML report also accepts a `-PreviousAssessment` parameter to render an
inline **"Since last assessment"** card row in the executive section (Resolved / New
/ Persistent counts) — handy when you want the delta visible without producing a
separate delta report.

In Interactive mode, the **Manage Snapshots** and **Compare Snapshots** menus give
you full control over snapshot selection and comparison.

---

## Troubleshooting

### "Running scripts is disabled on this system"

PowerShell's execution policy is blocking scripts. Run this once as Administrator:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "The term 'Connect-MgGraph' is not recognized"

The Microsoft Graph module isn't installed. Run:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

### "Microsoft Graph authentication failed"

EntraChecks requests admin-level permissions that require Global Admin consent.
Run `.\Grant-AdminConsent.ps1` and have a Global Administrator check **"Consent on
behalf of your organization"** in the consent screen.

Alternatively, use device code authentication from the interactive menu.

### "Insufficient privileges" or blank results

Your account doesn't have the required Graph permissions. Either:
- Sign in with a **Global Reader** or **Global Administrator** account, or
- Ask your admin to grant the needed scopes (listed above) via admin consent.

### Unicode characters display as garbage

PowerShell's console encoding is not set to UTF-8. Add to your PowerShell profile:

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
```

Or run `.\Scripts\Fix-FileEncoding.ps1` once.

### "Az.PolicyInsights module not found"

Only needed for Azure Policy checks. Install with:

```powershell
Install-Module Az.PolicyInsights -Scope CurrentUser -Force
```

### Browser doesn't open for sign-in

Try running PowerShell outside of ISE (use Windows Terminal or the regular
PowerShell console). ISE sometimes interferes with interactive authentication.

---

## Advanced: App Registration (Unattended)

For CI/CD or scheduled runs without interactive sign-in, register an app in
Azure AD:

1. Go to **Azure Portal > App registrations > New registration**
2. Add the API permissions listed above (Application type, not Delegated)
3. Grant admin consent
4. Create a certificate and upload the public key
5. Run EntraChecks with certificate auth:

```powershell
.\Start-EntraChecks.ps1 -Mode Scheduled `
    -AuthMode Application `
    -TenantId "your-tenant-id" `
    -ClientId "your-app-id" `
    -ClientCertificateThumbprint "your-cert-thumbprint" `
    -Modules All -SaveSnapshot
```

---

## Packaging

EntraChecks ships as:

- **GitHub Releases** (canonical) — `EntraChecks_<version>_x64-setup.exe`
  is attached to each release for direct download.
- **Scoop bucket** — this repo doubles as a Scoop bucket via
  [`bucket/entrachecks.json`](bucket/entrachecks.json). On every published
  release a [`scoop-update.yml`](.github/workflows/scoop-update.yml)
  workflow recomputes the SHA256 and bumps the manifest in-place.
- **WinGet** — submission pipeline lives in
  [`winget-submit.yml`](.github/workflows/winget-submit.yml). It uses
  [`vedantmgoyal9/winget-releaser`](https://github.com/vedantmgoyal9/winget-releaser)
  to open a PR against `microsoft/winget-pkgs` whenever a release is
  published. The workflow is a no-op until the `WINGET_TOKEN` repo
  secret is set (a fine-grained PAT with `Contents: write` and
  `Pull requests: write` on the user who'll fork `microsoft/winget-pkgs`).
  The very first submission gets human-reviewed by WinGet maintainers
  (1–3 days); after that, future releases auto-submit under the
  `Stells.EntraChecks` identifier.

Microsoft Store packaging is deferred; the Tauri shell could be repackaged
as MSIX if the free Microsoft signing route ever becomes worth the effort.
Chocolatey isn't currently planned — happy to take a contribution.

---

## Code signing (SmartScreen warning)

The v1.7.0 Windows installer is **unsigned by design** — purchased code-signing
certificates run $200–$500+/year and EntraChecks is a free tool. On first
install Windows SmartScreen will show "Windows protected your PC"; click
**More info → Run anyway** and you're through. The warning gradually fades as
the installer's download reputation builds with Microsoft.

If you ever want signed builds, the CI is already wired for it:

- Add a `SIGN_CERT_THUMBPRINT` repository secret.
- The next push to `main` (or a `v*` tag) will produce a signed NSIS installer
  with zero code changes required.

Realistic free paths to a real cert: [SignPath
Foundation](https://signpath.org/) (free OV-equivalent for established
open-source projects — application process), or [Azure Trusted
Signing](https://learn.microsoft.com/en-us/azure/trusted-signing/overview)
(~$120/yr, requires verified individual or D&B-registered organisation).

See [docs/Release-Signing-Guide.md](docs/Release-Signing-Guide.md) for the
full signing pipeline details.

---

## Documentation

For detailed documentation, see the `docs/` folder:

- [Getting Started](docs/GETTING-STARTED.md) — Beginner's guide
- [User Guide](docs/USER-GUIDE.md) — Complete reference
- [Cockpit Report Guide](docs/Cockpit-Report-Guide.md) — Walks through the analyst cockpit (sections, filters, accordions, deep-dive hub states)
- [Finding Schema Guide](docs/Finding-Schema-Guide.md) — v2 finding schema, FindingId derivation, ControlMappings / Evidence shape
- [SOC 2 Guide](docs/SOC2-Guide.md) — TSC coverage, redaction, evidence bundle, Type 2 period coverage
- [Active Directory Guide](docs/ActiveDirectory-Guide.md) — on-prem AD checks, permission model, all 33 checks with framework mappings
- [Hybrid Analysis Guide](docs/Hybrid-Analysis-Guide.md) — cloud + on-prem correlation, Confidence flags, report layout
- [Configuration Guide](docs/Configuration-Guide.md) — Config file reference
- [Release Signing Guide](docs/Release-Signing-Guide.md) — Signing the desktop installer (when you eventually have a cert)
- [Troubleshooting](docs/TROUBLESHOOTING.md) — Extended problem solving
- [API Reference](docs/API-REFERENCE.md) — Function reference
- [Code Quality Guide](docs/CodeQuality-Guide.md) — Quality standards

---

## License & Disclaimer

EntraChecks is provided as-is for security assessment purposes. It performs
**read-only** operations and does not modify your tenant configuration. Always
review findings with your security team before making changes.
