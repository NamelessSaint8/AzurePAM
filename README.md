# EntraChecks — Microsoft Cloud Compliance Assessment Toolkit

**Version 1.0.0** · PowerShell 5.1+ · Windows 10/11 or Server 2016+
**Author:** David Stells

EntraChecks runs read-only security and compliance checks across your Microsoft 365
and Azure environment, then produces actionable HTML/CSV/JSON/Excel reports you can
hand to auditors, leadership, or your remediation team.

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

> **All checks are read-only.** EntraChecks never modifies your tenant.

---

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/K3K71U9F55)

## Quick Start (5 Minutes)

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
│   └── EntraChecks-Hybrid.psm1             # Hybrid identity checks
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

After an assessment, look in the `Reports/` folder. You'll find a timestamped
subfolder containing:

- **Comprehensive HTML Report** — Open this in any browser. Color-coded findings with
  pass/fail/warning status, risk scores, remediation guidance, and an executive summary.
- **Executive Summary** — A concise overview for leadership with key metrics and
  prioritized recommendations.
- **Unified Compliance Report** — Consolidated view across all compliance frameworks
  (CIS, NIST, SOC 2, etc.) when external modules are enabled.
- **CSV Exports** — Prioritized findings, quick wins, and compliance gaps as rows.
  Import into Excel, Power BI, or a SIEM for further analysis.
- **JSON Export** — Machine-readable output for automation pipelines.
- **Excel Report** — Multi-sheet workbook with charts (requires ImportExcel module).

### Finding Severities

| Status    | Meaning                                                       |
|-----------|---------------------------------------------------------------|
| **FAIL**  | Security control is missing or misconfigured. Fix this.       |
| **WARNING** | Partial implementation or best-practice deviation. Review.  |
| **OK**    | Control is properly configured. No action needed.             |
| **INFO**  | Informational finding. No security impact.                    |

### Risk Levels

| Level        | Score Range | Meaning                                              |
|--------------|-------------|------------------------------------------------------|
| **Critical** | 80-100      | Immediate action required — active security risk     |
| **High**     | 60-79       | Fix within days — significant exposure               |
| **Medium**   | 40-59       | Fix within weeks — moderate concern                  |
| **Low**      | 0-39        | Address during next review cycle                     |

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

## Documentation

For detailed documentation, see the `docs/` folder:

- [Getting Started](docs/GETTING-STARTED.md) — Beginner's guide
- [User Guide](docs/USER-GUIDE.md) — Complete reference
- [Configuration Guide](docs/Configuration-Guide.md) — Config file reference
- [Troubleshooting](docs/TROUBLESHOOTING.md) — Extended problem solving
- [API Reference](docs/API-REFERENCE.md) — Function reference
- [Code Quality Guide](docs/CodeQuality-Guide.md) — Quality standards

---

## License & Disclaimer

EntraChecks is provided as-is for security assessment purposes. It performs
**read-only** operations and does not modify your tenant configuration. Always
review findings with your security team before making changes.
