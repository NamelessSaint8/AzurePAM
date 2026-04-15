# Active Directory (On-Prem) Module Guide

**Module:** `EntraChecks-ActiveDirectory.psm1`
**Status:** Shipping in v1.5.1 (this PR migrated the stand-alone `ad/ActiveDirectoryv3.ps1` script into a first-class EntraChecks module.)
**Coverage:** 29 read-only checks against on-premises Active Directory covering privileged access, authentication, delegation, account lifecycle, and infrastructure.

This guide covers: prerequisites, how to run the module, graceful degradation behavior, permission model, finding schema, and a full list of the 29 checks with their Trust Service Criteria / CIS / NIST mappings.

---

## 1. Prerequisites

| Requirement | Why |
|---|---|
| Windows 10/11 or Windows Server 2016+ | The `ActiveDirectory` PowerShell module only runs on Windows. |
| PowerShell 5.1+ | Same as the rest of EntraChecks. |
| RSAT (Remote Server Administration Tools) with the ActiveDirectory DS-LDS module | Provides `Get-ADUser`, `Get-ADComputer`, `Get-ADGroupMember`, etc. |
| GroupPolicy PowerShell module (optional) | Required for the `Test-GPOInventory` and `Test-OUAndGPODelegation` (GPO half) checks. |
| Domain-joined host | The ActiveDirectory module can only query a writable DC when the host is part of the domain. |
| Domain Admin (or Read-Only Domain Admin) | Needed for full check coverage — particularly ACL / drift audits. Lower-privilege accounts will see WARNING findings on the checks they can't read. |

Install RSAT:

```powershell
# Windows 10/11 — as Administrator
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
Get-WindowsCapability -Name RSAT.GroupPolicy* -Online | Add-WindowsCapability -Online
```

---

## 2. Running the module

### Option A — Interactive menu

```powershell
.\Start-EntraChecks.ps1
# Choose [8] Active Directory from the main menu
```

### Option B — CLI / scripted

```powershell
# Only AD checks
.\Start-EntraChecks.ps1 -Mode Quick -TenantName "Contoso" -Modules ActiveDirectory

# AD + cloud checks side-by-side
.\Start-EntraChecks.ps1 -Mode Quick -TenantName "Contoso" -Modules Core,IdentityProtection,ActiveDirectory
```

### Option C — direct module import

```powershell
Import-Module .\Modules\EntraChecks-ActiveDirectory.psm1 -Force

# Run the full assessment
$findings = Invoke-ActiveDirectoryAssessment

# Or one check at a time
Test-UnconstrainedDelegation
Test-KrbTgtAccountAge -MaxAgeDays 90
Test-ADStaleAccounts -UserLogonInactivityDays 90
```

---

## 3. Graceful degradation

The module runs a four-stage environment probe (`Test-ADEnvironment`) before any check fires. If any stage fails, a single diagnostic INFO / WARNING finding is emitted and the assessment returns early — no other checks run, no crashes.

| Stage | What it checks | On failure |
|---|---|---|
| 1. Platform | `$env:OS -eq 'Windows_NT'` | INFO: "Active Directory checks only run on Windows." |
| 2. RSAT | `Get-Module -ListAvailable ActiveDirectory` | INFO: "ActiveDirectory PowerShell module not installed. Install RSAT: ..." |
| 3. Domain join | `Get-ADDomain -ErrorAction Stop` | INFO: "Not domain-joined. AD checks skipped. Expected for cloud-only environments." |
| 4. Permissions | Domain Admin / local Administrators membership on the running token | WARNING: "Running without Domain Admin privileges. ACL / drift checks may return incomplete results." (continues running; individual checks emit WARNING on the items they can't read.) |

This is why the module is safe to leave enabled by default on any machine — it'll just emit a single "not applicable" finding if the environment isn't ready.

---

## 4. Permission model

| Role | Coverage |
|---|---|
| Domain Admin | 100% — all 29 checks fully populate. |
| Enterprise Admin | 100%. |
| Read-Only Domain Admin | 100% for read-only checks (everything in this module). |
| Built-in Administrators (local on a DC) | 100% on a DC; limited off-DC. |
| Domain User | ~70% — most read checks work; ACL audits (AdminSDHolder, OU delegation, privileged-object ACLs) may return partial data with WARNING findings. |

To check what the running user has before the first run:

```powershell
Import-Module .\Modules\EntraChecks-ActiveDirectory.psm1 -Force
Test-ADEnvironment
```

Returns an object with `IsAvailable`, `IsDomainAdmin`, `DomainName`, `FailureReason`.

---

## 5. Finding schema

Every AD finding matches the EntraChecks standard schema and therefore flows into the unified HTML report, Excel workbook, CSV bundle, SOC 2 evidence tables, and delta comparisons alongside cloud findings. Fields:

| Field | Description |
|---|---|
| `Time` | When the finding was emitted. |
| `CheckName` | The `Test-*` function that produced it (e.g., `Test-UnconstrainedDelegation`). |
| `Status` | `PASS` / `FAIL` / `WARNING` / `INFO`. |
| `Severity` | `Critical` / `High` / `Medium` / `Low`. Derived from Status + critical-by-nature check list. |
| `Category` | One of: `Privileged Access`, `Authentication`, `Delegation`, `Account Lifecycle`, `Infrastructure`. |
| `Object` | The entity flagged (UPN, SPN, group name, object DN). |
| `Description` | What was found. |
| `Remediation` | What to do. |
| `ComplianceFrameworks` | Array of framework tags (e.g., `CIS-AD`, `NIST-IA-5`, `SOC2-CC6.1`, `PCI-DSS-3.5`). |
| `ComplianceReference` | Flattened string form of the frameworks array. |
| `RiskScore` | 0-90 derived from Severity. |
| `Type` | `AD_<CheckName>` — used by the unified renderer for grouping. |
| `Source` | Always `ActiveDirectory`. |

---

## 6. Configuration

Optional block in `config/entrachecks.config.json`:

```json
{
  "ActiveDirectory": {
    "Enabled": false,
    "UserLogonInactivityDays": 180,
    "UserPasswordAgeDays": 180,
    "RecentPrivilegedDays": 30,
    "KrbTgtPasswordAgeDays": 180,
    "IncludeComputers": true,
    "PrivilegedGroupWhitelist": {}
  }
}
```

- `Enabled` is advisory only; the actual opt-in is via `-Modules ActiveDirectory` on the CLI, menu `[8]`, or selecting the module in the multi-select menu.
- `PrivilegedGroupWhitelist` is a map of privileged-group-name → array-of-approved-SamAccountName used by `Test-PrivilegedGroupCreep`. Empty defaults to `@('Administrator')` only — intentionally strict so unreviewed admins surface as warnings.

---

## 7. The 29 checks

Grouped by Category. Each row shows the CheckName (callable individually), its escalation ceiling (max Severity when it FAILs), and compliance mappings.

### Privileged Access (10 checks)

| CheckName | Max Severity | Frameworks |
|---|---|---|
| `Test-PrivilegedGroupMembership` | High | CIS-AD, NIST-AC-6, SOC2-CC6.1 |
| `Test-ProtectedUsersAdoption` | Medium | CIS-AD, MCSB-PA-5, SOC2-CC6.1 |
| `Test-PrivilegedSmartcardRequirement` | High | CIS-AD, NIST-IA-2, SOC2-CC6.1 |
| `Test-PrivilegedGroupCreep` | Medium | CIS-AD, NIST-AC-6, SOC2-CC6.1 |
| `Test-AdminSDHolderDrift` | **Critical** | CIS-AD, NIST-AC-6, SOC2-CC6.1 |
| `Test-DangerousSIDsInPrivilegedGroups` | **Critical** | CIS-AD, NIST-AC-6, SOC2-CC6.1 |
| `Test-PrivilegedObjectACLs` | Medium | CIS-AD, NIST-AC-6, SOC2-CC6.1 |
| `Test-OUAndGPODelegation` | Medium | CIS-AD, NIST-AC-6 |
| `Test-RecentPrivilegedAccounts` | High | CIS-AD, NIST-AC-2, SOC2-CC6.1 |
| `Test-NestedGroupPrivilegePaths` | Medium | CIS-AD, NIST-AC-6 |
| `Test-SIDHistory` | Medium | CIS-AD, NIST-AC-6 |
| `Test-SensitiveObjectACLDrift` | High | CIS-AD, NIST-AC-6, SOC2-CC6.1 |
| `Test-ShadowGroupNames` | Medium | CIS-AD, NIST-AC-6 |

### Authentication (6 checks)

| CheckName | Max Severity | Frameworks |
|---|---|---|
| `Test-ADPasswordPolicy` | High | CIS-AD, NIST-IA-5, SOC2-CC6.2, PCI-DSS-8.3 |
| `Test-KrbTgtAccountAge` | **Critical** | CIS-AD, NIST-IA-5, SOC2-CC6.1 |
| `Test-KerberosPreAuthDisabled` | High | CIS-AD, MCSB-IM, SOC2-CC6.2 |
| `Test-DuplicateSPNs` | High | CIS-AD, MCSB-IM |
| `Test-UserAccountsWithSPN` | Medium | CIS-AD, MCSB-IM, SOC2-CC6.2 |
| `Test-GPPPasswords` | **Critical** | CIS-AD, NIST-IA-5, SOC2-CC6.1, PCI-DSS-3.5 |

### Delegation (2 checks)

| CheckName | Max Severity | Frameworks |
|---|---|---|
| `Test-UnconstrainedDelegation` | **Critical** | CIS-AD, MCSB-IM, SOC2-CC6.1 |
| `Test-DelegationOverview` | Medium (INFO-only) | CIS-AD, MCSB-IM, SOC2-CC6.1 |

### Account Lifecycle (4 checks)

| CheckName | Max Severity | Frameworks |
|---|---|---|
| `Test-ADStaleAccounts` | Medium | CIS-AD, NIST-AC-2, SOC2-CC6.2 |
| `Test-PasswordNeverExpires` | High | CIS-AD, NIST-IA-5, SOC2-CC6.2 |
| `Test-ADServiceAccounts` | Medium (INFO-only) | CIS-AD, NIST-IA-5 |
| `Test-PasswordsInDescription` | High | CIS-AD, NIST-IA-5 |

### Infrastructure (4 checks)

| CheckName | Max Severity | Frameworks |
|---|---|---|
| `Test-ADForestAndDomain` | Low (INFO-only) | CIS-AD, NIST-CM-8 |
| `Test-DomainControllers` | Low (INFO-only) | CIS-AD, NIST-CM-8, SOC2-CC6.1 |
| `Test-DomainTrusts` | Medium | CIS-AD, NIST-AC-3 |
| `Test-GPOInventory` | Low (INFO-only) | CIS-AD |

---

## 8. Running a single check

All 29 `Test-*` functions are exported. Pass configurable parameters where supported:

```powershell
Test-ADStaleAccounts -UserLogonInactivityDays 90 -UserPasswordAgeDays 90
Test-KrbTgtAccountAge -MaxAgeDays 90
Test-RecentPrivilegedAccounts -RecentDays 14
Test-PrivilegedGroupCreep -Whitelist @{
  'Domain Admins'     = @('Administrator','Alice')
  'Enterprise Admins' = @('Administrator')
  'Schema Admins'     = @('Administrator')
}
```

Individual `Test-*` calls append findings to `$script:Findings` inside the module. To retrieve them:

```powershell
& (Get-Module EntraChecks-ActiveDirectory) { $script:Findings }
```

(Or just use `Invoke-ActiveDirectoryAssessment -IncludeChecks @('Test-UnconstrainedDelegation')`, which returns the array directly.)

---

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Single INFO: "Not running on Windows" | You're on macOS / Linux / PS Core on WSL. | Run on a Windows host. |
| Single INFO: "ActiveDirectory PowerShell module not installed" | RSAT isn't installed. | `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` |
| Single INFO: "Not domain-joined" | The host isn't part of the target AD domain. | Run from a domain-joined workstation or jump box. |
| WARNING: "Running without Domain Admin privileges" | Current user isn't in Domain Admins / Administrators. | Re-run as Domain Admin for full coverage (or accept the partial results). |
| Many WARNING findings on ACL checks, no FAILs | Running as non-Domain-Admin. | As above. |
| `Test-GPOInventory` returns "GroupPolicy module not installed" | RSAT GroupPolicy feature not added. | `Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0` |
| `Test-GPPPasswords` says "Unable to scan SYSVOL" | User can't read SYSVOL. | Run as Domain User or higher; all authenticated users should have SYSVOL read. Check antimalware isn't blocking. |
| `Test-PrivilegedSmartcardRequirement` returns FAIL for many accounts | Environment doesn't use smartcard. | That's not a check bug — consider adopting Windows Hello for Business / smartcard for privileged accounts, or rule the check out via `-ExcludeChecks`. |

---

## 10. What's next (PR 2)

PR 2 will add:

- **Four new checks** — `Test-LAPSDeployment`, `Test-DCSecuritySettings` (LDAP signing / channel binding, SMB signing), `Test-KerberoastableAccounts` (password-age correlation on top of `Test-UserAccountsWithSPN`), `Test-DirSyncAccountSecurity` (Azure AD Connect service account privilege audit).
- **New `[H] Hybrid Analysis` menu item** that runs cloud + hybrid + AD checks in one invocation and produces a **correlation report** (users flagged in both Entra Identity Protection AND on-prem AD).
- **SOC 2 CC6 evidence section** — AD findings flow into the SOC 2 report's control-evidence tables automatically.

Deferred to future PRs:

- AD CS template vulnerabilities (ESC1-8).
- BloodHound-style ACL abuse path enumeration.
- SMBv1 / NetBIOS / LLMNR host enumeration.
- Reversible-encryption audit (low finding count in practice).

See [plans/AD-PR2-HybridAnalysis-Plan.md](../plans/AD-PR2-HybridAnalysis-Plan.md) for details.
