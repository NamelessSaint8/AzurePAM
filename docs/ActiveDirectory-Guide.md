# Active Directory (On-Prem) Module Guide

**Module:** `EntraChecks-ActiveDirectory.psm1`
**Status:** v1.8.0 adds PR 4a — credential hygiene (LM hash, NTLMv1, DC Kerberos encryption, null sessions, domain encryption policy) and ACL abuse path detection (writable privileged objects, Shadow Credentials, RBCD, GenericWrite on privileged members). 51 total AD checks now.
**Coverage:** 51 read-only checks against on-premises Active Directory covering privileged access, authentication, delegation, account lifecycle, infrastructure, and AD CS.

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

## 7. The 33 checks

Grouped by Category. Each row shows the CheckName (callable individually), its escalation ceiling (max Severity when it FAILs), and compliance mappings.

### Privileged Access (12 checks)

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
| `Test-LAPSDeployment` (**PR 2**) | High | CIS-AD, MCSB-PA-5, SOC2-CC6.1 |
| `Test-DirSyncAccountSecurity` (**PR 2**) | **Critical** | MCSB-IM, NIST-AC-2, SOC2-CC6.1 |

### Authentication (7 checks)

| CheckName | Max Severity | Frameworks |
|---|---|---|
| `Test-ADPasswordPolicy` | High | CIS-AD, NIST-IA-5, SOC2-CC6.2, PCI-DSS-8.3 |
| `Test-KrbTgtAccountAge` | **Critical** | CIS-AD, NIST-IA-5, SOC2-CC6.1 |
| `Test-KerberosPreAuthDisabled` | High | CIS-AD, MCSB-IM, SOC2-CC6.2 |
| `Test-DuplicateSPNs` | High | CIS-AD, MCSB-IM |
| `Test-UserAccountsWithSPN` | Medium | CIS-AD, MCSB-IM, SOC2-CC6.2 |
| `Test-GPPPasswords` | **Critical** | CIS-AD, NIST-IA-5, SOC2-CC6.1, PCI-DSS-3.5 |
| `Test-KerberoastableAccounts` (**PR 2**) | **Critical** | CIS-AD, MCSB-IM, SOC2-CC6.2 |

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

### Infrastructure (5 checks)

| CheckName | Max Severity | Frameworks |
|---|---|---|
| `Test-ADForestAndDomain` | Low (INFO-only) | CIS-AD, NIST-CM-8 |
| `Test-DomainControllers` | Low (INFO-only) | CIS-AD, NIST-CM-8, SOC2-CC6.1 |
| `Test-DomainTrusts` | Medium | CIS-AD, NIST-AC-3 |
| `Test-GPOInventory` | Low (INFO-only) | CIS-AD |
| `Test-DCSecuritySettings` (**PR 2**) | High | CIS-AD, NIST-CA-7, MCSB-PA-6, SOC2-CC6.1 |

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

## 10. PR 2 additions — the four new checks

PR 2 shipped four new checks that close the highest-value coverage gaps from the initial audit.

### `Test-LAPSDeployment`

Detects whether the Local Administrator Password Solution schema extensions are present (legacy `ms-Mcs-AdmPwd*` or Windows LAPS `msLAPS-*`), samples up to 200 enabled computers, and reports coverage percentage + expired-password count.

- **PASS** when schema is extended AND >=90% of sampled computers have a populated, non-expired LAPS password.
- **FAIL** when the schema is missing, coverage <50%, or >25% of populated passwords are expired.
- **WARNING** for the band in between.
- Per-computer WARNING for the first 20 missing hosts so you can trace the gap.

Tuning: `LAPSCoverageGoalPercent` (default 90) and `LAPSSampleSize` (default 200) in `config/entrachecks.config.json`.

### `Test-DCSecuritySettings`

Probes each DC's registry via PSRemoting for five hardening settings:
1. **LDAP server signing** — `LDAPServerIntegrity = 2`
2. **LDAP channel binding** — `LdapEnforceChannelBinding = 2` (ADV190023)
3. **SMB signing required** — `RequireSecuritySignature = 1`
4. **SMBv1 disabled** — `SMB1` absent or `0`
5. **Restrict anonymous** — `RestrictAnonymous` in `{1, 2}`

One finding per (DC, setting) pair. DCs that block PSRemoting emit a WARNING scoped to that DC without failing the rest of the assessment.

### `Test-KerberoastableAccounts`

Extends `Test-UserAccountsWithSPN` with password-age + weak-hash correlation. Severity escalates in a four-tier matrix:

| Context | Status | Severity |
|---|---|---|
| Privileged SPN-bearer + RC4-capable hash | FAIL | **Critical** (domain-wide compromise target) |
| Non-privileged SPN-bearer + RC4 + password >90 days | FAIL | High |
| Non-privileged SPN-bearer + RC4 + fresh password | WARNING | Medium |
| AES-only SPN-bearer | INFO | Low |

Tuning: `KerberoastPasswordAgeDays` (default 90).

### `Test-DirSyncAccountSecurity`

Audits Azure AD Connect service accounts (default naming pattern `MSOL_*`). FAILs if the service account is in Domain Admins, Enterprise Admins, Account Operators, Backup Operators, Schema Admins, or local Administrators. WARNs if password age exceeds 365 days (Azure AD Connect rotates automatically; staleness suggests a broken install).

Emits INFO when no `MSOL_*` accounts are found — meaning either Azure AD Connect isn't in use or the service account was renamed from the default. In the latter case, verify manually.

---

## 11. Hybrid Analysis mode (PR 2)

The new `[Y] Hybrid Analysis` main-menu item (`-Mode Hybrid` on the CLI) runs cloud + hybrid + on-prem AD checks in sequence, then correlates identity-bearing findings across the two identity planes.

```powershell
# Interactive
.\Start-EntraChecks.ps1
# Select [Y] Hybrid Analysis

# CLI
.\Start-EntraChecks.ps1 -Mode Hybrid -TenantName "Contoso"
```

The unified report gains a **Hybrid Correlation** section showing principals flagged in BOTH planes with a Confidence flag:

- **Exact** — UPN match (e.g., a user flagged risky in Entra Identity Protection AND a Domain Admin in on-prem AD).
- **Inferred** — sAMAccountName match only (cloud UPN's left-hand side matches the on-prem sAMAccountName, but no UPN-level confirmation appeared).

See [docs/Hybrid-Analysis-Guide.md](Hybrid-Analysis-Guide.md) for the full workflow including the Excel sheet + CSV file formats.

---

## 12. AD CS (ESC1-8) audit (PR 3)

v1.7.0 adds nine checks that run automatically when an Enterprise Certificate Authority is detected in the forest. No new menu item or CLI flag — they ride along with the AD module.

| CheckName | ESC | Max Severity | Detection |
|---|---|---|---|
| `Test-ADCSInventory` | — | Low (INFO) | Lists CAs + template count |
| `Test-ADCSEscalation1` | ESC1 | **Critical** | SAN-supplying client-auth template enrollable by non-admins |
| `Test-ADCSEscalation2` | ESC2 | High | Any-Purpose / SubCA templates enrollable by non-admins |
| `Test-ADCSEscalation3` | ESC3 | High | Enrollment Agent template enrollable by non-admins |
| `Test-ADCSEscalation4` | ESC4 | **Critical** | Non-admin has write on template (can create ESC1) |
| `Test-ADCSEscalation5` | ESC5 | High | Non-admin has write on PKI containers |
| `Test-ADCSEscalation6` | ESC6 | **Critical** | `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set on CA |
| `Test-ADCSEscalation7` | ESC7 | High | Broad principal has ManageCA / ManageCertificates rights |
| `Test-ADCSEscalation8` | ESC8 | **Critical** | Web enrollment reachable over plain HTTP (NTLM relay target) |

Graceful degradation:
- **No Enterprise CA detected** → single INFO finding, other AD checks proceed normally.
- **ESC6 / ESC7 require PSRemoting to the CA server.** When unavailable, scoped WARNING per CA ("check is advisory for this CA") rather than FAIL.
- **ESC8 HTTP probe** can be disabled via `ActiveDirectory.ADCS.ProbeHTTP = false` in config.

Deep-dive with remediation references: [docs/ADCS-Guide.md](ADCS-Guide.md).

---

## 13. Credential hygiene + ACL abuse paths (PR 4a)

Five credential-hygiene checks (protocol-level defaults) and four ACL-abuse-path checks (single-step privilege escalation routes). All run automatically as part of `-Modules ActiveDirectory` / `-Mode Hybrid`; no new menu item.

### Credential hygiene (5 checks)

| CheckName | Max Severity | What it probes |
|---|---|---|
| `Test-LMHashStorage` | High | `NoLMHash` registry value on every DC (LM hashes must not be stored). |
| `Test-NTLMv1Allowed` | High | `LmCompatibilityLevel` on each DC (value must be `5` to refuse NTLMv1 inbound + outbound). |
| `Test-DCLegacyEncryption` | High | Kerberos encryption types on each DC (DES bits forbidden, RC4 should be off or at least paired with AES). |
| `Test-NullSessionShares` | High | `NullSessionPipes`, `NullSessionShares`, `RestrictAnonymous`, `RestrictAnonymousSAM`, `EveryoneIncludesAnonymous` on each DC. |
| `Test-DomainEncryptionTypesPolicy` | High | `msDS-SupportedEncryptionTypes` on the domain object and every cross-forest trust. |

All five fan out to every DC via PSRemoting. Sequential by default; flip `ActiveDirectory.ParallelDCProbing = true` in config to parallelise in large forests.

### ACL abuse paths (4 checks)

| CheckName | Max Severity | Detection |
|---|---|---|
| `Test-WritablePrivilegedACLs` | **Critical** | Non-admin principals with `GenericAll` / `GenericWrite` / `WriteDacl` / `WriteOwner` / `WriteProperty` / `AllExtendedRights` on Domain Admins / Enterprise Admins / Schema Admins / Account Operators / Backup Operators / Administrators / AdminSDHolder / krbtgt / Domain Controllers OU / each DC computer account. |
| `Test-ShadowCredentialsVulnerable` | **Critical** | Non-admin WriteProperty on `msDS-KeyCredentialLink` (attribute GUID `5b47d60f-6090-40b2-9f37-2a4de88f3063`) for privileged-group members + krbtgt + DC computer accounts. Enables Shadow Credentials (Whisker) attack — attacker installs a PKINIT public key and impersonates the target. |
| `Test-RBCDConfigured` | **Critical** (DC) / High (Tier 0) / INFO (other) | Triple-pass: (1) inventory of `msDS-AllowedToActOnBehalfOfOtherIdentity` across all computer accounts; (2) FAIL when RBCD is set on a DC or configured Tier 0 computer; (3) FAIL when a non-admin has write rights on the attribute itself (lets them plant RBCD). |
| `Test-GenericWriteToSensitive` | **Critical** | Non-admin `GenericWrite` / `GenericAll` / `WriteDacl` / `WriteOwner` / `AllExtendedRights` directly on Domain Admins / Enterprise Admins / Schema Admins **member user objects**. Complements `Test-WritablePrivilegedACLs` which scans group objects. |

### Configuration

Extending the `ActiveDirectory` block:

```json
{
  "ActiveDirectory": {
    "ParallelDCProbing": false,
    "Tier0OUDNs": [],
    "AuthorizedPrincipalsExtra": []
  }
}
```

- **`ParallelDCProbing`** — `true` fans out Group A registry probes across all DCs simultaneously via native `Invoke-Command -ComputerName <array>`. Default `false` (sequential, slower but safer on failure semantics).
- **`Tier0OUDNs`** — optional array of OU distinguished names whose computer members should be treated as Tier 0 by `Test-RBCDConfigured`. DCs are *always* Tier 0; this config only adds additional sensitive computer groupings.
- **`AuthorizedPrincipalsExtra`** — extends the Group B allow-list beyond the default 10 admin principals. Use when your environment has custom legitimate admin groups (e.g., `Contoso-ADAdmins`).

### Graceful degradation

- RSAT missing / not domain-joined: existing `Test-ADEnvironment` gate catches these; none of the new checks run.
- PSRemoting blocked to individual DCs: scoped WARNING per DC, rest of the assessment continues.
- Running as Domain User (not Admin): ACL-read failures on sensitive objects emit per-object WARNING; checks still run for the objects that ARE readable. A single top-level WARNING from the environment probe already tells the user to re-run as admin.

---

## 14. Deferred to future PRs

- ESC9-16 (more recent ADCS additions).
- BloodHound-style ACL abuse path enumeration (bounded attack-path discovery).
- SMBv1 / NetBIOS / LLMNR host enumeration.
- Event log / audit policy hygiene.
- DFSR SYSVOL health.
- `DNSAdmins` / `DHCP Administrators` escalation vectors.
