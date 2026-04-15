# Hybrid Analysis Mode Guide

**Status:** Shipping in v1.6.0 (PR 2 of the AD integration roadmap).
**Purpose:** Run cloud + hybrid + on-premises Active Directory security checks in a single invocation and correlate identity-bearing findings across the two planes.

Hybrid Analysis is for organizations running **Azure AD Connect** where the same users exist in both Entra (cloud) and on-prem AD. A user who's flagged risky in Entra Identity Protection AND who's a member of on-prem Domain Admins is a different risk profile than one flagged in only one plane — this mode surfaces that correlation explicitly.

---

## 1. Running Hybrid Analysis

### Option A — Interactive menu

```powershell
.\Start-EntraChecks.ps1
# Choose [Y] Hybrid Analysis
```

### Option B — CLI / scripted

```powershell
.\Start-EntraChecks.ps1 -Mode Hybrid -TenantName "Contoso"
```

### What it runs (in order)

1. Core cloud checks (same as Quick Assessment's `Core` module).
2. Identity Protection (if Azure AD Premium P2 detected).
3. Devices (Intune).
4. Secure Score.
5. Defender for Cloud (if Az context available).
6. Azure Policy (if Az context available).
7. Purview Compliance.
8. **Active Directory (on-prem)** — 33 AD checks via `EntraChecks-ActiveDirectory.psm1`. Gracefully degrades when the host isn't domain-joined.
9. **Correlation pass** — `Get-HybridIdentityCorrelation` walks the accumulated findings array and pairs principals flagged in both planes.
10. Unified report generation (HTML + Excel or CSV bundle) with a new **Hybrid Correlation** section.
11. SOC 2 readiness pass (if `SOC2.Enabled = true` in config).

---

## 2. Correlation model

`Get-HybridIdentityCorrelation` (in `Modules/EntraChecks-HybridCorrelation.psm1`) produces three buckets:

- **CorrelatedPrincipals** — flagged in BOTH cloud and on-prem.
- **CloudOnlyPrincipals** — flagged only in Entra.
- **OnPremOnlyPrincipals** — flagged only in AD.

Each correlated principal carries:

| Field | Meaning |
|---|---|
| `Principal` | The identifier used for matching (UPN or sAMAccountName, lowercased). |
| `Confidence` | `Exact` (UPN match) or `Inferred` (sAMAccountName match without UPN confirmation). |
| `MatchKey` | `UPN` or `sAMAccountName`. |
| `CloudFindings` | Array of cloud findings for this principal. |
| `OnPremFindings` | Array of on-prem findings for this principal. |
| `MaxCloudSeverity` | Highest severity among cloud findings (Critical > High > Medium > Low). |
| `MaxOnPremSeverity` | Highest severity among on-prem findings. |
| `CloudCount` / `OnPremCount` | Finding counts per plane. |

### How matching works

- **Pass 1 — UPN match (Confidence='Exact').** Every identity-bearing finding is keyed by the UPN extracted from its `Object` field (e.g., `alice@contoso.com`). When a UPN has both cloud and on-prem findings, it's a correlation.
- **Pass 2 — sAMAccountName match (Confidence='Inferred').** For principals not already matched by UPN, the lowercased sAMAccountName is tried. If cloud findings reference `alice@contoso.com` and on-prem findings reference `alice` (without domain), we infer a match — but mark it as Inferred so analysts know the link is heuristic.

### Findings excluded from correlation

- Findings with `Status` in `{INFO, PASS}` — we only correlate actionable findings.
- Findings with `Category = Infrastructure` — these are environment-scoped, not principal-scoped.
- Findings whose `Object` field doesn't look like a principal (e.g., group names with spaces, raw DNs that don't extract cleanly).

### What this is NOT

The correlation does not reason about **group membership transitivity** (e.g., "user X is in group Y which is in Domain Admins"). It only matches when the principal itself is directly named in both planes.

---

## 3. Where the correlation appears in the report

### HTML unified report

New section `#hybrid-correlation` rendered between the Purview section and Detailed Findings. Three metric cards at the top show correlation count + cloud/on-prem indexed counts, then a top-10 table with one row per correlated principal.

### Excel workbook

New sheet **`Hybrid Correlation`** with one row per correlated principal:

| Column | Description |
|---|---|
| Principal | The identifier used for matching. |
| Confidence | `Exact` / `Inferred`. |
| MatchKey | `UPN` / `sAMAccountName`. |
| CloudFindingCount / OnPremFindingCount | Integers. |
| MaxCloudSeverity / MaxOnPremSeverity | Highest severity per plane. |
| CloudFindingsSummary / OnPremFindingsSummary | First three finding descriptions joined with ` | `. |

### CSV bundle (no ImportExcel)

File `13-HybridCorrelation.csv` with the same columns.

---

## 4. Common scenarios

### "A user is flagged in Entra Identity Protection and is a Domain Admin on-prem"

Expect to see this user in **CorrelatedPrincipals** with `Confidence=Exact` (assuming standard UPN ↔ sAMAccountName mapping). MaxCloudSeverity typically High (risky user), MaxOnPremSeverity likely at least Medium (privileged group membership flagged by `Test-PrivilegedGroupCreep` if not on the whitelist).

**Action:** this is your highest-priority remediation target. Credential compromise in the cloud translates directly to privileged access on-prem.

### "An on-prem privileged account has no cloud footprint"

Expect to see this user in **OnPremOnlyPrincipals**. Typical for tier-0 break-glass accounts that are intentionally NOT synced. No action required unless the account shouldn't exist at all.

### "The correlation count is zero despite lots of cloud + on-prem findings"

Two common reasons:

1. Alternate UPN suffix in use. Cloud findings use `alice@contoso.onmicrosoft.com` while on-prem findings use `alice` — the sAMAccountName inference SHOULD catch this. If it doesn't, open an issue with sample Object-field values.
2. On-prem findings are all `Category=Infrastructure` (DC enumeration, GPO inventory) — these are deliberately excluded from correlation since they don't relate to a specific principal.

---

## 5. Tuning

Two knobs affect correlation accuracy — neither is exposed as a user-facing setting today. Both are in `Modules/EntraChecks-HybridCorrelation.psm1`:

- **`Test-IsIdentityFinding`** — the gate that decides which findings participate in correlation. If you're seeing too many or too few correlations, adjust the status/category filter.
- **`Get-FindingPrincipal`** — the heuristic that extracts a UPN / sAMAccountName from the `Object` field. Edge cases (decorated group names, custom identifiers) are handled here.

If you need to tune these for your environment, open an issue with representative `Object` values.

---

## 6. Behavior in cloud-only environments

`[Y] Hybrid Analysis` runs fine on hosts that aren't domain-joined or don't have RSAT. The on-prem AD leg emits a single INFO finding via `Test-ADEnvironment` ("Not domain-joined, expected for cloud-only environments") and returns early. The correlation pass runs on whatever findings exist — if one plane is empty, `CorrelationCount=0` and the section renders an empty-state card.

The value of Hybrid Analysis in a cloud-only environment is minimal — use Quick Assessment (`-Mode Quick`) instead for a cleaner UX — but the mode is safe to invoke anywhere.

---

## 7. Permissions

Same as Quick Assessment plus the AD module's requirements:

| Module | Minimum | Recommended |
|---|---|---|
| Cloud modules (Core/IdentityProtection/Devices/SecureScore/Purview) | Global Reader | Global Administrator |
| Azure modules (AzurePolicy/Defender) | Azure Reader on scoped subscriptions | Azure Reader + Security Reader |
| Active Directory | Domain User | Domain Admin (full coverage on ACL / drift checks) |

See [docs/ActiveDirectory-Guide.md](ActiveDirectory-Guide.md) §4 Permission model for the AD-specific breakdown.

---

## 8. SOC 2 CC6 integration

AD findings produced during a Hybrid Analysis run carry `ComplianceFrameworks` tags that include `SOC2-CC6.1` and `SOC2-CC6.2` where appropriate. When SOC 2 readiness is enabled (`SOC2.Enabled = true`), those findings automatically flow into the SOC 2 report's control-evidence tables. No additional configuration required.

---

## 9. Cross-surface correlators (PR 5)

The base correlator in §2 groups findings by principal. PR 5 adds a second pass — **cross-surface correlators** that specifically identify **hybrid takeover paths** where on-prem exposure intersects cloud privilege. Output is surfaced as a new `CrossSurfaceFindings` array on the correlation result, a new HTML subsection (inside `#hybrid-correlation`), a new Excel sheet (`Hybrid Cross-Surface`), and a new CSV (`14-HybridCrossSurface.csv`). Cross-surface findings also flow into the main risk score via the standard findings pool.

### The 5 correlators

| Correlator | Condition | Severity |
|---|---|---|
| `Find-DAExposureToCloudAdmin` | Direct-reach DACL exposure (`Test-AuthenticatedUsersDACLReach` / `Test-WritablePrivilegedACLs` FAIL with "DIRECT reach" or write-class rights) on a principal that also holds a privileged cloud role. | **Critical** — single ACE modification grants cloud tenant admin. |
| `Find-DnsAdminsWithCloudPrivilege` | `Test-DNSAdminsPrivilege` member ∩ privileged cloud role. | **Critical** on legacy DCs (CVE-2021-40469 class); **High** on modern. |
| `Find-ShadowCredentialsOnCloudSyncedAdmin` | `Test-ShadowCredentialsVulnerable` target is a synced cloud admin. | **Critical** — write msDS-KeyCredentialLink → PKINIT as admin → cloud session. |
| `Find-RBCDOnPrivilegedTier0Targeting` | `Test-RBCDConfigured` source principal (the impersonator) holds a cloud privileged role. Applies to DC / Tier 0 RBCD only. | **High** — requires cloud-side compromise first to weaponize, but hybrid both ways. |
| `Find-RiskyUserWithOnPremPrivilege` | IdentityProtection risky user (FAIL) is also a member of on-prem privileged groups. Severity floors at High when Domain/Enterprise/Schema Admins implicated. | Inherits IdentityProtection severity; floor High for Tier 0. |

### How the cloud side participates

The correlators depend on the **`PrivilegedRoleMember` inventory markers** emitted by `Test-DirectoryRolesAndMembers` (Core module). For every enabled non-guest member of a privileged directory role, the check emits an INFO finding with `Object = "upn@domain (RoleName)"` and `Description` starting with `PrivilegedRoleMember:`. Correlators index these markers via `New-PrincipalIndex` to answer "does this principal hold a cloud admin role?" in O(1).

If `Test-DirectoryRolesAndMembers` is unauthorized or skipped, correlators 1-4 produce no findings (they need the marker). Correlator 5 still works because it reads IdentityProtection and on-prem privileged-group findings directly.

### Identity mapping limitations (unchanged from §2)

The base correlator uses UPN + SamAccountName matching with no SID / ObjectGUID reconciliation. If a user's on-prem SamAccountName doesn't prefix-match their cloud UPN (`jsmith` on-prem vs `john.smith@contoso.com` cloud), the cross-surface correlators will miss them too. Environments with this mismatch can inspect the `CloudOnlyPrincipals` + `OnPremOnlyPrincipals` buckets to spot the principals that would be caught if matching were strengthened.

### Two-hop DACL indirect exposure is not escalated

`Test-AuthenticatedUsersDACLReach` emits both direct (one-hop Critical) and indirect (two-hop High) findings. Correlator 1 only matches the **direct** variant — the indirect path already requires an intermediate on-prem step, and re-weighting it through cloud correlation produces too many false positives for the marginal signal gained.

---

## 10. What's next

- Device-plane correlation (RBCD on member servers, Intune device ownership) — deferred to a future device-focused PR.
- SID / ObjectGUID reconciliation for environments with name mismatch — requires exposing `onPremisesSid` per user from the cloud side.
- AD CS template vulnerabilities (ESC1-13) — **shipped in PR 3 + PR 4b**.
- BloodHound-style ACL abuse path enumeration — remains out of scope; separate tool, separate problem.
- Richer correlation heuristics — group-membership transitivity, service-principal overlap, conditional-access scope intersection.
