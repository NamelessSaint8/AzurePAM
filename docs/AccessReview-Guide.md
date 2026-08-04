# Access Review Guide

Quarterly runbook for producing the **User Access Review (UAR) evidence package** a SOC 2 or PCI DSS assessor asks for:

1. System-generated user lists showing assigned roles, with administrators explicitly included, and evidence the list was system-generated.
2. Evidence the review was completed — per-user decisions, notes, and reviewer sign-off.
3. Updated user lists when changes were made as a result of the review.

Maps to SOC 2 TSC **CC6.1–CC6.3** and PCI DSS v4.0 **7.2.4** (user access review, at least every six months) and **7.2.5.1** (application/system account review). The cadence is **quarterly** — the stricter of the SOC 2 assessor convention and the PCI floor.

---

## Prerequisites

- Microsoft Graph connection with `Directory.Read.All` and `RoleManagement.Read.Directory` (the standard EntraChecks consent covers this). Connect via menu option **[A]** or `Connect-MgGraph`.
- Optional: Entra ID P1 + `AuditLog.Read.All` for last-sign-in data. Without it the roster still generates; the Last sign-in column is empty.

Configuration lives in `config/entrachecks.config.json`:

```json
"AccessReview": {
  "OutputDirectory": ".\\Output\\AccessReview",
  "IncludeGuests": true,
  "PeriodLabel": ""
}
```

`PeriodLabel` empty means the current quarter (e.g. `2026-Q3`) is used automatically.

---

## The quarterly cycle

Everything is driven from **menu option [9] Access Review** in `Start-EntraChecks.ps1`, or directly via the module functions shown below.

### Step 1 — Open the campaign

Menu `[9]` → `[1] Open new campaign`, or:

```powershell
Import-Module .\Modules\EntraChecks-AccessReview.psm1
New-AccessReviewCampaign -TenantName "Contoso"
```

This creates `Output/AccessReview/<PeriodLabel>-<timestamp>/` containing:

| File | Purpose |
|---|---|
| `roster-baseline.json/.csv` | Every user (members, guests, disabled) with role tags |
| `admins-baseline.json/.csv` | Every privileged principal: tier, privileges, assignment type |
| `review-worksheet.csv` | The worksheet the reviewer completes |
| `campaign.json` | System-generation evidence: tenant, UTC timestamp, tool version, authenticated principal |
| `manifest.json` | SHA-256 per file + rolling bundle hash |

The campaign **fails to open** if the privileged roster cannot be built — a review that cannot tag administrators does not satisfy the assessor requirement.

### Step 2 — The reviewer completes the worksheet

Open `review-worksheet.csv` in Excel. Privileged principals are sorted first and tagged `IsPrivileged=TRUE`. For **every** `Access` row, set the `Decision` column:

| Decision | Meaning |
|---|---|
| `Certify` | Access is appropriate — keep as-is |
| `Revoke` | Access must be removed (remove the role, disable, or delete the account) |
| `Modify` | Access should change (e.g. reduce a role); describe in Notes |
| `Investigate` | Needs follow-up outside this review; describe in Notes |

Rules the close step enforces:

- Every row needs a decision — partial reviews cannot close.
- Do **not** add, delete, or reorder columns, and do not delete rows.
- Fill the three `SignOff` rows at the bottom: put the reviewer's name, title, and date (YYYY-MM-DD) in the **Notes** column of each.
- Service principals and disabled admins are in scope deliberately (PCI 7.2.5.1; a disabled account holding a role is still an access right).

### Step 3 — Remediate

Before closing, actually perform the changes the decisions call for (remove roles, disable accounts). The close step **verifies** this — a `Revoke` whose access still exists is flagged `NOT_REMEDIATED` in the report, and a change nobody decided on is flagged `UNEXPLAINED_CHANGE`.

### Step 4 — Close the campaign

Menu `[9]` → `[2] Close campaign`, or:

```powershell
Complete-AccessReviewCampaign -CampaignDirectory .\Output\AccessReview\2026-Q3-20260803-141500
Import-Module .\Modules\EntraChecks-AccessReviewReport.psm1
New-AccessReviewReport -CampaignDirectory .\Output\AccessReview\2026-Q3-20260803-141500
```

Close re-pulls the tenant (`roster-final`, `admins-final`), computes the baseline→final delta, writes `verification.json`, embeds the sign-off into `campaign.json` (Status=`Closed`), and regenerates `manifest.json` over everything **including the completed worksheet** — the reviewer's decisions and sign-off share the hash chain with the system-generated data.

### Step 5 — Hand the evidence to the assessor

`AccessReview-Report.html` is the primary artifact; the campaign folder is the complete evidence bundle. The report's seven sections map directly onto the assessor's three asks (cover/system-generation → ask 1, decisions + sign-off → ask 2, delta + updated list → ask 3).

Campaigns that are still Open render with a **DRAFT watermark** and are not valid evidence.

---

## SOC 2 integration

When the SOC 2 report (menu `[6]`) runs and a **closed** campaign exists under `AccessReview.OutputDirectory`, the SOC 2 Evidence Matrix automatically cites the campaign report and its bundle hash as CC6.1/CC6.2/CC6.3 evidence. No campaign — no rows, no penalty (reference-if-present).

---

## Verifying integrity later

Any artifact can be re-verified against the manifest:

```powershell
$manifest = Get-Content .\Output\AccessReview\<campaign>\manifest.json -Raw | ConvertFrom-Json
foreach ($f in $manifest.Files) {
    $actual = (Get-FileHash -LiteralPath (Join-Path .\Output\AccessReview\<campaign> $f.RelativePath) -Algorithm SHA256).Hash.ToLower()
    "{0}  {1}" -f ($actual -eq $f.SHA256), $f.RelativePath
}
```

A mismatch means the artifact changed after the campaign closed.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Privileged roster unavailable" on open | No Graph context or missing `RoleManagement.Read.Directory`. Reconnect via menu [A]. |
| "access row(s) have no decision" on close | The reviewer left blank Decision cells; the error lists the first ten UPNs. |
| "rows must not be added or removed" | The worksheet row set no longer matches the baseline. Restore deleted rows (regenerate from `roster-baseline.csv` if needed). |
| Last sign-in column empty | Tenant lacks P1 / `AuditLog.Read.All`. Cosmetic — the review is still valid. |
| Report shows DRAFT | The campaign is still Open — close it (Step 4). |
