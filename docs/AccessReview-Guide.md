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

Closed with `NOT_REMEDIATED` rows still on it? The [remediation script generator](#remediation-script-generator) turns them into a script you can read and run.

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

## Headless / automation

Everything menu `[9]` does is scriptable. Two shapes:

**Campaign-only** — `-Mode AccessReview`. Auth runs, then the `AccessReview` phase; no assessment, no unified report, no SOC 2 pass. (`Remediate` is the exception: it never authenticates — see below.)

```powershell
# Open this quarter's campaign into a durable evidence folder
.\Start-EntraChecks.ps1 -Mode AccessReview -AccessReviewAction Open `
    -TenantName Contoso -AccessReviewDirectory 'C:\Evidence\AccessReview'

# Days later, once the reviewer has filled review-worksheet.csv
.\Start-EntraChecks.ps1 -Mode AccessReview -AccessReviewAction Close `
    -TenantName Contoso -AccessReviewDirectory 'C:\Evidence\AccessReview' `
    -CampaignId '2026-Q3-20260803-141500'

# Re-render a report (Open campaigns render as DRAFT)
.\Start-EntraChecks.ps1 -Mode AccessReview -AccessReviewAction Report `
    -TenantName Contoso -CampaignId '2026-Q3-20260803-141500'

# Generate the remediation script for a CLOSED campaign. No sign-in happens:
# this reads the campaign folder and writes a .ps1 — nothing touches the tenant.
.\Start-EntraChecks.ps1 -Mode AccessReview -AccessReviewAction Remediate `
    -TenantName Contoso -AccessReviewDirectory 'C:\Evidence\AccessReview' `
    -CampaignId '2026-Q3-20260803-141500'
```

**In concert** — a normal run that also opens a campaign. The `AccessReview` phase runs after `Modules` and before `SOC2`, so the campaign is on disk in time for the SOC 2 evidence matrix to cite it. With `-EmitPrivilegedRoster` the campaign reuses the privileged roster the run already built instead of re-pulling it.

```powershell
.\Start-EntraChecks.ps1 -Mode Quick -TenantName Contoso -Modules All `
    -EmitPrivilegedRoster -OpenAccessReviewCampaign
```

Setting `AccessReview.Enabled = true` in `config/entrachecks.config.json` makes the in-concert campaign the default for every run — the automation equivalent of the switch (mirrors `SOC2.Enabled`).

| Parameter | Meaning |
|---|---|
| `-AccessReviewAction Open\|Close\|Report\|Remediate` | The campaign action. Requires `-Mode AccessReview` (any other mode is rejected — use `-OpenAccessReviewCampaign` to open a campaign during a normal run). |
| `-AccessReviewDirectory <path>` | Campaign root. Overrides `AccessReview.OutputDirectory`. Relative paths resolve against the repo root. **Never point this at a temp folder** — a campaign spans days and is audit evidence. |
| `-CampaignId <folder name>` | Campaign folder name (e.g. `2026-Q3-20260803-141500`), not a path. Required for `Close`, `Report`, and `Remediate`. |
| `-OpenAccessReviewCampaign` | In-concert opt-in on a normal run. |

**`Remediate` never signs in.** The generator makes no Graph call, so the run skips the `Auth` phase entirely — no browser, no device code, no `auth.*` events. Generating a script costs nothing but a file read, which is also why it is safe to run from a machine that has no tenant session at all. `-AuthMethod` is ignored for this action.

`PeriodLabel` and `IncludeGuests` still come from the config block on every path. That block is read from the run's own `-ConfigFile` when one is supplied (so an environment-specific config can enable or redirect campaigns), otherwise from `config/entrachecks.config.json`.

`-Environment` is honoured too: `-ConfigFile base.json -Environment prod` merges `base.prod.json` over `base.json`, so an `AccessReview` block that exists **only** in the environment override still enables or redirects the campaign. The same applies to `SOC2.Enabled`. Note the override file is found by filename convention — `<base>.<environment>.json` in the same folder — and a missing one is skipped silently, so a typo in `-Environment` yields a run that looks configured but is not.

A close that completes but cannot render its HTML stays closed: the evidence bundle and its artifacts are intact, the phase completes `ok`, and the render fault is reported as an `accessReview.reportFailed` warning. Re-render it with menu `[4]` or `-AccessReviewAction Report`.

The same parameters exist on the contract wrapper `Invoke-EntraChecksRun.ps1` (which is what the desktop app spawns); add `-EmitEvents` there to stream the NDJSON run contract to stdout:

```powershell
.\Invoke-EntraChecksRun.ps1 -TenantName Contoso -AccessReviewAction Open `
    -AccessReviewDirectory 'C:\Evidence\AccessReview' -AuthMethod Skip -EmitEvents
```

**Reading the outcome.** The phase emits `phase.started` / `phase.completed` for `AccessReview` and records the files it produced as artifacts: `worksheet` (`review-worksheet.csv`), `access-review-html` (`AccessReview-Report.html`), `manifest` (`manifest.json`). A `Remediate` run instead records `remediation-script` (`remediate-<CampaignId>.ps1`) and `remediation-plan` (`remediation-plan.md`) — both outside the campaign folder, so the sealed bundle still verifies.

A refused close is a normal outcome, not a crash. An incomplete worksheet, a tampered row set, or a missing sign-off produces a **non-fatal** `accessReview.failed` error carrying the module's reason verbatim, the phase completes with status `failed`, the campaign stays **Open**, and the run still finishes with a `run.result`. Fix the worksheet and close again.

---

## Remediation script generator

**EntraChecks never applies a change to your tenant.** It has no write scopes, asks for none, and the generator makes no Graph calls at all — it reads a closed campaign folder and writes a `.ps1`. Running that script is a separate, deliberate human act.

A closed campaign proves what was decided; it does not undo anything. `New-AccessReviewRemediationScript` turns those decisions into a script you can read line by line before running:

```powershell
Import-Module .\Modules\EntraChecks-AccessReviewRemediation.psm1
New-AccessReviewRemediationScript -CampaignDirectory .\Output\AccessReview\2026-Q3-20260803-141500
```

Or drive it the same way as the rest of the lifecycle — menu `[9]` → `[5] Generate remediation script` (closed campaigns only), or `-AccessReviewAction Remediate` headless. Both paths print the script path and the action / manual / skipped counts, and neither one signs in.

Output lands in a **sibling** of the campaign folder — `<campaign root>\remediation\<CampaignId>\` — containing `remediate-<CampaignId>.ps1`, `remediation-plan.md`, and (once run) `remediation-log-<utc>.json`. Nothing is written inside the campaign folder: `manifest.json` covers every file there, and adding one after sign-off would either break the bundle hash or force a re-seal of a folder whose contents changed after the reviewer signed.

### The sign-off is the authorization

The generator refuses, and writes nothing, unless:

- `campaign.json` says `Status = Closed`, **and**
- every file listed in `manifest.json` still hashes to its recorded SHA-256.

A tampered or half-written bundle produces no script. The reviewer's name, title, sign-off date, the campaign id, and the bundle hash are stamped into the generated script's header, so the artifact carries its own provenance.

### What each decision produces

| Decision | How the privilege is held | Generated |
|---|---|---|
| `Revoke` | `Active` | Remove the directory role assignment |
| `Revoke` | `Eligible (PIM)` | Remove the eligibility schedule (`AdminRemove` request) |
| `Revoke` | `Owner` | Remove ownership of the privileged application |
| `Revoke` | `AppRole` | App-role removal, **commented out** with a warning naming the service principal |
| `Revoke` | `Unclassified`, or no privilege rows | Manual `# TODO` block carrying the reviewer's notes |
| `Modify` | any | Manual `# TODO` — a review cell cannot say *what* to modify |
| `Certify`, `Investigate` | — | Nothing |

Only rows whose verdict was `NotRemediated` produce actions; a `Remediated` row was already handled. `-IncludeRemediated` widens the scope for a re-run.

App-role grants ship inert on purpose: pulling an app permission out from under a service principal is how an integration breaks at 3am. Uncommenting is deliberate.

### What the generated script does when you run it

| Behaviour | Detail |
|---|---|
| Dry run by default | Prints every action and changes nothing. `-Execute` is required to act. |
| Re-resolves live | Never uses an assignment id captured at campaign open. Each block looks up current state and no-ops if the assignment is already gone — safe to run twice, safe after someone did half of it by hand. |
| Never the last Global Administrator | Counted live, immediately before the removal. Refuses if the count would hit zero, or if the count cannot be established. |
| Never a break-glass account | Patterns read from `SOC2.BreakGlassAccounts`, or `SOC2.AzureReadiness.BreakGlass.AccountUpnPatterns`, in `config/entrachecks.config.json` (auto-discovered, or pass `-ConfigFile`). |
| Never the identity running it | Locking yourself out mid-run is unrecoverable. |
| Rollback record first | Each removal is appended to `remediation-log-<utc>.json` **before** the call, so an interrupted run is still reconstructible. |
| Refuse and continue | A guardrail refusal or an API failure prints its reason and moves to the next action — one problem never strands the rest. |
| Stale campaign | Refuses to run at all once the campaign is more than 30 days old (`-StaleDays` at generation time) unless `-Force` is passed. |

```powershell
Connect-MgGraph -Scopes RoleManagement.ReadWrite.Directory,Directory.ReadWrite.All
.\remediate-2026-Q3-20260803-141500.ps1            # dry run — changes nothing
.\remediate-2026-Q3-20260803-141500.ps1 -Execute   # apply
```

Those write scopes are yours to grant to your own session. EntraChecks itself still requests only read scopes; nothing about this changes what `Grant-AdminConsent.ps1` consents to.

| Parameter | Meaning |
|---|---|
| `-CampaignDirectory <path>` | A **closed** campaign folder. Mandatory. |
| `-OutputDirectory <path>` | Overrides the default sibling location. |
| `-IncludeRemediated` | Also generate actions for decisions already verified as remediated. |
| `-StaleDays <int>` | Age threshold baked into the generated script's own refusal. Default 30. |

Returns `Success`, `FailureReason`, `ScriptPath`, `PlanPath`, `ActionCount`, `ManualCount`, `SkippedCount`. A refusal returns `Success = $false` with a reason and writes nothing.

Re-verify afterwards if you like: the campaign bundle still matches its original manifest, because the generator only read it.

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
