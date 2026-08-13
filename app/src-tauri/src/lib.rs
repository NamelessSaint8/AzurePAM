//! EntraChecks desktop shell — Native App Phase 4 (MVP).
//!
//! Phase 5.7 (this commit): **notify-only updater**. On launch the
//! app GETs a static `version.json`, compares it to `app_version()`,
//! and (only if newer) emits `update:available` for the webview to
//! show a dismissible banner with a download link. Failure/offline
//! is a silent no-op — launch is never blocked. No silent apply, no
//! Tauri-updater plugin, no update-signing keypair.
//!
//! Phase 5.5 (earlier): **relaunch-as-admin**. Some EntraChecks
//! local-machine checks (AD/hybrid, AAD Connect data, certain WMI/
//! event-log reads) need an elevated token at run time. Readiness now
//! reports `elevated`; the UI offers a "Restart as administrator"
//! button that calls `relaunch_as_admin`, which `ShellExecute(runas)`
//! the current exe and exits the non-elevated instance — one UAC
//! prompt per session, conventional Windows pattern. The rule is
//! **no silent self-elevation**, not "no elevation": the installer +
//! dependency-install path stay no-UAC (5.3); this is a *consented*
//! relaunch behind a user click. Cross-platform: non-Windows hosts
//! get a const-false `is_elevated` and a "not on this OS" error.
//!
//! `tauri-plugin-opener` is wired now because step 6 ("Open report")
//! needs it; it is otherwise inert at this stage.

pub mod contract;
mod elevation;
mod sidecar;
mod update;

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_opener::OpenerExt;

/// The in-flight run, so `cancel_run` can build the Phase-3a sentinel
/// path. `output_dir` is known when the run starts; `run_id` is
/// filled from the first streamed event that carries it.
#[derive(Default)]
struct RunState {
    output_dir: Option<PathBuf>,
    run_id: Option<String>,
}

/// The desktop shell's own version (the Cargo package version).
///
/// Distinct from the engine/contract `schemaVersion` (owned by the
/// PowerShell core, validated by the parser added in step 4.3).
pub fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// What `discover_pwsh_cmd` hands back to the frontend.
#[derive(serde::Serialize)]
pub struct PwshInfo {
    path: String,
    version: String,
}

/// Locate an installed `pwsh` 7+. Returns its path + version, or an
/// actionable not-found message (the frontend shows the install
/// link — the Phase-4 "detect, don't bundle" decision).
#[tauri::command]
fn discover_pwsh_cmd() -> Result<PwshInfo, String> {
    match sidecar::discover_pwsh() {
        Ok(loc) => Ok(PwshInfo {
            path: loc.path.to_string_lossy().into_owned(),
            version: loc.version,
        }),
        Err(e) => Err(e.to_string()),
    }
}

/// What `readiness` hands back to the frontend. `pwsh` is `None` when
/// PS 7 is not installed; `modules` is one row per
/// `READINESS_MODULES` entry. Detection only — the remediation
/// actions (running the bundled `Install-Prerequisites.ps1`, winget
/// for pwsh) arrive in step 5.3.
#[derive(serde::Serialize)]
pub struct ReadinessReport {
    pwsh: Option<PwshInfo>,
    modules: Vec<sidecar::ModuleStatus>,
    /// `true` iff this process has an elevated token (Windows). On
    /// non-Windows hosts always `false` — see `windows` below.
    elevated: bool,
    /// Whether the host is Windows. The UI uses this to decide
    /// whether the elevation row is meaningful at all (elevation is
    /// a Windows-only construct in the sense this app uses it).
    windows: bool,
}

/// Probe the three-dependency surface in one shot: discover `pwsh`;
/// if found, run a single inline `Get-Module -ListAvailable` probe
/// through it for every name in `READINESS_MODULES`. A failed probe
/// returns an empty module list (the panel renders "unknown" rows)
/// rather than erroring — Readiness is informational, never fatal.
#[tauri::command]
fn readiness() -> ReadinessReport {
    let pwsh_loc = sidecar::discover_pwsh().ok();
    let modules = pwsh_loc
        .as_ref()
        .and_then(|loc| sidecar::collect_readiness(&loc.path).ok())
        .unwrap_or_default();
    ReadinessReport {
        pwsh: pwsh_loc.map(|loc| PwshInfo {
            path: loc.path.to_string_lossy().into_owned(),
            version: loc.version,
        }),
        modules,
        elevated: elevation::is_elevated(),
        windows: cfg!(target_os = "windows"),
    }
}

/// Re-launch the app under UAC (`ShellExecute runas`) and exit the
/// current non-elevated instance. Consented (user-clicked) — never
/// invoked automatically. Windows-only; other OSes return an error.
#[tauri::command]
fn relaunch_as_admin(app: AppHandle) -> Result<(), String> {
    elevation::relaunch_self_as_admin()?;
    // The elevated instance is the one that should be running now.
    // Exit cleanly so the user sees one window, not two.
    app.exit(0);
    Ok(())
}

/// Phase 5.7: notify-only update check. GETs the version manifest
/// in a background thread; if a strictly-newer version is advertised,
/// emits `update:available` with the manifest as payload. Network
/// failure / 404 / parse error are **silent** — never surfaced to
/// the user; launch is never blocked. Returns immediately.
#[tauri::command]
fn check_update(app: AppHandle, url: Option<String>) -> Result<(), String> {
    let manifest_url = url.unwrap_or_else(|| update::DEFAULT_MANIFEST_URL.to_string());
    let current = app_version().to_string();
    std::thread::spawn(move || match update::check(&manifest_url, &current) {
        Ok(Some(m)) => {
            let _ = app.emit("update:available", m);
        }
        Ok(None) => { /* up to date — no banner */ }
        Err(e) => {
            // Silent by policy. Verbose log only; the user never sees
            // "couldn't reach the updater" warnings.
            eprintln!("[update] check failed: {e}");
        }
    });
    Ok(())
}

/// Discover `pwsh`, spawn the fixed tenant-free probe, and stream its
/// stdout to the webview: one `sidecar:line` event per line, then a
/// terminal `sidecar:exit` (exit code) or `sidecar:error` (message).
/// Runs on a background thread so the command returns immediately and
/// the UI stays responsive — the same shape step 4.4 needs for a long
/// assessment.
#[tauri::command]
fn run_sidecar_probe(app: AppHandle) -> Result<(), String> {
    let loc = sidecar::discover_pwsh().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let args = sidecar::probe_args();
        let app_err = app.clone();
        let result = sidecar::spawn_streaming(
            &loc.path,
            &args,
            |line| {
                let _ = app.emit("sidecar:line", line.to_string());
            },
            move |line| {
                let _ = app_err.emit("sidecar:line", format!("[stderr] {line}"));
            },
        );
        match result {
            Ok(code) => {
                let _ = app.emit("sidecar:exit", code);
            }
            Err(e) => {
                let _ = app.emit("sidecar:error", e.to_string());
            }
        }
    });
    Ok(())
}

/// The contract major this build understands — the webview compares
/// each event's `schemaMajor` against this to decide whether to show
/// the "engine is newer than this app" banner.
#[tauri::command]
fn supported_schema_major() -> u32 {
    contract::SUPPORTED_SCHEMA_MAJOR
}

/// Launch a real headless assessment and stream **parsed** contract
/// events to the webview. Reuses `spawn_streaming` verbatim (the 4.2
/// boundary) and `contract::parse_line` (the 4.3 parser) — this step
/// only joins them. Per parsed line a `run:event`
/// `{ schemaMajor, event }` is emitted (event = the 4.3
/// internally-tagged `AppEvent`); non-contract / decorative stdout is
/// silently dropped; then a terminal `run:exit` (code) or `run:error`
/// (message).
///
/// Record the run's id the first time the stream reveals it. A free
/// fn (not an inline block) so the `State` guard's drop order is
/// unambiguous.
fn record_run_id(app: &AppHandle, rid: String) {
    let st = app.state::<Mutex<RunState>>();
    let mut g = match st.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if g.run_id.is_none() {
        g.run_id = Some(rid);
    }
}

const ALLOWED_MODULES: &[&str] = &[
    "Core",
    "IdentityProtection",
    "Devices",
    "SecureScore",
    "Defender",
    "AzurePolicy",
    "Purview",
    "ActiveDirectory",
    "All",
];

fn normalize_modules(modules: Vec<String>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for raw in modules {
        let m = raw.trim();
        if m.is_empty() {
            continue;
        }
        if !ALLOWED_MODULES.contains(&m) {
            return Err(format!("Unknown assessment module: {m}"));
        }
        if !out.iter().any(|x| x == m) {
            out.push(m.to_string());
        }
    }
    if out.is_empty() {
        return Err("Select at least one assessment module.".to_string());
    }
    Ok(out)
}

fn normalize_auth_method(auth_method: String) -> Result<String, String> {
    let m = auth_method.trim();
    match m {
        "Interactive" | "DeviceCode" | "Skip" => Ok(m.to_string()),
        "" => Ok("DeviceCode".to_string()),
        other => Err(format!("Unknown auth method: {other}")),
    }
}

/// Whitelist matches the engine's `-HtmlDeepDiveDomains` ValidateSet
/// (see Get-HtmlReportPlan in EntraChecks-HTMLReporting.psm1). The
/// GUI checkboxes feed straight into this list; reject anything we
/// don't recognise so a future renamed key from the webview surfaces
/// loudly instead of silently doing nothing.
const ALLOWED_DEEP_DIVES: &[&str] = &[
    "SecureScore",
    "DefenderCompliance",
    "AzurePolicy",
    "PurviewCompliance",
    "Delta",
    "PrivilegedIdentity",
];

fn normalize_deep_dives(deep_dives: Vec<String>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for raw in deep_dives {
        let d = raw.trim();
        if d.is_empty() {
            continue;
        }
        if !ALLOWED_DEEP_DIVES.contains(&d) {
            return Err(format!("Unknown deep-dive report: {d}"));
        }
        if !out.iter().any(|x| x == d) {
            out.push(d.to_string());
        }
    }
    Ok(out)
}

/// Whatever the engine was asked to do (an assessment, an access-review
/// campaign action), the shell watches it identically: spawn `pwsh` on
/// a background thread, run stdout through the contract parser, and
/// emit the `run:*` event stream the webview already knows. Every
/// command that drives the engine calls this so device-code scraping,
/// run-id recording, and terminal events can't drift between them.
fn spawn_contract_stream(app: AppHandle, pwsh: PathBuf, args: Vec<String>) {
    std::thread::spawn(move || {
        let argrefs: Vec<&str> = args.iter().map(String::as_str).collect();
        // Two callbacks: stdout goes through the contract parser
        // (the run.* event stream); stderr bypasses the parser and
        // goes straight to the UI as `run:stderr-line` so a pwsh
        // crash, an early exception, or any non-NDJSON noise actually
        // shows up in the Log pane — that's what surfaces "exited 1
        // with no detail" properly.
        let app_err = app.clone();
        let app_frag = app.clone();
        let result = sidecar::spawn_streaming_with_stdout_fragments(
            &pwsh,
            &argrefs,
            |line| match contract::parse_line(line) {
                contract::ParsedLine::Event {
                    schema_major,
                    run_id,
                    event,
                } => {
                    if let Some(rid) = run_id {
                        record_run_id(&app, rid);
                    }
                    let _ = app.emit(
                        "run:event",
                        serde_json::json!({ "schemaMajor": schema_major, "event": event }),
                    );
                }
                contract::ParsedLine::Ignored => {
                    if !line.trim().is_empty() {
                        let _ = app.emit("run:stdout-line", line.to_string());
                    }
                    // Microsoft.Graph's `Connect-MgGraph -UseDevice-
                    // Authentication` prints the device code to the
                    // PowerShell host UI rather than as a contract
                    // event, which the Sign-in panel then can't show.
                    // Scrape the SDK's "enter the code XXXX-XXXX"
                    // line and promote it into a synthetic
                    // `authDeviceCode` event the existing webview
                    // handler already renders. Matches the engine's
                    // `Write-EcfAuthDeviceCode -Capture captured`
                    // shape so the JS code path is identical.
                    if let Some(user_code) = sidecar::extract_device_code(line) {
                        let _ = app.emit(
                            "run:event",
                            serde_json::json!({
                                "schemaMajor": 1,
                                "event": {
                                    "type": "authDeviceCode",
                                    "userCode": user_code,
                                    "verificationUri":
                                        "https://microsoft.com/devicelogin",
                                    "capture": "captured"
                                }
                            }),
                        );
                    }
                }
            },
            move |line| {
                let _ = app_err.emit("run:stderr-line", line.to_string());
            },
            move |fragment| {
                let _ = app_frag.emit("run:stdout-fragment", fragment.to_string());
            },
        );
        match result {
            Ok(code) => {
                let _ = app.emit("run:exit", code);
            }
            Err(e) => {
                let _ = app.emit("run:error", e.to_string());
            }
        }
    });
}

/// The run output directory — the engine's working folder, and where
/// `cancel_run` drops its sentinel. Deliberately TEMP: it is per-run
/// scratch. Access-review campaigns are audit evidence spanning days
/// and never live here (plan §3.1); they get their own durable folder.
fn gui_run_output_dir() -> PathBuf {
    sidecar::strip_extended_length_prefix(
        std::env::temp_dir().join("EntraChecks-GUI"),
    )
}

/// Arm cancellation state for a run: the output dir is known now, the
/// run id arrives with the first streamed event.
fn arm_run_state(app: &AppHandle, out_dir: &Path) -> Result<(), String> {
    let st = app.state::<Mutex<RunState>>();
    let mut g = st.lock().map_err(|_| "run state poisoned".to_string())?;
    g.output_dir = Some(out_dir.to_path_buf());
    g.run_id = None;
    Ok(())
}

/// The dedicated Result screen + Open report is 4.6. This step adds
/// the auth panel + Cancel: the run's `runId` (envelope) and
/// `output_dir` are recorded in `RunState` so `cancel_run` can drop
/// the Phase-3a sentinel.
///
/// `open_access_review` is the "in concert" opt-in (plan §1): the same
/// run also opens an access-review campaign, reusing the privileged
/// roster it already built.
#[tauri::command]
fn run_assessment(
    app: AppHandle,
    tenant: String,
    modules: Vec<String>,
    auth_method: String,
    deep_dives: Vec<String>,
    open_access_review: bool,
    campaign_dir: Option<String>,
) -> Result<(), String> {
    let pwsh = sidecar::discover_pwsh().map_err(|e| e.to_string())?;
    let res_dir = app.path().resource_dir().ok();
    let core = sidecar::resolve_core_script(res_dir.as_deref()).ok_or_else(|| {
        "Invoke-EntraChecksRun.ps1 was not found (not bundled, no \
         ENTRACHECKS_CORE override, and not inside the repository)."
            .to_string()
    })?;
    let tenant = tenant.trim().to_string();
    if tenant.is_empty() {
        return Err("Tenant name is required.".to_string());
    }
    let modules = normalize_modules(modules)?;
    let auth_method = normalize_auth_method(auth_method)?;
    let deep_dives = normalize_deep_dives(deep_dives)?;
    let campaign_dir = campaign_dir.map(|d| d.trim().to_string());
    let out_dir = gui_run_output_dir();
    let core_s = core.to_string_lossy().into_owned();
    let out_s = out_dir.to_string_lossy().into_owned();

    arm_run_state(&app, &out_dir)?;

    let args = sidecar::core_args(
        &core_s,
        &tenant,
        &out_s,
        &modules,
        &auth_method,
        &deep_dives,
        open_access_review,
        campaign_dir.as_deref(),
    );
    spawn_contract_stream(app, pwsh.path, args);
    Ok(())
}

const ACCESS_REVIEW_ACTIONS: &[&str] = &["Open", "Close", "Report"];

fn normalize_access_review_action(action: String) -> Result<String, String> {
    let a = action.trim();
    if !ACCESS_REVIEW_ACTIONS.contains(&a) {
        return Err(format!(
            "Unknown access review action: {a} (expected Open, Close or Report)."
        ));
    }
    Ok(a.to_string())
}

/// Run a campaign action on its own (plan §1, "separately"): prereqs →
/// auth → the `AccessReview` phase, with no Core/Modules/report pass.
/// Streams through the same contract pipeline as `run_assessment`, so
/// phases, log, artifacts and Cancel all work unchanged.
///
/// `campaign_dir` is the durable campaign folder; `campaign_id` is a
/// campaign *folder name* inside it (required by Close/Report, empty
/// for Open, which mints its own).
#[tauri::command]
fn run_access_review(
    app: AppHandle,
    tenant: String,
    auth_method: String,
    action: String,
    campaign_dir: String,
    campaign_id: String,
) -> Result<(), String> {
    let pwsh = sidecar::discover_pwsh().map_err(|e| e.to_string())?;
    let res_dir = app.path().resource_dir().ok();
    let core = sidecar::resolve_core_script(res_dir.as_deref()).ok_or_else(|| {
        "Invoke-EntraChecksRun.ps1 was not found (not bundled, no \
         ENTRACHECKS_CORE override, and not inside the repository)."
            .to_string()
    })?;
    let tenant = tenant.trim().to_string();
    if tenant.is_empty() {
        return Err("Tenant name is required.".to_string());
    }
    let auth_method = normalize_auth_method(auth_method)?;
    let action = normalize_access_review_action(action)?;
    let campaign_dir = campaign_dir.trim().to_string();
    if campaign_dir.is_empty() {
        return Err(
            "Campaign folder is required — a campaign is audit evidence and \
             needs a durable folder."
                .to_string(),
        );
    }
    let campaign_id = campaign_id.trim().to_string();
    if action != "Open" && campaign_id.is_empty() {
        return Err(format!(
            "Select a campaign first — {} needs an existing campaign.",
            action.to_lowercase()
        ));
    }
    // The campaign lands in campaign_dir; the run still needs its own
    // working output dir so Cancel has somewhere to drop the sentinel.
    let out_dir = gui_run_output_dir();
    let args = sidecar::access_review_args(
        &core.to_string_lossy(),
        &tenant,
        &out_dir.to_string_lossy(),
        &campaign_dir,
        &auth_method,
        &action,
        &campaign_id,
    );

    arm_run_state(&app, &out_dir)?;
    spawn_contract_stream(app, pwsh.path, args);
    Ok(())
}

/// One campaign folder as the Access Review panel renders it. The
/// engine writes `campaign.json` in PascalCase; the webview speaks
/// camelCase — this is the translation, and the only place that knows
/// both spellings.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignRow {
    id: String,
    period: String,
    status: String,
    generated_utc: String,
    path: String,
}

/// The subset of `campaign.json` the panel needs (writer:
/// `New-AccessReviewCampaign` in `EntraChecks-AccessReview.psm1`).
/// Every other key in the file is ignored, so the engine can add
/// fields without breaking the list.
#[derive(serde::Deserialize)]
struct CampaignMeta {
    #[serde(rename = "PeriodLabel")]
    period_label: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "GeneratedAtUtc")]
    generated_at_utc: String,
}

/// List the campaigns under `campaign_dir` by reading one small JSON
/// per folder (plan §3.4 — spawning pwsh for a directory listing would
/// cost seconds and be unavailable during a run). A folder that isn't
/// a campaign, or whose `campaign.json` is unreadable or corrupt, is
/// skipped silently: a half-written campaign must not hide the rest of
/// the list. A missing directory is simply "no campaigns yet".
#[tauri::command]
fn list_campaigns(campaign_dir: String) -> Vec<CampaignRow> {
    let mut rows: Vec<CampaignRow> = Vec::new();
    let entries = match std::fs::read_dir(campaign_dir.trim()) {
        Ok(e) => e,
        Err(_) => return rows,
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let raw = match std::fs::read_to_string(dir.join("campaign.json")) {
            Ok(r) => r,
            Err(_) => continue,
        };
        // Windows PowerShell's `Set-Content -Encoding UTF8` writes a
        // BOM, and serde_json rejects one — strip it or every real
        // campaign parses as corrupt and the list comes back empty.
        let meta: CampaignMeta = match serde_json::from_str(raw.trim_start_matches('\u{feff}')) {
            Ok(m) => m,
            Err(_) => continue,
        };
        // The FOLDER NAME is the id, not campaign.json's `CampaignId`.
        // The engine reconstructs the path as <root>/<CampaignId>, so a
        // restored or renamed evidence bundle whose inner id no longer
        // matches its folder would otherwise close the wrong path — or
        // none. The two coincide by convention; only one of them is
        // authoritative for the round trip.
        let id = match dir.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => continue,
        };
        rows.push(CampaignRow {
            id,
            period: meta.period_label,
            status: meta.status,
            generated_utc: meta.generated_at_utc,
            path: dir.to_string_lossy().into_owned(),
        });
    }
    // The timestamps are fixed-width ISO-8601 UTC, so a string sort is
    // a chronological sort — the same assumption the engine's own
    // Get-AccessReviewCampaign makes.
    rows.sort_by(|a, b| b.generated_utc.cmp(&a.generated_utc));
    rows
}

/// The default durable campaign folder (plan §3.1). Resolved here, not
/// in the webview: a `%USERPROFILE%` literal reaching PowerShell would
/// be taken verbatim and create a folder of that name, and this also
/// keeps the default independent of any webview path permission.
/// Empty string means "no home dir" — the panel then simply asks the
/// user for a folder.
#[tauri::command]
fn default_campaign_dir() -> String {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    if home.trim().is_empty() {
        return String::new();
    }
    std::path::Path::new(home.trim())
        .join("Documents")
        .join("EntraChecks")
        .join("AccessReview")
        .to_string_lossy()
        .into_owned()
}

/// Cooperatively cancel the in-flight run by writing the Phase-3a
/// sentinel `<outputDir>/.runs/<runId>.cancel`. The child is *not*
/// killed — the engine stops at its next safe checkpoint and emits a
/// `Cancelled` `run.result` with whatever artifacts exist. Fails
/// cleanly if no run is active or its id hasn't been seen yet.
#[tauri::command]
fn cancel_run(app: AppHandle) -> Result<(), String> {
    let (out_dir, run_id) = {
        let st = app.state::<Mutex<RunState>>();
        let g = st.lock().map_err(|_| "run state poisoned".to_string())?;
        match (g.output_dir.clone(), g.run_id.clone()) {
            (Some(o), Some(r)) => (o, r),
            _ => {
                return Err(
                    "No cancellable run yet (waiting for the run to report its id)."
                        .to_string(),
                )
            }
        }
    };
    sidecar::request_cancel(&out_dir, &run_id).map_err(|e| e.to_string())?;
    let _ = app.emit("run:cancelling", run_id);
    Ok(())
}

/// Open a URL (the device-code verification link) in the OS default
/// handler via the opener plugin.
#[tauri::command]
fn open_external(app: AppHandle, target: String) -> Result<(), String> {
    app.opener()
        .open_url(target, None::<&str>)
        .map_err(|e| e.to_string())
}

/// Phase 5.3: is `winget` on PATH? The frontend decides whether to
/// offer "Install via winget" vs. "Open download page" for `pwsh` 7.
#[tauri::command]
fn winget_available() -> bool {
    sidecar::winget_available()
}

/// Run the bundled `Install-Prerequisites.ps1` through the detected
/// `pwsh`, streaming its stdout to the webview (`install:line` /
/// `install:exit` / `install:error`). `-Scope CurrentUser` is the
/// script's posture — no *silent* self-elevation by the app for the
/// install path (consented relaunch-as-admin for the *run* path is
/// step 5.5, `relaunch_as_admin`). The 5.2 boundary (`spawn_streaming`)
/// is reused verbatim; this command only composes it.
#[tauri::command]
fn install_prereqs(app: AppHandle, include_azure: bool) -> Result<(), String> {
    let pwsh = sidecar::discover_pwsh().map_err(|e| e.to_string())?;
    let res_dir = app.path().resource_dir().ok();
    let core =
        sidecar::resolve_core_script(res_dir.as_deref()).ok_or_else(|| {
            "The PS core could not be located (bundled or in repo).".to_string()
        })?;
    let script = sidecar::resolve_install_prereqs_script(&core)
        .ok_or_else(|| "Install-Prerequisites.ps1 not found next to the core."
            .to_string())?;
    let args = sidecar::install_prereqs_args(&script, include_azure);

    std::thread::spawn(move || {
        let argrefs: Vec<&str> = args.iter().map(String::as_str).collect();
        // *>&1 in install_prereqs_args already merges PS streams
        // inside the child, but anything pwsh writes to stderr *before*
        // executing the script (load failure, signature gates,
        // AMSI blocks) lands on the process stderr and would still be
        // lost. Route it to the same install:line so failures are
        // never silent.
        let app_err = app.clone();
        let result = sidecar::spawn_streaming(
            &pwsh.path,
            &argrefs,
            |line| {
                let _ = app.emit("install:line", line.to_string());
            },
            move |line| {
                let _ = app_err.emit("install:line", format!("[stderr] {line}"));
            },
        );
        match result {
            Ok(code) => {
                let _ = app.emit("install:exit", code);
            }
            Err(e) => {
                let _ = app.emit("install:error", e.to_string());
            }
        }
    });
    Ok(())
}

/// Install `pwsh` 7 via winget. `winget` owns its own UAC prompt;
/// the app never self-elevates. If `winget` isn't on PATH the
/// command errors and the frontend offers the official download page
/// instead (via `open_external`).
#[tauri::command]
fn install_pwsh_via_winget(app: AppHandle) -> Result<(), String> {
    if !sidecar::winget_available() {
        return Err(
            "winget is not available on PATH. Install PowerShell 7 from \
             https://aka.ms/powershell instead."
                .to_string(),
        );
    }
    let args = sidecar::winget_install_pwsh_args();
    std::thread::spawn(move || {
        // `Path::new("winget")` lets the OS resolve via PATH.
        let app_err = app.clone();
        let result = sidecar::spawn_streaming(
            Path::new("winget"),
            &args,
            |line| {
                let _ = app.emit("install:line", line.to_string());
            },
            move |line| {
                let _ = app_err.emit("install:line", format!("[stderr] {line}"));
            },
        );
        match result {
            Ok(code) => {
                let _ = app.emit("install:exit", code);
            }
            Err(e) => {
                let _ = app.emit("install:error", e.to_string());
            }
        }
    });
    Ok(())
}

/// Open a `run.result` artifact (the cockpit HTML etc.) in the OS
/// default app via the opener plugin. The MVP uses OS-open for
/// reliability; an in-app webview window for the cockpit HTML is a
/// recorded post-MVP polish (plan §10 / step-6 deviation), not a
/// blocker — the configure→run→watch→open-report loop is complete
/// with OS-open.
#[tauri::command]
fn open_report(app: AppHandle, path: String) -> Result<(), String> {
    app.opener()
        .open_path(path, None::<&str>)
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Mutex::new(RunState::default()))
        .invoke_handler(tauri::generate_handler![
            discover_pwsh_cmd,
            run_sidecar_probe,
            run_assessment,
            supported_schema_major,
            cancel_run,
            default_campaign_dir,
            open_external,
            open_report,
            readiness,
            winget_available,
            install_prereqs,
            install_pwsh_via_winget,
            relaunch_as_admin,
            check_update,
            run_access_review,
            list_campaigns
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_version_matches_cargo_manifest() {
        // Don't hardcode the version — that turns every release bump
        // into a CI break. Assert the function returns the same value
        // CARGO_PKG_VERSION resolves to (which it does, by construction
        // in app_version() above) and that the value is a non-empty
        // dot-separated string. That's what consumers actually rely on.
        assert_eq!(app_version(), env!("CARGO_PKG_VERSION"));
        assert!(!app_version().is_empty());
        assert!(
            app_version().contains('.'),
            "app_version() must be a dotted version, got {:?}",
            app_version()
        );
    }

    #[test]
    fn normalize_modules_dedups_and_validates() {
        // Trims, dedups while preserving order, rejects unknown names,
        // refuses empty selection — the engine's -Modules validator
        // would be the second line of defence; this one fails fast
        // with a clear UI error before any process spawns.
        assert_eq!(
            normalize_modules(vec![
                " Core ".into(),
                "SecureScore".into(),
                "Core".into(),  // duplicate
            ])
            .unwrap(),
            vec!["Core", "SecureScore"]
        );
        assert!(normalize_modules(vec![]).is_err());
        assert!(normalize_modules(vec!["".into()]).is_err());
        assert!(normalize_modules(vec!["NotAModule".into()]).is_err());
    }

    #[test]
    fn normalize_auth_method_matches_engine_vocabulary() {
        // Mirror `Invoke-EntraChecksRun.ps1`'s ValidateSet exactly so
        // the engine never sees a value it would reject.
        assert_eq!(normalize_auth_method("Interactive".into()).unwrap(), "Interactive");
        assert_eq!(normalize_auth_method("DeviceCode".into()).unwrap(), "DeviceCode");
        assert_eq!(normalize_auth_method("Skip".into()).unwrap(), "Skip");
        // Empty defaults to DeviceCode (the GUI's documented default).
        assert_eq!(normalize_auth_method("".into()).unwrap(), "DeviceCode");
        assert!(normalize_auth_method("Something".into()).is_err());
    }

    #[test]
    fn normalize_deep_dives_dedups_and_rejects_unknown() {
        assert_eq!(
            normalize_deep_dives(vec![
                "SecureScore".into(),
                "  DefenderCompliance  ".into(),
                "SecureScore".into(), // duplicate
                "".into(),            // ignored
            ])
            .unwrap(),
            vec!["SecureScore", "DefenderCompliance"]
        );
        // Empty input is allowed — that's "no deep dives this run".
        assert_eq!(normalize_deep_dives(vec![]).unwrap(), Vec::<String>::new());
        // Anything outside the allow-list must fail loudly: silently
        // dropping a renamed key would make the GUI checkbox a no-op.
        assert!(normalize_deep_dives(vec!["NotAReport".into()]).is_err());
    }

    #[test]
    fn normalize_access_review_action_matches_engine_validateset() {
        // Mirrors -AccessReviewAction's ValidateSet. A typo from the
        // webview must fail here, before an auth prompt costs the user
        // a sign-in for a run the engine would then reject.
        for a in ["Open", "Close", "Report"] {
            assert_eq!(normalize_access_review_action(a.into()).unwrap(), a);
        }
        assert_eq!(normalize_access_review_action(" Close ".into()).unwrap(), "Close");
        assert!(normalize_access_review_action("".into()).is_err());
        assert!(normalize_access_review_action("close".into()).is_err());
        assert!(normalize_access_review_action("Delete".into()).is_err());
    }

    #[test]
    fn list_campaigns_parses_sorts_and_skips_unreadable_folders() {
        // A campaign folder is user-managed: half-written, hand-edited
        // and unrelated folders will show up there. None of them may
        // hide the campaigns that *are* valid.
        let base = std::env::temp_dir()
            .join(format!("ecf_ar_list_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // Nothing created yet — "no campaigns", not an error.
        assert!(list_campaigns(base.to_string_lossy().into_owned()).is_empty());

        let write = |name: &str, body: &str| {
            let d = base.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("campaign.json"), body).unwrap();
        };
        write(
            "2026-Q2-20260502-094100",
            r#"{"SchemaVersion":"1.0","CampaignId":"2026-Q2-20260502-094100",
                "PeriodLabel":"2026-Q2","Status":"Closed",
                "GeneratedAtUtc":"2026-05-02T09:41:00Z","TenantName":"Contoso"}"#,
        );
        // With the BOM Windows PowerShell actually writes.
        write(
            "2026-Q3-20260803-141500",
            "\u{feff}{\"CampaignId\":\"2026-Q3-20260803-141500\",\
             \"PeriodLabel\":\"2026-Q3\",\"Status\":\"Open\",\
             \"GeneratedAtUtc\":\"2026-08-03T14:15:00Z\"}",
        );
        // A restored bundle unpacked under a different folder name: the
        // id must follow the FOLDER, because that is what the engine
        // joins onto the campaign root to find it again.
        write(
            "2026-Q1-restored",
            r#"{"CampaignId":"2026-Q1-20260201-101500","PeriodLabel":"2026-Q1",
                "Status":"Closed","GeneratedAtUtc":"2026-02-01T10:15:00Z"}"#,
        );
        write("corrupt", "{ this is not json");
        std::fs::create_dir_all(base.join("not-a-campaign")).unwrap();
        std::fs::write(base.join("stray.txt"), "loose file").unwrap();

        let rows = list_campaigns(base.to_string_lossy().into_owned());
        assert_eq!(rows.len(), 3, "corrupt / non-campaign folders are skipped");
        // Newest first — the panel's default selection is the current
        // quarter's campaign.
        assert_eq!(rows[0].id, "2026-Q3-20260803-141500");
        assert_eq!(rows[0].period, "2026-Q3");
        assert_eq!(rows[0].status, "Open");
        assert_eq!(rows[0].generated_utc, "2026-08-03T14:15:00Z");
        assert!(rows[0].path.ends_with("2026-Q3-20260803-141500"));
        assert_eq!(rows[1].status, "Closed");
        assert_eq!(
            rows[2].id, "2026-Q1-restored",
            "the folder name is authoritative, not campaign.json's CampaignId"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The automated proof of the 4.4 join: resolve the real core →
    /// spawn it via the 4.2 boundary → run each line through the 4.3
    /// parser. Asserts a coherent run (RunStarted … RunResult) where
    /// pwsh + the repo are present (dev box / the Windows UX gate),
    /// skips cleanly otherwise. The GUI *rendering* is still the
    /// manual Windows gate; the Rust pipeline is proven here.
    #[test]
    fn live_run_pipeline_end_to_end() {
        use crate::contract::{parse_line, AppEvent, ParsedLine};

        let pwsh = match sidecar::discover_pwsh() {
            Ok(p) => p,
            Err(_) => return,
        };
        let core = match sidecar::resolve_core_script(None) {
            Some(c) => c,
            None => return,
        };
        let out = std::env::temp_dir().join("EntraChecks-GUI-test");
        let args = sidecar::core_args(
            &core.to_string_lossy(),
            "PipelineTest",
            &out.to_string_lossy(),
            &["Core".to_string()],
            "Skip", // -SkipAuthentication: no tenant needed
            &[],    // no deep-dive reports for the pipeline test
            false,  // no in-concert campaign for the pipeline test
            None,
        );
        let argrefs: Vec<&str> = args.iter().map(String::as_str).collect();

        let mut events = Vec::new();
        let code = sidecar::spawn_streaming(
            &pwsh.path,
            &argrefs,
            |line| {
                if let ParsedLine::Event { event, .. } = parse_line(line) {
                    events.push(event);
                }
            },
            |_| {},
        )
        .expect("core should spawn once pwsh + script resolve");

        assert_eq!(events.first(), Some(&AppEvent::RunStarted));
        let last_is_result =
            matches!(events.last(), Some(AppEvent::RunResult(_)));
        assert!(last_is_result, "stream must end with run.result");
        // -1 only if the child reported no code; a real run exits cleanly.
        assert_ne!(code, -1);
    }
}
