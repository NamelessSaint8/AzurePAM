//! EntraChecks desktop shell — Native App Phase 4 (MVP).
//!
//! Phase 5.5 (this commit): **relaunch-as-admin**. Some EntraChecks
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
        let result = sidecar::spawn_streaming(&loc.path, &args, |line| {
            let _ = app.emit("sidecar:line", line.to_string());
        });
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

/// The dedicated Result screen + Open report is 4.6. This step adds
/// the auth panel + Cancel: the run's `runId` (envelope) and
/// `output_dir` are recorded in `RunState` so `cancel_run` can drop
/// the Phase-3a sentinel.
#[tauri::command]
fn run_assessment(app: AppHandle, tenant: String, skip_auth: bool) -> Result<(), String> {
    let pwsh = sidecar::discover_pwsh().map_err(|e| e.to_string())?;
    let res_dir = app.path().resource_dir().ok();
    let core = sidecar::resolve_core_script(res_dir.as_deref()).ok_or_else(|| {
        "Invoke-EntraChecksRun.ps1 was not found (not bundled, no \
         ENTRACHECKS_CORE override, and not inside the repository)."
            .to_string()
    })?;
    let tenant = if tenant.trim().is_empty() {
        "DevTenant".to_string()
    } else {
        tenant
    };
    let out_dir = std::env::temp_dir().join("EntraChecks-GUI");
    let core_s = core.to_string_lossy().into_owned();
    let out_s = out_dir.to_string_lossy().into_owned();

    // Arm cancellation state for this run (output dir known now;
    // run_id arrives with the first event).
    {
        let st = app.state::<Mutex<RunState>>();
        let mut g = st.lock().map_err(|_| "run state poisoned".to_string())?;
        g.output_dir = Some(out_dir.clone());
        g.run_id = None;
    }

    std::thread::spawn(move || {
        let args = sidecar::core_args(&core_s, &tenant, &out_s, skip_auth);
        let argrefs: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = sidecar::spawn_streaming(&pwsh.path, &argrefs, |line| {
            if let contract::ParsedLine::Event {
                schema_major,
                run_id,
                event,
            } = contract::parse_line(line)
            {
                if let Some(rid) = run_id {
                    record_run_id(&app, rid);
                }
                let _ = app.emit(
                    "run:event",
                    serde_json::json!({ "schemaMajor": schema_major, "event": event }),
                );
            }
        });
        match result {
            Ok(code) => {
                let _ = app.emit("run:exit", code);
            }
            Err(e) => {
                let _ = app.emit("run:error", e.to_string());
            }
        }
    });
    Ok(())
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
        let result =
            sidecar::spawn_streaming(&pwsh.path, &argrefs, |line| {
                let _ = app.emit("install:line", line.to_string());
            });
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
        let result =
            sidecar::spawn_streaming(Path::new("winget"), &args, |line| {
                let _ = app.emit("install:line", line.to_string());
            });
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
            open_external,
            open_report,
            readiness,
            winget_available,
            install_prereqs,
            install_pwsh_via_winget,
            relaunch_as_admin
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_version_matches_cargo_manifest() {
        assert_eq!(app_version(), "0.1.0");
        assert!(!app_version().is_empty());
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
            true, // -SkipAuthentication: no tenant needed
        );
        let argrefs: Vec<&str> = args.iter().map(String::as_str).collect();

        let mut events = Vec::new();
        let code = sidecar::spawn_streaming(&pwsh.path, &argrefs, |line| {
            if let ParsedLine::Event { event, .. } = parse_line(line) {
                events.push(event);
            }
        })
        .expect("core should spawn once pwsh + script resolve");

        assert_eq!(events.first(), Some(&AppEvent::RunStarted));
        let last_is_result =
            matches!(events.last(), Some(AppEvent::RunResult(_)));
        assert!(last_is_result, "stream must end with run.result");
        // -1 only if the child reported no code; a real run exits cleanly.
        assert_ne!(code, -1);
    }
}
