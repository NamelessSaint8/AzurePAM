//! EntraChecks desktop shell — Native App Phase 4 (MVP).
//!
//! Step 4.4 (this commit): the **Live Run** path is joined. A real
//! `Invoke-EntraChecksRun.ps1 -EmitEvents` assessment is launched
//! (reusing the 4.2 `spawn_streaming` boundary), every stdout line
//! is run through the 4.3 `contract` parser, and parsed events are
//! emitted to the webview which renders phases / progress / log live
//! plus the "engine newer than app" banner. Auth device-code panel +
//! Cancel are step 4.5; the rich Result screen + Open report is 4.6.
//! Whole-phase discipline holds: Rust only discovers / spawns /
//! streams / parses / opens — it never re-implements the engine.
//!
//! `tauri-plugin-opener` is wired now because step 6 ("Open report")
//! needs it; it is otherwise inert at this stage.

pub mod contract;
mod sidecar;

use tauri::{AppHandle, Emitter};

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
/// only joins them. Per parsed line:
///   - `run:event`  → `{ schemaMajor, event }` (event = the 4.3
///                     internally-tagged `AppEvent`)
///   - non-contract / decorative stdout is silently dropped
/// then a terminal `run:exit` (code) or `run:error` (message).
///
/// Auth (device-code panel) and Cancel are deliberately *not* here —
/// they are step 4.5; the dedicated Result screen + Open report is
/// 4.6. This step renders phases/progress/log live and the
/// schema-newer banner.
#[tauri::command]
fn run_assessment(app: AppHandle, tenant: String, skip_auth: bool) -> Result<(), String> {
    let pwsh = sidecar::discover_pwsh().map_err(|e| e.to_string())?;
    let core = sidecar::resolve_core_script().ok_or_else(|| {
        "Invoke-EntraChecksRun.ps1 was not found. Set ENTRACHECKS_CORE \
         to its full path, or run from inside the repository."
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

    std::thread::spawn(move || {
        let args = sidecar::core_args(&core_s, &tenant, &out_s, skip_auth);
        let argrefs: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = sidecar::spawn_streaming(&pwsh.path, &argrefs, |line| {
            if let contract::ParsedLine::Event { schema_major, event } =
                contract::parse_line(line)
            {
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            discover_pwsh_cmd,
            run_sidecar_probe,
            run_assessment,
            supported_schema_major
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
        let core = match sidecar::resolve_core_script() {
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
