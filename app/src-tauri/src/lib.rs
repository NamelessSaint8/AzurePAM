//! EntraChecks desktop shell — Native App Phase 4 (MVP).
//!
//! Step 4.3 (this commit): the **contract parser** lands
//! (`contract` module) — pure, fully unit-tested against synthetic
//! lines *and* a real `Invoke-EntraChecksRun.ps1 -EmitEvents`
//! capture. It is not yet wired into the live stream: `sidecar` is
//! still raw passthrough and no real assessment is launched (that is
//! step 4.4, which feeds `sidecar` lines through `contract` into the
//! UI). Whole-phase discipline holds: Rust only discovers / spawns /
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            discover_pwsh_cmd,
            run_sidecar_probe
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
}
