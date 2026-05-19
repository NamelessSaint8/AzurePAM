//! EntraChecks desktop shell — Native App Phase 4 (MVP).
//!
//! Phase 4.1 (this commit): scaffold only. The Rust shell opens a
//! window and serves the static frontend. There is **no PowerShell
//! sidecar, no NDJSON parsing, and no assessment logic here yet** —
//! those arrive in steps 2–6 (see
//! `plans/Native-App-Phase4-Tauri-MVP-Plan.md`). The discipline for
//! the whole phase: Rust only spawns, parses, emits, writes the
//! cancel sentinel, and opens artifacts — it never re-implements the
//! engine.
//!
//! `tauri-plugin-opener` is wired now because step 6 ("Open report")
//! needs it; it is otherwise inert at this stage.

/// The desktop shell's own version (the Cargo package version).
///
/// Distinct from the engine/contract `schemaVersion` (owned by the
/// PowerShell core, validated by the parser added in step 3). Kept as
/// a tiny pure function so `cargo test` has something real to assert
/// against from the very first scaffold commit.
pub fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_version_matches_cargo_manifest() {
        // Pins that the shell can report its own version and that the
        // crate compiles + links its test target — the meaningful
        // green-bar for the scaffold step.
        assert_eq!(app_version(), "0.1.0");
        assert!(!app_version().is_empty());
    }
}
