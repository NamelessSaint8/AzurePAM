//! Sidecar boundary — Native App Phase 4, step 4.2.
//!
//! Two responsibilities, both pure process plumbing (NOT engine
//! logic, per the whole-phase discipline):
//!
//!   1. **Discover** an installed PowerShell 7 (`pwsh`). The MVP does
//!      not bundle a runtime (Phase-4 decision); it locates one or
//!      tells the user to install it.
//!   2. **Spawn + stream**: launch a child process and forward its
//!      stdout line-by-line to a callback. `spawn_streaming` is
//!      written generically so step 4.4 reuses it verbatim to launch
//!      `Invoke-EntraChecksRun.ps1 -EmitEvents` (the Phase-1 headless
//!      contract entry). Step 4.2 only exercises it with a fixed,
//!      tenant-free probe so the boundary is provable on any machine.
//!
//! No NDJSON parsing here — that is step 4.3 (`contract` module).
//! This step is deliberately "raw passthrough".

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Which OS family we are building discovery candidates for. Kept
/// explicit (rather than reading `cfg!` inline) so the candidate
/// builder is a pure function unit-testable on any host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    Windows,
    Unix,
}

impl OsFamily {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            OsFamily::Windows
        } else {
            OsFamily::Unix
        }
    }
}

/// Environment inputs for discovery, injected so the candidate list
/// is testable without touching the real environment/filesystem.
#[derive(Debug, Default, Clone)]
pub struct DiscoveryEnv {
    pub path: Option<String>,
    pub program_files: Option<String>,
    pub program_files_x86: Option<String>,
    pub local_appdata: Option<String>,
}

impl DiscoveryEnv {
    pub fn from_process() -> Self {
        DiscoveryEnv {
            path: std::env::var("PATH").ok(),
            program_files: std::env::var("ProgramFiles").ok(),
            program_files_x86: std::env::var("ProgramFiles(x86)").ok(),
            local_appdata: std::env::var("LOCALAPPDATA").ok(),
        }
    }
}

/// Ordered list of paths to try for `pwsh`, most-specific-first:
/// PATH entries, then the well-known install dirs (incl. the Windows
/// Store alias). Pure: no filesystem or process access.
pub fn pwsh_candidates(os: OsFamily, env: &DiscoveryEnv) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let exe = match os {
        OsFamily::Windows => "pwsh.exe",
        OsFamily::Unix => "pwsh",
    };
    let sep = if os == OsFamily::Windows { ';' } else { ':' };

    if let Some(path) = &env.path {
        for dir in path.split(sep).filter(|s| !s.is_empty()) {
            out.push(Path::new(dir).join(exe));
        }
    }

    match os {
        OsFamily::Windows => {
            for base in [&env.program_files, &env.program_files_x86]
                .into_iter()
                .flatten()
            {
                out.push(Path::new(base).join("PowerShell").join("7").join(exe));
            }
            if let Some(lad) = &env.local_appdata {
                // Store/winget app-execution-alias shim.
                out.push(
                    Path::new(lad)
                        .join("Microsoft")
                        .join("WindowsApps")
                        .join(exe),
                );
            }
        }
        OsFamily::Unix => {
            for fixed in [
                "/usr/local/bin/pwsh",
                "/opt/homebrew/bin/pwsh",
                "/usr/bin/pwsh",
                "/snap/bin/pwsh",
            ] {
                out.push(PathBuf::from(fixed));
            }
        }
    }

    // De-dupe while preserving order.
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(p.clone()));
    out
}

/// Parse `pwsh --version` output (e.g. `"PowerShell 7.6.1"`, or just
/// `"7.6.1"`) into `(major, full)`. Pure + total.
pub fn parse_pwsh_version(stdout: &str) -> Option<(u32, String)> {
    let token = stdout
        .split_whitespace()
        .find(|t| t.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))?;
    let major: u32 = token.split('.').next()?.parse().ok()?;
    Some((major, token.to_string()))
}

#[derive(Debug, Clone)]
pub struct PwshLocation {
    pub path: PathBuf,
    pub version: String,
}

#[derive(Debug)]
pub enum PwshError {
    /// No `pwsh` 7+ found on PATH or in the known install locations.
    NotFound,
}

impl std::fmt::Display for PwshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PwshError::NotFound => write!(
                f,
                "PowerShell 7 (pwsh) was not found. Install it from \
                 https://aka.ms/powershell and re-check."
            ),
        }
    }
}

/// Walk the candidates; the first that exists and reports major >= 7
/// from `--version` wins.
pub fn discover_pwsh() -> Result<PwshLocation, PwshError> {
    let env = DiscoveryEnv::from_process();
    for cand in pwsh_candidates(OsFamily::current(), &env) {
        if !cand.is_file() {
            continue;
        }
        let out = Command::new(&cand).arg("--version").output();
        if let Ok(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some((major, full)) = parse_pwsh_version(&text) {
                if major >= 7 {
                    return Ok(PwshLocation {
                        path: cand,
                        version: full,
                    });
                }
            }
        }
    }
    Err(PwshError::NotFound)
}

/// Spawn `program args...` and invoke `on_line` for every line the
/// child writes to stdout, in order, until EOF; then wait for exit
/// and return the exit code (or -1 if the process reported none).
///
/// Generic on purpose: step 4.4 calls this with the headless core
/// entry and `-EmitEvents`; step 4.2 calls it with the fixed probe.
pub fn spawn_streaming<F: FnMut(&str)>(
    program: &Path,
    args: &[&str],
    mut on_line: F,
) -> std::io::Result<i32> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null()) // 4.2: stdout only; stderr handling is later
        .spawn()?;

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => on_line(&l),
                Err(_) => break,
            }
        }
    }

    let status = child.wait()?;
    Ok(status.code().unwrap_or(-1))
}

/// The fixed, tenant-free probe command used by step 4.2 to prove the
/// boundary end-to-end (launch → ordered multi-line stdout streaming
/// → clean exit) without needing Graph/Az or a real run.
pub fn probe_args() -> Vec<&'static str> {
    vec![
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        // Deterministic: a marker, the runtime version, then 3 lines.
        "Write-Output 'sidecar-probe: pwsh boundary OK'; \
         $PSVersionTable.PSVersion.ToString(); \
         1..3 | ForEach-Object { Write-Output ('line ' + $_) }",
    ]
}

// ---- step 4.4: locating + invoking the headless core ----------------

/// Walk `start` and its ancestors looking for `filename`; return the
/// first hit. Pure (no env), so it is unit-testable with a tempdir.
pub fn find_upwards(start: &Path, filename: &str) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let cand = d.join(filename);
        if cand.is_file() {
            return Some(cand);
        }
        dir = d.parent();
    }
    None
}

/// The headless contract entry's filename, and its sub-path inside a
/// packaged app's resource dir (Phase 5.1 bundles the PS core under
/// `core/`, mirroring the repo layout `Start-EntraChecks.ps1` expects
/// as siblings via `$PSScriptRoot`).
pub const CORE_MARKER: &str = "Invoke-EntraChecksRun.ps1";
pub const BUNDLED_CORE_SUBPATH: &str = "core/Invoke-EntraChecksRun.ps1";

/// Pure resolve. Order = the Phase-5 §3 contract: (1) the
/// `ENTRACHECKS_CORE` override (dev / power-user escape hatch), then
/// (2) the bundled copy under the app resource dir (packaged app),
/// then (3) a walk up from cwd / exe dir for the repo marker (dev
/// checkout). Injectable so the order is unit-tested with simulated
/// dirs.
pub fn resolve_core_in(
    env_override: Option<&str>,
    resource_dir: Option<&Path>,
    walk_starts: &[PathBuf],
) -> Option<PathBuf> {
    if let Some(p) = env_override {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Some(rd) = resource_dir {
        let bundled = rd.join(BUNDLED_CORE_SUBPATH);
        if bundled.is_file() {
            return Some(bundled);
        }
    }
    walk_starts
        .iter()
        .find_map(|s| find_upwards(s, CORE_MARKER))
}

/// Locate `Invoke-EntraChecksRun.ps1`. `resource_dir` is the packaged
/// app's resource directory (from the Tauri path resolver) or `None`
/// in a dev run; everything else (env override, cwd, exe dir) is read
/// here and handed to the pure `resolve_core_in`.
pub fn resolve_core_script(resource_dir: Option<&Path>) -> Option<PathBuf> {
    let env_override = std::env::var("ENTRACHECKS_CORE").ok();
    let mut starts: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        starts.push(cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(p) = exe.parent() {
            starts.push(p.to_path_buf());
        }
    }
    resolve_core_in(env_override.as_deref(), resource_dir, &starts)
}

/// Build the `pwsh` argument vector for a headless run. Owned
/// `String`s (paths/tenant are runtime values); the caller maps to
/// `&str` for `spawn_streaming`. Pure + unit-tested.
pub fn core_args(
    core_script: &str,
    tenant: &str,
    output_dir: &str,
    skip_auth: bool,
) -> Vec<String> {
    let mut a = vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-File".to_string(),
        core_script.to_string(),
        "-TenantName".to_string(),
        tenant.to_string(),
        "-OutputDirectory".to_string(),
        output_dir.to_string(),
        "-Modules".to_string(),
        "Core".to_string(),
        "-EmitEvents".to_string(),
    ];
    if skip_auth {
        a.push("-SkipAuthentication".to_string());
    }
    a
}

// ---- step 5.2: readiness model (PS modules detect-only) -------------

/// The dependency surface the Readiness panel reports on. Mirrors
/// `Install-Prerequisites.ps1`: Microsoft.Graph is required, the
/// Az.* set is "optional but recommended" (Defender/AzurePolicy/
/// Recovery rely on it), ImportExcel is purely optional.
/// `(name, required)` — required modules gate Run; optional modules
/// degrade gracefully (a soft warning in the UI).
pub const READINESS_MODULES: &[(&str, bool)] = &[
    ("Microsoft.Graph", true),
    ("Az.Accounts", false),
    ("Az.PolicyInsights", false),
    ("Az.Resources", false),
    ("Az.Security", false),
    ("Az.RecoveryServices", false),
    ("ImportExcel", false),
];

/// One row in the readiness report — Serialize so the webview can
/// switch on it directly. The `required` flag is set by the const
/// list above (the source of truth, never duplicated in JS).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ModuleStatus {
    pub name: String,
    pub required: bool,
    pub present: bool,
    pub version: Option<String>,
}

/// Build a single pwsh -Command that probes every requested module in
/// one invocation (process startup matters on Windows). Emits one
/// `name|version-or-blank` line per module. Pure + tested.
pub fn build_modules_probe_command(names: &[&str]) -> String {
    // Quoted, comma-joined PS array literal — module names are static
    // identifiers (no quote-injection risk by construction).
    let arr = names
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "$names = @({arr}); \
         foreach ($n in $names) {{ \
           $m = Get-Module -ListAvailable -Name $n 2>$null | \
             Sort-Object Version -Descending | Select-Object -First 1; \
           if ($m) {{ ('{{0}}|{{1}}' -f $n, $m.Version.ToString()) }} \
           else {{ ('{{0}}|' -f $n) }} \
         }}"
    )
}

/// Parse `name|version` lines into `(name, Option<version>)` pairs in
/// the order they were emitted. Blank lines and lines without `|` are
/// ignored. CRLF is already stripped by `BufRead::lines`. Pure +
/// tested against synthetic + realistic fixtures.
pub fn parse_modules_probe_output(stdout: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let Some((name, ver)) = t.split_once('|') else {
            continue;
        };
        let v = ver.trim();
        out.push((
            name.trim().to_string(),
            if v.is_empty() { None } else { Some(v.to_string()) },
        ));
    }
    out
}

/// Run the probe against the discovered `pwsh` and return one
/// `ModuleStatus` per name in `READINESS_MODULES`, preserving order.
/// Modules not reported by the probe (shouldn't happen, but
/// defence-in-depth) come back as `present: false`.
pub fn collect_readiness(pwsh: &Path) -> std::io::Result<Vec<ModuleStatus>> {
    let names: Vec<&str> = READINESS_MODULES.iter().map(|(n, _)| *n).collect();
    let cmd = build_modules_probe_command(&names);
    let args: Vec<&str> = vec!["-NoProfile", "-NonInteractive", "-Command", &cmd];
    let mut buf = String::new();
    let _ = spawn_streaming(pwsh, &args, |line| {
        buf.push_str(line);
        buf.push('\n');
    })?;
    let parsed = parse_modules_probe_output(&buf);
    let map: std::collections::HashMap<&str, Option<String>> = parsed
        .iter()
        .map(|(n, v)| (n.as_str(), v.clone()))
        .collect();
    let report = READINESS_MODULES
        .iter()
        .map(|(name, required)| {
            let version = map.get(*name).cloned().unwrap_or(None);
            ModuleStatus {
                name: (*name).to_string(),
                required: *required,
                present: version.is_some(),
                version,
            }
        })
        .collect();
    Ok(report)
}

// ---- step 5.3: consented guided remediation -------------------------

/// Sibling of `Invoke-EntraChecksRun.ps1` in both the bundled `core/`
/// resource subtree and the dev checkout, so the same resolve order
/// (env override → bundled → walk-up) puts the prereqs script next
/// to wherever the core is.
pub const PREREQS_FILENAME: &str = "Install-Prerequisites.ps1";

/// Resolve the bundled `Install-Prerequisites.ps1`. Anchored to the
/// already-resolved core script: a packaged app keeps both under
/// `core/`, a dev checkout keeps both at the repo root.
pub fn resolve_install_prereqs_script(core_script: &Path) -> Option<PathBuf> {
    let cand = core_script.parent()?.join(PREREQS_FILENAME);
    if cand.is_file() {
        Some(cand)
    } else {
        None
    }
}

/// Build `pwsh` args to run `Install-Prerequisites.ps1`. `-GraphOnly`
/// is the script's existing switch (skip the Az.* set). Pure + tested.
pub fn install_prereqs_args(script: &Path, include_azure: bool) -> Vec<String> {
    let mut a = vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-File".to_string(),
        script.to_string_lossy().into_owned(),
    ];
    if !include_azure {
        a.push("-GraphOnly".to_string());
    }
    a
}

/// Whether `winget` is on PATH. The Phase-5 §4 decision is to *use
/// winget if present*, never silently download an MSI ourselves — so
/// the absence of winget hands the user to the official page, not to
/// a self-elevating installer.
pub fn winget_available() -> bool {
    let exe = if cfg!(target_os = "windows") {
        "winget.exe"
    } else {
        "winget"
    };
    let sep = if cfg!(target_os = "windows") { ';' } else { ':' };
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    path.split(sep)
        .filter(|s| !s.is_empty())
        .any(|d| Path::new(d).join(exe).is_file())
}

/// Args for `winget install --id Microsoft.PowerShell -e`. The
/// accept-* flags keep the install non-interactive on the *winget*
/// side; winget itself owns its UAC prompt (the app does not
/// self-elevate). Pure + tested.
pub fn winget_install_pwsh_args() -> Vec<&'static str> {
    vec![
        "install",
        "--id",
        "Microsoft.PowerShell",
        "-e",
        "--accept-source-agreements",
        "--accept-package-agreements",
    ]
}

// ---- step 4.5: cooperative cancel (Phase-3a sentinel) ---------------

/// `<output_dir>/.runs/<run_id>.cancel` — the exact path the engine's
/// `Get-EcfCancelSentinelPath` polls. Pure; unit-tested.
pub fn cancel_sentinel_path(output_dir: &Path, run_id: &str) -> PathBuf {
    output_dir
        .join(".runs")
        .join(format!("{run_id}.cancel"))
}

/// Request cancellation by creating the sentinel (its mere existence
/// is the signal — see `Test-EcfCancelled`). Creates `.runs` if
/// needed. The engine stops at the next safe checkpoint and emits
/// `run.cancelled` + a `Cancelled` `run.result`; the shell does not
/// kill the child (cooperative, artifact-preserving by design).
pub fn request_cancel(output_dir: &Path, run_id: &str) -> std::io::Result<PathBuf> {
    let path = cancel_sentinel_path(output_dir, run_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, b"cancel requested by EntraChecks desktop\n")?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Path::join` uses the *host* separator, so when this suite runs
    /// on Unix a Windows candidate serializes with `/`. Compare on a
    /// separator-normalized suffix so the test asserts the builder's
    /// logic identically on any CI host (production discovery runs on
    /// a real Windows host where `is_file()` resolves either way).
    fn has_suffix(c: &[PathBuf], suffix: &str) -> bool {
        c.iter()
            .any(|p| p.to_string_lossy().replace('\\', "/").ends_with(suffix))
    }

    #[test]
    fn windows_candidates_cover_path_and_known_dirs() {
        let env = DiscoveryEnv {
            path: Some(r"C:\bin;C:\tools".to_string()),
            program_files: Some(r"C:\Program Files".to_string()),
            program_files_x86: Some(r"C:\Program Files (x86)".to_string()),
            local_appdata: Some(r"C:\Users\me\AppData\Local".to_string()),
        };
        let c = pwsh_candidates(OsFamily::Windows, &env);
        assert!(has_suffix(&c, "C:/bin/pwsh.exe"));
        assert!(has_suffix(&c, "C:/tools/pwsh.exe"));
        assert!(has_suffix(&c, "C:/Program Files/PowerShell/7/pwsh.exe"));
        assert!(has_suffix(
            &c,
            "C:/Program Files (x86)/PowerShell/7/pwsh.exe"
        ));
        assert!(has_suffix(&c, "Microsoft/WindowsApps/pwsh.exe"));
    }

    #[test]
    fn unix_candidates_include_path_and_common_prefixes() {
        let env = DiscoveryEnv {
            path: Some("/usr/local/bin:/home/me/bin".to_string()),
            ..Default::default()
        };
        let c = pwsh_candidates(OsFamily::Unix, &env);
        assert!(c.contains(&PathBuf::from("/home/me/bin/pwsh")));
        assert!(c.contains(&PathBuf::from("/usr/local/bin/pwsh")));
        assert!(c.contains(&PathBuf::from("/opt/homebrew/bin/pwsh")));
    }

    #[test]
    fn candidates_are_order_preserving_and_deduped() {
        // /usr/local/bin appears both via PATH and the fixed list.
        let env = DiscoveryEnv {
            path: Some("/usr/local/bin".to_string()),
            ..Default::default()
        };
        let c = pwsh_candidates(OsFamily::Unix, &env);
        let n = c
            .iter()
            .filter(|p| p.as_path() == Path::new("/usr/local/bin/pwsh"))
            .count();
        assert_eq!(n, 1, "duplicate candidate should be collapsed");
        assert_eq!(c[0], Path::new("/usr/local/bin/pwsh"), "PATH first");
    }

    #[test]
    fn empty_env_unix_still_offers_known_prefixes() {
        let c = pwsh_candidates(OsFamily::Unix, &DiscoveryEnv::default());
        assert!(c.contains(&PathBuf::from("/usr/bin/pwsh")));
    }

    #[test]
    fn probe_streams_end_to_end_when_pwsh_present() {
        // The automated half of "proves the sidecar boundary". Where
        // pwsh 7 is installed (dev box, the Windows UX gate) this
        // exercises discover → spawn → ordered stdout streaming →
        // clean exit. Where it isn't (other CI hosts) it skips
        // cleanly — discovery returning NotFound is itself the
        // correct, tested behaviour there.
        let loc = match discover_pwsh() {
            Ok(l) => l,
            Err(_) => return,
        };
        let mut lines = Vec::new();
        let code = spawn_streaming(&loc.path, &probe_args(), |l| {
            lines.push(l.to_string())
        })
        .expect("probe should spawn once pwsh is discovered");
        assert_eq!(code, 0, "probe must exit 0");
        assert!(
            lines
                .first()
                .map(|s| s.contains("sidecar-probe: pwsh boundary OK"))
                .unwrap_or(false),
            "first streamed line is the probe marker"
        );
        assert!(
            lines.iter().any(|l| l == "line 3"),
            "later lines stream through in order too"
        );
    }

    #[test]
    fn find_upwards_locates_a_marker_in_an_ancestor() {
        let base = std::env::temp_dir()
            .join(format!("ecf_fu_{}", std::process::id()));
        let deep = base.join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        let marker = base.join("a").join("Invoke-EntraChecksRun.ps1");
        std::fs::write(&marker, "# marker").unwrap();

        let hit = find_upwards(&deep, "Invoke-EntraChecksRun.ps1");
        assert_eq!(hit.as_deref(), Some(marker.as_path()));
        assert!(find_upwards(&deep, "does-not-exist.ps1").is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn core_args_shape_and_skip_auth_toggle() {
        let with = core_args("/r/Invoke-EntraChecksRun.ps1", "Contoso", "/o", true);
        assert_eq!(with[2], "-File");
        assert_eq!(with[3], "/r/Invoke-EntraChecksRun.ps1");
        assert!(with.iter().any(|x| x == "-TenantName"));
        assert!(with.iter().any(|x| x == "Contoso"));
        assert!(with.iter().any(|x| x == "-EmitEvents"));
        assert!(with.iter().any(|x| x == "-SkipAuthentication"));

        let without = core_args("/r/c.ps1", "T", "/o", false);
        assert!(!without.iter().any(|x| x == "-SkipAuthentication"));
        // -EmitEvents is non-negotiable: it is how the GUI sees anything.
        assert!(without.iter().any(|x| x == "-EmitEvents"));
    }

    #[test]
    fn modules_probe_command_contains_every_requested_name() {
        let cmd = build_modules_probe_command(&[
            "Microsoft.Graph",
            "Az.Accounts",
            "ImportExcel",
        ]);
        for n in ["Microsoft.Graph", "Az.Accounts", "ImportExcel"] {
            assert!(cmd.contains(n), "probe command must mention {n}");
        }
        // The output template is what `parse_modules_probe_output`
        // assumes — a regression here would split the contract.
        assert!(cmd.contains("|"));
    }

    #[test]
    fn parses_modules_probe_output() {
        let raw = "\
Microsoft.Graph|2.20.0
Az.Accounts|3.5.0
Az.PolicyInsights|

ImportExcel|7.8.10
garbage line without a pipe
";
        let parsed = parse_modules_probe_output(raw);
        assert_eq!(
            parsed,
            vec![
                ("Microsoft.Graph".to_string(), Some("2.20.0".to_string())),
                ("Az.Accounts".to_string(), Some("3.5.0".to_string())),
                ("Az.PolicyInsights".to_string(), None),
                ("ImportExcel".to_string(), Some("7.8.10".to_string())),
            ]
        );
    }

    #[test]
    fn collect_readiness_e2e_when_pwsh_present() {
        // Automated proof of the 5.2 probe: where pwsh is installed
        // we actually run it and assert each requested module name
        // comes back exactly once (present or not — depends on the
        // machine). Skips cleanly where pwsh is absent.
        let loc = match discover_pwsh() {
            Ok(l) => l,
            Err(_) => return,
        };
        let report = collect_readiness(&loc.path).expect("probe should run");
        assert_eq!(report.len(), READINESS_MODULES.len());
        for ((expected, required), got) in
            READINESS_MODULES.iter().zip(report.iter())
        {
            assert_eq!(&got.name, expected);
            assert_eq!(got.required, *required);
            assert_eq!(got.present, got.version.is_some());
        }
    }

    #[test]
    fn install_prereqs_args_shape_and_graph_only_toggle() {
        let full = install_prereqs_args(
            Path::new("/r/Install-Prerequisites.ps1"),
            true,
        );
        assert_eq!(full[2], "-File");
        assert_eq!(full[3], "/r/Install-Prerequisites.ps1");
        assert!(!full.iter().any(|x| x == "-GraphOnly"));

        let graph_only = install_prereqs_args(
            Path::new("/r/Install-Prerequisites.ps1"),
            false,
        );
        assert!(graph_only.iter().any(|x| x == "-GraphOnly"));
    }

    #[test]
    fn winget_install_pwsh_args_carry_accept_flags() {
        let a = winget_install_pwsh_args();
        assert_eq!(a[0], "install");
        assert!(a.contains(&"Microsoft.PowerShell"));
        // Non-interactive on winget's side, BUT winget still owns its
        // own UAC prompt — the app must not silently elevate.
        assert!(a.contains(&"--accept-source-agreements"));
        assert!(a.contains(&"--accept-package-agreements"));
    }

    #[test]
    fn resolve_install_prereqs_anchors_to_core_dir() {
        let base = std::env::temp_dir()
            .join(format!("ecf_prereqs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let core_dir = base.join("core");
        std::fs::create_dir_all(&core_dir).unwrap();
        let core = core_dir.join("Invoke-EntraChecksRun.ps1");
        std::fs::write(&core, "# core").unwrap();

        // Missing sibling -> None (not fatal; UI surfaces it).
        assert_eq!(resolve_install_prereqs_script(&core), None);

        let prereqs = core_dir.join(PREREQS_FILENAME);
        std::fs::write(&prereqs, "# prereqs").unwrap();
        assert_eq!(
            resolve_install_prereqs_script(&core),
            Some(prereqs)
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn resolve_order_env_then_bundled_then_walkup() {
        let base = std::env::temp_dir()
            .join(format!("ecf_resolve_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // A fake repo checkout (walk-up target).
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let repo_marker = repo.join(CORE_MARKER);
        std::fs::write(&repo_marker, "# repo").unwrap();

        // A fake packaged resource dir with the bundled core.
        let res = base.join("res");
        std::fs::create_dir_all(res.join("core")).unwrap();
        let bundled = res.join(BUNDLED_CORE_SUBPATH);
        std::fs::write(&bundled, "# bundled").unwrap();

        // A fake explicit override.
        let ovr = base.join("override.ps1");
        std::fs::write(&ovr, "# override").unwrap();

        let starts = vec![repo.clone()];

        // 1. Override wins over everything.
        assert_eq!(
            resolve_core_in(
                Some(ovr.to_str().unwrap()),
                Some(&res),
                &starts
            ),
            Some(ovr.clone())
        );
        // 2. No override -> bundled resource dir beats walk-up.
        assert_eq!(
            resolve_core_in(None, Some(&res), &starts),
            Some(bundled.clone())
        );
        // 3. No override, no bundled -> walk-up (dev checkout).
        assert_eq!(
            resolve_core_in(None, None, &starts),
            Some(repo_marker.clone())
        );
        // A non-existent override is ignored, not fatal -> falls through.
        assert_eq!(
            resolve_core_in(Some("/no/such/file.ps1"), None, &starts),
            Some(repo_marker)
        );
        // Nothing anywhere -> None (the UI surfaces the actionable error).
        assert_eq!(resolve_core_in(None, None, &[]), None);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn bundled_resource_manifest_matches_real_source_files() {
        // Guard: every path the tauri.conf.json `bundle.resources`
        // manifest references must exist in the repo, so packaging
        // can't silently ship a broken core. Resolve the repo root via
        // the marker, then assert each bundled source is present.
        let cwd = std::env::current_dir().unwrap();
        let entry = match find_upwards(&cwd, CORE_MARKER) {
            Some(p) => p,
            None => return, // not in a checkout (e.g. packaged CI) — skip
        };
        let root = entry.parent().unwrap();
        for rel in [
            "Invoke-EntraChecksRun.ps1",
            "Start-EntraChecks.ps1",
            "EntraChecks.Orchestration.ps1",
            "Install-Prerequisites.ps1",
        ] {
            assert!(root.join(rel).is_file(), "bundled source missing: {rel}");
        }
        for dir in ["Scripts", "Modules", "config"] {
            assert!(root.join(dir).is_dir(), "bundled source dir missing: {dir}");
        }
    }

    #[test]
    fn cancel_sentinel_path_matches_engine_convention() {
        let p = cancel_sentinel_path(Path::new("/out/dir"), "abc-123");
        assert_eq!(p, Path::new("/out/dir/.runs/abc-123.cancel"));
    }

    #[test]
    fn request_cancel_creates_runs_dir_and_file() {
        let base = std::env::temp_dir()
            .join(format!("ecf_cancel_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let p = request_cancel(&base, "run-77").expect("write sentinel");
        assert!(p.is_file(), "sentinel must exist (presence is the signal)");
        assert_eq!(p, base.join(".runs").join("run-77.cancel"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn parses_versions() {
        assert_eq!(
            parse_pwsh_version("PowerShell 7.6.1"),
            Some((7, "7.6.1".to_string()))
        );
        assert_eq!(
            parse_pwsh_version("7.4.2\n"),
            Some((7, "7.4.2".to_string()))
        );
        assert_eq!(
            parse_pwsh_version("PowerShell 5.1.19041.4046"),
            Some((5, "5.1.19041.4046".to_string()))
        );
        assert_eq!(parse_pwsh_version("no version here"), None);
        assert_eq!(parse_pwsh_version(""), None);
    }
}
