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

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Suppress the console-window that Windows otherwise allocates when
/// a GUI-subsystem parent (Tauri) spawns a console-subsystem child
/// (pwsh, winget); also turn off ANSI/VT colour escapes from
/// PowerShell so a piped stderr doesn't end up littered with raw
/// `\e[36;1m`-style bytes that look like garbage in the Log pane.
/// `apply_no_console_window` is the misnomer name for legacy reasons;
/// it carries both the platform-specific console suppression and the
/// cross-platform colour-disable env vars.
fn apply_no_console_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    // De-facto cross-tool convention (also honored by many pwsh
    // formatters / PSReadLine). Combined with the pwsh-specific
    // legacy var below, both old and new ANSI paths are silenced.
    cmd.env("NO_COLOR", "1");
    cmd.env("__SuppressAnsiEscapeSequences", "1");
}

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
        // Even the brief `--version` probe pops a console window on
        // Windows without this — and `discover_pwsh` runs on every
        // Readiness re-check.
        let mut probe = Command::new(&cand);
        probe.arg("--version");
        apply_no_console_window(&mut probe);
        let out = probe.output();
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
/// Spawn `program args...`, pipe both stdout and stderr, and call
/// `on_stdout` / `on_stderr` for every line on each stream in arrival
/// order. Two callbacks (rather than one merged stream) so the run
/// path can keep the parser-fed stdout cleanly separated from
/// engine error output that should bypass the parser and go straight
/// to the user — exactly the gap that caused the "Run exited 1 with
/// no detail" report.
///
/// Implementation: two reader threads → an mpsc channel → the
/// calling thread drains it serially, calling the right callback per
/// line. Real-time, no lifetime gymnastics on the callbacks.
pub fn spawn_streaming<F, G>(
    program: &Path,
    args: &[&str],
    mut on_stdout: F,
    mut on_stderr: G,
) -> std::io::Result<i32>
where
    F: FnMut(&str),
    G: FnMut(&str),
{
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    apply_no_console_window(&mut cmd);
    let mut child = cmd.spawn()?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();

    // Stderr reader thread (owns its tx clone).
    let err_thread = stderr.map(|s| {
        let tx_err = tx.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(s);
            for line in reader.lines().map_while(Result::ok) {
                let _ = tx_err.send((true, line));
            }
        })
    });

    // Stdout reader thread (owns the original tx).
    let out_thread = stdout.map(|s| {
        std::thread::spawn(move || {
            let reader = BufReader::new(s);
            for line in reader.lines().map_while(Result::ok) {
                let _ = tx.send((false, line));
            }
        })
    });

    // Both thread copies of tx are now in their respective threads;
    // when both finish, the channel closes and rx returns Err.
    while let Ok((is_err, line)) = rx.recv() {
        if is_err {
            on_stderr(&line);
        } else {
            on_stdout(&line);
        }
    }

    if let Some(h) = out_thread {
        let _ = h.join();
    }
    if let Some(h) = err_thread {
        let _ = h.join();
    }

    let status = child.wait()?;
    Ok(status.code().unwrap_or(-1))
}

enum StreamItem {
    StdoutLine(String),
    StdoutFragment(String),
    StderrLine(String),
}

/// Like `spawn_streaming`, but also reports raw stdout fragments as
/// soon as bytes arrive. The assessment path needs this for auth
/// prompts from Microsoft.Graph: the device-code prompt can be written
/// without a trailing newline, so a line reader can leave the webview
/// waiting while PowerShell is already blocked on sign-in.
pub fn spawn_streaming_with_stdout_fragments<F, G, H>(
    program: &Path,
    args: &[&str],
    mut on_stdout: F,
    mut on_stderr: G,
    mut on_stdout_fragment: H,
) -> std::io::Result<i32>
where
    F: FnMut(&str),
    G: FnMut(&str),
    H: FnMut(&str),
{
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    apply_no_console_window(&mut cmd);
    let mut child = cmd.spawn()?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (tx, rx) = std::sync::mpsc::channel::<StreamItem>();

    let err_thread = stderr.map(|s| {
        let tx_err = tx.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(s);
            for line in reader.lines().map_while(Result::ok) {
                let _ = tx_err.send(StreamItem::StderrLine(line));
            }
        })
    });

    let out_thread = stdout.map(|mut s| {
        std::thread::spawn(move || {
            let mut buf = [0_u8; 1024];
            let mut pending = String::new();
            loop {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                        let _ = tx.send(StreamItem::StdoutFragment(chunk.clone()));
                        pending.push_str(&chunk);
                        drain_complete_lines(&mut pending, |line| {
                            let _ = tx.send(StreamItem::StdoutLine(line));
                        });
                    }
                    Err(_) => break,
                }
            }
            if !pending.is_empty() {
                let _ = tx.send(StreamItem::StdoutLine(pending));
            }
        })
    });

    while let Ok(item) = rx.recv() {
        match item {
            StreamItem::StdoutLine(line) => on_stdout(&line),
            StreamItem::StdoutFragment(fragment) => on_stdout_fragment(&fragment),
            StreamItem::StderrLine(line) => on_stderr(&line),
        }
    }

    if let Some(h) = out_thread {
        let _ = h.join();
    }
    if let Some(h) = err_thread {
        let _ = h.join();
    }

    let status = child.wait()?;
    Ok(status.code().unwrap_or(-1))
}

fn drain_complete_lines<F>(pending: &mut String, mut on_line: F)
where
    F: FnMut(String),
{
    while let Some(idx) = pending.find(['\n', '\r']) {
        let line = pending[..idx].to_string();
        let rest_start = if pending[idx..].starts_with("\r\n") {
            idx + 2
        } else {
            idx + 1
        };
        pending.drain(..rest_start);
        on_line(line);
    }
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
fn ps_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Scrape a Microsoft.Graph SDK device-code message and pull the
/// user code out. The SDK writes a host-UI message like
/// "...enter the code XXXX-XXXX to authenticate." which `Connect-
/// MgGraph -UseDeviceAuthentication` routes through PowerShell's
/// information stream — captured by our stdout reader, but
/// indistinguishable to the contract parser from any other
/// non-NDJSON line. This pure helper lets the desktop shell promote
/// that line into a synthetic `authDeviceCode` event so the Sign-in
/// panel can show the code (instead of "waiting for the SDK to
/// print it" forever).
///
/// Looks for case-insensitive `"code "` then takes the next token of
/// uppercase letters / digits / dashes; min length 6 to avoid false
/// positives on English words.
pub fn extract_device_code(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    let pos = lower.find("code ")?;
    let after = &line[pos + "code ".len()..];
    let token: String = after
        .chars()
        .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '-')
        .collect();
    // Real Azure device codes are 8–9 chars (e.g. `AYR2KQHQK` or
    // `B5C9-FXAB`). 8 as the floor reduces false positives from
    // English noise after "code " while still catching every real
    // SDK message.
    if token.len() >= 8 && token.chars().any(|c| c.is_ascii_digit() || c.is_ascii_uppercase()) {
        Some(token)
    } else {
        None
    }
}

pub fn core_args(
    core_script: &str,
    tenant: &str,
    output_dir: &str,
    modules: &[String],
    auth_method: &str,
) -> Vec<String> {
    let modules_literal = format!(
        "@({})",
        modules
            .iter()
            .map(|m| ps_single_quote(m))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut command = format!(
        "& {} -TenantName {} -OutputDirectory {} -Modules {} -AuthMethod {} -EmitEvents",
        ps_single_quote(core_script),
        ps_single_quote(tenant),
        ps_single_quote(output_dir),
        modules_literal,
        ps_single_quote(auth_method)
    );
    if auth_method == "Skip" {
        command.push_str(" -SkipAuthentication");
    }
    command.push_str(" *>&1");
    vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        // Bundled core scripts can be Mark-of-the-Web-tagged by NSIS;
        // the default RemoteSigned policy would silently refuse to
        // run them. Bypass scopes only to this invocation.
        "-ExecutionPolicy".to_string(),
        "Bypass".to_string(),
        "-Command".to_string(),
        command,
    ]
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
    ("Az.Monitor", false),
    ("Az.OperationalInsights", false),
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
    }, |_| {
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

/// Build `pwsh` args to run `Install-Prerequisites.ps1`. Two
/// posture choices baked in here, learned from a real Windows run
/// where the script appeared to "run but not install":
///
/// 1. `-ExecutionPolicy Bypass` — Tauri-bundled .ps1 files may be
///    Mark-of-the-Web tagged by the installer; the default
///    `RemoteSigned` policy then silently refuses to run them.
///    Bypass scopes only to this invocation; nothing system-wide.
/// 2. `-Command "& '<script>' -GraphOnly:$x *>&1"` — `*>&1` merges
///    every PowerShell stream (Error / Warning / Verbose / Debug /
///    Information / Success) into stdout. The spawn boundary
///    captures stdout only, so without this any `Install-Module` /
///    PSGallery exception lands on stderr and is dropped — the
///    user sees "OK" lines then silence. With it, the actual
///    failure cause reaches the log pane.
///
/// `-GraphOnly` mirrors the script's existing switch. Pure + tested.
pub fn install_prereqs_args(script: &Path, include_azure: bool) -> Vec<String> {
    let path_esc = script.to_string_lossy().replace('\'', "''");
    let graph_only = if include_azure { "$false" } else { "$true" };
    let cmd = format!("& '{path_esc}' -GraphOnly:{graph_only} *>&1");
    vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-ExecutionPolicy".to_string(),
        "Bypass".to_string(),
        "-Command".to_string(),
        cmd,
    ]
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
        let code = spawn_streaming(
            &loc.path,
            &probe_args(),
            |l| lines.push(l.to_string()),
            |_| {},
        )
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
        let with = core_args(
            "/r/Invoke-EntraChecksRun.ps1",
            "Contoso",
            "/o",
            &["Core".to_string(), "SecureScore".to_string()],
            "Skip",
        );
        // Both non-negotiable on Windows: bypass MotW-tagged bundled
        // scripts, and the core file we're running.
        assert!(with.contains(&"-ExecutionPolicy".to_string()));
        assert!(with.contains(&"Bypass".to_string()));
        let cmd_idx = with
            .iter()
            .position(|x| x == "-Command")
            .expect("-Command");
        let cmd = &with[cmd_idx + 1];
        assert!(cmd.contains("& '/r/Invoke-EntraChecksRun.ps1'"));
        assert!(cmd.contains("-TenantName 'Contoso'"));
        assert!(cmd.contains("-Modules @('Core','SecureScore')"));
        assert!(cmd.contains("-AuthMethod 'Skip'"));
        assert!(cmd.contains("-EmitEvents"));
        assert!(cmd.contains("-SkipAuthentication"));
        assert!(cmd.contains("*>&1"), "must merge PS streams to stdout");

        let without = core_args(
            "/r/c.ps1",
            "T",
            "/o",
            &["Core".to_string()],
            "DeviceCode",
        );
        let without_cmd = without
            .iter()
            .skip_while(|x| *x != "-Command")
            .nth(1)
            .expect("-Command payload");
        assert!(!without_cmd.contains("-SkipAuthentication"));
        assert!(without_cmd.contains("-AuthMethod 'DeviceCode'"));
        // -EmitEvents is non-negotiable: it is how the GUI sees anything.
        assert!(without_cmd.contains("-EmitEvents"));
        assert!(without_cmd.contains("*>&1"), "must merge PS streams to stdout");
    }

    #[test]
    fn drains_complete_lines_and_keeps_partial_tail() {
        let mut pending = "alpha\r\nbeta\npartial".to_string();
        let mut lines = Vec::new();
        drain_complete_lines(&mut pending, |line| lines.push(line));
        assert_eq!(lines, vec!["alpha", "beta"]);
        assert_eq!(pending, "partial");
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
        // -Command form (with *>&1 stream merge), bypass MotW.
        assert!(full.contains(&"-ExecutionPolicy".to_string()));
        assert!(full.contains(&"Bypass".to_string()));
        let cmd_idx = full
            .iter()
            .position(|x| x == "-Command")
            .expect("-Command present");
        let cmd = &full[cmd_idx + 1];
        assert!(cmd.contains("/r/Install-Prerequisites.ps1"));
        assert!(cmd.contains("*>&1"), "must merge PS streams to stdout");
        assert!(cmd.contains("-GraphOnly:$false"));

        let graph_only = install_prereqs_args(
            Path::new("/r/Install-Prerequisites.ps1"),
            false,
        );
        let g_cmd = graph_only
            .iter()
            .find(|s| s.contains("-GraphOnly"))
            .expect("graph-only present");
        assert!(g_cmd.contains("-GraphOnly:$true"));
    }

    #[test]
    fn install_prereqs_args_escapes_single_quotes_in_path() {
        // A path with a single quote shouldn't break the -Command
        // string. PS escape rule for single-quoted strings is `''`.
        let args = install_prereqs_args(
            Path::new("/some/dir/with'quote/Install-Prerequisites.ps1"),
            true,
        );
        let cmd = args
            .iter()
            .find(|s| s.contains("Install-Prerequisites.ps1"))
            .unwrap();
        assert!(cmd.contains("with''quote"), "single quotes must be doubled");
    }

    #[test]
    fn extracts_device_code_from_sdk_messages() {
        // Two real-world phrasings Microsoft.Graph has used; both
        // route through `code <TOKEN>`. The scraper must grab the
        // token and ignore everything after whitespace/punctuation.
        assert_eq!(
            extract_device_code(
                "To sign in, use a web browser to open the page \
                 https://microsoft.com/devicelogin and enter the code \
                 ABCD-1234 to authenticate."
            ),
            Some("ABCD-1234".to_string())
        );
        assert_eq!(
            extract_device_code(
                "To sign in, open https://microsoft.com/devicelogin in a \
                 browser. Enter the code A1B2C3D4 to authenticate."
            ),
            Some("A1B2C3D4".to_string())
        );
    }

    #[test]
    fn extract_device_code_rejects_false_positives() {
        // English words after "code " mustn't trigger.
        assert_eq!(extract_device_code("error: bad code format"), None);
        assert_eq!(extract_device_code("status code 500 returned"), None);
        // No "code " at all.
        assert_eq!(extract_device_code("starting auth flow"), None);
        // Too short.
        assert_eq!(extract_device_code("Code ABC-12"), None);
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
