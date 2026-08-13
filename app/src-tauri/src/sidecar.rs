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

/// The console situation this process is in. Three states, not a bool,
/// because the middle one is the entire bug: a console that exists but
/// has no window is useless to the WAM broker AND blocks `AllocConsole`.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsoleState {
    /// A console WITH a window — classic conhost, or one we allocated
    /// earlier. Already everything we need; never touch it.
    Windowed,
    /// Attached to a console that has NO window: a pseudoconsole
    /// (ConPTY). Windows Terminal, VS Code's terminal and `cargo test`
    /// all hand us this one.
    Conpty,
    /// No console at all — the release `windows_subsystem = "windows"`
    /// build launched from Explorer.
    Detached,
}

/// Pure classifier for the state above, split out so every branch is
/// unit-testable off a real console. `GetConsoleProcessList` is the
/// discriminator rather than a probing `AllocConsole` call: it is
/// side-effect-free and unambiguous. Measured on this host:
///
/// | state              | `GetConsoleWindow()` | `GetConsoleProcessList` |
/// |--------------------|----------------------|-------------------------|
/// | Windowed (conhost) | non-zero             | >= 1                    |
/// | Conpty (`cargo test`) | 0                 | 8                       |
/// | Detached (post-`FreeConsole`) | 0          | 0                       |
#[cfg(windows)]
fn classify_console(console_hwnd: isize, attached_process_count: u32) -> ConsoleState {
    if console_hwnd != 0 {
        ConsoleState::Windowed
    } else if attached_process_count > 0 {
        ConsoleState::Conpty
    } else {
        ConsoleState::Detached
    }
}

/// Windows: make sure THIS process owns a console window, hidden.
///
/// We need one to exist because MSAL's WAM broker — which Azure.Identity
/// 1.18+ uses by default for `Connect-MgGraph` interactive sign-in —
/// resolves its parent window from the process console. Spawn the engine
/// with `CREATE_NO_WINDOW` and the child has no console at all, so the
/// broker throws "A window handle must be configured" instead of signing
/// anyone in. A console that exists but is hidden satisfies it while
/// staying just as invisible as no console at all.
///
/// # The ConPTY case, and the FreeConsole tradeoff
///
/// A bare `AllocConsole` is not enough. Under a pseudoconsole — what
/// Windows Terminal, VS Code's terminal and `cargo test` all provide —
/// the process is ALREADY attached to a console, so `AllocConsole` is
/// refused with `ERROR_ACCESS_DENIED` (5); and that console has no
/// window, so `GetConsoleWindow()` returns 0. Both probes therefore say
/// "no window available" and the old code gave up, fell back to
/// `CREATE_NO_WINDOW`, and interactive sign-in was impossible — but only
/// for users who launched the app from a terminal, which is why it
/// survived testing from Explorer. Measured on this host under
/// `cargo test`: `GetConsoleWindow()` → 0, `GetConsoleProcessList` → 8,
/// `AllocConsole` → rc 0 / `GetLastError` 5. After `FreeConsole` → rc 1
/// and the process list reports 0; the retried `AllocConsole` → rc 1
/// with a real, non-zero window handle.
///
/// So in that state we `FreeConsole()` first and then allocate. **This
/// detaches us from the launching terminal**: writes to our own
/// stdout/stderr that were going to that terminal's console go to the
/// new hidden console instead, i.e. nowhere a human will look. Judged
/// acceptable, deliberately, because:
///
/// * The app's real output is the webview Log pane, fed by the piped
///   child streams. Those pipes are explicit `Stdio::piped()` handles
///   and are completely unaffected by any of this.
/// * The entire Rust shell writes exactly one line to the terminal
///   (`[update] check failed` in `lib.rs`), plus panic messages.
/// * REDIRECTED output survives. Measured: with stdout/stderr on a pipe
///   (`cargo test`, `app.exe > log.txt`, any CI harness), `AllocConsole`
///   leaves the redirected std handles alone and the output still lands.
///   Only output going straight to an interactive terminal is lost.
/// * The release build launched from Explorer — the overwhelmingly
///   common case — never reaches this branch at all: it is `Detached`,
///   so the plain `AllocConsole` succeeds.
///
/// It is nonetheless kept strictly conditional: we only ever detach from
/// a console that has NO window, and never from one that does. A real
/// console window (classic conhost, `windows_subsystem` debug build under
/// conhost) is both usable by the broker as-is and the place a developer
/// is actually reading — the `Windowed` arm returns immediately without
/// touching it.
///
/// Known cosmetic wart, pre-existing and not worsened: `AllocConsole`
/// creates the window visible and we hide it on the next line, so a
/// hidden console can flash for a frame. Win32 offers no allocate-hidden.
#[cfg(windows)]
fn ensure_hidden_console() -> bool {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Once;

    #[link(name = "kernel32")]
    extern "system" {
        fn AllocConsole() -> i32;
        fn FreeConsole() -> i32;
        fn GetConsoleWindow() -> isize;
        fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn ShowWindow(hwnd: isize, cmd: i32) -> i32;
    }
    const SW_HIDE: i32 = 0;

    static INIT: Once = Once::new();
    static HAVE_CONSOLE: AtomicBool = AtomicBool::new(false);

    INIT.call_once(|| {
        // SAFETY: `GetConsoleProcessList` gets a real, writable buffer
        // and its true element count; the rest take no pointers. We only
        // read the returned count, never the pids, so the documented
        // "buffer too small, returns the required size" case is fine.
        unsafe {
            let mut pids = [0_u32; 8];
            let state = classify_console(
                GetConsoleWindow(),
                GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32),
            );
            if state == ConsoleState::Windowed {
                HAVE_CONSOLE.store(true, Ordering::SeqCst);
                return;
            }
            // ConPTY: drop the windowless console we are attached to, or
            // `AllocConsole` below is refused with ERROR_ACCESS_DENIED.
            // If the detach fails we have changed nothing — fall through
            // and let `AllocConsole` fail too, ending in the
            // CREATE_NO_WINDOW fallback exactly as before.
            if state == ConsoleState::Conpty {
                FreeConsole();
            }
            if AllocConsole() != 0 {
                let hwnd = GetConsoleWindow();
                if hwnd != 0 {
                    ShowWindow(hwnd, SW_HIDE);
                    HAVE_CONSOLE.store(true, Ordering::SeqCst);
                }
            }
        }
    });
    HAVE_CONSOLE.load(Ordering::SeqCst)
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The console decision, as a value: the exact creation-flag word
/// `apply_no_console_window` hands the child. `0` means "no flag" — the
/// child inherits OUR console, which is the whole point (see below).
/// `CREATE_NO_WINDOW` is only the fallback for when we could not get a
/// console at all.
///
/// Split out of `apply_no_console_window` so the contract is assertable
/// as a value as well as through a spawned child. Both levels are pinned,
/// and since `ensure_hidden_console` learned to recover a real console
/// from the ConPTY state the spawn-level pin bites here too — mutating
/// this to an unconditional `CREATE_NO_WINDOW` fails
/// `spawned_child_inherits_our_console_when_pwsh_present` under
/// `cargo test`. Measured, not assumed.
#[cfg(windows)]
fn console_creation_flags(have_console: bool) -> u32 {
    if have_console {
        0
    } else {
        CREATE_NO_WINDOW
    }
}

/// Keep the console-subsystem child (pwsh, winget) from flashing a window
/// at the user, and turn off ANSI/VT colour escapes from PowerShell so a
/// piped stderr doesn't end up littered with raw `\e[36;1m`-style bytes
/// that look like garbage in the Log pane.
///
/// On Windows the child now INHERITS our hidden console rather than being
/// given `CREATE_NO_WINDOW`. Both are equally invisible; only the former
/// leaves a window handle for the WAM broker to parent its sign-in UI to.
/// `CREATE_NO_WINDOW` remains the fallback if we cannot get a console at
/// all — an invisible child beats a stray console window.
fn apply_no_console_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Deliberately ONE statement, routed through the tested seam:
        // a future "just put CREATE_NO_WINDOW back" has to edit
        // `console_creation_flags`, where a test is watching. Passing 0
        // is identical to never calling `creation_flags` (std defaults
        // the field to 0 and ORs in CREATE_UNICODE_ENVIRONMENT itself).
        cmd.creation_flags(console_creation_flags(ensure_hidden_console()));
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
        .map(strip_extended_length_prefix)
}

/// Strip Windows' `\\?\` long-path namespace prefix from a `PathBuf`
/// so PowerShell sees a normal `C:\...` path. Tauri's
/// `app.path().resource_dir()` on Windows returns paths in
/// `\\?\C:\Users\...\core` form. We pass that to `pwsh -File`,
/// `$PSScriptRoot` ends up prefixed too, and PowerShell's
/// `Test-Path` against the FileSystem provider becomes inconsistent
/// with the prefix — returns `False` for files that genuinely exist.
/// That made every module branch in `Invoke-ModuleAssessment` silently
/// no-op (`if (Test-Path $modulePath) { ... }`) and the run completed
/// with 0 findings in 0 minutes. No-op off-Windows.
pub fn strip_extended_length_prefix(p: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let s = p.to_string_lossy();
        // `\\?\UNC\server\share\...` is a separate UNC long-path
        // form — strip the `\\?\UNC\` and put `\\` back so it remains
        // a valid UNC path.
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
    }
    p
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

// Two flat in-concert params rather than a bag struct: they mirror the
// engine switches (`-OpenAccessReviewCampaign` / `-AccessReviewDirectory`)
// one-for-one, which is what makes a call site readable.
#[allow(clippy::too_many_arguments)]
pub fn core_args(
    core_script: &str,
    tenant: &str,
    output_dir: &str,
    modules: &[String],
    auth_method: &str,
    deep_dives: &[String],
    open_access_review: bool,
    campaign_dir: Option<&str>,
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
    if !deep_dives.is_empty() {
        let dd_literal = format!(
            "@({})",
            deep_dives
                .iter()
                .map(|d| ps_single_quote(d))
                .collect::<Vec<_>>()
                .join(",")
        );
        command.push_str(&format!(
            " -HtmlReportSet 'CockpitAndDeepDives' -HtmlDeepDiveDomains {dd_literal}"
        ));
    }
    if auth_method == "Skip" {
        command.push_str(" -SkipAuthentication");
    }
    // "In concert" (plan §1): the normal assessment additionally opens
    // an access-review campaign, reusing the privileged roster the run
    // already built.
    if open_access_review {
        command.push_str(" -OpenAccessReviewCampaign");
    }
    // The durable folder rides along whenever the user has one set, NOT
    // only with the checkbox: the engine also starts the phase when
    // config `AccessReview.Enabled` is true, and without the override
    // that campaign would silently land in the config default instead of
    // the folder the panel shows (plan §3.1 — never the run's TEMP dir).
    if let Some(dir) = campaign_dir.filter(|d| !d.is_empty()) {
        command.push_str(&format!(
            " -AccessReviewDirectory {}",
            ps_single_quote(dir)
        ));
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

/// Sibling of `core_args` for a campaign-only run (plan §4.2): the
/// engine's `-Mode AccessReview` path — prereqs, auth, and the
/// `AccessReview` phase, with no Core/Modules/unified report.
///
/// `output_dir` stays the run's working output (that is where the
/// cancel sentinel lives); `campaign_dir` is the durable, user-chosen
/// campaign folder and is deliberately never TEMP. `campaign_id` is a
/// campaign *folder name*, required by Close/Report and empty for
/// Open (which mints its own). Pure + unit-tested.
pub fn access_review_args(
    core_script: &str,
    tenant: &str,
    output_dir: &str,
    campaign_dir: &str,
    auth_method: &str,
    action: &str,
    campaign_id: &str,
) -> Vec<String> {
    let mut command = format!(
        "& {} -TenantName {} -OutputDirectory {} -AccessReviewAction {} \
         -AccessReviewDirectory {} -AuthMethod {} -EmitEvents",
        ps_single_quote(core_script),
        ps_single_quote(tenant),
        ps_single_quote(output_dir),
        ps_single_quote(action),
        ps_single_quote(campaign_dir),
        ps_single_quote(auth_method)
    );
    if !campaign_id.is_empty() {
        command.push_str(&format!(" -CampaignId {}", ps_single_quote(campaign_id)));
    }
    if auth_method == "Skip" {
        command.push_str(" -SkipAuthentication");
    }
    command.push_str(" *>&1");
    vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
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

    /// THE regression pin for console inheritance, and the one that fails on
    /// every Windows host. DO NOT DELETE AS NOISE — it is what stands between
    /// a future "just put `CREATE_NO_WINDOW` back, it's tidier" refactor and a
    /// GUI where interactive sign-in is impossible. A child spawned with
    /// `CREATE_NO_WINDOW` gets no console at all; MSAL's WAM broker
    /// (Azure.Identity 1.18+, what `Connect-MgGraph` interactive uses)
    /// resolves its parent window from the process console, so it throws
    /// "A window handle must be configured" and nobody can sign in — while
    /// every other test stays green.
    ///
    /// It asserts the DECISION as a value; `conpty_host_acquires_a_real_console`
    /// and `spawned_child_inherits_our_console_when_pwsh_present` pin the two
    /// halves either side of it (that the ConPTY state reaches `true` at all,
    /// and that a real child is actually spawned that way).
    ///
    /// NOT covered, and no green tick here should be read as covering it:
    /// * That `apply_no_console_window` actually calls this. std exposes no
    ///   way to read a `Command`'s creation flags back, so the guard is
    ///   structural: that call site is a single statement routed through this
    ///   function. The spawn-level test is what observes the outcome.
    /// * The `Detached` arm of `ensure_hidden_console` (plain `AllocConsole`
    ///   with no console at all), which needs a process that starts without
    ///   one — a release `windows_subsystem = "windows"` build launched from
    ///   Explorer, never a cargo test binary, which is always on a ConPTY.
    ///   `classify_console` covers the classification half of it.
    #[cfg(windows)]
    #[test]
    fn console_flags_drop_create_no_window_when_we_have_one() {
        assert_eq!(
            console_creation_flags(true),
            0,
            "a console we own must be INHERITED by the child: passing \
             CREATE_NO_WINDOW when we have a console leaves the WAM broker \
             with no window to parent its sign-in UI to, and interactive \
             sign-in becomes impossible"
        );
        assert_eq!(
            console_creation_flags(false),
            CREATE_NO_WINDOW,
            "with no console to inherit the child must still be windowless — \
             dropping the fallback flashes a stray console at the user"
        );
        assert_eq!(
            CREATE_NO_WINDOW, 0x0800_0000,
            "wrong constant = a flag that does not suppress the window"
        );
    }

    /// The three console states, by the numbers actually measured on this
    /// host (see `classify_console`). The middle row is the whole bug: a
    /// console with no window looks identical to "no console" through
    /// `GetConsoleWindow()` alone, and treating it as such is what left
    /// terminal-launched users unable to sign in.
    #[cfg(windows)]
    #[test]
    fn classify_console_separates_conpty_from_no_console_at_all() {
        assert_eq!(classify_console(33363174, 1), ConsoleState::Windowed);
        assert_eq!(
            classify_console(0, 8),
            ConsoleState::Conpty,
            "attached (process list non-empty) but windowless is a ConPTY — \
             it must NOT be read as 'no console', because the console has to \
             be released before a real one can be allocated"
        );
        assert_eq!(
            classify_console(0, 0),
            ConsoleState::Detached,
            "nothing attached — plain AllocConsole, nothing to release"
        );
        // A windowed console is windowed however many processes share it,
        // and is never released.
        assert_eq!(classify_console(42, 0), ConsoleState::Windowed);
    }

    /// The pin for the acquisition fix, and the reason the flag test above
    /// is no longer the only observable level. `cargo test` runs under a
    /// ConPTY (measured: `GetConsoleWindow()` → 0, `GetConsoleProcessList`
    /// → 8, `AllocConsole` → ERROR_ACCESS_DENIED), i.e. exactly the state
    /// that used to return false and fall back to `CREATE_NO_WINDOW`.
    ///
    /// Deleting the `FreeConsole` recovery makes this fail here and only
    /// here — the flag test still passes (its inputs are literals) and so
    /// does the spawn test (a false decision and a windowless child agree
    /// with each other). Windows-only by construction; there is no
    /// non-Windows console to acquire.
    #[cfg(windows)]
    #[test]
    fn conpty_host_acquires_a_real_console() {
        assert!(
            ensure_hidden_console(),
            "on Windows we must always end up owning a console: under a \
             ConPTY (Windows Terminal, VS Code, cargo test) that needs \
             FreeConsole before AllocConsole, and without it the app falls \
             back to CREATE_NO_WINDOW and interactive sign-in is impossible \
             for anyone who launched the app from a terminal"
        );
        assert_eq!(
            console_creation_flags(ensure_hidden_console()),
            0,
            "and the flags computed for THIS state must hand the child our \
             console, not CREATE_NO_WINDOW"
        );
    }

    /// Companion to the flag test above, kept for the coverage it adds where
    /// the flag test cannot reach: it observes a REAL child, so it also
    /// proves `apply_no_console_window` is on the spawn path at all.
    ///
    /// It now catches the headline regression on THIS host too, which it could
    /// not before: once `ensure_hidden_console` recovers a real console from
    /// the ConPTY state, `have_console` is true under `cargo test`, so an
    /// unconditional `CREATE_NO_WINDOW` gives the child its own console and the
    /// `INHERITED`/`SEPARATE` assertion fails. Mutation-tested, not assumed.
    /// It catches the opposite slip as well — dropping the fallback, so a child
    /// silently inherits a console we never meant to hand it. And with a real
    /// window handle now present, the check below additionally demands the child
    /// see OUR window: the handle the broker actually asks for.
    ///
    /// Inheritance is probed via the child's console *process list* rather
    /// than its window handle, since that is the signal that survives a
    /// windowless host.
    ///
    /// Skips cleanly where pwsh is absent, like the probe tests above.
    #[cfg(windows)]
    #[test]
    fn spawned_child_inherits_our_console_when_pwsh_present() {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetConsoleWindow() -> isize;
        }
        let loc = match discover_pwsh() {
            Ok(l) => l,
            Err(_) => return,
        };
        // Exactly the call `apply_no_console_window` gates on: is there a
        // console for the child to inherit in the first place?
        let have_console = ensure_hidden_console();
        // SAFETY: plain Win32 call with no pointer arguments.
        let parent_hwnd = unsafe { GetConsoleWindow() };

        // The child reports its own console window handle plus whether OUR
        // pid sits on its console's process list — sharing a console is the
        // signal that survives a windowless ConPTY host.
        let script = format!(
            "Add-Type -Namespace N -Name K -MemberDefinition \
             '[DllImport(\"kernel32.dll\")] public static extern \
             System.IntPtr GetConsoleWindow(); \
             [DllImport(\"kernel32.dll\")] public static extern \
             uint GetConsoleProcessList(uint[] l, uint c);'; \
             $b = New-Object uint[] 64; \
             $n = [N.K]::GetConsoleProcessList($b, 64); \
             $v = if ($n -gt 0 -and ($b[0..($n - 1)] -contains {})) \
             {{ 'INHERITED' }} else {{ 'SEPARATE' }}; \
             'hwnd=' + [N.K]::GetConsoleWindow() + ' ' + $v",
            std::process::id()
        );
        let mut lines = Vec::new();
        let code = spawn_streaming(
            &loc.path,
            &["-NoProfile", "-NonInteractive", "-Command", script.as_str()],
            |l| lines.push(l.to_string()),
            |_| {},
        )
        .expect("console probe should spawn once pwsh is discovered");
        assert_eq!(code, 0, "console probe must exit 0, got {lines:?}");
        let report = lines
            .iter()
            .find(|l| l.contains("hwnd="))
            .unwrap_or_else(|| panic!("child never reported its console: {lines:?}"));

        assert_eq!(
            report.contains("INHERITED"),
            have_console,
            "the child must share OUR console whenever we have one (and only \
             fall back to its own when we do not): reintroducing \
             CREATE_NO_WINDOW here leaves the WAM broker with no window to \
             parent to and kills interactive sign-in. have_console={have_console}, \
             child reported {report:?}"
        );
        if have_console && parent_hwnd != 0 {
            // A real console window exists — then it must be OUR window the
            // child sees, because that handle is what the broker asks for.
            assert!(
                report.contains(&format!("hwnd={parent_hwnd} ")),
                "child must see our console window {parent_hwnd}, got {report:?}"
            );
        }
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
            &[],
            false,
            None,
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
        // No deep-dives selected -> no HtmlReportSet / no
        // HtmlDeepDiveDomains overrides. Cockpit is the default in
        // Start-EntraChecks.ps1 and we want that path unaltered.
        assert!(!cmd.contains("-HtmlReportSet"));
        assert!(!cmd.contains("-HtmlDeepDiveDomains"));
        // In-concert not requested -> the campaign switches must be
        // absent, or every plain run would open a campaign.
        assert!(!cmd.contains("-OpenAccessReviewCampaign"));
        assert!(!cmd.contains("-AccessReviewDirectory"));

        let without = core_args(
            "/r/c.ps1",
            "T",
            "/o",
            &["Core".to_string()],
            "DeviceCode",
            &[],
            false,
            None,
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
    fn core_args_includes_deep_dive_switches_when_selected() {
        let args = core_args(
            "/r/c.ps1",
            "T",
            "/o",
            &["Core".to_string()],
            "DeviceCode",
            &[
                "SecureScore".to_string(),
                "DefenderCompliance".to_string(),
            ],
            false,
            None,
        );
        let cmd = args
            .iter()
            .skip_while(|x| *x != "-Command")
            .nth(1)
            .expect("-Command payload");
        // Engine flips to CockpitAndDeepDives whenever the GUI requested
        // at least one deep dive. The cockpit still renders; the named
        // deep dives render alongside as separate HTML files.
        assert!(cmd.contains("-HtmlReportSet 'CockpitAndDeepDives'"));
        assert!(cmd.contains("-HtmlDeepDiveDomains @('SecureScore','DefenderCompliance')"));
    }

    #[test]
    fn core_args_in_concert_flags_only_when_requested() {
        // The checkbox is opt-in per run: the switch may only appear
        // when the webview actually asked for it. The folder is NOT
        // tied to the switch — a config-enabled campaign still has to
        // land in the folder the panel shows.
        let on = core_args(
            "/r/c.ps1",
            "T",
            "/o",
            &["Core".to_string()],
            "DeviceCode",
            &[],
            true,
            Some("/campaigns"),
        );
        let on_cmd = on
            .iter()
            .skip_while(|x| *x != "-Command")
            .nth(1)
            .expect("-Command payload");
        assert!(on_cmd.contains("-OpenAccessReviewCampaign"));
        assert!(on_cmd.contains("-AccessReviewDirectory '/campaigns'"));
        assert!(on_cmd.ends_with("*>&1"), "redirection stays last");

        // Switch on, no folder -> engine falls back to its configured
        // AccessReview.OutputDirectory rather than being handed ''.
        let no_dir = core_args(
            "/r/c.ps1",
            "T",
            "/o",
            &["Core".to_string()],
            "DeviceCode",
            &[],
            true,
            Some(""),
        );
        let no_dir_cmd = no_dir
            .iter()
            .skip_while(|x| *x != "-Command")
            .nth(1)
            .expect("-Command payload");
        assert!(no_dir_cmd.contains("-OpenAccessReviewCampaign"));
        assert!(!no_dir_cmd.contains("-AccessReviewDirectory"));

        // Folder remembered but checkbox off -> no switch, but the
        // folder still travels: `AccessReview.Enabled` in config starts
        // the phase without the checkbox, and it must use this folder.
        let off = core_args(
            "/r/c.ps1",
            "T",
            "/o",
            &["Core".to_string()],
            "DeviceCode",
            &[],
            false,
            Some("/campaigns"),
        );
        let off_cmd = off
            .iter()
            .skip_while(|x| *x != "-Command")
            .nth(1)
            .expect("-Command payload");
        assert!(!off_cmd.contains("-OpenAccessReviewCampaign"));
        assert!(off_cmd.contains("-AccessReviewDirectory '/campaigns'"));

        // Nothing set at all -> neither appears.
        let none = core_args(
            "/r/c.ps1",
            "T",
            "/o",
            &["Core".to_string()],
            "DeviceCode",
            &[],
            false,
            None,
        );
        let none_cmd = none
            .iter()
            .skip_while(|x| *x != "-Command")
            .nth(1)
            .expect("-Command payload");
        assert!(!none_cmd.contains("-OpenAccessReviewCampaign"));
        assert!(!none_cmd.contains("-AccessReviewDirectory"));
    }

    #[test]
    fn access_review_args_shape_per_action() {
        // Open mints its own campaign id, so -CampaignId must be
        // absent — handing the engine an empty one would fail its
        // Close/Report lookup for no reason.
        let open = access_review_args(
            "/r/Invoke-EntraChecksRun.ps1",
            "Contoso",
            "/o",
            "/campaigns",
            "DeviceCode",
            "Open",
            "",
        );
        assert!(open.contains(&"-ExecutionPolicy".to_string()));
        assert!(open.contains(&"Bypass".to_string()));
        let open_cmd = open
            .iter()
            .skip_while(|x| *x != "-Command")
            .nth(1)
            .expect("-Command payload");
        // Exact shape: this string is the contract between the shell
        // and the engine's -Mode AccessReview param block. -EmitEvents
        // is how the GUI sees anything at all, and *>&1 must stay the
        // final token or PowerShell parses the rest as redirected.
        assert_eq!(
            open_cmd,
            "& '/r/Invoke-EntraChecksRun.ps1' -TenantName 'Contoso' \
             -OutputDirectory '/o' -AccessReviewAction 'Open' \
             -AccessReviewDirectory '/campaigns' -AuthMethod 'DeviceCode' \
             -EmitEvents *>&1"
        );
        assert!(!open_cmd.contains("-CampaignId"));
        assert!(!open_cmd.contains("-SkipAuthentication"));
        // A campaign-only run never carries assessment switches.
        assert!(!open_cmd.contains("-Modules"));

        for action in ["Close", "Report"] {
            let args = access_review_args(
                "/r/c.ps1",
                "T",
                "/o",
                "/campaigns",
                "DeviceCode",
                action,
                "2026-Q3-20260803-141500",
            );
            let cmd = args
                .iter()
                .skip_while(|x| *x != "-Command")
                .nth(1)
                .expect("-Command payload");
            assert!(cmd.contains(&format!("-AccessReviewAction '{action}'")));
            // The folder NAME, not a path — the engine joins it onto
            // -AccessReviewDirectory itself.
            assert!(cmd.contains("-CampaignId '2026-Q3-20260803-141500'"));
        }
    }

    #[test]
    fn access_review_args_escapes_quotes_and_toggles_skip_auth() {
        // A real Documents path can contain an apostrophe (O'Brien),
        // which would close the PS string literal early and turn the
        // rest of the path into commands. Doubling is the fix, and
        // "use my existing session" is the fast path for Close/Report.
        let args = access_review_args(
            "/r/c.ps1",
            "O'Brien Ltd",
            "/o",
            r"C:\Users\O'Brien\Documents\EntraChecks\AccessReview",
            "Skip",
            "Report",
            "2026-Q3'-1",
        );
        let cmd = args
            .iter()
            .skip_while(|x| *x != "-Command")
            .nth(1)
            .expect("-Command payload");
        assert!(cmd.contains("-TenantName 'O''Brien Ltd'"));
        assert!(cmd.contains(
            r"-AccessReviewDirectory 'C:\Users\O''Brien\Documents\EntraChecks\AccessReview'"
        ));
        assert!(cmd.contains("-CampaignId '2026-Q3''-1'"));
        assert!(cmd.contains("-SkipAuthentication"));
        assert!(cmd.ends_with("*>&1"), "redirection stays last");
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
    fn strips_extended_length_prefix() {
        // On Windows this is the active case; the cfg-gated impl
        // strips both the plain and UNC variants. Off-Windows the
        // helper is a no-op so the input round-trips.
        #[cfg(windows)]
        {
            assert_eq!(
                strip_extended_length_prefix(PathBuf::from(r"\\?\C:\Users\admin\AppData\Local\EntraChecks\core")),
                PathBuf::from(r"C:\Users\admin\AppData\Local\EntraChecks\core")
            );
            assert_eq!(
                strip_extended_length_prefix(PathBuf::from(r"\\?\UNC\server\share\app")),
                PathBuf::from(r"\\server\share\app")
            );
            assert_eq!(
                strip_extended_length_prefix(PathBuf::from(r"C:\already\clean")),
                PathBuf::from(r"C:\already\clean")
            );
        }
        // Off-Windows: never strips. Path-string comparison sidesteps
        // OS-separator differences in the literal.
        #[cfg(not(windows))]
        {
            let input = PathBuf::from("/tmp/foo");
            assert_eq!(strip_extended_length_prefix(input.clone()), input);
        }
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
