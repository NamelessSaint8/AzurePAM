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
