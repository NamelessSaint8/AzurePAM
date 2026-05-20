//! Elevation — Native App Phase 5.5.
//!
//! Some EntraChecks PowerShell work (local-machine reads — AD/hybrid,
//! AAD Connect data under `%ProgramData%`, certain WMI/CIM and Event-
//! Log queries) requires administrator rights at run time. The
//! Phase-5 decision (see plan §2.5 + the project memory
//! `project-elevation-required`) is **relaunch-as-admin**: the app
//! exits and re-execs itself via `ShellExecute(runas)`, which gives
//! the user the standard Windows UAC prompt once per session. Only
//! the *runtime* gets this path; the installer and the dependency-
//! install flow stay no-UAC. The rule is **no silent self-elevation**,
//! not "no elevation."
//!
//! Cross-platform: Windows hosts get real detection and the
//! re-launch; everything else gets a const-false `is_elevated` and a
//! "not on this OS" relaunch error. Tauri-free so the unit tests run
//! anywhere.

/// `true` iff the current process is running with an elevated token
/// (Windows). Other OSes always return `false` — elevation isn't a
/// thing there in the Windows sense, and the desktop app's Windows
/// gate is the only place this guards code paths.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken,
    };
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut info = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && info.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

/// Re-launch the current executable under UAC (`runas`). On success
/// the caller should exit the current process so only the elevated
/// instance remains. Returns the (best-effort) command result code or
/// an error string. **Has a real OS side effect** — invoked behind a
/// user-clicked Tauri command, never automatically.
#[cfg(windows)]
pub fn relaunch_self_as_admin() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_NORMAL;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_w: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();

    // SAFETY: pointers are valid for the duration of the call;
    // ShellExecuteW does not retain them.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_NORMAL as i32,
        )
    };
    // Per Win32: a value > 32 means success; anything ≤ 32 is an
    // error code (e.g. SE_ERR_ACCESSDENIED if the user dismissed UAC).
    if (result as isize) > 32 {
        Ok(())
    } else {
        Err(format!(
            "ShellExecute(runas) failed (code {})",
            result as isize
        ))
    }
}

#[cfg(not(windows))]
pub fn relaunch_self_as_admin() -> Result<(), String> {
    Err("Relaunch-as-administrator is a Windows-only path.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_elevated_is_false_on_non_windows_dev_hosts() {
        // On a non-Windows dev box (macOS/Linux CI) the stub must
        // be const-false — the UI uses this to decide whether to
        // surface the elevation row at all.
        #[cfg(not(windows))]
        assert!(!is_elevated());
        // On Windows it can be true or false depending on how the
        // tests were launched; the assertion is only "doesn't panic".
        #[cfg(windows)]
        {
            let _ = is_elevated();
        }
    }

    #[test]
    fn relaunch_errors_cleanly_off_windows() {
        #[cfg(not(windows))]
        assert!(relaunch_self_as_admin().is_err());
    }
}
