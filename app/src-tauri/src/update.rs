//! Notify-only updater — Native App Phase 5.7.
//!
//! On launch, the app fetches a small static `version.json`, compares
//! its `version` field to the running build, and (only if newer)
//! emits an `update:available` event for the webview to surface a
//! dismissible banner with a download link. There is no silent apply,
//! no Tauri-updater plugin, and no update-signing keypair — this is
//! the lightest possible "your users are not stuck on stale builds"
//! mechanism and matches the Phase-5 §2.4 decision.
//!
//! Failure/offline is a **silent no-op** by design — never blocks
//! launch, never warns the user about transient network problems.

use serde::{Deserialize, Serialize};

/// Where the version manifest is fetched from. Replace at release
/// time (e.g. a GitHub Releases asset) — the placeholder URL below
/// resolves to a 404 today, which makes the launch check a clean
/// no-op until the URL is wired. No user-visible noise in the
/// meantime.
pub const DEFAULT_MANIFEST_URL: &str =
    "https://github.com/f8l124/AzurePAM/releases/latest/download/version.json";

/// The frozen v1 shape of `version.json`. Additive-only within v1:
/// unknown fields are ignored, missing optional fields default sane.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct VersionManifest {
    pub version: String,
    pub url: String,
    #[serde(default)]
    pub notes: Option<String>,
}

/// Parse `x.y.z` (optionally prefixed with `v`, optionally followed
/// by `-pre.release` / `+build.metadata`). Pure + total — never
/// panics, never errors; malformed input is just `None`.
pub fn parse_semver(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    let core = match s.find(['-', '+']) {
        Some(i) => &s[..i],
        None => s,
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    let patch = parts[2].parse().ok()?;
    Some((major, minor, patch))
}

/// `true` iff `latest` parses as a strictly higher semver than
/// `current`. Either side malformed → `false` (defensive: we never
/// claim "newer" on garbage input).
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_semver(latest), parse_semver(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Network-touching check: GET the manifest URL, parse it, and
/// return `Some(manifest)` iff it advertises a newer version than
/// `current`. Any failure (network, parse) is returned as `Err`
/// so the caller can log it; the *user* never sees it (the Tauri
/// command swallows errors quietly per the no-op-on-failure rule).
pub fn check(url: &str, current: &str) -> Result<Option<VersionManifest>, String> {
    let body = ureq::get(url)
        .timeout(std::time::Duration::from_secs(8))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    let manifest: VersionManifest =
        serde_json::from_str(&body).map_err(|e| e.to_string())?;
    if is_newer(&manifest.version, current) {
        Ok(Some(manifest))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_semvers() {
        assert_eq!(parse_semver("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver("v0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_semver(" 10.20.30 "), Some((10, 20, 30)));
    }

    #[test]
    fn strips_pre_release_and_build_metadata() {
        assert_eq!(parse_semver("1.2.3-beta.1"), Some((1, 2, 3)));
        assert_eq!(parse_semver("v1.2.3+sha.abc"), Some((1, 2, 3)));
        assert_eq!(parse_semver("1.2.3-rc.4+build.7"), Some((1, 2, 3)));
    }

    #[test]
    fn malformed_versions_are_none_not_panic() {
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("abc"), None);
        assert_eq!(parse_semver("1.2"), None);
        assert_eq!(parse_semver("1.x.3"), None);
        assert_eq!(parse_semver("1.2.3.4.5"), Some((1, 2, 3))); // tolerated
    }

    #[test]
    fn newer_is_only_strictly_greater() {
        assert!(is_newer("1.0.1", "1.0.0"));
        assert!(is_newer("1.1.0", "1.0.99"));
        assert!(is_newer("2.0.0", "1.99.99"));
        assert!(!is_newer("1.0.0", "1.0.0"), "equal is not newer");
        assert!(!is_newer("1.0.0", "1.0.1"), "older is not newer");
    }

    #[test]
    fn malformed_inputs_never_claim_newer() {
        // Defensive: garbage on either side returns false so a broken
        // manifest can't make the UI lie about an "available" update.
        assert!(!is_newer("garbage", "1.0.0"));
        assert!(!is_newer("1.0.1", "garbage"));
        assert!(!is_newer("", ""));
    }

    #[test]
    fn manifest_parses_with_and_without_notes() {
        let with: VersionManifest = serde_json::from_str(
            r#"{"version":"0.2.0","url":"https://example/dl","notes":"first patch"}"#,
        )
        .unwrap();
        assert_eq!(with.version, "0.2.0");
        assert_eq!(with.notes.as_deref(), Some("first patch"));

        let without: VersionManifest = serde_json::from_str(
            r#"{"version":"0.2.0","url":"https://example/dl"}"#,
        )
        .unwrap();
        assert_eq!(without.notes, None);

        // Unknown fields are tolerated (additive-only contract).
        let extra: VersionManifest = serde_json::from_str(
            r#"{"version":"0.2.0","url":"https://example/dl","futureThing":42}"#,
        )
        .unwrap();
        assert_eq!(extra.version, "0.2.0");
    }
}
