//! Engine⇄UI contract parser — Native App Phase 4, step 4.3.
//!
//! Turns one line of the core's stdout into a typed `AppEvent`. This
//! is the CI-able heart of Phase 4: pure, no Tauri, no process, no
//! filesystem. The discipline holds — Rust *parses* the contract, it
//! never re-implements assessment logic.
//!
//! Robustness posture (master plan §5):
//!   - Only lines that are a JSON object carrying both `schemaVersion`
//!     and `type` are events; anything else (decorative `Write-Host`
//!     that Phase 1 §9 still allows) is `Ignored`, not an error.
//!   - An unrecognised `type` → `AppEvent::Unknown` (forward-compat;
//!     the contract is additive-only within a major version).
//!   - A `schemaVersion` major newer than we understand is surfaced
//!     (so the UI can warn "app older than engine") but known event
//!     types still parse — additive-only guarantees that is safe.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The contract major this build understands.
pub const SUPPORTED_SCHEMA_MAJOR: u32 = 1;

/// `"1.0"` → `1`, `"2.3"` → `2`. `None` if unparseable.
pub fn schema_major(schema_version: &str) -> Option<u32> {
    schema_version.split('.').next()?.parse().ok()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PhaseStatus {
    Ok,
    Skipped,
    Failed,
}

impl PhaseStatus {
    fn parse(s: &str) -> Self {
        match s {
            "skipped" => PhaseStatus::Skipped,
            "failed" => PhaseStatus::Failed,
            _ => PhaseStatus::Ok,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn parse(s: &str) -> Self {
        match s {
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => LogLevel::Info,
        }
    }
}

/// Terminal run status. Ordered by *severity precedence* — Cancelled
/// outranks everything (mirrors the engine's `Get-EcfRunStatus`
/// Cancelled-first guarantee), then Failed, Partial, Succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum RunStatus {
    Succeeded,
    PartiallySucceeded,
    Failed,
    Cancelled,
}

impl RunStatus {
    pub fn parse(s: &str) -> Self {
        match s {
            "Cancelled" => RunStatus::Cancelled,
            "Failed" => RunStatus::Failed,
            "PartiallySucceeded" => RunStatus::PartiallySucceeded,
            _ => RunStatus::Succeeded,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Artifact {
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunError {
    pub code: String,
    pub message: String,
    pub fatal: bool,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunResult {
    pub status: RunStatus,
    pub started_utc: String,
    pub ended_utc: String,
    pub findings: i64,
    pub critical: i64,
    pub high: i64,
    pub artifacts: Vec<Artifact>,
    pub errors: Vec<RunError>,
}

/// One understood (or explicitly unknown) contract event.
///
/// Serializes internally-tagged on `type` (camelCase variant names)
/// so the webview can `switch (event.type)` directly — e.g.
/// `{"type":"phaseProgress","phase":"Core","current":12,...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AppEvent {
    RunStarted,
    PhaseStarted { phase: String },
    PhaseProgress { phase: String, current: i64, total: i64, message: String },
    PhaseCompleted { phase: String, status: PhaseStatus },
    Log { level: LogLevel, message: String, code: Option<String>, remediation: Option<String> },
    Warning { code: String, message: String },
    AuthInfo { method: String, message: String },
    AuthBrowser { message: String },
    AuthDeviceCode {
        #[serde(rename = "userCode")]
        user_code: Option<String>,
        #[serde(rename = "verificationUri")]
        verification_uri: String,
        capture: String,
    },
    AuthSucceeded { account: String, method: String },
    AuthFailed { code: String, message: String, remediation: Option<String> },
    RunCancelled { reason: String },
    RunResult(RunResult),
    /// A `type` this build doesn't model — ignored by the UI, never
    /// fatal (additive-only forward-compat).
    Unknown { kind: String },
}

/// Result of parsing one stdout line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedLine {
    /// Not a contract event (non-JSON, or JSON lacking the envelope).
    /// Not an error — Phase 1 §9 still allows decorative stdout.
    Ignored,
    Event {
        /// Major of the line's `schemaVersion`. `> SUPPORTED_SCHEMA_MAJOR`
        /// means the engine is newer than this app; the caller warns
        /// but still renders the known `event`.
        schema_major: u32,
        /// The envelope `runId` (present on every event). The shell
        /// captures this to build the Phase-3a cancel sentinel path
        /// `<outputDir>/.runs/<runId>.cancel`. `None` only if a line
        /// somehow omits it.
        run_id: Option<String>,
        event: AppEvent,
    },
}

/// The envelope every contract event carries; `rest` keeps the
/// type-specific fields for the second-stage map.
#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "schemaVersion")]
    schema_version: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(flatten)]
    rest: Value,
}

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|x| x.to_string())
}
fn s_or(v: &Value, key: &str) -> String {
    s(v, key).unwrap_or_default()
}
fn i(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(|x| x.as_i64()).unwrap_or(0)
}
fn b(v: &Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn map_event(kind: &str, d: &Value) -> AppEvent {
    match kind {
        "run.started" => AppEvent::RunStarted,
        "phase.started" => AppEvent::PhaseStarted { phase: s_or(d, "phase") },
        "phase.progress" => AppEvent::PhaseProgress {
            phase: s_or(d, "phase"),
            current: i(d, "current"),
            total: i(d, "total"),
            message: s_or(d, "message"),
        },
        "phase.completed" => AppEvent::PhaseCompleted {
            phase: s_or(d, "phase"),
            status: PhaseStatus::parse(&s_or(d, "status")),
        },
        "log" => AppEvent::Log {
            level: LogLevel::parse(&s_or(d, "level")),
            message: s_or(d, "message"),
            code: s(d, "code"),
            remediation: s(d, "remediation"),
        },
        "warning" => AppEvent::Warning {
            code: s(d, "code").unwrap_or_else(|| "warning".to_string()),
            message: s_or(d, "message"),
        },
        "auth.info" => AppEvent::AuthInfo {
            method: s_or(d, "method"),
            message: s_or(d, "message"),
        },
        "auth.browser" => AppEvent::AuthBrowser { message: s_or(d, "message") },
        "auth.devicecode" => AppEvent::AuthDeviceCode {
            user_code: s(d, "userCode"),
            verification_uri: s(d, "verificationUri")
                .unwrap_or_else(|| "https://microsoft.com/devicelogin".to_string()),
            capture: s(d, "capture").unwrap_or_else(|| "sdk-console".to_string()),
        },
        "auth.succeeded" => AppEvent::AuthSucceeded {
            account: s_or(d, "account"),
            method: s_or(d, "method"),
        },
        "auth.failed" => AppEvent::AuthFailed {
            code: s(d, "code").unwrap_or_else(|| "auth.failed".to_string()),
            message: s_or(d, "message"),
            remediation: s(d, "remediation"),
        },
        "run.cancelled" => AppEvent::RunCancelled {
            reason: s(d, "reason").unwrap_or_else(|| "cancel requested".to_string()),
        },
        "run.result" => AppEvent::RunResult(map_run_result(d)),
        other => AppEvent::Unknown { kind: other.to_string() },
    }
}

fn map_run_result(d: &Value) -> RunResult {
    let summary = d.get("summary").cloned().unwrap_or(Value::Null);
    let artifacts = d
        .get("artifacts")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .map(|a| Artifact {
                    kind: s_or(a, "kind"),
                    path: s_or(a, "path"),
                })
                .collect()
        })
        .unwrap_or_default();
    let errors = d
        .get("errors")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .map(|e| RunError {
                    code: s_or(e, "code"),
                    message: s_or(e, "message"),
                    fatal: b(e, "fatal"),
                    remediation: s(e, "remediation"),
                })
                .collect()
        })
        .unwrap_or_default();
    RunResult {
        status: RunStatus::parse(&s_or(d, "status")),
        started_utc: s_or(d, "startedUtc"),
        ended_utc: s_or(d, "endedUtc"),
        findings: i(&summary, "findings"),
        critical: i(&summary, "critical"),
        high: i(&summary, "high"),
        artifacts,
        errors,
    }
}

/// Parse one stdout line. Never panics; never errors — a bad line is
/// `Ignored`, an unknown type is `AppEvent::Unknown`.
pub fn parse_line(line: &str) -> ParsedLine {
    let trimmed = line.trim();
    if !trimmed.starts_with('{') {
        return ParsedLine::Ignored;
    }
    let env: Envelope = match serde_json::from_str(trimmed) {
        Ok(e) => e,
        Err(_) => return ParsedLine::Ignored,
    };
    // The envelope is the contract's identity: both fields required.
    let (Some(sv), Some(kind)) = (env.schema_version.as_deref(), env.kind.as_deref()) else {
        return ParsedLine::Ignored;
    };
    let major = match schema_major(sv) {
        Some(m) => m,
        None => return ParsedLine::Ignored,
    };
    ParsedLine::Event {
        schema_major: major,
        run_id: s(&env.rest, "runId"),
        event: map_event(kind, &env.rest),
    }
}

/// Fold a whole stream into the status the UI should show. The
/// `run.result` status is authoritative, but if a `run.cancelled`
/// was seen, Cancelled wins regardless (defensive mirror of the
/// engine's Cancelled-first precedence — a truncated stream that
/// cancelled but never delivered `run.result` still reads correctly).
pub fn terminal_status(events: &[AppEvent]) -> Option<RunStatus> {
    let mut status: Option<RunStatus> = None;
    let mut saw_cancel = false;
    for e in events {
        match e {
            AppEvent::RunCancelled { .. } => saw_cancel = true,
            AppEvent::RunResult(r) => status = Some(r.status),
            _ => {}
        }
    }
    if saw_cancel {
        return Some(RunStatus::Cancelled);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(ndjson: &str) -> Vec<AppEvent> {
        ndjson
            .lines()
            .filter_map(|l| match parse_line(l) {
                ParsedLine::Event { event, .. } => Some(event),
                ParsedLine::Ignored => None,
            })
            .collect()
    }

    #[test]
    fn schema_major_parsing() {
        assert_eq!(schema_major("1.0"), Some(1));
        assert_eq!(schema_major("2.3"), Some(2));
        assert_eq!(schema_major("nope"), None);
    }

    #[test]
    fn decorative_and_garbage_lines_are_ignored() {
        assert_eq!(parse_line("   "), ParsedLine::Ignored);
        assert_eq!(parse_line("[+] Starting assessment"), ParsedLine::Ignored);
        assert_eq!(parse_line("{ not json"), ParsedLine::Ignored);
        // JSON but missing the envelope identity.
        assert_eq!(parse_line(r#"{"hello":"world"}"#), ParsedLine::Ignored);
        assert_eq!(
            parse_line(r#"{"type":"log","message":"no schema"}"#),
            ParsedLine::Ignored
        );
    }

    #[test]
    fn unknown_type_is_forward_compatible() {
        let p = parse_line(
            r#"{"schemaVersion":"1.0","type":"some.future.event","x":1}"#,
        );
        match p {
            ParsedLine::Event { event: AppEvent::Unknown { kind }, .. } => {
                assert_eq!(kind, "some.future.event")
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn newer_schema_major_still_parses_known_events() {
        let p = parse_line(
            r#"{"schemaVersion":"2.0","type":"phase.started","phase":"Core"}"#,
        );
        match p {
            ParsedLine::Event { schema_major, event, .. } => {
                assert_eq!(schema_major, 2);
                assert!(schema_major > SUPPORTED_SCHEMA_MAJOR);
                assert_eq!(event, AppEvent::PhaseStarted { phase: "Core".into() });
            }
            _ => panic!("expected Event"),
        }
    }

    #[test]
    fn run_id_is_captured_from_the_envelope() {
        // The shell needs this to build the Phase-3a cancel sentinel
        // path; it is present on every event, not just run.started.
        match parse_line(
            r#"{"schemaVersion":"1.0","type":"phase.started","runId":"abc-123","phase":"Core"}"#,
        ) {
            ParsedLine::Event { run_id, .. } => {
                assert_eq!(run_id.as_deref(), Some("abc-123"))
            }
            _ => panic!("expected Event"),
        }
        // A line that omits runId still parses; run_id is just None.
        match parse_line(r#"{"schemaVersion":"1.0","type":"run.started"}"#) {
            ParsedLine::Event { run_id, .. } => assert_eq!(run_id, None),
            _ => panic!("expected Event"),
        }
    }

    #[test]
    fn maps_each_event_shape() {
        assert_eq!(
            events(r#"{"schemaVersion":"1.0","type":"run.started","params":{}}"#),
            vec![AppEvent::RunStarted]
        );
        assert_eq!(
            events(
                r#"{"schemaVersion":"1.0","type":"phase.progress","phase":"Core","current":12,"total":25,"message":"CA"}"#
            ),
            vec![AppEvent::PhaseProgress {
                phase: "Core".into(),
                current: 12,
                total: 25,
                message: "CA".into()
            }]
        );
        assert_eq!(
            events(
                r#"{"schemaVersion":"1.0","type":"phase.completed","phase":"Report","status":"failed"}"#
            ),
            vec![AppEvent::PhaseCompleted {
                phase: "Report".into(),
                status: PhaseStatus::Failed
            }]
        );
        assert_eq!(
            events(
                r#"{"schemaVersion":"1.0","type":"auth.devicecode","userCode":null,"verificationUri":"https://microsoft.com/devicelogin","capture":"sdk-console"}"#
            ),
            vec![AppEvent::AuthDeviceCode {
                user_code: None,
                verification_uri: "https://microsoft.com/devicelogin".into(),
                capture: "sdk-console".into()
            }]
        );
        // Write-EcfError-style log carries code + remediation.
        match &events(
            r#"{"schemaVersion":"1.0","type":"log","level":"error","message":"boom","code":"report.writeFailed","fatal":true,"remediation":"fix it"}"#,
        )[0]
        {
            AppEvent::Log { level, code, remediation, .. } => {
                assert_eq!(*level, LogLevel::Error);
                assert_eq!(code.as_deref(), Some("report.writeFailed"));
                assert_eq!(remediation.as_deref(), Some("fix it"));
            }
            e => panic!("expected Log, got {e:?}"),
        }
    }

    #[test]
    fn status_precedence_is_cancelled_first() {
        // Engine ordinal: Cancelled is the strongest.
        assert!(RunStatus::Cancelled > RunStatus::Failed);
        assert!(RunStatus::Failed > RunStatus::PartiallySucceeded);
        assert!(RunStatus::PartiallySucceeded > RunStatus::Succeeded);

        // A run.result says Failed, but a run.cancelled was seen ->
        // terminal status must be Cancelled (truncation-safe).
        let evs = vec![
            AppEvent::RunCancelled { reason: "user".into() },
            AppEvent::RunResult(RunResult {
                status: RunStatus::Failed,
                started_utc: "a".into(),
                ended_utc: "b".into(),
                findings: 0,
                critical: 0,
                high: 0,
                artifacts: vec![],
                errors: vec![],
            }),
        ];
        assert_eq!(terminal_status(&evs), Some(RunStatus::Cancelled));
        assert_eq!(terminal_status(&[]), None);
    }

    #[test]
    fn real_failed_run_fixture_parses_end_to_end() {
        // Captured from a live `Invoke-EntraChecksRun.ps1 -EmitEvents`
        // (-SkipAuthentication, no modules) — the parser is tested
        // against the engine's actual bytes, not only hand-written JSON.
        let raw = include_str!("../fixtures/real-failed-run.ndjson");
        let evs = events(raw);
        assert_eq!(evs.len(), 7, "all 7 real lines map to events");
        assert_eq!(evs[0], AppEvent::RunStarted);
        assert!(matches!(
            evs[1],
            AppEvent::PhaseStarted { ref phase } if phase == "Modules"
        ));
        match evs.last().unwrap() {
            AppEvent::RunResult(r) => {
                assert_eq!(r.status, RunStatus::Failed);
                assert_eq!(r.errors.len(), 1);
                assert_eq!(r.errors[0].code, "report.writeFailed");
                assert!(r.errors[0].fatal);
                assert!(r.artifacts.is_empty());
            }
            e => panic!("last event should be RunResult, got {e:?}"),
        }
        assert_eq!(terminal_status(&evs), Some(RunStatus::Failed));
    }

    #[test]
    fn synthetic_auth_cancel_fixture() {
        let raw = include_str!("../fixtures/synthetic-auth-cancel.ndjson");
        let evs = events(raw);
        // The decorative non-JSON line is dropped; the schema-2.0 line
        // and the future event still parse (Unknown for the latter).
        assert!(evs.iter().any(|e| matches!(
            e,
            AppEvent::AuthDeviceCode { user_code: None, .. }
        )));
        assert!(evs
            .iter()
            .any(|e| matches!(e, AppEvent::AuthSucceeded { .. })));
        assert!(evs
            .iter()
            .any(|e| matches!(e, AppEvent::Unknown { kind } if kind == "some.future.event")));
        // run.result says Cancelled and a run.cancelled was seen.
        assert_eq!(terminal_status(&evs), Some(RunStatus::Cancelled));
        // The cancelled run still carried an artifact (Phase 3a:
        // whatever exists is reported).
        let rr = evs.iter().find_map(|e| match e {
            AppEvent::RunResult(r) => Some(r),
            _ => None,
        });
        assert_eq!(rr.unwrap().artifacts.len(), 1);
    }

    #[test]
    fn schema_2_line_is_flagged_newer() {
        let raw = include_str!("../fixtures/synthetic-auth-cancel.ndjson");
        let newer = raw.lines().any(|l| matches!(
            parse_line(l),
            ParsedLine::Event { schema_major, .. } if schema_major > SUPPORTED_SCHEMA_MAJOR
        ));
        assert!(newer, "fixture includes a schemaVersion 2.0 line");
    }
}
