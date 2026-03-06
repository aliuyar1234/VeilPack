use std::collections::BTreeMap;

use serde::Serialize;

pub(crate) const UNKNOWN_LOG_ID: &str = "unknown";

#[derive(Debug, Clone, Copy)]
pub(crate) struct LogContext<'a> {
    pub(crate) run_id: &'a str,
    pub(crate) policy_id: &'a str,
}

impl<'a> LogContext<'a> {
    pub(crate) const fn new(run_id: &'a str, policy_id: &'a str) -> Self {
        Self { run_id, policy_id }
    }

    pub(crate) const fn unknown() -> Self {
        Self {
            run_id: UNKNOWN_LOG_ID,
            policy_id: UNKNOWN_LOG_ID,
        }
    }
}

#[derive(Debug, Serialize)]
struct LogEvent<'a> {
    level: &'a str,
    event: &'a str,
    run_id: &'a str,
    policy_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_locator_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    counters: Option<BTreeMap<&'a str, u64>>,
}

fn emit_log(event: &LogEvent<'_>) {
    if let Ok(line) = serde_json::to_string(event) {
        eprintln!("{line}");
    } else {
        eprintln!(
            "{{\"level\":\"ERROR\",\"event\":\"log_serialize_failed\",\"run_id\":\"unknown\",\"policy_id\":\"unknown\",\"reason_code\":\"INTERNAL_ERROR\"}}"
        );
    }
}

pub(crate) fn log_info(ctx: LogContext<'_>, event: &str, counters: Option<BTreeMap<&str, u64>>) {
    emit_log(&LogEvent {
        level: "INFO",
        event,
        run_id: ctx.run_id,
        policy_id: ctx.policy_id,
        artifact_id: None,
        source_locator_hash: None,
        reason_code: None,
        detail: None,
        counters,
    });
}

pub(crate) fn log_warn(ctx: LogContext<'_>, event: &str, reason_code: &str, detail: Option<&str>) {
    emit_log(&LogEvent {
        level: "WARN",
        event,
        run_id: ctx.run_id,
        policy_id: ctx.policy_id,
        artifact_id: None,
        source_locator_hash: None,
        reason_code: Some(reason_code),
        detail,
        counters: None,
    });
}

pub(crate) fn log_error(ctx: LogContext<'_>, event: &str, reason_code: &str, detail: Option<&str>) {
    emit_log(&LogEvent {
        level: "ERROR",
        event,
        run_id: ctx.run_id,
        policy_id: ctx.policy_id,
        artifact_id: None,
        source_locator_hash: None,
        reason_code: Some(reason_code),
        detail,
        counters: None,
    });
}

pub(crate) fn log_artifact_error(
    ctx: LogContext<'_>,
    event: &str,
    reason_code: &str,
    sort_key: &veil_domain::ArtifactSortKey,
    detail: Option<&str>,
) {
    let artifact_id = sort_key.artifact_id.to_string();
    let source_locator_hash = sort_key.source_locator_hash.to_string();
    emit_log(&LogEvent {
        level: "ERROR",
        event,
        run_id: ctx.run_id,
        policy_id: ctx.policy_id,
        artifact_id: Some(&artifact_id),
        source_locator_hash: Some(&source_locator_hash),
        reason_code: Some(reason_code),
        detail,
        counters: None,
    });
}
