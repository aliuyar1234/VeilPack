use std::collections::BTreeMap;
use std::process::ExitCode;

use crate::evidence_io::{
    ArtifactRunResult, PackManifestJsonV1, RunManifestJsonV1, RunTotals, TOOL_VERSION,
    write_artifacts_evidence, write_quarantine_index,
};
use crate::fs_safety::write_json_atomic;
use crate::logging::{log_error, log_info};
use crate::run_bootstrap::{RunContext, RunPaths};
use crate::{EXIT_FATAL, EXIT_OK, EXIT_QUARANTINED, PACK_SCHEMA_VERSION};

pub(crate) struct FinalizeSummary {
    pub(crate) artifacts_quarantined: u64,
}

pub(crate) fn finalize_run(
    context: &RunContext,
    paths: &RunPaths,
    artifacts: &[crate::input_inventory::DiscoveredArtifact],
    ledger: &veil_evidence::Ledger,
    proof_tokens_by_artifact: &BTreeMap<veil_domain::ArtifactId, Vec<String>>,
) -> Result<FinalizeSummary, ExitCode> {
    let mut results = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let summary = match ledger.artifact_summary(&artifact.sort_key.artifact_id) {
            Ok(Some(s)) => s,
            Ok(None) => {
                log_error(
                    context.log_ctx(),
                    "ledger_missing_artifact_record",
                    "INTERNAL_ERROR",
                    Some("ledger missing artifact record (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }
            Err(_) => {
                log_error(
                    context.log_ctx(),
                    "ledger_read_failed",
                    "INTERNAL_ERROR",
                    Some("ledger read failed (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }
        };

        results.push(ArtifactRunResult {
            sort_key: artifact.sort_key,
            size_bytes: artifact.size_bytes,
            artifact_type: artifact.artifact_type.clone(),
            state: summary.state,
            quarantine_reason_code: summary.quarantine_reason_code,
            output_id: summary.output_id,
            proof_tokens: proof_tokens_by_artifact
                .get(&artifact.sort_key.artifact_id)
                .cloned()
                .unwrap_or_default(),
        });
    }

    let mut quarantine_reason_counts = BTreeMap::<String, u64>::new();
    let mut artifacts_verified = 0_u64;
    let mut artifacts_quarantined = 0_u64;
    for result in &results {
        match result.state {
            veil_domain::ArtifactState::Verified => artifacts_verified += 1,
            veil_domain::ArtifactState::Quarantined => {
                artifacts_quarantined += 1;
                let Some(code) = result.quarantine_reason_code.as_ref() else {
                    log_error(
                        context.log_ctx(),
                        "quarantine_reason_missing",
                        "INTERNAL_ERROR",
                        Some("quarantined artifact missing reason code (redacted)"),
                    );
                    return Err(ExitCode::from(EXIT_FATAL));
                };
                *quarantine_reason_counts.entry(code.clone()).or_insert(0) += 1;
            }
            _ => {}
        }
    }

    if let Err(msg) = write_quarantine_index(&paths.quarantine_index_path, &results) {
        log_error(
            context.log_ctx(),
            "write_quarantine_index_failed",
            "INTERNAL_ERROR",
            Some(msg.as_str()),
        );
        return Err(ExitCode::from(EXIT_FATAL));
    }

    if std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_quarantine_index_write") {
        log_error(
            context.log_ctx(),
            "failpoint_triggered",
            "INTERNAL_ERROR",
            Some("failpoint triggered (redacted)"),
        );
        return Err(ExitCode::from(EXIT_FATAL));
    }

    if let Err(msg) = write_artifacts_evidence(&paths.artifacts_ndjson_path, &results) {
        log_error(
            context.log_ctx(),
            "write_artifacts_evidence_failed",
            "INTERNAL_ERROR",
            Some(msg.as_str()),
        );
        return Err(ExitCode::from(EXIT_FATAL));
    }

    if std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_artifacts_evidence_write") {
        log_error(
            context.log_ctx(),
            "failpoint_triggered",
            "INTERNAL_ERROR",
            Some("failpoint triggered (redacted)"),
        );
        return Err(ExitCode::from(EXIT_FATAL));
    }

    let run_manifest_path = paths.evidence_dir.join("run_manifest.json");
    let run_manifest = RunManifestJsonV1 {
        tool_version: TOOL_VERSION,
        run_id: context.run_id_str().to_string(),
        policy_id: context.policy_id_str().to_string(),
        input_corpus_id: context.input_corpus_id_str().to_string(),
        totals: RunTotals {
            artifacts_discovered: artifacts.len() as u64,
            artifacts_verified,
            artifacts_quarantined,
        },
        quarantine_reason_counts,
        tokenization_enabled: context.parsed.enable_tokenization,
        tokenization_scope: context.tokenization_scope(),
        proof_scope: context.proof_scope,
        proof_key_commitment: context.proof_key_commitment.clone(),
        quarantine_copy_enabled: context.parsed.quarantine_copy,
    };
    if write_json_atomic(&run_manifest_path, &run_manifest).is_err() {
        log_error(
            context.log_ctx(),
            "write_run_manifest_failed",
            "INTERNAL_ERROR",
            Some("could not write run_manifest.json (redacted)"),
        );
        return Err(ExitCode::from(EXIT_FATAL));
    }

    let pack_manifest_path = paths.output.join("pack_manifest.json");
    let pack_manifest = PackManifestJsonV1 {
        pack_schema_version: PACK_SCHEMA_VERSION,
        tool_version: TOOL_VERSION,
        run_id: context.run_id_str().to_string(),
        policy_id: context.policy_id_str().to_string(),
        input_corpus_id: context.input_corpus_id_str().to_string(),
        tokenization_enabled: context.parsed.enable_tokenization,
        tokenization_scope: context.tokenization_scope(),
        quarantine_copy_enabled: context.parsed.quarantine_copy,
        ledger_schema_version: veil_evidence::LEDGER_SCHEMA_VERSION,
    };
    if write_json_atomic(&pack_manifest_path, &pack_manifest).is_err() {
        log_error(
            context.log_ctx(),
            "write_pack_manifest_failed",
            "INTERNAL_ERROR",
            Some("could not write pack_manifest.json (redacted)"),
        );
        return Err(ExitCode::from(EXIT_FATAL));
    }

    let mut run_complete_counters = BTreeMap::<&str, u64>::new();
    run_complete_counters.insert("artifacts_discovered", artifacts.len() as u64);
    run_complete_counters.insert("artifacts_verified", artifacts_verified);
    run_complete_counters.insert("artifacts_quarantined", artifacts_quarantined);
    log_info(
        context.log_ctx(),
        "run_completed",
        Some(run_complete_counters),
    );

    let _ = std::fs::remove_file(&paths.marker_path);

    Ok(FinalizeSummary {
        artifacts_quarantined,
    })
}

pub(crate) fn exit_code_for_summary(summary: &FinalizeSummary) -> ExitCode {
    if summary.artifacts_quarantined > 0 {
        ExitCode::from(EXIT_QUARANTINED)
    } else {
        ExitCode::from(EXIT_OK)
    }
}
