use std::collections::BTreeMap;
use std::process::ExitCode;

use crate::error::AppError;
use crate::evidence_io::{
    ArtifactRunResult, RunManifestJsonV1, RunTotals, TOOL_VERSION, write_artifacts_evidence,
    write_quarantine_index,
};
use crate::fs_safety::write_json_atomic;
use crate::run_bootstrap::{RunContext, RunPaths};
use crate::{EXIT_OK, EXIT_QUARANTINED};

pub(crate) struct FinalizeSummary {
    pub(crate) artifacts_quarantined: u64,
}

pub(crate) fn finalize_run(
    context: &RunContext,
    paths: &RunPaths,
    artifacts: &[crate::input_inventory::DiscoveredArtifact],
    ledger: &veil_evidence::Ledger,
    proof_tokens_by_artifact: &BTreeMap<veil_domain::ArtifactId, Vec<String>>,
) -> Result<FinalizeSummary, AppError> {
    let mut results = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let summary = match ledger.artifact_summary(&artifact.sort_key.artifact_id) {
            Ok(Some(s)) => s,
            Ok(None) => {
                tracing::error!(
                    event = "ledger_missing_artifact_record",
                    reason_code = "INTERNAL_ERROR",
                    "ledger missing artifact record"
                );
                return Err(AppError::Internal(
                    "ledger_missing_artifact_record".to_string(),
                ));
            }
            Err(_) => {
                tracing::error!(
                    event = "ledger_read_failed",
                    reason_code = "INTERNAL_ERROR",
                    "ledger read failed"
                );
                return Err(AppError::Internal("ledger_read_failed".to_string()));
            }
        };

        results.push(ArtifactRunResult {
            sort_key: artifact.sort_key,
            size_bytes: artifact.size_bytes,
            artifact_type: artifact.artifact_type_wire().to_string(),
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
                    tracing::error!(
                        event = "quarantine_reason_missing",
                        reason_code = "INTERNAL_ERROR",
                        "quarantined artifact missing reason code"
                    );
                    return Err(AppError::Internal("quarantine_reason_missing".to_string()));
                };
                *quarantine_reason_counts.entry(code.clone()).or_insert(0) += 1;
            }
            _ => {}
        }
    }

    if let Err(msg) = write_quarantine_index(&paths.quarantine_index_path, &results) {
        tracing::error!(
            event = "write_quarantine_index_failed",
            reason_code = "INTERNAL_ERROR",
            detail = %msg,
            "could not write quarantine index"
        );
        return Err(AppError::Internal(
            "write_quarantine_index_failed".to_string(),
        ));
    }

    if std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_quarantine_index_write") {
        tracing::error!(
            event = "failpoint_triggered",
            reason_code = "INTERNAL_ERROR",
            "failpoint triggered"
        );
        return Err(AppError::Internal("failpoint_triggered".to_string()));
    }

    if let Err(msg) = write_artifacts_evidence(&paths.artifacts_ndjson_path, &results) {
        tracing::error!(
            event = "write_artifacts_evidence_failed",
            reason_code = "INTERNAL_ERROR",
            detail = %msg,
            "could not write artifacts evidence"
        );
        return Err(AppError::Internal(
            "write_artifacts_evidence_failed".to_string(),
        ));
    }

    if std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_artifacts_evidence_write") {
        tracing::error!(
            event = "failpoint_triggered",
            reason_code = "INTERNAL_ERROR",
            "failpoint triggered"
        );
        return Err(AppError::Internal("failpoint_triggered".to_string()));
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
        tracing::error!(
            event = "write_run_manifest_failed",
            reason_code = "INTERNAL_ERROR",
            "could not write run_manifest.json"
        );
        return Err(AppError::Internal("write_run_manifest_failed".to_string()));
    }

    let pack_manifest_path = paths.output.join("pack_manifest.json");
    let pack_manifest = veil_evidence::PackManifest::current(
        TOOL_VERSION,
        context.run_id_str().to_string(),
        context.policy_id_str().to_string(),
        context.input_corpus_id_str().to_string(),
        context.parsed.enable_tokenization,
        context.tokenization_scope().map(str::to_string),
        context.parsed.quarantine_copy,
    );
    if write_json_atomic(&pack_manifest_path, &pack_manifest).is_err() {
        tracing::error!(
            event = "write_pack_manifest_failed",
            reason_code = "INTERNAL_ERROR",
            "could not write pack_manifest.json"
        );
        return Err(AppError::Internal("write_pack_manifest_failed".to_string()));
    }

    tracing::info!(
        event = "run_completed",
        artifacts_discovered = artifacts.len() as u64,
        artifacts_verified,
        artifacts_quarantined,
        "run completed"
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
