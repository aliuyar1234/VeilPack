use std::collections::BTreeMap;
use std::time::Instant;

use veil_detect::DetectorEngine;
use veil_transform::Transformer;

use crate::error::AppError;
use crate::evidence_io::{
    collect_proof_tokens, coverage_hash_v1, sanitized_output_path_v1, write_quarantine_raw_or_fail,
};
use crate::fs_safety::{
    ensure_existing_file_safe, ensure_existing_path_components_safe, is_unsafe_reparse_point,
    sync_parent_dir, write_bytes_atomic, write_bytes_sync,
};
use crate::input_inventory::{
    DiscoveredArtifact, ReadArtifactError, read_artifact_bytes_for_processing,
};
use crate::parallel::SharedWorkerContext;
use crate::run_bootstrap::{RunContext, RunPaths};

// ArtifactProcessor owns the per-artifact fail-closed state machine.
// The invariant is simple: every discovered artifact must end the phase as
// VERIFIED, QUARANTINED, or an immediate fatal error.
pub(crate) enum ArtifactProcessStatus {
    SkippedTerminal,
    Verified,
    Quarantined,
}

pub(crate) struct ArtifactProcessor<'a> {
    pub(crate) context: &'a RunContext,
    pub(crate) paths: &'a RunPaths,
    pub(crate) ledger: &'a mut veil_evidence::Ledger,
    pub(crate) proof_tokens_by_artifact: &'a mut BTreeMap<veil_domain::ArtifactId, Vec<String>>,
    pub(crate) workdir_bytes_observed: &'a mut u64,
}

/// Owned event log payload produced by the pure pipeline. Lives in the
/// `WorkerOutcome` so the committer can replay the event verbatim
/// without re-deriving the strings on the committer thread.
#[derive(Debug, Clone)]
pub(crate) struct OwnedArtifactEvent {
    pub(crate) event: &'static str,
    pub(crate) reason_code: &'static str,
    pub(crate) detail: Option<&'static str>,
}

/// Successful pure-pipeline output.
pub(crate) struct VerifiedOutcome {
    pub(crate) extractor_id: veil_extract::ExtractorId,
    pub(crate) coverage: veil_domain::CoverageMapV1,
    pub(crate) sanitized_bytes: Vec<u8>,
    pub(crate) findings_summary: Vec<OwnedFindingsSummaryRow>,
    pub(crate) proof_tokens: Vec<String>,
    pub(crate) artifact_started: Instant,
}

/// Owned mirror of `veil_evidence::ledger::FindingsSummaryRow` so the
/// findings rows can survive across thread boundaries inside a
/// `WorkerOutcome`.
#[derive(Debug, Clone)]
pub(crate) struct OwnedFindingsSummaryRow {
    pub(crate) class_id: String,
    pub(crate) severity: String,
    pub(crate) action: String,
    pub(crate) count: u64,
}

/// Quarantine outcome carrying the original bytes (so the committer can
/// optionally write the raw quarantine copy) and an optional event log
/// the committer must emit.
pub(crate) struct QuarantinedOutcome {
    pub(crate) reason: veil_domain::QuarantineReasonCode,
    pub(crate) raw_bytes: Option<Vec<u8>>,
    pub(crate) event: Option<OwnedArtifactEvent>,
}

/// Result of running the pure pipeline on one artifact in a worker
/// thread. Carries no references back into the run context so it can
/// safely cross a `crossbeam-channel::Sender`.
pub(crate) enum WorkerOutcome {
    Verified(VerifiedOutcome),
    Quarantined(QuarantinedOutcome),
    /// The worker thread panicked while running the pure pipeline. The
    /// committer surfaces this as a fatal `worker_panic` event.
    Panicked,
}

impl ArtifactProcessor<'_> {
    /// Apply a `WorkerOutcome` produced elsewhere (e.g. by a worker
    /// thread). All ledger writes for one artifact happen inside a
    /// single `LedgerTransaction` so the artifact's state transitions
    /// are atomic, and so the FS dest write commits before the
    /// VERIFIED ledger transition.
    pub(crate) fn commit(
        &mut self,
        artifact: &DiscoveredArtifact,
        outcome: WorkerOutcome,
    ) -> Result<ArtifactProcessStatus, AppError> {
        // First, do the upsert + terminal-skip read on the live ledger.
        // Resume runs land here for already-VERIFIED/QUARANTINED rows.
        let state = self.upsert_discovered_and_get_state(artifact)?;
        if state.is_terminal() {
            return Ok(ArtifactProcessStatus::SkippedTerminal);
        }

        // Reset any prior in-memory proof tokens for this artifact.
        // The detect path repopulates this on the verified path; on the
        // quarantine path we never re-add.
        self.proof_tokens_by_artifact
            .remove(&artifact.sort_key.artifact_id);

        match outcome {
            WorkerOutcome::Panicked => {
                tracing::error!(
                    event = "worker_panic",
                    reason_code = "INTERNAL_ERROR",
                    artifact_id = %artifact.sort_key.artifact_id,
                    source_locator_hash = %artifact.sort_key.source_locator_hash,
                    "worker thread panicked"
                );
                Err(AppError::Internal("worker_panic".to_string()))
            }
            WorkerOutcome::Quarantined(q) => {
                self.commit_quarantine(artifact, q)?;
                Ok(ArtifactProcessStatus::Quarantined)
            }
            WorkerOutcome::Verified(v) => {
                if self.commit_verified(artifact, v)? {
                    Ok(ArtifactProcessStatus::Verified)
                } else {
                    Ok(ArtifactProcessStatus::Quarantined)
                }
            }
        }
    }

    fn log_ledger_write_failed(&self) {
        tracing::error!(
            event = "ledger_write_failed",
            reason_code = "INTERNAL_ERROR",
            "ledger write failed"
        );
    }

    fn upsert_discovered_and_get_state(
        &mut self,
        artifact: &DiscoveredArtifact,
    ) -> Result<veil_domain::ArtifactState, AppError> {
        if self
            .ledger
            .upsert_discovered(
                &artifact.sort_key.artifact_id,
                &artifact.sort_key.source_locator_hash,
                artifact.size_bytes,
                artifact.artifact_type_wire(),
            )
            .is_err()
        {
            self.log_ledger_write_failed();
            return Err(AppError::Internal("ledger_write_failed".to_string()));
        }

        match self.ledger.artifact_summary(&artifact.sort_key.artifact_id) {
            Ok(Some(s)) => Ok(s.state),
            Ok(None) => {
                tracing::error!(
                    event = "ledger_missing_artifact_record",
                    reason_code = "INTERNAL_ERROR",
                    "ledger missing artifact record"
                );
                Err(AppError::Internal(
                    "ledger_missing_artifact_record".to_string(),
                ))
            }
            Err(_) => {
                tracing::error!(
                    event = "ledger_read_failed",
                    reason_code = "INTERNAL_ERROR",
                    "ledger read failed"
                );
                Err(AppError::Internal("ledger_read_failed".to_string()))
            }
        }
    }

    /// Commit a verified outcome: stage + dest write, then ledger
    /// transitions atomically inside a single `LedgerTransaction`.
    /// Returns `Ok(true)` if the artifact landed VERIFIED, `Ok(false)`
    /// if it ended up Quarantined for a commit-time reason (limit /
    /// path safety / etc.).
    #[allow(clippy::too_many_lines)]
    fn commit_verified(
        &mut self,
        artifact: &DiscoveredArtifact,
        verified: VerifiedOutcome,
    ) -> Result<bool, AppError> {
        let VerifiedOutcome {
            extractor_id,
            coverage,
            sanitized_bytes,
            findings_summary,
            proof_tokens,
            artifact_started,
        } = verified;

        if artifact_started.elapsed().as_millis()
            > u128::from(self.context.runtime_limits.max_processing_ms_per_artifact)
        {
            self.commit_quarantine(
                artifact,
                QuarantinedOutcome {
                    reason: veil_domain::QuarantineReasonCode::LimitExceeded,
                    raw_bytes: None,
                    event: None,
                },
            )?;
            return Ok(false);
        }

        let output_id = veil_domain::hash_output_id(&sanitized_bytes);
        let output_id_str = output_id.to_string();
        let dest_path = sanitized_output_path_v1(
            &self.paths.sanitized_dir,
            &artifact.sort_key,
            artifact.artifact_type_wire(),
        );

        if ensure_existing_path_components_safe(&dest_path, "sanitized output").is_err() {
            self.commit_quarantine(
                artifact,
                QuarantinedOutcome {
                    reason: veil_domain::QuarantineReasonCode::InternalError,
                    raw_bytes: None,
                    event: Some(OwnedArtifactEvent {
                        event: "sanitized_output_path_unsafe",
                        reason_code: "INTERNAL_ERROR",
                        detail: Some("sanitized output path is unsafe"),
                    }),
                },
            )?;
            return Ok(false);
        }

        if let Ok(meta) = std::fs::symlink_metadata(&dest_path)
            && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
        {
            self.commit_quarantine(
                artifact,
                QuarantinedOutcome {
                    reason: veil_domain::QuarantineReasonCode::InternalError,
                    raw_bytes: None,
                    event: Some(OwnedArtifactEvent {
                        event: "sanitized_output_path_symlink",
                        reason_code: "INTERNAL_ERROR",
                        detail: Some("sanitized output path is unsafe"),
                    }),
                },
            )?;
            return Ok(false);
        }

        // Idempotent re-entry: if a prior crashed run already wrote the
        // sanitized output and its bytes match, just bring the ledger up
        // to VERIFIED (with findings + proof tokens) without re-staging.
        if let Ok(meta) = std::fs::metadata(&dest_path)
            && meta.is_file()
        {
            let existing = std::fs::read(&dest_path).unwrap_or_default();
            if veil_domain::hash_output_id(&existing) == output_id {
                if self
                    .write_verified_ledger_transaction(
                        artifact,
                        &extractor_id,
                        coverage,
                        &findings_summary,
                        &proof_tokens,
                        &output_id_str,
                    )
                    .is_err()
                {
                    self.log_ledger_write_failed();
                    return Err(AppError::Internal("ledger_write_failed".to_string()));
                }
                self.proof_tokens_by_artifact
                    .insert(artifact.sort_key.artifact_id, proof_tokens);
                return Ok(true);
            }
            self.commit_quarantine(
                artifact,
                QuarantinedOutcome {
                    reason: veil_domain::QuarantineReasonCode::InternalError,
                    raw_bytes: None,
                    event: None,
                },
            )?;
            return Ok(false);
        }

        let file_name = match dest_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => {
                self.commit_quarantine(
                    artifact,
                    QuarantinedOutcome {
                        reason: veil_domain::QuarantineReasonCode::InternalError,
                        raw_bytes: None,
                        event: None,
                    },
                )?;
                return Ok(false);
            }
        };

        let sanitized_size = u64::try_from(sanitized_bytes.len()).unwrap_or(u64::MAX);
        if sanitized_size > self.context.archive_limits.max_bytes_per_artifact {
            self.commit_quarantine(
                artifact,
                QuarantinedOutcome {
                    reason: veil_domain::QuarantineReasonCode::LimitExceeded,
                    raw_bytes: None,
                    event: None,
                },
            )?;
            return Ok(false);
        }

        if self.workdir_bytes_observed.saturating_add(sanitized_size)
            > self.context.runtime_limits.max_workdir_bytes
        {
            self.commit_quarantine(
                artifact,
                QuarantinedOutcome {
                    reason: veil_domain::QuarantineReasonCode::LimitExceeded,
                    raw_bytes: None,
                    event: None,
                },
            )?;
            return Ok(false);
        }

        let stage_path = self.paths.staging_dir.join(format!("{file_name}.tmp"));
        if write_bytes_sync(&stage_path, &sanitized_bytes).is_err() {
            let _ = std::fs::remove_file(&stage_path);
            self.commit_quarantine(
                artifact,
                QuarantinedOutcome {
                    reason: veil_domain::QuarantineReasonCode::InternalError,
                    raw_bytes: None,
                    event: None,
                },
            )?;
            return Ok(false);
        }
        *self.workdir_bytes_observed = self.workdir_bytes_observed.saturating_add(sanitized_size);

        if std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_stage_write") {
            tracing::error!(
                event = "failpoint_triggered",
                reason_code = "INTERNAL_ERROR",
                "failpoint triggered"
            );
            return Err(AppError::Internal("failpoint_triggered".to_string()));
        }

        if ensure_existing_path_components_safe(&dest_path, "sanitized output").is_err() {
            let _ = std::fs::remove_file(&stage_path);
            *self.workdir_bytes_observed =
                self.workdir_bytes_observed.saturating_sub(sanitized_size);
            self.commit_quarantine(
                artifact,
                QuarantinedOutcome {
                    reason: veil_domain::QuarantineReasonCode::InternalError,
                    raw_bytes: None,
                    event: None,
                },
            )?;
            return Ok(false);
        }

        if std::fs::rename(&stage_path, &dest_path).is_err() {
            let _ = std::fs::remove_file(&stage_path);
            *self.workdir_bytes_observed =
                self.workdir_bytes_observed.saturating_sub(sanitized_size);
            if write_bytes_atomic(&dest_path, &sanitized_bytes).is_err() {
                self.commit_quarantine(
                    artifact,
                    QuarantinedOutcome {
                        reason: veil_domain::QuarantineReasonCode::InternalError,
                        raw_bytes: None,
                        event: None,
                    },
                )?;
                return Ok(false);
            }
        } else {
            *self.workdir_bytes_observed =
                self.workdir_bytes_observed.saturating_sub(sanitized_size);
            if sync_parent_dir(&dest_path).is_err() {
                let _ = std::fs::remove_file(&dest_path);
                self.commit_quarantine(
                    artifact,
                    QuarantinedOutcome {
                        reason: veil_domain::QuarantineReasonCode::InternalError,
                        raw_bytes: None,
                        event: None,
                    },
                )?;
                return Ok(false);
            }
        }

        if ensure_existing_file_safe(&dest_path, "sanitized output").is_err() {
            let _ = std::fs::remove_file(&dest_path);
            self.commit_quarantine(
                artifact,
                QuarantinedOutcome {
                    reason: veil_domain::QuarantineReasonCode::InternalError,
                    raw_bytes: None,
                    event: None,
                },
            )?;
            return Ok(false);
        }

        if self
            .write_verified_ledger_transaction(
                artifact,
                &extractor_id,
                coverage,
                &findings_summary,
                &proof_tokens,
                &output_id_str,
            )
            .is_err()
        {
            self.log_ledger_write_failed();
            return Err(AppError::Internal("ledger_write_failed".to_string()));
        }
        self.proof_tokens_by_artifact
            .insert(artifact.sort_key.artifact_id, proof_tokens);

        Ok(true)
    }

    /// Apply the verified state transition + findings + proof tokens
    /// inside one batched ledger transaction. Reduces fsync cost from
    /// four to one per artifact and guarantees the verified transitions
    /// are atomic relative to the destination FS write that just landed.
    fn write_verified_ledger_transaction(
        &mut self,
        artifact: &DiscoveredArtifact,
        extractor_id: &veil_extract::ExtractorId,
        coverage: veil_domain::CoverageMapV1,
        findings_summary: &[OwnedFindingsSummaryRow],
        proof_tokens: &[String],
        output_id_str: &str,
    ) -> Result<(), veil_evidence::LedgerError> {
        let coverage_hash = coverage_hash_v1(coverage);
        let rows = findings_summary
            .iter()
            .map(|r| veil_evidence::ledger::FindingsSummaryRow {
                class_id: r.class_id.as_str(),
                severity: r.severity.as_str(),
                action: r.action.as_str(),
                count: r.count,
            })
            .collect::<Vec<_>>();

        let tx = self.ledger.transaction()?;
        tx.mark_extracted(
            &artifact.sort_key.artifact_id,
            extractor_id.as_str(),
            &coverage_hash,
        )?;
        tx.mark_transformed(&artifact.sort_key.artifact_id)?;
        tx.replace_findings_summary(&artifact.sort_key.artifact_id, &rows)?;
        tx.replace_proof_tokens(&artifact.sort_key.artifact_id, proof_tokens)?;
        tx.mark_verified(&artifact.sort_key.artifact_id, output_id_str)?;
        tx.commit()
    }

    fn commit_quarantine(
        &mut self,
        artifact: &DiscoveredArtifact,
        outcome: QuarantinedOutcome,
    ) -> Result<(), AppError> {
        if self
            .ledger
            .quarantine(&artifact.sort_key.artifact_id, outcome.reason)
            .is_err()
        {
            self.log_ledger_write_failed();
            return Err(AppError::Internal("ledger_write_failed".to_string()));
        }

        if let Some(bytes) = outcome.raw_bytes
            && write_quarantine_raw_or_fail(
                self.context.parsed.quarantine_copy,
                &self.paths.quarantine_raw_dir,
                &artifact.sort_key,
                artifact.artifact_type_wire(),
                &bytes,
            )
            .is_err()
        {
            return Err(AppError::Internal(
                "quarantine_raw_write_failed".to_string(),
            ));
        }

        if let Some(event) = outcome.event {
            let artifact_id = artifact.sort_key.artifact_id.to_string();
            let source_locator_hash = artifact.sort_key.source_locator_hash.to_string();
            tracing::error!(
                event = event.event,
                reason_code = event.reason_code,
                artifact_id = %artifact_id,
                source_locator_hash = %source_locator_hash,
                detail = event.detail.unwrap_or(""),
                "{}",
                event.event,
            );
        }

        Ok(())
    }
}

/// Run the pure pipeline (load -> extract -> coverage -> detect ->
/// transform -> reverify) without touching the ledger or the
/// destination filesystem. Returns a `WorkerOutcome` the committer can
/// apply atomically. Workers call this from inside a
/// `catch_unwind`; `prepare_outcome_from_pure_pipeline` itself never
/// returns an `AppError` — failures collapse to
/// `WorkerOutcome::Quarantined { reason, ... }` so the committer can
/// always make forward progress.
pub(crate) fn prepare_outcome_from_pure_pipeline(
    shared: &SharedWorkerContext,
    artifact: &DiscoveredArtifact,
) -> WorkerOutcome {
    let artifact_started = Instant::now();

    // Load bytes.
    let bytes = match read_artifact_bytes_for_processing(
        &artifact.path,
        artifact.size_bytes,
        &artifact.sort_key.artifact_id,
        shared.archive_limits.max_bytes_per_artifact,
    ) {
        Ok(b) => b,
        Err(ReadArtifactError::LimitExceeded) => {
            return WorkerOutcome::Quarantined(QuarantinedOutcome {
                reason: veil_domain::QuarantineReasonCode::LimitExceeded,
                raw_bytes: None,
                event: None,
            });
        }
        Err(ReadArtifactError::IdentityMismatch) | Err(ReadArtifactError::Io) => {
            return WorkerOutcome::Quarantined(QuarantinedOutcome {
                reason: veil_domain::QuarantineReasonCode::InternalError,
                raw_bytes: None,
                event: None,
            });
        }
    };

    // Extract.
    let Some(artifact_type) = artifact.artifact_type else {
        return WorkerOutcome::Quarantined(QuarantinedOutcome {
            reason: veil_domain::QuarantineReasonCode::UnsupportedFormat,
            raw_bytes: Some(bytes),
            event: None,
        });
    };

    let ctx = veil_extract::ArtifactContext {
        artifact_id: &artifact.sort_key.artifact_id,
        source_locator_hash: &artifact.sort_key.source_locator_hash,
    };
    let extracted = if shared.isolate_risky_extractors && artifact_type.is_risky_extractor() {
        match crate::extract_worker::run_extract_in_worker(
            &artifact.path,
            artifact_type,
            shared.archive_limits,
            shared.runtime_limits.max_processing_ms_per_artifact,
        ) {
            Ok(v) => v,
            Err(_) => {
                return WorkerOutcome::Quarantined(QuarantinedOutcome {
                    reason: veil_domain::QuarantineReasonCode::InternalError,
                    raw_bytes: Some(bytes),
                    event: Some(OwnedArtifactEvent {
                        event: "extract_worker_failed",
                        reason_code: "INTERNAL_ERROR",
                        detail: Some("extract worker failed"),
                    }),
                });
            }
        }
    } else {
        shared.extractors.extract(artifact_type, ctx, &bytes)
    };

    let (extractor_id, canonical, coverage) = match extracted {
        veil_extract::ExtractOutcome::Extracted {
            extractor_id,
            canonical,
            coverage,
        } => (extractor_id, canonical, coverage),
        veil_extract::ExtractOutcome::Quarantined { reason, .. } => {
            return WorkerOutcome::Quarantined(QuarantinedOutcome {
                reason,
                raw_bytes: Some(bytes),
                event: None,
            });
        }
    };

    if coverage.has_unknown() {
        return WorkerOutcome::Quarantined(QuarantinedOutcome {
            reason: veil_domain::QuarantineReasonCode::UnknownCoverage,
            raw_bytes: Some(bytes),
            event: None,
        });
    }

    // Detect.
    let findings = shared
        .detector
        .detect(&shared.policy, &canonical, Some(&shared.proof_key));
    let proof_tokens = collect_proof_tokens(&findings);
    let findings_summary = owned_findings_summary_rows(&shared.policy, &findings);

    // Transform.
    let sanitized_bytes = match shared.transformer.transform(&shared.policy, &canonical) {
        veil_transform::TransformOutcome::Transformed { sanitized_bytes } => sanitized_bytes,
        veil_transform::TransformOutcome::Quarantined { reason } => {
            return WorkerOutcome::Quarantined(QuarantinedOutcome {
                reason,
                raw_bytes: Some(bytes),
                event: None,
            });
        }
    };

    // Reverify by re-extracting the sanitized output and re-running the
    // detector. Pure operation — no ledger or FS dest touch.
    let verify_artifact_type = artifact_type.verification_artifact_type();
    let extracted_out = shared
        .extractors
        .extract(verify_artifact_type, ctx, &sanitized_bytes);
    let canonical_out = match extracted_out {
        veil_extract::ExtractOutcome::Extracted { canonical, .. } => canonical,
        veil_extract::ExtractOutcome::Quarantined { .. } => {
            return WorkerOutcome::Quarantined(QuarantinedOutcome {
                reason: veil_domain::QuarantineReasonCode::ParseError,
                raw_bytes: Some(bytes),
                event: None,
            });
        }
    };

    let findings_out =
        shared
            .detector
            .detect(&shared.policy, &canonical_out, Some(&shared.proof_key));
    let verification = veil_verify::residual_verify(&findings_out);
    if let veil_verify::VerificationOutcome::Quarantined { reason } = verification {
        return WorkerOutcome::Quarantined(QuarantinedOutcome {
            reason,
            raw_bytes: Some(bytes),
            event: None,
        });
    }

    WorkerOutcome::Verified(VerifiedOutcome {
        extractor_id,
        coverage,
        sanitized_bytes,
        findings_summary,
        proof_tokens,
        artifact_started,
    })
}

/// Build the owned findings-summary rows from policy + findings.
/// Same logic as `evidence_io::findings_summary_rows` but produces an
/// owned-string row so the committer can move it across thread
/// boundaries inside a `WorkerOutcome`.
fn owned_findings_summary_rows(
    policy: &veil_policy::Policy,
    findings: &[veil_detect::Finding],
) -> Vec<OwnedFindingsSummaryRow> {
    use std::collections::BTreeMap;
    let mut counts = BTreeMap::<&str, u64>::new();
    for f in findings {
        *counts.entry(f.class_id.as_str()).or_insert(0) += 1;
    }

    let mut out = Vec::<OwnedFindingsSummaryRow>::new();
    for class in &policy.classes {
        let count = counts.get(class.class_id.as_str()).copied().unwrap_or(0);
        if count == 0 {
            continue;
        }
        out.push(OwnedFindingsSummaryRow {
            class_id: class.class_id.clone(),
            severity: class.severity.as_str().to_string(),
            action: action_as_string(&class.action),
            count,
        });
    }
    out
}

fn action_as_string(action: &veil_policy::Action) -> String {
    match action {
        veil_policy::Action::Redact => "REDACT",
        veil_policy::Action::Mask { .. } => "MASK",
        veil_policy::Action::Drop => "DROP",
    }
    .to_string()
}
