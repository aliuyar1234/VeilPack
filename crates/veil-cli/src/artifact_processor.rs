use std::collections::BTreeMap;
use std::process::ExitCode;
use std::time::Instant;

use veil_detect::DetectorEngine;
use veil_transform::Transformer;

use crate::EXIT_FATAL;
use crate::evidence_io::{
    collect_proof_tokens, coverage_hash_v1, findings_summary_rows, sanitized_output_path_v1,
    verification_artifact_type_v1, write_quarantine_raw_or_fail,
};
use crate::fs_safety::{
    ensure_existing_file_safe, ensure_existing_path_components_safe, is_unsafe_reparse_point,
    sync_parent_dir, write_bytes_atomic, write_bytes_sync,
};
use crate::input_inventory::{
    DiscoveredArtifact, ReadArtifactError, read_artifact_bytes_for_processing,
};
use crate::logging::{log_artifact_error, log_error};
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
    pub(crate) extractors: &'a veil_extract::ExtractorRegistry,
    pub(crate) detector: &'a veil_detect::DetectorEngineV1,
    pub(crate) transformer: &'a veil_transform::TransformerV1,
    pub(crate) proof_tokens_by_artifact: &'a mut BTreeMap<veil_domain::ArtifactId, Vec<String>>,
    pub(crate) workdir_bytes_observed: &'a mut u64,
}

struct ExtractedArtifact {
    extractor_id: &'static str,
    canonical: veil_extract::CanonicalArtifact,
    coverage: veil_domain::CoverageMapV1,
}

struct ArtifactEvent<'a> {
    event: &'a str,
    reason_code: &'a str,
    detail: Option<&'a str>,
}

impl<'a> ArtifactProcessor<'a> {
    pub(crate) fn process(
        &mut self,
        artifact: &DiscoveredArtifact,
    ) -> Result<ArtifactProcessStatus, ExitCode> {
        let state = self.upsert_discovered_and_get_state(artifact)?;
        if state.is_terminal() {
            return Ok(ArtifactProcessStatus::SkippedTerminal);
        }

        self.proof_tokens_by_artifact
            .remove(&artifact.sort_key.artifact_id);
        let artifact_started = Instant::now();

        let Some(bytes) = self.load_bytes(artifact)? else {
            return Ok(ArtifactProcessStatus::Quarantined);
        };

        let Some(extracted) = self.extract(artifact, &bytes)? else {
            return Ok(ArtifactProcessStatus::Quarantined);
        };

        if self.handle_unknown_coverage(artifact, &bytes, extracted.coverage)? {
            return Ok(ArtifactProcessStatus::Quarantined);
        }

        self.mark_extracted_or_exit(artifact, &extracted)?;

        self.detect(artifact, &extracted.canonical)?;

        let Some(sanitized_bytes) = self.transform(artifact, &bytes, &extracted.canonical)? else {
            return Ok(ArtifactProcessStatus::Quarantined);
        };

        self.mark_transformed_or_exit(artifact)?;

        if !self.reverify(artifact, &bytes, &sanitized_bytes)? {
            return Ok(ArtifactProcessStatus::Quarantined);
        }

        if !self.commit_verified_output(artifact, &bytes, &sanitized_bytes, artifact_started)? {
            return Ok(ArtifactProcessStatus::Quarantined);
        }

        Ok(ArtifactProcessStatus::Verified)
    }

    fn upsert_discovered_and_get_state(
        &mut self,
        artifact: &DiscoveredArtifact,
    ) -> Result<veil_domain::ArtifactState, ExitCode> {
        if self
            .ledger
            .upsert_discovered(
                &artifact.sort_key.artifact_id,
                &artifact.sort_key.source_locator_hash,
                artifact.size_bytes,
                &artifact.artifact_type,
            )
            .is_err()
        {
            log_error(
                self.context.log_ctx(),
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        match self.ledger.artifact_summary(&artifact.sort_key.artifact_id) {
            Ok(Some(s)) => Ok(s.state),
            Ok(None) => {
                log_error(
                    self.context.log_ctx(),
                    "ledger_missing_artifact_record",
                    "INTERNAL_ERROR",
                    Some("ledger missing artifact record (redacted)"),
                );
                Err(ExitCode::from(EXIT_FATAL))
            }
            Err(_) => {
                log_error(
                    self.context.log_ctx(),
                    "ledger_read_failed",
                    "INTERNAL_ERROR",
                    Some("ledger read failed (redacted)"),
                );
                Err(ExitCode::from(EXIT_FATAL))
            }
        }
    }

    fn mark_extracted_or_exit(
        &mut self,
        artifact: &DiscoveredArtifact,
        extracted: &ExtractedArtifact,
    ) -> Result<(), ExitCode> {
        if self
            .ledger
            .mark_extracted(
                &artifact.sort_key.artifact_id,
                extracted.extractor_id,
                &coverage_hash_v1(extracted.coverage),
            )
            .is_err()
        {
            log_error(
                self.context.log_ctx(),
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
        Ok(())
    }

    fn mark_transformed_or_exit(&mut self, artifact: &DiscoveredArtifact) -> Result<(), ExitCode> {
        if self
            .ledger
            .mark_transformed(&artifact.sort_key.artifact_id)
            .is_err()
        {
            log_error(
                self.context.log_ctx(),
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
        Ok(())
    }

    fn load_bytes(&mut self, artifact: &DiscoveredArtifact) -> Result<Option<Vec<u8>>, ExitCode> {
        let bytes = match read_artifact_bytes_for_processing(
            &artifact.path,
            artifact.size_bytes,
            &artifact.sort_key.artifact_id,
            self.context.archive_limits.max_bytes_per_artifact,
        ) {
            Ok(b) => b,
            Err(ReadArtifactError::LimitExceeded) => {
                self.quarantine(
                    artifact,
                    veil_domain::QuarantineReasonCode::LimitExceeded,
                    None,
                    None,
                )?;
                return Ok(None);
            }
            Err(ReadArtifactError::IdentityMismatch) | Err(ReadArtifactError::Io) => {
                self.quarantine(
                    artifact,
                    veil_domain::QuarantineReasonCode::InternalError,
                    None,
                    None,
                )?;
                return Ok(None);
            }
        };

        Ok(Some(bytes))
    }

    fn extract(
        &mut self,
        artifact: &DiscoveredArtifact,
        bytes: &[u8],
    ) -> Result<Option<ExtractedArtifact>, ExitCode> {
        let ctx = veil_extract::ArtifactContext {
            artifact_id: &artifact.sort_key.artifact_id,
            source_locator_hash: &artifact.sort_key.source_locator_hash,
        };
        let extracted = if self.context.parsed.isolate_risky_extractors
            && crate::extract_worker::is_risky_extractor_type(&artifact.artifact_type)
        {
            match crate::extract_worker::run_extract_in_worker(
                &artifact.path,
                &artifact.artifact_type,
                self.context.archive_limits,
                self.context.runtime_limits.max_processing_ms_per_artifact,
            ) {
                Ok(v) => v,
                Err(_) => {
                    self.quarantine(
                        artifact,
                        veil_domain::QuarantineReasonCode::InternalError,
                        Some(bytes),
                        Some(ArtifactEvent {
                            event: "extract_worker_failed",
                            reason_code: "INTERNAL_ERROR",
                            detail: Some("extract worker failed (redacted)"),
                        }),
                    )?;
                    return Ok(None);
                }
            }
        } else {
            self.extractors
                .extract_by_type(&artifact.artifact_type, ctx, bytes)
        };

        match extracted {
            veil_extract::ExtractOutcome::Extracted {
                extractor_id,
                canonical,
                coverage,
            } => Ok(Some(ExtractedArtifact {
                extractor_id,
                canonical,
                coverage,
            })),
            veil_extract::ExtractOutcome::Quarantined { reason, .. } => {
                self.quarantine(artifact, reason, Some(bytes), None)?;
                Ok(None)
            }
        }
    }

    fn handle_unknown_coverage(
        &mut self,
        artifact: &DiscoveredArtifact,
        bytes: &[u8],
        coverage: veil_domain::CoverageMapV1,
    ) -> Result<bool, ExitCode> {
        if coverage.has_unknown() {
            self.quarantine(
                artifact,
                veil_domain::QuarantineReasonCode::UnknownCoverage,
                Some(bytes),
                None,
            )?;
            return Ok(true);
        }
        Ok(false)
    }

    fn detect(
        &mut self,
        artifact: &DiscoveredArtifact,
        canonical: &veil_extract::CanonicalArtifact,
    ) -> Result<(), ExitCode> {
        let findings = self.detector.detect(
            &self.context.policy,
            canonical,
            Some(&*self.context.proof_key),
        );
        self.proof_tokens_by_artifact.insert(
            artifact.sort_key.artifact_id,
            collect_proof_tokens(&findings),
        );
        if self
            .ledger
            .replace_findings_summary(
                &artifact.sort_key.artifact_id,
                &findings_summary_rows(&self.context.policy, &findings),
            )
            .is_err()
        {
            log_error(
                self.context.log_ctx(),
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
        Ok(())
    }

    fn transform(
        &mut self,
        artifact: &DiscoveredArtifact,
        bytes: &[u8],
        canonical: &veil_extract::CanonicalArtifact,
    ) -> Result<Option<Vec<u8>>, ExitCode> {
        let sanitized_bytes = match self.transformer.transform(&self.context.policy, canonical) {
            veil_transform::TransformOutcome::Transformed { sanitized_bytes } => sanitized_bytes,
            veil_transform::TransformOutcome::Quarantined { reason } => {
                self.quarantine(artifact, reason, Some(bytes), None)?;
                return Ok(None);
            }
        };

        Ok(Some(sanitized_bytes))
    }

    fn reverify(
        &mut self,
        artifact: &DiscoveredArtifact,
        bytes: &[u8],
        sanitized_bytes: &[u8],
    ) -> Result<bool, ExitCode> {
        let ctx = veil_extract::ArtifactContext {
            artifact_id: &artifact.sort_key.artifact_id,
            source_locator_hash: &artifact.sort_key.source_locator_hash,
        };
        let verify_artifact_type = verification_artifact_type_v1(&artifact.artifact_type);
        let extracted_out =
            self.extractors
                .extract_by_type(verify_artifact_type, ctx, sanitized_bytes);
        let canonical_out = match extracted_out {
            veil_extract::ExtractOutcome::Extracted { canonical, .. } => canonical,
            veil_extract::ExtractOutcome::Quarantined { .. } => {
                self.quarantine(
                    artifact,
                    veil_domain::QuarantineReasonCode::ParseError,
                    Some(bytes),
                    None,
                )?;
                return Ok(false);
            }
        };

        let findings_out = self.detector.detect(
            &self.context.policy,
            &canonical_out,
            Some(&*self.context.proof_key),
        );
        let verification = veil_verify::residual_verify(&findings_out);
        if verification != veil_verify::VerificationOutcome::Verified {
            let reason = match verification {
                veil_verify::VerificationOutcome::Verified => unreachable!(),
                veil_verify::VerificationOutcome::Quarantined { reason } => reason,
            };
            self.quarantine(artifact, reason, Some(bytes), None)?;
            return Ok(false);
        }

        Ok(true)
    }

    fn commit_verified_output(
        &mut self,
        artifact: &DiscoveredArtifact,
        bytes: &[u8],
        sanitized_bytes: &[u8],
        artifact_started: Instant,
    ) -> Result<bool, ExitCode> {
        if artifact_started.elapsed().as_millis()
            > u128::from(self.context.runtime_limits.max_processing_ms_per_artifact)
        {
            self.quarantine(
                artifact,
                veil_domain::QuarantineReasonCode::LimitExceeded,
                Some(bytes),
                None,
            )?;
            return Ok(false);
        }

        let output_id = veil_domain::hash_output_id(sanitized_bytes);
        let output_id_str = output_id.to_string();
        let dest_path = sanitized_output_path_v1(
            &self.paths.sanitized_dir,
            &artifact.sort_key,
            &artifact.artifact_type,
        );

        if ensure_existing_path_components_safe(&dest_path, "sanitized output").is_err() {
            self.quarantine(
                artifact,
                veil_domain::QuarantineReasonCode::InternalError,
                Some(bytes),
                Some(ArtifactEvent {
                    event: "sanitized_output_path_unsafe",
                    reason_code: "INTERNAL_ERROR",
                    detail: Some("sanitized output path is unsafe (redacted)"),
                }),
            )?;
            return Ok(false);
        }

        if let Ok(meta) = std::fs::symlink_metadata(&dest_path)
            && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
        {
            self.quarantine(
                artifact,
                veil_domain::QuarantineReasonCode::InternalError,
                Some(bytes),
                Some(ArtifactEvent {
                    event: "sanitized_output_path_symlink",
                    reason_code: "INTERNAL_ERROR",
                    detail: Some("sanitized output path is unsafe (redacted)"),
                }),
            )?;
            return Ok(false);
        }

        if let Ok(meta) = std::fs::metadata(&dest_path)
            && meta.is_file()
        {
            let existing = std::fs::read(&dest_path).unwrap_or_default();
            if veil_domain::hash_output_id(&existing) == output_id {
                if self
                    .ledger
                    .mark_verified(&artifact.sort_key.artifact_id, &output_id_str)
                    .is_err()
                {
                    log_error(
                        self.context.log_ctx(),
                        "ledger_write_failed",
                        "INTERNAL_ERROR",
                        Some("ledger write failed (redacted)"),
                    );
                    return Err(ExitCode::from(EXIT_FATAL));
                }
                return Ok(true);
            }
            self.quarantine(
                artifact,
                veil_domain::QuarantineReasonCode::InternalError,
                Some(bytes),
                None,
            )?;
            return Ok(false);
        }

        let file_name = match dest_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => {
                self.quarantine(
                    artifact,
                    veil_domain::QuarantineReasonCode::InternalError,
                    Some(bytes),
                    None,
                )?;
                return Ok(false);
            }
        };

        let sanitized_size = u64::try_from(sanitized_bytes.len()).unwrap_or(u64::MAX);
        if sanitized_size > self.context.archive_limits.max_bytes_per_artifact {
            self.quarantine(
                artifact,
                veil_domain::QuarantineReasonCode::LimitExceeded,
                Some(bytes),
                None,
            )?;
            return Ok(false);
        }

        if self.workdir_bytes_observed.saturating_add(sanitized_size)
            > self.context.runtime_limits.max_workdir_bytes
        {
            self.quarantine(
                artifact,
                veil_domain::QuarantineReasonCode::LimitExceeded,
                Some(bytes),
                None,
            )?;
            return Ok(false);
        }

        let stage_path = self.paths.staging_dir.join(format!("{file_name}.tmp"));
        if write_bytes_sync(&stage_path, sanitized_bytes).is_err() {
            let _ = std::fs::remove_file(&stage_path);
            self.quarantine(
                artifact,
                veil_domain::QuarantineReasonCode::InternalError,
                Some(bytes),
                None,
            )?;
            return Ok(false);
        }
        *self.workdir_bytes_observed = self.workdir_bytes_observed.saturating_add(sanitized_size);

        if std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_stage_write") {
            log_error(
                self.context.log_ctx(),
                "failpoint_triggered",
                "INTERNAL_ERROR",
                Some("failpoint triggered (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        if ensure_existing_path_components_safe(&dest_path, "sanitized output").is_err() {
            let _ = std::fs::remove_file(&stage_path);
            *self.workdir_bytes_observed =
                self.workdir_bytes_observed.saturating_sub(sanitized_size);
            self.quarantine(
                artifact,
                veil_domain::QuarantineReasonCode::InternalError,
                Some(bytes),
                None,
            )?;
            return Ok(false);
        }

        if std::fs::rename(&stage_path, &dest_path).is_err() {
            let _ = std::fs::remove_file(&stage_path);
            *self.workdir_bytes_observed =
                self.workdir_bytes_observed.saturating_sub(sanitized_size);
            if write_bytes_atomic(&dest_path, sanitized_bytes).is_err() {
                self.quarantine(
                    artifact,
                    veil_domain::QuarantineReasonCode::InternalError,
                    Some(bytes),
                    None,
                )?;
                return Ok(false);
            }
        } else {
            *self.workdir_bytes_observed =
                self.workdir_bytes_observed.saturating_sub(sanitized_size);
            if sync_parent_dir(&dest_path).is_err() {
                let _ = std::fs::remove_file(&dest_path);
                self.quarantine(
                    artifact,
                    veil_domain::QuarantineReasonCode::InternalError,
                    Some(bytes),
                    None,
                )?;
                return Ok(false);
            }
        }

        if ensure_existing_file_safe(&dest_path, "sanitized output").is_err() {
            let _ = std::fs::remove_file(&dest_path);
            self.quarantine(
                artifact,
                veil_domain::QuarantineReasonCode::InternalError,
                Some(bytes),
                None,
            )?;
            return Ok(false);
        }

        if self
            .ledger
            .mark_verified(&artifact.sort_key.artifact_id, &output_id_str)
            .is_err()
        {
            log_error(
                self.context.log_ctx(),
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        Ok(true)
    }

    fn quarantine(
        &mut self,
        artifact: &DiscoveredArtifact,
        reason: veil_domain::QuarantineReasonCode,
        raw_bytes: Option<&[u8]>,
        event: Option<ArtifactEvent<'_>>,
    ) -> Result<(), ExitCode> {
        if self
            .ledger
            .quarantine(&artifact.sort_key.artifact_id, reason)
            .is_err()
        {
            log_error(
                self.context.log_ctx(),
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        if let Some(bytes) = raw_bytes
            && write_quarantine_raw_or_fail(
                self.context.parsed.quarantine_copy,
                &self.paths.quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                bytes,
                self.context.log_ctx(),
            )
            .is_err()
        {
            return Err(ExitCode::from(EXIT_FATAL));
        }

        if let Some(event) = event {
            log_artifact_error(
                self.context.log_ctx(),
                event.event,
                event.reason_code,
                &artifact.sort_key,
                event.detail,
            );
        }

        Ok(())
    }
}
