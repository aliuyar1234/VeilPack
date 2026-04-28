use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use veil_detect::DetectorEngine;
use veil_evidence::{ManifestReadError, NdjsonReader, PackManifest};

use crate::error::AppError;
use crate::evidence_io::{ArtifactEvidenceRecordOwned, sanitized_output_path_v1};
use crate::fs_safety::{
    ensure_existing_file_safe, ensure_existing_path_components_safe, is_unsafe_reparse_point,
};
use crate::logging::UNKNOWN_LOG_ID;
use crate::{EXIT_FATAL, EXIT_OK, EXIT_QUARANTINED};

// PackVerifier is the pack-integrity gate for `veil verify`.
// It owns pack-manifest loading, evidence reconciliation, output identity checks,
// and residual rescanning. Any mismatch fails closed.
pub(crate) enum PackVerifyResult {
    Exit(ExitCode),
    Usage(String),
}

struct LoadedEvidence {
    ledger: veil_evidence::Ledger,
    evidence_by_artifact: BTreeMap<String, ArtifactEvidenceRecordOwned>,
}

/// One verified ledger record paired with its `artifacts.ndjson` row and
/// the derived `dest_path` on disk. Carries everything the four post-
/// reconcile passes need so they don't have to re-derive paths or
/// re-parse the ledger artifact_type.
struct ReconciledArtifact {
    ledger_rec: veil_evidence::ledger::ArtifactRecord,
    /// Reserved for future passes that need the raw NDJSON view (e.g.
    /// proof-token sanity checks). Keeping the full row attached avoids
    /// a re-read of `artifacts.ndjson` from each helper.
    #[allow(dead_code)]
    evidence_rec: ArtifactEvidenceRecordOwned,
    sort_key: veil_domain::ArtifactSortKey,
    dest_path: PathBuf,
}

pub(crate) struct PackVerifier<'a> {
    pack_root: &'a Path,
    policy: &'a veil_policy::Policy,
    pack_manifest: Option<PackManifest>,
}

impl<'a> PackVerifier<'a> {
    pub(crate) fn new(pack_root: &'a Path, policy: &'a veil_policy::Policy) -> Self {
        Self {
            pack_root,
            policy,
            pack_manifest: None,
        }
    }

    pub(crate) fn run(mut self) -> PackVerifyResult {
        match self.run_inner() {
            Ok(code) => PackVerifyResult::Exit(code),
            Err(AppError::Usage(msg)) => PackVerifyResult::Usage(msg),
            Err(_) => PackVerifyResult::Exit(ExitCode::from(EXIT_FATAL)),
        }
    }

    fn run_inner(&mut self) -> Result<ExitCode, AppError> {
        let pack_manifest = self.load_pack_manifest()?;
        self.pack_manifest = Some(pack_manifest);

        let verify_span = tracing::info_span!(
            "verify",
            run_id = self.pack_manifest().run_id.as_str(),
            policy_id = self.pack_manifest().policy_id.as_str(),
        );
        let _guard = verify_span.enter();

        tracing::info!(event = "verify_started", "verify started");

        if self.pack_manifest().policy_id != self.policy.policy_id.to_string() {
            return Err(AppError::Usage("policy_id mismatch for verify".to_string()));
        }

        let mut evidence = self.load_validate_evidence()?;

        let (verified_checked, failures, expected_verified_paths) =
            self.verify_expected_verified_outputs(&mut evidence)?;

        if !evidence.evidence_by_artifact.is_empty() {
            tracing::error!(
                event = "verify_extra_artifacts_records",
                reason_code = "INTERNAL_ERROR",
                "artifacts.ndjson contains records not present in ledger"
            );
            return Err(AppError::Internal(
                "verify_extra_artifacts_records".to_string(),
            ));
        }

        let failures =
            self.verify_no_unexpected_sanitized_outputs(expected_verified_paths, failures)?;

        tracing::info!(
            event = "verify_completed",
            verified_checked,
            verification_failures = failures,
            "verify completed"
        );

        if failures > 0 {
            Ok(ExitCode::from(EXIT_QUARANTINED))
        } else {
            Ok(ExitCode::from(EXIT_OK))
        }
    }

    fn load_pack_manifest(&self) -> Result<PackManifest, AppError> {
        let pack_manifest_path = self.pack_root.join("pack_manifest.json");
        if ensure_existing_file_safe(&pack_manifest_path, "pack manifest").is_err() {
            tracing::error!(
                event = "verify_pack_manifest_unsafe",
                reason_code = "INTERNAL_ERROR",
                run_id = UNKNOWN_LOG_ID,
                policy_id = UNKNOWN_LOG_ID,
                "pack_manifest.json path is unsafe"
            );
            return Err(AppError::Internal(
                "verify_pack_manifest_unsafe".to_string(),
            ));
        }

        match PackManifest::read_validate(&pack_manifest_path) {
            Ok(m) => Ok(m),
            Err(err) => {
                self.log_manifest_read_error(&err);
                Err(AppError::Manifest(err))
            }
        }
    }

    /// Map a `ManifestReadError` to the same fatal log events the inline
    /// parser used to emit. Keeping the event codes stable preserves the
    /// CLI's external test contracts while the parsing logic moves into
    /// `veil-evidence::manifest`.
    fn log_manifest_read_error(&self, err: &ManifestReadError) {
        match err {
            ManifestReadError::UnsafePath => {
                tracing::error!(
                    event = "verify_pack_manifest_unsafe",
                    reason_code = "INTERNAL_ERROR",
                    run_id = UNKNOWN_LOG_ID,
                    policy_id = UNKNOWN_LOG_ID,
                    "pack_manifest.json path is unsafe"
                );
            }
            ManifestReadError::Io => {
                tracing::error!(
                    event = "verify_pack_manifest_read_failed",
                    reason_code = "INTERNAL_ERROR",
                    run_id = UNKNOWN_LOG_ID,
                    policy_id = UNKNOWN_LOG_ID,
                    "could not read pack_manifest.json"
                );
            }
            ManifestReadError::InvalidJson => {
                tracing::error!(
                    event = "verify_pack_manifest_parse_failed",
                    reason_code = "INTERNAL_ERROR",
                    run_id = UNKNOWN_LOG_ID,
                    policy_id = UNKNOWN_LOG_ID,
                    "pack_manifest.json is invalid JSON"
                );
            }
            ManifestReadError::UnsupportedPackSchema { .. } => {
                tracing::error!(
                    event = "verify_pack_schema_unsupported",
                    reason_code = "INTERNAL_ERROR",
                    run_id = UNKNOWN_LOG_ID,
                    policy_id = UNKNOWN_LOG_ID,
                    "unsupported pack_schema_version"
                );
            }
            ManifestReadError::UnsupportedLedgerSchema { .. } => {
                tracing::error!(
                    event = "verify_ledger_schema_unsupported",
                    reason_code = "INTERNAL_ERROR",
                    run_id = UNKNOWN_LOG_ID,
                    policy_id = UNKNOWN_LOG_ID,
                    "unsupported ledger schema_version"
                );
            }
            ManifestReadError::MissingRequiredField => {
                tracing::error!(
                    event = "verify_pack_manifest_missing_fields",
                    reason_code = "INTERNAL_ERROR",
                    run_id = UNKNOWN_LOG_ID,
                    policy_id = UNKNOWN_LOG_ID,
                    "pack_manifest.json is missing required fields"
                );
            }
            ManifestReadError::InvalidTokenizationScope => {
                tracing::error!(
                    event = "verify_invalid_tokenization_scope",
                    reason_code = "INTERNAL_ERROR",
                    run_id = UNKNOWN_LOG_ID,
                    policy_id = UNKNOWN_LOG_ID,
                    "invalid tokenization scope metadata"
                );
            }
        }
    }

    fn load_validate_evidence(&self) -> Result<LoadedEvidence, AppError> {
        let ledger = self.open_existing_ledger()?;
        if !self.metadata_matches(&ledger) {
            tracing::error!(
                event = "verify_ledger_metadata_mismatch",
                reason_code = "INTERNAL_ERROR",
                "ledger metadata does not match pack manifest"
            );
            return Err(AppError::Internal(
                "verify_ledger_metadata_mismatch".to_string(),
            ));
        }

        let artifacts_file = self.open_artifacts_evidence_file()?;
        let reader = std::io::BufReader::new(artifacts_file);

        let mut evidence_by_artifact = BTreeMap::<String, ArtifactEvidenceRecordOwned>::new();
        for entry in NdjsonReader::new(reader) {
            let line = match entry {
                Ok(line) => line,
                Err(_) => {
                    tracing::error!(
                        event = "verify_artifacts_line_read_failed",
                        reason_code = "INTERNAL_ERROR",
                        "could not read artifacts.ndjson line"
                    );
                    return Err(AppError::Internal(
                        "verify_artifacts_line_read_failed".to_string(),
                    ));
                }
            };

            let rec: ArtifactEvidenceRecordOwned = match serde_json::from_str(&line.raw) {
                Ok(v) => v,
                Err(_) => {
                    tracing::error!(
                        event = "verify_artifacts_record_parse_failed",
                        reason_code = "INTERNAL_ERROR",
                        "artifacts.ndjson record is invalid JSON"
                    );
                    return Err(AppError::Internal(
                        "verify_artifacts_record_parse_failed".to_string(),
                    ));
                }
            };
            if evidence_by_artifact
                .insert(rec.artifact_id.clone(), rec)
                .is_some()
            {
                tracing::error!(
                    event = "verify_duplicate_artifact_record",
                    reason_code = "INTERNAL_ERROR",
                    "artifacts.ndjson contains duplicate artifact_id"
                );
                return Err(AppError::Internal(
                    "verify_duplicate_artifact_record".to_string(),
                ));
            }
        }

        let ledger_records = match ledger.artifact_records() {
            Ok(v) => v,
            Err(_) => {
                tracing::error!(
                    event = "verify_ledger_read_failed",
                    reason_code = "INTERNAL_ERROR",
                    "could not read ledger artifacts"
                );
                return Err(AppError::Internal("verify_ledger_read_failed".to_string()));
            }
        };
        if ledger_records.len() != evidence_by_artifact.len() {
            tracing::error!(
                event = "verify_evidence_count_mismatch",
                reason_code = "INTERNAL_ERROR",
                "ledger and artifacts evidence differ"
            );
            return Err(AppError::Internal(
                "verify_evidence_count_mismatch".to_string(),
            ));
        }

        Ok(LoadedEvidence {
            ledger,
            evidence_by_artifact,
        })
    }

    fn open_existing_ledger(&self) -> Result<veil_evidence::Ledger, AppError> {
        let ledger_path = self.pack_root.join("evidence").join("ledger.sqlite3");
        if ensure_existing_file_safe(&ledger_path, "ledger").is_err() {
            tracing::error!(
                event = "verify_ledger_unsafe",
                reason_code = "INTERNAL_ERROR",
                "ledger.sqlite3 path is unsafe"
            );
            return Err(AppError::Internal("verify_ledger_unsafe".to_string()));
        }

        veil_evidence::Ledger::open_existing(&ledger_path).map_err(|e| {
            tracing::error!(
                event = "verify_ledger_open_failed",
                reason_code = "INTERNAL_ERROR",
                "could not open ledger.sqlite3"
            );
            AppError::Ledger(e)
        })
    }

    fn open_artifacts_evidence_file(&self) -> Result<std::fs::File, AppError> {
        let artifacts_path = self.pack_root.join("evidence").join("artifacts.ndjson");
        if ensure_existing_file_safe(&artifacts_path, "artifacts evidence").is_err() {
            tracing::error!(
                event = "verify_artifacts_evidence_unsafe",
                reason_code = "INTERNAL_ERROR",
                "artifacts.ndjson path is unsafe"
            );
            return Err(AppError::Internal(
                "verify_artifacts_evidence_unsafe".to_string(),
            ));
        }

        std::fs::File::open(&artifacts_path).map_err(|_| {
            tracing::error!(
                event = "verify_artifacts_evidence_read_failed",
                reason_code = "INTERNAL_ERROR",
                "could not read artifacts.ndjson"
            );
            AppError::Internal("verify_artifacts_evidence_read_failed".to_string())
        })
    }

    /// Reconcile, then verify safety, then verify hashes, then verify
    /// residual detections — in that order. The reconcile pass returns
    /// `ReconciledArtifact` rows for every VERIFIED ledger record (the
    /// only state that produces a sanitized output to verify) so the
    /// downstream passes don't have to re-derive paths or re-parse types.
    /// Behaviour is byte-identical to the previous monolithic helper:
    /// same fail-closed reasons, same event codes, same skip semantics
    /// — every record contributes at most one failure tick because
    /// each pass only looks at the rows that survived the previous pass.
    fn verify_expected_verified_outputs(
        &self,
        evidence: &mut LoadedEvidence,
    ) -> Result<(u64, u64, HashSet<PathBuf>), AppError> {
        let reconciled = self.reconcile_artifacts(evidence)?;

        let verified_checked = reconciled.len() as u64;
        let expected_verified_paths = reconciled
            .iter()
            .map(|r| r.dest_path.clone())
            .collect::<HashSet<PathBuf>>();

        let mut failures = 0_u64;
        // Each helper takes the indices that survived the previous pass
        // and returns indices that survived its own pass. This mirrors
        // the original monolithic loop's `continue` semantics, where a
        // failure at any step short-circuits subsequent checks for that
        // row, so each artifact tallies at most one failure.
        let all_indices = (0..reconciled.len()).collect::<Vec<usize>>();
        let (safety_failures, safety_passed) =
            self.verify_safety_invariants(&reconciled, &all_indices);
        failures = failures.saturating_add(safety_failures);
        let (hash_failures, hash_passed) = self.verify_output_hashes(&reconciled, &safety_passed);
        failures = failures.saturating_add(hash_failures);
        failures =
            failures.saturating_add(self.verify_residual_detections(&reconciled, &hash_passed));

        Ok((verified_checked, failures, expected_verified_paths))
    }

    /// Walk every ledger artifact and pair it with its
    /// `artifacts.ndjson` row. Mismatches across the six compared fields
    /// (`source_locator_hash`, `size_bytes`, `artifact_type`, `state`,
    /// `quarantine_reason_code`, `output_id`) abort the verification
    /// fatally with `verify_artifacts_ledger_mismatch`. Records whose
    /// state is not VERIFIED are dropped from the returned set; only
    /// VERIFIED records produce sanitized outputs that need downstream
    /// verification.
    fn reconcile_artifacts(
        &self,
        evidence: &mut LoadedEvidence,
    ) -> Result<Vec<ReconciledArtifact>, AppError> {
        let sanitized_dir = self.pack_root.join("sanitized");
        let ledger_records = match evidence.ledger.artifact_records() {
            Ok(v) => v,
            Err(_) => {
                tracing::error!(
                    event = "verify_ledger_read_failed",
                    reason_code = "INTERNAL_ERROR",
                    "could not read ledger artifacts"
                );
                return Err(AppError::Internal("verify_ledger_read_failed".to_string()));
            }
        };

        let mut out = Vec::<ReconciledArtifact>::new();
        let mut seen_paths = HashSet::<PathBuf>::new();
        for ledger_rec in ledger_records {
            let artifact_id_hex = ledger_rec.artifact_id.to_string();
            let Some(rec) = evidence.evidence_by_artifact.remove(&artifact_id_hex) else {
                tracing::error!(
                    event = "verify_missing_artifacts_record",
                    reason_code = "INTERNAL_ERROR",
                    "artifacts.ndjson is missing a ledger artifact record"
                );
                return Err(AppError::Internal(
                    "verify_missing_artifacts_record".to_string(),
                ));
            };

            if rec.source_locator_hash != ledger_rec.source_locator_hash.to_string()
                || rec.size_bytes != ledger_rec.size_bytes
                || rec.artifact_type != ledger_rec.artifact_type
                || rec.state != ledger_rec.state.as_str()
                || rec.quarantine_reason_code != ledger_rec.quarantine_reason_code
                || rec.output_id != ledger_rec.output_id
            {
                tracing::error!(
                    event = "verify_artifacts_ledger_mismatch",
                    reason_code = "INTERNAL_ERROR",
                    "artifacts.ndjson does not match ledger state"
                );
                return Err(AppError::Internal(
                    "verify_artifacts_ledger_mismatch".to_string(),
                ));
            }

            if ledger_rec.state != veil_domain::ArtifactState::Verified {
                continue;
            }

            if ledger_rec.output_id.is_none() {
                tracing::error!(
                    event = "verify_missing_output_id",
                    reason_code = "INTERNAL_ERROR",
                    "verified artifact is missing output identity"
                );
                return Err(AppError::Internal("verify_missing_output_id".to_string()));
            }

            let sort_key = veil_domain::ArtifactSortKey::new(
                ledger_rec.artifact_id,
                ledger_rec.source_locator_hash,
            );
            let dest_path =
                sanitized_output_path_v1(&sanitized_dir, &sort_key, &ledger_rec.artifact_type);
            if !seen_paths.insert(dest_path.clone()) {
                tracing::error!(
                    event = "verify_duplicate_artifact_record",
                    reason_code = "INTERNAL_ERROR",
                    "duplicate VERIFIED artifact path detected"
                );
                return Err(AppError::Internal(
                    "verify_duplicate_artifact_record".to_string(),
                ));
            }

            out.push(ReconciledArtifact {
                ledger_rec,
                evidence_rec: rec,
                sort_key,
                dest_path,
            });
        }

        Ok(out)
    }

    /// Per-row safety invariants on each sanitized output path: the path
    /// components must be safe (no traversal segments, no NUL, etc.) and
    /// the on-disk inode must be a regular file (no symlinks, no Windows
    /// reparse points). Each violating row contributes one `failures` tick.
    /// Returns `(failure_count, indices_that_passed_safety)` so subsequent
    /// passes can short-circuit; this preserves the original loop's
    /// "fail at first violation, continue to next record" semantics.
    fn verify_safety_invariants(
        &self,
        recs: &[ReconciledArtifact],
        candidate_indices: &[usize],
    ) -> (u64, Vec<usize>) {
        let mut failures = 0_u64;
        let mut passed = Vec::<usize>::with_capacity(candidate_indices.len());
        for &idx in candidate_indices {
            let r = &recs[idx];
            if ensure_existing_path_components_safe(&r.dest_path, "sanitized output").is_err() {
                failures = failures.saturating_add(1);
                let artifact_id = r.sort_key.artifact_id.to_string();
                let source_locator_hash = r.sort_key.source_locator_hash.to_string();
                tracing::error!(
                    event = "verify_output_path_unsafe",
                    reason_code = "UNSAFE_PATH",
                    artifact_id = %artifact_id,
                    source_locator_hash = %source_locator_hash,
                    "sanitized output path is unsafe"
                );
                continue;
            }
            match std::fs::symlink_metadata(&r.dest_path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink()
                        || is_unsafe_reparse_point(&meta)
                        || !meta.is_file()
                    {
                        failures = failures.saturating_add(1);
                        let artifact_id = r.sort_key.artifact_id.to_string();
                        let source_locator_hash = r.sort_key.source_locator_hash.to_string();
                        tracing::error!(
                            event = "verify_output_path_symlink_or_non_file",
                            reason_code = "UNSAFE_PATH",
                            artifact_id = %artifact_id,
                            source_locator_hash = %source_locator_hash,
                            "sanitized output path is unsafe"
                        );
                        continue;
                    }
                }
                Err(_) => {
                    failures = failures.saturating_add(1);
                    continue;
                }
            }
            passed.push(idx);
        }
        (failures, passed)
    }

    /// `hash_output_id` of the on-disk bytes must match the
    /// `output_id` recorded in the ledger. Returns
    /// `(failure_count, indices_of_records_that_passed)`. Only the passed
    /// records survive into residual verification — there is no point
    /// re-detecting against bytes that already failed identity.
    fn verify_output_hashes(
        &self,
        recs: &[ReconciledArtifact],
        candidate_indices: &[usize],
    ) -> (u64, Vec<usize>) {
        let mut failures = 0_u64;
        let mut passed = Vec::<usize>::with_capacity(candidate_indices.len());
        for &idx in candidate_indices {
            let r = &recs[idx];
            let Some(output_id) = r.ledger_rec.output_id.as_deref() else {
                // reconcile_artifacts already aborted on missing
                // output_id; this branch is unreachable in practice but
                // kept defensive.
                failures = failures.saturating_add(1);
                continue;
            };

            let bytes = match std::fs::read(&r.dest_path) {
                Ok(b) => b,
                Err(_) => {
                    failures = failures.saturating_add(1);
                    continue;
                }
            };
            if veil_domain::hash_output_id(&bytes).to_string() != output_id {
                failures = failures.saturating_add(1);
                let artifact_id = r.sort_key.artifact_id.to_string();
                let source_locator_hash = r.sort_key.source_locator_hash.to_string();
                tracing::error!(
                    event = "verify_output_id_mismatch",
                    reason_code = "VERIFICATION_FAILED",
                    artifact_id = %artifact_id,
                    source_locator_hash = %source_locator_hash,
                    "sanitized output identity mismatch"
                );
                continue;
            }
            passed.push(idx);
        }
        (failures, passed)
    }

    /// Re-extract each sanitized output that has already passed safety +
    /// hash, re-detect against the policy, and require
    /// `residual_verify` == `Verified`. Anything else is a failure tick.
    /// This is the slowest step (it allocates a fresh detector and
    /// extracts each output) so we restrict it to the rows that survived
    /// hash verification.
    fn verify_residual_detections(
        &self,
        recs: &[ReconciledArtifact],
        passed_indices: &[usize],
    ) -> u64 {
        let extractors = veil_extract::ExtractorRegistry::default();
        let detector = veil_detect::DetectorEngineV1;
        let mut failures = 0_u64;
        for &idx in passed_indices {
            let r = &recs[idx];
            let bytes = match std::fs::read(&r.dest_path) {
                Ok(b) => b,
                Err(_) => {
                    failures = failures.saturating_add(1);
                    continue;
                }
            };

            let ctx = veil_extract::ArtifactContext {
                artifact_id: &r.sort_key.artifact_id,
                source_locator_hash: &r.sort_key.source_locator_hash,
            };
            // Reverify by re-extracting the sanitized output. Container types
            // sanitize as NDJSON; everything else round-trips as itself.
            // Unsupported artifact types cannot reach VERIFIED, so a parse
            // failure here genuinely means a tampered or corrupt pack.
            let verify_artifact_type =
                match veil_domain::ArtifactType::parse(&r.ledger_rec.artifact_type) {
                    Ok(t) => t.verification_artifact_type(),
                    Err(_) => {
                        failures = failures.saturating_add(1);
                        let artifact_id = r.sort_key.artifact_id.to_string();
                        let source_locator_hash = r.sort_key.source_locator_hash.to_string();
                        tracing::error!(
                            event = "verify_unsupported_artifact_type",
                            reason_code = "VERIFICATION_FAILED",
                            artifact_id = %artifact_id,
                            source_locator_hash = %source_locator_hash,
                            "ledger artifact_type is not a supported v1 type"
                        );
                        continue;
                    }
                };
            let extracted = extractors.extract(verify_artifact_type, ctx, &bytes);
            let canonical = match extracted {
                veil_extract::ExtractOutcome::Extracted { canonical, .. } => canonical,
                veil_extract::ExtractOutcome::Quarantined { .. } => {
                    failures = failures.saturating_add(1);
                    continue;
                }
            };

            let findings = detector.detect(self.policy, &canonical, None);
            let verification = veil_verify::residual_verify(&findings);
            if verification != veil_verify::VerificationOutcome::Verified {
                failures = failures.saturating_add(1);
            }
        }
        failures
    }

    fn verify_no_unexpected_sanitized_outputs(
        &self,
        expected_verified_paths: HashSet<PathBuf>,
        mut failures: u64,
    ) -> Result<u64, AppError> {
        let sanitized_dir = self.pack_root.join("sanitized");
        if ensure_existing_path_components_safe(&sanitized_dir, "sanitized output").is_err() {
            tracing::error!(
                event = "verify_sanitized_path_unsafe",
                reason_code = "INTERNAL_ERROR",
                "sanitized directory path is unsafe"
            );
            return Err(AppError::Internal(
                "verify_sanitized_path_unsafe".to_string(),
            ));
        }
        let sanitized_entries = match std::fs::read_dir(&sanitized_dir) {
            Ok(v) => v,
            Err(_) => {
                tracing::error!(
                    event = "verify_sanitized_read_failed",
                    reason_code = "INTERNAL_ERROR",
                    "could not read sanitized directory"
                );
                return Err(AppError::Internal(
                    "verify_sanitized_read_failed".to_string(),
                ));
            }
        };
        for entry in sanitized_entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    tracing::error!(
                        event = "verify_sanitized_entry_read_failed",
                        reason_code = "INTERNAL_ERROR",
                        "could not read sanitized directory entry"
                    );
                    return Err(AppError::Internal(
                        "verify_sanitized_entry_read_failed".to_string(),
                    ));
                }
            };
            let entry_path = entry.path();
            if ensure_existing_path_components_safe(&entry_path, "sanitized output").is_err() {
                failures = failures.saturating_add(1);
                continue;
            }
            match std::fs::symlink_metadata(&entry_path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink()
                        || is_unsafe_reparse_point(&meta)
                        || !meta.is_file()
                    {
                        failures = failures.saturating_add(1);
                        continue;
                    }
                }
                Err(_) => {
                    failures = failures.saturating_add(1);
                    continue;
                }
            }
            if !expected_verified_paths.contains(&entry_path) {
                failures = failures.saturating_add(1);
            }
        }
        Ok(failures)
    }

    fn metadata_matches(&self, ledger: &veil_evidence::Ledger) -> bool {
        let pack_manifest = self.pack_manifest();
        matches!(ledger.get_meta("run_id"), Ok(Some(v)) if v == pack_manifest.run_id)
            && matches!(ledger.get_meta("policy_id"), Ok(Some(v)) if v == pack_manifest.policy_id)
            && matches!(
                ledger.get_meta("input_corpus_id"),
                Ok(Some(v)) if v == pack_manifest.input_corpus_id
            )
    }

    fn pack_manifest(&self) -> &PackManifest {
        self.pack_manifest
            .as_ref()
            .expect("pack manifest must be loaded before use")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use veil_domain::{Digest32, PolicyId};

    fn dummy_policy() -> veil_policy::Policy {
        veil_policy::Policy {
            policy_id: PolicyId::from_digest(Digest32::from_bytes([0x11; 32])),
            classes: Vec::new(),
        }
    }

    #[test]
    fn load_pack_manifest_rejects_missing_tokenization_scope_when_enabled() {
        let pack_root = TempDir::new().expect("create temp dir");
        let manifest_path = pack_root.path().join("pack_manifest.json");
        let manifest = serde_json::json!({
            "pack_schema_version": veil_evidence::PackSchemaVersion::CURRENT.as_str(),
            "tool_version": "0.1.0",
            "run_id": "run-1",
            "policy_id": "policy-1",
            "input_corpus_id": "input-1",
            "tokenization_enabled": true,
            "quarantine_copy_enabled": false,
            "ledger_schema_version": veil_evidence::LEDGER_SCHEMA_VERSION
        });
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");

        let policy = dummy_policy();
        let verifier = PackVerifier::new(pack_root.path(), &policy);
        let err = verifier
            .load_pack_manifest()
            .expect_err("missing tokenization scope must fail closed");

        assert!(matches!(err, AppError::Manifest(_)));
    }

    #[test]
    fn open_artifacts_evidence_file_rejects_missing_ndjson() {
        let pack_root = TempDir::new().expect("create temp dir");
        let policy = dummy_policy();
        let verifier = PackVerifier::new(pack_root.path(), &policy);

        let err = verifier
            .open_artifacts_evidence_file()
            .expect_err("missing artifacts evidence must fail closed");

        assert!(matches!(err, AppError::Internal(_)));
    }
}
