use std::collections::{BTreeMap, HashSet};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use veil_detect::DetectorEngine;

use crate::evidence_io::{
    ArtifactEvidenceRecordOwned, PackManifestJsonV1Read, sanitized_output_path_v1,
    verification_artifact_type_v1,
};
use crate::fs_safety::{
    ensure_existing_file_safe, ensure_existing_path_components_safe, is_unsafe_reparse_point,
};
use crate::logging::{LogContext, log_artifact_error, log_error, log_info};
use crate::{EXIT_FATAL, EXIT_OK, EXIT_QUARANTINED, PACK_SCHEMA_VERSION};

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

pub(crate) struct PackVerifier<'a> {
    pack_root: &'a Path,
    policy: &'a veil_policy::Policy,
    pack_manifest: Option<PackManifestJsonV1Read>,
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
        let pack_manifest = match self.load_pack_manifest() {
            Ok(v) => v,
            Err(code) => return PackVerifyResult::Exit(code),
        };
        self.pack_manifest = Some(pack_manifest);

        log_info(self.log_ctx(), "verify_started", None);

        if self.pack_manifest().policy_id != self.policy.policy_id.to_string() {
            return PackVerifyResult::Usage("policy_id mismatch for verify (redacted)".to_string());
        }

        let mut evidence = match self.load_validate_evidence() {
            Ok(v) => v,
            Err(code) => return PackVerifyResult::Exit(code),
        };

        let (verified_checked, failures, expected_verified_paths) =
            match self.verify_expected_verified_outputs(&mut evidence) {
                Ok(v) => v,
                Err(code) => return PackVerifyResult::Exit(code),
            };

        if !evidence.evidence_by_artifact.is_empty() {
            log_error(
                self.log_ctx(),
                "verify_extra_artifacts_records",
                "INTERNAL_ERROR",
                Some("artifacts.ndjson contains records not present in ledger (redacted)"),
            );
            return PackVerifyResult::Exit(ExitCode::from(EXIT_FATAL));
        }

        let failures =
            match self.verify_no_unexpected_sanitized_outputs(expected_verified_paths, failures) {
                Ok(v) => v,
                Err(code) => return PackVerifyResult::Exit(code),
            };

        let mut verify_complete = BTreeMap::<&str, u64>::new();
        verify_complete.insert("verified_checked", verified_checked);
        verify_complete.insert("verification_failures", failures);
        log_info(self.log_ctx(), "verify_completed", Some(verify_complete));

        if failures > 0 {
            PackVerifyResult::Exit(ExitCode::from(EXIT_QUARANTINED))
        } else {
            PackVerifyResult::Exit(ExitCode::from(EXIT_OK))
        }
    }

    fn load_pack_manifest(&self) -> Result<PackManifestJsonV1Read, ExitCode> {
        let pack_manifest_path = self.pack_root.join("pack_manifest.json");
        if ensure_existing_file_safe(&pack_manifest_path, "pack manifest").is_err() {
            log_error(
                self.log_ctx(),
                "verify_pack_manifest_unsafe",
                "INTERNAL_ERROR",
                Some("pack_manifest.json path is unsafe (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
        let pack_manifest_json = match std::fs::read_to_string(&pack_manifest_path) {
            Ok(s) => s,
            Err(_) => {
                log_error(
                    self.log_ctx(),
                    "verify_pack_manifest_read_failed",
                    "INTERNAL_ERROR",
                    Some("could not read pack_manifest.json (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }
        };
        let pack_manifest: PackManifestJsonV1Read = match serde_json::from_str(&pack_manifest_json)
        {
            Ok(v) => v,
            Err(_) => {
                log_error(
                    self.log_ctx(),
                    "verify_pack_manifest_parse_failed",
                    "INTERNAL_ERROR",
                    Some("pack_manifest.json is invalid JSON (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }
        };

        if pack_manifest.pack_schema_version != PACK_SCHEMA_VERSION {
            log_error(
                LogContext::new(&pack_manifest.run_id, &pack_manifest.policy_id),
                "verify_pack_schema_unsupported",
                "INTERNAL_ERROR",
                Some("unsupported pack_schema_version (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        if pack_manifest.tool_version.trim().is_empty()
            || pack_manifest.run_id.trim().is_empty()
            || pack_manifest.input_corpus_id.trim().is_empty()
        {
            log_error(
                LogContext::new(&pack_manifest.run_id, &pack_manifest.policy_id),
                "verify_pack_manifest_missing_fields",
                "INTERNAL_ERROR",
                Some("pack_manifest.json is missing required fields (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
        let _ = pack_manifest.quarantine_copy_enabled;

        if pack_manifest.ledger_schema_version != veil_evidence::LEDGER_SCHEMA_VERSION {
            log_error(
                LogContext::new(&pack_manifest.run_id, &pack_manifest.policy_id),
                "verify_ledger_schema_unsupported",
                "INTERNAL_ERROR",
                Some("unsupported ledger schema_version (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        if pack_manifest.tokenization_enabled && pack_manifest.tokenization_scope.is_none() {
            log_error(
                LogContext::new(&pack_manifest.run_id, &pack_manifest.policy_id),
                "verify_invalid_tokenization_scope",
                "INTERNAL_ERROR",
                Some("invalid tokenization scope metadata (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
        if !pack_manifest.tokenization_enabled && pack_manifest.tokenization_scope.is_some() {
            log_error(
                LogContext::new(&pack_manifest.run_id, &pack_manifest.policy_id),
                "verify_invalid_tokenization_scope",
                "INTERNAL_ERROR",
                Some("invalid tokenization scope metadata (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        Ok(pack_manifest)
    }

    fn load_validate_evidence(&self) -> Result<LoadedEvidence, ExitCode> {
        let ledger = self.open_existing_ledger()?;
        if !self.metadata_matches(&ledger) {
            log_error(
                self.log_ctx(),
                "verify_ledger_metadata_mismatch",
                "INTERNAL_ERROR",
                Some("ledger metadata does not match pack manifest (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        let artifacts_file = self.open_artifacts_evidence_file()?;
        let reader = std::io::BufReader::new(artifacts_file);

        let mut evidence_by_artifact = BTreeMap::<String, ArtifactEvidenceRecordOwned>::new();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => {
                    log_error(
                        self.log_ctx(),
                        "verify_artifacts_line_read_failed",
                        "INTERNAL_ERROR",
                        Some("could not read artifacts.ndjson line (redacted)"),
                    );
                    return Err(ExitCode::from(EXIT_FATAL));
                }
            };
            if line.trim().is_empty() {
                continue;
            }

            let rec: ArtifactEvidenceRecordOwned = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => {
                    log_error(
                        self.log_ctx(),
                        "verify_artifacts_record_parse_failed",
                        "INTERNAL_ERROR",
                        Some("artifacts.ndjson record is invalid JSON (redacted)"),
                    );
                    return Err(ExitCode::from(EXIT_FATAL));
                }
            };
            if evidence_by_artifact
                .insert(rec.artifact_id.clone(), rec)
                .is_some()
            {
                log_error(
                    self.log_ctx(),
                    "verify_duplicate_artifact_record",
                    "INTERNAL_ERROR",
                    Some("artifacts.ndjson contains duplicate artifact_id (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }
        }

        let ledger_records = match ledger.artifact_records() {
            Ok(v) => v,
            Err(_) => {
                log_error(
                    self.log_ctx(),
                    "verify_ledger_read_failed",
                    "INTERNAL_ERROR",
                    Some("could not read ledger artifacts (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }
        };
        if ledger_records.len() != evidence_by_artifact.len() {
            log_error(
                self.log_ctx(),
                "verify_evidence_count_mismatch",
                "INTERNAL_ERROR",
                Some("ledger and artifacts evidence differ (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        Ok(LoadedEvidence {
            ledger,
            evidence_by_artifact,
        })
    }

    fn open_existing_ledger(&self) -> Result<veil_evidence::Ledger, ExitCode> {
        let ledger_path = self.pack_root.join("evidence").join("ledger.sqlite3");
        if ensure_existing_file_safe(&ledger_path, "ledger").is_err() {
            log_error(
                self.log_ctx(),
                "verify_ledger_unsafe",
                "INTERNAL_ERROR",
                Some("ledger.sqlite3 path is unsafe (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        veil_evidence::Ledger::open_existing(&ledger_path).map_err(|_| {
            log_error(
                self.log_ctx(),
                "verify_ledger_open_failed",
                "INTERNAL_ERROR",
                Some("could not open ledger.sqlite3 (redacted)"),
            );
            ExitCode::from(EXIT_FATAL)
        })
    }

    fn open_artifacts_evidence_file(&self) -> Result<std::fs::File, ExitCode> {
        let artifacts_path = self.pack_root.join("evidence").join("artifacts.ndjson");
        if ensure_existing_file_safe(&artifacts_path, "artifacts evidence").is_err() {
            log_error(
                self.log_ctx(),
                "verify_artifacts_evidence_unsafe",
                "INTERNAL_ERROR",
                Some("artifacts.ndjson path is unsafe (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }

        std::fs::File::open(&artifacts_path).map_err(|_| {
            log_error(
                self.log_ctx(),
                "verify_artifacts_evidence_read_failed",
                "INTERNAL_ERROR",
                Some("could not read artifacts.ndjson (redacted)"),
            );
            ExitCode::from(EXIT_FATAL)
        })
    }

    fn verify_expected_verified_outputs(
        &self,
        evidence: &mut LoadedEvidence,
    ) -> Result<(u64, u64, HashSet<PathBuf>), ExitCode> {
        let sanitized_dir = self.pack_root.join("sanitized");
        let extractors = veil_extract::ExtractorRegistry::default();
        let detector = veil_detect::DetectorEngineV1;

        let ledger_records = match evidence.ledger.artifact_records() {
            Ok(v) => v,
            Err(_) => {
                log_error(
                    self.log_ctx(),
                    "verify_ledger_read_failed",
                    "INTERNAL_ERROR",
                    Some("could not read ledger artifacts (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }
        };

        let mut failures = 0_u64;
        let mut verified_checked = 0_u64;
        let mut expected_verified_paths = HashSet::<PathBuf>::new();
        for ledger_rec in ledger_records {
            let artifact_id_hex = ledger_rec.artifact_id.to_string();
            let Some(rec) = evidence.evidence_by_artifact.remove(&artifact_id_hex) else {
                log_error(
                    self.log_ctx(),
                    "verify_missing_artifacts_record",
                    "INTERNAL_ERROR",
                    Some("artifacts.ndjson is missing a ledger artifact record (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            };

            if rec.source_locator_hash != ledger_rec.source_locator_hash.to_string()
                || rec.size_bytes != ledger_rec.size_bytes
                || rec.artifact_type != ledger_rec.artifact_type
                || rec.state != ledger_rec.state.as_str()
                || rec.quarantine_reason_code != ledger_rec.quarantine_reason_code
                || rec.output_id != ledger_rec.output_id
            {
                log_error(
                    self.log_ctx(),
                    "verify_artifacts_ledger_mismatch",
                    "INTERNAL_ERROR",
                    Some("artifacts.ndjson does not match ledger state (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }

            if ledger_rec.state != veil_domain::ArtifactState::Verified {
                continue;
            }
            verified_checked = verified_checked.saturating_add(1);

            let Some(output_id) = ledger_rec.output_id.as_deref() else {
                log_error(
                    self.log_ctx(),
                    "verify_missing_output_id",
                    "INTERNAL_ERROR",
                    Some("verified artifact is missing output identity (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            };

            let sort_key = veil_domain::ArtifactSortKey::new(
                ledger_rec.artifact_id,
                ledger_rec.source_locator_hash,
            );
            let path =
                sanitized_output_path_v1(&sanitized_dir, &sort_key, &ledger_rec.artifact_type);
            if !expected_verified_paths.insert(path.clone()) {
                log_error(
                    self.log_ctx(),
                    "verify_duplicate_artifact_record",
                    "INTERNAL_ERROR",
                    Some("duplicate VERIFIED artifact path detected (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }

            if ensure_existing_path_components_safe(&path, "sanitized output").is_err() {
                failures = failures.saturating_add(1);
                log_artifact_error(
                    self.log_ctx(),
                    "verify_output_path_unsafe",
                    "UNSAFE_PATH",
                    &sort_key,
                    Some("sanitized output path is unsafe (redacted)"),
                );
                continue;
            }
            match std::fs::symlink_metadata(&path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink()
                        || is_unsafe_reparse_point(&meta)
                        || !meta.is_file()
                    {
                        failures = failures.saturating_add(1);
                        log_artifact_error(
                            self.log_ctx(),
                            "verify_output_path_symlink_or_non_file",
                            "UNSAFE_PATH",
                            &sort_key,
                            Some("sanitized output path is unsafe (redacted)"),
                        );
                        continue;
                    }
                }
                Err(_) => {
                    failures = failures.saturating_add(1);
                    continue;
                }
            }

            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => {
                    failures = failures.saturating_add(1);
                    continue;
                }
            };
            if veil_domain::hash_output_id(&bytes).to_string() != output_id {
                failures = failures.saturating_add(1);
                log_artifact_error(
                    self.log_ctx(),
                    "verify_output_id_mismatch",
                    "VERIFICATION_FAILED",
                    &sort_key,
                    Some("sanitized output identity mismatch (redacted)"),
                );
                continue;
            }

            let ctx = veil_extract::ArtifactContext {
                artifact_id: &sort_key.artifact_id,
                source_locator_hash: &sort_key.source_locator_hash,
            };
            let verify_artifact_type = verification_artifact_type_v1(&ledger_rec.artifact_type);
            let extracted = extractors.extract_by_type(verify_artifact_type, ctx, &bytes);
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

        Ok((verified_checked, failures, expected_verified_paths))
    }

    fn verify_no_unexpected_sanitized_outputs(
        &self,
        expected_verified_paths: HashSet<PathBuf>,
        mut failures: u64,
    ) -> Result<u64, ExitCode> {
        let sanitized_dir = self.pack_root.join("sanitized");
        if ensure_existing_path_components_safe(&sanitized_dir, "sanitized output").is_err() {
            log_error(
                self.log_ctx(),
                "verify_sanitized_path_unsafe",
                "INTERNAL_ERROR",
                Some("sanitized directory path is unsafe (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
        let sanitized_entries = match std::fs::read_dir(&sanitized_dir) {
            Ok(v) => v,
            Err(_) => {
                log_error(
                    self.log_ctx(),
                    "verify_sanitized_read_failed",
                    "INTERNAL_ERROR",
                    Some("could not read sanitized directory (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }
        };
        for entry in sanitized_entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    log_error(
                        self.log_ctx(),
                        "verify_sanitized_entry_read_failed",
                        "INTERNAL_ERROR",
                        Some("could not read sanitized directory entry (redacted)"),
                    );
                    return Err(ExitCode::from(EXIT_FATAL));
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

    fn pack_manifest(&self) -> &PackManifestJsonV1Read {
        self.pack_manifest
            .as_ref()
            .expect("pack manifest must be loaded before use")
    }

    fn log_ctx(&self) -> LogContext<'_> {
        match self.pack_manifest.as_ref() {
            Some(pack_manifest) => LogContext::new(&pack_manifest.run_id, &pack_manifest.policy_id),
            None => LogContext::unknown(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use veil_domain::{Digest32, PolicyId};

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("veil-cli-{name}-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn dummy_policy() -> veil_policy::Policy {
        veil_policy::Policy {
            policy_id: PolicyId::from_digest(Digest32::from_bytes([0x11; 32])),
            classes: Vec::new(),
        }
    }

    #[test]
    fn load_pack_manifest_rejects_missing_tokenization_scope_when_enabled() {
        let pack_root = TempDirGuard::new("verify-pack-manifest");
        let manifest_path = pack_root.path().join("pack_manifest.json");
        let manifest = serde_json::json!({
            "pack_schema_version": PACK_SCHEMA_VERSION,
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

        assert_eq!(err, ExitCode::from(crate::EXIT_FATAL));
    }

    #[test]
    fn open_artifacts_evidence_file_rejects_missing_ndjson() {
        let pack_root = TempDirGuard::new("verify-artifacts-ndjson");
        let policy = dummy_policy();
        let verifier = PackVerifier::new(pack_root.path(), &policy);

        let err = verifier
            .open_artifacts_evidence_file()
            .expect_err("missing artifacts evidence must fail closed");

        assert_eq!(err, ExitCode::from(crate::EXIT_FATAL));
    }
}
