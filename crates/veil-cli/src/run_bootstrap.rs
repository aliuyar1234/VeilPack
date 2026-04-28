use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

use crate::args::RunArgs;
use crate::error::AppError;
use crate::evidence_io::{TOOL_VERSION, create_pack_dirs, derive_proof_key};
use crate::fs_safety::{dir_total_file_bytes, ensure_dir_exists_or_create};
use crate::identity::{RunCryptoMeta, RunIdentity};
use crate::input_inventory::{DiscoveredArtifact, EnumeratedCorpus, enumerate_input_corpus};
use crate::logging::UNKNOWN_LOG_ID;
use crate::runtime_limits::RuntimeLimits;

// bootstrap_run owns the run-level invariants before artifact processing starts:
// policy identity, corpus identity, proof key derivation, pack directory layout,
// and safe resume semantics.
pub(crate) struct RunContext {
    pub(crate) parsed: RunArgs,
    pub(crate) runtime_limits: RuntimeLimits,
    pub(crate) archive_limits: veil_domain::ArchiveLimits,
    pub(crate) policy: veil_policy::Policy,
    pub(crate) proof_key: Zeroizing<[u8; 32]>,
    pub(crate) proof_scope: &'static str,
    pub(crate) proof_key_commitment: String,
    run_id_str: String,
    policy_id_str: String,
    input_corpus_id_str: String,
}

impl RunContext {
    pub(crate) fn run_id_str(&self) -> &str {
        &self.run_id_str
    }

    pub(crate) fn policy_id_str(&self) -> &str {
        &self.policy_id_str
    }

    pub(crate) fn input_corpus_id_str(&self) -> &str {
        &self.input_corpus_id_str
    }

    pub(crate) fn tokenization_scope(&self) -> Option<&'static str> {
        if self.parsed.enable_tokenization {
            Some(veil_domain::TokenizationScope::PerRun.as_str())
        } else {
            None
        }
    }
}

pub(crate) struct RunPaths {
    pub(crate) output: PathBuf,
    pub(crate) staging_dir: PathBuf,
    pub(crate) evidence_dir: PathBuf,
    pub(crate) quarantine_raw_dir: PathBuf,
    pub(crate) sanitized_dir: PathBuf,
    pub(crate) marker_path: PathBuf,
    pub(crate) quarantine_index_path: PathBuf,
    pub(crate) artifacts_ndjson_path: PathBuf,
}

pub(crate) struct BootstrappedRun {
    pub(crate) context: RunContext,
    pub(crate) paths: RunPaths,
    pub(crate) artifacts: Vec<DiscoveredArtifact>,
    pub(crate) ledger: veil_evidence::Ledger,
    pub(crate) proof_tokens_by_artifact: BTreeMap<veil_domain::ArtifactId, Vec<String>>,
    pub(crate) workdir_bytes_observed: u64,
}

pub(crate) fn bootstrap_run(
    exe: &str,
    parsed: RunArgs,
    runtime_limits: RuntimeLimits,
) -> Result<BootstrappedRun, AppError> {
    let _ = exe;
    let archive_limits = runtime_limits.archive_limits;

    let policy = load_policy_or_exit(&parsed.policy)?;
    let policy_id = policy.policy_id;

    let workdir = parsed
        .workdir
        .clone()
        .unwrap_or_else(|| parsed.output.join(".veil_work"));
    let marker_path = workdir.join("in_progress.marker");

    let enumerated = match enumerate_input_corpus(&parsed.input) {
        Ok(a) => a,
        Err(msg) => {
            let policy_id_for_log = policy_id.to_string();
            tracing::error!(
                event = "input_enumeration_failed",
                reason_code = "INTERNAL_ERROR",
                run_id = UNKNOWN_LOG_ID,
                policy_id = policy_id_for_log,
                detail = %msg,
                "input enumeration failed"
            );
            return Err(AppError::Internal("input_enumeration_failed".to_string()));
        }
    };
    let EnumeratedCorpus {
        artifacts,
        mut corpus_secret,
    } = enumerated;

    let mut sort_keys = artifacts
        .iter()
        .map(|a| a.sort_key)
        .collect::<Vec<veil_domain::ArtifactSortKey>>();
    let input_corpus_id = veil_domain::compute_input_corpus_id(&mut sort_keys);
    let run_id = veil_domain::compute_run_id(TOOL_VERSION, &policy_id, &input_corpus_id);

    let proof_key: Zeroizing<[u8; 32]> = {
        let proof_root_secret: Zeroizing<Vec<u8>> = if parsed.enable_tokenization {
            let key_path = match parsed.secret_key_file.as_ref() {
                Some(p) => p,
                None => {
                    return Err(AppError::Usage(
                        "--enable-tokenization true requires --secret-key-file".to_string(),
                    ));
                }
            };
            let key_bytes = match std::fs::read(key_path) {
                Ok(b) => b,
                Err(_) => {
                    return Err(AppError::Usage("secret-key-file is unreadable".to_string()));
                }
            };
            Zeroizing::new(key_bytes)
        } else {
            Zeroizing::new(corpus_secret.to_vec())
        };

        Zeroizing::new(derive_proof_key(&proof_root_secret, &run_id))
    };
    corpus_secret.zeroize();

    let proof_key_commitment = blake3::hash(&*proof_key).to_hex().to_string();
    let proof_scope = veil_domain::TokenizationScope::PerRun.as_str();

    let policy_id_str = policy_id.to_string();
    let input_corpus_id_str = input_corpus_id.to_string();
    let run_id_str = run_id.to_string();

    let requested_workers = parsed.max_workers.unwrap_or(1);
    log_run_start(
        &run_id_str,
        &policy_id_str,
        artifacts.len(),
        requested_workers,
    );

    let is_resume = std::fs::metadata(&marker_path)
        .map(|m| m.is_file())
        .unwrap_or(false);

    let evidence_dir = parsed.output.join("evidence");
    let ledger_path = evidence_dir.join("ledger.sqlite3");

    if is_resume && !resume_quarantine_mode_matches(&parsed) {
        return Err(AppError::Usage(
            "cannot resume with different --quarantine-copy setting".to_string(),
        ));
    }

    if let Err(msg) = create_pack_dirs(&parsed.output, parsed.quarantine_copy) {
        tracing::error!(
            event = "create_pack_dirs_failed",
            reason_code = "INTERNAL_ERROR",
            run_id = %run_id_str,
            policy_id = %policy_id_str,
            detail = %msg,
            "create pack dirs failed"
        );
        return Err(AppError::Internal("create_pack_dirs_failed".to_string()));
    }

    if let Err(msg) = ensure_dir_exists_or_create(&workdir, "workdir") {
        tracing::error!(
            event = "create_workdir_failed",
            reason_code = "INTERNAL_ERROR",
            run_id = %run_id_str,
            policy_id = %policy_id_str,
            detail = %msg,
            "create workdir failed"
        );
        return Err(AppError::Internal("create_workdir_failed".to_string()));
    }

    let tokenization_enabled_meta = if parsed.enable_tokenization {
        "true"
    } else {
        "false"
    };
    let tokenization_scope_meta = if parsed.enable_tokenization {
        veil_domain::TokenizationScope::PerRun.as_str()
    } else {
        "NONE"
    };

    let ledger = if is_resume {
        resume_ledger(
            &ledger_path,
            &marker_path,
            &run_id_str,
            &policy_id_str,
            &input_corpus_id_str,
            proof_scope,
            &proof_key_commitment,
            tokenization_enabled_meta,
            tokenization_scope_meta,
        )?
    } else {
        create_new_ledger(
            &ledger_path,
            &marker_path,
            &run_id_str,
            &policy_id,
            &run_id,
            &input_corpus_id,
            proof_scope,
            &proof_key_commitment,
            tokenization_enabled_meta,
            tokenization_scope_meta,
            &policy_id_str,
        )?
    };

    let quarantine_dir = parsed.output.join("quarantine");
    let quarantine_raw_dir = quarantine_dir.join("raw");
    let quarantine_index_path = quarantine_dir.join("index.ndjson");
    let artifacts_ndjson_path = evidence_dir.join("artifacts.ndjson");
    let sanitized_dir = parsed.output.join("sanitized");
    let staging_dir = workdir.join("staging");
    if std::fs::create_dir_all(&staging_dir).is_err() {
        tracing::error!(
            event = "create_staging_dir_failed",
            reason_code = "INTERNAL_ERROR",
            run_id = %run_id_str,
            policy_id = %policy_id_str,
            "could not create staging directory"
        );
        return Err(AppError::Internal("create_staging_dir_failed".to_string()));
    }

    let workdir_bytes_observed = match dir_total_file_bytes(&workdir) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!(
                event = "workdir_usage_scan_failed",
                reason_code = "INTERNAL_ERROR",
                run_id = %run_id_str,
                policy_id = %policy_id_str,
                "could not measure workdir usage"
            );
            return Err(AppError::Internal("workdir_usage_scan_failed".to_string()));
        }
    };
    if workdir_bytes_observed > runtime_limits.max_workdir_bytes {
        tracing::error!(
            event = "workdir_usage_limit_exceeded",
            reason_code = "LIMIT_EXCEEDED",
            run_id = %run_id_str,
            policy_id = %policy_id_str,
            "workdir usage exceeds configured limit"
        );
        return Err(AppError::LimitExceeded {
            what: "workdir_usage",
        });
    }

    let mut proof_tokens_by_artifact = BTreeMap::<veil_domain::ArtifactId, Vec<String>>::new();
    if is_resume {
        // Pack v2 stores proof tokens in the ledger DB; resume rehydrates
        // the in-memory map from there instead of parsing
        // `evidence/artifacts.ndjson`. The migrator already upgraded a v1
        // ledger by this point so `proof_tokens_for` always succeeds —
        // returning an empty vec for legacy v1 packs that never wrote
        // tokens to the table.
        let records = match ledger.artifact_records() {
            Ok(r) => r,
            Err(_) => {
                tracing::error!(
                    event = "resume_proof_tokens_read_failed",
                    reason_code = "INTERNAL_ERROR",
                    run_id = %run_id_str,
                    policy_id = %policy_id_str,
                    "could not load existing proof tokens"
                );
                return Err(AppError::Internal(
                    "resume_proof_tokens_read_failed".to_string(),
                ));
            }
        };
        for rec in records {
            let tokens = match ledger.proof_tokens_for(&rec.artifact_id) {
                Ok(t) => t,
                Err(_) => {
                    tracing::error!(
                        event = "resume_proof_tokens_read_failed",
                        reason_code = "INTERNAL_ERROR",
                        run_id = %run_id_str,
                        policy_id = %policy_id_str,
                        "could not load existing proof tokens"
                    );
                    return Err(AppError::Internal(
                        "resume_proof_tokens_read_failed".to_string(),
                    ));
                }
            };
            if !tokens.is_empty() {
                proof_tokens_by_artifact.insert(rec.artifact_id, tokens);
            }
        }
    }

    let output_path = parsed.output.clone();

    Ok(BootstrappedRun {
        context: RunContext {
            parsed,
            runtime_limits,
            archive_limits,
            policy,
            proof_key,
            proof_scope,
            proof_key_commitment,
            run_id_str,
            policy_id_str,
            input_corpus_id_str,
        },
        paths: RunPaths {
            output: output_path,
            staging_dir,
            evidence_dir,
            quarantine_raw_dir,
            sanitized_dir,
            marker_path,
            quarantine_index_path,
            artifacts_ndjson_path,
        },
        artifacts,
        ledger,
        proof_tokens_by_artifact,
        workdir_bytes_observed,
    })
}

fn load_policy_or_exit(policy_dir: &Path) -> Result<veil_policy::Policy, AppError> {
    veil_policy::load_policy_bundle(policy_dir)
        .map_err(|_| AppError::Usage("policy bundle is invalid or unreadable".to_string()))
}

fn log_run_start(
    run_id: &str,
    policy_id: &str,
    artifacts_discovered: usize,
    requested_workers: u32,
) {
    tracing::info!(
        event = "run_started",
        run_id = run_id,
        policy_id = policy_id,
        artifacts_discovered = artifacts_discovered as u64,
        max_workers_requested = u64::from(requested_workers),
        "run started"
    );
    // Phase 4 honors `--max-workers > 1` by spawning a real worker pool;
    // the legacy `max_workers_single_threaded_baseline` advisory has been
    // retired now that the flag is no longer ignored. The
    // `max_workers_requested` field on `run_started` carries the
    // requested worker count for downstream tooling.
}

fn resume_quarantine_mode_matches(parsed: &RunArgs) -> bool {
    let raw_dir = parsed.output.join("quarantine").join("raw");
    raw_dir.exists() == parsed.quarantine_copy
}

#[allow(clippy::too_many_arguments)]
fn resume_ledger(
    ledger_path: &Path,
    marker_path: &Path,
    run_id_str: &str,
    policy_id_str: &str,
    input_corpus_id_str: &str,
    proof_scope: &str,
    proof_key_commitment: &str,
    tokenization_enabled_meta: &str,
    tokenization_scope_meta: &str,
) -> Result<veil_evidence::Ledger, AppError> {
    let marker_run_id = match std::fs::read_to_string(marker_path) {
        Ok(s) => s,
        Err(_) => {
            tracing::error!(
                event = "resume_marker_read_failed",
                reason_code = "INTERNAL_ERROR",
                run_id = %run_id_str,
                policy_id = %policy_id_str,
                "could not read in-progress marker"
            );
            return Err(AppError::Internal("resume_marker_read_failed".to_string()));
        }
    };
    if marker_run_id.trim() != run_id_str {
        return Err(AppError::Usage(
            "output directory contains an in-progress marker for a different run".to_string(),
        ));
    }

    let ledger = match veil_evidence::Ledger::open_existing(ledger_path) {
        Ok(l) => l,
        Err(_) => {
            tracing::error!(
                event = "resume_ledger_open_failed",
                reason_code = "INTERNAL_ERROR",
                run_id = %run_id_str,
                policy_id = %policy_id_str,
                "could not open ledger.sqlite3 for resume"
            );
            return Err(AppError::Internal("resume_ledger_open_failed".to_string()));
        }
    };

    let identity = RunIdentity {
        run_id: run_id_str,
        policy_id: policy_id_str,
        input_corpus_id: input_corpus_id_str,
    };
    identity.verify_against(&ledger)?;

    let crypto_meta = RunCryptoMeta {
        proof_scope,
        proof_key_commitment,
        tokenization_enabled: tokenization_enabled_meta,
        tokenization_scope: tokenization_scope_meta,
    };
    crypto_meta.verify_or_seed_against(&ledger)?;

    Ok(ledger)
}

#[allow(clippy::too_many_arguments)]
fn create_new_ledger(
    ledger_path: &Path,
    marker_path: &Path,
    run_id_str: &str,
    policy_id: &veil_domain::PolicyId,
    run_id: &veil_domain::RunId,
    input_corpus_id: &veil_domain::InputCorpusId,
    proof_scope: &str,
    proof_key_commitment: &str,
    tokenization_enabled_meta: &str,
    tokenization_scope_meta: &str,
    policy_id_str: &str,
) -> Result<veil_evidence::Ledger, AppError> {
    if std::fs::write(marker_path, run_id_str).is_err() {
        tracing::error!(
            event = "write_resume_marker_failed",
            reason_code = "INTERNAL_ERROR",
            run_id = %run_id_str,
            policy_id = %policy_id_str,
            "could not write in-progress marker"
        );
        return Err(AppError::Internal("write_resume_marker_failed".to_string()));
    }

    match veil_evidence::Ledger::create_new(
        ledger_path,
        TOOL_VERSION,
        policy_id,
        run_id,
        input_corpus_id,
    ) {
        Ok(l) => {
            if l.upsert_meta("proof_scope", proof_scope).is_err()
                || l.upsert_meta("proof_key_commitment", proof_key_commitment)
                    .is_err()
                || l.upsert_meta("tokenization_enabled", tokenization_enabled_meta)
                    .is_err()
                || l.upsert_meta("tokenization_scope", tokenization_scope_meta)
                    .is_err()
            {
                tracing::error!(
                    event = "ledger_write_failed",
                    reason_code = "INTERNAL_ERROR",
                    run_id = %run_id_str,
                    policy_id = %policy_id_str,
                    "ledger write failed"
                );
                return Err(AppError::Internal("ledger_write_failed".to_string()));
            }
            Ok(l)
        }
        Err(_) => {
            tracing::error!(
                event = "create_ledger_failed",
                reason_code = "INTERNAL_ERROR",
                run_id = %run_id_str,
                policy_id = %policy_id_str,
                "could not create ledger.sqlite3"
            );
            Err(AppError::Internal("create_ledger_failed".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_temp_dir() -> TempDir {
        TempDir::new().expect("create temp dir")
    }

    fn test_run_args(output: &Path, quarantine_copy: bool) -> RunArgs {
        RunArgs {
            input: PathBuf::from("input"),
            output: output.to_path_buf(),
            policy: PathBuf::from("policy"),
            workdir: None,
            max_workers: None,
            strictness: None,
            enable_tokenization: false,
            secret_key_file: None,
            quarantine_copy,
            isolate_risky_extractors: false,
            limits_json: None,
        }
    }

    #[test]
    fn resume_quarantine_mode_matches_raw_dir_presence() {
        let output = test_temp_dir();

        let args_without_copy = test_run_args(output.path(), false);
        assert!(resume_quarantine_mode_matches(&args_without_copy));

        let raw_dir = output.path().join("quarantine").join("raw");
        std::fs::create_dir_all(&raw_dir).expect("create quarantine raw dir");

        let args_with_copy = test_run_args(output.path(), true);
        assert!(resume_quarantine_mode_matches(&args_with_copy));

        assert!(!resume_quarantine_mode_matches(&args_without_copy));

        let missing_raw = test_temp_dir();
        let args_missing_raw = test_run_args(missing_raw.path(), true);
        assert!(!resume_quarantine_mode_matches(&args_missing_raw));
    }

    #[test]
    fn load_policy_or_exit_returns_usage_for_missing_bundle() {
        let tmp = test_temp_dir();
        let missing_policy_dir = tmp.path().join("policy");
        let err = load_policy_or_exit(&missing_policy_dir).expect_err("missing policy");
        assert!(matches!(err, AppError::Usage(_)));
    }
}
