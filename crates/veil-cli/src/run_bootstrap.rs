use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use zeroize::{Zeroize, Zeroizing};

use crate::args::{RunArgs, exit_usage};
use crate::evidence_io::{
    TOOL_VERSION, create_pack_dirs, derive_proof_key, load_existing_proof_tokens,
    validate_or_seed_resume_meta,
};
use crate::fs_safety::{dir_total_file_bytes, ensure_dir_exists_or_create};
use crate::input_inventory::{DiscoveredArtifact, EnumeratedCorpus, enumerate_input_corpus};
use crate::logging::{LogContext, UNKNOWN_LOG_ID, log_error, log_info, log_warn};
use crate::runtime_limits::RuntimeLimits;
use crate::{EXIT_FATAL, print_run_help};

// bootstrap_run owns the run-level invariants before artifact processing starts:
// policy identity, corpus identity, proof key derivation, pack directory layout,
// and safe resume semantics.
pub(crate) struct RunContext {
    pub(crate) parsed: RunArgs,
    pub(crate) runtime_limits: RuntimeLimits,
    pub(crate) archive_limits: veil_domain::ArchiveLimits,
    pub(crate) policy: veil_policy::Policy,
    #[allow(dead_code)]
    pub(crate) run_id: veil_domain::RunId,
    #[allow(dead_code)]
    pub(crate) input_corpus_id: veil_domain::InputCorpusId,
    pub(crate) proof_key: Zeroizing<[u8; 32]>,
    pub(crate) proof_scope: &'static str,
    pub(crate) proof_key_commitment: String,
    #[allow(dead_code)]
    pub(crate) tokenization_enabled_meta: &'static str,
    #[allow(dead_code)]
    pub(crate) tokenization_scope_meta: &'static str,
    run_id_str: String,
    policy_id_str: String,
    input_corpus_id_str: String,
}

impl RunContext {
    pub(crate) fn log_ctx(&self) -> LogContext<'_> {
        LogContext::new(&self.run_id_str, &self.policy_id_str)
    }

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
    #[allow(dead_code)]
    pub(crate) workdir: PathBuf,
    pub(crate) staging_dir: PathBuf,
    pub(crate) evidence_dir: PathBuf,
    #[allow(dead_code)]
    pub(crate) quarantine_dir: PathBuf,
    pub(crate) quarantine_raw_dir: PathBuf,
    pub(crate) sanitized_dir: PathBuf,
    pub(crate) marker_path: PathBuf,
    #[allow(dead_code)]
    pub(crate) ledger_path: PathBuf,
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
) -> Result<BootstrappedRun, ExitCode> {
    let archive_limits = runtime_limits.archive_limits;

    let policy = load_policy_or_exit(exe, &parsed.policy)?;
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
            log_error(
                LogContext::new(UNKNOWN_LOG_ID, &policy_id_for_log),
                "input_enumeration_failed",
                "INTERNAL_ERROR",
                Some(msg.as_str()),
            );
            return Err(ExitCode::from(EXIT_FATAL));
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
                    return Err(exit_usage(
                        exe,
                        "--enable-tokenization true requires --secret-key-file",
                        print_run_help,
                    ));
                }
            };
            let key_bytes = match std::fs::read(key_path) {
                Ok(b) => b,
                Err(_) => {
                    return Err(exit_usage(
                        exe,
                        "secret-key-file is unreadable (redacted)",
                        print_run_help,
                    ));
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
    let log_ctx = LogContext::new(&run_id_str, &policy_id_str);

    let requested_workers = parsed.max_workers.unwrap_or(1);
    log_run_start(log_ctx, artifacts.len(), requested_workers);

    let is_resume = std::fs::metadata(&marker_path)
        .map(|m| m.is_file())
        .unwrap_or(false);

    let evidence_dir = parsed.output.join("evidence");
    let ledger_path = evidence_dir.join("ledger.sqlite3");

    if is_resume && !resume_quarantine_mode_matches(&parsed) {
        return Err(exit_usage(
            exe,
            "cannot resume with different --quarantine-copy setting (redacted)",
            print_run_help,
        ));
    }

    if let Err(msg) = create_pack_dirs(&parsed.output, parsed.quarantine_copy) {
        log_error(
            log_ctx,
            "create_pack_dirs_failed",
            "INTERNAL_ERROR",
            Some(msg.as_str()),
        );
        return Err(ExitCode::from(EXIT_FATAL));
    }

    if let Err(msg) = ensure_dir_exists_or_create(&workdir, "workdir") {
        log_error(
            log_ctx,
            "create_workdir_failed",
            "INTERNAL_ERROR",
            Some(msg.as_str()),
        );
        return Err(ExitCode::from(EXIT_FATAL));
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
            exe,
            &ledger_path,
            &marker_path,
            &run_id_str,
            &policy_id_str,
            &input_corpus_id_str,
            proof_scope,
            &proof_key_commitment,
            tokenization_enabled_meta,
            tokenization_scope_meta,
            log_ctx,
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
            log_ctx,
        )?
    };

    let quarantine_dir = parsed.output.join("quarantine");
    let quarantine_raw_dir = quarantine_dir.join("raw");
    let quarantine_index_path = quarantine_dir.join("index.ndjson");
    let artifacts_ndjson_path = evidence_dir.join("artifacts.ndjson");
    let sanitized_dir = parsed.output.join("sanitized");
    let staging_dir = workdir.join("staging");
    if std::fs::create_dir_all(&staging_dir).is_err() {
        log_error(
            log_ctx,
            "create_staging_dir_failed",
            "INTERNAL_ERROR",
            Some("could not create staging directory (redacted)"),
        );
        return Err(ExitCode::from(EXIT_FATAL));
    }

    let workdir_bytes_observed = match dir_total_file_bytes(&workdir) {
        Ok(v) => v,
        Err(_) => {
            log_error(
                log_ctx,
                "workdir_usage_scan_failed",
                "INTERNAL_ERROR",
                Some("could not measure workdir usage (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
    };
    if workdir_bytes_observed > runtime_limits.max_workdir_bytes {
        log_error(
            log_ctx,
            "workdir_usage_limit_exceeded",
            "LIMIT_EXCEEDED",
            Some("workdir usage exceeds configured limit (redacted)"),
        );
        return Err(ExitCode::from(EXIT_FATAL));
    }

    let mut proof_tokens_by_artifact = BTreeMap::<veil_domain::ArtifactId, Vec<String>>::new();
    if is_resume {
        match load_existing_proof_tokens(&artifacts_ndjson_path) {
            Ok(m) => proof_tokens_by_artifact = m,
            Err(_) => {
                log_error(
                    log_ctx,
                    "resume_proof_tokens_read_failed",
                    "INTERNAL_ERROR",
                    Some("could not load existing proof tokens (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
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
            run_id,
            input_corpus_id,
            proof_key,
            proof_scope,
            proof_key_commitment,
            tokenization_enabled_meta,
            tokenization_scope_meta,
            run_id_str,
            policy_id_str,
            input_corpus_id_str,
        },
        paths: RunPaths {
            output: output_path,
            workdir,
            staging_dir,
            evidence_dir,
            quarantine_dir,
            quarantine_raw_dir,
            sanitized_dir,
            marker_path,
            ledger_path,
            quarantine_index_path,
            artifacts_ndjson_path,
        },
        artifacts,
        ledger,
        proof_tokens_by_artifact,
        workdir_bytes_observed,
    })
}

fn load_policy_or_exit(exe: &str, policy_dir: &Path) -> Result<veil_policy::Policy, ExitCode> {
    veil_policy::load_policy_bundle(policy_dir).map_err(|_| {
        exit_usage(
            exe,
            "policy bundle is invalid or unreadable (redacted)",
            print_run_help,
        )
    })
}

fn log_run_start(log_ctx: LogContext<'_>, artifacts_discovered: usize, requested_workers: u32) {
    let mut run_start_counters = BTreeMap::<&str, u64>::new();
    run_start_counters.insert("artifacts_discovered", artifacts_discovered as u64);
    run_start_counters.insert("max_workers_requested", u64::from(requested_workers));
    log_info(log_ctx, "run_started", Some(run_start_counters));
    if requested_workers > 1 {
        log_warn(
            log_ctx,
            "max_workers_single_threaded_baseline",
            "CONFIG_IGNORED",
            Some("v1 baseline executes deterministically with a single worker"),
        );
    }
}

fn resume_quarantine_mode_matches(parsed: &RunArgs) -> bool {
    let raw_dir = parsed.output.join("quarantine").join("raw");
    raw_dir.exists() == parsed.quarantine_copy
}

#[allow(clippy::too_many_arguments)]
fn resume_ledger(
    exe: &str,
    ledger_path: &Path,
    marker_path: &Path,
    run_id_str: &str,
    policy_id_str: &str,
    input_corpus_id_str: &str,
    proof_scope: &str,
    proof_key_commitment: &str,
    tokenization_enabled_meta: &str,
    tokenization_scope_meta: &str,
    log_ctx: LogContext<'_>,
) -> Result<veil_evidence::Ledger, ExitCode> {
    let marker_run_id = match std::fs::read_to_string(marker_path) {
        Ok(s) => s,
        Err(_) => {
            log_error(
                log_ctx,
                "resume_marker_read_failed",
                "INTERNAL_ERROR",
                Some("could not read in-progress marker (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
    };
    if marker_run_id.trim() != run_id_str {
        return Err(exit_usage(
            exe,
            "output directory contains an in-progress marker for a different run (redacted)",
            print_run_help,
        ));
    }

    let ledger = match veil_evidence::Ledger::open_existing(ledger_path) {
        Ok(l) => l,
        Err(_) => {
            log_error(
                log_ctx,
                "resume_ledger_open_failed",
                "INTERNAL_ERROR",
                Some("could not open ledger.sqlite3 for resume (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
    };

    validate_resume_identity(exe, &ledger, "policy_id", policy_id_str, log_ctx)?;
    validate_resume_identity(exe, &ledger, "run_id", run_id_str, log_ctx)?;
    validate_resume_identity(
        exe,
        &ledger,
        "input_corpus_id",
        input_corpus_id_str,
        log_ctx,
    )?;

    if !validate_or_seed_resume_meta(&ledger, "proof_scope", proof_scope) {
        return Err(exit_usage(
            exe,
            "proof scope mismatch for resume (redacted)",
            print_run_help,
        ));
    }
    if !validate_or_seed_resume_meta(&ledger, "proof_key_commitment", proof_key_commitment) {
        return Err(exit_usage(
            exe,
            "proof key commitment mismatch for resume (redacted)",
            print_run_help,
        ));
    }
    if !validate_or_seed_resume_meta(&ledger, "tokenization_enabled", tokenization_enabled_meta) {
        return Err(exit_usage(
            exe,
            "tokenization setting mismatch for resume (redacted)",
            print_run_help,
        ));
    }
    if !validate_or_seed_resume_meta(&ledger, "tokenization_scope", tokenization_scope_meta) {
        return Err(exit_usage(
            exe,
            "tokenization scope mismatch for resume (redacted)",
            print_run_help,
        ));
    }

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
    log_ctx: LogContext<'_>,
) -> Result<veil_evidence::Ledger, ExitCode> {
    if std::fs::write(marker_path, run_id_str).is_err() {
        log_error(
            log_ctx,
            "write_resume_marker_failed",
            "INTERNAL_ERROR",
            Some("could not write in-progress marker (redacted)"),
        );
        return Err(ExitCode::from(EXIT_FATAL));
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
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return Err(ExitCode::from(EXIT_FATAL));
            }
            Ok(l)
        }
        Err(_) => {
            log_error(
                log_ctx,
                "create_ledger_failed",
                "INTERNAL_ERROR",
                Some("could not create ledger.sqlite3 (redacted)"),
            );
            Err(ExitCode::from(EXIT_FATAL))
        }
    }
}

fn validate_resume_identity(
    exe: &str,
    ledger: &veil_evidence::Ledger,
    key: &str,
    expected: &str,
    log_ctx: LogContext<'_>,
) -> Result<(), ExitCode> {
    let value = match ledger.get_meta(key) {
        Ok(Some(v)) => v,
        Ok(None) => {
            log_error(
                log_ctx,
                "ledger_meta_missing",
                "INTERNAL_ERROR",
                Some("ledger missing required meta key (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
        Err(_) => {
            log_error(
                log_ctx,
                "ledger_read_failed",
                "INTERNAL_ERROR",
                Some("ledger read failed (redacted)"),
            );
            return Err(ExitCode::from(EXIT_FATAL));
        }
    };

    if value != expected {
        let message = match key {
            "policy_id" => "policy_id mismatch for resume (redacted)",
            "run_id" => "run_id mismatch for resume (redacted)",
            "input_corpus_id" => "input_corpus_id mismatch for resume (redacted)",
            _ => "resume metadata mismatch (redacted)",
        };
        return Err(exit_usage(exe, message, print_run_help));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let output = TempDirGuard::new("resume-quarantine-mode");

        let args_without_copy = test_run_args(output.path(), false);
        assert!(resume_quarantine_mode_matches(&args_without_copy));

        let raw_dir = output.path().join("quarantine").join("raw");
        std::fs::create_dir_all(&raw_dir).expect("create quarantine raw dir");

        let args_with_copy = test_run_args(output.path(), true);
        assert!(resume_quarantine_mode_matches(&args_with_copy));

        assert!(!resume_quarantine_mode_matches(&args_without_copy));

        let missing_raw = TempDirGuard::new("resume-quarantine-mode-missing-raw");
        let args_missing_raw = test_run_args(missing_raw.path(), true);
        assert!(!resume_quarantine_mode_matches(&args_missing_raw));
    }

    #[test]
    fn load_policy_or_exit_returns_usage_for_missing_bundle() {
        let missing_policy_dir = TempDirGuard::new("missing-policy").path().join("policy");
        let err = load_policy_or_exit("veil", &missing_policy_dir).expect_err("missing policy");
        assert_eq!(err, ExitCode::from(crate::EXIT_USAGE));
    }
}
