use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};
use veil_detect::DetectorEngine;
use veil_transform::Transformer;

const EXIT_OK: u8 = 0;
const EXIT_FATAL: u8 = 1;
const EXIT_QUARANTINED: u8 = 2;
const EXIT_USAGE: u8 = 3;

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const PACK_SCHEMA_VERSION: &str = "pack.v1";

fn main() -> ExitCode {
    let mut args = std::env::args().collect::<Vec<String>>();
    let exe = args.first().cloned().unwrap_or_else(|| "veil".to_string());
    args.remove(0);

    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_root_help(&exe);
        return ExitCode::from(EXIT_OK);
    }

    match args[0].as_str() {
        "run" => cmd_run(&exe, &args[1..]),
        "verify" => cmd_verify(&exe, &args[1..]),
        "policy" => cmd_policy(&exe, &args[1..]),
        _ => {
            eprintln!("error: unknown command (redacted)");
            eprintln!();
            print_root_help(&exe);
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn cmd_policy(exe: &str, args: &[String]) -> ExitCode {
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_policy_help(exe);
        return ExitCode::from(EXIT_OK);
    }

    match args[0].as_str() {
        "lint" => cmd_policy_lint(exe, &args[1..]),
        _ => {
            eprintln!("error: unknown policy subcommand (redacted)");
            eprintln!();
            print_policy_help(exe);
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn cmd_run(exe: &str, args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_run_help(exe);
        return ExitCode::from(EXIT_OK);
    }

    let parsed = match parse_run_args(args) {
        Ok(p) => p,
        Err(msg) => return exit_usage(exe, &msg, print_run_help),
    };

    if let Err(msg) = validate_run_args(&parsed) {
        return exit_usage(exe, &msg, print_run_help);
    }

    let policy = match veil_policy::load_policy_bundle(&parsed.policy) {
        Ok(p) => p,
        Err(_) => {
            return exit_usage(
                exe,
                "policy bundle is invalid or unreadable (redacted)",
                print_run_help,
            );
        }
    };
    let policy_id = policy.policy_id;

    let workdir = parsed
        .workdir
        .clone()
        .unwrap_or_else(|| parsed.output.join(".veil_work"));
    let marker_path = workdir.join("in_progress.marker");

    let enumerated = match enumerate_input_corpus(&parsed.input) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let EnumeratedCorpus {
        artifacts,
        corpus_secret,
    } = enumerated;

    let mut sort_keys = artifacts
        .iter()
        .map(|a| a.sort_key)
        .collect::<Vec<veil_domain::ArtifactSortKey>>();
    let input_corpus_id = veil_domain::compute_input_corpus_id(&mut sort_keys);
    let run_id = veil_domain::compute_run_id(TOOL_VERSION, &policy_id, &input_corpus_id);

    let proof_root_secret = if parsed.enable_tokenization {
        let key_path = match parsed.secret_key_file.as_ref() {
            Some(p) => p,
            None => {
                return exit_usage(
                    exe,
                    "--enable-tokenization true requires --secret-key-file",
                    print_run_help,
                );
            }
        };
        match std::fs::read(key_path) {
            Ok(b) => b,
            Err(_) => {
                return exit_usage(exe, "secret-key-file is unreadable (redacted)", print_run_help);
            }
        }
    } else {
        corpus_secret.to_vec()
    };
    let proof_key = derive_proof_key(&proof_root_secret, &run_id);
    let proof_key_commitment = blake3::hash(&proof_key).to_hex().to_string();
    let proof_scope = veil_domain::TokenizationScope::PerRun.as_str();

    let policy_id_str = policy_id.to_string();
    let input_corpus_id_str = input_corpus_id.to_string();
    let run_id_str = run_id.to_string();

    let is_resume = std::fs::metadata(&marker_path)
        .map(|m| m.is_file())
        .unwrap_or(false);

    let evidence_dir = parsed.output.join("evidence");
    let ledger_path = evidence_dir.join("ledger.sqlite3");

    if is_resume {
        let raw_dir = parsed.output.join("quarantine").join("raw");
        let raw_present = raw_dir.exists();
        if raw_present != parsed.quarantine_copy {
            return exit_usage(
                exe,
                "cannot resume with different --quarantine-copy setting (redacted)",
                print_run_help,
            );
        }
    }

    if let Err(msg) = create_pack_dirs(&parsed.output, parsed.quarantine_copy) {
        eprintln!("error: {msg}");
        return ExitCode::from(EXIT_FATAL);
    }

    if let Err(msg) = ensure_dir_exists_or_create(&workdir, "workdir") {
        eprintln!("error: {msg}");
        return ExitCode::from(EXIT_FATAL);
    }

    let mut ledger = if is_resume {
        let marker_run_id = match std::fs::read_to_string(&marker_path) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("error: could not read in-progress marker (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };
        if marker_run_id.trim() != run_id_str {
            return exit_usage(
                exe,
                "output directory contains an in-progress marker for a different run (redacted)",
                print_run_help,
            );
        }

        let ledger = match veil_evidence::Ledger::open_existing(&ledger_path) {
            Ok(l) => l,
            Err(_) => {
                eprintln!("error: could not open ledger.sqlite3 for resume (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };

        let meta_policy_id = match ledger.get_meta("policy_id") {
            Ok(Some(v)) => v,
            Ok(None) => {
                eprintln!("error: ledger missing required meta key policy_id (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
            Err(_) => {
                eprintln!("error: ledger read failed (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };
        if meta_policy_id != policy_id_str {
            return exit_usage(
                exe,
                "policy_id mismatch for resume (redacted)",
                print_run_help,
            );
        }

        let meta_run_id = match ledger.get_meta("run_id") {
            Ok(Some(v)) => v,
            Ok(None) => {
                eprintln!("error: ledger missing required meta key run_id (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
            Err(_) => {
                eprintln!("error: ledger read failed (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };
        if meta_run_id != run_id_str {
            return exit_usage(exe, "run_id mismatch for resume (redacted)", print_run_help);
        }

        let meta_input_corpus_id = match ledger.get_meta("input_corpus_id") {
            Ok(Some(v)) => v,
            Ok(None) => {
                eprintln!("error: ledger missing required meta key input_corpus_id (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
            Err(_) => {
                eprintln!("error: ledger read failed (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };
        if meta_input_corpus_id != input_corpus_id_str {
            return exit_usage(
                exe,
                "input_corpus_id mismatch for resume (redacted)",
                print_run_help,
            );
        }

        ledger
    } else {
        if std::fs::write(&marker_path, &run_id_str).is_err() {
            eprintln!("error: could not write in-progress marker (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }

        match veil_evidence::Ledger::create_new(
            &ledger_path,
            TOOL_VERSION,
            &policy_id,
            &run_id,
            &input_corpus_id,
        ) {
            Ok(l) => l,
            Err(_) => {
                eprintln!("error: could not create ledger.sqlite3 (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        }
    };

    let quarantine_dir = parsed.output.join("quarantine");
    let quarantine_raw_dir = quarantine_dir.join("raw");
    let quarantine_index_path = quarantine_dir.join("index.ndjson");
    let artifacts_ndjson_path = evidence_dir.join("artifacts.ndjson");

    let sanitized_dir = parsed.output.join("sanitized");
    let staging_dir = workdir.join("staging");
    if std::fs::create_dir_all(&staging_dir).is_err() {
        eprintln!("error: could not create staging directory (redacted)");
        return ExitCode::from(EXIT_FATAL);
    }

    let extractors = veil_extract::ExtractorRegistry::default();
    let detector = veil_detect::DetectorEngineV1::default();
    let transformer = veil_transform::TransformerV1::default();

    let mut proof_tokens_by_artifact = BTreeMap::<veil_domain::ArtifactId, Vec<String>>::new();
    if is_resume {
        match load_existing_proof_tokens(&artifacts_ndjson_path) {
            Ok(m) => proof_tokens_by_artifact = m,
            Err(_) => {
                eprintln!("warn: could not load existing proof tokens (redacted)");
            }
        }
    }

    for artifact in artifacts.iter() {
        if ledger
            .upsert_discovered(
                &artifact.sort_key.artifact_id,
                &artifact.sort_key.source_locator_hash,
                artifact.size_bytes,
                &artifact.artifact_type,
            )
            .is_err()
        {
            eprintln!("error: ledger write failed (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }

        let state = match ledger.artifact_summary(&artifact.sort_key.artifact_id) {
            Ok(Some(s)) => s.state,
            Ok(None) => {
                eprintln!("error: ledger missing artifact record (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
            Err(_) => {
                eprintln!("error: ledger read failed (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };
        if state.is_terminal() {
            continue;
        }

        proof_tokens_by_artifact.remove(&artifact.sort_key.artifact_id);

        let bytes = match std::fs::read(&artifact.path) {
            Ok(b) => b,
            Err(_) => {
                if ledger
                    .quarantine(
                        &artifact.sort_key.artifact_id,
                        veil_domain::QuarantineReasonCode::InternalError,
                    )
                    .is_err()
                {
                    eprintln!("error: ledger write failed (redacted)");
                    return ExitCode::from(EXIT_FATAL);
                }
                continue;
            }
        };

        let ctx = veil_extract::ArtifactContext {
            artifact_id: &artifact.sort_key.artifact_id,
            source_locator_hash: &artifact.sort_key.source_locator_hash,
        };
        let extracted = extractors.extract_by_type(&artifact.artifact_type, ctx, &bytes);

        let (extractor_id, canonical, coverage) = match extracted {
            veil_extract::ExtractOutcome::Extracted {
                extractor_id,
                canonical,
                coverage,
            } => (extractor_id, canonical, coverage),
            veil_extract::ExtractOutcome::Quarantined { reason, .. } => {
                if ledger.quarantine(&artifact.sort_key.artifact_id, reason).is_err() {
                    eprintln!("error: ledger write failed (redacted)");
                    return ExitCode::from(EXIT_FATAL);
                }
                if parsed.quarantine_copy {
                    let _ = write_quarantine_raw(
                        &quarantine_raw_dir,
                        &artifact.sort_key,
                        &artifact.artifact_type,
                        &bytes,
                    );
                }
                continue;
            }
        };

        if coverage.has_unknown() {
            if ledger
                .quarantine(
                    &artifact.sort_key.artifact_id,
                    veil_domain::QuarantineReasonCode::UnknownCoverage,
                )
                .is_err()
            {
                eprintln!("error: ledger write failed (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
            if parsed.quarantine_copy {
                let _ = write_quarantine_raw(
                    &quarantine_raw_dir,
                    &artifact.sort_key,
                    &artifact.artifact_type,
                    &bytes,
                );
            }
            continue;
        }

        let coverage_hash = coverage_hash_v1(coverage);
        if ledger
            .mark_extracted(&artifact.sort_key.artifact_id, extractor_id, &coverage_hash)
            .is_err()
        {
            eprintln!("error: ledger write failed (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }

        let findings = detector.detect(&policy, &canonical, Some(&proof_key));
        proof_tokens_by_artifact.insert(
            artifact.sort_key.artifact_id,
            collect_proof_tokens(&findings),
        );
        if ledger
            .replace_findings_summary(
                &artifact.sort_key.artifact_id,
                &findings_summary_rows(&policy, &findings),
            )
            .is_err()
        {
            eprintln!("error: ledger write failed (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }

        let sanitized_bytes = match transformer.transform(&policy, &canonical) {
            veil_transform::TransformOutcome::Transformed { sanitized_bytes } => sanitized_bytes,
            veil_transform::TransformOutcome::Quarantined { reason } => {
                if ledger.quarantine(&artifact.sort_key.artifact_id, reason).is_err() {
                    eprintln!("error: ledger write failed (redacted)");
                    return ExitCode::from(EXIT_FATAL);
                }
                if parsed.quarantine_copy {
                    let _ = write_quarantine_raw(
                        &quarantine_raw_dir,
                        &artifact.sort_key,
                        &artifact.artifact_type,
                        &bytes,
                    );
                }
                continue;
            }
        };

        if ledger
            .mark_transformed(&artifact.sort_key.artifact_id)
            .is_err()
        {
            eprintln!("error: ledger write failed (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }

        let extracted_out = extractors.extract_by_type(&artifact.artifact_type, ctx, &sanitized_bytes);
        let canonical_out = match extracted_out {
            veil_extract::ExtractOutcome::Extracted { canonical, .. } => canonical,
            veil_extract::ExtractOutcome::Quarantined { .. } => {
                if ledger
                    .quarantine(
                        &artifact.sort_key.artifact_id,
                        veil_domain::QuarantineReasonCode::ParseError,
                    )
                    .is_err()
                {
                    eprintln!("error: ledger write failed (redacted)");
                    return ExitCode::from(EXIT_FATAL);
                }
                if parsed.quarantine_copy {
                    let _ = write_quarantine_raw(
                        &quarantine_raw_dir,
                        &artifact.sort_key,
                        &artifact.artifact_type,
                        &bytes,
                    );
                }
                continue;
            }
        };

        let findings_out = detector.detect(&policy, &canonical_out, Some(&proof_key));
        let verification = veil_verify::residual_verify(&findings_out);
        if verification != veil_verify::VerificationOutcome::Verified {
            let reason = match verification {
                veil_verify::VerificationOutcome::Verified => unreachable!(),
                veil_verify::VerificationOutcome::Quarantined { reason } => reason,
            };
            if ledger.quarantine(&artifact.sort_key.artifact_id, reason).is_err() {
                eprintln!("error: ledger write failed (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
            if parsed.quarantine_copy {
                let _ = write_quarantine_raw(
                    &quarantine_raw_dir,
                    &artifact.sort_key,
                    &artifact.artifact_type,
                    &bytes,
                );
            }
            continue;
        }

        let output_id = veil_domain::hash_output_id(&sanitized_bytes);
        let output_id_str = output_id.to_string();

        let dest_path =
            sanitized_output_path_v1(&sanitized_dir, &artifact.sort_key, &artifact.artifact_type);

        if let Ok(meta) = std::fs::metadata(&dest_path)
            && meta.is_file()
        {
            let existing = match std::fs::read(&dest_path) {
                Ok(b) => b,
                Err(_) => Vec::new(),
            };
            if veil_domain::hash_output_id(&existing) == output_id {
                if ledger
                    .mark_verified(&artifact.sort_key.artifact_id, &output_id_str)
                    .is_err()
                {
                    eprintln!("error: ledger write failed (redacted)");
                    return ExitCode::from(EXIT_FATAL);
                }
                continue;
            }
            if ledger
                .quarantine(
                    &artifact.sort_key.artifact_id,
                    veil_domain::QuarantineReasonCode::InternalError,
                )
                .is_err()
            {
                eprintln!("error: ledger write failed (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
            if parsed.quarantine_copy {
                let _ = write_quarantine_raw(
                    &quarantine_raw_dir,
                    &artifact.sort_key,
                    &artifact.artifact_type,
                    &bytes,
                );
            }
            continue;
        }

        let file_name = match dest_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => {
                if ledger
                    .quarantine(
                        &artifact.sort_key.artifact_id,
                        veil_domain::QuarantineReasonCode::InternalError,
                    )
                    .is_err()
                {
                    eprintln!("error: ledger write failed (redacted)");
                    return ExitCode::from(EXIT_FATAL);
                }
                continue;
            }
        };
        let stage_path = staging_dir.join(format!("{file_name}.tmp"));
        if write_bytes_sync(&stage_path, &sanitized_bytes).is_err() {
            let _ = std::fs::remove_file(&stage_path);
            if ledger
                .quarantine(
                    &artifact.sort_key.artifact_id,
                    veil_domain::QuarantineReasonCode::InternalError,
                )
                .is_err()
            {
                eprintln!("error: ledger write failed (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
            continue;
        }

        if std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_stage_write") {
            eprintln!("error: failpoint triggered (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }

        if std::fs::rename(&stage_path, &dest_path).is_err() {
            let _ = std::fs::remove_file(&stage_path);
            if ledger
                .quarantine(
                    &artifact.sort_key.artifact_id,
                    veil_domain::QuarantineReasonCode::InternalError,
                )
                .is_err()
            {
                eprintln!("error: ledger write failed (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
            continue;
        }

        if ledger
            .mark_verified(&artifact.sort_key.artifact_id, &output_id_str)
            .is_err()
        {
            eprintln!("error: ledger write failed (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }
    }

    let mut results = Vec::with_capacity(artifacts.len());
    for artifact in artifacts.iter() {
        let summary = match ledger.artifact_summary(&artifact.sort_key.artifact_id) {
            Ok(Some(s)) => s,
            Ok(None) => {
                eprintln!("error: ledger missing artifact record (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
            Err(_) => {
                eprintln!("error: ledger read failed (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };

        results.push(ArtifactRunResult {
            sort_key: artifact.sort_key,
            size_bytes: artifact.size_bytes,
            artifact_type: artifact.artifact_type.clone(),
            state: summary.state,
            quarantine_reason_code: summary.quarantine_reason_code,
            proof_tokens: proof_tokens_by_artifact
                .get(&artifact.sort_key.artifact_id)
                .cloned()
                .unwrap_or_default(),
        });
    }

    let mut quarantine_reason_counts = BTreeMap::<String, u64>::new();
    let mut artifacts_verified = 0_u64;
    let mut artifacts_quarantined = 0_u64;
    for r in results.iter() {
        match r.state {
            veil_domain::ArtifactState::Verified => artifacts_verified += 1,
            veil_domain::ArtifactState::Quarantined => {
                artifacts_quarantined += 1;
                let Some(code) = r.quarantine_reason_code.as_ref() else {
                    eprintln!("error: quarantined artifact missing reason code (redacted)");
                    return ExitCode::from(EXIT_FATAL);
                };
                *quarantine_reason_counts.entry(code.clone()).or_insert(0) += 1;
            }
            _ => {}
        }
    }

    if let Err(msg) = write_quarantine_index(&quarantine_index_path, &results) {
        eprintln!("error: {msg}");
        return ExitCode::from(EXIT_FATAL);
    }

    if let Err(msg) = write_artifacts_evidence(&artifacts_ndjson_path, &results) {
        eprintln!("error: {msg}");
        return ExitCode::from(EXIT_FATAL);
    }

    let run_manifest_path = evidence_dir.join("run_manifest.json");
    let run_manifest = RunManifestJsonV1 {
        tool_version: TOOL_VERSION,
        run_id: run_id_str.clone(),
        policy_id: policy_id_str.clone(),
        input_corpus_id: input_corpus_id_str.clone(),
        totals: RunTotals {
            artifacts_discovered: artifacts.len() as u64,
            artifacts_verified,
            artifacts_quarantined,
        },
        quarantine_reason_counts,
        tokenization_enabled: parsed.enable_tokenization,
        tokenization_scope: if parsed.enable_tokenization {
            Some(veil_domain::TokenizationScope::PerRun.as_str())
        } else {
            None
        },
        proof_scope,
        proof_key_commitment,
        quarantine_copy_enabled: parsed.quarantine_copy,
    };
    if write_json_atomic(&run_manifest_path, &run_manifest).is_err() {
        eprintln!("error: could not write run_manifest.json (redacted)");
        return ExitCode::from(EXIT_FATAL);
    }

    let pack_manifest_path = parsed.output.join("pack_manifest.json");
    let pack_manifest = PackManifestJsonV1 {
        pack_schema_version: PACK_SCHEMA_VERSION,
        tool_version: TOOL_VERSION,
        run_id: run_id_str,
        policy_id: policy_id_str,
        input_corpus_id: input_corpus_id_str,
        tokenization_enabled: parsed.enable_tokenization,
        tokenization_scope: if parsed.enable_tokenization {
            Some(veil_domain::TokenizationScope::PerRun.as_str())
        } else {
            None
        },
        quarantine_copy_enabled: parsed.quarantine_copy,
        ledger_schema_version: veil_evidence::LEDGER_SCHEMA_VERSION,
    };
    if write_json_atomic(&pack_manifest_path, &pack_manifest).is_err() {
        eprintln!("error: could not write pack_manifest.json (redacted)");
        return ExitCode::from(EXIT_FATAL);
    }

    let _ = std::fs::remove_file(&marker_path);

    if artifacts_quarantined > 0 {
        ExitCode::from(EXIT_QUARANTINED)
    } else {
        ExitCode::from(EXIT_OK)
    }
}

fn cmd_verify(exe: &str, args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_verify_help(exe);
        return ExitCode::from(EXIT_OK);
    }

    let parsed = match parse_verify_args(args) {
        Ok(p) => p,
        Err(msg) => return exit_usage(exe, &msg, print_verify_help),
    };

    if let Err(msg) = validate_verify_args(&parsed) {
        return exit_usage(exe, &msg, print_verify_help);
    }

    let policy = match veil_policy::load_policy_bundle(&parsed.policy) {
        Ok(p) => p,
        Err(_) => {
            return exit_usage(
                exe,
                "policy bundle is invalid or unreadable (redacted)",
                print_verify_help,
            );
        }
    };

    let pack_manifest_path = parsed.pack.join("pack_manifest.json");
    let pack_manifest_json = match std::fs::read_to_string(&pack_manifest_path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("error: could not read pack_manifest.json (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let pack_manifest: PackManifestJsonV1Read = match serde_json::from_str(&pack_manifest_json) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("error: pack_manifest.json is invalid JSON (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }
    };

    if pack_manifest.pack_schema_version != PACK_SCHEMA_VERSION {
        eprintln!("error: unsupported pack_schema_version (redacted)");
        return ExitCode::from(EXIT_FATAL);
    }

    if pack_manifest.tool_version.trim().is_empty()
        || pack_manifest.run_id.trim().is_empty()
        || pack_manifest.input_corpus_id.trim().is_empty()
    {
        eprintln!("error: pack_manifest.json is missing required fields (redacted)");
        return ExitCode::from(EXIT_FATAL);
    }
    let _ = pack_manifest.quarantine_copy_enabled;

    if pack_manifest.ledger_schema_version != veil_evidence::LEDGER_SCHEMA_VERSION {
        eprintln!("error: unsupported ledger schema_version (redacted)");
        return ExitCode::from(EXIT_FATAL);
    }

    if pack_manifest.tokenization_enabled && pack_manifest.tokenization_scope.is_none() {
        eprintln!("error: invalid tokenization scope metadata (redacted)");
        return ExitCode::from(EXIT_FATAL);
    }
    if !pack_manifest.tokenization_enabled && pack_manifest.tokenization_scope.is_some() {
        eprintln!("error: invalid tokenization scope metadata (redacted)");
        return ExitCode::from(EXIT_FATAL);
    }

    if pack_manifest.policy_id != policy.policy_id.to_string() {
        return exit_usage(
            exe,
            "policy_id mismatch for verify (redacted)",
            print_verify_help,
        );
    }

    let artifacts_path = parsed.pack.join("evidence").join("artifacts.ndjson");
    let artifacts_file = match std::fs::File::open(&artifacts_path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("error: could not read artifacts.ndjson (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let reader = std::io::BufReader::new(artifacts_file);

    let sanitized_dir = parsed.pack.join("sanitized");
    let extractors = veil_extract::ExtractorRegistry::default();
    let detector = veil_detect::DetectorEngineV1::default();

    let mut failures = 0_u64;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => {
                eprintln!("error: could not read artifacts.ndjson line (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let rec: ArtifactEvidenceRecordOwned = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("error: artifacts.ndjson record is invalid JSON (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };

        let _ = rec.size_bytes;

        if rec.state != "VERIFIED" {
            continue;
        }

        if rec.quarantine_reason_code.is_some() {
            eprintln!("error: verified artifact has quarantine_reason_code (redacted)");
            return ExitCode::from(EXIT_FATAL);
        }

        let artifact_id = match veil_domain::ArtifactId::from_hex(&rec.artifact_id) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("error: artifacts.ndjson contains invalid artifact_id (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };
        let source_locator_hash = match veil_domain::SourceLocatorHash::from_hex(&rec.source_locator_hash) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("error: artifacts.ndjson contains invalid source_locator_hash (redacted)");
                return ExitCode::from(EXIT_FATAL);
            }
        };
        let sort_key = veil_domain::ArtifactSortKey::new(artifact_id, source_locator_hash);
        let path = sanitized_output_path_v1(&sanitized_dir, &sort_key, &rec.artifact_type);

        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                failures += 1;
                continue;
            }
        };

        let ctx = veil_extract::ArtifactContext {
            artifact_id: &sort_key.artifact_id,
            source_locator_hash: &sort_key.source_locator_hash,
        };
        let extracted = extractors.extract_by_type(&rec.artifact_type, ctx, &bytes);
        let canonical = match extracted {
            veil_extract::ExtractOutcome::Extracted { canonical, .. } => canonical,
            veil_extract::ExtractOutcome::Quarantined { .. } => {
                failures += 1;
                continue;
            }
        };

        let findings = detector.detect(&policy, &canonical, None);
        let verification = veil_verify::residual_verify(&findings);
        if verification != veil_verify::VerificationOutcome::Verified {
            failures += 1;
        }
    }

    if failures > 0 {
        ExitCode::from(EXIT_QUARANTINED)
    } else {
        ExitCode::from(EXIT_OK)
    }
}

fn cmd_policy_lint(exe: &str, args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_policy_lint_help(exe);
        return ExitCode::from(EXIT_OK);
    }

    let parsed = match parse_policy_lint_args(args) {
        Ok(p) => p,
        Err(msg) => return exit_usage(exe, &msg, print_policy_lint_help),
    };

    if let Err(msg) = validate_policy_lint_args(&parsed) {
        return exit_usage(exe, &msg, print_policy_lint_help);
    }

    let policy = match veil_policy::load_policy_bundle(&parsed.policy) {
        Ok(p) => p,
        Err(_) => {
            return exit_usage(
                exe,
                "policy bundle is invalid or unreadable (redacted)",
                print_policy_lint_help,
            );
        }
    };

    println!("{}", policy.policy_id);
    ExitCode::from(EXIT_OK)
}

fn exit_usage(exe: &str, message: &str, help: fn(&str)) -> ExitCode {
    eprintln!("error: {message}");
    eprintln!();
    help(exe);
    ExitCode::from(EXIT_USAGE)
}

#[derive(Debug)]
struct RunArgs {
    input: PathBuf,
    output: PathBuf,
    policy: PathBuf,
    workdir: Option<PathBuf>,
    max_workers: Option<u32>,
    strictness: Option<String>,
    enable_tokenization: bool,
    secret_key_file: Option<PathBuf>,
    quarantine_copy: bool,
    limits_json: Option<PathBuf>,
}

fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut input = None;
    let mut output = None;
    let mut policy = None;
    let mut workdir = None;
    let mut max_workers = None;
    let mut strictness = None;
    let mut enable_tokenization = false;
    let mut secret_key_file = None;
    let mut quarantine_copy = false;
    let mut limits_json = None;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--input" => {
                i += 1;
                input = Some(require_value(args, i, "--input")?);
            }
            "--output" => {
                i += 1;
                output = Some(require_value(args, i, "--output")?);
            }
            "--policy" => {
                i += 1;
                policy = Some(require_value(args, i, "--policy")?);
            }
            "--workdir" => {
                i += 1;
                workdir = Some(require_value(args, i, "--workdir")?);
            }
            "--max-workers" => {
                i += 1;
                let raw: PathBuf = require_value(args, i, "--max-workers")?;
                let raw = raw
                    .to_str()
                    .ok_or_else(|| "--max-workers must be a UTF-8 number".to_string())?;
                let parsed: u32 = raw
                    .parse()
                    .map_err(|_| "--max-workers must be a positive integer".to_string())?;
                if parsed == 0 {
                    return Err("--max-workers must be >= 1".to_string());
                }
                max_workers = Some(parsed);
            }
            "--strictness" => {
                i += 1;
                let raw: PathBuf = require_value(args, i, "--strictness")?;
                let raw = raw
                    .to_str()
                    .ok_or_else(|| "--strictness must be UTF-8".to_string())?;
                strictness = Some(raw.to_string());
            }
            "--enable-tokenization" => {
                i += 1;
                let raw: PathBuf = require_value(args, i, "--enable-tokenization")?;
                let raw = raw
                    .to_str()
                    .ok_or_else(|| "--enable-tokenization must be 'true' or 'false'".to_string())?;
                enable_tokenization = parse_bool_flag("--enable-tokenization", raw)?;
            }
            "--secret-key-file" => {
                i += 1;
                secret_key_file = Some(require_value(args, i, "--secret-key-file")?);
            }
            "--quarantine-copy" => {
                i += 1;
                let raw: PathBuf = require_value(args, i, "--quarantine-copy")?;
                let raw = raw
                    .to_str()
                    .ok_or_else(|| "--quarantine-copy must be 'true' or 'false'".to_string())?;
                quarantine_copy = parse_bool_flag("--quarantine-copy", raw)?;
            }
            "--limits-json" => {
                i += 1;
                limits_json = Some(require_value(args, i, "--limits-json")?);
            }
            unknown if unknown.starts_with("--") => {
                return Err(format!("unknown flag: {unknown}"));
            }
            other => {
                return Err(format!("unexpected argument: {other}"));
            }
        }
        i += 1;
    }

    Ok(RunArgs {
        input: input.ok_or_else(|| "missing required flag: --input".to_string())?,
        output: output.ok_or_else(|| "missing required flag: --output".to_string())?,
        policy: policy.ok_or_else(|| "missing required flag: --policy".to_string())?,
        workdir,
        max_workers,
        strictness,
        enable_tokenization,
        secret_key_file,
        quarantine_copy,
        limits_json,
    })
}

fn validate_run_args(args: &RunArgs) -> Result<(), String> {
    ensure_dir_exists(&args.input, "input")?;
    ensure_dir_exists(&args.policy, "policy")?;
    ensure_policy_json_exists(&args.policy)?;
    let workdir = args
        .workdir
        .clone()
        .unwrap_or_else(|| args.output.join(".veil_work"));
    ensure_output_fresh_or_resumable(&args.output, &workdir, args.quarantine_copy)?;

    if let Ok(meta) = std::fs::metadata(&workdir)
        && !meta.is_dir()
    {
        return Err("workdir path must be a directory when it exists (redacted)".to_string());
    }

    if let Some(strictness) = &args.strictness
        && strictness != "strict"
    {
        return Err("--strictness must be 'strict' (v1)".to_string());
    }

    if args.enable_tokenization && args.secret_key_file.is_none() {
        return Err("--enable-tokenization true requires --secret-key-file".to_string());
    }

    if !args.enable_tokenization && args.secret_key_file.is_some() {
        return Err("--secret-key-file requires --enable-tokenization true".to_string());
    }

    if let Some(key) = &args.secret_key_file {
        ensure_file_exists(key, "secret-key-file")?;
    }

    if let Some(limits_json) = &args.limits_json {
        ensure_file_exists(limits_json, "limits-json")?;
        let _limits = load_archive_limits_from_json(limits_json)?;
    }

    if let Some(max_workers) = args.max_workers {
        let _ = max_workers;
    }

    if args.quarantine_copy {
        // Explicit opt-in is allowed; additional safety checks happen once output emission exists.
    }

    Ok(())
}

#[derive(Debug)]
struct VerifyArgs {
    pack: PathBuf,
    policy: PathBuf,
}

fn parse_verify_args(args: &[String]) -> Result<VerifyArgs, String> {
    let mut pack = None;
    let mut policy = None;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--pack" => {
                i += 1;
                pack = Some(require_value(args, i, "--pack")?);
            }
            "--policy" => {
                i += 1;
                policy = Some(require_value(args, i, "--policy")?);
            }
            unknown if unknown.starts_with("--") => {
                return Err(format!("unknown flag: {unknown}"));
            }
            other => {
                return Err(format!("unexpected argument: {other}"));
            }
        }
        i += 1;
    }

    Ok(VerifyArgs {
        pack: pack.ok_or_else(|| "missing required flag: --pack".to_string())?,
        policy: policy.ok_or_else(|| "missing required flag: --policy".to_string())?,
    })
}

fn validate_verify_args(args: &VerifyArgs) -> Result<(), String> {
    ensure_dir_exists(&args.pack, "pack")?;
    ensure_dir_exists(&args.policy, "policy")?;
    ensure_policy_json_exists(&args.policy)?;
    Ok(())
}

#[derive(Debug)]
struct PolicyLintArgs {
    policy: PathBuf,
}

fn parse_policy_lint_args(args: &[String]) -> Result<PolicyLintArgs, String> {
    let mut policy = None;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--policy" => {
                i += 1;
                policy = Some(require_value(args, i, "--policy")?);
            }
            unknown if unknown.starts_with("--") => {
                return Err(format!("unknown flag: {unknown}"));
            }
            other => {
                return Err(format!("unexpected argument: {other}"));
            }
        }
        i += 1;
    }

    Ok(PolicyLintArgs {
        policy: policy.ok_or_else(|| "missing required flag: --policy".to_string())?,
    })
}

fn validate_policy_lint_args(args: &PolicyLintArgs) -> Result<(), String> {
    ensure_dir_exists(&args.policy, "policy")?;
    ensure_policy_json_exists(&args.policy)?;
    Ok(())
}

fn require_value(args: &[String], i: usize, flag: &'static str) -> Result<PathBuf, String> {
    let value = args
        .get(i)
        .ok_or_else(|| format!("missing value for {flag}"))?;
    if value.starts_with("--") {
        return Err(format!("missing value for {flag}"));
    }
    Ok(PathBuf::from(value))
}

fn parse_bool_flag(flag: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{flag} must be 'true' or 'false'")),
    }
}

fn ensure_dir_exists(path: &Path, kind: &str) -> Result<(), String> {
    let meta = std::fs::metadata(path)
        .map_err(|_| format!("{kind} path does not exist or is not accessible (redacted)"))?;
    if !meta.is_dir() {
        return Err(format!("{kind} path must be a directory (redacted)"));
    }
    Ok(())
}

fn ensure_file_exists(path: &Path, kind: &str) -> Result<(), String> {
    let meta = std::fs::metadata(path)
        .map_err(|_| format!("{kind} path does not exist or is not accessible (redacted)"))?;
    if !meta.is_file() {
        return Err(format!("{kind} path must be a file (redacted)"));
    }
    Ok(())
}

fn ensure_policy_json_exists(policy_dir: &Path) -> Result<(), String> {
    let path = policy_dir.join("policy.json");
    ensure_file_exists(&path, "policy.json")?;
    Ok(())
}

fn ensure_output_fresh_or_resumable(
    output: &Path,
    workdir: &Path,
    quarantine_copy_enabled: bool,
) -> Result<(), String> {
    match std::fs::metadata(output) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err("output path must be a directory when it exists (redacted)".to_string());
            }

            let mut entries = std::fs::read_dir(output)
                .map_err(|_| "output path is not readable (redacted)".to_string())?;
            if entries.next().is_none() {
                return Ok(());
            }

            let marker_path = workdir.join("in_progress.marker");
            let marker_meta = std::fs::metadata(&marker_path).map_err(|_| {
                "output directory must be empty or resumable (redacted)".to_string()
            })?;
            if !marker_meta.is_file() {
                return Err(
                    "output directory contains an invalid in-progress marker (redacted)"
                        .to_string(),
                );
            }

            let ledger_path = output.join("evidence").join("ledger.sqlite3");
            let ledger_meta = std::fs::metadata(&ledger_path).map_err(|_| {
                "output directory must be empty or resumable (missing ledger) (redacted)"
                    .to_string()
            })?;
            if !ledger_meta.is_file() {
                return Err("ledger.sqlite3 must be a file (redacted)".to_string());
            }

            let raw_dir = output.join("quarantine").join("raw");
            let raw_present = raw_dir.exists();
            if raw_present != quarantine_copy_enabled {
                return Err(
                    "cannot resume with different --quarantine-copy setting (redacted)".to_string(),
                );
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err("output path is not accessible (redacted)".to_string());
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFileV1 {
    schema_version: String,
    #[serde(default)]
    archive: ArchiveLimitsOverride,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveLimitsOverride {
    max_nested_archive_depth: Option<u32>,
    max_entries_per_archive: Option<u32>,
    max_expansion_ratio: Option<u32>,
    max_expanded_bytes_per_archive: Option<u64>,
}

fn load_archive_limits_from_json(path: &Path) -> Result<veil_domain::ArchiveLimits, String> {
    let json = std::fs::read_to_string(path)
        .map_err(|_| "limits-json could not be read (redacted)".to_string())?;

    let parsed: LimitsFileV1 = serde_json::from_str(&json)
        .map_err(|_| "limits-json is not valid JSON (redacted)".to_string())?;

    if parsed.schema_version != "limits.v1" {
        return Err("limits-json schema_version must be 'limits.v1' (v1)".to_string());
    }

    let mut limits = veil_domain::ArchiveLimits::default();
    if let Some(v) = parsed.archive.max_nested_archive_depth {
        limits.max_nested_archive_depth = v;
    }
    if let Some(v) = parsed.archive.max_entries_per_archive {
        limits.max_entries_per_archive = v;
    }
    if let Some(v) = parsed.archive.max_expansion_ratio {
        if v == 0 {
            return Err("limits-json max_expansion_ratio must be >= 1".to_string());
        }
        limits.max_expansion_ratio = v;
    }
    if let Some(v) = parsed.archive.max_expanded_bytes_per_archive {
        if v == 0 {
            return Err("limits-json max_expanded_bytes_per_archive must be >= 1".to_string());
        }
        limits.max_expanded_bytes_per_archive = v;
    }

    Ok(limits)
}

#[derive(Debug, Clone)]
struct DiscoveredArtifact {
    sort_key: veil_domain::ArtifactSortKey,
    path: PathBuf,
    size_bytes: u64,
    artifact_type: String,
}

#[derive(Debug, Clone)]
struct ArtifactRunResult {
    sort_key: veil_domain::ArtifactSortKey,
    size_bytes: u64,
    artifact_type: String,
    state: veil_domain::ArtifactState,
    quarantine_reason_code: Option<String>,
    proof_tokens: Vec<String>,
}

fn create_pack_dirs(pack_root: &Path, quarantine_copy_enabled: bool) -> Result<(), String> {
    ensure_dir_exists_or_create(pack_root, "output")?;
    ensure_dir_exists_or_create(&pack_root.join("sanitized"), "sanitized")?;
    ensure_dir_exists_or_create(&pack_root.join("quarantine"), "quarantine")?;
    ensure_dir_exists_or_create(&pack_root.join("evidence"), "evidence")?;

    if quarantine_copy_enabled {
        ensure_dir_exists_or_create(&pack_root.join("quarantine").join("raw"), "quarantine/raw")?;
    }

    Ok(())
}

fn ensure_dir_exists_or_create(path: &Path, kind: &str) -> Result<(), String> {
    match std::fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(format!("{kind} path must be a directory (redacted)"));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .map_err(|_| format!("{kind} path could not be created (redacted)"))?;
        }
        Err(_) => {
            return Err(format!("{kind} path is not accessible (redacted)"));
        }
    }
    Ok(())
}

struct EnumeratedCorpus {
    artifacts: Vec<DiscoveredArtifact>,
    corpus_secret: [u8; 32],
}

fn enumerate_input_corpus(input_root: &Path) -> Result<EnumeratedCorpus, String> {
    let mut out = Vec::new();
    let mut corpus_hasher = blake3::Hasher::new();
    collect_input_files(input_root, input_root, &mut out, &mut corpus_hasher)?;
    out.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));
    Ok(EnumeratedCorpus {
        artifacts: out,
        corpus_secret: *corpus_hasher.finalize().as_bytes(),
    })
}

fn collect_input_files(
    root: &Path,
    current: &Path,
    out: &mut Vec<DiscoveredArtifact>,
    corpus_hasher: &mut blake3::Hasher,
) -> Result<(), String> {
    let read_dir = std::fs::read_dir(current)
        .map_err(|_| "input corpus directory is not readable (redacted)".to_string())?;

    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry
            .map_err(|_| "input corpus directory entry could not be read (redacted)".to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| "input corpus contains a non-UTF-8 path (redacted)".to_string())?
            .to_string();
        entries.push((name, entry));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (_, entry) in entries {
        let file_type = entry
            .file_type()
            .map_err(|_| "input corpus entry type could not be read (redacted)".to_string())?;
        if file_type.is_symlink() {
            return Err("input corpus contains an unsafe path (symlink) (redacted)".to_string());
        }

        let path = entry.path();
        if file_type.is_dir() {
            collect_input_files(root, &path, out, corpus_hasher)?;
            continue;
        }

        if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| "input corpus path normalization failed (redacted)".to_string())?;
            let normalized_rel_path = normalize_rel_path(rel)?;
            let source_locator_hash = veil_domain::hash_source_locator_hash(&normalized_rel_path);

            let size_bytes = entry
                .metadata()
                .map_err(|_| "input corpus file metadata could not be read (redacted)".to_string())?
                .len();
            let path_bytes = normalized_rel_path.as_bytes();
            let path_len: u32 = path_bytes
                .len()
                .try_into()
                .map_err(|_| "input corpus path is too long (redacted)".to_string())?;
            corpus_hasher.update(&path_len.to_le_bytes());
            corpus_hasher.update(path_bytes);
            corpus_hasher.update(&size_bytes.to_le_bytes());

            let artifact_id = hash_file_artifact_id_and_update(&path, corpus_hasher)?;

            let artifact_type = classify_artifact_type(&path);
            out.push(DiscoveredArtifact {
                sort_key: veil_domain::ArtifactSortKey::new(artifact_id, source_locator_hash),
                path,
                size_bytes,
                artifact_type,
            });
        } else {
            return Err(
                "input corpus contains an unsupported filesystem entry (redacted)".to_string(),
            );
        }
    }

    Ok(())
}

fn normalize_rel_path(rel: &Path) -> Result<String, String> {
    let mut out = String::new();
    for (i, comp) in rel.components().enumerate() {
        let name = match comp {
            std::path::Component::Normal(os) => os,
            _ => {
                return Err(
                    "input corpus path is not a normalized relative path (redacted)".to_string(),
                );
            }
        };

        let name = name
            .to_str()
            .ok_or_else(|| "input corpus contains a non-UTF-8 path (redacted)".to_string())?;
        if i > 0 {
            out.push('/');
        }
        out.push_str(name);
    }
    Ok(out)
}

fn hash_file_artifact_id_and_update(
    path: &Path,
    corpus_hasher: &mut blake3::Hasher,
) -> Result<veil_domain::ArtifactId, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| "input artifact is not readable (redacted)".to_string())?;

    let mut hasher = blake3::Hasher::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| "input artifact could not be read (redacted)".to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        corpus_hasher.update(&buf[..n]);
    }

    Ok(veil_domain::ArtifactId::from_digest(
        veil_domain::Digest32::from_bytes(*hasher.finalize().as_bytes()),
    ))
}

const PROOF_KEY_DERIVATION_DOMAIN: &[u8] = b"veil.proof.key.v1";

fn derive_proof_key(root_secret: &[u8], run_id: &veil_domain::RunId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROOF_KEY_DERIVATION_DOMAIN);
    hasher.update(run_id.as_digest().as_bytes());
    hasher.update(root_secret);
    *hasher.finalize().as_bytes()
}

fn classify_artifact_type(path: &Path) -> String {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "txt" => "TEXT",
        "csv" => "CSV",
        "tsv" => "TSV",
        "json" => "JSON",
        "ndjson" => "NDJSON",
        _ => "FILE",
    }
    .to_string()
}

#[derive(Debug, Serialize)]
struct RunTotals {
    artifacts_discovered: u64,
    artifacts_verified: u64,
    artifacts_quarantined: u64,
}

#[derive(Debug, Serialize)]
struct RunManifestJsonV1 {
    tool_version: &'static str,
    run_id: String,
    policy_id: String,
    input_corpus_id: String,
    totals: RunTotals,
    quarantine_reason_counts: BTreeMap<String, u64>,
    tokenization_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tokenization_scope: Option<&'static str>,
    proof_scope: &'static str,
    proof_key_commitment: String,
    quarantine_copy_enabled: bool,
}

#[derive(Debug, Serialize)]
struct PackManifestJsonV1 {
    pack_schema_version: &'static str,
    tool_version: &'static str,
    run_id: String,
    policy_id: String,
    input_corpus_id: String,
    tokenization_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tokenization_scope: Option<&'static str>,
    quarantine_copy_enabled: bool,
    ledger_schema_version: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackManifestJsonV1Read {
    pack_schema_version: String,
    tool_version: String,
    run_id: String,
    policy_id: String,
    input_corpus_id: String,
    tokenization_enabled: bool,
    #[serde(default)]
    tokenization_scope: Option<String>,
    quarantine_copy_enabled: bool,
    ledger_schema_version: String,
}

#[derive(Debug, Serialize)]
struct QuarantineIndexRecord<'a> {
    artifact_id: &'a str,
    source_locator_hash: &'a str,
    reason_code: &'a str,
}

fn write_quarantine_index(path: &Path, artifacts: &[ArtifactRunResult]) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| "could not create quarantine index (redacted)".to_string())?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "could not create quarantine index (redacted)".to_string())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));

    let file = std::fs::File::create(&tmp_path)
        .map_err(|_| "could not create quarantine index (redacted)".to_string())?;
    let mut writer = std::io::BufWriter::new(file);

    for a in artifacts {
        if a.state != veil_domain::ArtifactState::Quarantined {
            continue;
        }
        let Some(reason_code) = a.quarantine_reason_code.as_deref() else {
            return Err("quarantined artifact missing reason_code (redacted)".to_string());
        };

        let artifact_id = a.sort_key.artifact_id.to_string();
        let source_locator_hash = a.sort_key.source_locator_hash.to_string();
        let record = QuarantineIndexRecord {
            artifact_id: &artifact_id,
            source_locator_hash: &source_locator_hash,
            reason_code,
        };
        let line = serde_json::to_string(&record)
            .map_err(|_| "could not serialize quarantine index record (redacted)".to_string())?;
        writer
            .write_all(line.as_bytes())
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|_| "could not write quarantine index (redacted)".to_string())?;
    }

    writer
        .flush()
        .map_err(|_| "could not flush quarantine index (redacted)".to_string())?;
    std::fs::rename(&tmp_path, path)
        .map_err(|_| "could not persist quarantine index (redacted)".to_string())?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct ArtifactEvidenceRecord<'a> {
    artifact_id: &'a str,
    source_locator_hash: &'a str,
    size_bytes: u64,
    artifact_type: &'a str,
    state: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    quarantine_reason_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_tokens: Option<&'a [String]>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEvidenceRecordOwned {
    artifact_id: String,
    source_locator_hash: String,
    size_bytes: u64,
    artifact_type: String,
    state: String,
    #[serde(default)]
    quarantine_reason_code: Option<String>,
    #[serde(default)]
    proof_tokens: Vec<String>,
}

fn collect_proof_tokens(findings: &[veil_detect::Finding]) -> Vec<String> {
    let mut out = BTreeSet::<String>::new();
    for f in findings {
        if let Some(t) = &f.proof_token {
            out.insert(t.clone());
        }
    }
    out.into_iter().collect()
}

fn load_existing_proof_tokens(
    path: &Path,
) -> Result<BTreeMap<veil_domain::ArtifactId, Vec<String>>, String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => return Err("could not read artifacts.ndjson (redacted)".to_string()),
    };
    let reader = std::io::BufReader::new(file);

    let mut out = BTreeMap::<veil_domain::ArtifactId, Vec<String>>::new();
    for line in reader.lines() {
        let line = line
            .map_err(|_| "could not read artifacts.ndjson line (redacted)".to_string())?;
        if line.trim().is_empty() {
            continue;
        }

        let rec: ArtifactEvidenceRecordOwned =
            serde_json::from_str(&line).map_err(|_| "artifacts.ndjson is invalid (redacted)".to_string())?;

        let artifact_id = veil_domain::ArtifactId::from_hex(&rec.artifact_id)
            .map_err(|_| "artifacts.ndjson contains invalid artifact_id (redacted)".to_string())?;
        if !rec.proof_tokens.is_empty() {
            out.insert(artifact_id, rec.proof_tokens);
        }
    }

    Ok(out)
}

fn write_artifacts_evidence(path: &Path, artifacts: &[ArtifactRunResult]) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| "could not create artifacts evidence (redacted)".to_string())?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "could not create artifacts evidence (redacted)".to_string())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));

    let file = std::fs::File::create(&tmp_path)
        .map_err(|_| "could not create artifacts evidence (redacted)".to_string())?;
    let mut writer = std::io::BufWriter::new(file);

    for a in artifacts {
        let artifact_id = a.sort_key.artifact_id.to_string();
        let source_locator_hash = a.sort_key.source_locator_hash.to_string();
        let record = ArtifactEvidenceRecord {
            artifact_id: &artifact_id,
            source_locator_hash: &source_locator_hash,
            size_bytes: a.size_bytes,
            artifact_type: &a.artifact_type,
            state: a.state.as_str(),
            quarantine_reason_code: a.quarantine_reason_code.as_deref(),
            proof_tokens: if a.proof_tokens.is_empty() {
                None
            } else {
                Some(a.proof_tokens.as_slice())
            },
        };
        let line = serde_json::to_string(&record)
            .map_err(|_| "could not serialize artifacts evidence record (redacted)".to_string())?;
        writer
            .write_all(line.as_bytes())
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|_| "could not write artifacts evidence (redacted)".to_string())?;
    }

    writer
        .flush()
        .map_err(|_| "could not flush artifacts evidence (redacted)".to_string())?;
    std::fs::rename(&tmp_path, path)
        .map_err(|_| "could not persist artifacts evidence (redacted)".to_string())?;
    Ok(())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), ()> {
    let dir = path.parent().ok_or(())?;
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or(())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));

    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    std::fs::write(&tmp_path, bytes).map_err(|_| ())?;
    std::fs::rename(&tmp_path, path).map_err(|_| ())?;
    Ok(())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    let dir = path.parent().ok_or(())?;
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or(())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));

    std::fs::write(&tmp_path, bytes).map_err(|_| ())?;
    std::fs::rename(&tmp_path, path).map_err(|_| ())?;
    Ok(())
}

fn write_bytes_sync(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    let mut file = std::fs::File::create(path).map_err(|_| ())?;
    file.write_all(bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    Ok(())
}

fn ext_for_artifact_type_v1(artifact_type: &str) -> &'static str {
    match artifact_type {
        "TEXT" => "txt",
        "CSV" => "csv",
        "TSV" => "tsv",
        "JSON" => "json",
        "NDJSON" => "ndjson",
        _ => "bin",
    }
}

fn sanitized_output_path_v1(
    sanitized_dir: &Path,
    sort_key: &veil_domain::ArtifactSortKey,
    artifact_type: &str,
) -> PathBuf {
    let ext = ext_for_artifact_type_v1(artifact_type);
    sanitized_dir.join(format!(
        "{}__{}.{}",
        sort_key.source_locator_hash, sort_key.artifact_id, ext
    ))
}

fn write_quarantine_raw(
    quarantine_raw_dir: &Path,
    sort_key: &veil_domain::ArtifactSortKey,
    artifact_type: &str,
    bytes: &[u8],
) -> Result<(), ()> {
    let ext = ext_for_artifact_type_v1(artifact_type);
    let path = quarantine_raw_dir.join(format!(
        "{}__{}.{}",
        sort_key.source_locator_hash, sort_key.artifact_id, ext
    ));
    write_bytes_atomic(&path, bytes)
}

fn coverage_hash_v1(coverage: veil_domain::CoverageMapV1) -> String {
    let s = format!(
        "coverage.v1|content_text={}|structured_fields={}|metadata={}|embedded_objects={}|attachments={}",
        coverage.content_text.as_str(),
        coverage.structured_fields.as_str(),
        coverage.metadata.as_str(),
        coverage.embedded_objects.as_str(),
        coverage.attachments.as_str()
    );
    blake3::hash(s.as_bytes()).to_hex().to_string()
}

fn action_as_str(action: &veil_policy::Action) -> &'static str {
    match action {
        veil_policy::Action::Redact => "REDACT",
        veil_policy::Action::Mask { .. } => "MASK",
        veil_policy::Action::Drop => "DROP",
    }
}

fn findings_summary_rows<'a>(
    policy: &'a veil_policy::Policy,
    findings: &[veil_detect::Finding],
) -> Vec<veil_evidence::ledger::FindingsSummaryRow<'a>> {
    let mut counts = BTreeMap::<&str, u64>::new();
    for f in findings {
        *counts.entry(&f.class_id).or_insert(0) += 1;
    }

    let mut out = Vec::<veil_evidence::ledger::FindingsSummaryRow<'a>>::new();
    for class in policy.classes.iter() {
        let count = counts.get(class.class_id.as_str()).copied().unwrap_or(0);
        if count == 0 {
            continue;
        }
        out.push(veil_evidence::ledger::FindingsSummaryRow {
            class_id: &class.class_id,
            severity: class.severity.as_str(),
            action: action_as_str(&class.action),
            count,
        });
    }
    out
}

fn print_root_help(exe: &str) {
    println!("Veil (offline fail-closed privacy gate)");
    println!();
    println!("USAGE:");
    println!("  {exe} <COMMAND> [FLAGS]");
    println!();
    println!("COMMANDS:");
    println!("  run           Process a corpus into a Veil Pack");
    println!("  verify        Verify a Veil Pack output");
    println!("  policy lint   Validate policy bundle and compute policy_id");
    println!();
    println!("Run '{exe} <COMMAND> --help' for command-specific help.");
}

fn print_run_help(exe: &str) {
    println!("USAGE:");
    println!("  {exe} run --input <PATH> --output <PATH> --policy <PATH> [FLAGS]");
    println!();
    println!("REQUIRED:");
    println!("  --input <PATH>     Input corpus root (read-only)");
    println!(
        "  --output <PATH>    Output Veil Pack root (new: must not exist or be empty; resume: must be an in-progress pack)"
    );
    println!("  --policy <PATH>    Policy bundle directory");
    println!();
    println!("OPTIONAL:");
    println!("  --workdir <PATH>               Work directory (default: <output>/.veil_work/)");
    println!("  --max-workers <N>              Concurrency bound (>= 1)");
    println!("  --strictness strict            Strict is the only supported baseline in v1");
    println!("  --enable-tokenization true|false   Default: false");
    println!("  --secret-key-file <PATH>       Required if tokenization is enabled");
    println!("  --quarantine-copy true|false    Default: false");
    println!("  --limits-json <PATH>            Optional JSON file overriding safety limits");
}

fn print_verify_help(exe: &str) {
    println!("USAGE:");
    println!("  {exe} verify --pack <PATH> --policy <PATH>");
    println!();
    println!("REQUIRED:");
    println!("  --pack <PATH>     Veil Pack root");
    println!("  --policy <PATH>   Policy bundle directory");
}

fn print_policy_help(exe: &str) {
    println!("USAGE:");
    println!("  {exe} policy <SUBCOMMAND> [FLAGS]");
    println!();
    println!("SUBCOMMANDS:");
    println!("  lint   Validate policy bundle and compute policy_id");
}

fn print_policy_lint_help(exe: &str) {
    println!("USAGE:");
    println!("  {exe} policy lint --policy <PATH>");
    println!();
    println!("REQUIRED:");
    println!("  --policy <PATH>   Policy bundle directory");
}

#[allow(dead_code)]
fn _exit_quarantined_stub() -> ExitCode {
    ExitCode::from(EXIT_QUARANTINED)
}
