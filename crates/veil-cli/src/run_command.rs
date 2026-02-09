use super::*;

pub(super) fn cmd_run(exe: &str, args: &[String]) -> ExitCode {
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

    let runtime_limits = match parsed.limits_json.as_ref() {
        Some(path) => match load_runtime_limits_from_json(path) {
            Ok(l) => l,
            Err(msg) => return exit_usage(exe, &msg, print_run_help),
        },
        None => RuntimeLimits::default(),
    };
    let archive_limits = runtime_limits.archive_limits;

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
            let policy_id_for_log = policy_id.to_string();
            log_error(
                LogContext::new(UNKNOWN_LOG_ID, &policy_id_for_log),
                "input_enumeration_failed",
                "INTERNAL_ERROR",
                Some(msg.as_str()),
            );
            return ExitCode::from(EXIT_FATAL);
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
                    return exit_usage(
                        exe,
                        "--enable-tokenization true requires --secret-key-file",
                        print_run_help,
                    );
                }
            };
            let key_bytes = match std::fs::read(key_path) {
                Ok(b) => b,
                Err(_) => {
                    return exit_usage(
                        exe,
                        "secret-key-file is unreadable (redacted)",
                        print_run_help,
                    );
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
    let mut run_start_counters = BTreeMap::<&str, u64>::new();
    run_start_counters.insert("artifacts_discovered", artifacts.len() as u64);
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
        log_error(
            log_ctx,
            "create_pack_dirs_failed",
            "INTERNAL_ERROR",
            Some(msg.as_str()),
        );
        return ExitCode::from(EXIT_FATAL);
    }

    if let Err(msg) = ensure_dir_exists_or_create(&workdir, "workdir") {
        log_error(
            log_ctx,
            "create_workdir_failed",
            "INTERNAL_ERROR",
            Some(msg.as_str()),
        );
        return ExitCode::from(EXIT_FATAL);
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

    let mut ledger = if is_resume {
        let marker_run_id = match std::fs::read_to_string(&marker_path) {
            Ok(s) => s,
            Err(_) => {
                log_error(
                    log_ctx,
                    "resume_marker_read_failed",
                    "INTERNAL_ERROR",
                    Some("could not read in-progress marker (redacted)"),
                );
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
                log_error(
                    log_ctx,
                    "resume_ledger_open_failed",
                    "INTERNAL_ERROR",
                    Some("could not open ledger.sqlite3 for resume (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
        };

        let meta_policy_id = match ledger.get_meta("policy_id") {
            Ok(Some(v)) => v,
            Ok(None) => {
                log_error(
                    log_ctx,
                    "ledger_meta_missing",
                    "INTERNAL_ERROR",
                    Some("ledger missing required meta key policy_id (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            Err(_) => {
                log_error(
                    log_ctx,
                    "ledger_read_failed",
                    "INTERNAL_ERROR",
                    Some("ledger read failed (redacted)"),
                );
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
                log_error(
                    log_ctx,
                    "ledger_meta_missing",
                    "INTERNAL_ERROR",
                    Some("ledger missing required meta key run_id (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            Err(_) => {
                log_error(
                    log_ctx,
                    "ledger_read_failed",
                    "INTERNAL_ERROR",
                    Some("ledger read failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
        };
        if meta_run_id != run_id_str {
            return exit_usage(exe, "run_id mismatch for resume (redacted)", print_run_help);
        }

        let meta_input_corpus_id = match ledger.get_meta("input_corpus_id") {
            Ok(Some(v)) => v,
            Ok(None) => {
                log_error(
                    log_ctx,
                    "ledger_meta_missing",
                    "INTERNAL_ERROR",
                    Some("ledger missing required meta key input_corpus_id (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            Err(_) => {
                log_error(
                    log_ctx,
                    "ledger_read_failed",
                    "INTERNAL_ERROR",
                    Some("ledger read failed (redacted)"),
                );
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

        if !validate_or_seed_resume_meta(&ledger, "proof_scope", proof_scope) {
            return exit_usage(
                exe,
                "proof scope mismatch for resume (redacted)",
                print_run_help,
            );
        }
        if !validate_or_seed_resume_meta(&ledger, "proof_key_commitment", &proof_key_commitment) {
            return exit_usage(
                exe,
                "proof key commitment mismatch for resume (redacted)",
                print_run_help,
            );
        }
        if !validate_or_seed_resume_meta(&ledger, "tokenization_enabled", tokenization_enabled_meta)
        {
            return exit_usage(
                exe,
                "tokenization setting mismatch for resume (redacted)",
                print_run_help,
            );
        }
        if !validate_or_seed_resume_meta(&ledger, "tokenization_scope", tokenization_scope_meta) {
            return exit_usage(
                exe,
                "tokenization scope mismatch for resume (redacted)",
                print_run_help,
            );
        }

        ledger
    } else {
        if std::fs::write(&marker_path, &run_id_str).is_err() {
            log_error(
                log_ctx,
                "write_resume_marker_failed",
                "INTERNAL_ERROR",
                Some("could not write in-progress marker (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }

        match veil_evidence::Ledger::create_new(
            &ledger_path,
            TOOL_VERSION,
            &policy_id,
            &run_id,
            &input_corpus_id,
        ) {
            Ok(l) => {
                if l.upsert_meta("proof_scope", proof_scope).is_err()
                    || l.upsert_meta("proof_key_commitment", &proof_key_commitment)
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
                    return ExitCode::from(EXIT_FATAL);
                }
                l
            }
            Err(_) => {
                log_error(
                    log_ctx,
                    "create_ledger_failed",
                    "INTERNAL_ERROR",
                    Some("could not create ledger.sqlite3 (redacted)"),
                );
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
        log_error(
            log_ctx,
            "create_staging_dir_failed",
            "INTERNAL_ERROR",
            Some("could not create staging directory (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }
    let mut workdir_bytes_observed = match dir_total_file_bytes(&workdir) {
        Ok(v) => v,
        Err(_) => {
            log_error(
                log_ctx,
                "workdir_usage_scan_failed",
                "INTERNAL_ERROR",
                Some("could not measure workdir usage (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }
    };
    if workdir_bytes_observed > runtime_limits.max_workdir_bytes {
        log_error(
            log_ctx,
            "workdir_usage_limit_exceeded",
            "LIMIT_EXCEEDED",
            Some("workdir usage exceeds configured limit (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }

    let extractors = veil_extract::ExtractorRegistry::new(archive_limits);
    let detector = veil_detect::DetectorEngineV1;
    let transformer = veil_transform::TransformerV1;

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
                return ExitCode::from(EXIT_FATAL);
            }
        }
    }

    let mut verified_count = 0_u64;
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
            log_error(
                log_ctx,
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }

        let state = match ledger.artifact_summary(&artifact.sort_key.artifact_id) {
            Ok(Some(s)) => s.state,
            Ok(None) => {
                log_error(
                    log_ctx,
                    "ledger_missing_artifact_record",
                    "INTERNAL_ERROR",
                    Some("ledger missing artifact record (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            Err(_) => {
                log_error(
                    log_ctx,
                    "ledger_read_failed",
                    "INTERNAL_ERROR",
                    Some("ledger read failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
        };
        if state.is_terminal() {
            continue;
        }

        proof_tokens_by_artifact.remove(&artifact.sort_key.artifact_id);

        let bytes = match read_artifact_bytes_for_processing(
            &artifact.path,
            artifact.size_bytes,
            &artifact.sort_key.artifact_id,
            archive_limits.max_bytes_per_artifact,
        ) {
            Ok(b) => b,
            Err(ReadArtifactError::LimitExceeded) => {
                if ledger
                    .quarantine(
                        &artifact.sort_key.artifact_id,
                        veil_domain::QuarantineReasonCode::LimitExceeded,
                    )
                    .is_err()
                {
                    log_error(
                        log_ctx,
                        "ledger_write_failed",
                        "INTERNAL_ERROR",
                        Some("ledger write failed (redacted)"),
                    );
                    return ExitCode::from(EXIT_FATAL);
                }
                continue;
            }
            Err(ReadArtifactError::IdentityMismatch) | Err(ReadArtifactError::Io) => {
                if ledger
                    .quarantine(
                        &artifact.sort_key.artifact_id,
                        veil_domain::QuarantineReasonCode::InternalError,
                    )
                    .is_err()
                {
                    log_error(
                        log_ctx,
                        "ledger_write_failed",
                        "INTERNAL_ERROR",
                        Some("ledger write failed (redacted)"),
                    );
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
                if ledger
                    .quarantine(&artifact.sort_key.artifact_id, reason)
                    .is_err()
                {
                    log_error(
                        log_ctx,
                        "ledger_write_failed",
                        "INTERNAL_ERROR",
                        Some("ledger write failed (redacted)"),
                    );
                    return ExitCode::from(EXIT_FATAL);
                }
                if write_quarantine_raw_or_fail(
                    parsed.quarantine_copy,
                    &quarantine_raw_dir,
                    &artifact.sort_key,
                    &artifact.artifact_type,
                    &bytes,
                    log_ctx,
                )
                .is_err()
                {
                    return ExitCode::from(EXIT_FATAL);
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
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            if write_quarantine_raw_or_fail(
                parsed.quarantine_copy,
                &quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                &bytes,
                log_ctx,
            )
            .is_err()
            {
                return ExitCode::from(EXIT_FATAL);
            }
            continue;
        }

        let coverage_hash = coverage_hash_v1(coverage);
        if ledger
            .mark_extracted(&artifact.sort_key.artifact_id, extractor_id, &coverage_hash)
            .is_err()
        {
            log_error(
                log_ctx,
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }

        let findings = detector.detect(&policy, &canonical, Some(&*proof_key));
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
            log_error(
                log_ctx,
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }

        let sanitized_bytes = match transformer.transform(&policy, &canonical) {
            veil_transform::TransformOutcome::Transformed { sanitized_bytes } => sanitized_bytes,
            veil_transform::TransformOutcome::Quarantined { reason } => {
                if ledger
                    .quarantine(&artifact.sort_key.artifact_id, reason)
                    .is_err()
                {
                    log_error(
                        log_ctx,
                        "ledger_write_failed",
                        "INTERNAL_ERROR",
                        Some("ledger write failed (redacted)"),
                    );
                    return ExitCode::from(EXIT_FATAL);
                }
                if write_quarantine_raw_or_fail(
                    parsed.quarantine_copy,
                    &quarantine_raw_dir,
                    &artifact.sort_key,
                    &artifact.artifact_type,
                    &bytes,
                    log_ctx,
                )
                .is_err()
                {
                    return ExitCode::from(EXIT_FATAL);
                }
                continue;
            }
        };

        if ledger
            .mark_transformed(&artifact.sort_key.artifact_id)
            .is_err()
        {
            log_error(
                log_ctx,
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }

        let verify_artifact_type = verification_artifact_type_v1(&artifact.artifact_type);
        let extracted_out = extractors.extract_by_type(verify_artifact_type, ctx, &sanitized_bytes);
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
                    log_error(
                        log_ctx,
                        "ledger_write_failed",
                        "INTERNAL_ERROR",
                        Some("ledger write failed (redacted)"),
                    );
                    return ExitCode::from(EXIT_FATAL);
                }
                if write_quarantine_raw_or_fail(
                    parsed.quarantine_copy,
                    &quarantine_raw_dir,
                    &artifact.sort_key,
                    &artifact.artifact_type,
                    &bytes,
                    log_ctx,
                )
                .is_err()
                {
                    return ExitCode::from(EXIT_FATAL);
                }
                continue;
            }
        };

        let findings_out = detector.detect(&policy, &canonical_out, Some(&*proof_key));
        let verification = veil_verify::residual_verify(&findings_out);
        if verification != veil_verify::VerificationOutcome::Verified {
            let reason = match verification {
                veil_verify::VerificationOutcome::Verified => unreachable!(),
                veil_verify::VerificationOutcome::Quarantined { reason } => reason,
            };
            if ledger
                .quarantine(&artifact.sort_key.artifact_id, reason)
                .is_err()
            {
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            if write_quarantine_raw_or_fail(
                parsed.quarantine_copy,
                &quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                &bytes,
                log_ctx,
            )
            .is_err()
            {
                return ExitCode::from(EXIT_FATAL);
            }
            continue;
        }

        let output_id = veil_domain::hash_output_id(&sanitized_bytes);
        let output_id_str = output_id.to_string();

        let dest_path =
            sanitized_output_path_v1(&sanitized_dir, &artifact.sort_key, &artifact.artifact_type);

        if ensure_existing_path_components_safe(&dest_path, "sanitized output").is_err() {
            if ledger
                .quarantine(
                    &artifact.sort_key.artifact_id,
                    veil_domain::QuarantineReasonCode::InternalError,
                )
                .is_err()
            {
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            if write_quarantine_raw_or_fail(
                parsed.quarantine_copy,
                &quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                &bytes,
                log_ctx,
            )
            .is_err()
            {
                return ExitCode::from(EXIT_FATAL);
            }
            log_artifact_error(
                log_ctx,
                "sanitized_output_path_unsafe",
                "INTERNAL_ERROR",
                &artifact.sort_key,
                Some("sanitized output path is unsafe (redacted)"),
            );
            continue;
        }

        if let Ok(meta) = std::fs::symlink_metadata(&dest_path)
            && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
        {
            if ledger
                .quarantine(
                    &artifact.sort_key.artifact_id,
                    veil_domain::QuarantineReasonCode::InternalError,
                )
                .is_err()
            {
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            if write_quarantine_raw_or_fail(
                parsed.quarantine_copy,
                &quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                &bytes,
                log_ctx,
            )
            .is_err()
            {
                return ExitCode::from(EXIT_FATAL);
            }
            log_artifact_error(
                log_ctx,
                "sanitized_output_path_symlink",
                "INTERNAL_ERROR",
                &artifact.sort_key,
                Some("sanitized output path is unsafe (redacted)"),
            );
            continue;
        }

        if let Ok(meta) = std::fs::metadata(&dest_path)
            && meta.is_file()
        {
            let existing = std::fs::read(&dest_path).unwrap_or_default();
            if veil_domain::hash_output_id(&existing) == output_id {
                if ledger
                    .mark_verified(&artifact.sort_key.artifact_id, &output_id_str)
                    .is_err()
                {
                    log_error(
                        log_ctx,
                        "ledger_write_failed",
                        "INTERNAL_ERROR",
                        Some("ledger write failed (redacted)"),
                    );
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
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            if write_quarantine_raw_or_fail(
                parsed.quarantine_copy,
                &quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                &bytes,
                log_ctx,
            )
            .is_err()
            {
                return ExitCode::from(EXIT_FATAL);
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
                    log_error(
                        log_ctx,
                        "ledger_write_failed",
                        "INTERNAL_ERROR",
                        Some("ledger write failed (redacted)"),
                    );
                    return ExitCode::from(EXIT_FATAL);
                }
                if write_quarantine_raw_or_fail(
                    parsed.quarantine_copy,
                    &quarantine_raw_dir,
                    &artifact.sort_key,
                    &artifact.artifact_type,
                    &bytes,
                    log_ctx,
                )
                .is_err()
                {
                    return ExitCode::from(EXIT_FATAL);
                }
                continue;
            }
        };

        let sanitized_size = u64::try_from(sanitized_bytes.len()).unwrap_or(u64::MAX);
        if sanitized_size > archive_limits.max_bytes_per_artifact {
            if ledger
                .quarantine(
                    &artifact.sort_key.artifact_id,
                    veil_domain::QuarantineReasonCode::LimitExceeded,
                )
                .is_err()
            {
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            if write_quarantine_raw_or_fail(
                parsed.quarantine_copy,
                &quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                &bytes,
                log_ctx,
            )
            .is_err()
            {
                return ExitCode::from(EXIT_FATAL);
            }
            continue;
        }

        if workdir_bytes_observed.saturating_add(sanitized_size) > runtime_limits.max_workdir_bytes
        {
            if ledger
                .quarantine(
                    &artifact.sort_key.artifact_id,
                    veil_domain::QuarantineReasonCode::LimitExceeded,
                )
                .is_err()
            {
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            if write_quarantine_raw_or_fail(
                parsed.quarantine_copy,
                &quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                &bytes,
                log_ctx,
            )
            .is_err()
            {
                return ExitCode::from(EXIT_FATAL);
            }
            continue;
        }

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
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            if write_quarantine_raw_or_fail(
                parsed.quarantine_copy,
                &quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                &bytes,
                log_ctx,
            )
            .is_err()
            {
                return ExitCode::from(EXIT_FATAL);
            }
            continue;
        }
        workdir_bytes_observed = workdir_bytes_observed.saturating_add(sanitized_size);

        if std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_stage_write") {
            log_error(
                log_ctx,
                "failpoint_triggered",
                "INTERNAL_ERROR",
                Some("failpoint triggered (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }

        if ensure_existing_path_components_safe(&dest_path, "sanitized output").is_err() {
            let _ = std::fs::remove_file(&stage_path);
            workdir_bytes_observed = workdir_bytes_observed.saturating_sub(sanitized_size);
            if ledger
                .quarantine(
                    &artifact.sort_key.artifact_id,
                    veil_domain::QuarantineReasonCode::InternalError,
                )
                .is_err()
            {
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            if write_quarantine_raw_or_fail(
                parsed.quarantine_copy,
                &quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                &bytes,
                log_ctx,
            )
            .is_err()
            {
                return ExitCode::from(EXIT_FATAL);
            }
            continue;
        }

        if std::fs::rename(&stage_path, &dest_path).is_err() {
            let _ = std::fs::remove_file(&stage_path);
            workdir_bytes_observed = workdir_bytes_observed.saturating_sub(sanitized_size);
            if write_bytes_atomic(&dest_path, &sanitized_bytes).is_err() {
                if ledger
                    .quarantine(
                        &artifact.sort_key.artifact_id,
                        veil_domain::QuarantineReasonCode::InternalError,
                    )
                    .is_err()
                {
                    log_error(
                        log_ctx,
                        "ledger_write_failed",
                        "INTERNAL_ERROR",
                        Some("ledger write failed (redacted)"),
                    );
                    return ExitCode::from(EXIT_FATAL);
                }
                if write_quarantine_raw_or_fail(
                    parsed.quarantine_copy,
                    &quarantine_raw_dir,
                    &artifact.sort_key,
                    &artifact.artifact_type,
                    &bytes,
                    log_ctx,
                )
                .is_err()
                {
                    return ExitCode::from(EXIT_FATAL);
                }
                continue;
            }
        } else {
            workdir_bytes_observed = workdir_bytes_observed.saturating_sub(sanitized_size);
            if sync_parent_dir(&dest_path).is_err() {
                let _ = std::fs::remove_file(&dest_path);
                if ledger
                    .quarantine(
                        &artifact.sort_key.artifact_id,
                        veil_domain::QuarantineReasonCode::InternalError,
                    )
                    .is_err()
                {
                    log_error(
                        log_ctx,
                        "ledger_write_failed",
                        "INTERNAL_ERROR",
                        Some("ledger write failed (redacted)"),
                    );
                    return ExitCode::from(EXIT_FATAL);
                }
                if write_quarantine_raw_or_fail(
                    parsed.quarantine_copy,
                    &quarantine_raw_dir,
                    &artifact.sort_key,
                    &artifact.artifact_type,
                    &bytes,
                    log_ctx,
                )
                .is_err()
                {
                    return ExitCode::from(EXIT_FATAL);
                }
                continue;
            }
        }

        if ensure_existing_file_safe(&dest_path, "sanitized output").is_err() {
            let _ = std::fs::remove_file(&dest_path);
            if ledger
                .quarantine(
                    &artifact.sort_key.artifact_id,
                    veil_domain::QuarantineReasonCode::InternalError,
                )
                .is_err()
            {
                log_error(
                    log_ctx,
                    "ledger_write_failed",
                    "INTERNAL_ERROR",
                    Some("ledger write failed (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            if write_quarantine_raw_or_fail(
                parsed.quarantine_copy,
                &quarantine_raw_dir,
                &artifact.sort_key,
                &artifact.artifact_type,
                &bytes,
                log_ctx,
            )
            .is_err()
            {
                return ExitCode::from(EXIT_FATAL);
            }
            continue;
        }

        if ledger
            .mark_verified(&artifact.sort_key.artifact_id, &output_id_str)
            .is_err()
        {
            log_error(
                log_ctx,
                "ledger_write_failed",
                "INTERNAL_ERROR",
                Some("ledger write failed (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }

        verified_count = verified_count.saturating_add(1);
        if verified_count == 1
            && std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_first_verified")
        {
            log_error(
                log_ctx,
                "failpoint_triggered",
                "INTERNAL_ERROR",
                Some("failpoint triggered (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }
    }

    let mut results = Vec::with_capacity(artifacts.len());
    for artifact in artifacts.iter() {
        let summary = match ledger.artifact_summary(&artifact.sort_key.artifact_id) {
            Ok(Some(s)) => s,
            Ok(None) => {
                log_error(
                    log_ctx,
                    "ledger_missing_artifact_record",
                    "INTERNAL_ERROR",
                    Some("ledger missing artifact record (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
            Err(_) => {
                log_error(
                    log_ctx,
                    "ledger_read_failed",
                    "INTERNAL_ERROR",
                    Some("ledger read failed (redacted)"),
                );
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
                    log_error(
                        log_ctx,
                        "quarantine_reason_missing",
                        "INTERNAL_ERROR",
                        Some("quarantined artifact missing reason code (redacted)"),
                    );
                    return ExitCode::from(EXIT_FATAL);
                };
                *quarantine_reason_counts.entry(code.clone()).or_insert(0) += 1;
            }
            _ => {}
        }
    }

    if let Err(msg) = write_quarantine_index(&quarantine_index_path, &results) {
        log_error(
            log_ctx,
            "write_quarantine_index_failed",
            "INTERNAL_ERROR",
            Some(msg.as_str()),
        );
        return ExitCode::from(EXIT_FATAL);
    }

    if let Err(msg) = write_artifacts_evidence(&artifacts_ndjson_path, &results) {
        log_error(
            log_ctx,
            "write_artifacts_evidence_failed",
            "INTERNAL_ERROR",
            Some(msg.as_str()),
        );
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
        log_error(
            log_ctx,
            "write_run_manifest_failed",
            "INTERNAL_ERROR",
            Some("could not write run_manifest.json (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }

    let pack_manifest_path = parsed.output.join("pack_manifest.json");
    let pack_manifest = PackManifestJsonV1 {
        pack_schema_version: PACK_SCHEMA_VERSION,
        tool_version: TOOL_VERSION,
        run_id: run_id_str.clone(),
        policy_id: policy_id_str.clone(),
        input_corpus_id: input_corpus_id_str.clone(),
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
        log_error(
            log_ctx,
            "write_pack_manifest_failed",
            "INTERNAL_ERROR",
            Some("could not write pack_manifest.json (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }

    let mut run_complete_counters = BTreeMap::<&str, u64>::new();
    run_complete_counters.insert("artifacts_discovered", artifacts.len() as u64);
    run_complete_counters.insert("artifacts_verified", artifacts_verified);
    run_complete_counters.insert("artifacts_quarantined", artifacts_quarantined);
    log_info(log_ctx, "run_completed", Some(run_complete_counters));

    let _ = std::fs::remove_file(&marker_path);

    if artifacts_quarantined > 0 {
        ExitCode::from(EXIT_QUARANTINED)
    } else {
        ExitCode::from(EXIT_OK)
    }
}
