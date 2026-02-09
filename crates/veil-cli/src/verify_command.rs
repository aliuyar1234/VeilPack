use super::*;

pub(super) fn cmd_verify(exe: &str, args: &[String]) -> ExitCode {
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

    let mut log_ctx = LogContext::unknown();
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
    if ensure_existing_file_safe(&pack_manifest_path, "pack manifest").is_err() {
        log_error(
            log_ctx,
            "verify_pack_manifest_unsafe",
            "INTERNAL_ERROR",
            Some("pack_manifest.json path is unsafe (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }
    let pack_manifest_json = match std::fs::read_to_string(&pack_manifest_path) {
        Ok(s) => s,
        Err(_) => {
            log_error(
                log_ctx,
                "verify_pack_manifest_read_failed",
                "INTERNAL_ERROR",
                Some("could not read pack_manifest.json (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let pack_manifest: PackManifestJsonV1Read = match serde_json::from_str(&pack_manifest_json) {
        Ok(v) => v,
        Err(_) => {
            log_error(
                log_ctx,
                "verify_pack_manifest_parse_failed",
                "INTERNAL_ERROR",
                Some("pack_manifest.json is invalid JSON (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }
    };
    log_ctx = LogContext::new(&pack_manifest.run_id, &pack_manifest.policy_id);
    log_info(log_ctx, "verify_started", None);

    if pack_manifest.pack_schema_version != PACK_SCHEMA_VERSION {
        log_error(
            log_ctx,
            "verify_pack_schema_unsupported",
            "INTERNAL_ERROR",
            Some("unsupported pack_schema_version (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }

    if pack_manifest.tool_version.trim().is_empty()
        || pack_manifest.run_id.trim().is_empty()
        || pack_manifest.input_corpus_id.trim().is_empty()
    {
        log_error(
            log_ctx,
            "verify_pack_manifest_missing_fields",
            "INTERNAL_ERROR",
            Some("pack_manifest.json is missing required fields (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }
    let _ = pack_manifest.quarantine_copy_enabled;

    if pack_manifest.ledger_schema_version != veil_evidence::LEDGER_SCHEMA_VERSION {
        log_error(
            log_ctx,
            "verify_ledger_schema_unsupported",
            "INTERNAL_ERROR",
            Some("unsupported ledger schema_version (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }

    if pack_manifest.tokenization_enabled && pack_manifest.tokenization_scope.is_none() {
        log_error(
            log_ctx,
            "verify_invalid_tokenization_scope",
            "INTERNAL_ERROR",
            Some("invalid tokenization scope metadata (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }
    if !pack_manifest.tokenization_enabled && pack_manifest.tokenization_scope.is_some() {
        log_error(
            log_ctx,
            "verify_invalid_tokenization_scope",
            "INTERNAL_ERROR",
            Some("invalid tokenization scope metadata (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }
    let pdf_output_mode = match pack_manifest.pdf_output_mode.as_deref() {
        Some(raw) => match PdfOutputMode::from_limits_value(raw) {
            Some(v) => v,
            None => {
                log_error(
                    log_ctx,
                    "verify_invalid_pdf_output_mode",
                    "INTERNAL_ERROR",
                    Some("pack manifest contains invalid pdf output mode (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
        },
        None => PdfOutputMode::DerivedNdjson,
    };
    let pdf_worker = PdfWorkerOptions {
        enabled: pack_manifest.pdf_worker_enabled.unwrap_or(false),
        ..PdfWorkerOptions::default()
    };
    let max_pdf_pages = pack_manifest
        .max_pdf_pages
        .filter(|v| *v >= 1)
        .unwrap_or_else(|| veil_domain::ArchiveLimits::default().max_pdf_pages);
    let pdf_ocr = veil_extract::PdfOcrOptions::default();

    if pack_manifest.policy_id != policy.policy_id.to_string() {
        return exit_usage(
            exe,
            "policy_id mismatch for verify (redacted)",
            print_verify_help,
        );
    }

    let artifacts_path = parsed.pack.join("evidence").join("artifacts.ndjson");
    if ensure_existing_file_safe(&artifacts_path, "artifacts evidence").is_err() {
        log_error(
            log_ctx,
            "verify_artifacts_evidence_unsafe",
            "INTERNAL_ERROR",
            Some("artifacts.ndjson path is unsafe (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }
    let artifacts_file = match std::fs::File::open(&artifacts_path) {
        Ok(f) => f,
        Err(_) => {
            log_error(
                log_ctx,
                "verify_artifacts_evidence_read_failed",
                "INTERNAL_ERROR",
                Some("could not read artifacts.ndjson (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let reader = std::io::BufReader::new(artifacts_file);

    let sanitized_dir = parsed.pack.join("sanitized");
    let extractors = veil_extract::ExtractorRegistry::default();
    let detector = veil_detect::DetectorEngineV1;

    let mut failures = 0_u64;
    let mut verified_checked = 0_u64;
    let mut expected_verified_paths = HashSet::<PathBuf>::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => {
                log_error(
                    log_ctx,
                    "verify_artifacts_line_read_failed",
                    "INTERNAL_ERROR",
                    Some("could not read artifacts.ndjson line (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let rec: ArtifactEvidenceRecordOwned = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                log_error(
                    log_ctx,
                    "verify_artifacts_record_parse_failed",
                    "INTERNAL_ERROR",
                    Some("artifacts.ndjson record is invalid JSON (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
        };

        let _ = rec.size_bytes;

        if rec.state != "VERIFIED" {
            continue;
        }
        verified_checked = verified_checked.saturating_add(1);

        if rec.quarantine_reason_code.is_some() {
            log_error(
                log_ctx,
                "verify_invalid_quarantine_reason_on_verified",
                "INTERNAL_ERROR",
                Some("verified artifact has quarantine_reason_code (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }

        let artifact_id = match veil_domain::ArtifactId::from_hex(&rec.artifact_id) {
            Ok(v) => v,
            Err(_) => {
                log_error(
                    log_ctx,
                    "verify_invalid_artifact_id",
                    "INTERNAL_ERROR",
                    Some("artifacts.ndjson contains invalid artifact_id (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
        };
        let source_locator_hash =
            match veil_domain::SourceLocatorHash::from_hex(&rec.source_locator_hash) {
                Ok(v) => v,
                Err(_) => {
                    log_error(
                        log_ctx,
                        "verify_invalid_source_locator_hash",
                        "INTERNAL_ERROR",
                        Some("artifacts.ndjson contains invalid source_locator_hash (redacted)"),
                    );
                    return ExitCode::from(EXIT_FATAL);
                }
            };
        let sort_key = veil_domain::ArtifactSortKey::new(artifact_id, source_locator_hash);
        let path = sanitized_output_path_v1_with_pdf_mode(
            &sanitized_dir,
            &sort_key,
            &rec.artifact_type,
            pdf_output_mode,
        );
        if !expected_verified_paths.insert(path.clone()) {
            log_error(
                log_ctx,
                "verify_duplicate_artifact_record",
                "INTERNAL_ERROR",
                Some("artifacts.ndjson contains duplicate VERIFIED artifact (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }

        if ensure_existing_path_components_safe(&path, "sanitized output").is_err() {
            failures = failures.saturating_add(1);
            log_artifact_error(
                log_ctx,
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
                        log_ctx,
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

        let ctx = veil_extract::ArtifactContext {
            artifact_id: &sort_key.artifact_id,
            source_locator_hash: &sort_key.source_locator_hash,
        };
        let verify_artifact_type =
            verification_artifact_type_v1_with_pdf_mode(&rec.artifact_type, pdf_output_mode);
        let extracted = if verify_artifact_type == "PDF" && pdf_worker.enabled {
            extract_pdf_via_worker(ctx, &bytes, max_pdf_pages, &pdf_ocr, &pdf_worker)
        } else {
            extractors.extract_by_type(verify_artifact_type, ctx, &bytes)
        };
        let canonical = match extracted {
            veil_extract::ExtractOutcome::Extracted { canonical, .. } => canonical,
            veil_extract::ExtractOutcome::Quarantined { .. } => {
                failures = failures.saturating_add(1);
                continue;
            }
        };

        let findings = detector.detect(&policy, &canonical, None);
        let verification = veil_verify::residual_verify(&findings);
        if verification != veil_verify::VerificationOutcome::Verified {
            failures = failures.saturating_add(1);
        }
    }

    if ensure_existing_path_components_safe(&sanitized_dir, "sanitized output").is_err() {
        log_error(
            log_ctx,
            "verify_sanitized_path_unsafe",
            "INTERNAL_ERROR",
            Some("sanitized directory path is unsafe (redacted)"),
        );
        return ExitCode::from(EXIT_FATAL);
    }
    let sanitized_entries = match std::fs::read_dir(&sanitized_dir) {
        Ok(v) => v,
        Err(_) => {
            log_error(
                log_ctx,
                "verify_sanitized_read_failed",
                "INTERNAL_ERROR",
                Some("could not read sanitized directory (redacted)"),
            );
            return ExitCode::from(EXIT_FATAL);
        }
    };
    for entry in sanitized_entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                log_error(
                    log_ctx,
                    "verify_sanitized_entry_read_failed",
                    "INTERNAL_ERROR",
                    Some("could not read sanitized directory entry (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
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

    let mut verify_complete = BTreeMap::<&str, u64>::new();
    verify_complete.insert("verified_checked", verified_checked);
    verify_complete.insert("verification_failures", failures);
    log_info(log_ctx, "verify_completed", Some(verify_complete));

    if failures > 0 {
        ExitCode::from(EXIT_QUARANTINED)
    } else {
        ExitCode::from(EXIT_OK)
    }
}
