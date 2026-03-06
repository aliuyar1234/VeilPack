use std::process::ExitCode;

use crate::args::{exit_usage, parse_run_args, validate_run_args};
use crate::artifact_processor::{ArtifactProcessStatus, ArtifactProcessor};
use crate::logging::log_error;
use crate::pack_finalize::{exit_code_for_summary, finalize_run};
use crate::run_bootstrap::bootstrap_run;
use crate::runtime_limits::{RuntimeLimits, load_runtime_limits_from_json};
use crate::{EXIT_FATAL, EXIT_OK, print_run_help};

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

    let mut run = match bootstrap_run(exe, parsed, runtime_limits) {
        Ok(v) => v,
        Err(code) => return code,
    };

    let extractors = veil_extract::ExtractorRegistry::new(run.context.archive_limits);
    let detector = veil_detect::DetectorEngineV1;
    let transformer = veil_transform::TransformerV1;

    let mut verified_count = 0_u64;
    for artifact in &run.artifacts {
        let status = {
            let mut processor = ArtifactProcessor {
                context: &run.context,
                paths: &run.paths,
                ledger: &mut run.ledger,
                extractors: &extractors,
                detector: &detector,
                transformer: &transformer,
                proof_tokens_by_artifact: &mut run.proof_tokens_by_artifact,
                workdir_bytes_observed: &mut run.workdir_bytes_observed,
            };
            match processor.process(artifact) {
                Ok(v) => v,
                Err(code) => return code,
            }
        };

        if matches!(status, ArtifactProcessStatus::Verified) {
            verified_count = verified_count.saturating_add(1);
            if verified_count == 1
                && std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_first_verified")
            {
                log_error(
                    run.context.log_ctx(),
                    "failpoint_triggered",
                    "INTERNAL_ERROR",
                    Some("failpoint triggered (redacted)"),
                );
                return ExitCode::from(EXIT_FATAL);
            }
        }
    }

    let summary = match finalize_run(
        &run.context,
        &run.paths,
        &run.artifacts,
        &run.ledger,
        &run.proof_tokens_by_artifact,
    ) {
        Ok(v) => v,
        Err(code) => return code,
    };

    exit_code_for_summary(&summary)
}
