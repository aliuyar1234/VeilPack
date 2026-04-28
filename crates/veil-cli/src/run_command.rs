use std::process::ExitCode;

use crate::args::{RunArgs, exit_usage, validate_run_args};
use crate::error::AppError;
use crate::pack_finalize::{exit_code_for_summary, finalize_run};
use crate::parallel::run_pool;
use crate::run_bootstrap::bootstrap_run;
use crate::runtime_limits::{RuntimeLimits, load_runtime_limits_from_json};
use crate::{EXIT_FATAL, print_run_help};

pub(super) fn cmd_run(exe: &str, parsed: RunArgs) -> ExitCode {
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

    match run_with_args(exe, parsed, runtime_limits) {
        Ok(code) => code,
        Err(AppError::Usage(msg)) => exit_usage(exe, &msg, print_run_help),
        Err(_e) => ExitCode::from(EXIT_FATAL),
    }
}

fn run_with_args(
    exe: &str,
    parsed: RunArgs,
    runtime_limits: RuntimeLimits,
) -> Result<ExitCode, AppError> {
    let mut run = bootstrap_run(exe, parsed, runtime_limits)?;

    // Open a run-level span so every subsequent event automatically picks up
    // run_id and policy_id without per-call plumbing. bootstrap_run already
    // emitted its own events with explicit run_id / policy_id fields when
    // those identifiers were known.
    let run_span = tracing::info_span!(
        "run",
        run_id = run.context.run_id_str(),
        policy_id = run.context.policy_id_str(),
    );
    let _span_guard = run_span.enter();

    // Phase 4 always uses the worker-pool harness: with N=1 it
    // degenerates to producer + 1 worker + committer (still serial in
    // observable effect, byte-identical to the pre-pool inline code);
    // with N > 1 it parallelizes the pure pipeline while the committer
    // applies side-effects in `ArtifactSortKey` order.
    let max_workers = run.context.parsed.max_workers.unwrap_or(1);
    let _verified_count = run_pool(&mut run, max_workers)?;

    let summary = finalize_run(
        &run.context,
        &run.paths,
        &run.artifacts,
        &run.ledger,
        &run.proof_tokens_by_artifact,
    )?;

    Ok(exit_code_for_summary(&summary))
}
