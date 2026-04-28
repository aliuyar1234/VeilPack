use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::EXIT_USAGE;
use crate::fs_safety::{
    ensure_dir_exists, ensure_existing_path_components_safe, ensure_file_exists,
    ensure_output_fresh_or_resumable, ensure_policy_json_exists,
};
use crate::runtime_limits::load_runtime_limits_from_json;

/// Top-level Veil CLI parser.
///
/// Subcommands map 1:1 to the public command surface. The `extract-worker`
/// subcommand is internal and hidden from `--help` output, but kept on the
/// same parser so the binary handles all entry points uniformly.
#[derive(Debug, Parser)]
#[command(
    name = "veil",
    bin_name = "veil",
    about = "Veil (offline fail-closed privacy gate)",
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Process a corpus into a Veil Pack.
    Run(RunArgs),
    /// Verify a Veil Pack output.
    Verify(VerifyArgs),
    /// Policy bundle utilities.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCommand,
    },
    /// Internal: extract one artifact in an isolated worker.
    #[command(hide = true, name = "extract-worker")]
    ExtractWorker(crate::extract_worker::ExtractWorkerArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum PolicyCommand {
    /// Validate policy bundle and compute policy_id.
    Lint(PolicyLintArgs),
}

#[derive(Debug, clap::Args)]
#[command(about = "Process a corpus into a Veil Pack")]
pub(crate) struct RunArgs {
    /// Input corpus root (read-only).
    #[arg(long)]
    pub(crate) input: PathBuf,
    /// Output Veil Pack root (new: must not exist or be empty; resume: must be an in-progress pack).
    #[arg(long)]
    pub(crate) output: PathBuf,
    /// Policy bundle directory.
    #[arg(long)]
    pub(crate) policy: PathBuf,
    /// Work directory (default: <output>/.veil_work/).
    #[arg(long)]
    pub(crate) workdir: Option<PathBuf>,
    /// Worker bound (>= 1). N=1 runs serially (byte-identical to the
    /// pre-Phase-4 baseline). N > 1 runs the pure pipeline in parallel
    /// while a single committer thread applies side-effects in
    /// `ArtifactSortKey` order so output is deterministic regardless of
    /// worker count.
    #[arg(long, value_parser = parse_max_workers)]
    pub(crate) max_workers: Option<u32>,
    /// Strictness baseline. v1 only accepts `strict`.
    #[arg(long)]
    pub(crate) strictness: Option<String>,
    /// Enable token-mask outputs. Accepts the literal `true` or `false`.
    /// Default: false.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_flag,
        default_value = "false",
        num_args = 1,
        action = clap::ArgAction::Set,
    )]
    pub(crate) enable_tokenization: bool,
    /// Required if tokenization is enabled.
    #[arg(long)]
    pub(crate) secret_key_file: Option<PathBuf>,
    /// Persist a raw copy of every quarantined artifact. Accepts `true` or
    /// `false`. Default: false.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_flag,
        default_value = "false",
        num_args = 1,
        action = clap::ArgAction::Set,
    )]
    pub(crate) quarantine_copy: bool,
    /// Run risky extractors (zip/tar/eml/mbox/ooxml) in an isolated worker.
    /// Accepts `true` or `false`. Default: false.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_flag,
        default_value = "false",
        num_args = 1,
        action = clap::ArgAction::Set,
    )]
    pub(crate) isolate_risky_extractors: bool,
    /// Optional JSON file overriding safety limits.
    #[arg(long)]
    pub(crate) limits_json: Option<PathBuf>,
}

pub(crate) fn validate_run_args(args: &RunArgs) -> Result<(), String> {
    ensure_dir_exists(&args.input, "input")?;
    ensure_existing_path_components_safe(&args.input, "input")?;
    ensure_dir_exists(&args.policy, "policy")?;
    ensure_policy_json_exists(&args.policy)?;
    let workdir = args
        .workdir
        .clone()
        .unwrap_or_else(|| args.output.join(".veil_work"));
    ensure_existing_path_components_safe(&args.output, "output")?;
    ensure_existing_path_components_safe(&workdir, "workdir")?;
    ensure_output_fresh_or_resumable(&args.output, &workdir, args.quarantine_copy)?;

    if let Ok(meta) = std::fs::metadata(&workdir)
        && !meta.is_dir()
    {
        return Err("workdir path must be a directory when it exists".to_string());
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
        let _limits = load_runtime_limits_from_json(limits_json)?;
    }

    Ok(())
}

#[derive(Debug, clap::Args)]
#[command(about = "Verify a Veil Pack output")]
pub(crate) struct VerifyArgs {
    /// Existing Veil Pack root.
    #[arg(long)]
    pub(crate) pack: PathBuf,
    /// Policy bundle directory.
    #[arg(long)]
    pub(crate) policy: PathBuf,
}

pub(crate) fn validate_verify_args(args: &VerifyArgs) -> Result<(), String> {
    ensure_dir_exists(&args.pack, "pack")?;
    ensure_existing_path_components_safe(&args.pack, "pack")?;
    ensure_dir_exists(&args.policy, "policy")?;
    ensure_policy_json_exists(&args.policy)?;
    Ok(())
}

#[derive(Debug, clap::Args)]
#[command(about = "Validate policy bundle and compute policy_id")]
pub(crate) struct PolicyLintArgs {
    /// Policy bundle directory.
    #[arg(long)]
    pub(crate) policy: PathBuf,
}

pub(crate) fn validate_policy_lint_args(args: &PolicyLintArgs) -> Result<(), String> {
    ensure_dir_exists(&args.policy, "policy")?;
    ensure_policy_json_exists(&args.policy)?;
    Ok(())
}

/// Custom value parser preserving the exact `true`/`false` semantics of
/// the legacy hand-rolled parser. Anything else is a usage error.
fn parse_bool_flag(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("must be 'true' or 'false'".to_string()),
    }
}

/// Parse `--max-workers` as a positive `u32`. Zero is rejected.
fn parse_max_workers(value: &str) -> Result<u32, String> {
    let n: u32 = value
        .parse()
        .map_err(|_| "must be a positive integer".to_string())?;
    if n == 0 {
        return Err(">= 1".to_string());
    }
    Ok(n)
}

pub(crate) fn exit_usage(exe: &str, message: &str, help: fn(&str)) -> ExitCode {
    tracing::error!(
        event = "usage_error",
        reason_code = "USAGE",
        detail = message,
        "usage error"
    );
    help(exe);
    ExitCode::from(EXIT_USAGE)
}
