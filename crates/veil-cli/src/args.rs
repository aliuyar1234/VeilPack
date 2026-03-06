use std::path::PathBuf;
use std::process::ExitCode;

use crate::EXIT_USAGE;
use crate::fs_safety::{
    ensure_dir_exists, ensure_existing_path_components_safe, ensure_file_exists,
    ensure_output_fresh_or_resumable, ensure_policy_json_exists,
};
use crate::logging::{LogContext, log_error};
use crate::runtime_limits::load_runtime_limits_from_json;

#[derive(Debug)]
pub(crate) struct RunArgs {
    pub(crate) input: PathBuf,
    pub(crate) output: PathBuf,
    pub(crate) policy: PathBuf,
    pub(crate) workdir: Option<PathBuf>,
    pub(crate) max_workers: Option<u32>,
    pub(crate) strictness: Option<String>,
    pub(crate) enable_tokenization: bool,
    pub(crate) secret_key_file: Option<PathBuf>,
    pub(crate) quarantine_copy: bool,
    pub(crate) isolate_risky_extractors: bool,
    pub(crate) limits_json: Option<PathBuf>,
}

pub(crate) fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut input = None;
    let mut output = None;
    let mut policy = None;
    let mut workdir = None;
    let mut max_workers = None;
    let mut strictness = None;
    let mut enable_tokenization = false;
    let mut secret_key_file = None;
    let mut quarantine_copy = false;
    let mut isolate_risky_extractors = false;
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
            "--isolate-risky-extractors" => {
                i += 1;
                let raw: PathBuf = require_value(args, i, "--isolate-risky-extractors")?;
                let raw = raw.to_str().ok_or_else(|| {
                    "--isolate-risky-extractors must be 'true' or 'false'".to_string()
                })?;
                isolate_risky_extractors = parse_bool_flag("--isolate-risky-extractors", raw)?;
            }
            "--limits-json" => {
                i += 1;
                limits_json = Some(require_value(args, i, "--limits-json")?);
            }
            unknown if unknown.starts_with("--") => {
                let _ = unknown;
                return Err("unknown flag (redacted)".to_string());
            }
            other => {
                let _ = other;
                return Err("unexpected argument (redacted)".to_string());
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
        isolate_risky_extractors,
        limits_json,
    })
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
        let _limits = load_runtime_limits_from_json(limits_json)?;
    }

    Ok(())
}

#[derive(Debug)]
pub(crate) struct VerifyArgs {
    pub(crate) pack: PathBuf,
    pub(crate) policy: PathBuf,
}

pub(crate) fn parse_verify_args(args: &[String]) -> Result<VerifyArgs, String> {
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
                let _ = unknown;
                return Err("unknown flag (redacted)".to_string());
            }
            other => {
                let _ = other;
                return Err("unexpected argument (redacted)".to_string());
            }
        }
        i += 1;
    }

    Ok(VerifyArgs {
        pack: pack.ok_or_else(|| "missing required flag: --pack".to_string())?,
        policy: policy.ok_or_else(|| "missing required flag: --policy".to_string())?,
    })
}

pub(crate) fn validate_verify_args(args: &VerifyArgs) -> Result<(), String> {
    ensure_dir_exists(&args.pack, "pack")?;
    ensure_existing_path_components_safe(&args.pack, "pack")?;
    ensure_dir_exists(&args.policy, "policy")?;
    ensure_policy_json_exists(&args.policy)?;
    Ok(())
}

#[derive(Debug)]
pub(crate) struct PolicyLintArgs {
    pub(crate) policy: PathBuf,
}

pub(crate) fn parse_policy_lint_args(args: &[String]) -> Result<PolicyLintArgs, String> {
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
                let _ = unknown;
                return Err("unknown flag (redacted)".to_string());
            }
            other => {
                let _ = other;
                return Err("unexpected argument (redacted)".to_string());
            }
        }
        i += 1;
    }

    Ok(PolicyLintArgs {
        policy: policy.ok_or_else(|| "missing required flag: --policy".to_string())?,
    })
}

pub(crate) fn validate_policy_lint_args(args: &PolicyLintArgs) -> Result<(), String> {
    ensure_dir_exists(&args.policy, "policy")?;
    ensure_policy_json_exists(&args.policy)?;
    Ok(())
}

pub(crate) fn require_value(args: &[String], i: usize, flag: &str) -> Result<PathBuf, String> {
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

pub(crate) fn exit_usage(exe: &str, message: &str, help: fn(&str)) -> ExitCode {
    log_error(LogContext::unknown(), "usage_error", "USAGE", Some(message));
    help(exe);
    ExitCode::from(EXIT_USAGE)
}
