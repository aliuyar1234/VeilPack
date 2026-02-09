use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};
use veil_detect::DetectorEngine;
use veil_transform::Transformer;
use zeroize::{Zeroize, Zeroizing};

const EXIT_OK: u8 = 0;
const EXIT_FATAL: u8 = 1;
const EXIT_QUARANTINED: u8 = 2;
const EXIT_USAGE: u8 = 3;

mod extract_worker;
mod run_command;
mod verify_command;

use extract_worker::{is_risky_extractor_type, run_extract_in_worker};

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const PACK_SCHEMA_VERSION: &str = "pack.v1";
const UNKNOWN_LOG_ID: &str = "unknown";
const DEFAULT_MAX_WORKDIR_BYTES: u64 = 1_073_741_824;
const DEFAULT_MAX_PROCESSING_MS_PER_ARTIFACT: u64 = 30_000;

#[derive(Debug, Clone, Copy)]
struct LogContext<'a> {
    run_id: &'a str,
    policy_id: &'a str,
}

impl<'a> LogContext<'a> {
    const fn new(run_id: &'a str, policy_id: &'a str) -> Self {
        Self { run_id, policy_id }
    }

    const fn unknown() -> Self {
        Self {
            run_id: UNKNOWN_LOG_ID,
            policy_id: UNKNOWN_LOG_ID,
        }
    }
}

#[derive(Debug, Serialize)]
struct LogEvent<'a> {
    level: &'a str,
    event: &'a str,
    run_id: &'a str,
    policy_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_locator_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    counters: Option<BTreeMap<&'a str, u64>>,
}

fn emit_log(event: &LogEvent<'_>) {
    if let Ok(line) = serde_json::to_string(event) {
        eprintln!("{line}");
    } else {
        eprintln!(
            "{{\"level\":\"ERROR\",\"event\":\"log_serialize_failed\",\"run_id\":\"unknown\",\"policy_id\":\"unknown\",\"reason_code\":\"INTERNAL_ERROR\"}}"
        );
    }
}

fn log_info(ctx: LogContext<'_>, event: &str, counters: Option<BTreeMap<&str, u64>>) {
    emit_log(&LogEvent {
        level: "INFO",
        event,
        run_id: ctx.run_id,
        policy_id: ctx.policy_id,
        artifact_id: None,
        source_locator_hash: None,
        reason_code: None,
        detail: None,
        counters,
    });
}

fn log_warn(ctx: LogContext<'_>, event: &str, reason_code: &str, detail: Option<&str>) {
    emit_log(&LogEvent {
        level: "WARN",
        event,
        run_id: ctx.run_id,
        policy_id: ctx.policy_id,
        artifact_id: None,
        source_locator_hash: None,
        reason_code: Some(reason_code),
        detail,
        counters: None,
    });
}

fn log_error(ctx: LogContext<'_>, event: &str, reason_code: &str, detail: Option<&str>) {
    emit_log(&LogEvent {
        level: "ERROR",
        event,
        run_id: ctx.run_id,
        policy_id: ctx.policy_id,
        artifact_id: None,
        source_locator_hash: None,
        reason_code: Some(reason_code),
        detail,
        counters: None,
    });
}

fn log_artifact_error(
    ctx: LogContext<'_>,
    event: &str,
    reason_code: &str,
    sort_key: &veil_domain::ArtifactSortKey,
    detail: Option<&str>,
) {
    let artifact_id = sort_key.artifact_id.to_string();
    let source_locator_hash = sort_key.source_locator_hash.to_string();
    emit_log(&LogEvent {
        level: "ERROR",
        event,
        run_id: ctx.run_id,
        policy_id: ctx.policy_id,
        artifact_id: Some(&artifact_id),
        source_locator_hash: Some(&source_locator_hash),
        reason_code: Some(reason_code),
        detail,
        counters: None,
    });
}

fn main() -> ExitCode {
    let mut args = std::env::args().collect::<Vec<String>>();
    let exe = args.first().cloned().unwrap_or_else(|| "veil".to_string());
    args.remove(0);

    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_root_help(&exe);
        return ExitCode::from(EXIT_OK);
    }

    match args[0].as_str() {
        "run" => cmd_run(&exe, &args[1..]),
        "verify" => cmd_verify(&exe, &args[1..]),
        "policy" => cmd_policy(&exe, &args[1..]),
        "extract-worker" => extract_worker::cmd_extract_worker(&args[1..]),
        _ => {
            log_error(
                LogContext::unknown(),
                "cli_unknown_command",
                "USAGE",
                Some("unknown command (redacted)"),
            );
            print_root_help(&exe);
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn cmd_policy(exe: &str, args: &[String]) -> ExitCode {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_policy_help(exe);
        return ExitCode::from(EXIT_OK);
    }

    match args[0].as_str() {
        "lint" => cmd_policy_lint(exe, &args[1..]),
        _ => {
            log_error(
                LogContext::unknown(),
                "cli_unknown_policy_subcommand",
                "USAGE",
                Some("unknown policy subcommand (redacted)"),
            );
            print_policy_help(exe);
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn cmd_run(exe: &str, args: &[String]) -> ExitCode {
    run_command::cmd_run(exe, args)
}

fn cmd_verify(exe: &str, args: &[String]) -> ExitCode {
    verify_command::cmd_verify(exe, args)
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
    log_error(LogContext::unknown(), "usage_error", "USAGE", Some(message));
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
    isolate_risky_extractors: bool,
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

fn validate_run_args(args: &RunArgs) -> Result<(), String> {
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

fn validate_verify_args(args: &VerifyArgs) -> Result<(), String> {
    ensure_dir_exists(&args.pack, "pack")?;
    ensure_existing_path_components_safe(&args.pack, "pack")?;
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

fn validate_policy_lint_args(args: &PolicyLintArgs) -> Result<(), String> {
    ensure_dir_exists(&args.policy, "policy")?;
    ensure_policy_json_exists(&args.policy)?;
    Ok(())
}

fn require_value(args: &[String], i: usize, flag: &str) -> Result<PathBuf, String> {
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

fn is_unsafe_reparse_point(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        let _ = meta;
        false
    }
}

fn ensure_existing_path_components_safe(path: &Path, kind: &str) -> Result<(), String> {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp.as_os_str());
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) {
                    return Err(format!(
                        "{kind} path points to an unsafe location (redacted)"
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(format!("{kind} path is not accessible (redacted)"));
            }
        }
    }
    Ok(())
}

fn ensure_existing_file_safe(path: &Path, kind: &str) -> Result<(), String> {
    ensure_existing_path_components_safe(path, kind)?;
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| format!("{kind} is not accessible (redacted)"))?;
    if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) || !meta.is_file() {
        return Err(format!("{kind} path is unsafe (redacted)"));
    }
    Ok(())
}

fn dir_total_file_bytes(root: &Path) -> Result<u64, ()> {
    ensure_existing_path_components_safe(root, "workdir").map_err(|_| ())?;
    let mut total = 0_u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|_| ())?;
        for entry in entries {
            let entry = entry.map_err(|_| ())?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).map_err(|_| ())?;
            if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) {
                return Err(());
            }
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if meta.is_file() {
                total = total.checked_add(meta.len()).ok_or(())?;
            }
        }
    }
    Ok(total)
}

fn sync_parent_dir(path: &Path) -> Result<(), ()> {
    let parent = path.parent().ok_or(())?;
    ensure_existing_path_components_safe(parent, "output").map_err(|_| ())?;
    #[cfg(unix)]
    {
        let dir = std::fs::File::open(parent).map_err(|_| ())?;
        dir.sync_all().map_err(|_| ())?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

fn ensure_output_fresh_or_resumable(
    output: &Path,
    workdir: &Path,
    quarantine_copy_enabled: bool,
) -> Result<(), String> {
    ensure_existing_path_components_safe(output, "output")?;
    ensure_existing_path_components_safe(workdir, "workdir")?;

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

            let pack_manifest_path = output.join("pack_manifest.json");
            if let Ok(meta) = std::fs::symlink_metadata(&pack_manifest_path) {
                if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) {
                    return Err(
                        "output directory contains an unsafe pack manifest path (redacted)"
                            .to_string(),
                    );
                }
                if meta.is_file() {
                    return Err(
                        "output directory already contains a completed pack (redacted)".to_string(),
                    );
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err("output path is not accessible (redacted)".to_string());
        }
    }
    Ok(())
}

fn validate_or_seed_resume_meta(ledger: &veil_evidence::Ledger, key: &str, expected: &str) -> bool {
    match ledger.get_meta(key) {
        Ok(Some(value)) => value == expected,
        Ok(None) => ledger.upsert_meta(key, expected).is_ok(),
        Err(_) => false,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFileV1 {
    schema_version: String,
    #[serde(default)]
    archive: ArchiveLimitsOverride,
    #[serde(default)]
    artifact: ArtifactLimitsOverride,
    #[serde(default)]
    disk: DiskLimitsOverride,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveLimitsOverride {
    max_nested_archive_depth: Option<u32>,
    max_entries_per_archive: Option<u32>,
    max_expansion_ratio: Option<u32>,
    max_expanded_bytes_per_archive: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactLimitsOverride {
    max_bytes_per_artifact: Option<u64>,
    max_processing_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskLimitsOverride {
    max_workdir_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeLimits {
    archive_limits: veil_domain::ArchiveLimits,
    max_workdir_bytes: u64,
    max_processing_ms_per_artifact: u64,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            archive_limits: veil_domain::ArchiveLimits::default(),
            max_workdir_bytes: DEFAULT_MAX_WORKDIR_BYTES,
            max_processing_ms_per_artifact: DEFAULT_MAX_PROCESSING_MS_PER_ARTIFACT,
        }
    }
}

fn load_runtime_limits_from_json(path: &Path) -> Result<RuntimeLimits, String> {
    let json = std::fs::read_to_string(path)
        .map_err(|_| "limits-json could not be read (redacted)".to_string())?;

    let parsed: LimitsFileV1 = serde_json::from_str(&json)
        .map_err(|_| "limits-json is not valid JSON (redacted)".to_string())?;

    if parsed.schema_version != "limits.v1" {
        return Err("limits-json schema_version must be 'limits.v1' (v1)".to_string());
    }

    let mut archive_limits = veil_domain::ArchiveLimits::default();
    let mut max_workdir_bytes = DEFAULT_MAX_WORKDIR_BYTES;
    let mut max_processing_ms_per_artifact = DEFAULT_MAX_PROCESSING_MS_PER_ARTIFACT;
    if let Some(v) = parsed.archive.max_nested_archive_depth {
        archive_limits.max_nested_archive_depth = v;
    }
    if let Some(v) = parsed.archive.max_entries_per_archive {
        archive_limits.max_entries_per_archive = v;
    }
    if let Some(v) = parsed.archive.max_expansion_ratio {
        if v == 0 {
            return Err("limits-json max_expansion_ratio must be >= 1".to_string());
        }
        archive_limits.max_expansion_ratio = v;
    }
    if let Some(v) = parsed.archive.max_expanded_bytes_per_archive {
        if v == 0 {
            return Err("limits-json max_expanded_bytes_per_archive must be >= 1".to_string());
        }
        archive_limits.max_expanded_bytes_per_archive = v;
    }
    if let Some(v) = parsed.artifact.max_bytes_per_artifact {
        if v == 0 {
            return Err("limits-json max_bytes_per_artifact must be >= 1".to_string());
        }
        archive_limits.max_bytes_per_artifact = v;
    }
    if let Some(v) = parsed.artifact.max_processing_ms {
        if v == 0 {
            return Err("limits-json max_processing_ms must be >= 1".to_string());
        }
        max_processing_ms_per_artifact = v;
    }
    if let Some(v) = parsed.disk.max_workdir_bytes {
        if v == 0 {
            return Err("limits-json max_workdir_bytes must be >= 1".to_string());
        }
        max_workdir_bytes = v;
    }

    Ok(RuntimeLimits {
        archive_limits,
        max_workdir_bytes,
        max_processing_ms_per_artifact,
    })
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
    ensure_existing_path_components_safe(path, kind)?;
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
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|_| "input corpus entry type could not be read (redacted)".to_string())?;
        if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) {
            return Err("input corpus contains an unsafe path (symlink) (redacted)".to_string());
        }

        if meta.is_dir() {
            collect_input_files(root, &path, out, corpus_hasher)?;
            continue;
        }

        if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| "input corpus path normalization failed (redacted)".to_string())?;
            let normalized_rel_path = normalize_rel_path(rel)?;
            let source_locator_hash = veil_domain::hash_source_locator_hash(&normalized_rel_path);

            let size_bytes = meta.len();
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

#[derive(Debug, Clone, Copy)]
enum ReadArtifactError {
    Io,
    LimitExceeded,
    IdentityMismatch,
}

fn read_artifact_bytes_for_processing(
    path: &Path,
    expected_size_bytes: u64,
    expected_artifact_id: &veil_domain::ArtifactId,
    max_bytes_per_artifact: u64,
) -> Result<Vec<u8>, ReadArtifactError> {
    if max_bytes_per_artifact == 0 {
        return Err(ReadArtifactError::LimitExceeded);
    }

    let mut file = std::fs::File::open(path).map_err(|_| ReadArtifactError::Io)?;
    if let Ok(meta) = file.metadata()
        && meta.len() > max_bytes_per_artifact
    {
        return Err(ReadArtifactError::LimitExceeded);
    }

    let mut out = Vec::<u8>::new();
    let mut total = 0_u64;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|_| ReadArtifactError::Io)?;
        if n == 0 {
            break;
        }

        let n_u64 = u64::try_from(n).map_err(|_| ReadArtifactError::LimitExceeded)?;
        total = total
            .checked_add(n_u64)
            .ok_or(ReadArtifactError::LimitExceeded)?;
        if total > max_bytes_per_artifact {
            return Err(ReadArtifactError::LimitExceeded);
        }

        hasher.update(&buf[..n]);
        out.extend_from_slice(&buf[..n]);
    }

    let observed_artifact_id = veil_domain::ArtifactId::from_digest(
        veil_domain::Digest32::from_bytes(*hasher.finalize().as_bytes()),
    );
    if observed_artifact_id != *expected_artifact_id || total != expected_size_bytes {
        return Err(ReadArtifactError::IdentityMismatch);
    }

    Ok(out)
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
        "zip" => "ZIP",
        "tar" => "TAR",
        "eml" => "EML",
        "mbox" => "MBOX",
        "docx" => "DOCX",
        "pptx" => "PPTX",
        "xlsx" => "XLSX",
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
    ensure_existing_path_components_safe(path, "quarantine index")?;
    let dir = path
        .parent()
        .ok_or_else(|| "could not create quarantine index (redacted)".to_string())?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "could not create quarantine index (redacted)".to_string())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    if let Ok(meta) = std::fs::symlink_metadata(&tmp_path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        return Err("could not create quarantine index (redacted)".to_string());
    }

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
    let file = writer
        .into_inner()
        .map_err(|_| "could not flush quarantine index (redacted)".to_string())?;
    file.sync_all()
        .map_err(|_| "could not persist quarantine index (redacted)".to_string())?;
    drop(file);
    ensure_existing_path_components_safe(path, "quarantine index")?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err("quarantine index path is unsafe (redacted)".to_string());
    }
    std::fs::rename(&tmp_path, path)
        .map_err(|_| "could not persist quarantine index (redacted)".to_string())?;
    sync_parent_dir(path)
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
    ensure_existing_path_components_safe(path, "artifacts evidence")?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) || !meta.is_file() {
                return Err("artifacts.ndjson path is unsafe (redacted)".to_string());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => return Err("could not read artifacts.ndjson (redacted)".to_string()),
    };

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Err("could not read artifacts.ndjson (redacted)".to_string()),
    };
    let reader = std::io::BufReader::new(file);

    let mut out = BTreeMap::<veil_domain::ArtifactId, Vec<String>>::new();
    for line in reader.lines() {
        let line =
            line.map_err(|_| "could not read artifacts.ndjson line (redacted)".to_string())?;
        if line.trim().is_empty() {
            continue;
        }

        let rec: ArtifactEvidenceRecordOwned = serde_json::from_str(&line)
            .map_err(|_| "artifacts.ndjson is invalid (redacted)".to_string())?;

        let artifact_id = veil_domain::ArtifactId::from_hex(&rec.artifact_id)
            .map_err(|_| "artifacts.ndjson contains invalid artifact_id (redacted)".to_string())?;
        if !rec.proof_tokens.is_empty() {
            out.insert(artifact_id, rec.proof_tokens);
        }
    }

    Ok(out)
}

fn write_artifacts_evidence(path: &Path, artifacts: &[ArtifactRunResult]) -> Result<(), String> {
    ensure_existing_path_components_safe(path, "artifacts evidence")?;
    let dir = path
        .parent()
        .ok_or_else(|| "could not create artifacts evidence (redacted)".to_string())?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "could not create artifacts evidence (redacted)".to_string())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    if let Ok(meta) = std::fs::symlink_metadata(&tmp_path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        return Err("could not create artifacts evidence (redacted)".to_string());
    }

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
    let file = writer
        .into_inner()
        .map_err(|_| "could not flush artifacts evidence (redacted)".to_string())?;
    file.sync_all()
        .map_err(|_| "could not persist artifacts evidence (redacted)".to_string())?;
    drop(file);
    ensure_existing_path_components_safe(path, "artifacts evidence")?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err("artifacts evidence path is unsafe (redacted)".to_string());
    }
    std::fs::rename(&tmp_path, path)
        .map_err(|_| "could not persist artifacts evidence (redacted)".to_string())?;
    sync_parent_dir(path)
        .map_err(|_| "could not persist artifacts evidence (redacted)".to_string())?;
    Ok(())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), ()> {
    ensure_existing_path_components_safe(path, "output").map_err(|_| ())?;
    let dir = path.parent().ok_or(())?;
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or(())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    if let Ok(meta) = std::fs::symlink_metadata(&tmp_path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        return Err(());
    }

    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    let mut tmp_file = std::fs::File::create(&tmp_path).map_err(|_| ())?;
    tmp_file.write_all(&bytes).map_err(|_| ())?;
    tmp_file.sync_all().map_err(|_| ())?;
    drop(tmp_file);
    ensure_existing_path_components_safe(path, "output").map_err(|_| ())?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(());
    }
    std::fs::rename(&tmp_path, path).map_err(|_| ())?;
    sync_parent_dir(path)?;
    Ok(())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    ensure_existing_path_components_safe(path, "output").map_err(|_| ())?;
    let dir = path.parent().ok_or(())?;
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or(())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    if let Ok(meta) = std::fs::symlink_metadata(&tmp_path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        return Err(());
    }

    let mut tmp_file = std::fs::File::create(&tmp_path).map_err(|_| ())?;
    tmp_file.write_all(bytes).map_err(|_| ())?;
    tmp_file.sync_all().map_err(|_| ())?;
    drop(tmp_file);
    ensure_existing_path_components_safe(path, "output").map_err(|_| ())?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(());
    }
    std::fs::rename(&tmp_path, path).map_err(|_| ())?;
    sync_parent_dir(path)?;
    Ok(())
}

fn write_bytes_sync(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    ensure_existing_path_components_safe(path, "output").map_err(|_| ())?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        return Err(());
    }
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
        "ZIP" => "ndjson",
        "TAR" => "ndjson",
        "EML" => "ndjson",
        "MBOX" => "ndjson",
        "DOCX" => "ndjson",
        "PPTX" => "ndjson",
        "XLSX" => "ndjson",
        _ => "bin",
    }
}

fn verification_artifact_type_v1(artifact_type: &str) -> &'static str {
    match artifact_type {
        "ZIP" | "TAR" | "EML" | "MBOX" | "DOCX" | "PPTX" | "XLSX" => "NDJSON",
        "TEXT" => "TEXT",
        "CSV" => "CSV",
        "TSV" => "TSV",
        "JSON" => "JSON",
        "NDJSON" => "NDJSON",
        _ => "FILE",
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

fn write_quarantine_raw_or_fail(
    quarantine_copy_enabled: bool,
    quarantine_raw_dir: &Path,
    sort_key: &veil_domain::ArtifactSortKey,
    artifact_type: &str,
    bytes: &[u8],
    log_ctx: LogContext<'_>,
) -> Result<(), ()> {
    if !quarantine_copy_enabled {
        return Ok(());
    }

    if write_quarantine_raw(quarantine_raw_dir, sort_key, artifact_type, bytes).is_err() {
        log_error(
            log_ctx,
            "quarantine_raw_write_failed",
            "INTERNAL_ERROR",
            Some("could not persist quarantine raw copy (redacted)"),
        );
        return Err(());
    }
    Ok(())
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
    println!(
        "  --max-workers <N>              Worker bound (>= 1; v1 baseline executes single-worker deterministically)"
    );
    println!("  --strictness strict            Strict is the only supported baseline in v1");
    println!("  --enable-tokenization true|false   Default: false");
    println!("  --secret-key-file <PATH>       Required if tokenization is enabled");
    println!("  --quarantine-copy true|false    Default: false");
    println!("  --isolate-risky-extractors true|false   Default: false");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "veil_cli_main_test_{}_{}",
            std::process::id(),
            label.replace(['\\', '/', ':'], "_")
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn read_artifact_detects_identity_mismatch() {
        let dir = test_dir("identity_mismatch");
        let file_path = dir.join("a.txt");
        std::fs::write(&file_path, b"hello").expect("write file");

        let expected = veil_domain::hash_artifact_id(b"hello");
        std::fs::write(&file_path, b"goodbye").expect("overwrite file");

        let read = read_artifact_bytes_for_processing(&file_path, 5, &expected, 1024)
            .expect_err("mismatch");
        assert!(matches!(read, ReadArtifactError::IdentityMismatch));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn read_artifact_enforces_max_bytes_per_artifact() {
        let dir = test_dir("artifact_limit");
        let file_path = dir.join("a.txt");
        std::fs::write(&file_path, b"0123456789ABCDEF").expect("write file");

        let expected = veil_domain::hash_artifact_id(b"0123456789ABCDEF");
        let read =
            read_artifact_bytes_for_processing(&file_path, 16, &expected, 8).expect_err("limit");
        assert!(matches!(read, ReadArtifactError::LimitExceeded));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn safe_path_check_rejects_symlink_component() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("symlink_component");
        let real = dir.join("real");
        let link = dir.join("link");
        std::fs::create_dir_all(&real).expect("create real dir");
        symlink(&real, &link).expect("create symlink");

        let candidate = link.join("child");
        let err = ensure_existing_path_components_safe(&candidate, "output")
            .expect_err("unsafe location");
        assert!(err.contains("unsafe location"));
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[allow(dead_code)]
fn _exit_quarantined_stub() -> ExitCode {
    ExitCode::from(EXIT_QUARANTINED)
}
