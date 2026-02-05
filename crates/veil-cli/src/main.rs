use std::path::{Path, PathBuf};
use std::process::ExitCode;

const EXIT_OK: u8 = 0;
const EXIT_FATAL: u8 = 1;
const EXIT_QUARANTINED: u8 = 2;
const EXIT_USAGE: u8 = 3;

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

    eprintln!("error: not implemented yet (fail-closed)");
    ExitCode::from(EXIT_FATAL)
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

    eprintln!("error: not implemented yet (fail-closed)");
    ExitCode::from(EXIT_FATAL)
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

    eprintln!("error: not implemented yet (fail-closed)");
    ExitCode::from(EXIT_FATAL)
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
    ensure_output_safe(&args.output)?;

    if let Some(workdir) = &args.workdir
        && let Ok(meta) = std::fs::metadata(workdir)
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

fn ensure_output_safe(output: &Path) -> Result<(), String> {
    match std::fs::metadata(output) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err("output path must be a directory when it exists (redacted)".to_string());
            }
            let mut entries = std::fs::read_dir(output)
                .map_err(|_| "output path is not readable (redacted)".to_string())?;
            if entries.next().is_some() {
                return Err("output directory must be empty (redacted)".to_string());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err("output path is not accessible (redacted)".to_string());
        }
    }
    Ok(())
}

fn print_root_help(exe: &str) {
    println!("Veil (offline fail-closed privacy gate)");
    println!();
    println!("USAGE:");
    println!("  {exe} <COMMAND> [FLAGS]");
    println!();
    println!("COMMANDS:");
    println!("  run           Process a corpus into a Veil Pack (v1 stub)");
    println!("  verify        Verify a Veil Pack output (v1 stub)");
    println!("  policy lint   Validate policy bundle and compute policy_id (v1 stub)");
    println!();
    println!("Run '{exe} <COMMAND> --help' for command-specific help.");
}

fn print_run_help(exe: &str) {
    println!("USAGE:");
    println!("  {exe} run --input <PATH> --output <PATH> --policy <PATH> [FLAGS]");
    println!();
    println!("REQUIRED:");
    println!("  --input <PATH>     Input corpus root (read-only)");
    println!("  --output <PATH>    Output Veil Pack root (must not exist or must be empty)");
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
    println!("  lint   Validate policy bundle and compute policy_id (v1 stub)");
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
