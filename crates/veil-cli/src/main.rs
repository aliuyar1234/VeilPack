use std::process::ExitCode;

pub(crate) const EXIT_OK: u8 = 0;
pub(crate) const EXIT_FATAL: u8 = 1;
pub(crate) const EXIT_QUARANTINED: u8 = 2;
pub(crate) const EXIT_USAGE: u8 = 3;
pub(crate) const PACK_SCHEMA_VERSION: &str = "pack.v1";

mod args;
mod artifact_processor;
mod evidence_io;
mod extract_worker;
mod fs_safety;
mod input_inventory;
mod logging;
mod pack_finalize;
mod pack_verifier;
mod run_bootstrap;
mod run_command;
mod runtime_limits;
mod verify_command;

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
            logging::log_error(
                logging::LogContext::unknown(),
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
            logging::log_error(
                logging::LogContext::unknown(),
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

    let parsed = match args::parse_policy_lint_args(args) {
        Ok(p) => p,
        Err(msg) => return args::exit_usage(exe, &msg, print_policy_lint_help),
    };

    if let Err(msg) = args::validate_policy_lint_args(&parsed) {
        return args::exit_usage(exe, &msg, print_policy_lint_help);
    }

    let policy = match veil_policy::load_policy_bundle(&parsed.policy) {
        Ok(p) => p,
        Err(_) => {
            return args::exit_usage(
                exe,
                "policy bundle is invalid or unreadable (redacted)",
                print_policy_lint_help,
            );
        }
    };

    println!("{}", policy.policy_id);
    ExitCode::from(EXIT_OK)
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
    println!("  --pack <PATH>     Existing Veil Pack root");
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
