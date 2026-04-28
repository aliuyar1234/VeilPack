use std::process::ExitCode;

use clap::{CommandFactory, Parser};

pub(crate) const EXIT_OK: u8 = 0;
pub(crate) const EXIT_FATAL: u8 = 1;
pub(crate) const EXIT_QUARANTINED: u8 = 2;
pub(crate) const EXIT_USAGE: u8 = 3;

mod args;
mod artifact_processor;
mod error;
mod evidence_io;
mod extract_worker;
mod extract_worker_protocol;
mod fs_safety;
mod identity;
mod input_inventory;
mod logging;
mod pack_finalize;
mod pack_verifier;
mod parallel;
mod run_bootstrap;
mod run_command;
mod runtime_limits;
mod verify_command;

fn main() -> ExitCode {
    logging::init_tracing();

    let argv = std::env::args().collect::<Vec<String>>();
    let exe = argv.first().cloned().unwrap_or_else(|| "veil".to_string());

    // clap consumes argv[0] as the program name.
    let cli = match args::Cli::try_parse_from(&argv) {
        Ok(c) => c,
        Err(e) => return handle_clap_error(&exe, e),
    };

    match cli.command {
        args::Command::Run(parsed) => run_command::cmd_run(&exe, parsed),
        args::Command::Verify(parsed) => verify_command::cmd_verify(&exe, parsed),
        args::Command::Policy { cmd } => match cmd {
            args::PolicyCommand::Lint(parsed) => cmd_policy_lint(&exe, parsed),
        },
        args::Command::ExtractWorker(parsed) => extract_worker::cmd_extract_worker(parsed),
    }
}

fn handle_clap_error(exe: &str, err: clap::Error) -> ExitCode {
    use clap::error::ErrorKind;
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            // clap renders help/version to stdout for us.
            print!("{err}");
            ExitCode::from(EXIT_OK)
        }
        _ => {
            // Don't echo the user's original argv content (clap may include
            // it). Emit the canonical structured usage_error and a generic
            // help banner so secrets passed inline aren't reflected back.
            let _ = err; // discard original to avoid leaking raw argv
            tracing::error!(
                event = "usage_error",
                reason_code = "USAGE",
                "invalid command-line arguments"
            );
            print_root_help(exe);
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn cmd_policy_lint(exe: &str, parsed: args::PolicyLintArgs) -> ExitCode {
    if let Err(msg) = args::validate_policy_lint_args(&parsed) {
        return args::exit_usage(exe, &msg, print_policy_lint_help);
    }

    let policy = match veil_policy::load_policy_bundle(&parsed.policy) {
        Ok(p) => p,
        Err(_) => {
            return args::exit_usage(
                exe,
                "policy bundle is invalid or unreadable",
                print_policy_lint_help,
            );
        }
    };

    println!("{}", policy.policy_id);
    ExitCode::from(EXIT_OK)
}

fn print_root_help(exe: &str) {
    let _ = exe;
    let mut cmd = args::Cli::command();
    let _ = cmd.print_help();
    println!();
}

pub(crate) fn print_run_help(exe: &str) {
    let _ = exe;
    let mut cmd = args::Cli::command();
    if let Some(sub) = cmd.find_subcommand_mut("run") {
        let _ = sub.print_help();
        println!();
    } else {
        let _ = cmd.print_help();
        println!();
    }
}

pub(crate) fn print_verify_help(exe: &str) {
    let _ = exe;
    let mut cmd = args::Cli::command();
    if let Some(sub) = cmd.find_subcommand_mut("verify") {
        let _ = sub.print_help();
        println!();
    } else {
        let _ = cmd.print_help();
        println!();
    }
}

pub(crate) fn print_policy_lint_help(exe: &str) {
    let _ = exe;
    let mut cmd = args::Cli::command();
    if let Some(policy) = cmd.find_subcommand_mut("policy")
        && let Some(lint) = policy.find_subcommand_mut("lint")
    {
        let _ = lint.print_help();
        println!();
    } else {
        let _ = cmd.print_help();
        println!();
    }
}
