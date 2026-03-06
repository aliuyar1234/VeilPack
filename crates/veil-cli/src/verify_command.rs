use std::process::ExitCode;

use crate::args::{exit_usage, parse_verify_args, validate_verify_args};
use crate::pack_verifier::{PackVerifier, PackVerifyResult};
use crate::{EXIT_OK, print_verify_help};

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

    match PackVerifier::new(&parsed.pack, &policy).run() {
        PackVerifyResult::Exit(code) => code,
        PackVerifyResult::Usage(msg) => exit_usage(exe, &msg, print_verify_help),
    }
}
