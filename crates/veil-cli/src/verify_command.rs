use std::process::ExitCode;

use crate::args::{VerifyArgs, exit_usage, validate_verify_args};
use crate::pack_verifier::{PackVerifier, PackVerifyResult};
use crate::print_verify_help;

pub(super) fn cmd_verify(exe: &str, parsed: VerifyArgs) -> ExitCode {
    if let Err(msg) = validate_verify_args(&parsed) {
        return exit_usage(exe, &msg, print_verify_help);
    }

    let policy = match veil_policy::load_policy_bundle(&parsed.policy) {
        Ok(p) => p,
        Err(_) => {
            return exit_usage(
                exe,
                "policy bundle is invalid or unreadable",
                print_verify_help,
            );
        }
    };

    match PackVerifier::new(&parsed.pack, &policy).run() {
        PackVerifyResult::Exit(code) => code,
        PackVerifyResult::Usage(msg) => exit_usage(exe, &msg, print_verify_help),
    }
}
