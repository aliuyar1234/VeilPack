// Top-level CLI error type.
//
// Every fallible function in the CLI now plumbs `AppError` through
// `Result<_, AppError>` so the `?` operator can compose them without the old
// `if X.is_err() { log_error(...); return Err(EXIT_FATAL.into()); }` boilerplate.
//
// Error→exit-code mapping happens once at the outer `main()` boundary. The
// `log` method is a thin helper that emits the canonical structured event
// for the variant; callers that need a *specific* event code (e.g. the
// pack-finalize stage emits `write_quarantine_index_failed` rather than the
// generic `internal_error`) call `tracing::error!` themselves and then
// return the appropriate variant.

use std::process::ExitCode;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AppError {
    #[error("usage error: {0}")]
    Usage(String),

    #[error("io error")]
    Io(#[from] std::io::Error),

    #[error("policy error")]
    Policy(#[from] veil_policy::PolicyLoadError),

    #[error("ledger error")]
    Ledger(#[from] veil_evidence::LedgerError),

    #[error("manifest error")]
    Manifest(#[from] veil_evidence::ManifestReadError),

    #[error("ndjson error")]
    Ndjson(#[from] veil_evidence::NdjsonReadError),

    /// Catch-all for fatal internal errors. The accompanying string is a
    /// short stable label (e.g. "ledger_write_failed") that callers may use
    /// for context; the actual event-code log line is emitted at the
    /// originating site so that stable event codes remain centralised with
    /// the call.
    #[error("internal error: {0}")]
    Internal(String),

    /// Specific limit was exceeded. Carried as a separate variant so future
    /// reason-code mapping can route this distinctly from generic internal
    /// errors.
    #[error("limit exceeded: {what}")]
    LimitExceeded { what: &'static str },
}

impl AppError {
    /// CLI exit code for this error variant. The mapping is part of the
    /// public CLI contract: 1 = fatal, 3 = usage. Quarantined runs
    /// (exit 2) are *not* errors and never go through `AppError`.
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => crate::EXIT_USAGE,
            _ => crate::EXIT_FATAL,
        }
    }
}

impl From<AppError> for ExitCode {
    fn from(e: AppError) -> Self {
        ExitCode::from(e.exit_code())
    }
}
