//! Run identity collapsed into typed structs.
//!
//! `run_bootstrap::resume_ledger` originally fanned out 7 nearly-identical
//! call sites:
//!
//! ```ignore
//! validate_resume_identity(&ledger, "policy_id", policy_id_str, run_id_str)?;
//! validate_resume_identity(&ledger, "run_id", run_id_str, run_id_str)?;
//! validate_resume_identity(&ledger, "input_corpus_id", input_corpus_id_str, run_id_str)?;
//! if !validate_or_seed_resume_meta(&ledger, "proof_scope", proof_scope) { ... }
//! if !validate_or_seed_resume_meta(&ledger, "proof_key_commitment", proof_key_commitment) { ... }
//! if !validate_or_seed_resume_meta(&ledger, "tokenization_enabled", ...) { ... }
//! if !validate_or_seed_resume_meta(&ledger, "tokenization_scope", ...) { ... }
//! ```
//!
//! These split into two distinct semantics:
//!
//! 1. The three identity IDs (`policy_id`, `run_id`, `input_corpus_id`) MUST
//!    match the values stored at run creation. They were always written
//!    when the ledger was first created (see `Ledger::create_new`), so a
//!    missing entry on resume is itself a structural fault and bubbles up
//!    as `ledger_meta_missing`. Each key produces a distinct
//!    `AppError::Usage` message naming the field.
//! 2. The four crypto-meta keys (`proof_scope`, `proof_key_commitment`,
//!    `tokenization_enabled`, `tokenization_scope`) match if present and
//!    are seeded if missing. This is the upgrade path for old ledgers
//!    that didn't yet store the crypto meta. Mismatch is a usage error;
//!    seeding a missing entry is normal flow.
//!
//! Two structs preserve the type-level distinction. Identity verification
//! uses `Err(...)` per missing/mismatched key with a precise message;
//! crypto-meta verification falls back to seeding when absent.

use crate::error::AppError;
use crate::evidence_io::validate_or_seed_resume_meta;

/// The three identity IDs that uniquely characterise a run. All three must
/// already exist in the ledger at resume time and must match exactly.
pub(crate) struct RunIdentity<'a> {
    pub(crate) run_id: &'a str,
    pub(crate) policy_id: &'a str,
    pub(crate) input_corpus_id: &'a str,
}

/// The four crypto-meta keys that are seeded at run creation but might be
/// absent on a ledger created before they existed. Match-or-seed semantics
/// preserves backward compatibility; mismatch is a hard usage error.
pub(crate) struct RunCryptoMeta<'a> {
    pub(crate) proof_scope: &'a str,
    pub(crate) proof_key_commitment: &'a str,
    pub(crate) tokenization_enabled: &'a str,
    pub(crate) tokenization_scope: &'a str,
}

impl<'a> RunIdentity<'a> {
    /// Verify the three identity IDs match the values stored in the
    /// ledger. Each mismatch produces a precise per-field message. Missing
    /// entries indicate structural ledger corruption and surface as
    /// `ledger_meta_missing` events.
    pub(crate) fn verify_against(&self, ledger: &veil_evidence::Ledger) -> Result<(), AppError> {
        verify_identity_field(ledger, "policy_id", self.policy_id, self.run_id)?;
        verify_identity_field(ledger, "run_id", self.run_id, self.run_id)?;
        verify_identity_field(ledger, "input_corpus_id", self.input_corpus_id, self.run_id)?;
        Ok(())
    }
}

impl<'a> RunCryptoMeta<'a> {
    /// Verify the four crypto-meta keys against the ledger. Missing keys
    /// are seeded with the expected value (upgrade path); mismatches are
    /// usage errors with a precise per-field message.
    pub(crate) fn verify_or_seed_against(
        &self,
        ledger: &veil_evidence::Ledger,
    ) -> Result<(), AppError> {
        verify_or_seed_field(ledger, "proof_scope", self.proof_scope, "proof scope")?;
        verify_or_seed_field(
            ledger,
            "proof_key_commitment",
            self.proof_key_commitment,
            "proof key commitment",
        )?;
        verify_or_seed_field(
            ledger,
            "tokenization_enabled",
            self.tokenization_enabled,
            "tokenization setting",
        )?;
        verify_or_seed_field(
            ledger,
            "tokenization_scope",
            self.tokenization_scope,
            "tokenization scope",
        )?;
        Ok(())
    }
}

fn verify_identity_field(
    ledger: &veil_evidence::Ledger,
    key: &str,
    expected: &str,
    run_id_str: &str,
) -> Result<(), AppError> {
    let value = match ledger.get_meta(key) {
        Ok(Some(v)) => v,
        Ok(None) => {
            tracing::error!(
                event = "ledger_meta_missing",
                reason_code = "INTERNAL_ERROR",
                run_id = %run_id_str,
                key = %key,
                "ledger missing required meta key"
            );
            return Err(AppError::Internal("ledger_meta_missing".to_string()));
        }
        Err(_) => {
            tracing::error!(
                event = "ledger_read_failed",
                reason_code = "INTERNAL_ERROR",
                run_id = %run_id_str,
                "ledger read failed"
            );
            return Err(AppError::Internal("ledger_read_failed".to_string()));
        }
    };

    if value != expected {
        let message = match key {
            "policy_id" => "policy_id mismatch for resume",
            "run_id" => "run_id mismatch for resume",
            "input_corpus_id" => "input_corpus_id mismatch for resume",
            _ => "resume metadata mismatch",
        };
        return Err(AppError::Usage(message.to_string()));
    }

    Ok(())
}

fn verify_or_seed_field(
    ledger: &veil_evidence::Ledger,
    key: &str,
    expected: &str,
    human_label: &str,
) -> Result<(), AppError> {
    if validate_or_seed_resume_meta(ledger, key, expected) {
        Ok(())
    } else {
        Err(AppError::Usage(format!(
            "{human_label} mismatch for resume"
        )))
    }
}
