pub mod ledger;

use veil_domain::{InputCorpusId, PolicyId, RunId};
use veil_verify::VerificationOutcome;

pub use ledger::{LEDGER_SCHEMA_VERSION, Ledger, LedgerError};

#[derive(Debug, Clone)]
pub struct RunManifestV1 {
    pub run_id: RunId,
    pub policy_id: PolicyId,
    pub input_corpus_id: InputCorpusId,
    pub verification: VerificationOutcome,
}
