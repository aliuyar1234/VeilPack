pub mod ledger;
pub mod manifest;
pub mod ndjson;
pub mod schema;

use veil_domain::{InputCorpusId, PolicyId, RunId};
use veil_verify::VerificationOutcome;

pub use ledger::{LEDGER_SCHEMA_VERSION, Ledger, LedgerError};
pub use manifest::{ManifestReadError, PackManifest};
pub use ndjson::{NdjsonLine, NdjsonReadError, NdjsonReader, read_ndjson_records};
pub use schema::{
    IdentityMigrator, LedgerMigrator, LedgerSchemaVersion, MigrationError, PackMigrator,
    PackSchemaVersion, SchemaKind, UnknownSchemaVersion,
};

#[derive(Debug, Clone)]
pub struct RunManifestV1 {
    pub run_id: RunId,
    pub policy_id: PolicyId,
    pub input_corpus_id: InputCorpusId,
    pub verification: VerificationOutcome,
}
