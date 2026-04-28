// Crate-level error type for veil-domain.
//
// Today the surface is small: hex parsing for the digest-backed identifiers
// and unsupported wire-format strings (artifact_type, etc.). The domain crate
// otherwise produces values rather than fallible operations, so this enum is
// intentionally narrow and grows only when new fallible APIs are introduced.

use crate::ids::ParseHexError;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid digest hex (length: expected {expected}, got {actual})")]
    InvalidDigestHexLength { expected: usize, actual: usize },
    #[error("invalid digest hex (byte at index {index})")]
    InvalidDigestHexByte { index: usize },
    #[error("unsupported artifact_type: {raw}")]
    UnsupportedArtifactType { raw: String },
}

impl From<ParseHexError> for DomainError {
    fn from(err: ParseHexError) -> Self {
        match err {
            ParseHexError::InvalidLength { expected, actual } => {
                DomainError::InvalidDigestHexLength { expected, actual }
            }
            ParseHexError::InvalidByte { index } => DomainError::InvalidDigestHexByte { index },
        }
    }
}
