use core::fmt;

use veil_domain::{ArtifactId, CoverageMapV1, QuarantineReasonCode, SourceLocatorHash};

#[derive(Clone)]
pub struct CanonicalText {
    text: String,
}

impl CanonicalText {
    pub fn new(text: String) -> Self {
        Self { text }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for CanonicalText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalText")
            .field("len", &self.text.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ArtifactContext<'a> {
    pub artifact_id: &'a ArtifactId,
    pub source_locator_hash: &'a SourceLocatorHash,
}

#[derive(Debug, Clone)]
pub enum ExtractOutcome {
    Extracted {
        extractor_id: &'static str,
        canonical: CanonicalText,
        coverage: CoverageMapV1,
    },
    Quarantined {
        extractor_id: Option<&'static str>,
        reason: QuarantineReasonCode,
    },
}

pub trait Extractor {
    fn id(&self) -> &'static str;

    fn extract(&self, ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome;
}
