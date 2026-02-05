use crate::{ArtifactId, SourceLocatorHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArtifactSortKey {
    pub artifact_id: ArtifactId,
    pub source_locator_hash: SourceLocatorHash,
}

impl ArtifactSortKey {
    pub const fn new(artifact_id: ArtifactId, source_locator_hash: SourceLocatorHash) -> Self {
        Self {
            artifact_id,
            source_locator_hash,
        }
    }
}
