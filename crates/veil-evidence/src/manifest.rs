// Canonical pack-manifest type.
//
// Both the writer (`veil run` -> pack_finalize.rs) and the reader
// (`veil verify` -> pack_verifier.rs) consume this single struct so that
// the on-disk JSON layout has exactly one source of truth.
//
// Schema-version tokens are emitted via [`crate::schema`] so that any future
// migration always surfaces through the typed parse path.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::schema::{LedgerSchemaVersion, PackSchemaVersion, SchemaKind, UnknownSchemaVersion};

/// Wire-format pack manifest. Field names and order are part of the public
/// pack contract — change them only with a schema-version bump.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackManifest {
    pub pack_schema_version: String,
    pub tool_version: String,
    pub run_id: String,
    pub policy_id: String,
    pub input_corpus_id: String,
    pub tokenization_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenization_scope: Option<String>,
    pub quarantine_copy_enabled: bool,
    pub ledger_schema_version: String,
}

/// Errors raised while reading or structurally validating a pack manifest.
///
/// Variants are deliberately coarse — callers route them to a single
/// "fatal" log path. Specific filenames or content are not echoed to
/// info-level output; the variant name is the user-visible diagnostic.
#[derive(Debug, thiserror::Error)]
pub enum ManifestReadError {
    /// File path component traversed an unsafe location (symlink, reparse).
    #[error("pack manifest path is unsafe")]
    UnsafePath,
    /// File could not be opened or read.
    #[error("pack manifest io error")]
    Io,
    /// Bytes parsed but did not match the expected JSON shape.
    #[error("pack manifest is not valid JSON")]
    InvalidJson,
    /// `pack_schema_version` is not a value this binary understands.
    #[error("unsupported pack_schema_version: {raw}")]
    UnsupportedPackSchema { raw: String },
    /// `ledger_schema_version` is not a value this binary understands.
    #[error("unsupported ledger_schema_version: {raw}")]
    UnsupportedLedgerSchema { raw: String },
    /// One of the required string fields is empty after trimming.
    #[error("pack manifest is missing required fields")]
    MissingRequiredField,
    /// `tokenization_enabled` and `tokenization_scope` are inconsistent.
    #[error("invalid tokenization scope metadata")]
    InvalidTokenizationScope,
}

impl PackManifest {
    /// Build a manifest for the writer side, encoding the current schema
    /// versions automatically. Callers fill in the run-specific fields.
    pub fn current(
        tool_version: impl Into<String>,
        run_id: impl Into<String>,
        policy_id: impl Into<String>,
        input_corpus_id: impl Into<String>,
        tokenization_enabled: bool,
        tokenization_scope: Option<String>,
        quarantine_copy_enabled: bool,
    ) -> Self {
        Self {
            pack_schema_version: PackSchemaVersion::CURRENT.as_str().to_string(),
            tool_version: tool_version.into(),
            run_id: run_id.into(),
            policy_id: policy_id.into(),
            input_corpus_id: input_corpus_id.into(),
            tokenization_enabled,
            tokenization_scope,
            quarantine_copy_enabled,
            ledger_schema_version: LedgerSchemaVersion::CURRENT.as_str().to_string(),
        }
    }

    /// Atomically serialize the manifest to disk.
    ///
    /// Uses a tmp-then-rename dance so partial writes never leak a
    /// half-formed manifest into the pack root.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        let dir = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "pack manifest path has no parent",
            )
        })?;
        let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "pack manifest path has no file name",
            )
        })?;
        let tmp_path: PathBuf = dir.join(format!("{file_name}.tmp"));

        let bytes = serde_json::to_vec(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        {
            let mut f = std::fs::File::create(&tmp_path)?;
            std::io::Write::write_all(&mut f, &bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Read a manifest from disk and run structural validation that the
    /// CLI verifier needs (schema-version compatibility, required fields,
    /// tokenization metadata coherence). The caller still verifies content
    /// like `policy_id` matching the supplied policy bundle.
    pub fn read_validate(path: &Path) -> Result<Self, ManifestReadError> {
        let bytes = std::fs::read(path).map_err(|_| ManifestReadError::Io)?;
        let manifest: PackManifest =
            serde_json::from_slice(&bytes).map_err(|_| ManifestReadError::InvalidJson)?;
        manifest.validate_structural()?;
        Ok(manifest)
    }

    /// Validate the manifest fields without touching the filesystem. Pulled
    /// out so unit tests can exercise it directly.
    pub fn validate_structural(&self) -> Result<(), ManifestReadError> {
        if let Err(UnknownSchemaVersion { kind, raw }) =
            PackSchemaVersion::parse(&self.pack_schema_version)
        {
            debug_assert_eq!(kind, SchemaKind::Pack);
            return Err(ManifestReadError::UnsupportedPackSchema { raw });
        }
        if let Err(UnknownSchemaVersion { kind, raw }) =
            LedgerSchemaVersion::parse(&self.ledger_schema_version)
        {
            debug_assert_eq!(kind, SchemaKind::Ledger);
            return Err(ManifestReadError::UnsupportedLedgerSchema { raw });
        }
        if self.tool_version.trim().is_empty()
            || self.run_id.trim().is_empty()
            || self.input_corpus_id.trim().is_empty()
            || self.policy_id.trim().is_empty()
        {
            return Err(ManifestReadError::MissingRequiredField);
        }
        if self.tokenization_enabled && self.tokenization_scope.is_none() {
            return Err(ManifestReadError::InvalidTokenizationScope);
        }
        if !self.tokenization_enabled && self.tokenization_scope.is_some() {
            return Err(ManifestReadError::InvalidTokenizationScope);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> PackManifest {
        PackManifest::current("0.1.0", "run-1", "policy-1", "input-1", false, None, false)
    }

    #[test]
    fn current_uses_current_schema_versions() {
        let m = baseline();
        assert_eq!(m.pack_schema_version, "pack.v2");
        assert_eq!(m.ledger_schema_version, "ledger.v2");
    }

    #[test]
    fn current_writers_emit_pack_v2() {
        // Pinned version-token check so accidental version regressions in
        // PackSchemaVersion::CURRENT surface as a build failure.
        assert_eq!(PackSchemaVersion::CURRENT.as_str(), "pack.v2");
        assert_eq!(LedgerSchemaVersion::CURRENT.as_str(), "ledger.v2");
    }

    #[test]
    fn validate_accepts_baseline() {
        baseline().validate_structural().expect("baseline ok");
    }

    #[test]
    fn validate_rejects_unsupported_pack_version() {
        let mut m = baseline();
        m.pack_schema_version = "pack.v0".to_string();
        let err = m.validate_structural().expect_err("must reject");
        match err {
            ManifestReadError::UnsupportedPackSchema { raw } => assert_eq!(raw, "pack.v0"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_unsupported_ledger_version() {
        let mut m = baseline();
        m.ledger_schema_version = "ledger.v0".to_string();
        let err = m.validate_structural().expect_err("must reject");
        match err {
            ManifestReadError::UnsupportedLedgerSchema { raw } => assert_eq!(raw, "ledger.v0"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_missing_required_field() {
        let mut m = baseline();
        m.run_id = String::new();
        match m.validate_structural() {
            Err(ManifestReadError::MissingRequiredField) => {}
            other => panic!("expected missing-field error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_inconsistent_tokenization() {
        let mut m = baseline();
        m.tokenization_enabled = true;
        m.tokenization_scope = None;
        match m.validate_structural() {
            Err(ManifestReadError::InvalidTokenizationScope) => {}
            other => panic!("expected tokenization error, got {other:?}"),
        }

        let mut m = baseline();
        m.tokenization_enabled = false;
        m.tokenization_scope = Some("PER_RUN".to_string());
        match m.validate_structural() {
            Err(ManifestReadError::InvalidTokenizationScope) => {}
            other => panic!("expected tokenization error, got {other:?}"),
        }
    }

    #[test]
    fn json_round_trip_keeps_field_shape() {
        let m = PackManifest::current(
            "0.1.0",
            "run-1",
            "policy-1",
            "input-1",
            true,
            Some("PER_RUN".to_string()),
            true,
        );
        let bytes = serde_json::to_vec(&m).expect("serialize");
        let parsed: PackManifest = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(parsed, m);
    }

    #[test]
    fn rejects_unknown_fields() {
        let raw = br#"{
            "pack_schema_version":"pack.v2",
            "tool_version":"x",
            "run_id":"x",
            "policy_id":"x",
            "input_corpus_id":"x",
            "tokenization_enabled":false,
            "quarantine_copy_enabled":false,
            "ledger_schema_version":"ledger.v2",
            "stowaway":42
        }"#;
        assert!(serde_json::from_slice::<PackManifest>(raw).is_err());
    }

    #[test]
    fn validate_accepts_legacy_pack_v1_for_migration() {
        // pack v1 manifests must remain readable so `verify` can check
        // older packs after a tool upgrade.
        let mut m = baseline();
        m.pack_schema_version = "pack.v1".to_string();
        m.ledger_schema_version = "ledger.v1".to_string();
        m.validate_structural()
            .expect("v1 stays acceptable for read");
    }
}
