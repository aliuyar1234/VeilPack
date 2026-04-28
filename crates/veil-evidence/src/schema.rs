// Schema version negotiation for Veil evidence artifacts.
//
// V2 introduces the `proof_tokens` table to the ledger so resume no longer
// reconstructs proof tokens by parsing `evidence/artifacts.ndjson`. The
// migrator path still has to read V1 packs (e.g. for `verify`) so the
// type-level negotiation surface lets us route those reads through a typed
// migration rather than parsing version strings on every call site.

use core::fmt;

/// The kind of schema being negotiated. Used in error reporting so that
/// callers can route different error events without parsing strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaKind {
    Pack,
    Ledger,
}

impl SchemaKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pack => "pack",
            Self::Ledger => "ledger",
        }
    }
}

impl fmt::Display for SchemaKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returned when a wire-format string does not map to a known schema version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownSchemaVersion {
    pub kind: SchemaKind,
    pub raw: String,
}

impl fmt::Display for UnknownSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported {} schema version", self.kind.as_str())
    }
}

impl std::error::Error for UnknownSchemaVersion {}

/// Pack-level schema version. V2 is the current write format; V1 is still
/// a legal read-only input via the migrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackSchemaVersion {
    V1,
    V2,
}

impl PackSchemaVersion {
    /// The schema version emitted by current writers.
    pub const CURRENT: Self = Self::V2;

    /// Wire-format token persisted in `pack_manifest.json`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "pack.v1",
            Self::V2 => "pack.v2",
        }
    }

    /// Parse a wire-format token into a typed schema version.
    ///
    /// Unknown tokens are reported via [`UnknownSchemaVersion`] so that
    /// callers can route them to the migration path (today: fatal-fail).
    pub fn parse(s: &str) -> Result<Self, UnknownSchemaVersion> {
        match s {
            "pack.v1" => Ok(Self::V1),
            "pack.v2" => Ok(Self::V2),
            other => Err(UnknownSchemaVersion {
                kind: SchemaKind::Pack,
                raw: other.to_string(),
            }),
        }
    }
}

impl fmt::Display for PackSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Ledger schema version. V2 is the current write format; V1 is still
/// a legal read-only input via the migrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerSchemaVersion {
    V1,
    V2,
}

impl LedgerSchemaVersion {
    pub const CURRENT: Self = Self::V2;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "ledger.v1",
            Self::V2 => "ledger.v2",
        }
    }

    pub fn parse(s: &str) -> Result<Self, UnknownSchemaVersion> {
        match s {
            "ledger.v1" => Ok(Self::V1),
            "ledger.v2" => Ok(Self::V2),
            other => Err(UnknownSchemaVersion {
                kind: SchemaKind::Ledger,
                raw: other.to_string(),
            }),
        }
    }
}

impl fmt::Display for LedgerSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors raised when migrating an artifact to the current schema version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    UnsupportedVersionJump {
        from: SchemaKind,
        raw_from: String,
        raw_to: String,
    },
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersionJump { from, .. } => {
                write!(f, "unsupported {} schema migration", from.as_str())
            }
        }
    }
}

impl std::error::Error for MigrationError {}

/// Migrate a parsed pack-schema version to the current one.
///
/// Implementations are expected to be pure logical migrations that do not
/// touch the filesystem; the byte-level transform is the caller's job.
pub trait PackMigrator {
    fn migrate_to_current(version: PackSchemaVersion) -> Result<(), MigrationError>;
}

/// Migrate a parsed ledger-schema version to the current one.
pub trait LedgerMigrator {
    fn migrate_to_current(version: LedgerSchemaVersion) -> Result<(), MigrationError>;
}

/// Identity migrator. Logical pack migrations from V1 to V2 are no-ops at
/// this layer because the V1 manifest is a strict subset of V2 — V2 only
/// adds an optional `proof_tokens` table to the ledger, which is created
/// on demand at `Ledger::open_existing` time. Older versions return
/// `UnsupportedVersionJump`.
pub struct IdentityMigrator;

impl PackMigrator for IdentityMigrator {
    fn migrate_to_current(version: PackSchemaVersion) -> Result<(), MigrationError> {
        match version {
            PackSchemaVersion::V1 | PackSchemaVersion::V2 => Ok(()),
        }
    }
}

impl LedgerMigrator for IdentityMigrator {
    fn migrate_to_current(version: LedgerSchemaVersion) -> Result<(), MigrationError> {
        match version {
            LedgerSchemaVersion::V1 | LedgerSchemaVersion::V2 => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_schema_version_round_trips() {
        let parsed = PackSchemaVersion::parse(PackSchemaVersion::CURRENT.as_str())
            .expect("current pack version round-trips");
        assert_eq!(parsed, PackSchemaVersion::CURRENT);
        assert_eq!(parsed.as_str(), "pack.v2");
    }

    #[test]
    fn pack_schema_version_accepts_v1_for_migration() {
        let parsed = PackSchemaVersion::parse("pack.v1").expect("v1 stays parseable");
        assert_eq!(parsed, PackSchemaVersion::V1);
    }

    #[test]
    fn pack_schema_version_rejects_unknown() {
        let err = PackSchemaVersion::parse("pack.v0").expect_err("unknown pack schema version");
        assert_eq!(err.kind, SchemaKind::Pack);
        assert_eq!(err.raw, "pack.v0");
    }

    #[test]
    fn ledger_schema_version_round_trips() {
        let parsed = LedgerSchemaVersion::parse(LedgerSchemaVersion::CURRENT.as_str())
            .expect("current ledger version round-trips");
        assert_eq!(parsed, LedgerSchemaVersion::CURRENT);
        assert_eq!(parsed.as_str(), "ledger.v2");
    }

    #[test]
    fn ledger_schema_version_accepts_v1_for_migration() {
        let parsed = LedgerSchemaVersion::parse("ledger.v1").expect("v1 stays parseable");
        assert_eq!(parsed, LedgerSchemaVersion::V1);
    }

    #[test]
    fn ledger_schema_version_rejects_unknown() {
        let err =
            LedgerSchemaVersion::parse("ledger.v0").expect_err("unknown ledger schema version");
        assert_eq!(err.kind, SchemaKind::Ledger);
        assert_eq!(err.raw, "ledger.v0");
    }

    #[test]
    fn identity_migrator_accepts_supported_versions() {
        <IdentityMigrator as PackMigrator>::migrate_to_current(PackSchemaVersion::V1)
            .expect("v1 -> current noop");
        <IdentityMigrator as PackMigrator>::migrate_to_current(PackSchemaVersion::V2)
            .expect("v2 -> current noop");
        <IdentityMigrator as LedgerMigrator>::migrate_to_current(LedgerSchemaVersion::V1)
            .expect("v1 -> current noop");
        <IdentityMigrator as LedgerMigrator>::migrate_to_current(LedgerSchemaVersion::V2)
            .expect("v2 -> current noop");
    }
}
