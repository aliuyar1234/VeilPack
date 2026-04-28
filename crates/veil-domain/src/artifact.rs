use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    Discovered,
    Extracted,
    Transformed,
    Verified,
    Quarantined,
}

impl ArtifactState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Verified | Self::Quarantined)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "DISCOVERED",
            Self::Extracted => "EXTRACTED",
            Self::Transformed => "TRANSFORMED",
            Self::Verified => "VERIFIED",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineReasonCode {
    UnsupportedFormat,
    Encrypted,
    ParseError,
    LimitExceeded,
    UnsafePath,
    UnknownCoverage,
    VerificationFailed,
    InternalError,
}

impl QuarantineReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Self::Encrypted => "ENCRYPTED",
            Self::ParseError => "PARSE_ERROR",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::UnsafePath => "UNSAFE_PATH",
            Self::UnknownCoverage => "UNKNOWN_COVERAGE",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }
}

impl fmt::Display for QuarantineReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}

/// Canonical, closed set of artifact types Veil can extract.
///
/// The on-the-wire representation is the uppercase string form returned by
/// [`ArtifactType::as_str`] (e.g. `"TEXT"`, `"ZIP"`). Anything outside this
/// set is unsupported and must be quarantined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArtifactType {
    Text,
    Csv,
    Tsv,
    Json,
    Ndjson,
    Zip,
    Tar,
    Eml,
    Mbox,
    Docx,
    Pptx,
    Xlsx,
}

impl ArtifactType {
    /// All supported artifact types in canonical declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Text,
        Self::Csv,
        Self::Tsv,
        Self::Json,
        Self::Ndjson,
        Self::Zip,
        Self::Tar,
        Self::Eml,
        Self::Mbox,
        Self::Docx,
        Self::Pptx,
        Self::Xlsx,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "TEXT",
            Self::Csv => "CSV",
            Self::Tsv => "TSV",
            Self::Json => "JSON",
            Self::Ndjson => "NDJSON",
            Self::Zip => "ZIP",
            Self::Tar => "TAR",
            Self::Eml => "EML",
            Self::Mbox => "MBOX",
            Self::Docx => "DOCX",
            Self::Pptx => "PPTX",
            Self::Xlsx => "XLSX",
        }
    }

    pub fn parse(s: &str) -> Result<Self, UnknownArtifactType> {
        match s {
            "TEXT" => Ok(Self::Text),
            "CSV" => Ok(Self::Csv),
            "TSV" => Ok(Self::Tsv),
            "JSON" => Ok(Self::Json),
            "NDJSON" => Ok(Self::Ndjson),
            "ZIP" => Ok(Self::Zip),
            "TAR" => Ok(Self::Tar),
            "EML" => Ok(Self::Eml),
            "MBOX" => Ok(Self::Mbox),
            "DOCX" => Ok(Self::Docx),
            "PPTX" => Ok(Self::Pptx),
            "XLSX" => Ok(Self::Xlsx),
            other => Err(UnknownArtifactType {
                raw: other.to_string(),
            }),
        }
    }

    /// Sanitized output extension for VERIFIED artifacts of this type.
    ///
    /// Container types (zip/tar/eml/mbox/ooxml) sanitize as canonical NDJSON.
    pub const fn sanitized_extension(self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::Csv => "csv",
            Self::Tsv => "tsv",
            Self::Json => "json",
            Self::Ndjson
            | Self::Zip
            | Self::Tar
            | Self::Eml
            | Self::Mbox
            | Self::Docx
            | Self::Pptx
            | Self::Xlsx => "ndjson",
        }
    }

    /// Artifact type to use when re-extracting sanitized output for residual
    /// verification. Container types verify as NDJSON because that's the
    /// canonical sanitized form.
    pub const fn verification_artifact_type(self) -> Self {
        match self {
            Self::Zip
            | Self::Tar
            | Self::Eml
            | Self::Mbox
            | Self::Docx
            | Self::Pptx
            | Self::Xlsx => Self::Ndjson,
            other => other,
        }
    }

    /// Whether this type runs through the risky-extractor isolated worker by
    /// default.
    pub const fn is_risky_extractor(self) -> bool {
        matches!(
            self,
            Self::Zip | Self::Tar | Self::Eml | Self::Mbox | Self::Docx | Self::Pptx | Self::Xlsx
        )
    }
}

impl fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for ArtifactType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for ArtifactType {
    type Err = UnknownArtifactType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for ArtifactType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ArtifactType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <&str as Deserialize>::deserialize(deserializer)?;
        Self::parse(raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownArtifactType {
    pub raw: String,
}

impl fmt::Display for UnknownArtifactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown artifact type")
    }
}

impl std::error::Error for UnknownArtifactType {}
