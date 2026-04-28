use core::fmt;
use core::str::FromStr;
use std::io::BufRead;

use veil_domain::{
    ArchiveLimits, ArtifactId, ArtifactType, CoverageMapV1, CoverageStatus, QuarantineReasonCode,
    SourceLocatorHash,
};

mod archive;
mod canonical;
mod mail;
mod ooxml;

pub use canonical::{
    CanonicalArtifact, CanonicalCsv, CanonicalJson, CanonicalNdjson, CanonicalText,
    canonicalize_json_value,
};

use archive::{archive_coverage_full, extract_tar_entries, extract_zip_entries};
use mail::{email_coverage, extract_eml_entries, extract_mbox_entries};
use ooxml::{extract_ooxml_entries, ooxml_coverage_full, ooxml_coverage_unknown_embedded};

#[derive(Debug, Clone, Copy)]
pub struct ArtifactContext<'a> {
    pub artifact_id: &'a ArtifactId,
    pub source_locator_hash: &'a SourceLocatorHash,
}

#[derive(Debug, Clone)]
pub enum ExtractOutcome {
    Extracted {
        extractor_id: ExtractorId,
        canonical: CanonicalArtifact,
        coverage: CoverageMapV1,
    },
    Quarantined {
        extractor_id: Option<ExtractorId>,
        reason: QuarantineReasonCode,
    },
}

/// Stable identifier of a v1 extractor.
///
/// The wire format is the dotted lowercase string (e.g. `"extract.csv.v1"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExtractorId {
    TextV1,
    CsvV1,
    TsvV1,
    JsonV1,
    NdjsonV1,
    ZipV1,
    TarV1,
    EmlV1,
    MboxV1,
    OoxmlDocxV1,
    OoxmlPptxV1,
    OoxmlXlsxV1,
}

impl ExtractorId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TextV1 => "extract.text.v1",
            Self::CsvV1 => "extract.csv.v1",
            Self::TsvV1 => "extract.tsv.v1",
            Self::JsonV1 => "extract.json.v1",
            Self::NdjsonV1 => "extract.ndjson.v1",
            Self::ZipV1 => "extract.zip.v1",
            Self::TarV1 => "extract.tar.v1",
            Self::EmlV1 => "extract.eml.v1",
            Self::MboxV1 => "extract.mbox.v1",
            Self::OoxmlDocxV1 => "extract.ooxml.docx.v1",
            Self::OoxmlPptxV1 => "extract.ooxml.pptx.v1",
            Self::OoxmlXlsxV1 => "extract.ooxml.xlsx.v1",
        }
    }

    pub fn parse(s: &str) -> Result<Self, UnknownExtractorId> {
        match s {
            "extract.text.v1" => Ok(Self::TextV1),
            "extract.csv.v1" => Ok(Self::CsvV1),
            "extract.tsv.v1" => Ok(Self::TsvV1),
            "extract.json.v1" => Ok(Self::JsonV1),
            "extract.ndjson.v1" => Ok(Self::NdjsonV1),
            "extract.zip.v1" => Ok(Self::ZipV1),
            "extract.tar.v1" => Ok(Self::TarV1),
            "extract.eml.v1" => Ok(Self::EmlV1),
            "extract.mbox.v1" => Ok(Self::MboxV1),
            "extract.ooxml.docx.v1" => Ok(Self::OoxmlDocxV1),
            "extract.ooxml.pptx.v1" => Ok(Self::OoxmlPptxV1),
            "extract.ooxml.xlsx.v1" => Ok(Self::OoxmlXlsxV1),
            other => Err(UnknownExtractorId {
                raw: other.to_string(),
            }),
        }
    }
}

impl fmt::Display for ExtractorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for ExtractorId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for ExtractorId {
    type Err = UnknownExtractorId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownExtractorId {
    pub raw: String,
}

impl fmt::Display for UnknownExtractorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown extractor id")
    }
}

impl std::error::Error for UnknownExtractorId {}

#[derive(Debug, Clone, Copy)]
pub struct ExtractorRegistry {
    limits: ArchiveLimits,
}

impl ExtractorRegistry {
    pub fn new(limits: ArchiveLimits) -> Self {
        Self { limits }
    }

    pub fn extract(
        &self,
        artifact_type: ArtifactType,
        ctx: ArtifactContext<'_>,
        bytes: &[u8],
    ) -> ExtractOutcome {
        let _ = ctx;
        match artifact_type {
            ArtifactType::Text => extract_text(bytes),
            ArtifactType::Csv => extract_delimited(bytes, b',', ExtractorId::CsvV1),
            ArtifactType::Tsv => extract_delimited(bytes, b'\t', ExtractorId::TsvV1),
            ArtifactType::Json => extract_json(bytes),
            ArtifactType::Ndjson => extract_ndjson(bytes),
            ArtifactType::Zip => extract_zip(self.limits, bytes),
            ArtifactType::Tar => extract_tar(self.limits, bytes),
            ArtifactType::Eml => extract_eml(self.limits, bytes),
            ArtifactType::Mbox => extract_mbox(self.limits, bytes),
            ArtifactType::Docx => extract_ooxml(self.limits, bytes, ExtractorId::OoxmlDocxV1),
            ArtifactType::Pptx => extract_ooxml(self.limits, bytes, ExtractorId::OoxmlPptxV1),
            ArtifactType::Xlsx => extract_ooxml(self.limits, bytes, ExtractorId::OoxmlXlsxV1),
        }
    }
}

impl Default for ExtractorRegistry {
    fn default() -> Self {
        Self::new(ArchiveLimits::default())
    }
}

fn extract_text(bytes: &[u8]) -> ExtractOutcome {
    let extractor_id = ExtractorId::TextV1;
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(extractor_id),
                reason: QuarantineReasonCode::ParseError,
            };
        }
    };

    ExtractOutcome::Extracted {
        extractor_id,
        canonical: CanonicalArtifact::Text(CanonicalText::new(text)),
        coverage: CoverageMapV1 {
            content_text: CoverageStatus::Full,
            structured_fields: CoverageStatus::None,
            metadata: CoverageStatus::Full,
            embedded_objects: CoverageStatus::None,
            attachments: CoverageStatus::None,
        },
    }
}

fn extract_delimited(bytes: &[u8], delimiter: u8, extractor_id: ExtractorId) -> ExtractOutcome {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .delimiter(delimiter)
        .from_reader(bytes);

    let headers = match reader.headers() {
        Ok(h) => h.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        Err(_) => {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(extractor_id),
                reason: QuarantineReasonCode::ParseError,
            };
        }
    };

    let mut records = Vec::<Vec<String>>::new();
    for row in reader.records() {
        let row = match row {
            Ok(r) => r,
            Err(_) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(extractor_id),
                    reason: QuarantineReasonCode::ParseError,
                };
            }
        };
        if row.len() != headers.len() {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(extractor_id),
                reason: QuarantineReasonCode::ParseError,
            };
        }
        records.push(row.iter().map(|s| s.to_string()).collect());
    }

    ExtractOutcome::Extracted {
        extractor_id,
        canonical: CanonicalArtifact::Csv(CanonicalCsv {
            delimiter,
            headers,
            records,
        }),
        coverage: CoverageMapV1 {
            content_text: CoverageStatus::None,
            structured_fields: CoverageStatus::Full,
            metadata: CoverageStatus::Full,
            embedded_objects: CoverageStatus::None,
            attachments: CoverageStatus::None,
        },
    }
}

fn extract_json(bytes: &[u8]) -> ExtractOutcome {
    let extractor_id = ExtractorId::JsonV1;
    let mut value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(extractor_id),
                reason: QuarantineReasonCode::ParseError,
            };
        }
    };

    canonicalize_json_value(&mut value);

    ExtractOutcome::Extracted {
        extractor_id,
        canonical: CanonicalArtifact::Json(CanonicalJson { value }),
        coverage: CoverageMapV1 {
            content_text: CoverageStatus::None,
            structured_fields: CoverageStatus::Full,
            metadata: CoverageStatus::Full,
            embedded_objects: CoverageStatus::None,
            attachments: CoverageStatus::None,
        },
    }
}

fn extract_ndjson(bytes: &[u8]) -> ExtractOutcome {
    let extractor_id = ExtractorId::NdjsonV1;
    let mut values = Vec::<serde_json::Value>::new();
    let reader = std::io::BufReader::new(bytes);
    for line in reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(extractor_id),
                    reason: QuarantineReasonCode::ParseError,
                };
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(extractor_id),
                    reason: QuarantineReasonCode::ParseError,
                };
            }
        };
        canonicalize_json_value(&mut v);
        values.push(v);
    }

    ExtractOutcome::Extracted {
        extractor_id,
        canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
        coverage: CoverageMapV1 {
            content_text: CoverageStatus::None,
            structured_fields: CoverageStatus::Full,
            metadata: CoverageStatus::Full,
            embedded_objects: CoverageStatus::None,
            attachments: CoverageStatus::None,
        },
    }
}

fn extract_zip(limits: ArchiveLimits, bytes: &[u8]) -> ExtractOutcome {
    let extractor_id = ExtractorId::ZipV1;
    let values = match extract_zip_entries(limits, bytes, 1, None) {
        Ok(v) => v,
        Err(reason) => {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(extractor_id),
                reason,
            };
        }
    };

    ExtractOutcome::Extracted {
        extractor_id,
        canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
        coverage: archive_coverage_full(),
    }
}

fn extract_tar(limits: ArchiveLimits, bytes: &[u8]) -> ExtractOutcome {
    let extractor_id = ExtractorId::TarV1;
    let values = match extract_tar_entries(limits, bytes, 1, None) {
        Ok(v) => v,
        Err(reason) => {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(extractor_id),
                reason,
            };
        }
    };

    ExtractOutcome::Extracted {
        extractor_id,
        canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
        coverage: archive_coverage_full(),
    }
}

fn extract_eml(limits: ArchiveLimits, bytes: &[u8]) -> ExtractOutcome {
    let extractor_id = ExtractorId::EmlV1;
    let (values, has_attachments) = match extract_eml_entries(limits, bytes) {
        Ok(v) => v,
        Err(reason) => {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(extractor_id),
                reason,
            };
        }
    };

    ExtractOutcome::Extracted {
        extractor_id,
        canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
        coverage: email_coverage(has_attachments),
    }
}

fn extract_mbox(limits: ArchiveLimits, bytes: &[u8]) -> ExtractOutcome {
    let extractor_id = ExtractorId::MboxV1;
    let (values, has_attachments) = match extract_mbox_entries(limits, bytes) {
        Ok(v) => v,
        Err(reason) => {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(extractor_id),
                reason,
            };
        }
    };

    ExtractOutcome::Extracted {
        extractor_id,
        canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
        coverage: email_coverage(has_attachments),
    }
}

fn extract_ooxml(limits: ArchiveLimits, bytes: &[u8], extractor_id: ExtractorId) -> ExtractOutcome {
    let (values, embedded_binaries) = match extract_ooxml_entries(limits, bytes) {
        Ok(v) => v,
        Err(reason) => {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(extractor_id),
                reason,
            };
        }
    };

    ExtractOutcome::Extracted {
        extractor_id,
        canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
        coverage: if embedded_binaries {
            ooxml_coverage_unknown_embedded()
        } else {
            ooxml_coverage_full()
        },
    }
}
