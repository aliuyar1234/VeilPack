use std::io::BufRead;

use veil_domain::{
    ArchiveLimits, ArtifactId, CoverageMapV1, CoverageStatus, QuarantineReasonCode,
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
        extractor_id: &'static str,
        canonical: CanonicalArtifact,
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

#[derive(Debug)]
pub struct ExtractorRegistry {
    text: TextExtractor,
    csv: CsvExtractor,
    tsv: TsvExtractor,
    json: JsonExtractor,
    ndjson: NdjsonExtractor,
    zip: ZipExtractor,
    tar: TarExtractor,
    eml: EmlExtractor,
    mbox: MboxExtractor,
    docx: DocxExtractor,
    pptx: PptxExtractor,
    xlsx: XlsxExtractor,
}

impl ExtractorRegistry {
    pub fn new(limits: ArchiveLimits) -> Self {
        Self {
            text: TextExtractor,
            csv: CsvExtractor,
            tsv: TsvExtractor,
            json: JsonExtractor,
            ndjson: NdjsonExtractor,
            zip: ZipExtractor { limits },
            tar: TarExtractor { limits },
            eml: EmlExtractor { limits },
            mbox: MboxExtractor { limits },
            docx: DocxExtractor { limits },
            pptx: PptxExtractor { limits },
            xlsx: XlsxExtractor { limits },
        }
    }

    pub fn extract_by_type(
        &self,
        artifact_type: &str,
        ctx: ArtifactContext<'_>,
        bytes: &[u8],
    ) -> ExtractOutcome {
        match artifact_type {
            "TEXT" => self.text.extract(ctx, bytes),
            "CSV" => self.csv.extract(ctx, bytes),
            "TSV" => self.tsv.extract(ctx, bytes),
            "JSON" => self.json.extract(ctx, bytes),
            "NDJSON" => self.ndjson.extract(ctx, bytes),
            "ZIP" => self.zip.extract(ctx, bytes),
            "TAR" => self.tar.extract(ctx, bytes),
            "EML" => self.eml.extract(ctx, bytes),
            "MBOX" => self.mbox.extract(ctx, bytes),
            "DOCX" => self.docx.extract(ctx, bytes),
            "PPTX" => self.pptx.extract(ctx, bytes),
            "XLSX" => self.xlsx.extract(ctx, bytes),
            _ => ExtractOutcome::Quarantined {
                extractor_id: None,
                reason: QuarantineReasonCode::UnsupportedFormat,
            },
        }
    }
}

impl Default for ExtractorRegistry {
    fn default() -> Self {
        Self::new(ArchiveLimits::default())
    }
}

#[derive(Debug, Default)]
struct TextExtractor;

impl Extractor for TextExtractor {
    fn id(&self) -> &'static str {
        "extract.text.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let text = match std::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason: QuarantineReasonCode::ParseError,
                };
            }
        };

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
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
}

#[derive(Debug, Default)]
struct CsvExtractor;

impl Extractor for CsvExtractor {
    fn id(&self) -> &'static str {
        "extract.csv.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        extract_delimited(bytes, b',', self.id())
    }
}

#[derive(Debug, Default)]
struct TsvExtractor;

impl Extractor for TsvExtractor {
    fn id(&self) -> &'static str {
        "extract.tsv.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        extract_delimited(bytes, b'\t', self.id())
    }
}

fn extract_delimited(bytes: &[u8], delimiter: u8, extractor_id: &'static str) -> ExtractOutcome {
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

#[derive(Debug, Default)]
struct JsonExtractor;

impl Extractor for JsonExtractor {
    fn id(&self) -> &'static str {
        "extract.json.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let mut value: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(_) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason: QuarantineReasonCode::ParseError,
                };
            }
        };

        canonicalize_json_value(&mut value);

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
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
}

#[derive(Debug, Default)]
struct NdjsonExtractor;

impl Extractor for NdjsonExtractor {
    fn id(&self) -> &'static str {
        "extract.ndjson.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let mut values = Vec::<serde_json::Value>::new();
        let reader = std::io::BufReader::new(bytes);
        for line in reader.lines() {
            let line = match line {
                Ok(v) => v,
                Err(_) => {
                    return ExtractOutcome::Quarantined {
                        extractor_id: Some(self.id()),
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
                        extractor_id: Some(self.id()),
                        reason: QuarantineReasonCode::ParseError,
                    };
                }
            };
            canonicalize_json_value(&mut v);
            values.push(v);
        }

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
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
}

#[derive(Debug, Clone, Copy)]
struct ZipExtractor {
    limits: ArchiveLimits,
}

impl Extractor for ZipExtractor {
    fn id(&self) -> &'static str {
        "extract.zip.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let values = match extract_zip_entries(self.limits, bytes, 1, None) {
            Ok(v) => v,
            Err(reason) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason,
                };
            }
        };

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
            canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
            coverage: archive_coverage_full(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TarExtractor {
    limits: ArchiveLimits,
}

impl Extractor for TarExtractor {
    fn id(&self) -> &'static str {
        "extract.tar.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let values = match extract_tar_entries(self.limits, bytes, 1, None) {
            Ok(v) => v,
            Err(reason) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason,
                };
            }
        };

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
            canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
            coverage: archive_coverage_full(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EmlExtractor {
    limits: ArchiveLimits,
}

impl Extractor for EmlExtractor {
    fn id(&self) -> &'static str {
        "extract.eml.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let (values, has_attachments) = match extract_eml_entries(self.limits, bytes) {
            Ok(v) => v,
            Err(reason) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason,
                };
            }
        };

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
            canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
            coverage: email_coverage(has_attachments),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MboxExtractor {
    limits: ArchiveLimits,
}

impl Extractor for MboxExtractor {
    fn id(&self) -> &'static str {
        "extract.mbox.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let (values, has_attachments) = match extract_mbox_entries(self.limits, bytes) {
            Ok(v) => v,
            Err(reason) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason,
                };
            }
        };

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
            canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
            coverage: email_coverage(has_attachments),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DocxExtractor {
    limits: ArchiveLimits,
}

impl Extractor for DocxExtractor {
    fn id(&self) -> &'static str {
        "extract.ooxml.docx.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let (values, embedded_binaries) = match extract_ooxml_entries(self.limits, bytes) {
            Ok(v) => v,
            Err(reason) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason,
                };
            }
        };

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
            canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
            coverage: if embedded_binaries {
                ooxml_coverage_unknown_embedded()
            } else {
                ooxml_coverage_full()
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PptxExtractor {
    limits: ArchiveLimits,
}

impl Extractor for PptxExtractor {
    fn id(&self) -> &'static str {
        "extract.ooxml.pptx.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let (values, embedded_binaries) = match extract_ooxml_entries(self.limits, bytes) {
            Ok(v) => v,
            Err(reason) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason,
                };
            }
        };

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
            canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
            coverage: if embedded_binaries {
                ooxml_coverage_unknown_embedded()
            } else {
                ooxml_coverage_full()
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct XlsxExtractor {
    limits: ArchiveLimits,
}

impl Extractor for XlsxExtractor {
    fn id(&self) -> &'static str {
        "extract.ooxml.xlsx.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let (values, embedded_binaries) = match extract_ooxml_entries(self.limits, bytes) {
            Ok(v) => v,
            Err(reason) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason,
                };
            }
        };

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
            canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
            coverage: if embedded_binaries {
                ooxml_coverage_unknown_embedded()
            } else {
                ooxml_coverage_full()
            },
        }
    }
}
