use core::fmt;

use veil_domain::{
    ArtifactId, CoverageMapV1, CoverageStatus, QuarantineReasonCode, SourceLocatorHash,
};

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

#[derive(Clone)]
pub struct CanonicalCsv {
    pub delimiter: u8,
    pub headers: Vec<String>,
    pub records: Vec<Vec<String>>,
}

impl fmt::Debug for CanonicalCsv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalCsv")
            .field("delimiter", &self.delimiter)
            .field("headers_len", &self.headers.len())
            .field("records", &self.records.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct CanonicalJson {
    pub value: serde_json::Value,
}

impl fmt::Debug for CanonicalJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalJson")
            .field("kind", &json_kind_name(&self.value))
            .finish()
    }
}

#[derive(Clone)]
pub struct CanonicalNdjson {
    pub values: Vec<serde_json::Value>,
}

impl fmt::Debug for CanonicalNdjson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalNdjson")
            .field("records", &self.values.len())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub enum CanonicalArtifact {
    Text(CanonicalText),
    Csv(CanonicalCsv),
    Json(CanonicalJson),
    Ndjson(CanonicalNdjson),
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

#[derive(Debug, Default)]
pub struct ExtractorRegistry {
    text: TextExtractor,
    csv: CsvExtractor,
    tsv: TsvExtractor,
    json: JsonExtractor,
    ndjson: NdjsonExtractor,
}

impl ExtractorRegistry {
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
            _ => ExtractOutcome::Quarantined {
                extractor_id: None,
                reason: QuarantineReasonCode::UnsupportedFormat,
            },
        }
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
        let text = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason: QuarantineReasonCode::ParseError,
                };
            }
        };

        let mut values = Vec::<serde_json::Value>::new();
        for line in text.lines() {
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

fn canonicalize_json_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            let mut old = std::mem::take(map);
            let mut keys = old.keys().cloned().collect::<Vec<_>>();
            keys.sort();

            let mut out = serde_json::Map::new();
            for k in keys {
                let mut vv = old
                    .remove(&k)
                    .expect("key was present when enumerated");
                canonicalize_json_value(&mut vv);
                out.insert(k, vv);
            }
            *map = out;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                canonicalize_json_value(item);
            }
        }
        _ => {}
    }
}

fn json_kind_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
