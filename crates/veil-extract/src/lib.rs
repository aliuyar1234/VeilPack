use core::fmt;
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::process::{ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use veil_domain::{
    ArchiveLimits, ArtifactId, CoverageMapV1, CoverageStatus, QuarantineReasonCode,
    SourceLocatorHash,
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

const PDF_OCR_DEFAULT_TIMEOUT_MS: u64 = 30_000;
const PDF_OCR_DEFAULT_MAX_OUTPUT_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone)]
pub struct PdfOcrOptions {
    pub enabled: bool,
    pub command: Vec<String>,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
}

impl Default for PdfOcrOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            command: Vec::new(),
            timeout_ms: PDF_OCR_DEFAULT_TIMEOUT_MS,
            max_output_bytes: PDF_OCR_DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
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
    pdf: PdfExtractor,
}

impl ExtractorRegistry {
    pub fn new(limits: ArchiveLimits) -> Self {
        Self::with_pdf_options(limits, PdfOcrOptions::default())
    }

    pub fn with_pdf_options(limits: ArchiveLimits, pdf_ocr: PdfOcrOptions) -> Self {
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
            pdf: PdfExtractor {
                limits,
                ocr: pdf_ocr,
            },
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
            "PDF" => self.pdf.extract(ctx, bytes),
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
                let mut vv = old.remove(&k).expect("key was present when enumerated");
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NestedArchiveKind {
    Zip,
    Tar,
}

fn classify_nested_archive_path(normalized_path: &str) -> Option<NestedArchiveKind> {
    let lower = normalized_path.to_ascii_lowercase();
    if lower.ends_with(".zip") {
        Some(NestedArchiveKind::Zip)
    } else if lower.ends_with(".tar") {
        Some(NestedArchiveKind::Tar)
    } else {
        None
    }
}

fn normalize_archive_entry_path(raw: &str) -> Option<String> {
    let mut path = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => path.push('/'),
            '\0' => return None,
            _ => path.push(ch),
        }
    }

    // Reject absolute or UNC-like paths.
    if path.starts_with('/') || path.starts_with("//") {
        return None;
    }

    // Reject Windows drive prefixes like "C:".
    if path.len() >= 2 {
        let b = path.as_bytes();
        if b[1] == b':' && (b[0] as char).is_ascii_alphabetic() {
            return None;
        }
    }

    let mut out_segments = Vec::<&str>::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None;
        }
        out_segments.push(seg);
    }

    if out_segments.is_empty() {
        return None;
    }

    Some(out_segments.join("/"))
}

fn check_archive_totals(
    limits: ArchiveLimits,
    entry_count: usize,
    total_compressed_bytes: u64,
    total_expanded_bytes: u64,
) -> Result<(), QuarantineReasonCode> {
    let entry_count_u32 = u32::try_from(entry_count).unwrap_or(u32::MAX);
    if entry_count_u32 > limits.max_entries_per_archive {
        return Err(QuarantineReasonCode::LimitExceeded);
    }

    if total_expanded_bytes > limits.max_expanded_bytes_per_archive {
        return Err(QuarantineReasonCode::LimitExceeded);
    }

    if total_compressed_bytes == 0 {
        if total_expanded_bytes > 0 {
            return Err(QuarantineReasonCode::LimitExceeded);
        }
        return Ok(());
    }

    let ratio = u128::from(limits.max_expansion_ratio.max(1));
    let expanded = u128::from(total_expanded_bytes);
    let compressed = u128::from(total_compressed_bytes);
    if expanded > compressed.saturating_mul(ratio) {
        return Err(QuarantineReasonCode::LimitExceeded);
    }

    Ok(())
}

fn read_to_end_bounded<R: Read>(
    reader: &mut R,
    max_bytes: u64,
) -> Result<Vec<u8>, QuarantineReasonCode> {
    if max_bytes == 0 {
        return Err(QuarantineReasonCode::LimitExceeded);
    }

    let mut out = Vec::<u8>::new();
    let mut total = 0_u64;
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| QuarantineReasonCode::ParseError)?;
        if n == 0 {
            break;
        }

        let n_u64 = u64::try_from(n).map_err(|_| QuarantineReasonCode::LimitExceeded)?;
        total = total
            .checked_add(n_u64)
            .ok_or(QuarantineReasonCode::LimitExceeded)?;
        if total > max_bytes {
            return Err(QuarantineReasonCode::LimitExceeded);
        }

        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn archive_coverage_full() -> CoverageMapV1 {
    CoverageMapV1 {
        content_text: CoverageStatus::Full,
        structured_fields: CoverageStatus::None,
        metadata: CoverageStatus::Full,
        embedded_objects: CoverageStatus::None,
        attachments: CoverageStatus::Full,
    }
}

fn email_coverage(has_attachments: bool) -> CoverageMapV1 {
    CoverageMapV1 {
        content_text: CoverageStatus::Full,
        structured_fields: CoverageStatus::None,
        metadata: CoverageStatus::Full,
        embedded_objects: CoverageStatus::None,
        attachments: if has_attachments {
            CoverageStatus::Full
        } else {
            CoverageStatus::None
        },
    }
}

fn ooxml_coverage_full() -> CoverageMapV1 {
    CoverageMapV1 {
        content_text: CoverageStatus::Full,
        structured_fields: CoverageStatus::None,
        metadata: CoverageStatus::Full,
        embedded_objects: CoverageStatus::None,
        attachments: CoverageStatus::None,
    }
}

fn ooxml_coverage_unknown_embedded() -> CoverageMapV1 {
    CoverageMapV1 {
        content_text: CoverageStatus::Full,
        structured_fields: CoverageStatus::None,
        metadata: CoverageStatus::Full,
        embedded_objects: CoverageStatus::Unknown,
        attachments: CoverageStatus::None,
    }
}

fn pdf_coverage_full() -> CoverageMapV1 {
    CoverageMapV1 {
        content_text: CoverageStatus::Full,
        structured_fields: CoverageStatus::None,
        metadata: CoverageStatus::Full,
        embedded_objects: CoverageStatus::None,
        attachments: CoverageStatus::None,
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

#[derive(Debug, Clone)]
struct PdfExtractor {
    limits: ArchiveLimits,
    ocr: PdfOcrOptions,
}

impl Extractor for PdfExtractor {
    fn id(&self) -> &'static str {
        "extract.pdf.v1"
    }

    fn extract(&self, _ctx: ArtifactContext<'_>, bytes: &[u8]) -> ExtractOutcome {
        let document = match lopdf::Document::load_mem(bytes) {
            Ok(doc) => doc,
            Err(_) => {
                return ExtractOutcome::Quarantined {
                    extractor_id: Some(self.id()),
                    reason: QuarantineReasonCode::PdfParseError,
                };
            }
        };

        if document.is_encrypted() {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(self.id()),
                reason: QuarantineReasonCode::PdfEncrypted,
            };
        }

        let pages: BTreeMap<u32, lopdf::ObjectId> = document.get_pages();
        if pages.is_empty() {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(self.id()),
                reason: QuarantineReasonCode::PdfMalformed,
            };
        }

        if u32::try_from(pages.len()).unwrap_or(u32::MAX) > self.limits.max_pdf_pages {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(self.id()),
                reason: QuarantineReasonCode::PdfLimitExceeded,
            };
        }

        if let Err(reason) = ensure_pdf_supported_surfaces(&document, &pages) {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(self.id()),
                reason,
            };
        }

        let mut values = Vec::<serde_json::Value>::new();
        let mut pages_requiring_ocr = 0_u32;
        for (seq, (page_number, page_id)) in pages.iter().enumerate() {
            let page_text = match document.extract_text(&[*page_number]) {
                Ok(s) => s,
                Err(_) => {
                    return ExtractOutcome::Quarantined {
                        extractor_id: Some(self.id()),
                        reason: QuarantineReasonCode::PdfParseError,
                    };
                }
            };

            let content_bytes = match document.get_page_content(*page_id) {
                Ok(c) => c,
                Err(_) => {
                    return ExtractOutcome::Quarantined {
                        extractor_id: Some(self.id()),
                        reason: QuarantineReasonCode::PdfParseError,
                    };
                }
            };

            let has_page_ops = content_bytes.iter().any(|b| !b.is_ascii_whitespace());
            let text = sanitize_pdf_text(&page_text);
            if text.trim().is_empty() {
                if has_page_ops {
                    if !self.ocr.enabled {
                        pages_requiring_ocr = pages_requiring_ocr.saturating_add(1);
                        continue;
                    }

                    let ocr_text = match run_pdf_ocr_command(
                        &self.ocr,
                        _ctx,
                        bytes,
                        page_number.saturating_sub(1),
                        *page_number,
                    ) {
                        Ok(t) => t,
                        Err(reason) => {
                            return ExtractOutcome::Quarantined {
                                extractor_id: Some(self.id()),
                                reason,
                            };
                        }
                    };
                    let ocr_text = sanitize_pdf_text(&ocr_text);
                    if ocr_text.trim().is_empty() {
                        return ExtractOutcome::Quarantined {
                            extractor_id: Some(self.id()),
                            reason: QuarantineReasonCode::PdfOcrFailed,
                        };
                    }
                    values.push(make_pdf_text_record(
                        page_number.saturating_sub(1),
                        seq as u32,
                        "ocr",
                        &ocr_text,
                    ));
                }
                continue;
            }

            values.push(make_pdf_text_record(
                page_number.saturating_sub(1),
                seq as u32,
                "text_layer",
                &text,
            ));
        }

        if pages_requiring_ocr > 0 {
            return ExtractOutcome::Quarantined {
                extractor_id: Some(self.id()),
                reason: QuarantineReasonCode::PdfOcrRequiredButDisabled,
            };
        }

        ExtractOutcome::Extracted {
            extractor_id: self.id(),
            canonical: CanonicalArtifact::Ndjson(CanonicalNdjson { values }),
            coverage: pdf_coverage_full(),
        }
    }
}

fn sanitize_pdf_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch == '\u{0}' {
            continue;
        }
        if ch == '\r' {
            out.push('\n');
            continue;
        }
        out.push(ch);
    }
    out
}

fn make_pdf_text_record(page_index: u32, seq: u32, surface: &str, text: &str) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "schema_version".to_string(),
        serde_json::Value::String("veil.pdf.ndjson.v1".to_string()),
    );
    map.insert(
        "page_index".to_string(),
        serde_json::Value::Number(serde_json::Number::from(page_index as u64)),
    );
    map.insert(
        "surface".to_string(),
        serde_json::Value::String(surface.to_string()),
    );
    map.insert(
        "seq".to_string(),
        serde_json::Value::Number(serde_json::Number::from(seq as u64)),
    );
    map.insert(
        "text".to_string(),
        serde_json::Value::String(text.to_string()),
    );
    serde_json::Value::Object(map)
}

fn ensure_pdf_supported_surfaces(
    document: &lopdf::Document,
    pages: &BTreeMap<u32, lopdf::ObjectId>,
) -> Result<(), QuarantineReasonCode> {
    let root_obj = document
        .trailer
        .get(b"Root")
        .and_then(|obj| document.dereference(obj))
        .map_err(|_| QuarantineReasonCode::PdfParseError)?
        .1;
    let root = root_obj
        .as_dict()
        .map_err(|_| QuarantineReasonCode::PdfParseError)?;

    if root.has(b"OpenAction") || root.has(b"AA") {
        return Err(QuarantineReasonCode::PdfActionsPresentUnsupported);
    }

    if let Ok(acro_form_obj) = root.get_deref(b"AcroForm", document) {
        let acro_form = acro_form_obj
            .as_dict()
            .map_err(|_| QuarantineReasonCode::PdfParseError)?;
        if acro_form.has(b"XFA") {
            return Err(QuarantineReasonCode::PdfXfaUnsupported);
        }
        if acro_form.has(b"AA") {
            return Err(QuarantineReasonCode::PdfActionsPresentUnsupported);
        }
    }

    if let Ok(names_obj) = root.get_deref(b"Names", document) {
        let names = names_obj
            .as_dict()
            .map_err(|_| QuarantineReasonCode::PdfParseError)?;
        if names.has(b"JavaScript") {
            return Err(QuarantineReasonCode::PdfActionsPresentUnsupported);
        }
        if names.has(b"EmbeddedFiles") {
            return Err(QuarantineReasonCode::PdfEmbeddedFileExtractionFailed);
        }
    }

    for page_id in pages.values() {
        let page = document
            .get_object(*page_id)
            .and_then(lopdf::Object::as_dict)
            .map_err(|_| QuarantineReasonCode::PdfParseError)?;

        if page.has(b"AA") {
            return Err(QuarantineReasonCode::PdfActionsPresentUnsupported);
        }

        if let Ok(annots_obj) = page.get_deref(b"Annots", document) {
            let annots = annots_obj
                .as_array()
                .map_err(|_| QuarantineReasonCode::PdfParseError)?;
            for annot in annots {
                let annot_obj = document
                    .dereference(annot)
                    .map_err(|_| QuarantineReasonCode::PdfParseError)?
                    .1;
                let annot_dict = annot_obj
                    .as_dict()
                    .map_err(|_| QuarantineReasonCode::PdfParseError)?;
                if annot_dict.has(b"A") || annot_dict.has(b"AA") {
                    return Err(QuarantineReasonCode::PdfActionsPresentUnsupported);
                }
            }
        }
    }

    Ok(())
}

fn run_pdf_ocr_command(
    options: &PdfOcrOptions,
    ctx: ArtifactContext<'_>,
    pdf_bytes: &[u8],
    page_index: u32,
    page_number: u32,
) -> Result<String, QuarantineReasonCode> {
    if options.command.is_empty() {
        return Err(QuarantineReasonCode::PdfOcrFailed);
    }

    let mut command = Command::new(&options.command[0]);
    command
        .args(&options.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("VEIL_PDF_OCR_PAGE_INDEX", page_index.to_string())
        .env("VEIL_PDF_OCR_PAGE_NUMBER", page_number.to_string())
        .env("VEIL_ARTIFACT_ID", ctx.artifact_id.to_string())
        .env(
            "VEIL_SOURCE_LOCATOR_HASH",
            ctx.source_locator_hash.to_string(),
        );

    let mut child = command
        .spawn()
        .map_err(|_| QuarantineReasonCode::PdfOcrFailed)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(QuarantineReasonCode::PdfOcrFailed)?;
    let max_output_bytes = options.max_output_bytes;
    let stdout_reader = thread::spawn(move || read_pdf_ocr_stdout(stdout, max_output_bytes));

    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(pdf_bytes).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            return Err(QuarantineReasonCode::PdfOcrFailed);
        }
    } else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = stdout_reader.join();
        return Err(QuarantineReasonCode::PdfOcrFailed);
    }

    let timeout = Duration::from_millis(options.timeout_ms);
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    return Err(QuarantineReasonCode::PdfOcrFailed);
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                return Err(QuarantineReasonCode::PdfOcrFailed);
            }
        }
    };

    let (stdout, overflow) = stdout_reader
        .join()
        .map_err(|_| QuarantineReasonCode::PdfOcrFailed)?
        .map_err(|_| QuarantineReasonCode::PdfOcrFailed)?;
    if overflow || !status.success() {
        return Err(QuarantineReasonCode::PdfOcrFailed);
    }

    String::from_utf8(stdout).map_err(|_| QuarantineReasonCode::PdfOcrFailed)
}

fn read_pdf_ocr_stdout(stdout: ChildStdout, max_output_bytes: u64) -> Result<(Vec<u8>, bool), ()> {
    let max_bytes = usize::try_from(max_output_bytes).map_err(|_| ())?;
    let mut reader = stdout;
    let mut out = Vec::<u8>::new();
    let mut overflow = false;
    let mut buf = [0_u8; 8192];
    loop {
        let n = reader.read(&mut buf).map_err(|_| ())?;
        if n == 0 {
            break;
        }
        if out.len() < max_bytes {
            let remaining = max_bytes.saturating_sub(out.len());
            let copy_len = remaining.min(n);
            out.extend_from_slice(&buf[..copy_len]);
            if copy_len < n {
                overflow = true;
            }
        } else {
            overflow = true;
        }
    }
    Ok((out, overflow))
}

fn classify_attachment_archive(
    mimetype: &str,
    disposition_filename: Option<&str>,
) -> Option<NestedArchiveKind> {
    let mimetype = mimetype.to_ascii_lowercase();
    if mimetype == "application/zip" {
        return Some(NestedArchiveKind::Zip);
    }
    if mimetype == "application/x-tar" {
        return Some(NestedArchiveKind::Tar);
    }

    let name = disposition_filename?;
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".zip") {
        Some(NestedArchiveKind::Zip)
    } else if lower.ends_with(".tar") {
        Some(NestedArchiveKind::Tar)
    } else {
        None
    }
}

fn make_email_header_record(
    message_index: Option<u32>,
    header_index: u32,
    key: &str,
    value: &str,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(message_index) = message_index {
        map.insert(
            "message_index".to_string(),
            serde_json::Value::Number(serde_json::Number::from(message_index as u64)),
        );
    }
    map.insert(
        "header_index".to_string(),
        serde_json::Value::Number(serde_json::Number::from(header_index as u64)),
    );
    map.insert(
        "key".to_string(),
        serde_json::Value::String(key.to_string()),
    );
    map.insert(
        "value".to_string(),
        serde_json::Value::String(value.to_string()),
    );
    serde_json::Value::Object(map)
}

fn make_email_body_record(
    message_index: Option<u32>,
    body_index: u32,
    text: &str,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(message_index) = message_index {
        map.insert(
            "message_index".to_string(),
            serde_json::Value::Number(serde_json::Number::from(message_index as u64)),
        );
    }
    map.insert(
        "body_index".to_string(),
        serde_json::Value::Number(serde_json::Number::from(body_index as u64)),
    );
    map.insert(
        "text".to_string(),
        serde_json::Value::String(text.to_string()),
    );
    serde_json::Value::Object(map)
}

fn make_email_attachment_record(
    message_index: Option<u32>,
    attachment_index: u32,
    attachment_locator_hash: &str,
    filename_hash: Option<&str>,
    text: &str,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(message_index) = message_index {
        map.insert(
            "message_index".to_string(),
            serde_json::Value::Number(serde_json::Number::from(message_index as u64)),
        );
    }
    map.insert(
        "attachment_index".to_string(),
        serde_json::Value::Number(serde_json::Number::from(attachment_index as u64)),
    );
    map.insert(
        "attachment_locator_hash".to_string(),
        serde_json::Value::String(attachment_locator_hash.to_string()),
    );
    if let Some(filename_hash) = filename_hash {
        map.insert(
            "filename_hash".to_string(),
            serde_json::Value::String(filename_hash.to_string()),
        );
    }
    map.insert(
        "text".to_string(),
        serde_json::Value::String(text.to_string()),
    );
    serde_json::Value::Object(map)
}

fn synth_locator_hash(parts: &[&str]) -> String {
    let joined = parts.join("/");
    veil_domain::hash_source_locator_hash(&joined).to_string()
}

fn extract_eml_entries(
    limits: ArchiveLimits,
    bytes: &[u8],
) -> Result<(Vec<serde_json::Value>, bool), QuarantineReasonCode> {
    let mail = mailparse::parse_mail(bytes).map_err(|_| QuarantineReasonCode::ParseError)?;

    let mut out = Vec::<serde_json::Value>::new();

    for (idx, h) in mail.headers.iter().enumerate() {
        let idx = u32::try_from(idx).unwrap_or(u32::MAX);
        out.push(make_email_header_record(
            None,
            idx,
            &h.get_key(),
            &h.get_value(),
        ));
    }

    let mut has_attachments = false;
    let mut attachment_index = 0_u32;
    let mut body_index = 0_u32;
    collect_mail_leaf_parts(
        limits,
        &mail,
        None,
        &mut out,
        &mut has_attachments,
        &mut attachment_index,
        &mut body_index,
    )?;

    Ok((out, has_attachments))
}

fn extract_mbox_entries(
    limits: ArchiveLimits,
    bytes: &[u8],
) -> Result<(Vec<serde_json::Value>, bool), QuarantineReasonCode> {
    let messages = split_mbox_messages(bytes);

    let mut out = Vec::<serde_json::Value>::new();
    let mut any_attachments = false;

    for (msg_idx, msg_bytes) in messages.iter().enumerate() {
        let msg_idx_u32 = u32::try_from(msg_idx).unwrap_or(u32::MAX);
        let mail =
            mailparse::parse_mail(msg_bytes).map_err(|_| QuarantineReasonCode::ParseError)?;

        for (idx, h) in mail.headers.iter().enumerate() {
            let idx = u32::try_from(idx).unwrap_or(u32::MAX);
            out.push(make_email_header_record(
                Some(msg_idx_u32),
                idx,
                &h.get_key(),
                &h.get_value(),
            ));
        }

        let mut has_attachments = false;
        let mut attachment_index = 0_u32;
        let mut body_index = 0_u32;
        collect_mail_leaf_parts(
            limits,
            &mail,
            Some(msg_idx_u32),
            &mut out,
            &mut has_attachments,
            &mut attachment_index,
            &mut body_index,
        )?;
        if has_attachments {
            any_attachments = true;
        }
    }

    Ok((out, any_attachments))
}

fn collect_mail_leaf_parts(
    limits: ArchiveLimits,
    mail: &mailparse::ParsedMail<'_>,
    message_index: Option<u32>,
    out: &mut Vec<serde_json::Value>,
    has_attachments: &mut bool,
    attachment_index: &mut u32,
    body_index: &mut u32,
) -> Result<(), QuarantineReasonCode> {
    use mailparse::MailHeaderMap;

    if !mail.subparts.is_empty() {
        for sub in mail.subparts.iter() {
            collect_mail_leaf_parts(
                limits,
                sub,
                message_index,
                out,
                has_attachments,
                attachment_index,
                body_index,
            )?;
        }
        return Ok(());
    }

    let disposition = mail
        .headers
        .get_first_value("Content-Disposition")
        .map(|s| mailparse::parse_content_disposition(&s))
        .unwrap_or_default();
    let filename = disposition
        .params
        .get("filename")
        .or_else(|| disposition.params.get("name"))
        .map(|s| s.as_str());

    let mimetype = mail.ctype.mimetype.to_ascii_lowercase();
    let is_text = mimetype.starts_with("text/");

    let is_attachment = matches!(
        disposition.disposition,
        mailparse::DispositionType::Attachment
    ) || filename.is_some()
        || !is_text;

    if is_attachment {
        *has_attachments = true;

        let idx = *attachment_index;
        *attachment_index = attachment_index.saturating_add(1);

        let locator_hash = match message_index {
            Some(m) => synth_locator_hash(&["mbox", &m.to_string(), "attach", &idx.to_string()]),
            None => synth_locator_hash(&["eml", "attach", &idx.to_string()]),
        };

        let filename_hash = filename.map(|f| veil_domain::hash_source_locator_hash(f).to_string());

        let raw = mail
            .get_body_raw()
            .map_err(|_| QuarantineReasonCode::ParseError)?;
        let raw_len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        if raw_len > limits.max_bytes_per_artifact {
            return Err(QuarantineReasonCode::LimitExceeded);
        }

        if let Some(kind) = classify_attachment_archive(&mimetype, filename) {
            let nested = match kind {
                NestedArchiveKind::Zip => {
                    extract_zip_entries(limits, &raw, 1, Some(&locator_hash))?
                }
                NestedArchiveKind::Tar => {
                    extract_tar_entries(limits, &raw, 1, Some(&locator_hash))?
                }
            };
            for mut v in nested {
                if let serde_json::Value::Object(ref mut map) = v {
                    if let Some(message_index) = message_index {
                        map.insert(
                            "message_index".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(
                                message_index as u64,
                            )),
                        );
                    }
                    map.insert(
                        "attachment_index".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(idx as u64)),
                    );
                    map.insert(
                        "attachment_locator_hash".to_string(),
                        serde_json::Value::String(locator_hash.clone()),
                    );
                    if let Some(ref filename_hash) = filename_hash {
                        map.insert(
                            "filename_hash".to_string(),
                            serde_json::Value::String(filename_hash.clone()),
                        );
                    }
                }
                out.push(v);
            }
            return Ok(());
        }

        if !is_text {
            return Err(QuarantineReasonCode::UnsupportedFormat);
        }

        let text = mail
            .get_body()
            .map_err(|_| QuarantineReasonCode::ParseError)?;
        out.push(make_email_attachment_record(
            message_index,
            idx,
            &locator_hash,
            filename_hash.as_deref(),
            &text,
        ));
        return Ok(());
    }

    let idx = *body_index;
    *body_index = body_index.saturating_add(1);
    let text = mail
        .get_body()
        .map_err(|_| QuarantineReasonCode::ParseError)?;
    out.push(make_email_body_record(message_index, idx, &text));
    Ok(())
}

fn split_mbox_messages(bytes: &[u8]) -> Vec<&[u8]> {
    // If no mbox separators exist, treat the whole file as one message.
    let mut starts = Vec::<usize>::new();
    if bytes.starts_with(b"From ") {
        starts.push(0);
    }

    let mut i = 0;
    while i + 6 <= bytes.len() {
        if bytes[i] == b'\n' && bytes[i + 1..].starts_with(b"From ") {
            starts.push(i + 1);
            i += 6;
            continue;
        }
        i += 1;
    }

    if starts.is_empty() {
        return vec![bytes];
    }

    let mut out = Vec::<&[u8]>::new();
    for (pos_idx, start) in starts.iter().copied().enumerate() {
        let end = starts.get(pos_idx + 1).copied().unwrap_or(bytes.len());
        let slice = &bytes[start..end];

        // Skip the "From " separator line.
        let mut msg_start = 0;
        while msg_start < slice.len() && slice[msg_start] != b'\n' {
            msg_start += 1;
        }
        if msg_start < slice.len() {
            msg_start += 1;
        }

        if msg_start < slice.len() {
            out.push(&slice[msg_start..]);
        }
    }

    out
}

fn read_zip_index<'a>(
    archive: &'a mut zip::ZipArchive<Cursor<&[u8]>>,
    idx: usize,
) -> Result<zip::read::ZipFile<'a>, QuarantineReasonCode> {
    match archive.by_index(idx) {
        Ok(file) => Ok(file),
        Err(zip::result::ZipError::UnsupportedArchive(
            zip::result::ZipError::PASSWORD_REQUIRED,
        )) => Err(QuarantineReasonCode::Encrypted),
        Err(zip::result::ZipError::UnsupportedArchive(_)) => {
            Err(QuarantineReasonCode::UnsupportedFormat)
        }
        Err(zip::result::ZipError::InvalidArchive(_)) => Err(QuarantineReasonCode::ParseError),
        Err(zip::result::ZipError::Io(_)) => Err(QuarantineReasonCode::ParseError),
        Err(zip::result::ZipError::FileNotFound) => Err(QuarantineReasonCode::ParseError),
    }
}

fn make_ooxml_record(part_path_hash: &str, text: &str) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "part_path_hash".to_string(),
        serde_json::Value::String(part_path_hash.to_string()),
    );
    map.insert(
        "text".to_string(),
        serde_json::Value::String(text.to_string()),
    );
    serde_json::Value::Object(map)
}

fn extract_ooxml_entries(
    limits: ArchiveLimits,
    bytes: &[u8],
) -> Result<(Vec<serde_json::Value>, bool), QuarantineReasonCode> {
    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|_| QuarantineReasonCode::ParseError)?;

    let entry_count = archive.len();
    if u32::try_from(entry_count).unwrap_or(u32::MAX) > limits.max_entries_per_archive {
        return Err(QuarantineReasonCode::LimitExceeded);
    }

    #[derive(Debug, Clone)]
    struct PartMeta {
        index: usize,
        normalized_path: String,
        part_path_hash: String,
        is_dir: bool,
        is_xml: bool,
    }

    let mut total_compressed_bytes = 0_u64;
    let mut total_expanded_bytes_observed = 0_u64;

    let mut has_embedded_binaries = false;
    let mut metas = Vec::<PartMeta>::with_capacity(entry_count);
    for idx in 0..entry_count {
        let file = read_zip_index(&mut archive, idx)?;

        if let Some(mode) = file.unix_mode() {
            let file_type = mode & 0o170000;
            if file_type == 0o120000 {
                return Err(QuarantineReasonCode::UnsafePath);
            }
        }

        let normalized_path =
            normalize_archive_entry_path(file.name()).ok_or(QuarantineReasonCode::UnsafePath)?;
        let lower = normalized_path.to_ascii_lowercase();
        let is_xml = lower.ends_with(".xml") || lower.ends_with(".rels");

        let is_dir = file.is_dir();
        if !is_dir && !is_xml {
            has_embedded_binaries = true;
        }

        total_compressed_bytes = total_compressed_bytes
            .checked_add(file.compressed_size())
            .ok_or(QuarantineReasonCode::LimitExceeded)?;
        let part_path_hash = veil_domain::hash_source_locator_hash(&normalized_path).to_string();
        metas.push(PartMeta {
            index: idx,
            normalized_path,
            part_path_hash,
            is_dir,
            is_xml,
        });
    }

    check_archive_totals(limits, entry_count, total_compressed_bytes, 0)?;

    if has_embedded_binaries {
        return Ok((Vec::new(), true));
    }

    metas.sort_by(|a, b| a.normalized_path.cmp(&b.normalized_path));

    let mut values = Vec::<serde_json::Value>::new();
    for meta in metas {
        if meta.is_dir || !meta.is_xml {
            continue;
        }

        let mut file = read_zip_index(&mut archive, meta.index)?;
        let part_bytes = read_to_end_bounded(&mut file, limits.max_bytes_per_artifact)?;
        total_expanded_bytes_observed = total_expanded_bytes_observed
            .checked_add(u64::try_from(part_bytes.len()).unwrap_or(u64::MAX))
            .ok_or(QuarantineReasonCode::LimitExceeded)?;
        if total_expanded_bytes_observed > limits.max_expanded_bytes_per_archive {
            return Err(QuarantineReasonCode::LimitExceeded);
        }

        let text = extract_xml_text(&part_bytes)?;
        if text.trim().is_empty() {
            continue;
        }

        values.push(make_ooxml_record(&meta.part_path_hash, &text));
    }

    check_archive_totals(
        limits,
        entry_count,
        total_compressed_bytes,
        total_expanded_bytes_observed,
    )?;
    Ok((values, false))
}

fn extract_xml_text(xml_bytes: &[u8]) -> Result<String, QuarantineReasonCode> {
    // OOXML parts are expected to be UTF-8 XML. Fail closed on invalid encoding.
    let s = std::str::from_utf8(xml_bytes).map_err(|_| QuarantineReasonCode::ParseError)?;
    let bytes = s.as_bytes();

    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if bytes[i..].starts_with(b"<!--") {
                if let Some(end) = find_subslice(bytes, b"-->", i + 4) {
                    i = end + 3;
                    continue;
                }
                break;
            }

            if bytes[i..].starts_with(b"<![CDATA[") {
                if let Some(end) = find_subslice(bytes, b"]]>", i + 9) {
                    let token = &bytes[i + 9..end];
                    push_xml_token(&mut out, token);
                    i = end + 3;
                    continue;
                }
                break;
            }

            // Parse tag and capture attribute values.
            i += 1;
            while i < bytes.len() && bytes[i] != b'>' {
                let b = bytes[i];
                if b == b'\"' || b == b'\'' {
                    let quote = b;
                    i += 1;
                    let start = i;
                    while i < bytes.len() && bytes[i] != quote {
                        i += 1;
                    }
                    let token = &bytes[start..i];
                    push_xml_token(&mut out, token);
                    if i < bytes.len() {
                        i += 1;
                    }
                    continue;
                }
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'>' {
                i += 1;
            }
            continue;
        }

        let start = i;
        while i < bytes.len() && bytes[i] != b'<' {
            i += 1;
        }
        let token = &bytes[start..i];
        push_xml_token(&mut out, token);
    }

    Ok(out)
}

fn find_subslice(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| start + p)
}

fn push_xml_token(out: &mut String, token: &[u8]) {
    let Ok(s) = std::str::from_utf8(token) else {
        return;
    };
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return;
    }
    let decoded = decode_xml_entities(trimmed);
    let decoded = decoded.trim();
    if decoded.is_empty() {
        return;
    }
    out.push_str(decoded);
    out.push('\n');
}

fn decode_xml_entities(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            let ch = s[i..].chars().next().expect("non-empty");
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }

        let Some(end_rel) = bytes[i..].iter().position(|b| *b == b';') else {
            out.push('&');
            i += 1;
            continue;
        };
        let end = i + end_rel;
        let ent = &s[i + 1..end];

        match ent {
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "amp" => out.push('&'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                if let Some(hex) = ent.strip_prefix("#x") {
                    if let Ok(v) = u32::from_str_radix(hex, 16)
                        && let Some(ch) = char::from_u32(v)
                    {
                        out.push(ch);
                    } else {
                        out.push('&');
                        out.push_str(ent);
                        out.push(';');
                    }
                } else if let Some(dec) = ent.strip_prefix('#') {
                    if let Ok(v) = dec.parse::<u32>()
                        && let Some(ch) = char::from_u32(v)
                    {
                        out.push(ch);
                    } else {
                        out.push('&');
                        out.push_str(ent);
                        out.push(';');
                    }
                } else {
                    out.push('&');
                    out.push_str(ent);
                    out.push(';');
                }
            }
        }

        i = end + 1;
    }
    out
}

fn make_archive_record(
    depth: u32,
    container_path_hash: Option<&str>,
    entry_path_hash: &str,
    text: &str,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "archive_depth".to_string(),
        serde_json::Value::Number(serde_json::Number::from(depth as u64)),
    );
    if let Some(container_path_hash) = container_path_hash {
        map.insert(
            "container_path_hash".to_string(),
            serde_json::Value::String(container_path_hash.to_string()),
        );
    }
    map.insert(
        "entry_path_hash".to_string(),
        serde_json::Value::String(entry_path_hash.to_string()),
    );
    map.insert(
        "text".to_string(),
        serde_json::Value::String(text.to_string()),
    );
    serde_json::Value::Object(map)
}

fn extract_zip_entries(
    limits: ArchiveLimits,
    bytes: &[u8],
    depth: u32,
    container_path_hash: Option<&str>,
) -> Result<Vec<serde_json::Value>, QuarantineReasonCode> {
    if depth > limits.max_nested_archive_depth {
        return Err(QuarantineReasonCode::LimitExceeded);
    }

    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|_| QuarantineReasonCode::ParseError)?;

    let entry_count = archive.len();
    if u32::try_from(entry_count).unwrap_or(u32::MAX) > limits.max_entries_per_archive {
        return Err(QuarantineReasonCode::LimitExceeded);
    }

    let mut total_compressed_bytes = 0_u64;
    let mut total_expanded_bytes_observed = 0_u64;

    #[derive(Debug, Clone)]
    struct ZipMeta {
        index: usize,
        normalized_path: String,
        entry_path_hash: String,
        is_dir: bool,
        nested_kind: Option<NestedArchiveKind>,
    }

    let mut metas = Vec::<ZipMeta>::with_capacity(entry_count);
    for i in 0..entry_count {
        let file = read_zip_index(&mut archive, i)?;

        if let Some(mode) = file.unix_mode() {
            let file_type = mode & 0o170000;
            // 0o120000: symlink. Hardlinks are not representable in ZIP in a safe way.
            if file_type == 0o120000 {
                return Err(QuarantineReasonCode::UnsafePath);
            }
        }

        let raw_name = file.name();
        let normalized_path =
            normalize_archive_entry_path(raw_name).ok_or(QuarantineReasonCode::UnsafePath)?;
        let entry_path_hash = veil_domain::hash_source_locator_hash(&normalized_path).to_string();

        total_compressed_bytes = total_compressed_bytes
            .checked_add(file.compressed_size())
            .ok_or(QuarantineReasonCode::LimitExceeded)?;
        let nested_kind = classify_nested_archive_path(&normalized_path);
        metas.push(ZipMeta {
            index: i,
            normalized_path,
            entry_path_hash,
            is_dir: file.is_dir(),
            nested_kind,
        });
    }

    check_archive_totals(limits, entry_count, total_compressed_bytes, 0)?;

    metas.sort_by(|a, b| a.normalized_path.cmp(&b.normalized_path));

    let mut out = Vec::<serde_json::Value>::new();
    for meta in metas {
        if meta.is_dir {
            continue;
        }

        let mut file = read_zip_index(&mut archive, meta.index)?;

        if let Some(kind) = meta.nested_kind {
            let next_depth = depth
                .checked_add(1)
                .ok_or(QuarantineReasonCode::LimitExceeded)?;
            if next_depth > limits.max_nested_archive_depth {
                return Err(QuarantineReasonCode::LimitExceeded);
            }

            let nested_bytes = read_to_end_bounded(&mut file, limits.max_bytes_per_artifact)?;
            total_expanded_bytes_observed = total_expanded_bytes_observed
                .checked_add(u64::try_from(nested_bytes.len()).unwrap_or(u64::MAX))
                .ok_or(QuarantineReasonCode::LimitExceeded)?;
            if total_expanded_bytes_observed > limits.max_expanded_bytes_per_archive {
                return Err(QuarantineReasonCode::LimitExceeded);
            }

            let nested_entries = match kind {
                NestedArchiveKind::Zip => extract_zip_entries(
                    limits,
                    &nested_bytes,
                    next_depth,
                    Some(&meta.entry_path_hash),
                )?,
                NestedArchiveKind::Tar => extract_tar_entries(
                    limits,
                    &nested_bytes,
                    next_depth,
                    Some(&meta.entry_path_hash),
                )?,
            };
            out.extend(nested_entries);
            continue;
        }

        let entry_bytes = read_to_end_bounded(&mut file, limits.max_bytes_per_artifact)?;
        total_expanded_bytes_observed = total_expanded_bytes_observed
            .checked_add(u64::try_from(entry_bytes.len()).unwrap_or(u64::MAX))
            .ok_or(QuarantineReasonCode::LimitExceeded)?;
        if total_expanded_bytes_observed > limits.max_expanded_bytes_per_archive {
            return Err(QuarantineReasonCode::LimitExceeded);
        }

        let text = std::str::from_utf8(&entry_bytes)
            .map_err(|_| QuarantineReasonCode::UnsupportedFormat)?;
        out.push(make_archive_record(
            depth,
            container_path_hash,
            &meta.entry_path_hash,
            text,
        ));
    }

    check_archive_totals(
        limits,
        entry_count,
        total_compressed_bytes,
        total_expanded_bytes_observed,
    )?;
    Ok(out)
}

fn extract_tar_entries(
    limits: ArchiveLimits,
    bytes: &[u8],
    depth: u32,
    container_path_hash: Option<&str>,
) -> Result<Vec<serde_json::Value>, QuarantineReasonCode> {
    if depth > limits.max_nested_archive_depth {
        return Err(QuarantineReasonCode::LimitExceeded);
    }

    let cursor = Cursor::new(bytes);
    let mut archive = tar::Archive::new(cursor);

    let mut total_entries = 0_usize;
    let mut total_expanded_bytes = 0_u64;
    let mut extracted = Vec::<(String, serde_json::Value)>::new();

    let entries = archive
        .entries()
        .map_err(|_| QuarantineReasonCode::ParseError)?;

    for entry in entries {
        let mut entry = entry.map_err(|_| QuarantineReasonCode::ParseError)?;
        total_entries += 1;
        if u32::try_from(total_entries).unwrap_or(u32::MAX) > limits.max_entries_per_archive {
            return Err(QuarantineReasonCode::LimitExceeded);
        }

        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink()
            || entry_type.is_hard_link()
            || entry_type.is_character_special()
            || entry_type.is_block_special()
            || entry_type.is_fifo()
        {
            return Err(QuarantineReasonCode::UnsafePath);
        }

        let raw_path = entry.path().map_err(|_| QuarantineReasonCode::ParseError)?;
        let raw_path = raw_path.to_str().ok_or(QuarantineReasonCode::UnsafePath)?;
        let normalized_path =
            normalize_archive_entry_path(raw_path).ok_or(QuarantineReasonCode::UnsafePath)?;

        if entry.header().entry_type().is_dir() {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err(QuarantineReasonCode::UnsupportedFormat);
        }

        let entry_path_hash = veil_domain::hash_source_locator_hash(&normalized_path).to_string();
        let nested_kind = classify_nested_archive_path(&normalized_path);

        let entry_bytes = read_to_end_bounded(&mut entry, limits.max_bytes_per_artifact)?;
        total_expanded_bytes = total_expanded_bytes
            .checked_add(u64::try_from(entry_bytes.len()).unwrap_or(u64::MAX))
            .ok_or(QuarantineReasonCode::LimitExceeded)?;
        if total_expanded_bytes > limits.max_expanded_bytes_per_archive {
            return Err(QuarantineReasonCode::LimitExceeded);
        }

        if let Some(kind) = nested_kind {
            let next_depth = depth
                .checked_add(1)
                .ok_or(QuarantineReasonCode::LimitExceeded)?;
            if next_depth > limits.max_nested_archive_depth {
                return Err(QuarantineReasonCode::LimitExceeded);
            }

            let nested_entries = match kind {
                NestedArchiveKind::Zip => {
                    extract_zip_entries(limits, &entry_bytes, next_depth, Some(&entry_path_hash))?
                }
                NestedArchiveKind::Tar => {
                    extract_tar_entries(limits, &entry_bytes, next_depth, Some(&entry_path_hash))?
                }
            };
            for v in nested_entries {
                extracted.push((normalized_path.clone(), v));
            }
            continue;
        }

        let text = std::str::from_utf8(&entry_bytes)
            .map_err(|_| QuarantineReasonCode::UnsupportedFormat)?;
        extracted.push((
            normalized_path.clone(),
            make_archive_record(depth, container_path_hash, &entry_path_hash, text),
        ));
    }

    // TAR is uncompressed; compressed_bytes == expanded_bytes for ratio purposes.
    check_archive_totals(
        limits,
        total_entries,
        total_expanded_bytes,
        total_expanded_bytes,
    )?;

    extracted.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(extracted.into_iter().map(|(_, v)| v).collect())
}
