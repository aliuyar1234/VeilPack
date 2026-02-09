use veil_domain::{
    ArchiveLimits, CoverageStatus, QuarantineReasonCode, hash_artifact_id, hash_source_locator_hash,
};
use veil_extract::{
    ArtifactContext, CanonicalArtifact, ExtractOutcome, ExtractorRegistry, PdfOcrOptions,
};

use std::path::{Path, PathBuf};

fn ctx() -> (veil_domain::ArtifactId, veil_domain::SourceLocatorHash) {
    let artifact_id = hash_artifact_id(b"test");
    let source_locator_hash = hash_source_locator_hash("test.txt");
    (artifact_id, source_locator_hash)
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "veil_extract_test_{}_{}",
            std::process::id(),
            label.replace(['\\', '/', ':'], "_")
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn python_executable() -> String {
    std::env::var("PYTHON").unwrap_or_else(|_| "python".to_string())
}

fn write_ocr_script(path: &Path, source: &str) {
    std::fs::write(path, source).expect("write OCR script");
}

fn ocr_options(script_path: &Path) -> PdfOcrOptions {
    PdfOcrOptions {
        enabled: true,
        command: vec![
            python_executable(),
            script_path.to_str().expect("UTF-8 script path").to_string(),
        ],
        timeout_ms: 5_000,
        max_output_bytes: 16_384,
    }
}

fn escape_pdf_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

fn build_pdf(content_stream: &str) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("%PDF-1.4\n");

    let mut offsets = Vec::<usize>::new();
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n".to_string(),
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            content_stream.len(),
            content_stream
        ),
        "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".to_string(),
    ];

    for obj in &objects {
        offsets.push(out.len());
        out.push_str(obj);
    }

    let xref_offset = out.len();
    out.push_str("xref\n0 6\n");
    out.push_str("0000000000 65535 f \n");
    for off in offsets {
        out.push_str(&format!("{off:010} 00000 n \n"));
    }
    out.push_str("trailer\n<< /Size 6 /Root 1 0 R >>\n");
    out.push_str(&format!("startxref\n{xref_offset}\n%%EOF\n"));
    out.into_bytes()
}

fn make_pdf_with_text(text: &str) -> Vec<u8> {
    let escaped = escape_pdf_text(text);
    let content = format!("BT /F1 24 Tf 72 720 Td ({escaped}) Tj ET");
    build_pdf(&content)
}

fn make_pdf_with_graphics_only() -> Vec<u8> {
    // Rectangle fill with no text operators.
    build_pdf("0 0 200 200 re f")
}

fn make_pdf_with_open_action() -> Vec<u8> {
    let mut out = String::new();
    out.push_str("%PDF-1.4\n");

    let content_stream = "BT /F1 24 Tf 72 720 Td (HELLO) Tj ET";
    let mut offsets = Vec::<usize>::new();
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n".to_string(),
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            content_stream.len(),
            content_stream
        ),
        "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".to_string(),
    ];

    for obj in &objects {
        offsets.push(out.len());
        out.push_str(obj);
    }

    let xref_offset = out.len();
    out.push_str("xref\n0 6\n");
    out.push_str("0000000000 65535 f \n");
    for off in offsets {
        out.push_str(&format!("{off:010} 00000 n \n"));
    }
    out.push_str("trailer\n<< /Size 6 /Root 1 0 R >>\n");
    out.push_str(&format!("startxref\n{xref_offset}\n%%EOF\n"));
    out.into_bytes()
}

#[test]
fn text_utf8_extracts_with_full_coverage() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let out = reg.extract_by_type("TEXT", ctx, b"hello");
    let ExtractOutcome::Extracted {
        canonical,
        coverage,
        ..
    } = out
    else {
        panic!("expected extracted");
    };

    assert!(!coverage.has_unknown());
    assert_eq!(coverage.content_text, CoverageStatus::Full);
    assert_eq!(coverage.structured_fields, CoverageStatus::None);
    assert_eq!(coverage.metadata, CoverageStatus::Full);
    assert_eq!(coverage.embedded_objects, CoverageStatus::None);
    assert_eq!(coverage.attachments, CoverageStatus::None);

    let CanonicalArtifact::Text(t) = canonical else {
        panic!("expected canonical text");
    };
    assert_eq!(t.as_str(), "hello");
}

#[test]
fn text_non_utf8_quarantines() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let out = reg.extract_by_type("TEXT", ctx, &[0xff]);
    let ExtractOutcome::Quarantined { reason, .. } = out else {
        panic!("expected quarantined");
    };
    assert_eq!(reason, QuarantineReasonCode::ParseError);
}

#[test]
fn csv_extracts_headers_and_records() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let out = reg.extract_by_type("CSV", ctx, b"a,b\n1,2\n");
    let ExtractOutcome::Extracted {
        canonical,
        coverage,
        ..
    } = out
    else {
        panic!("expected extracted");
    };
    assert!(!coverage.has_unknown());
    assert_eq!(coverage.content_text, CoverageStatus::None);
    assert_eq!(coverage.structured_fields, CoverageStatus::Full);

    let CanonicalArtifact::Csv(c) = canonical else {
        panic!("expected canonical csv");
    };
    assert_eq!(c.delimiter, b',');
    assert_eq!(c.headers, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(c.records, vec![vec!["1".to_string(), "2".to_string()]]);
}

#[test]
fn tsv_extracts_headers_and_records() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let out = reg.extract_by_type("TSV", ctx, b"a\tb\n1\t2\n");
    let ExtractOutcome::Extracted {
        canonical,
        coverage,
        ..
    } = out
    else {
        panic!("expected extracted");
    };
    assert!(!coverage.has_unknown());
    assert_eq!(coverage.content_text, CoverageStatus::None);
    assert_eq!(coverage.structured_fields, CoverageStatus::Full);

    let CanonicalArtifact::Csv(c) = canonical else {
        panic!("expected canonical csv");
    };
    assert_eq!(c.delimiter, b'\t');
    assert_eq!(c.headers, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(c.records, vec![vec!["1".to_string(), "2".to_string()]]);
}

#[test]
fn json_is_canonicalized() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let out = reg.extract_by_type("JSON", ctx, br#"{"b":2,"a":1}"#);
    let ExtractOutcome::Extracted { canonical, .. } = out else {
        panic!("expected extracted");
    };
    let CanonicalArtifact::Json(j) = canonical else {
        panic!("expected canonical json");
    };

    let s = serde_json::to_string(&j.value).expect("serialize");
    assert_eq!(s, r#"{"a":1,"b":2}"#);
}

#[test]
fn ndjson_is_canonicalized_per_record() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let out = reg.extract_by_type("NDJSON", ctx, b"{\"b\":2,\"a\":1}\n{\"z\":0,\"y\":1}\n");
    let ExtractOutcome::Extracted { canonical, .. } = out else {
        panic!("expected extracted");
    };
    let CanonicalArtifact::Ndjson(n) = canonical else {
        panic!("expected canonical ndjson");
    };

    let s0 = serde_json::to_string(&n.values[0]).expect("serialize");
    let s1 = serde_json::to_string(&n.values[1]).expect("serialize");
    assert_eq!(s0, r#"{"a":1,"b":2}"#);
    assert_eq!(s1, r#"{"y":1,"z":0}"#);
}

#[test]
fn unsupported_type_quarantines() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let out = reg.extract_by_type("FILE", ctx, b"raw");
    let ExtractOutcome::Quarantined { reason, .. } = out else {
        panic!("expected quarantined");
    };
    assert_eq!(reason, QuarantineReasonCode::UnsupportedFormat);
}

#[test]
fn pdf_searchable_extracts_to_ndjson() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let pdf_bytes = make_pdf_with_text("SECRET");
    let out = reg.extract_by_type("PDF", ctx, &pdf_bytes);
    let ExtractOutcome::Extracted {
        canonical,
        coverage,
        ..
    } = out
    else {
        panic!("expected extracted");
    };

    assert!(!coverage.has_unknown());
    assert_eq!(coverage.content_text, CoverageStatus::Full);

    let CanonicalArtifact::Ndjson(n) = canonical else {
        panic!("expected canonical ndjson");
    };
    assert!(!n.values.is_empty());
    let line = serde_json::to_string(&n.values[0]).expect("serialize");
    assert!(line.contains("\"schema_version\":\"veil.pdf.ndjson.v1\""));
    assert!(line.contains("\"surface\":\"text_layer\""));
    assert!(line.contains("SECRET"));
}

#[test]
fn pdf_graphics_only_quarantines_ocr_required() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let pdf_bytes = make_pdf_with_graphics_only();
    let out = reg.extract_by_type("PDF", ctx, &pdf_bytes);
    let ExtractOutcome::Quarantined { reason, .. } = out else {
        panic!("expected quarantined");
    };
    assert_eq!(reason, QuarantineReasonCode::PdfOcrRequiredButDisabled);
}

#[test]
fn pdf_malformed_quarantines_parse_error() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let out = reg.extract_by_type("PDF", ctx, b"not-a-pdf");
    let ExtractOutcome::Quarantined { reason, .. } = out else {
        panic!("expected quarantined");
    };
    assert_eq!(reason, QuarantineReasonCode::PdfParseError);
}

#[test]
fn pdf_graphics_only_with_enabled_ocr_extracts_ndjson() {
    let tmp = TestDir::new("pdf_ocr_success");
    let script = tmp.join("ocr_success.py");
    write_ocr_script(
        &script,
        "import os, sys\n_ = sys.stdin.buffer.read()\nif os.environ.get('VEIL_PDF_OCR_PAGE_INDEX') == '0':\n    sys.stdout.write('SCANNED_SECRET')\n",
    );

    let reg = ExtractorRegistry::with_pdf_options(ArchiveLimits::default(), ocr_options(&script));
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let pdf_bytes = make_pdf_with_graphics_only();
    let out = reg.extract_by_type("PDF", ctx, &pdf_bytes);
    let ExtractOutcome::Extracted { canonical, .. } = out else {
        panic!("expected extracted");
    };
    let CanonicalArtifact::Ndjson(n) = canonical else {
        panic!("expected canonical ndjson");
    };
    assert!(!n.values.is_empty());
    let line = serde_json::to_string(&n.values[0]).expect("serialize");
    assert!(line.contains("\"surface\":\"ocr\""));
    assert!(line.contains("SCANNED_SECRET"));
}

#[test]
fn pdf_graphics_only_with_enabled_ocr_quarantines_when_command_fails() {
    let tmp = TestDir::new("pdf_ocr_failure");
    let script = tmp.join("ocr_fail.py");
    write_ocr_script(
        &script,
        "import sys\n_ = sys.stdin.buffer.read()\nsys.exit(9)\n",
    );

    let reg = ExtractorRegistry::with_pdf_options(ArchiveLimits::default(), ocr_options(&script));
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let pdf_bytes = make_pdf_with_graphics_only();
    let out = reg.extract_by_type("PDF", ctx, &pdf_bytes);
    let ExtractOutcome::Quarantined { reason, .. } = out else {
        panic!("expected quarantined");
    };
    assert_eq!(reason, QuarantineReasonCode::PdfOcrFailed);
}

#[test]
fn pdf_with_open_action_quarantines_actions_present() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let pdf_bytes = make_pdf_with_open_action();
    let out = reg.extract_by_type("PDF", ctx, &pdf_bytes);
    let ExtractOutcome::Quarantined { reason, .. } = out else {
        panic!("expected quarantined");
    };
    assert_eq!(reason, QuarantineReasonCode::PdfActionsPresentUnsupported);
}
