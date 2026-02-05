use veil_domain::{CoverageStatus, QuarantineReasonCode, hash_artifact_id, hash_source_locator_hash};
use veil_extract::{ArtifactContext, CanonicalArtifact, ExtractOutcome, ExtractorRegistry};

fn ctx() -> (veil_domain::ArtifactId, veil_domain::SourceLocatorHash) {
    let artifact_id = hash_artifact_id(b"test");
    let source_locator_hash = hash_source_locator_hash("test.txt");
    (artifact_id, source_locator_hash)
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
        canonical, coverage, ..
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
        canonical, coverage, ..
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
        canonical, coverage, ..
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
