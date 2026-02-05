use veil_detect::{DetectorEngine, DetectorEngineV1};
use veil_domain::{Digest32, PolicyId, Severity};
use veil_extract::{CanonicalArtifact, CanonicalCsv, CanonicalJson, CanonicalText};
use veil_policy::{
    Action, CompiledDetector, FieldSelector, FieldSelectorKind, Policy, PolicyClass,
};

fn dummy_policy_id() -> PolicyId {
    PolicyId::from_digest(Digest32::from_bytes([7_u8; 32]))
}

#[test]
fn luhn_detector_finds_candidate_in_text() {
    let policy = Policy {
        policy_id: dummy_policy_id(),
        classes: vec![PolicyClass {
            class_id: "PCI.Card".to_string(),
            severity: Severity::High,
            detectors: vec![CompiledDetector::ChecksumLuhn],
            action: Action::Redact,
            field_selector: None,
        }],
    };

    let canonical = CanonicalArtifact::Text(CanonicalText::new(
        "card 4111-1111-1111-1111".to_string(),
    ));

    let findings = DetectorEngineV1.detect(&policy, &canonical, None);
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.class_id == "PCI.Card"));
}

#[test]
fn json_pointer_selector_limits_scanning() {
    let policy = Policy {
        policy_id: dummy_policy_id(),
        classes: vec![PolicyClass {
            class_id: "PII.Email".to_string(),
            severity: Severity::High,
            detectors: vec![CompiledDetector::Regex(regex::Regex::new("@").unwrap())],
            action: Action::Redact,
            field_selector: Some(FieldSelector {
                kind: FieldSelectorKind::JsonPointer,
                fields: vec!["/email".to_string()],
            }),
        }],
    };

    let canonical = CanonicalArtifact::Json(CanonicalJson {
        value: serde_json::json!({
            "email": "a@b.com",
            "other": "a@b.com",
        }),
    });

    let findings = DetectorEngineV1.detect(&policy, &canonical, None);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class_id, "PII.Email");
}

#[test]
fn csv_header_selector_limits_scanning() {
    let policy = Policy {
        policy_id: dummy_policy_id(),
        classes: vec![PolicyClass {
            class_id: "PII.Email".to_string(),
            severity: Severity::High,
            detectors: vec![CompiledDetector::Regex(regex::Regex::new("@").unwrap())],
            action: Action::Redact,
            field_selector: Some(FieldSelector {
                kind: FieldSelectorKind::CsvHeader,
                fields: vec!["email".to_string()],
            }),
        }],
    };

    let canonical = CanonicalArtifact::Csv(CanonicalCsv {
        delimiter: b',',
        headers: vec!["email".to_string(), "other".to_string()],
        records: vec![vec!["a@b.com".to_string(), "a@b.com".to_string()]],
    });

    let findings = DetectorEngineV1.detect(&policy, &canonical, None);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class_id, "PII.Email");
}
