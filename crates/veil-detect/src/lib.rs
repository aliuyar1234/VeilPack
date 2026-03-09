use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use serde_json::Value;
use veil_domain::{Digest32, Severity};
use veil_extract::{
    CanonicalArtifact, CanonicalCsv, CanonicalJson, CanonicalNdjson, CanonicalText,
};
use veil_policy::{CompiledDetector, Policy, PolicyClass};

mod matching;

pub use matching::{
    StructuredSelector, class_applies, collect_match_spans, csv_selected_columns,
    find_luhn_candidate_spans, json_pointer_escape, json_pointer_matches_class,
    json_pointer_selection,
};

const PROOF_TOKEN_DOMAIN: &[u8] = b"veil.proof.v1";

#[derive(Debug, Clone)]
pub struct Finding {
    pub class_id: String,
    pub severity: Severity,
    pub location: FindingLocation,
    pub proof_token: Option<String>,
}

#[derive(Debug, Clone)]
pub enum FindingLocation {
    Opaque { locator: String },
}

pub trait DetectorEngine {
    fn detect(
        &self,
        policy: &Policy,
        canonical: &CanonicalArtifact,
        proof_key: Option<&[u8; 32]>,
    ) -> Vec<Finding>;
}

#[derive(Debug, Default)]
pub struct DetectorEngineV1;

impl DetectorEngine for DetectorEngineV1 {
    fn detect(
        &self,
        policy: &Policy,
        canonical: &CanonicalArtifact,
        proof_key: Option<&[u8; 32]>,
    ) -> Vec<Finding> {
        match canonical {
            CanonicalArtifact::Text(t) => detect_text(policy, t, proof_key),
            CanonicalArtifact::Csv(c) => detect_csv(policy, c, proof_key),
            CanonicalArtifact::Json(j) => detect_json(policy, j, proof_key),
            CanonicalArtifact::Ndjson(n) => detect_ndjson(policy, n, proof_key),
        }
    }
}

fn detect_text(policy: &Policy, t: &CanonicalText, proof_key: Option<&[u8; 32]>) -> Vec<Finding> {
    let mut out = Vec::new();
    let text = t.as_str();
    for class in policy.classes.iter() {
        detect_in_str(
            class,
            text,
            &format!("text:{}", class.class_id),
            proof_key,
            &mut out,
        );
    }
    out
}

fn detect_csv(policy: &Policy, c: &CanonicalCsv, proof_key: Option<&[u8; 32]>) -> Vec<Finding> {
    let mut out = Vec::new();
    let selected_cols_by_class = csv_selected_columns(policy, c);

    for (col_idx, header) in c.headers.iter().enumerate() {
        for class in policy.classes.iter() {
            if !class_applies(
                Some(StructuredSelector::CsvColumn(
                    col_idx as u32,
                    &selected_cols_by_class,
                )),
                class,
            ) {
                continue;
            }

            detect_in_str(
                class,
                header,
                &format!("csv:header:c{col_idx}:{}", class.class_id),
                proof_key,
                &mut out,
            );
        }
    }

    for (row_idx, row) in c.records.iter().enumerate() {
        for class in policy.classes.iter() {
            for (col_idx, cell) in row.iter().enumerate() {
                if !class_applies(
                    Some(StructuredSelector::CsvColumn(
                        col_idx as u32,
                        &selected_cols_by_class,
                    )),
                    class,
                ) {
                    continue;
                }

                detect_in_str(
                    class,
                    cell,
                    &format!("csv:r{row_idx}:c{col_idx}:{}", class.class_id),
                    proof_key,
                    &mut out,
                );
            }
        }
    }

    out
}

fn detect_json(policy: &Policy, j: &CanonicalJson, proof_key: Option<&[u8; 32]>) -> Vec<Finding> {
    let mut out = Vec::new();
    let selected_by_class = json_pointer_selection(policy);

    let mut pointer = String::new();
    walk_json(
        "json",
        policy,
        &selected_by_class,
        &mut pointer,
        &j.value,
        proof_key,
        &mut out,
    );
    out
}

fn walk_json(
    kind: &str,
    policy: &Policy,
    selected_by_class: &BTreeMap<String, BTreeSet<String>>,
    pointer: &mut String,
    value: &Value,
    proof_key: Option<&[u8; 32]>,
    out: &mut Vec<Finding>,
) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter() {
                // Always scan keys. v1 keeps JSON object keys stable through transform,
                // so residual verification can evaluate the same key paths.
                let escaped = json_pointer_escape(k);
                let mut key_pointer = String::with_capacity(pointer.len() + escaped.len() + 1);
                key_pointer.push_str(pointer);
                key_pointer.push('/');
                key_pointer.push_str(&escaped);
                for class in policy.classes.iter() {
                    if !json_pointer_matches_class(class, selected_by_class, &key_pointer) {
                        continue;
                    }
                    detect_in_str(
                        class,
                        k,
                        &format!(
                            "{kind}:key:pathhash:{}:{}",
                            hash_locator(&key_pointer),
                            class.class_id
                        ),
                        proof_key,
                        out,
                    );
                }

                let old_len = pointer.len();
                pointer.push('/');
                pointer.push_str(&escaped);

                walk_json(kind, policy, selected_by_class, pointer, v, proof_key, out);
                pointer.truncate(old_len);
            }
        }
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                let old_len = pointer.len();
                pointer.push('/');
                pointer.push_str(&idx.to_string());
                walk_json(
                    kind,
                    policy,
                    selected_by_class,
                    pointer,
                    item,
                    proof_key,
                    out,
                );
                pointer.truncate(old_len);
            }
        }
        Value::String(s) => {
            for class in policy.classes.iter() {
                if !json_pointer_matches_class(class, selected_by_class, pointer) {
                    continue;
                }

                detect_in_str(
                    class,
                    s,
                    &format!(
                        "{kind}:pathhash:{}:{}",
                        hash_locator(pointer),
                        class.class_id
                    ),
                    proof_key,
                    out,
                );
            }
        }
        _ => {}
    }
}

fn detect_ndjson(
    policy: &Policy,
    n: &CanonicalNdjson,
    proof_key: Option<&[u8; 32]>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let selected_by_class = json_pointer_selection(policy);

    for (idx, v) in n.values.iter().enumerate() {
        let mut pointer = String::new();
        let kind = format!("ndjson:r{idx}");
        walk_json(
            &kind,
            policy,
            &selected_by_class,
            &mut pointer,
            v,
            proof_key,
            &mut out,
        );
    }

    out
}

fn detect_in_str(
    class: &PolicyClass,
    s: &str,
    base: &str,
    proof_key: Option<&[u8; 32]>,
    out: &mut Vec<Finding>,
) {
    for det in class.detectors.iter() {
        match det {
            CompiledDetector::Regex(re) => {
                for m in re.find_iter(s) {
                    let proof_token =
                        proof_key.map(|k| compute_proof_token(k, m.as_str().as_bytes()));
                    out.push(Finding {
                        class_id: class.class_id.clone(),
                        severity: class.severity,
                        location: FindingLocation::Opaque {
                            locator: format!("{base}:b{}:{}", m.start(), m.end()),
                        },
                        proof_token,
                    });
                }
            }
            CompiledDetector::ChecksumLuhn => {
                for (start, end) in find_luhn_candidate_spans(s) {
                    let digits = digits_only(&s[start..end]);
                    let proof_token = proof_key.map(|k| compute_proof_token(k, &digits));
                    out.push(Finding {
                        class_id: class.class_id.clone(),
                        severity: class.severity,
                        location: FindingLocation::Opaque {
                            locator: format!("{base}:b{start}:{end}"),
                        },
                        proof_token,
                    });
                }
            }
        }
    }
}

fn digits_only(span: &str) -> Vec<u8> {
    span.as_bytes()
        .iter()
        .copied()
        .filter(|b| b.is_ascii_digit())
        .collect::<Vec<_>>()
}

fn compute_proof_token(key: &[u8; 32], value: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(PROOF_TOKEN_DOMAIN);
    hasher.update(value);
    let digest = hasher.finalize();
    let hex = digest.to_hex().to_string();
    hex[..12].to_string()
}

fn hash_locator(locator: &str) -> String {
    let mut h = Hasher::new();
    h.update(locator.as_bytes());
    Digest32::from_bytes(*h.finalize().as_bytes()).to_hex()
}
