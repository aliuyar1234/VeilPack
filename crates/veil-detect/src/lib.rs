use blake3::Hasher;
use serde_json::Value;
use veil_domain::{Digest32, Severity};
use veil_extract::{CanonicalArtifact, CanonicalCsv, CanonicalJson, CanonicalNdjson, CanonicalText};
use veil_policy::{CompiledDetector, FieldSelectorKind, Policy, PolicyClass};

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
    fn detect(&self, policy: &Policy, canonical: &CanonicalArtifact) -> Vec<Finding>;
}

#[derive(Debug, Default)]
pub struct DetectorEngineV1;

impl DetectorEngine for DetectorEngineV1 {
    fn detect(&self, policy: &Policy, canonical: &CanonicalArtifact) -> Vec<Finding> {
        match canonical {
            CanonicalArtifact::Text(t) => detect_text(policy, t),
            CanonicalArtifact::Csv(c) => detect_csv(policy, c),
            CanonicalArtifact::Json(j) => detect_json(policy, j),
            CanonicalArtifact::Ndjson(n) => detect_ndjson(policy, n),
        }
    }
}

fn detect_text(policy: &Policy, t: &CanonicalText) -> Vec<Finding> {
    let mut out = Vec::new();
    let text = t.as_str();
    for class in policy.classes.iter() {
        detect_in_str(
            class,
            text,
            &format!("text:{}", class.class_id),
            &mut out,
        );
    }
    out
}

fn detect_csv(policy: &Policy, c: &CanonicalCsv) -> Vec<Finding> {
    let mut out = Vec::new();
    let selected_cols_by_class = build_csv_selection(policy, c);

    for (col_idx, header) in c.headers.iter().enumerate() {
        for class in policy.classes.iter() {
            let selected = selected_cols_by_class
                .get(&class.class_id)
                .map(|v| v.as_slice());
            if let Some(cols) = selected
                && !cols.contains(&(col_idx as u32))
            {
                continue;
            }

            detect_in_str(
                class,
                header,
                &format!("csv:header:c{col_idx}:{}", class.class_id),
                &mut out,
            );
        }
    }

    for (row_idx, row) in c.records.iter().enumerate() {
        for class in policy.classes.iter() {
            let selected = selected_cols_by_class
                .get(&class.class_id)
                .map(|v| v.as_slice());
            for (col_idx, cell) in row.iter().enumerate() {
                if let Some(cols) = selected
                    && !cols.contains(&(col_idx as u32))
                {
                    continue;
                }

                detect_in_str(
                    class,
                    cell,
                    &format!("csv:r{row_idx}:c{col_idx}:{}", class.class_id),
                    &mut out,
                );
            }
        }
    }

    out
}

fn build_csv_selection(policy: &Policy, c: &CanonicalCsv) -> std::collections::BTreeMap<String, Vec<u32>> {
    let mut by_class = std::collections::BTreeMap::<String, Vec<u32>>::new();

    for class in policy.classes.iter() {
        let Some(sel) = &class.field_selector else {
            continue;
        };
        if sel.kind != FieldSelectorKind::CsvHeader {
            continue;
        }

        let mut cols = Vec::<u32>::new();
        for field in sel.fields.iter() {
            for (idx, header) in c.headers.iter().enumerate() {
                if header == field {
                    cols.push(idx as u32);
                }
            }
        }
        cols.sort();
        cols.dedup();
        by_class.insert(class.class_id.clone(), cols);
    }

    by_class
}

fn detect_json(policy: &Policy, j: &CanonicalJson) -> Vec<Finding> {
    let mut out = Vec::new();
    let selected_by_class = build_json_selection(policy);

    let mut pointer = String::new();
    walk_json(
        "json",
        policy,
        &selected_by_class,
        &mut pointer,
        &j.value,
        &mut out,
    );
    out
}

fn build_json_selection(policy: &Policy) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
    let mut by_class =
        std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();

    for class in policy.classes.iter() {
        let Some(sel) = &class.field_selector else {
            continue;
        };
        if sel.kind != FieldSelectorKind::JsonPointer {
            continue;
        }
        let set = sel.fields.iter().cloned().collect::<std::collections::BTreeSet<_>>();
        by_class.insert(class.class_id.clone(), set);
    }

    by_class
}

fn walk_json(
    kind: &str,
    policy: &Policy,
    selected_by_class: &std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    pointer: &mut String,
    value: &Value,
    out: &mut Vec<Finding>,
) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter() {
                // Always scan keys (fail-closed: transformers do not rewrite keys in v1).
                let escaped = json_pointer_escape(k);
                let mut key_pointer = String::with_capacity(pointer.len() + escaped.len() + 1);
                key_pointer.push_str(pointer);
                key_pointer.push('/');
                key_pointer.push_str(&escaped);
                for class in policy.classes.iter() {
                    if let Some(set) = selected_by_class.get(&class.class_id) {
                        if !set.contains(&key_pointer) {
                            continue;
                        }
                    }
                    detect_in_str(
                        class,
                        k,
                        &format!(
                            "{kind}:key:pathhash:{}:{}",
                            hash_locator(&key_pointer),
                            class.class_id
                        ),
                        out,
                    );
                }

                let old_len = pointer.len();
                pointer.push('/');
                pointer.push_str(&escaped);

                walk_json(kind, policy, selected_by_class, pointer, v, out);
                pointer.truncate(old_len);
            }
        }
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                let old_len = pointer.len();
                pointer.push('/');
                pointer.push_str(&idx.to_string());
                walk_json(kind, policy, selected_by_class, pointer, item, out);
                pointer.truncate(old_len);
            }
        }
        Value::String(s) => {
            for class in policy.classes.iter() {
                if let Some(set) = selected_by_class.get(&class.class_id) {
                    if !set.contains(pointer) {
                        continue;
                    }
                }

                detect_in_str(
                    class,
                    s,
                    &format!(
                        "{kind}:pathhash:{}:{}",
                        hash_locator(pointer),
                        class.class_id
                    ),
                    out,
                );
            }
        }
        _ => {}
    }
}

fn detect_ndjson(policy: &Policy, n: &CanonicalNdjson) -> Vec<Finding> {
    let mut out = Vec::new();
    let selected_by_class = build_json_selection(policy);

    for (idx, v) in n.values.iter().enumerate() {
        let mut pointer = String::new();
        let kind = format!("ndjson:r{idx}");
        walk_json(
            &kind,
            policy,
            &selected_by_class,
            &mut pointer,
            v,
            &mut out,
        );
    }

    out
}

fn detect_in_str(class: &PolicyClass, s: &str, base: &str, out: &mut Vec<Finding>) {
    for det in class.detectors.iter() {
        match det {
            CompiledDetector::Regex(re) => {
                for m in re.find_iter(s) {
                    out.push(Finding {
                        class_id: class.class_id.clone(),
                        severity: class.severity,
                        location: FindingLocation::Opaque {
                            locator: format!("{base}:b{}:{}", m.start(), m.end()),
                        },
                        proof_token: None,
                    });
                }
            }
            CompiledDetector::ChecksumLuhn => {
                for (start, end) in find_luhn_matches(s) {
                    out.push(Finding {
                        class_id: class.class_id.clone(),
                        severity: class.severity,
                        location: FindingLocation::Opaque {
                            locator: format!("{base}:b{start}:{end}"),
                        },
                        proof_token: None,
                    });
                }
            }
        }
    }
}

fn find_luhn_matches(s: &str) -> Vec<(usize, usize)> {
    let bytes = s.as_bytes();
    let mut out = Vec::<(usize, usize)>::new();

    let mut span_start = None::<usize>;
    for (i, b) in bytes.iter().copied().enumerate() {
        let is_candidate = b.is_ascii_digit() || b == b' ' || b == b'-';
        if is_candidate {
            if span_start.is_none() {
                span_start = Some(i);
            }
            continue;
        }

        if let Some(start) = span_start.take() {
            let end = i;
            maybe_push_luhn(s, start, end, &mut out);
        }
    }

    if let Some(start) = span_start {
        maybe_push_luhn(s, start, bytes.len(), &mut out);
    }

    out
}

fn maybe_push_luhn(s: &str, start: usize, end: usize, out: &mut Vec<(usize, usize)>) {
    let raw = &s[start..end];
    let digits = raw
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .collect::<Vec<_>>();
    if digits.len() < 13 || digits.len() > 19 {
        return;
    }
    if !luhn_ok(&digits) {
        return;
    }
    out.push((start, end));
}

fn luhn_ok(digits: &[u8]) -> bool {
    let mut sum = 0_u32;
    let mut double = false;
    for d in digits.iter().rev() {
        let mut v = (d - b'0') as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum % 10 == 0
}

fn json_pointer_escape(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            _ => out.push(ch),
        }
    }
    out
}

fn hash_locator(locator: &str) -> String {
    let mut h = Hasher::new();
    h.update(locator.as_bytes());
    Digest32::from_bytes(*h.finalize().as_bytes()).to_hex()
}
