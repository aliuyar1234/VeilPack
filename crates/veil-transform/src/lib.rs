use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use veil_detect::{
    StructuredSelector, class_applies, collect_match_spans, csv_selected_columns,
    json_pointer_escape, json_pointer_matches_class, json_pointer_selection,
};
use veil_domain::QuarantineReasonCode;
use veil_extract::{CanonicalArtifact, CanonicalCsv, canonicalize_json_value};
use veil_policy::{Action, Policy};

#[derive(Debug, Clone)]
pub enum TransformOutcome {
    Transformed { sanitized_bytes: Vec<u8> },
    Quarantined { reason: QuarantineReasonCode },
}

pub trait Transformer {
    fn transform(&self, policy: &Policy, canonical: &CanonicalArtifact) -> TransformOutcome;
}

#[derive(Debug, Default)]
pub struct TransformerV1;

impl Transformer for TransformerV1 {
    fn transform(&self, policy: &Policy, canonical: &CanonicalArtifact) -> TransformOutcome {
        match canonical {
            CanonicalArtifact::Text(t) => TransformOutcome::Transformed {
                sanitized_bytes: transform_string_value(policy, None, t.as_str()).into_bytes(),
            },
            CanonicalArtifact::Csv(c) => transform_csv(policy, c),
            CanonicalArtifact::Json(j) => transform_json(policy, &j.value),
            CanonicalArtifact::Ndjson(n) => transform_ndjson(policy, &n.values),
        }
    }
}

fn transform_csv(policy: &Policy, c: &CanonicalCsv) -> TransformOutcome {
    let selected_cols_by_class = csv_selected_columns(policy, c);

    let mut headers = c.headers.clone();
    for (col_idx, header) in headers.iter_mut().enumerate() {
        let transformed = transform_string_value(
            policy,
            Some(StructuredSelector::CsvColumn(
                col_idx as u32,
                &selected_cols_by_class,
            )),
            header,
        );
        *header = transformed;
    }

    let mut records = c.records.clone();
    for row in records.iter_mut() {
        for (col_idx, cell) in row.iter_mut().enumerate() {
            let transformed = transform_string_value(
                policy,
                Some(StructuredSelector::CsvColumn(
                    col_idx as u32,
                    &selected_cols_by_class,
                )),
                cell,
            );
            *cell = transformed;
        }
    }

    let mut writer = csv::WriterBuilder::new()
        .delimiter(c.delimiter)
        .terminator(csv::Terminator::Any(b'\n'))
        .from_writer(Vec::<u8>::new());

    if writer.write_record(headers.iter()).is_err() {
        return TransformOutcome::Quarantined {
            reason: QuarantineReasonCode::InternalError,
        };
    }
    for row in records.iter() {
        if writer.write_record(row.iter()).is_err() {
            return TransformOutcome::Quarantined {
                reason: QuarantineReasonCode::InternalError,
            };
        }
    }
    if writer.flush().is_err() {
        return TransformOutcome::Quarantined {
            reason: QuarantineReasonCode::InternalError,
        };
    }

    let out = match writer.into_inner() {
        Ok(v) => v,
        Err(_) => {
            return TransformOutcome::Quarantined {
                reason: QuarantineReasonCode::InternalError,
            };
        }
    };

    TransformOutcome::Transformed {
        sanitized_bytes: out,
    }
}

fn transform_json(policy: &Policy, value: &Value) -> TransformOutcome {
    let selected_by_class = json_pointer_selection(policy);
    let mut pointer = String::new();

    let mut out_value = value.clone();
    if transform_json_value(policy, &selected_by_class, &mut pointer, &mut out_value).is_err() {
        return TransformOutcome::Quarantined {
            reason: QuarantineReasonCode::InternalError,
        };
    }
    canonicalize_json_value(&mut out_value);

    let Ok(sanitized_bytes) = serde_json::to_vec(&out_value) else {
        return TransformOutcome::Quarantined {
            reason: QuarantineReasonCode::InternalError,
        };
    };

    TransformOutcome::Transformed { sanitized_bytes }
}

fn transform_ndjson(policy: &Policy, values: &[Value]) -> TransformOutcome {
    let selected_by_class = json_pointer_selection(policy);

    let mut out = String::new();
    for v in values.iter() {
        let mut pointer = String::new();
        let mut vv = v.clone();
        if transform_json_value(policy, &selected_by_class, &mut pointer, &mut vv).is_err() {
            return TransformOutcome::Quarantined {
                reason: QuarantineReasonCode::InternalError,
            };
        }
        canonicalize_json_value(&mut vv);
        let line = match serde_json::to_string(&vv) {
            Ok(s) => s,
            Err(_) => {
                return TransformOutcome::Quarantined {
                    reason: QuarantineReasonCode::InternalError,
                };
            }
        };
        out.push_str(&line);
        out.push('\n');
    }

    TransformOutcome::Transformed {
        sanitized_bytes: out.into_bytes(),
    }
}

fn transform_string_value(
    policy: &Policy,
    selector: Option<StructuredSelector<'_>>,
    s: &str,
) -> String {
    let mut out = s.to_string();

    for class in policy.classes.iter() {
        if !class_applies(selector, class) {
            continue;
        }

        let spans = collect_match_spans(class, &out);
        if spans.is_empty() {
            continue;
        }
        out = apply_action(&out, &class.action, &class.class_id, &spans);
    }

    out
}

fn transform_json_value(
    policy: &Policy,
    selected_by_class: &BTreeMap<String, BTreeSet<String>>,
    pointer: &mut String,
    value: &mut Value,
) -> Result<(), ()> {
    match value {
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();

            for (k, mut v) in std::mem::take(map) {
                let escaped = json_pointer_escape(&k);
                let old_len = pointer.len();
                pointer.push('/');
                pointer.push_str(&escaped);

                transform_json_value(policy, selected_by_class, pointer, &mut v)?;
                // v1 keeps JSON object keys stable so selector semantics remain
                // identical across detect, transform, and residual verify.
                new_map.insert(k, v);
                pointer.truncate(old_len);
            }

            *map = new_map;
            Ok(())
        }
        Value::Array(items) => {
            for (idx, item) in items.iter_mut().enumerate() {
                let old_len = pointer.len();
                pointer.push('/');
                pointer.push_str(&idx.to_string());
                transform_json_value(policy, selected_by_class, pointer, item)?;
                pointer.truncate(old_len);
            }
            Ok(())
        }
        Value::String(s) => {
            let mut out = s.clone();
            for class in policy.classes.iter() {
                if !json_pointer_matches_class(class, selected_by_class, pointer) {
                    continue;
                }
                let spans = collect_match_spans(class, &out);
                if spans.is_empty() {
                    continue;
                }
                out = apply_action(&out, &class.action, &class.class_id, &spans);
            }
            *s = out;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn apply_action(s: &str, action: &Action, class_id: &str, spans: &[(usize, usize)]) -> String {
    let mut out = s.to_string();

    for &(start, end) in spans.iter().rev() {
        let replacement = match action {
            Action::Redact => format!("{{{{{class_id}}}}}"),
            Action::Mask { keep_last } => {
                let keep_last = usize::try_from(*keep_last).unwrap_or(0);
                let matched = &out[start..end];
                mask_keep_last(matched, keep_last)
            }
            Action::Drop => String::new(),
        };

        out.replace_range(start..end, &replacement);
    }

    out
}

fn mask_keep_last(s: &str, keep_last: usize) -> String {
    let chars = s.chars().collect::<Vec<_>>();
    if keep_last == 0 || chars.len() <= keep_last {
        return s.to_string();
    }

    let mut out = String::new();
    out.extend(std::iter::repeat_n('*', chars.len() - keep_last));
    for ch in chars.iter().skip(chars.len() - keep_last) {
        out.push(*ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_domain::{Digest32, PolicyId, Severity};
    use veil_policy::{CompiledDetector, FieldSelector, FieldSelectorKind, Policy, PolicyClass};

    fn dummy_policy_id() -> PolicyId {
        PolicyId::from_digest(Digest32::from_bytes([9_u8; 32]))
    }

    #[test]
    fn transform_json_keeps_keys_stable() {
        let policy = Policy {
            policy_id: dummy_policy_id(),
            classes: vec![PolicyClass {
                class_id: "PII.Test".to_string(),
                severity: Severity::High,
                detectors: vec![CompiledDetector::Regex(
                    regex::Regex::new("SECRET7?").unwrap(),
                )],
                action: Action::Mask { keep_last: 6 },
                field_selector: Some(FieldSelector {
                    kind: FieldSelectorKind::JsonPointer,
                    fields: vec!["/SECRET7".to_string()],
                }),
            }],
        };

        let canonical = CanonicalArtifact::Json(veil_extract::CanonicalJson {
            value: serde_json::json!({ "SECRET7": "SECRET" }),
        });

        let out = TransformerV1.transform(&policy, &canonical);
        let TransformOutcome::Transformed { sanitized_bytes } = out else {
            panic!("expected transformed output");
        };
        let json: serde_json::Value =
            serde_json::from_slice(&sanitized_bytes).expect("parse sanitized json");
        let obj = json.as_object().expect("json object");
        assert!(obj.contains_key("SECRET7"));
    }
}
