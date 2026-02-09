use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use veil_detect::{csv_selected_columns, find_luhn_candidate_spans, json_pointer_selection};
use veil_domain::QuarantineReasonCode;
use veil_extract::{CanonicalArtifact, CanonicalCsv};
use veil_policy::{Action, CompiledDetector, FieldSelectorKind, Policy, PolicyClass};

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

#[derive(Clone, Copy)]
enum StructuredSelector<'a> {
    CsvColumn(u32, &'a BTreeMap<String, Vec<u32>>),
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

fn class_applies(selector: Option<StructuredSelector<'_>>, class: &PolicyClass) -> bool {
    let Some(selector) = selector else {
        return true;
    };

    let Some(sel) = &class.field_selector else {
        return true;
    };

    match (sel.kind, selector) {
        (FieldSelectorKind::CsvHeader, StructuredSelector::CsvColumn(col_idx, by_class)) => {
            by_class
                .get(&class.class_id)
                .map(|cols| cols.contains(&col_idx))
                .unwrap_or(false)
        }
        _ => true,
    }
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
            let mut used_keys = BTreeSet::<String>::new();

            for (k, mut v) in std::mem::take(map) {
                let escaped = json_pointer_escape(&k);
                let old_len = pointer.len();
                pointer.push('/');
                pointer.push_str(&escaped);

                let mut new_key = k.clone();
                for class in policy.classes.iter() {
                    if let Some(set) = selected_by_class.get(&class.class_id)
                        && !set.contains(pointer)
                    {
                        continue;
                    }
                    let spans = collect_match_spans(class, &new_key);
                    if spans.is_empty() {
                        continue;
                    }
                    new_key = apply_action(&new_key, &class.action, &class.class_id, &spans);
                }

                // Ensure keys remain unique deterministically.
                if !used_keys.insert(new_key.clone()) {
                    let base = new_key.clone();
                    let mut n = 1_u32;
                    loop {
                        let candidate = format!("{base}__dup{n}");
                        if used_keys.insert(candidate.clone()) {
                            new_key = candidate;
                            break;
                        }
                        n += 1;
                        if n > 10_000 {
                            return Err(());
                        }
                    }
                }

                transform_json_value(policy, selected_by_class, pointer, &mut v)?;
                new_map.insert(new_key, v);
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
                if let Some(set) = selected_by_class.get(&class.class_id)
                    && !set.contains(pointer)
                {
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

fn collect_match_spans(class: &PolicyClass, s: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::<(usize, usize)>::new();
    for det in class.detectors.iter() {
        match det {
            CompiledDetector::Regex(re) => {
                for m in re.find_iter(s) {
                    spans.push((m.start(), m.end()));
                }
            }
            CompiledDetector::ChecksumLuhn => spans.extend(find_luhn_candidate_spans(s)),
        }
    }

    spans.sort();
    spans = merge_spans(spans);
    spans
}

fn merge_spans(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    if spans.is_empty() {
        return spans;
    }
    spans.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut out = Vec::<(usize, usize)>::new();
    let mut cur = spans[0];
    for (s, e) in spans.into_iter().skip(1) {
        if s <= cur.1 {
            cur.1 = cur.1.max(e);
        } else {
            out.push(cur);
            cur = (s, e);
        }
    }
    out.push(cur);
    out
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

fn canonicalize_json_value(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let mut old = std::mem::take(map);
            let mut keys = old.keys().cloned().collect::<Vec<_>>();
            keys.sort();

            let mut out = serde_json::Map::new();
            for k in keys {
                let mut vv = old.remove(&k).expect("key must exist");
                canonicalize_json_value(&mut vv);
                out.insert(k, vv);
            }
            *map = out;
        }
        Value::Array(items) => {
            for item in items {
                canonicalize_json_value(item);
            }
        }
        _ => {}
    }
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
