use std::collections::{BTreeMap, BTreeSet};

use veil_extract::CanonicalCsv;
use veil_policy::{CompiledDetector, FieldSelectorKind, Policy, PolicyClass};

pub type MatchSpan = (usize, usize);

#[derive(Clone, Copy)]
pub enum StructuredSelector<'a> {
    CsvColumn(u32, &'a BTreeMap<String, Vec<u32>>),
}

pub fn csv_selected_columns(policy: &Policy, c: &CanonicalCsv) -> BTreeMap<String, Vec<u32>> {
    let mut by_class = BTreeMap::<String, Vec<u32>>::new();

    for class in &policy.classes {
        let Some(sel) = &class.field_selector else {
            continue;
        };
        if sel.kind != FieldSelectorKind::CsvHeader {
            continue;
        }

        let mut cols = Vec::<u32>::new();
        for field in &sel.fields {
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

pub fn json_pointer_selection(policy: &Policy) -> BTreeMap<String, BTreeSet<String>> {
    let mut by_class = BTreeMap::<String, BTreeSet<String>>::new();

    for class in &policy.classes {
        let Some(sel) = &class.field_selector else {
            continue;
        };
        if sel.kind != FieldSelectorKind::JsonPointer {
            continue;
        }

        let set = sel.fields.iter().cloned().collect::<BTreeSet<_>>();
        by_class.insert(class.class_id.clone(), set);
    }

    by_class
}

pub fn class_applies(selector: Option<StructuredSelector<'_>>, class: &PolicyClass) -> bool {
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

pub fn json_pointer_matches_class(
    class: &PolicyClass,
    selected_by_class: &BTreeMap<String, BTreeSet<String>>,
    pointer: &str,
) -> bool {
    selected_by_class
        .get(&class.class_id)
        .map(|set| set.contains(pointer))
        .unwrap_or(true)
}

pub fn collect_match_spans(class: &PolicyClass, s: &str) -> Vec<MatchSpan> {
    let mut spans = Vec::<MatchSpan>::new();
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

    merge_spans(spans)
}

pub fn find_luhn_candidate_spans(s: &str) -> Vec<MatchSpan> {
    let bytes = s.as_bytes();
    let mut out = Vec::<MatchSpan>::new();

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
            maybe_push_luhn_candidate(s, start, i, &mut out);
        }
    }

    if let Some(start) = span_start {
        maybe_push_luhn_candidate(s, start, bytes.len(), &mut out);
    }

    out
}

pub fn json_pointer_escape(s: &str) -> String {
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

fn merge_spans(mut spans: Vec<MatchSpan>) -> Vec<MatchSpan> {
    if spans.is_empty() {
        return spans;
    }
    spans.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut out = Vec::<MatchSpan>::new();
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

fn maybe_push_luhn_candidate(s: &str, start: usize, end: usize, out: &mut Vec<MatchSpan>) {
    let raw = &s[start..end];
    let digits = raw
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .collect::<Vec<_>>();
    if digits.len() < 13 || digits.len() > 19 {
        return;
    }
    if !luhn_checksum_ok(&digits) {
        return;
    }
    out.push((start, end));
}

fn luhn_checksum_ok(digits: &[u8]) -> bool {
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
    sum.is_multiple_of(10)
}
