use std::io::Cursor;

use veil_domain::{ArchiveLimits, CoverageMapV1, CoverageStatus, QuarantineReasonCode};

use crate::archive::{
    check_archive_totals, normalize_archive_entry_path, read_to_end_bounded, read_zip_index,
};

pub(crate) fn ooxml_coverage_full() -> CoverageMapV1 {
    CoverageMapV1 {
        content_text: CoverageStatus::Full,
        structured_fields: CoverageStatus::None,
        metadata: CoverageStatus::Full,
        embedded_objects: CoverageStatus::None,
        attachments: CoverageStatus::None,
    }
}

pub(crate) fn ooxml_coverage_unknown_embedded() -> CoverageMapV1 {
    CoverageMapV1 {
        content_text: CoverageStatus::Full,
        structured_fields: CoverageStatus::None,
        metadata: CoverageStatus::Full,
        embedded_objects: CoverageStatus::Unknown,
        attachments: CoverageStatus::None,
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

pub(crate) fn extract_ooxml_entries(
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

            i += 1;
            while i < bytes.len() && bytes[i] != b'>' {
                let b = bytes[i];
                if b == b'"' || b == b'\'' {
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
