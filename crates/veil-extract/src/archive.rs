use std::io::{Cursor, Read};

use veil_domain::{ArchiveLimits, CoverageMapV1, CoverageStatus, QuarantineReasonCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NestedArchiveKind {
    Zip,
    Tar,
}

pub(crate) fn classify_nested_archive_path(normalized_path: &str) -> Option<NestedArchiveKind> {
    let lower = normalized_path.to_ascii_lowercase();
    if lower.ends_with(".zip") {
        Some(NestedArchiveKind::Zip)
    } else if lower.ends_with(".tar") {
        Some(NestedArchiveKind::Tar)
    } else {
        None
    }
}

pub(crate) fn normalize_archive_entry_path(raw: &str) -> Option<String> {
    let mut path = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => path.push('/'),
            '\0' => return None,
            _ => path.push(ch),
        }
    }

    if path.starts_with('/') || path.starts_with("//") {
        return None;
    }

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

pub(crate) fn check_archive_totals(
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

pub(crate) fn read_to_end_bounded<R: Read>(
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

pub(crate) fn archive_coverage_full() -> CoverageMapV1 {
    CoverageMapV1 {
        content_text: CoverageStatus::Full,
        structured_fields: CoverageStatus::None,
        metadata: CoverageStatus::Full,
        embedded_objects: CoverageStatus::None,
        attachments: CoverageStatus::Full,
    }
}

pub(crate) fn read_zip_index<'a>(
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

pub(crate) fn extract_zip_entries(
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
            if file_type == 0o120000 {
                return Err(QuarantineReasonCode::UnsafePath);
            }
        }

        let normalized_path =
            normalize_archive_entry_path(file.name()).ok_or(QuarantineReasonCode::UnsafePath)?;
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

pub(crate) fn extract_tar_entries(
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

    check_archive_totals(
        limits,
        total_entries,
        total_expanded_bytes,
        total_expanded_bytes,
    )?;

    extracted.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(extracted.into_iter().map(|(_, v)| v).collect())
}
