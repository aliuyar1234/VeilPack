use veil_domain::{ArchiveLimits, CoverageMapV1, CoverageStatus, QuarantineReasonCode};

use crate::archive::{NestedArchiveKind, extract_tar_entries, extract_zip_entries};

pub(crate) fn email_coverage(has_attachments: bool) -> CoverageMapV1 {
    CoverageMapV1 {
        content_text: CoverageStatus::Full,
        structured_fields: CoverageStatus::None,
        metadata: CoverageStatus::Full,
        embedded_objects: CoverageStatus::None,
        attachments: if has_attachments {
            CoverageStatus::Full
        } else {
            CoverageStatus::None
        },
    }
}

fn classify_attachment_archive(
    mimetype: &str,
    disposition_filename: Option<&str>,
) -> Option<NestedArchiveKind> {
    let mimetype = mimetype.to_ascii_lowercase();
    if mimetype == "application/zip" {
        return Some(NestedArchiveKind::Zip);
    }
    if mimetype == "application/x-tar" {
        return Some(NestedArchiveKind::Tar);
    }

    let name = disposition_filename?;
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".zip") {
        Some(NestedArchiveKind::Zip)
    } else if lower.ends_with(".tar") {
        Some(NestedArchiveKind::Tar)
    } else {
        None
    }
}

fn make_email_header_record(
    message_index: Option<u32>,
    header_index: u32,
    key: &str,
    value: &str,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(message_index) = message_index {
        map.insert(
            "message_index".to_string(),
            serde_json::Value::Number(serde_json::Number::from(message_index as u64)),
        );
    }
    map.insert(
        "header_index".to_string(),
        serde_json::Value::Number(serde_json::Number::from(header_index as u64)),
    );
    map.insert(
        "key".to_string(),
        serde_json::Value::String(key.to_string()),
    );
    map.insert(
        "value".to_string(),
        serde_json::Value::String(value.to_string()),
    );
    serde_json::Value::Object(map)
}

fn make_email_body_record(
    message_index: Option<u32>,
    body_index: u32,
    text: &str,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(message_index) = message_index {
        map.insert(
            "message_index".to_string(),
            serde_json::Value::Number(serde_json::Number::from(message_index as u64)),
        );
    }
    map.insert(
        "body_index".to_string(),
        serde_json::Value::Number(serde_json::Number::from(body_index as u64)),
    );
    map.insert(
        "text".to_string(),
        serde_json::Value::String(text.to_string()),
    );
    serde_json::Value::Object(map)
}

fn make_email_attachment_record(
    message_index: Option<u32>,
    attachment_index: u32,
    attachment_locator_hash: &str,
    filename_hash: Option<&str>,
    text: &str,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(message_index) = message_index {
        map.insert(
            "message_index".to_string(),
            serde_json::Value::Number(serde_json::Number::from(message_index as u64)),
        );
    }
    map.insert(
        "attachment_index".to_string(),
        serde_json::Value::Number(serde_json::Number::from(attachment_index as u64)),
    );
    map.insert(
        "attachment_locator_hash".to_string(),
        serde_json::Value::String(attachment_locator_hash.to_string()),
    );
    if let Some(filename_hash) = filename_hash {
        map.insert(
            "filename_hash".to_string(),
            serde_json::Value::String(filename_hash.to_string()),
        );
    }
    map.insert(
        "text".to_string(),
        serde_json::Value::String(text.to_string()),
    );
    serde_json::Value::Object(map)
}

fn synth_locator_hash(parts: &[&str]) -> String {
    let joined = parts.join("/");
    veil_domain::hash_source_locator_hash(&joined).to_string()
}

pub(crate) fn extract_eml_entries(
    limits: ArchiveLimits,
    bytes: &[u8],
) -> Result<(Vec<serde_json::Value>, bool), QuarantineReasonCode> {
    let mail = mailparse::parse_mail(bytes).map_err(|_| QuarantineReasonCode::ParseError)?;

    let mut out = Vec::<serde_json::Value>::new();

    for (idx, h) in mail.headers.iter().enumerate() {
        let idx = u32::try_from(idx).unwrap_or(u32::MAX);
        out.push(make_email_header_record(
            None,
            idx,
            &h.get_key(),
            &h.get_value(),
        ));
    }

    let mut has_attachments = false;
    let mut attachment_index = 0_u32;
    let mut body_index = 0_u32;
    collect_mail_leaf_parts(
        limits,
        &mail,
        None,
        &mut out,
        &mut has_attachments,
        &mut attachment_index,
        &mut body_index,
    )?;

    Ok((out, has_attachments))
}

pub(crate) fn extract_mbox_entries(
    limits: ArchiveLimits,
    bytes: &[u8],
) -> Result<(Vec<serde_json::Value>, bool), QuarantineReasonCode> {
    let messages = split_mbox_messages(bytes)?;

    let mut out = Vec::<serde_json::Value>::new();
    let mut any_attachments = false;

    for (msg_idx, msg_bytes) in messages.iter().enumerate() {
        let msg_idx_u32 = u32::try_from(msg_idx).unwrap_or(u32::MAX);
        let mail =
            mailparse::parse_mail(msg_bytes).map_err(|_| QuarantineReasonCode::ParseError)?;

        for (idx, h) in mail.headers.iter().enumerate() {
            let idx = u32::try_from(idx).unwrap_or(u32::MAX);
            out.push(make_email_header_record(
                Some(msg_idx_u32),
                idx,
                &h.get_key(),
                &h.get_value(),
            ));
        }

        let mut has_attachments = false;
        let mut attachment_index = 0_u32;
        let mut body_index = 0_u32;
        collect_mail_leaf_parts(
            limits,
            &mail,
            Some(msg_idx_u32),
            &mut out,
            &mut has_attachments,
            &mut attachment_index,
            &mut body_index,
        )?;
        if has_attachments {
            any_attachments = true;
        }
    }

    Ok((out, any_attachments))
}

fn collect_mail_leaf_parts(
    limits: ArchiveLimits,
    mail: &mailparse::ParsedMail<'_>,
    message_index: Option<u32>,
    out: &mut Vec<serde_json::Value>,
    has_attachments: &mut bool,
    attachment_index: &mut u32,
    body_index: &mut u32,
) -> Result<(), QuarantineReasonCode> {
    use mailparse::MailHeaderMap;

    if !mail.subparts.is_empty() {
        for sub in mail.subparts.iter() {
            collect_mail_leaf_parts(
                limits,
                sub,
                message_index,
                out,
                has_attachments,
                attachment_index,
                body_index,
            )?;
        }
        return Ok(());
    }

    let disposition = mail
        .headers
        .get_first_value("Content-Disposition")
        .map(|s| mailparse::parse_content_disposition(&s))
        .unwrap_or_default();
    let filename = disposition
        .params
        .get("filename")
        .or_else(|| disposition.params.get("name"))
        .map(|s| s.as_str());

    let mimetype = mail.ctype.mimetype.to_ascii_lowercase();
    let is_text = mimetype.starts_with("text/");

    let is_attachment = matches!(
        disposition.disposition,
        mailparse::DispositionType::Attachment
    ) || filename.is_some()
        || !is_text;

    if is_attachment {
        *has_attachments = true;

        let idx = *attachment_index;
        *attachment_index = attachment_index.saturating_add(1);

        let locator_hash = match message_index {
            Some(m) => synth_locator_hash(&["mbox", &m.to_string(), "attach", &idx.to_string()]),
            None => synth_locator_hash(&["eml", "attach", &idx.to_string()]),
        };

        let filename_hash = filename.map(|f| veil_domain::hash_source_locator_hash(f).to_string());

        let raw = mail
            .get_body_raw()
            .map_err(|_| QuarantineReasonCode::ParseError)?;
        let raw_len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        if raw_len > limits.max_bytes_per_artifact {
            return Err(QuarantineReasonCode::LimitExceeded);
        }

        if let Some(kind) = classify_attachment_archive(&mimetype, filename) {
            let nested = match kind {
                NestedArchiveKind::Zip => {
                    extract_zip_entries(limits, &raw, 1, Some(&locator_hash))?
                }
                NestedArchiveKind::Tar => {
                    extract_tar_entries(limits, &raw, 1, Some(&locator_hash))?
                }
            };
            for mut v in nested {
                if let serde_json::Value::Object(ref mut map) = v {
                    if let Some(message_index) = message_index {
                        map.insert(
                            "message_index".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(
                                message_index as u64,
                            )),
                        );
                    }
                    map.insert(
                        "attachment_index".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(idx as u64)),
                    );
                    map.insert(
                        "attachment_locator_hash".to_string(),
                        serde_json::Value::String(locator_hash.clone()),
                    );
                    if let Some(ref filename_hash) = filename_hash {
                        map.insert(
                            "filename_hash".to_string(),
                            serde_json::Value::String(filename_hash.clone()),
                        );
                    }
                }
                out.push(v);
            }
            return Ok(());
        }

        if !is_text {
            return Err(QuarantineReasonCode::UnsupportedFormat);
        }

        let text = mail
            .get_body()
            .map_err(|_| QuarantineReasonCode::ParseError)?;
        out.push(make_email_attachment_record(
            message_index,
            idx,
            &locator_hash,
            filename_hash.as_deref(),
            &text,
        ));
        return Ok(());
    }

    let idx = *body_index;
    *body_index = body_index.saturating_add(1);
    let text = mail
        .get_body()
        .map_err(|_| QuarantineReasonCode::ParseError)?;
    out.push(make_email_body_record(message_index, idx, &text));
    Ok(())
}

fn split_mbox_messages(bytes: &[u8]) -> Result<Vec<&[u8]>, QuarantineReasonCode> {
    let mut starts = Vec::<usize>::new();
    if bytes.starts_with(b"From ") {
        let first_line_end = bytes
            .iter()
            .position(|b| *b == b'\n')
            .unwrap_or(bytes.len());
        if !is_valid_mbox_separator_line(&bytes[..first_line_end]) {
            return Err(QuarantineReasonCode::ParseError);
        }
        starts.push(0);
    }

    let mut line_start = 0_usize;
    while line_start < bytes.len() {
        let line_end = bytes[line_start..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|rel| line_start + rel)
            .unwrap_or(bytes.len());
        let line = &bytes[line_start..line_end];

        if line_start > 0 && line.starts_with(b"From ") {
            if !is_valid_mbox_separator_line(line) {
                return Err(QuarantineReasonCode::ParseError);
            }
            starts.push(line_start);
        }

        if line_end == bytes.len() {
            break;
        }
        line_start = line_end + 1;
    }

    if starts.is_empty() {
        return Ok(vec![bytes]);
    }

    let mut out = Vec::<&[u8]>::new();
    for (pos_idx, start) in starts.iter().copied().enumerate() {
        let end = starts.get(pos_idx + 1).copied().unwrap_or(bytes.len());
        let slice = &bytes[start..end];

        let mut msg_start = 0;
        while msg_start < slice.len() && slice[msg_start] != b'\n' {
            msg_start += 1;
        }
        if msg_start < slice.len() {
            msg_start += 1;
        }

        if msg_start < slice.len() {
            out.push(&slice[msg_start..]);
        }
    }

    Ok(out)
}

// Strict mbox-O separator validation.
//
// Reference grammar (RFC 4155-style):
//   "From " <addr-spec> " " <day> " " <mon> " " <dd> " " <hh:mm:ss> " " <yyyy>
//
// All separators are exactly one ASCII 0x20 (space). Any tab, NUL, CR, LF, or
// non-ASCII byte in the separator line is rejected. `split_whitespace` and
// similar tolerant tokenizers must NOT be used here: they would silently
// accept tabs and runs of spaces, allowing crafted message bodies that
// contain a "From " line with whitespace anomalies to be misclassified as a
// new message envelope, splitting headers into the previous message.
fn is_valid_mbox_separator_line(line: &[u8]) -> bool {
    // CRLF line endings: drop the trailing \r before validation.
    let line = match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    };

    // Reject any control / non-ASCII byte; tabs and CR are explicitly out.
    if line.iter().any(|b| !(0x20..=0x7e).contains(b)) {
        return false;
    }

    let Ok(text) = std::str::from_utf8(line) else {
        return false;
    };

    // No double-space runs. Any field with empty content fails the parse below.
    if text.contains("  ") {
        return false;
    }

    let mut parts = text.split(' ');
    if parts.next() != Some("From") {
        return false;
    }
    let Some(sender) = parts.next() else {
        return false;
    };
    if sender.is_empty() {
        return false;
    }
    let Some(day_name) = parts.next() else {
        return false;
    };
    let Some(month_name) = parts.next() else {
        return false;
    };
    let Some(day_of_month) = parts.next() else {
        return false;
    };
    let Some(time_of_day) = parts.next() else {
        return false;
    };
    let Some(year) = parts.next() else {
        return false;
    };

    if !matches!(
        day_name,
        "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
    ) {
        return false;
    }
    if !matches!(
        month_name,
        "Jan"
            | "Feb"
            | "Mar"
            | "Apr"
            | "May"
            | "Jun"
            | "Jul"
            | "Aug"
            | "Sep"
            | "Oct"
            | "Nov"
            | "Dec"
    ) {
        return false;
    }
    if day_of_month
        .parse::<u32>()
        .map_or(true, |day| !(1..=31).contains(&day))
    {
        return false;
    }
    if !is_valid_mbox_time(time_of_day) {
        return false;
    }
    if year.len() != 4 || !year.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }

    // After the year, optional timezone offset (e.g. "+0000"). Anything
    // beyond that, including extra whitespace, is rejected.
    match parts.next() {
        None => true,
        Some(tz) => {
            if parts.next().is_some() {
                return false;
            }
            is_valid_mbox_tz(tz)
        }
    }
}

fn is_valid_mbox_tz(tz: &str) -> bool {
    let bytes = tz.as_bytes();
    if bytes.len() != 5 {
        return false;
    }
    if bytes[0] != b'+' && bytes[0] != b'-' {
        return false;
    }
    bytes[1..].iter().all(u8::is_ascii_digit)
}

fn is_valid_mbox_time(value: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    if !(parts.len() == 2 || parts.len() == 3) {
        return false;
    }
    let mut nums = Vec::with_capacity(parts.len());
    for part in &parts {
        if part.len() != 2 || !part.chars().all(|ch| ch.is_ascii_digit()) {
            return false;
        }
        let Ok(n) = part.parse::<u32>() else {
            return false;
        };
        nums.push(n);
    }
    if nums[0] > 23 || nums[1] > 59 {
        return false;
    }
    if nums.len() == 3 && nums[2] > 59 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separator_canonical_form_accepted() {
        assert!(is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 15 12:34:56 2024"
        ));
    }

    #[test]
    fn separator_with_tz_offset_accepted() {
        assert!(is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 15 12:34:56 2024 +0000"
        ));
        assert!(is_valid_mbox_separator_line(
            b"From user@example.com Tue Dec 31 23:59:59 2024 -0700"
        ));
    }

    #[test]
    fn separator_with_crlf_line_ending_accepted() {
        assert!(is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 15 12:34:56 2024\r"
        ));
    }

    #[test]
    fn separator_rejects_tab_between_fields() {
        assert!(!is_valid_mbox_separator_line(
            b"From\tuser@example.com Mon Jan 15 12:34:56 2024"
        ));
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com\tMon Jan 15 12:34:56 2024"
        ));
    }

    #[test]
    fn separator_rejects_double_space() {
        assert!(!is_valid_mbox_separator_line(
            b"From  user@example.com Mon Jan 15 12:34:56 2024"
        ));
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon  Jan 15 12:34:56 2024"
        ));
    }

    #[test]
    fn separator_rejects_non_ascii() {
        assert!(!is_valid_mbox_separator_line(
            "From usér@example.com Mon Jan 15 12:34:56 2024".as_bytes()
        ));
    }

    #[test]
    fn separator_rejects_empty_sender() {
        assert!(!is_valid_mbox_separator_line(
            b"From  Mon Jan 15 12:34:56 2024"
        ));
    }

    #[test]
    fn separator_rejects_invalid_day_or_month() {
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Funday Jan 15 12:34:56 2024"
        ));
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon NotAMonth 15 12:34:56 2024"
        ));
    }

    #[test]
    fn separator_rejects_invalid_day_of_month_or_time() {
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 32 12:34:56 2024"
        ));
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 0 12:34:56 2024"
        ));
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 15 25:00:00 2024"
        ));
    }

    #[test]
    fn separator_rejects_short_or_non_numeric_year() {
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 15 12:34:56 24"
        ));
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 15 12:34:56 abcd"
        ));
    }

    #[test]
    fn separator_rejects_extra_trailing_field() {
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 15 12:34:56 2024 +0000 garbage"
        ));
    }

    #[test]
    fn separator_rejects_malformed_tz() {
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 15 12:34:56 2024 +00"
        ));
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 15 12:34:56 2024 0000"
        ));
        assert!(!is_valid_mbox_separator_line(
            b"From user@example.com Mon Jan 15 12:34:56 2024 +abcd"
        ));
    }
}
