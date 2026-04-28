// Shared NDJSON reader for Veil evidence files.
//
// Deduplicates the two near-identical NDJSON loops that previously lived in
// the CLI: one in `pack_verifier.rs` (artifacts.ndjson reconciliation) and
// one in `evidence_io.rs` (proof-token recovery during resume). Both call
// sites now route through `NdjsonReader` so that BOM handling, blank-line
// skipping, and error propagation are consistent and only have to be tested
// in one place.

use std::io::BufRead;

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// One non-blank line lifted from an NDJSON stream.
///
/// `raw` has any trailing `\n`/`\r\n` stripped, but keeps the rest of the
/// content verbatim so callers can hand it to `serde_json::from_str` (or any
/// other parser) without further trimming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdjsonLine {
    /// 1-indexed line number in the source file (counts blank lines too,
    /// so error messages match what a human would see in an editor).
    pub line_no: u64,
    /// Trimmed line content with no trailing newline.
    pub raw: String,
}

/// Errors that can surface while reading an NDJSON file.
#[derive(Debug, thiserror::Error)]
pub enum NdjsonReadError {
    /// Underlying I/O error; the byte stream is corrupt or unreadable.
    #[error("ndjson io error")]
    Io,
    /// Line bytes were not valid UTF-8.
    #[error("ndjson invalid utf-8 at line {line_no}")]
    InvalidUtf8 { line_no: u64 },
}

/// Iterator over non-blank lines of an NDJSON file.
///
/// * Strips a UTF-8 BOM on the very first line if present.
/// * Skips lines that are empty or whitespace-only (matching the legacy CLI
///   loops). Skipped blank lines still increment the internal line counter
///   so reported `line_no` values match a text editor.
/// * Handles both `\n` and `\r\n` line endings transparently.
pub struct NdjsonReader<R> {
    reader: R,
    line_no: u64,
    saw_first_line: bool,
}

impl<R: BufRead> NdjsonReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            line_no: 0,
            saw_first_line: false,
        }
    }
}

impl<R: BufRead> Iterator for NdjsonReader<R> {
    type Item = Result<NdjsonLine, NdjsonReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut buf = Vec::<u8>::new();
            let read = match self.reader.read_until(b'\n', &mut buf) {
                Ok(n) => n,
                Err(_) => return Some(Err(NdjsonReadError::Io)),
            };
            if read == 0 {
                return None;
            }
            self.line_no = self.line_no.saturating_add(1);

            // Trim trailing newline / carriage return from whatever the
            // platform handed us.
            if buf.last() == Some(&b'\n') {
                buf.pop();
            }
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }

            // Strip the UTF-8 BOM only on the first line. NDJSON producers
            // shouldn't emit one, but our writers historically didn't, so
            // we keep this lenient on read.
            if !self.saw_first_line {
                self.saw_first_line = true;
                if buf.starts_with(&UTF8_BOM) {
                    buf.drain(0..UTF8_BOM.len());
                }
            }

            let raw = match String::from_utf8(buf) {
                Ok(s) => s,
                Err(_) => {
                    return Some(Err(NdjsonReadError::InvalidUtf8 {
                        line_no: self.line_no,
                    }));
                }
            };

            if raw.trim().is_empty() {
                continue;
            }

            return Some(Ok(NdjsonLine {
                line_no: self.line_no,
                raw,
            }));
        }
    }
}

/// Convenience helper: parse every record into `T` via `serde_json`.
///
/// Returns the first deserialization or read error wrapped in
/// [`NdjsonReadError::Io`] for parse failures (callers are expected to log
/// "invalid NDJSON" with their own message — they don't surface
/// `serde_json` errors directly).
pub fn read_ndjson_records<T: serde::de::DeserializeOwned, R: BufRead>(
    reader: R,
) -> Result<Vec<T>, NdjsonReadError> {
    let mut out = Vec::new();
    for entry in NdjsonReader::new(reader) {
        let line = entry?;
        let value: T =
            serde_json::from_str(&line.raw).map_err(|_| NdjsonReadError::InvalidUtf8 {
                line_no: line.line_no,
            })?;
        out.push(value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn iterates_basic_lines() {
        let input = "{\"a\":1}\n{\"b\":2}\n";
        let lines: Vec<_> = NdjsonReader::new(Cursor::new(input))
            .collect::<Result<Vec<_>, _>>()
            .expect("ok");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].line_no, 1);
        assert_eq!(lines[0].raw, "{\"a\":1}");
        assert_eq!(lines[1].line_no, 2);
        assert_eq!(lines[1].raw, "{\"b\":2}");
    }

    #[test]
    fn skips_blank_lines_but_preserves_line_numbers() {
        let input = "{\"a\":1}\n\n   \n{\"b\":2}\n";
        let lines: Vec<_> = NdjsonReader::new(Cursor::new(input))
            .collect::<Result<Vec<_>, _>>()
            .expect("ok");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].line_no, 1);
        assert_eq!(lines[1].line_no, 4);
    }

    #[test]
    fn handles_crlf_line_endings() {
        let input = "{\"a\":1}\r\n{\"b\":2}\r\n";
        let lines: Vec<_> = NdjsonReader::new(Cursor::new(input))
            .collect::<Result<Vec<_>, _>>()
            .expect("ok");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].raw, "{\"a\":1}");
        assert_eq!(lines[1].raw, "{\"b\":2}");
    }

    #[test]
    fn strips_utf8_bom_on_first_line_only() {
        let mut input = Vec::new();
        input.extend_from_slice(&UTF8_BOM);
        input.extend_from_slice(b"{\"a\":1}\n{\"b\":2}\n");
        let lines: Vec<_> = NdjsonReader::new(Cursor::new(input))
            .collect::<Result<Vec<_>, _>>()
            .expect("ok");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].raw, "{\"a\":1}");
        assert_eq!(lines[1].raw, "{\"b\":2}");
    }

    #[test]
    fn last_line_without_newline_is_emitted() {
        let input = "{\"a\":1}";
        let lines: Vec<_> = NdjsonReader::new(Cursor::new(input))
            .collect::<Result<Vec<_>, _>>()
            .expect("ok");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].raw, "{\"a\":1}");
    }

    #[test]
    fn read_ndjson_records_parses_values() {
        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct Row {
            a: u32,
        }
        let input = "{\"a\":1}\n{\"a\":2}\n";
        let rows: Vec<Row> = read_ndjson_records(Cursor::new(input)).expect("parsed");
        assert_eq!(rows, vec![Row { a: 1 }, Row { a: 2 }]);
    }

    #[test]
    fn read_ndjson_records_propagates_parse_error() {
        let input = "{\"a\":1}\nnot json\n";
        let err = read_ndjson_records::<serde_json::Value, _>(Cursor::new(input))
            .expect_err("invalid line should error");
        match err {
            NdjsonReadError::InvalidUtf8 { line_no } => assert_eq!(line_no, 2),
            NdjsonReadError::Io => panic!("unexpected io error"),
        }
    }
}
