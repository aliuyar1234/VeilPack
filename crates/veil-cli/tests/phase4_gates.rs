use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use serde::Deserialize;
use zip::write::FileOptions;

fn veil_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_veil"))
}

fn minimal_policy_json(detector_pattern: &str) -> String {
    format!(
        r#"{{
  "schema_version": "policy.v1",
  "classes": [
    {{
      "class_id": "PII.Test",
      "severity": "HIGH",
      "detectors": [
        {{
          "kind": "regex",
          "pattern": "{detector_pattern}"
        }}
      ],
      "action": {{
        "kind": "REDACT"
      }}
    }}
  ],
  "defaults": {{}},
  "scopes": []
}}"#
    )
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "veil_cli_test_{}_{}",
            std::process::id(),
            label.replace(['\\', '/', ':'], "_")
        ));

        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");

        Self { path }
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[derive(Debug, Deserialize)]
struct QuarantineIndexRecord {
    source_locator_hash: String,
    reason_code: String,
}

fn read_quarantine_index(pack_root: &Path) -> Vec<QuarantineIndexRecord> {
    let path = pack_root.join("quarantine").join("index.ndjson");
    let text = std::fs::read_to_string(path).expect("read quarantine index");
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line).expect("parse quarantine index line"));
    }
    out
}

fn expected_sanitized_path(
    pack_root: &Path,
    rel: &str,
    artifact_bytes: &[u8],
    ext: &str,
) -> PathBuf {
    let artifact_id = veil_domain::hash_artifact_id(artifact_bytes);
    let source_locator_hash = veil_domain::hash_source_locator_hash(rel);
    let sort_key = veil_domain::ArtifactSortKey::new(artifact_id, source_locator_hash);
    pack_root.join("sanitized").join(format!(
        "{}__{}.{}",
        sort_key.source_locator_hash, sort_key.artifact_id, ext
    ))
}

fn make_zip_bytes(entries: &[(&str, &[u8])], compression: zip::CompressionMethod) -> Vec<u8> {
    let cursor = Cursor::new(Vec::<u8>::new());
    let mut writer = zip::ZipWriter::new(cursor);

    let options = FileOptions::default().compression_method(compression);
    for (name, data) in entries {
        writer.start_file(*name, options).expect("start zip file");
        writer.write_all(data).expect("write zip data");
    }

    let cursor = writer.finish().expect("finish zip");
    cursor.into_inner()
}

fn write_limits_json(dir: &TestDir, json: &str) -> PathBuf {
    let path = dir.join("limits.json");
    std::fs::write(&path, json).expect("write limits.json");
    path
}

fn make_tar_bytes(path: &str, data: &[u8]) -> Vec<u8> {
    // Minimal ustar tar with one regular file entry.
    assert!(path.as_bytes().len() <= 100);

    let mut header = [0_u8; 512];
    header[..path.len()].copy_from_slice(path.as_bytes());

    fn write_octal(dst: &mut [u8], value: u64) {
        let width = dst.len() - 1;
        let s = format!("{value:0width$o}");
        dst[..width].copy_from_slice(s.as_bytes());
        dst[width] = 0;
    }

    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], data.len() as u64);
    write_octal(&mut header[136..148], 0);

    // checksum field treated as spaces for calculation
    for b in &mut header[148..156] {
        *b = b' ';
    }

    header[156] = b'0'; // regular file
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    let checksum: u64 = header.iter().map(|b| *b as u64).sum();
    // 6 digits, NUL, space
    let chk = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(chk.as_bytes());

    let mut out = Vec::<u8>::new();
    out.extend_from_slice(&header);
    out.extend_from_slice(data);

    let pad = (512 - (data.len() % 512)) % 512;
    out.extend(std::iter::repeat(0_u8).take(pad));
    // two zero blocks
    out.extend(std::iter::repeat(0_u8).take(1024));
    out
}

fn make_tar_files(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::<u8>::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder
                .append_data(&mut header, *path, Cursor::new(*data))
                .expect("append tar data");
        }
        builder.finish().expect("finish tar");
    }
    out
}

fn make_tar_symlink(path: &str, target: &str) -> Vec<u8> {
    let mut out = Vec::<u8>::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_cksum();
        builder
            .append_link(&mut header, path, target)
            .expect("append symlink");
        builder.finish().expect("finish tar");
    }
    out
}

#[test]
fn zip_max_entries_limit_quarantines_entire_archive() {
    let input = TestDir::new("zip_entries_input");
    let zip_bytes = make_zip_bytes(
        &[("a.txt", b"hello"), ("b.txt", b"world")],
        zip::CompressionMethod::Stored,
    );
    std::fs::write(input.join("a.zip"), &zip_bytes).expect("write a.zip");

    let policy = TestDir::new("zip_entries_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let limits = TestDir::new("zip_entries_limits");
    let limits_json = write_limits_json(
        &limits,
        r#"{"schema_version":"limits.v1","archive":{"max_entries_per_archive":1}}"#,
    );

    let output = TestDir::new("zip_entries_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(limits_json)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));

    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.zip").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "LIMIT_EXCEEDED");

    let sanitized_path = expected_sanitized_path(output.path(), "a.zip", &zip_bytes, "ndjson");
    assert!(!sanitized_path.exists());
}

#[test]
fn zip_unsafe_path_quarantines_entire_archive() {
    let input = TestDir::new("zip_path_input");
    let zip_bytes = make_zip_bytes(&[("../evil.txt", b"hello")], zip::CompressionMethod::Stored);
    std::fs::write(input.join("a.zip"), &zip_bytes).expect("write a.zip");

    let policy = TestDir::new("zip_path_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("zip_path_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));

    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.zip").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "UNSAFE_PATH");

    let sanitized_path = expected_sanitized_path(output.path(), "a.zip", &zip_bytes, "ndjson");
    assert!(!sanitized_path.exists());
}

#[test]
fn zip_absolute_path_quarantines_entire_archive() {
    let input = TestDir::new("zip_abs_path_input");
    let zip_bytes = make_zip_bytes(
        &[("/etc/passwd", b"root:x:0:0")],
        zip::CompressionMethod::Stored,
    );
    std::fs::write(input.join("a.zip"), &zip_bytes).expect("write a.zip");

    let policy = TestDir::new("zip_abs_path_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("zip_abs_path_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.zip").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "UNSAFE_PATH");
}

#[test]
fn zip_nested_depth_limit_quarantines_entire_archive() {
    // Default max_nested_archive_depth is 3; create 4 levels to exceed it.
    let level4 = make_zip_bytes(&[("a.txt", b"hello")], zip::CompressionMethod::Stored);
    let level3 = make_zip_bytes(&[("l4.zip", &level4)], zip::CompressionMethod::Stored);
    let level2 = make_zip_bytes(&[("l3.zip", &level3)], zip::CompressionMethod::Stored);
    let level1 = make_zip_bytes(&[("l2.zip", &level2)], zip::CompressionMethod::Stored);

    let input = TestDir::new("zip_depth_input");
    std::fs::write(input.join("a.zip"), &level1).expect("write a.zip");

    let policy = TestDir::new("zip_depth_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("zip_depth_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.zip").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "LIMIT_EXCEEDED");

    let sanitized_path = expected_sanitized_path(output.path(), "a.zip", &level1, "ndjson");
    assert!(!sanitized_path.exists());
}

#[test]
fn zip_expansion_ratio_limit_quarantines_entire_archive() {
    let input = TestDir::new("zip_ratio_input");
    let data = vec![b'A'; 20_000];
    let zip_bytes = make_zip_bytes(&[("a.txt", &data)], zip::CompressionMethod::Deflated);
    std::fs::write(input.join("a.zip"), &zip_bytes).expect("write a.zip");

    let policy = TestDir::new("zip_ratio_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let limits = TestDir::new("zip_ratio_limits");
    let limits_json = write_limits_json(
        &limits,
        r#"{"schema_version":"limits.v1","archive":{"max_expansion_ratio":1}}"#,
    );

    let output = TestDir::new("zip_ratio_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(limits_json)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.zip").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "LIMIT_EXCEEDED");
}

#[test]
fn zip_expanded_bytes_limit_quarantines_entire_archive() {
    let input = TestDir::new("zip_bytes_input");
    let data = b"01234567890"; // 11 bytes
    let zip_bytes = make_zip_bytes(&[("a.txt", data)], zip::CompressionMethod::Stored);
    std::fs::write(input.join("a.zip"), &zip_bytes).expect("write a.zip");

    let policy = TestDir::new("zip_bytes_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let limits = TestDir::new("zip_bytes_limits");
    let limits_json = write_limits_json(
        &limits,
        r#"{"schema_version":"limits.v1","archive":{"max_expanded_bytes_per_archive":10}}"#,
    );

    let output = TestDir::new("zip_bytes_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(limits_json)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.zip").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "LIMIT_EXCEEDED");
}

#[test]
fn tar_unsafe_path_quarantines_entire_archive() {
    let input = TestDir::new("tar_path_input");
    let tar_bytes = make_tar_bytes("../evil.txt", b"hello");
    std::fs::write(input.join("a.tar"), &tar_bytes).expect("write a.tar");

    let policy = TestDir::new("tar_path_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("tar_path_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.tar").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "UNSAFE_PATH");
}

#[test]
fn tar_max_entries_limit_quarantines_entire_archive() {
    let input = TestDir::new("tar_entries_input");
    let tar_bytes = make_tar_files(&[("a.txt", b"hello"), ("b.txt", b"world")]);
    std::fs::write(input.join("a.tar"), &tar_bytes).expect("write a.tar");

    let policy = TestDir::new("tar_entries_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let limits = TestDir::new("tar_entries_limits");
    let limits_json = write_limits_json(
        &limits,
        r#"{"schema_version":"limits.v1","archive":{"max_entries_per_archive":1}}"#,
    );

    let output = TestDir::new("tar_entries_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(limits_json)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.tar").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "LIMIT_EXCEEDED");
}

#[test]
fn tar_expanded_bytes_limit_quarantines_entire_archive() {
    let input = TestDir::new("tar_bytes_input");
    let tar_bytes = make_tar_bytes("a.txt", b"01234567890"); // 11 bytes
    std::fs::write(input.join("a.tar"), &tar_bytes).expect("write a.tar");

    let policy = TestDir::new("tar_bytes_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let limits = TestDir::new("tar_bytes_limits");
    let limits_json = write_limits_json(
        &limits,
        r#"{"schema_version":"limits.v1","archive":{"max_expanded_bytes_per_archive":10}}"#,
    );

    let output = TestDir::new("tar_bytes_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(limits_json)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.tar").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "LIMIT_EXCEEDED");
}

#[test]
fn tar_symlink_entry_quarantines_entire_archive() {
    let input = TestDir::new("tar_symlink_input");
    let tar_bytes = make_tar_symlink("link.txt", "/etc/passwd");
    std::fs::write(input.join("a.tar"), &tar_bytes).expect("write a.tar");

    let policy = TestDir::new("tar_symlink_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("tar_symlink_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.tar").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "UNSAFE_PATH");
}

#[test]
fn eml_headers_and_body_are_sanitized() {
    let input = TestDir::new("eml_ok_input");
    let eml = concat!(
        "Subject: hello SECRET\n",
        "From: alice@example.com\n",
        "To: bob@example.com\n",
        "\n",
        "Body SECRET\n"
    );
    std::fs::write(input.join("a.eml"), eml).expect("write a.eml");

    let policy = TestDir::new("eml_ok_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("SECRET"))
        .expect("write policy.json");

    let output = TestDir::new("eml_ok_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(0));

    let eml_bytes = eml.as_bytes();
    let sanitized_path = expected_sanitized_path(output.path(), "a.eml", eml_bytes, "ndjson");
    let sanitized = std::fs::read_to_string(sanitized_path).expect("read sanitized");
    assert!(!sanitized.contains("SECRET"));
    assert!(sanitized.contains("{{PII.Test}}"));
}

#[test]
fn eml_unsupported_attachment_quarantines() {
    let input = TestDir::new("eml_bad_attach_input");

    // /w== => 0xFF (invalid UTF-8)
    let attachment_b64 = "/w==";
    let eml = format!(
        concat!(
            "Subject: test\n",
            "Content-Type: multipart/mixed; boundary=BOUND\n",
            "\n",
            "--BOUND\n",
            "Content-Type: text/plain; charset=utf-8\n",
            "\n",
            "hello\n",
            "--BOUND\n",
            "Content-Type: application/octet-stream\n",
            "Content-Disposition: attachment; filename=\"a.bin\"\n",
            "Content-Transfer-Encoding: base64\n",
            "\n",
            "{attachment_b64}\n",
            "--BOUND--\n",
        ),
        attachment_b64 = attachment_b64,
    );
    std::fs::write(input.join("a.eml"), &eml).expect("write a.eml");

    let policy = TestDir::new("eml_bad_attach_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("eml_bad_attach_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.eml").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "UNSUPPORTED_FORMAT");
}

#[test]
fn docx_text_is_sanitized() {
    let input = TestDir::new("docx_ok_input");

    let doc_xml = r#"<?xml version="1.0" encoding="UTF-8"?><doc>SECRET</doc>"#;
    let docx_bytes = make_zip_bytes(
        &[
            ("[Content_Types].xml", b"<types/>"),
            ("word/document.xml", doc_xml.as_bytes()),
            ("_rels/.rels", b"<rels/>"),
        ],
        zip::CompressionMethod::Stored,
    );
    std::fs::write(input.join("a.docx"), &docx_bytes).expect("write a.docx");

    let policy = TestDir::new("docx_ok_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("SECRET"))
        .expect("write policy.json");

    let output = TestDir::new("docx_ok_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(0));

    let sanitized_path = expected_sanitized_path(output.path(), "a.docx", &docx_bytes, "ndjson");
    let sanitized = std::fs::read_to_string(sanitized_path).expect("read sanitized");
    assert!(!sanitized.contains("SECRET"));
    assert!(sanitized.contains("{{PII.Test}}"));
}

#[test]
fn docx_with_embedded_binary_quarantines_unknown_coverage() {
    let input = TestDir::new("docx_bin_input");

    let docx_bytes = make_zip_bytes(
        &[
            ("[Content_Types].xml", b"<types/>"),
            ("word/document.xml", b"<doc>hello</doc>"),
            ("word/media/image1.png", b"PNG"),
        ],
        zip::CompressionMethod::Stored,
    );
    std::fs::write(input.join("a.docx"), &docx_bytes).expect("write a.docx");

    let policy = TestDir::new("docx_bin_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("docx_bin_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.docx").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "UNKNOWN_COVERAGE");
}

#[test]
fn eml_zip_attachment_is_scanned_and_sanitized() {
    let input = TestDir::new("eml_zip_attach_input");

    let inner_zip = make_zip_bytes(
        &[("a.txt", b"hello SECRET")],
        zip::CompressionMethod::Stored,
    );
    let inner_b64 = base64::engine::general_purpose::STANDARD.encode(inner_zip);

    let eml = format!(
        concat!(
            "Subject: test\n",
            "Content-Type: multipart/mixed; boundary=BOUND\n",
            "\n",
            "--BOUND\n",
            "Content-Type: text/plain; charset=utf-8\n",
            "\n",
            "body\n",
            "--BOUND\n",
            "Content-Type: application/zip\n",
            "Content-Disposition: attachment; filename=\"a.zip\"\n",
            "Content-Transfer-Encoding: base64\n",
            "\n",
            "{inner_b64}\n",
            "--BOUND--\n",
        ),
        inner_b64 = inner_b64,
    );
    std::fs::write(input.join("a.eml"), &eml).expect("write a.eml");

    let policy = TestDir::new("eml_zip_attach_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("SECRET"))
        .expect("write policy.json");

    let output = TestDir::new("eml_zip_attach_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(0));

    let sanitized_path = expected_sanitized_path(output.path(), "a.eml", eml.as_bytes(), "ndjson");
    let sanitized = std::fs::read_to_string(sanitized_path).expect("read sanitized");
    assert!(!sanitized.contains("SECRET"));
    assert!(sanitized.contains("{{PII.Test}}"));
}

#[test]
fn zip_extension_with_ndjson_payload_quarantines_parse_error() {
    let input = TestDir::new("zip_mislabeled_ndjson_input");
    let fake_zip_bytes = br#"{"record":"not-a-zip"}"#;
    std::fs::write(input.join("a.zip"), fake_zip_bytes).expect("write a.zip");

    let policy = TestDir::new("zip_mislabeled_ndjson_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("zip_mislabeled_ndjson_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));

    let recs = read_quarantine_index(output.path());
    let rec = recs
        .iter()
        .find(|r| {
            r.source_locator_hash == veil_domain::hash_source_locator_hash("a.zip").to_string()
        })
        .expect("find quarantine record");
    assert_eq!(rec.reason_code, "PARSE_ERROR");
}
