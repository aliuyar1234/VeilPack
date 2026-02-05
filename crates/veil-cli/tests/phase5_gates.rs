use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn snapshot_files(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, cur: &Path, out: &mut BTreeMap<String, String>) {
        let mut entries = std::fs::read_dir(cur)
            .expect("read_dir")
            .map(|e| e.expect("dir entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(|e| e.file_name());

        for e in entries {
            let path = e.path();
            let rel = path.strip_prefix(root).expect("strip_prefix");

            if rel
                .components()
                .next()
                .is_some_and(|c| c.as_os_str() == ".veil_work")
            {
                continue;
            }

            let meta = e.metadata().expect("metadata");
            if meta.is_dir() {
                walk(root, &path, out);
                continue;
            }

            if meta.is_file() {
                let rel = rel.to_string_lossy().replace('\\', "/");
                let bytes = std::fs::read(&path).expect("read file");
                let h = blake3::hash(&bytes).to_hex().to_string();
                out.insert(rel, h);
            }
        }
    }

    let mut out = BTreeMap::<String, String>::new();
    walk(root, root, &mut out);
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

fn make_zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::<u8>::new());
    let mut writer = zip::ZipWriter::new(cursor);

    let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in entries {
        writer.start_file(*name, options).expect("start zip file");
        writer.write_all(data).expect("write zip data");
    }

    let cursor = writer.finish().expect("finish zip");
    cursor.into_inner()
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

#[test]
fn resume_after_crash_completes_remaining_artifacts() {
    let input = TestDir::new("resume_crash_input");
    let a_bytes = b"SECRET A".to_vec();
    let b_bytes = b"SECRET B".to_vec();
    std::fs::write(input.join("a.txt"), &a_bytes).expect("write a.txt");
    std::fs::write(input.join("b.txt"), &b_bytes).expect("write b.txt");

    let policy = TestDir::new("resume_crash_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("SECRET"))
        .expect("write policy.json");

    let output = TestDir::new("resume_crash_output");

    let out = veil_cmd()
        .env("VEIL_FAILPOINT", "after_first_verified")
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run (crash)");
    assert_eq!(out.status.code(), Some(1));

    let marker_path = output.path().join(".veil_work").join("in_progress.marker");
    assert!(marker_path.is_file(), "in-progress marker should exist");
    assert!(!output.path().join("pack_manifest.json").exists());

    let a_out = expected_sanitized_path(output.path(), "a.txt", &a_bytes, "txt");
    let b_out = expected_sanitized_path(output.path(), "b.txt", &b_bytes, "txt");
    let a_exists = a_out.is_file();
    let b_exists = b_out.is_file();
    assert_ne!(
        a_exists, b_exists,
        "expected exactly one VERIFIED output before crash"
    );

    let preserved = if a_exists { &a_out } else { &b_out };
    let preserved_hash_before = blake3::hash(&std::fs::read(preserved).expect("read preserved"))
        .to_hex()
        .to_string();

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run (resume)");
    assert_eq!(out.status.code(), Some(0));

    assert!(
        !marker_path.exists(),
        "in-progress marker should be removed"
    );
    assert!(output.path().join("pack_manifest.json").is_file());
    assert!(a_out.is_file());
    assert!(b_out.is_file());

    let preserved_hash_after = blake3::hash(&std::fs::read(preserved).expect("read preserved"))
        .to_hex()
        .to_string();
    assert_eq!(
        preserved_hash_before, preserved_hash_after,
        "terminal VERIFIED output must not change across resume"
    );
}

#[test]
fn determinism_corpus_with_containers_is_stable() {
    let input = TestDir::new("det5_input");
    std::fs::write(input.join("a.txt"), "SECRET").expect("write input");
    std::fs::write(input.join("b.json"), r#"{"b":"SECRET","a":1}"#).expect("write input");

    let zip_bytes = make_zip_bytes(&[("inner.txt", b"SECRET")]);
    std::fs::write(input.join("c.zip"), &zip_bytes).expect("write c.zip");

    let tar_bytes = make_tar_bytes("inner.txt", b"SECRET");
    std::fs::write(input.join("d.tar"), &tar_bytes).expect("write d.tar");

    let eml = concat!(
        "Subject: test\n",
        "Content-Type: text/plain; charset=utf-8\n",
        "\n",
        "SECRET\n",
    );
    std::fs::write(input.join("e.eml"), eml).expect("write e.eml");

    let mbox = concat!(
        "From sender@example.com Sat Jan 01 00:00:00 2022\n",
        "Subject: test\n",
        "Content-Type: text/plain; charset=utf-8\n",
        "\n",
        "SECRET\n",
    );
    std::fs::write(input.join("f.mbox"), mbox).expect("write f.mbox");

    let doc_xml = r#"<?xml version="1.0" encoding="UTF-8"?><doc>SECRET</doc>"#;
    let docx_bytes = make_zip_bytes(&[
        ("[Content_Types].xml", b"<types/>"),
        ("word/document.xml", doc_xml.as_bytes()),
        ("_rels/.rels", b"<rels/>"),
    ]);
    std::fs::write(input.join("g.docx"), &docx_bytes).expect("write g.docx");

    let policy = TestDir::new("det5_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("SECRET"))
        .expect("write policy.json");

    let out1 = TestDir::new("det5_out1");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(out1.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run #1");
    assert_eq!(out.status.code(), Some(0));

    let out2 = TestDir::new("det5_out2");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(out2.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run #2");
    assert_eq!(out.status.code(), Some(0));

    let snap1 = snapshot_files(out1.path());
    let snap2 = snapshot_files(out2.path());
    assert_eq!(snap1, snap2, "determinism snapshot mismatch");
}

#[test]
fn runbook_quickstart_end_to_end() {
    let input = TestDir::new("runbook_input");
    std::fs::write(input.join("a.txt"), "CANARY").expect("write input");
    std::fs::write(input.join("b.json"), r#"{"k":"CANARY"}"#).expect("write input");

    let policy = TestDir::new("runbook_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("CANARY"))
        .expect("write policy.json");

    let output = TestDir::new("runbook_output");
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

    let verify = veil_cmd()
        .arg("verify")
        .arg("--pack")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil verify");
    assert_eq!(verify.status.code(), Some(0));
}

#[test]
fn resume_fails_closed_on_invalid_existing_artifacts_evidence() {
    let input = TestDir::new("resume_invalid_evidence_input");
    std::fs::write(input.join("a.txt"), "SECRET A").expect("write a.txt");
    std::fs::write(input.join("b.txt"), "SECRET B").expect("write b.txt");

    let policy = TestDir::new("resume_invalid_evidence_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("SECRET"))
        .expect("write policy.json");

    let output = TestDir::new("resume_invalid_evidence_output");
    let out = veil_cmd()
        .env("VEIL_FAILPOINT", "after_first_verified")
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run (crash)");
    assert_eq!(out.status.code(), Some(1));

    let artifacts_path = output.path().join("evidence").join("artifacts.ndjson");
    std::fs::write(&artifacts_path, "{not-json\n").expect("write invalid artifacts.ndjson");

    let resumed = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run (resume)");
    assert_eq!(resumed.status.code(), Some(1));
}
