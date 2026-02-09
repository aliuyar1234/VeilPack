use std::path::{Path, PathBuf};
use std::process::Command;

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

fn quarantine_index_text(pack_root: &Path) -> String {
    std::fs::read_to_string(pack_root.join("quarantine").join("index.ndjson"))
        .expect("read quarantine index")
}

fn build_pdf_with_page_count(page_count: u32) -> Vec<u8> {
    assert!(page_count >= 1);

    let mut out = String::new();
    out.push_str("%PDF-1.4\n");

    let page_obj_start = 3_u32;
    let content_obj_start = page_obj_start + page_count;
    let font_obj_id = content_obj_start + page_count;

    let mut objects = Vec::<String>::new();
    objects.push("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string());

    let mut kids = String::new();
    for i in 0..page_count {
        if i > 0 {
            kids.push(' ');
        }
        kids.push_str(&(page_obj_start + i).to_string());
        kids.push_str(" 0 R");
    }
    objects.push(format!(
        "2 0 obj\n<< /Type /Pages /Kids [{}] /Count {} >>\nendobj\n",
        kids, page_count
    ));

    for i in 0..page_count {
        let page_obj_id = page_obj_start + i;
        let content_obj_id = content_obj_start + i;
        objects.push(format!(
            "{page_obj_id} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_obj_id} 0 R >> >> /Contents {content_obj_id} 0 R >>\nendobj\n"
        ));
    }

    for i in 0..page_count {
        let content_obj_id = content_obj_start + i;
        let content_stream = format!("BT /F1 18 Tf 72 720 Td (P{}) Tj ET", i + 1);
        objects.push(format!(
            "{content_obj_id} 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            content_stream.len(),
            content_stream
        ));
    }

    objects.push(format!(
        "{font_obj_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    ));

    let mut offsets = Vec::<usize>::new();
    for obj in &objects {
        offsets.push(out.len());
        out.push_str(obj);
    }

    let xref_offset = out.len();
    out.push_str("xref\n");
    out.push_str(&format!("0 {}\n", objects.len() + 1));
    out.push_str("0000000000 65535 f \n");
    for off in offsets {
        out.push_str(&format!("{off:010} 00000 n \n"));
    }
    out.push_str("trailer\n<< /Size ");
    out.push_str(&(objects.len() + 1).to_string());
    out.push_str(" /Root 1 0 R >>\n");
    out.push_str("startxref\n");
    out.push_str(&xref_offset.to_string());
    out.push_str("\n%%EOF\n");

    out.into_bytes()
}

#[test]
fn run_accepts_valid_limits_json() {
    let input = TestDir::new("input_limits_ok");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_ok");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_ok");

    let limits = TestDir::new("limits_ok");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","archive":{"max_expansion_ratio":25},"artifact":{"max_bytes_per_artifact":1024},"disk":{"max_workdir_bytes":1048576}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    // Valid limits-json should pass validation and complete.
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn run_quarantines_artifact_exceeding_max_bytes_per_artifact() {
    let input = TestDir::new("input_limits_artifact_size");
    std::fs::write(input.join("a.txt"), "0123456789ABCDEF").expect("write input file");

    let policy = TestDir::new("policy_limits_artifact_size");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_artifact_size");

    let limits = TestDir::new("limits_artifact_size");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","artifact":{"max_bytes_per_artifact":8}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let q = quarantine_index_text(output.path());
    assert!(q.contains("\"reason_code\":\"LIMIT_EXCEEDED\""));
}

#[test]
fn run_rejects_wrong_limits_schema_version() {
    let input = TestDir::new("input_limits_bad_schema");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_bad_schema");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_bad_schema");

    let limits = TestDir::new("limits_bad_schema");
    let limits_path = limits.join("limits.json");
    std::fs::write(&limits_path, br#"{"schema_version":"limits.v2"}"#).expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_rejects_limits_json_unknown_fields() {
    let input = TestDir::new("input_limits_unknown_fields");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_unknown_fields");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_unknown_fields");

    let limits = TestDir::new("limits_unknown_fields");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","unexpected":true}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_rejects_limits_json_unknown_nested_fields() {
    let input = TestDir::new("input_limits_unknown_nested");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_unknown_nested");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_unknown_nested");
    let limits = TestDir::new("limits_unknown_nested");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","archive":{"unknown":1},"artifact":{"also_unknown":2}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_rejects_limits_json_unknown_pdf_nested_fields() {
    let input = TestDir::new("input_limits_unknown_pdf_nested");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_unknown_pdf_nested");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_unknown_pdf_nested");
    let limits = TestDir::new("limits_unknown_pdf_nested");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","pdf":{"unknown":true}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_rejects_limits_json_zero_values() {
    let input = TestDir::new("input_limits_zero_values");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_zero_values");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_zero_values");
    let limits = TestDir::new("limits_zero_values");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","archive":{"max_expansion_ratio":0,"max_expanded_bytes_per_archive":0,"max_pdf_pages":0},"artifact":{"max_bytes_per_artifact":0},"disk":{"max_workdir_bytes":0}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_rejects_limits_json_pdf_ocr_enabled_without_command() {
    let input = TestDir::new("input_limits_pdf_ocr_missing_command");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_pdf_ocr_missing_command");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_pdf_ocr_missing_command");
    let limits = TestDir::new("limits_pdf_ocr_missing_command");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","pdf":{"ocr":{"enabled":true}}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_rejects_limits_json_pdf_invalid_output_mode() {
    let input = TestDir::new("input_limits_pdf_invalid_output_mode");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_pdf_invalid_output_mode");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_pdf_invalid_output_mode");
    let limits = TestDir::new("limits_pdf_invalid_output_mode");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","pdf":{"output_mode":"unknown"}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_rejects_limits_json_pdf_ocr_zero_values() {
    let input = TestDir::new("input_limits_pdf_ocr_zero_values");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_pdf_ocr_zero_values");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_pdf_ocr_zero_values");
    let limits = TestDir::new("limits_pdf_ocr_zero_values");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","pdf":{"ocr":{"enabled":true,"command":["python","script.py"],"timeout_ms":0,"max_output_bytes":0}}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_rejects_limits_json_pdf_worker_zero_values() {
    let input = TestDir::new("input_limits_pdf_worker_zero_values");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_pdf_worker_zero_values");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_pdf_worker_zero_values");
    let limits = TestDir::new("limits_pdf_worker_zero_values");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","pdf":{"worker":{"timeout_ms":0,"max_output_bytes":0}}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_quarantines_pdf_when_max_pdf_pages_exceeded() {
    let input = TestDir::new("input_limits_pdf_pages");
    let pdf_bytes = build_pdf_with_page_count(2);
    std::fs::write(input.join("a.pdf"), pdf_bytes).expect("write input pdf");

    let policy = TestDir::new("policy_limits_pdf_pages");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_pdf_pages");

    let limits = TestDir::new("limits_pdf_pages");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","archive":{"max_pdf_pages":1},"pdf":{"enabled":true}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let q = quarantine_index_text(output.path());
    assert!(q.contains("\"reason_code\":\"PDF_LIMIT_EXCEEDED\""));
}

#[test]
fn run_quarantines_when_workdir_limit_would_be_exceeded() {
    let input = TestDir::new("input_limits_workdir");
    std::fs::write(input.join("a.txt"), "X".repeat(1024)).expect("write input file");

    let policy = TestDir::new("policy_limits_workdir");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_workdir");

    let limits = TestDir::new("limits_workdir");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","disk":{"max_workdir_bytes":200}}"#,
    )
    .expect("write limits.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--limits-json")
        .arg(&limits_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(2));
    let q = quarantine_index_text(output.path());
    assert!(q.contains("\"reason_code\":\"LIMIT_EXCEEDED\""));
}
