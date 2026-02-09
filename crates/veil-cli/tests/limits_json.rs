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
        br#"{"schema_version":"limits.v1","archive":{"max_expansion_ratio":0,"max_expanded_bytes_per_archive":0},"artifact":{"max_bytes_per_artifact":0},"disk":{"max_workdir_bytes":0}}"#,
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

#[test]
fn run_rejects_limits_json_zero_max_processing_ms() {
    let input = TestDir::new("input_limits_zero_processing_ms");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_zero_processing_ms");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_zero_processing_ms");
    let limits = TestDir::new("limits_zero_processing_ms");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","artifact":{"max_processing_ms":0}}"#,
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
fn run_quarantines_when_processing_time_limit_is_too_low() {
    let input = TestDir::new("input_limits_processing_ms");
    std::fs::write(input.join("a.json"), r#"{"v":"SECRET"}"#).expect("write input file");

    let policy = TestDir::new("policy_limits_processing_ms");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("SECRET"))
        .expect("write policy.json");

    let output = TestDir::new("output_limits_processing_ms");
    let limits = TestDir::new("limits_processing_ms");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","artifact":{"max_processing_ms":1}}"#,
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
