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

fn stderr_contains_reason_code(stderr: &[u8], code: &str) -> bool {
    let stderr = String::from_utf8_lossy(stderr);
    stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|v| v.get("reason_code").and_then(|r| r.as_str()) == Some(code))
}

#[test]
fn unknown_command_uses_usage_error_code() {
    let out = veil_cmd().arg("does-not-exist").output().expect("run veil");
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr_contains_reason_code(&out.stderr, "USAGE"));
}

#[test]
fn run_missing_required_flag_uses_usage_error_code() {
    let out = veil_cmd().arg("run").output().expect("run veil");
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr_contains_reason_code(&out.stderr, "USAGE"));
}

#[test]
fn runtime_failpoint_uses_internal_error_code() {
    let input = TestDir::new("error_code_internal_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input");

    let policy = TestDir::new("error_code_internal_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy");

    let output = TestDir::new("error_code_internal_output");
    let out = veil_cmd()
        .env("VEIL_FAILPOINT", "after_stage_write")
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil");
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr_contains_reason_code(&out.stderr, "INTERNAL_ERROR"));
}
