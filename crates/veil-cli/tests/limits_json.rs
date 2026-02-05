use std::path::{Path, PathBuf};
use std::process::Command;

fn veil_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_veil"))
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

#[test]
fn run_accepts_valid_limits_json() {
    let input = TestDir::new("input_limits_ok");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_ok");
    std::fs::write(policy.join("policy.json"), "{}").expect("write policy.json");

    let output = TestDir::new("output_limits_ok");

    let limits = TestDir::new("limits_ok");
    let limits_path = limits.join("limits.json");
    std::fs::write(
        &limits_path,
        br#"{"schema_version":"limits.v1","archive":{"max_expansion_ratio":25}}"#,
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

    // Valid limits-json should pass validation and hit the fail-closed stub path.
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn run_rejects_wrong_limits_schema_version() {
    let input = TestDir::new("input_limits_bad_schema");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy_limits_bad_schema");
    std::fs::write(policy.join("policy.json"), "{}").expect("write policy.json");

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
    std::fs::write(policy.join("policy.json"), "{}").expect("write policy.json");

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
