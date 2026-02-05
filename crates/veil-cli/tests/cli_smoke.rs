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
fn help_is_available() {
    let out = veil_cmd().arg("--help").output().expect("run veil --help");
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Veil"));
    assert!(stdout.contains("USAGE:"));
}

#[test]
fn run_missing_flags_is_usage_error() {
    let out = veil_cmd().arg("run").output().expect("run veil run");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_valid_args_fails_closed_until_implemented() {
    let input = TestDir::new("input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("policy");
    std::fs::write(policy.join("policy.json"), "{}").expect("write policy.json");

    let output = TestDir::new("output");

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

    assert_eq!(out.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("fail-closed"));
}

#[test]
fn verify_missing_flags_is_usage_error() {
    let out = veil_cmd().arg("verify").output().expect("run veil verify");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn policy_lint_missing_flags_is_usage_error() {
    let out = veil_cmd()
        .args(["policy", "lint"])
        .output()
        .expect("run veil policy lint");
    assert_eq!(out.status.code(), Some(3));
}
