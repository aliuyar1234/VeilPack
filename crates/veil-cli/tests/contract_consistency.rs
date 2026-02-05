use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

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
struct PackManifestJsonV1 {
    pack_schema_version: String,
    tool_version: String,
    run_id: String,
    policy_id: String,
    input_corpus_id: String,
    tokenization_enabled: bool,
    tokenization_scope: Option<String>,
    quarantine_copy_enabled: bool,
    ledger_schema_version: String,
}

#[test]
fn help_outputs_include_required_flags() {
    let out = veil_cmd()
        .args(["run", "--help"])
        .output()
        .expect("run veil run --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--input"));
    assert!(stdout.contains("--output"));
    assert!(stdout.contains("--policy"));

    let out = veil_cmd()
        .args(["verify", "--help"])
        .output()
        .expect("run veil verify --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--pack"));
    assert!(stdout.contains("--policy"));

    let out = veil_cmd()
        .args(["policy", "lint", "--help"])
        .output()
        .expect("run veil policy lint --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--policy"));
}

#[test]
fn pack_layout_v1_contains_required_paths() {
    let input = TestDir::new("contract_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");
    std::fs::write(input.join("b.bin"), b"\x00\x01\x02").expect("write input file");

    let policy = TestDir::new("contract_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("contract_output");

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

    assert!(output.join("pack_manifest.json").is_file());
    assert!(output.join("sanitized").is_dir());
    assert!(output.join("quarantine").is_dir());
    assert!(output.join("quarantine").join("index.ndjson").is_file());
    assert!(!output.join("quarantine").join("raw").exists());
    assert!(output.join("evidence").is_dir());
    assert!(output.join("evidence").join("run_manifest.json").is_file());
    assert!(output.join("evidence").join("artifacts.ndjson").is_file());
    assert!(output.join("evidence").join("ledger.sqlite3").is_file());

    let pack_manifest: PackManifestJsonV1 = serde_json::from_slice(
        &std::fs::read(output.join("pack_manifest.json")).expect("read pack_manifest.json"),
    )
    .expect("parse pack_manifest.json");
    assert_eq!(pack_manifest.pack_schema_version, "pack.v1");
    assert!(!pack_manifest.tool_version.is_empty());
    assert!(!pack_manifest.run_id.is_empty());
    assert!(!pack_manifest.policy_id.is_empty());
    assert!(!pack_manifest.input_corpus_id.is_empty());
    assert!(!pack_manifest.tokenization_enabled);
    assert!(pack_manifest.tokenization_scope.is_none());
    assert!(!pack_manifest.quarantine_copy_enabled);
    assert_eq!(
        pack_manifest.ledger_schema_version,
        veil_evidence::LEDGER_SCHEMA_VERSION
    );
}

#[test]
fn quarantine_raw_copy_is_opt_in_and_recorded() {
    let input = TestDir::new("contract_raw_input");
    std::fs::write(input.join("a.bin"), b"\x00\x01\x02").expect("write input file");

    let policy = TestDir::new("contract_raw_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("contract_raw_output");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .args(["--quarantine-copy", "true"])
        .output()
        .expect("run veil run");
    assert_eq!(out.status.code(), Some(2));

    let pack_manifest: PackManifestJsonV1 = serde_json::from_slice(
        &std::fs::read(output.join("pack_manifest.json")).expect("read pack_manifest.json"),
    )
    .expect("parse pack_manifest.json");
    assert!(pack_manifest.quarantine_copy_enabled);
    assert_eq!(
        pack_manifest.ledger_schema_version,
        veil_evidence::LEDGER_SCHEMA_VERSION
    );

    assert!(output.join("quarantine").join("raw").is_dir());
    let has_raw_file = std::fs::read_dir(output.join("quarantine").join("raw"))
        .expect("read_dir raw")
        .any(|e| e.expect("raw entry").path().is_file());
    assert!(has_raw_file);
}

#[test]
fn pack_manifest_records_tokenization_scope_when_enabled() {
    let input = TestDir::new("contract_token_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("contract_token_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let secret_dir = TestDir::new("contract_token_secret");
    let secret_key = secret_dir.join("secret.key");
    std::fs::write(&secret_key, "CONTRACT_TEST_SECRET").expect("write secret");

    let output = TestDir::new("contract_token_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .args(["--enable-tokenization", "true"])
        .arg("--secret-key-file")
        .arg(&secret_key)
        .output()
        .expect("run veil run");
    assert_eq!(out.status.code(), Some(0));

    let pack_manifest: PackManifestJsonV1 = serde_json::from_slice(
        &std::fs::read(output.join("pack_manifest.json")).expect("read pack_manifest.json"),
    )
    .expect("parse pack_manifest.json");
    assert!(pack_manifest.tokenization_enabled);
    assert_eq!(pack_manifest.tokenization_scope.as_deref(), Some("PER_RUN"));
    assert_eq!(
        pack_manifest.ledger_schema_version,
        veil_evidence::LEDGER_SCHEMA_VERSION
    );
}
