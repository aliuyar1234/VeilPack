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
            "veil_phase3_test_{}_{}",
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
struct PackManifestRead {
    pack_schema_version: String,
    ledger_schema_version: String,
    quarantine_copy_enabled: bool,
}

#[test]
fn quarantine_raw_copy_is_opt_in_and_contained() {
    let input = TestDir::new("qc_input");
    let raw_bytes = b"\x00\x01\x02\x03";
    std::fs::write(input.join("a.bin"), raw_bytes).expect("write input file");

    let policy = TestDir::new("qc_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("qc_output");
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

    let pack_manifest_json =
        std::fs::read_to_string(output.join("pack_manifest.json")).expect("read pack_manifest");
    let pack_manifest: PackManifestRead =
        serde_json::from_str(&pack_manifest_json).expect("parse pack_manifest");
    assert_eq!(pack_manifest.pack_schema_version, "pack.v1");
    assert_eq!(
        pack_manifest.ledger_schema_version,
        veil_evidence::LEDGER_SCHEMA_VERSION
    );
    assert!(pack_manifest.quarantine_copy_enabled);

    let artifact_id = veil_domain::hash_artifact_id(raw_bytes);
    let source_locator_hash = veil_domain::hash_source_locator_hash("a.bin");
    let sort_key = veil_domain::ArtifactSortKey::new(artifact_id, source_locator_hash);
    let expected_name = format!(
        "{}__{}.bin",
        sort_key.source_locator_hash, sort_key.artifact_id
    );
    let copied = output.join("quarantine").join("raw").join(expected_name);
    assert!(copied.is_file());
    assert_eq!(std::fs::read(copied).expect("read copied file"), raw_bytes);
}

#[test]
fn verify_refuses_unsupported_pack_schema_versions() {
    let input = TestDir::new("pack_schema_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("pack_schema_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("pack_schema_output");
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

    let pack_manifest_path = output.join("pack_manifest.json");
    let mut pack_manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&pack_manifest_path).expect("read pack_manifest"),
    )
    .expect("parse pack_manifest");
    pack_manifest["pack_schema_version"] = serde_json::Value::String("pack.v0".to_string());
    std::fs::write(
        &pack_manifest_path,
        serde_json::to_vec(&pack_manifest).expect("serialize"),
    )
    .expect("write pack_manifest");

    let out = veil_cmd()
        .arg("verify")
        .arg("--pack")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil verify");

    assert_eq!(out.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn verify_refuses_when_pack_manifest_path_is_symlink() {
    use std::os::unix::fs::symlink;

    let input = TestDir::new("pack_manifest_symlink_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("pack_manifest_symlink_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("pack_manifest_symlink_output");
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

    let pack_manifest_path = output.join("pack_manifest.json");
    let external = TestDir::new("pack_manifest_symlink_external");
    let external_file = external.join("outside.json");
    std::fs::write(&external_file, "{}").expect("write external");
    std::fs::remove_file(&pack_manifest_path).expect("remove pack_manifest");
    symlink(&external_file, &pack_manifest_path).expect("symlink pack_manifest");

    let verify = veil_cmd()
        .arg("verify")
        .arg("--pack")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil verify");
    assert_eq!(verify.status.code(), Some(1));
}

#[test]
fn verify_refuses_unsupported_ledger_schema_versions() {
    let input = TestDir::new("ledger_schema_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("ledger_schema_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("ledger_schema_output");
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

    let pack_manifest_path = output.join("pack_manifest.json");
    let mut pack_manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&pack_manifest_path).expect("read pack_manifest"),
    )
    .expect("parse pack_manifest");
    pack_manifest["ledger_schema_version"] = serde_json::Value::String("ledger.v0".to_string());
    std::fs::write(
        &pack_manifest_path,
        serde_json::to_vec(&pack_manifest).expect("serialize"),
    )
    .expect("write pack_manifest");

    let out = veil_cmd()
        .arg("verify")
        .arg("--pack")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil verify");

    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn proof_tokens_are_emitted_as_digests() {
    let input = TestDir::new("proof_tokens_input");
    std::fs::write(input.join("a.txt"), "CREDITCARD 4111-1111-1111-1111").expect("write input");

    let policy = TestDir::new("proof_tokens_policy");
    std::fs::write(
        policy.join("policy.json"),
        minimal_policy_json(r"4111-1111-1111-1111"),
    )
    .expect("write policy.json");

    let output = TestDir::new("proof_tokens_output");
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

    let artifacts_ndjson =
        std::fs::read_to_string(output.join("evidence").join("artifacts.ndjson"))
            .expect("read artifacts.ndjson");
    let first = artifacts_ndjson.lines().next().expect("first record");
    let rec: serde_json::Value = serde_json::from_str(first).expect("parse artifacts record");
    let tokens = rec
        .get("proof_tokens")
        .and_then(|v| v.as_array())
        .expect("proof_tokens array");
    assert!(!tokens.is_empty());
    for t in tokens {
        let t = t.as_str().expect("token string");
        assert_eq!(t.len(), 12);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }
    assert!(!artifacts_ndjson.contains("4111-1111-1111-1111"));
}
