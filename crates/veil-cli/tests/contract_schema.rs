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
#[serde(deny_unknown_fields)]
struct RunManifestV1 {
    tool_version: String,
    run_id: String,
    policy_id: String,
    input_corpus_id: String,
    totals: RunTotals,
    quarantine_reason_counts: std::collections::BTreeMap<String, u64>,
    tokenization_enabled: bool,
    tokenization_scope: Option<String>,
    proof_scope: String,
    proof_key_commitment: String,
    quarantine_copy_enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunTotals {
    artifacts_discovered: u64,
    artifacts_verified: u64,
    artifacts_quarantined: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEvidenceRecordV1 {
    artifact_id: String,
    source_locator_hash: String,
    size_bytes: u64,
    artifact_type: String,
    state: String,
    quarantine_reason_code: Option<String>,
    #[serde(default)]
    proof_tokens: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuarantineIndexRecordV1 {
    artifact_id: String,
    source_locator_hash: String,
    reason_code: String,
}

#[test]
fn run_manifest_schema_v1_is_stable() {
    let input = TestDir::new("contract_schema_run_manifest_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input");

    let policy = TestDir::new("contract_schema_run_manifest_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy");

    let output = TestDir::new("contract_schema_run_manifest_output");
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

    let run_manifest: RunManifestV1 = serde_json::from_slice(
        &std::fs::read(output.join("evidence").join("run_manifest.json"))
            .expect("read run_manifest"),
    )
    .expect("parse run_manifest");

    assert!(!run_manifest.tool_version.is_empty());
    assert!(!run_manifest.run_id.is_empty());
    assert!(!run_manifest.policy_id.is_empty());
    assert!(!run_manifest.input_corpus_id.is_empty());
    assert_eq!(run_manifest.proof_scope, "PER_RUN");
    assert_eq!(run_manifest.proof_key_commitment.len(), 64);
    assert!(!run_manifest.quarantine_copy_enabled);
    assert!(!run_manifest.tokenization_enabled);
    assert!(run_manifest.tokenization_scope.is_none());
    assert_eq!(run_manifest.totals.artifacts_discovered, 1);
    assert_eq!(run_manifest.totals.artifacts_verified, 1);
    assert_eq!(run_manifest.totals.artifacts_quarantined, 0);
    assert!(run_manifest.quarantine_reason_counts.is_empty());
}

#[test]
fn evidence_ndjson_schema_v1_is_stable() {
    let input = TestDir::new("contract_schema_evidence_input");
    std::fs::write(input.join("a.txt"), "hello SECRET").expect("write input");
    std::fs::write(input.join("b.bin"), [0, 1, 2]).expect("write input");

    let policy = TestDir::new("contract_schema_evidence_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("SECRET"))
        .expect("write policy");

    let output = TestDir::new("contract_schema_evidence_output");
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

    let artifacts_ndjson =
        std::fs::read_to_string(output.join("evidence").join("artifacts.ndjson"))
            .expect("read ndjson");
    let mut seen = 0_usize;
    for line in artifacts_ndjson.lines() {
        if line.trim().is_empty() {
            continue;
        }
        seen += 1;
        let rec: ArtifactEvidenceRecordV1 =
            serde_json::from_str(line).expect("parse artifacts record");
        assert!(!rec.artifact_id.is_empty());
        assert!(!rec.source_locator_hash.is_empty());
        assert!(!rec.artifact_type.is_empty());
        assert!(rec.size_bytes > 0);
        assert!(rec.state == "VERIFIED" || rec.state == "QUARANTINED");
        if rec.state == "VERIFIED" {
            assert!(rec.quarantine_reason_code.is_none());
        } else {
            assert!(rec.quarantine_reason_code.is_some());
        }
        let _ = rec.proof_tokens.len();
    }
    assert_eq!(seen, 2);

    let quarantine_ndjson = std::fs::read_to_string(output.join("quarantine").join("index.ndjson"))
        .expect("read ndjson");
    let mut quarantined = 0_usize;
    for line in quarantine_ndjson.lines() {
        if line.trim().is_empty() {
            continue;
        }
        quarantined += 1;
        let rec: QuarantineIndexRecordV1 =
            serde_json::from_str(line).expect("parse quarantine record");
        assert!(!rec.artifact_id.is_empty());
        assert!(!rec.source_locator_hash.is_empty());
        assert!(!rec.reason_code.is_empty());
    }
    assert!(quarantined >= 1);
}
