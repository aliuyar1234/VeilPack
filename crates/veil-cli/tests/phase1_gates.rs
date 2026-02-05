use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

fn veil_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_veil"))
}

fn policy_json_single_class(detector_pattern: &str, action_json: &str) -> String {
    format!(
        r#"{{
  "schema_version": "policy.v1",
  "classes": [
    {{
      "class_id": "PII.Canary",
      "severity": "HIGH",
      "detectors": [
        {{
          "kind": "regex",
          "pattern": "{detector_pattern}"
        }}
      ],
      "action": {action_json}
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
            "veil_phase1_test_{}_{}",
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

#[derive(Debug, Deserialize)]
struct ArtifactEvidenceRecord {
    state: String,
}

#[test]
fn fail_closed_terminal_states_only() {
    let input = TestDir::new("terminal_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input");
    std::fs::write(input.join("b.bin"), b"\x00\x01").expect("write input");

    let policy = TestDir::new("terminal_policy");
    std::fs::write(
        policy.join("policy.json"),
        policy_json_single_class("NO_MATCH", r#"{ "kind": "REDACT" }"#),
    )
    .expect("write policy.json");

    let output = TestDir::new("terminal_output");
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
        std::fs::read_to_string(output.join("evidence").join("artifacts.ndjson")).unwrap();
    for line in artifacts_ndjson.lines().filter(|l| !l.trim().is_empty()) {
        let rec: ArtifactEvidenceRecord = serde_json::from_str(line).expect("parse ndjson");
        assert!(
            rec.state == "VERIFIED" || rec.state == "QUARANTINED",
            "non-terminal state present"
        );
    }
}

#[test]
fn no_plaintext_canary_leaks_to_logs_or_evidence() {
    let canary = "CANARY_SECRET_ABC123";

    let input = TestDir::new("canary_input");
    std::fs::write(input.join("a.txt"), format!("hello {canary} world")).expect("write input");

    let policy = TestDir::new("canary_policy");
    std::fs::write(
        policy.join("policy.json"),
        policy_json_single_class(canary, r#"{ "kind": "REDACT" }"#),
    )
    .expect("write policy.json");

    let output = TestDir::new("canary_output");
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

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains(canary), "stderr leaked canary");

    let run_manifest =
        std::fs::read_to_string(output.join("evidence").join("run_manifest.json")).unwrap();
    assert!(!run_manifest.contains(canary), "run_manifest leaked canary");

    let artifacts_ndjson =
        std::fs::read_to_string(output.join("evidence").join("artifacts.ndjson")).unwrap();
    assert!(
        !artifacts_ndjson.contains(canary),
        "artifacts.ndjson leaked canary"
    );

    let quarantine_index =
        std::fs::read_to_string(output.join("quarantine").join("index.ndjson")).unwrap();
    assert!(
        !quarantine_index.contains(canary),
        "quarantine index leaked canary"
    );

    let pack_manifest = std::fs::read_to_string(output.join("pack_manifest.json")).unwrap();
    assert!(
        !pack_manifest.contains(canary),
        "pack_manifest leaked canary"
    );

    // Verify sanitized output does not contain the canary.
    let sanitized_dir = output.join("sanitized");
    let mut sanitized_files = std::fs::read_dir(&sanitized_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .collect::<Vec<_>>();
    sanitized_files.sort();
    assert_eq!(sanitized_files.len(), 1);

    let sanitized_bytes = std::fs::read(&sanitized_files[0]).unwrap();
    let sanitized_text = String::from_utf8_lossy(&sanitized_bytes);
    assert!(!sanitized_text.contains(canary), "sanitized leaked canary");
    assert!(
        sanitized_text.contains("{{PII.Canary}}"),
        "expected redact marker"
    );
}

#[test]
fn logs_use_structured_json_schema_v1() {
    let input = TestDir::new("log_schema_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input");

    let policy = TestDir::new("log_schema_policy");
    std::fs::write(
        policy.join("policy.json"),
        policy_json_single_class("NO_MATCH", r#"{ "kind": "REDACT" }"#),
    )
    .expect("write policy.json");

    let output = TestDir::new("log_schema_output");
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

    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut saw_any = false;
    for line in stderr.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        saw_any = true;
        let v: serde_json::Value = serde_json::from_str(line).expect("stderr line must be json");
        assert!(v.get("level").is_some(), "missing level");
        assert!(v.get("event").is_some(), "missing event");
        assert!(v.get("run_id").is_some(), "missing run_id");
        assert!(v.get("policy_id").is_some(), "missing policy_id");
    }
    assert!(saw_any, "expected structured log lines on stderr");
}

#[test]
fn residual_verification_quarantines_on_high_residual() {
    let input = TestDir::new("residual_input");
    std::fs::write(input.join("a.txt"), "card=1234").expect("write input");

    let policy = TestDir::new("residual_policy");
    std::fs::write(
        policy.join("policy.json"),
        policy_json_single_class("1234", r#"{ "kind": "MASK", "keep_last": 4 }"#),
    )
    .expect("write policy.json");

    let output = TestDir::new("residual_output");
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

    let quarantine_index =
        std::fs::read_to_string(output.join("quarantine").join("index.ndjson")).unwrap();
    assert!(
        quarantine_index.contains("VERIFICATION_FAILED"),
        "expected VERIFICATION_FAILED quarantine"
    );

    // No outputs should be committed for verification-failed artifacts.
    let sanitized_dir = output.join("sanitized");
    let has_any_file = std::fs::read_dir(&sanitized_dir)
        .unwrap()
        .any(|e| e.unwrap().path().is_file());
    assert!(!has_any_file, "sanitized should be empty");
}

#[test]
fn determinism_double_run_produces_identical_outputs() {
    let input = TestDir::new("det_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input");
    std::fs::write(input.join("b.json"), r#"{"b":2,"a":1}"#).expect("write input");

    let policy = TestDir::new("det_policy");
    std::fs::write(
        policy.join("policy.json"),
        policy_json_single_class("NO_MATCH", r#"{ "kind": "REDACT" }"#),
    )
    .expect("write policy.json");

    let out1 = TestDir::new("det_out1");
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

    let out2 = TestDir::new("det_out2");
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
fn verify_fails_on_tampered_verified_output() {
    let input = TestDir::new("verify_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input");

    let policy = TestDir::new("verify_policy");
    std::fs::write(
        policy.join("policy.json"),
        policy_json_single_class("TAMPER", r#"{ "kind": "REDACT" }"#),
    )
    .expect("write policy.json");

    let output = TestDir::new("verify_output");
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

    // Tamper with a VERIFIED output to ensure `veil verify` catches residuals.
    let sanitized_dir = output.join("sanitized");
    let sanitized_file = std::fs::read_dir(&sanitized_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_file())
        .expect("find sanitized file");
    let mut bytes = std::fs::read(&sanitized_file).unwrap();
    bytes.extend_from_slice(b"\nTAMPER\n");
    std::fs::write(&sanitized_file, bytes).unwrap();

    let verify = veil_cmd()
        .arg("verify")
        .arg("--pack")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil verify");
    assert_eq!(verify.status.code(), Some(2));
}

#[test]
fn atomic_commit_no_partial_files_in_sanitized_on_failpoint() {
    let input = TestDir::new("atomic_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input");

    let policy = TestDir::new("atomic_policy");
    std::fs::write(
        policy.join("policy.json"),
        policy_json_single_class("NO_MATCH", r#"{ "kind": "REDACT" }"#),
    )
    .expect("write policy.json");

    let output = TestDir::new("atomic_output");
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
        .expect("run veil run with failpoint");

    assert_eq!(out.status.code(), Some(1));

    let sanitized_dir = output.join("sanitized");
    let any_file = std::fs::read_dir(&sanitized_dir)
        .unwrap()
        .any(|e| e.unwrap().path().is_file());
    assert!(!any_file, "sanitized contains partial outputs");
    assert!(!output.join("pack_manifest.json").exists());
}
