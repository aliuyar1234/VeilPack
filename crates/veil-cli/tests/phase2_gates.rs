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
            "veil_phase2_test_{}_{}",
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
    policy_id: String,
    tokenization_enabled: bool,
    #[serde(default)]
    tokenization_scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RunManifestRead {
    tokenization_enabled: bool,
    #[serde(default)]
    tokenization_scope: Option<String>,
    proof_scope: String,
    proof_key_commitment: String,
}

#[test]
fn policy_lint_prints_policy_id() {
    let policy = TestDir::new("policy_lint_ok");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let expected = veil_policy::compute_policy_id(policy.path()).expect("compute policy_id");

    let out = veil_cmd()
        .args(["policy", "lint", "--policy"])
        .arg(policy.path())
        .output()
        .expect("run veil policy lint");

    assert_eq!(out.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), expected.to_string());
}

#[test]
fn policy_lint_rejects_unknown_fields() {
    let policy = TestDir::new("policy_lint_unknown");
    std::fs::write(
        policy.join("policy.json"),
        r#"{"schema_version":"policy.v1","classes":[],"defaults":{},"scopes":[],"unknown":1}"#,
    )
    .expect("write policy.json");

    let out = veil_cmd()
        .args(["policy", "lint", "--policy"])
        .arg(policy.path())
        .output()
        .expect("run veil policy lint");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn policy_lint_rejects_non_v1_schema_version() {
    let policy = TestDir::new("policy_lint_schema_mismatch");
    std::fs::write(
        policy.join("policy.json"),
        r#"{"schema_version":"policy.v2","classes":[],"defaults":{},"scopes":[]}"#,
    )
    .expect("write policy.json");

    let out = veil_cmd()
        .args(["policy", "lint", "--policy"])
        .arg(policy.path())
        .output()
        .expect("run veil policy lint");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn policy_lint_rejects_non_empty_scopes_in_v1_baseline() {
    let policy = TestDir::new("policy_lint_non_empty_scopes");
    std::fs::write(
        policy.join("policy.json"),
        r#"{
  "schema_version":"policy.v1",
  "classes":[{"class_id":"PII.Test","severity":"HIGH","detectors":[{"kind":"regex","pattern":"NO_MATCH"}],"action":{"kind":"REDACT"}}],
  "defaults":{},
  "scopes":[{"kind":"field_selector","selector":"json_pointer","fields":["/a"]}]
}"#,
    )
    .expect("write policy.json");

    let out = veil_cmd()
        .args(["policy", "lint", "--policy"])
        .arg(policy.path())
        .output()
        .expect("run veil policy lint");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn policy_lint_rejects_tokenize_action_in_v1_baseline() {
    let policy = TestDir::new("policy_lint_tokenize_action");
    std::fs::write(
        policy.join("policy.json"),
        r#"{
  "schema_version":"policy.v1",
  "classes":[{"class_id":"PII.Test","severity":"HIGH","detectors":[{"kind":"regex","pattern":"NO_MATCH"}],"action":{"kind":"TOKENIZE"}}],
  "defaults":{},
  "scopes":[]
}"#,
    )
    .expect("write policy.json");

    let out = veil_cmd()
        .args(["policy", "lint", "--policy"])
        .arg(policy.path())
        .output()
        .expect("run veil policy lint");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn policy_lint_rejects_mask_keep_last_zero() {
    let policy = TestDir::new("policy_lint_mask_zero");
    std::fs::write(
        policy.join("policy.json"),
        r#"{
  "schema_version":"policy.v1",
  "classes":[{"class_id":"PII.Test","severity":"HIGH","detectors":[{"kind":"regex","pattern":"NO_MATCH"}],"action":{"kind":"MASK","keep_last":0}}],
  "defaults":{},
  "scopes":[]
}"#,
    )
    .expect("write policy.json");

    let out = veil_cmd()
        .args(["policy", "lint", "--policy"])
        .arg(policy.path())
        .output()
        .expect("run veil policy lint");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn verify_refuses_on_policy_id_mismatch() {
    let input = TestDir::new("verify_mismatch_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy_a = TestDir::new("verify_mismatch_policy_a");
    std::fs::write(
        policy_a.join("policy.json"),
        minimal_policy_json("NO_MATCH_A"),
    )
    .expect("write policy.json");

    let output = TestDir::new("verify_mismatch_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy_a.path())
        .output()
        .expect("run veil run");
    assert_eq!(out.status.code(), Some(0));

    let expected_policy_id = veil_policy::compute_policy_id(policy_a.path()).expect("policy id");
    let pack_manifest_json =
        std::fs::read_to_string(output.join("pack_manifest.json")).expect("read pack_manifest");
    let pack_manifest: PackManifestRead =
        serde_json::from_str(&pack_manifest_json).expect("parse pack_manifest");
    assert_eq!(pack_manifest.policy_id, expected_policy_id.to_string());

    let policy_b = TestDir::new("verify_mismatch_policy_b");
    std::fs::write(
        policy_b.join("policy.json"),
        minimal_policy_json("NO_MATCH_B"),
    )
    .expect("write policy.json");

    let out = veil_cmd()
        .arg("verify")
        .arg("--pack")
        .arg(output.path())
        .arg("--policy")
        .arg(policy_b.path())
        .output()
        .expect("run veil verify");

    assert_eq!(out.status.code(), Some(3));
}

#[cfg(unix)]
#[test]
fn verify_fails_closed_when_sanitized_output_is_symlink() {
    use std::os::unix::fs::symlink;

    let input = TestDir::new("verify_symlink_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("verify_symlink_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("verify_symlink_output");
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

    let sanitized_file = std::fs::read_dir(output.join("sanitized"))
        .expect("read sanitized dir")
        .map(|e| e.expect("entry").path())
        .find(|p| p.is_file())
        .expect("find sanitized file");

    let external = TestDir::new("verify_symlink_external");
    let external_file = external.join("outside.txt");
    std::fs::write(&external_file, "outside").expect("write external");

    std::fs::remove_file(&sanitized_file).expect("remove sanitized");
    symlink(&external_file, &sanitized_file).expect("symlink sanitized -> external");

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
fn verify_fails_closed_on_unexpected_sanitized_output_file() {
    let input = TestDir::new("verify_extra_output_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("verify_extra_output_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("verify_extra_output_pack");
    let run = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");
    assert_eq!(run.status.code(), Some(0));

    std::fs::write(output.join("sanitized").join("rogue.txt"), "ROGUE")
        .expect("write unexpected sanitized file");

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

#[cfg(unix)]
#[test]
fn verify_refuses_when_artifacts_evidence_path_is_symlink() {
    use std::os::unix::fs::symlink;

    let input = TestDir::new("verify_artifacts_symlink_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("verify_artifacts_symlink_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("verify_artifacts_symlink_output");
    let run = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");
    assert_eq!(run.status.code(), Some(0));

    let artifacts_path = output.join("evidence").join("artifacts.ndjson");
    let external = TestDir::new("verify_artifacts_symlink_external");
    let external_file = external.join("outside.ndjson");
    std::fs::write(&external_file, "").expect("write external file");
    std::fs::remove_file(&artifacts_path).expect("remove artifacts.ndjson");
    symlink(&external_file, &artifacts_path).expect("symlink artifacts.ndjson");

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
fn run_refuses_tokenization_without_key() {
    let input = TestDir::new("token_no_key_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("token_no_key_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("token_no_key_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .args(["--enable-tokenization", "true"])
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_refuses_key_without_tokenization_enabled() {
    let input = TestDir::new("key_without_token_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("key_without_token_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let key = TestDir::new("key_without_token_keydir");
    let key_path = key.join("secret.key");
    std::fs::write(&key_path, "VEIL_SECRET_KEY_DO_NOT_LEAK").expect("write secret key");

    let output = TestDir::new("key_without_token_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--secret-key-file")
        .arg(&key_path)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_refuses_non_strict_strictness() {
    let input = TestDir::new("non_strict_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("non_strict_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("non_strict_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .args(["--strictness", "permissive"])
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_tokenization_is_disabled_by_default() {
    let input = TestDir::new("token_default_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("token_default_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("token_default_output");
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

    let pack_manifest_json =
        std::fs::read_to_string(output.join("pack_manifest.json")).expect("read pack_manifest");
    let pack_manifest: PackManifestRead =
        serde_json::from_str(&pack_manifest_json).expect("parse pack_manifest");
    assert!(!pack_manifest.tokenization_enabled);
    assert!(pack_manifest.tokenization_scope.is_none());

    let run_manifest_json =
        std::fs::read_to_string(output.join("evidence").join("run_manifest.json"))
            .expect("read run_manifest.json");
    let run_manifest: RunManifestRead =
        serde_json::from_str(&run_manifest_json).expect("parse run_manifest");
    assert!(!run_manifest.tokenization_enabled);
    assert!(run_manifest.tokenization_scope.is_none());
    assert_eq!(run_manifest.proof_scope, "PER_RUN");
    assert!(!run_manifest.proof_key_commitment.trim().is_empty());
}

#[test]
fn run_never_persists_secret_key_plaintext() {
    let input = TestDir::new("token_key_redaction_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("token_key_redaction_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let key = TestDir::new("token_key_redaction_keydir");
    let key_path = key.join("secret.key");
    let secret = "VEIL_SECRET_KEY_DO_NOT_LEAK";
    std::fs::write(&key_path, secret).expect("write secret key");

    let output = TestDir::new("token_key_redaction_output");
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
        .arg(&key_path)
        .output()
        .expect("run veil run");
    assert_eq!(out.status.code(), Some(0));

    let pack_manifest = std::fs::read_to_string(output.join("pack_manifest.json"))
        .expect("read pack_manifest.json");
    assert!(!pack_manifest.contains(secret));

    let quarantine_index = std::fs::read_to_string(output.join("quarantine").join("index.ndjson"))
        .expect("read quarantine index");
    assert!(!quarantine_index.contains(secret));

    let artifacts_ndjson =
        std::fs::read_to_string(output.join("evidence").join("artifacts.ndjson"))
            .expect("read artifacts.ndjson");
    assert!(!artifacts_ndjson.contains(secret));

    let run_manifest_json =
        std::fs::read_to_string(output.join("evidence").join("run_manifest.json"))
            .expect("read run_manifest.json");
    assert!(!run_manifest_json.contains(secret));

    let run_manifest: RunManifestRead =
        serde_json::from_str(&run_manifest_json).expect("parse run_manifest");
    assert!(run_manifest.tokenization_enabled);
    assert_eq!(run_manifest.tokenization_scope.as_deref(), Some("PER_RUN"));
    assert_eq!(run_manifest.proof_scope, "PER_RUN");
    assert!(!run_manifest.proof_key_commitment.trim().is_empty());
}
