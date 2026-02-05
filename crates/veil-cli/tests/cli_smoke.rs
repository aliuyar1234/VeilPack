use std::path::{Path, PathBuf};
use std::process::Command;

use veil_domain::{
    ArtifactSortKey, compute_input_corpus_id, compute_run_id, hash_artifact_id,
    hash_source_locator_hash,
};

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

#[cfg(unix)]
#[test]
fn run_rejects_output_symlink_path() {
    use std::os::unix::fs::symlink;

    let input = TestDir::new("symlink_output_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("symlink_output_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let real_output = TestDir::new("symlink_output_real");
    let link_parent = TestDir::new("symlink_output_link_parent");
    let output_link = link_parent.join("output_link");
    symlink(real_output.path(), &output_link).expect("create output symlink");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(&output_link)
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[cfg(unix)]
#[test]
fn run_rejects_workdir_symlink_path() {
    use std::os::unix::fs::symlink;

    let input = TestDir::new("symlink_workdir_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("symlink_workdir_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("symlink_workdir_output");
    let real_workdir = TestDir::new("symlink_workdir_real");
    let links = TestDir::new("symlink_workdir_links");
    let workdir_link = links.join("workdir_link");
    symlink(real_workdir.path(), &workdir_link).expect("create workdir symlink");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--workdir")
        .arg(&workdir_link)
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[cfg(unix)]
#[test]
fn run_fails_when_input_contains_symlink_entry() {
    use std::os::unix::fs::symlink;

    let input = TestDir::new("symlink_input_entry_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");
    let outside = TestDir::new("symlink_input_entry_outside");
    let outside_file = outside.join("outside.txt");
    std::fs::write(&outside_file, "outside").expect("write outside file");
    symlink(&outside_file, input.join("linked.txt")).expect("create input symlink");

    let policy = TestDir::new("symlink_input_entry_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("symlink_input_entry_output");
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
}

#[cfg(windows)]
#[test]
fn run_rejects_output_reparse_symlink_path() {
    use std::os::windows::fs::symlink_dir;

    let input = TestDir::new("reparse_output_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("reparse_output_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let real_output = TestDir::new("reparse_output_real");
    let links = TestDir::new("reparse_output_links");
    let output_link = links.join("output_link");

    // Symlink creation may require privileges on some hosts; skip when unavailable.
    if symlink_dir(real_output.path(), &output_link).is_err() {
        return;
    }

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(&output_link)
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_valid_args_produces_pack_with_quarantines() {
    let input = TestDir::new("input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");
    std::fs::write(input.join("b.bin"), b"\x00\x01\x02").expect("write input file");

    let policy = TestDir::new("policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

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

    let quarantine_index = std::fs::read_to_string(output.join("quarantine").join("index.ndjson"))
        .expect("read quarantine index");
    assert!(!quarantine_index.contains("a.txt"));

    let artifacts_ndjson =
        std::fs::read_to_string(output.join("evidence").join("artifacts.ndjson"))
            .expect("read artifacts.ndjson");
    assert!(!artifacts_ndjson.contains("a.txt"));

    let run_manifest = std::fs::read_to_string(output.join("evidence").join("run_manifest.json"))
        .expect("read run_manifest.json");
    assert!(!run_manifest.contains("a.txt"));
}

#[test]
fn run_accepts_max_workers_flag() {
    let input = TestDir::new("max_workers_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("max_workers_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("max_workers_output");
    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .args(["--max-workers", "2"])
        .output()
        .expect("run veil run");

    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("\"event\":\"max_workers_single_threaded_baseline\""),
        "expected advisory warning for max-workers>1"
    );
}

#[test]
fn run_resumes_when_in_progress_marker_and_ledger_exist() {
    let input = TestDir::new("resume_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("resume_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");
    let policy_id = veil_policy::compute_policy_id(policy.path()).expect("compute policy_id");

    let bytes = std::fs::read(input.join("a.txt")).expect("read input file");
    let artifact_id = hash_artifact_id(&bytes);
    let source_locator_hash = hash_source_locator_hash("a.txt");
    let mut keys = vec![ArtifactSortKey::new(artifact_id, source_locator_hash)];
    let input_corpus_id = compute_input_corpus_id(&mut keys);
    let run_id = compute_run_id(env!("CARGO_PKG_VERSION"), &policy_id, &input_corpus_id);

    let output = TestDir::new("resume_output");
    std::fs::create_dir_all(output.join("sanitized")).expect("create sanitized");
    std::fs::create_dir_all(output.join("quarantine")).expect("create quarantine");
    std::fs::create_dir_all(output.join("evidence")).expect("create evidence");
    std::fs::create_dir_all(output.join(".veil_work")).expect("create workdir");

    let marker_path = output.join(".veil_work").join("in_progress.marker");
    std::fs::write(&marker_path, run_id.to_string()).expect("write marker");

    let ledger_path = output.join("evidence").join("ledger.sqlite3");
    let _ledger = veil_evidence::Ledger::create_new(
        &ledger_path,
        env!("CARGO_PKG_VERSION"),
        &policy_id,
        &run_id,
        &input_corpus_id,
    )
    .expect("create ledger");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run (resume)");

    assert_eq!(out.status.code(), Some(0));
    assert!(output.join("pack_manifest.json").is_file());
    assert!(!marker_path.exists());
}

#[test]
fn run_resume_refuses_when_policy_mismatches_in_progress_pack() {
    let input = TestDir::new("mismatch_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy_a = TestDir::new("policy_a");
    std::fs::write(
        policy_a.join("policy.json"),
        minimal_policy_json("NO_MATCH_A"),
    )
    .expect("write policy.json");
    let policy_id_a = veil_policy::compute_policy_id(policy_a.path()).expect("compute policy_id");

    let bytes = std::fs::read(input.join("a.txt")).expect("read input file");
    let artifact_id = hash_artifact_id(&bytes);
    let source_locator_hash = hash_source_locator_hash("a.txt");
    let mut keys = vec![ArtifactSortKey::new(artifact_id, source_locator_hash)];
    let input_corpus_id = compute_input_corpus_id(&mut keys);
    let run_id = compute_run_id(env!("CARGO_PKG_VERSION"), &policy_id_a, &input_corpus_id);

    let output = TestDir::new("mismatch_output");
    std::fs::create_dir_all(output.join("sanitized")).expect("create sanitized");
    std::fs::create_dir_all(output.join("quarantine")).expect("create quarantine");
    std::fs::create_dir_all(output.join("evidence")).expect("create evidence");
    std::fs::create_dir_all(output.join(".veil_work")).expect("create workdir");

    let marker_path = output.join(".veil_work").join("in_progress.marker");
    std::fs::write(&marker_path, run_id.to_string()).expect("write marker");

    let ledger_path = output.join("evidence").join("ledger.sqlite3");
    let _ledger = veil_evidence::Ledger::create_new(
        &ledger_path,
        env!("CARGO_PKG_VERSION"),
        &policy_id_a,
        &run_id,
        &input_corpus_id,
    )
    .expect("create ledger");

    let policy_b = TestDir::new("policy_b");
    std::fs::write(
        policy_b.join("policy.json"),
        minimal_policy_json("NO_MATCH_B"),
    )
    .expect("write policy.json");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy_b.path())
        .output()
        .expect("run veil run (policy mismatch)");

    assert_eq!(out.status.code(), Some(3));
    assert!(marker_path.exists());
}

#[test]
fn run_resume_refuses_when_pack_manifest_already_exists() {
    let input = TestDir::new("resume_finalized_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input file");

    let policy = TestDir::new("resume_finalized_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");
    let policy_id = veil_policy::compute_policy_id(policy.path()).expect("compute policy_id");

    let bytes = std::fs::read(input.join("a.txt")).expect("read input file");
    let artifact_id = hash_artifact_id(&bytes);
    let source_locator_hash = hash_source_locator_hash("a.txt");
    let mut keys = vec![ArtifactSortKey::new(artifact_id, source_locator_hash)];
    let input_corpus_id = compute_input_corpus_id(&mut keys);
    let run_id = compute_run_id(env!("CARGO_PKG_VERSION"), &policy_id, &input_corpus_id);

    let output = TestDir::new("resume_finalized_output");
    std::fs::create_dir_all(output.join("sanitized")).expect("create sanitized");
    std::fs::create_dir_all(output.join("quarantine")).expect("create quarantine");
    std::fs::create_dir_all(output.join("evidence")).expect("create evidence");
    std::fs::create_dir_all(output.join(".veil_work")).expect("create workdir");

    let marker_path = output.join(".veil_work").join("in_progress.marker");
    std::fs::write(&marker_path, run_id.to_string()).expect("write marker");

    let ledger_path = output.join("evidence").join("ledger.sqlite3");
    let _ledger = veil_evidence::Ledger::create_new(
        &ledger_path,
        env!("CARGO_PKG_VERSION"),
        &policy_id,
        &run_id,
        &input_corpus_id,
    )
    .expect("create ledger");

    std::fs::write(
        output.join("pack_manifest.json"),
        br#"{"pack_schema_version":"pack.v1","tool_version":"x","run_id":"x","policy_id":"x","input_corpus_id":"x","tokenization_enabled":false,"quarantine_copy_enabled":false,"ledger_schema_version":"ledger.v1"}"#,
    )
    .expect("write pack manifest");

    let out = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .output()
        .expect("run veil run (resume)");

    assert_eq!(out.status.code(), Some(3));
    assert!(marker_path.exists());
}

#[test]
fn usage_errors_redact_unexpected_argument_values() {
    let secret = "TOP_SECRET_INLINE_ARG";
    let out = veil_cmd()
        .arg("run")
        .arg(secret)
        .output()
        .expect("run veil run");
    assert_eq!(out.status.code(), Some(3));

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(secret),
        "usage error should not echo unexpected argument content"
    );
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
