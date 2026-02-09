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

#[test]
fn verify_enforces_pack_and_ledger_compatibility_matrix() {
    let input = TestDir::new("compat_matrix_input");
    std::fs::write(input.join("a.txt"), "hello").expect("write input");

    let policy = TestDir::new("compat_matrix_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("compat_matrix_output");
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
    let original = std::fs::read_to_string(&pack_manifest_path).expect("read pack_manifest");
    let manifest_value: serde_json::Value =
        serde_json::from_str(&original).expect("parse pack_manifest");

    let current_ledger = manifest_value
        .get("ledger_schema_version")
        .and_then(|v| v.as_str())
        .expect("ledger_schema_version")
        .to_string();

    struct Case<'a> {
        pack_schema_version: &'a str,
        ledger_schema_version: &'a str,
        expected_code: i32,
    }

    let cases = [
        Case {
            pack_schema_version: "pack.v1",
            ledger_schema_version: &current_ledger,
            expected_code: 0,
        },
        Case {
            pack_schema_version: "pack.v0",
            ledger_schema_version: &current_ledger,
            expected_code: 1,
        },
        Case {
            pack_schema_version: "pack.v1",
            ledger_schema_version: "ledger.v0",
            expected_code: 1,
        },
    ];

    for case in cases {
        let mut v = manifest_value.clone();
        v["pack_schema_version"] = serde_json::Value::String(case.pack_schema_version.to_string());
        v["ledger_schema_version"] =
            serde_json::Value::String(case.ledger_schema_version.to_string());
        std::fs::write(
            &pack_manifest_path,
            serde_json::to_vec(&v).expect("serialize manifest"),
        )
        .expect("write manifest");

        let verify = veil_cmd()
            .arg("verify")
            .arg("--pack")
            .arg(output.path())
            .arg("--policy")
            .arg(policy.path())
            .output()
            .expect("run veil verify");
        assert_eq!(verify.status.code(), Some(case.expected_code));
    }

    std::fs::write(&pack_manifest_path, original).expect("restore manifest");
}
