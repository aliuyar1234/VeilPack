use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn veil_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_veil"))
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let mut path = canonical_temp_root();
        path.push(format!(
            "veil_additional_demo_test_{}_{}",
            std::process::id(),
            label.replace(['\\', '/', ':'], "_")
        ));

        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn canonical_temp_root() -> PathBuf {
    let path = std::env::temp_dir();
    #[cfg(unix)]
    {
        std::fs::canonicalize(&path).unwrap_or(path)
    }
    #[cfg(not(unix))]
    {
        path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cwd = std::env::current_dir().expect("current_dir");
    let candidates = [
        manifest_dir.clone(),
        manifest_dir.join("..").join(".."),
        cwd.clone(),
    ];

    for candidate in candidates {
        let candidate = candidate.canonicalize().unwrap_or(candidate);
        if candidate
            .join("examples")
            .join("archive-redaction")
            .is_dir()
        {
            return candidate;
        }
    }

    panic!("could not locate repository root from CARGO_MANIFEST_DIR/current_dir");
}

fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}

fn normalize_json_strings(value: &mut Value) {
    match value {
        Value::String(s) => *s = normalize_newlines(s),
        Value::Array(items) => {
            for item in items {
                normalize_json_strings(item);
            }
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                normalize_json_strings(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn parse_normalized_ndjson(s: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in s.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut value: Value = serde_json::from_str(line).expect("parse ndjson record");
        normalize_json_strings(&mut value);
        out.push(value);
    }
    out
}

fn assert_ndjson_example(root: &Path, demo_name: &str) {
    let demo = root.join("examples").join(demo_name);
    let input = demo.join("input");
    let policy = demo.join("policy");
    let expected_path = demo.join("expected").join("sample.sanitized.ndjson");

    assert!(input.is_dir(), "demo input directory missing");
    assert!(policy.is_dir(), "demo policy directory missing");
    assert!(expected_path.is_file(), "expected output file missing");

    let expected = std::fs::read_to_string(&expected_path).expect("read expected output");

    let output = TestDir::new(demo_name);
    let out = veil_cmd()
        .current_dir(root)
        .arg("run")
        .arg("--input")
        .arg(format!("examples/{demo_name}/input"))
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(format!("examples/{demo_name}/policy"))
        .output()
        .expect("run example demo");

    assert_eq!(
        out.status.code(),
        Some(0),
        "{demo_name} demo must verify successfully\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let sanitized_dir = output.path().join("sanitized");
    let mut sanitized_files = std::fs::read_dir(&sanitized_dir)
        .expect("read sanitized dir")
        .map(|e| e.expect("sanitized entry").path())
        .filter(|p| p.is_file())
        .collect::<Vec<_>>();
    sanitized_files.sort();

    assert_eq!(sanitized_files.len(), 1, "expected one sanitized file");
    assert_eq!(
        sanitized_files[0]
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or(""),
        "ndjson",
        "expected sanitized NDJSON output"
    );

    let actual = std::fs::read_to_string(&sanitized_files[0]).expect("read sanitized ndjson");
    assert_eq!(
        parse_normalized_ndjson(&actual),
        parse_normalized_ndjson(&expected)
    );

    let quarantine_index = std::fs::read_to_string(output.path().join("quarantine/index.ndjson"))
        .expect("read quarantine index");
    assert!(
        quarantine_index.trim().is_empty(),
        "demo should not quarantine artifacts"
    );
}

#[test]
fn archive_redaction_example_stays_valid() {
    let root = repo_root();
    assert_ndjson_example(&root, "archive-redaction");
}

#[test]
fn email_redaction_example_stays_valid() {
    let root = repo_root();
    assert_ndjson_example(&root, "email-redaction");
}
