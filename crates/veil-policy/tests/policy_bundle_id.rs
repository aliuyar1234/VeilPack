use std::path::{Path, PathBuf};

use veil_policy::compute_policy_id;

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("veil_policy_test_{}_{}", std::process::id(), label));
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

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(path, bytes).expect("write file");
}

#[test]
fn policy_id_is_order_independent() {
    let a = TestDir::new("a");
    write_file(&a.join("policy.json"), br#"{"schema_version":"policy.v1"}"#);
    write_file(&a.join("dicts/custom.txt"), b"ALPHA\nBETA\n");
    write_file(&a.join("rules/extra.json"), br#"{"k":1}"#);

    let b = TestDir::new("b");
    // Same bytes but created in a different order.
    write_file(&b.join("rules/extra.json"), br#"{"k":1}"#);
    write_file(&b.join("dicts/custom.txt"), b"ALPHA\nBETA\n");
    write_file(&b.join("policy.json"), br#"{"schema_version":"policy.v1"}"#);

    let id_a = compute_policy_id(a.path()).expect("policy id a");
    let id_b = compute_policy_id(b.path()).expect("policy id b");

    assert_eq!(id_a, id_b);
}

#[test]
fn policy_id_changes_on_content_change() {
    let a = TestDir::new("content_change");
    let policy_path = a.join("policy.json");
    write_file(&policy_path, br#"{"schema_version":"policy.v1"}"#);
    write_file(&a.join("dicts/custom.txt"), b"ALPHA\n");

    let id_1 = compute_policy_id(a.path()).expect("policy id");
    write_file(&policy_path, br#"{"schema_version":"policy.v1","x":1}"#);
    let id_2 = compute_policy_id(a.path()).expect("policy id");

    assert_ne!(id_1, id_2);
}
