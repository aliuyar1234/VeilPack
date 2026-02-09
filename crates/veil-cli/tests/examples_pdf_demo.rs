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
            "veil_pdf_demo_test_{}_{}",
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
        if candidate.join("examples").join("pdf-redaction").is_dir() {
            return candidate;
        }
    }

    panic!("could not locate repository root from CARGO_MANIFEST_DIR/current_dir");
}

fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[test]
fn pdf_redaction_example_stays_valid() {
    let root = repo_root();
    let demo = root.join("examples").join("pdf-redaction");
    let input = demo.join("input");
    let policy = demo.join("policy");
    let expected_path = demo.join("expected").join("invoice.sanitized.ndjson");

    assert!(input.is_dir(), "demo input directory missing");
    assert!(policy.is_dir(), "demo policy directory missing");
    assert!(expected_path.is_file(), "expected output file missing");

    let expected = std::fs::read_to_string(&expected_path).expect("read expected output");

    let output = TestDir::new("output");
    let out = veil_cmd()
        .current_dir(&root)
        .arg("run")
        .arg("--input")
        .arg("examples/pdf-redaction/input")
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg("examples/pdf-redaction/policy")
        .output()
        .expect("run pdf demo");

    assert_eq!(
        out.status.code(),
        Some(0),
        "pdf demo must verify successfully\nstdout:\n{}\nstderr:\n{}",
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
        "expected sanitized NDJSON output for PDF input"
    );

    let actual = std::fs::read_to_string(&sanitized_files[0]).expect("read sanitized ndjson");
    assert_eq!(normalize_newlines(&actual), normalize_newlines(&expected));

    let quarantine_index = std::fs::read_to_string(output.path().join("quarantine/index.ndjson"))
        .expect("read quarantine index");
    assert!(
        quarantine_index.trim().is_empty(),
        "demo should not quarantine artifacts"
    );
}
