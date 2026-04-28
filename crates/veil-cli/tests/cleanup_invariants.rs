//! Tests that lock in invariants from the Phase 0-5 cleanup. If any of these
//! fail, the codebase has regressed toward pre-cleanup patterns.

use std::path::Path;

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

fn read_all_rs_under(dir: &Path) -> Vec<(std::path::PathBuf, String)> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<(std::path::PathBuf, String)>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                if p.file_name().and_then(|n| n.to_str()) == Some("target") {
                    continue;
                }
                walk(&p, out);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs")
                && let Ok(s) = std::fs::read_to_string(&p)
            {
                out.push((p, s));
            }
        }
    }
    walk(dir, &mut out);
    out
}

#[test]
fn no_redacted_literals_remain_in_source() {
    // Skip the test file itself (this file mentions the literal in a doc comment).
    let crates = workspace_root().join("crates");
    let mut hits = Vec::new();
    for (path, src) in read_all_rs_under(&crates) {
        // Skip this very test file.
        if path.file_name().and_then(|n| n.to_str()) == Some("cleanup_invariants.rs") {
            continue;
        }
        for (i, line) in src.lines().enumerate() {
            // Match the literal "(redacted)" string occurrence.
            if line.contains("(redacted)") {
                hits.push(format!("{}:{} {}", path.display(), i + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "(redacted) literal should not appear in source:\n{}",
        hits.join("\n")
    );
}

#[test]
fn no_result_exitcode_in_pipeline_signatures() {
    // The Phase 2 sweep replaced Result<T, ExitCode> with Result<T, AppError>.
    // Catch any drift back to the old pattern.
    let crates = workspace_root().join("crates");
    let mut hits = Vec::new();
    for (path, src) in read_all_rs_under(&crates) {
        if path.file_name().and_then(|n| n.to_str()) == Some("cleanup_invariants.rs") {
            continue;
        }
        // Look for Result<..., ExitCode> in any form.
        for (i, line) in src.lines().enumerate() {
            // crude but effective: match the pattern in fn signatures.
            if line.contains("Result<") && line.contains(", ExitCode>") {
                hits.push(format!("{}:{} {}", path.display(), i + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "Result<_, ExitCode> should not appear in pipeline signatures (use AppError):\n{}",
        hits.join("\n")
    );
}

#[test]
fn no_dead_allow_attributes_on_pub_fields() {
    // Phase 0 deleted #[allow(dead_code)] on RunContext/RunPaths fields.
    // Catch any drift.
    let crates = workspace_root().join("crates");
    for (path, src) in read_all_rs_under(&crates) {
        if path.file_name().and_then(|n| n.to_str()) == Some("cleanup_invariants.rs") {
            continue;
        }
        // "// allowed: ..." doc-style markers don't match this.
        // Look for `#[allow(dead_code)]` immediately preceding `pub(crate)` or `pub` field/struct lines.
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim() == "#[allow(dead_code)]"
                && let Some(next) = lines.get(i + 1)
            {
                let nxt = next.trim_start();
                // It's allowed if it's on `pub use` aliases or whole-module
                // shims; only flag struct fields (line ends with `,`).
                if (nxt.starts_with("pub(crate) ") || nxt.starts_with("pub "))
                    && nxt.contains(':')
                    && nxt.trim_end().ends_with(',')
                {
                    panic!(
                        "dead_code on pub field: {}:{}\n  {}\n  {}",
                        path.display(),
                        i + 1,
                        line,
                        next
                    );
                }
            }
        }
    }
}

#[test]
fn workspace_uses_workspace_dependencies_table() {
    // Cargo.toml at workspace root must have [workspace.dependencies].
    let cargo = workspace_root().join("Cargo.toml");
    let s = std::fs::read_to_string(&cargo).expect("read root Cargo.toml");
    assert!(
        s.contains("[workspace.dependencies]"),
        "workspace Cargo.toml must define [workspace.dependencies]"
    );
    assert!(
        s.contains("[workspace.lints"),
        "workspace Cargo.toml must define [workspace.lints]"
    );
}

#[test]
fn no_println_or_eprintln_in_pipeline_crates() {
    // tracing migration should have removed all println!/eprintln! from
    // pipeline crates. Help printers in main.rs are exempt.
    // main.rs has the help printer; logging.rs is the tracing layer's
    // bottom-of-stack writer that actually emits to stderr.
    let exempt_files = &["main.rs", "logging.rs"];
    let crates = workspace_root().join("crates");
    let mut hits = Vec::new();
    for (path, src) in read_all_rs_under(&crates) {
        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if fname == "cleanup_invariants.rs" {
            continue;
        }
        if exempt_files.contains(&fname) {
            continue;
        }
        // Skip tests files and test modules; they're allowed to print.
        let path_str = path.to_string_lossy();
        if path_str.contains("/tests/") || path_str.contains("\\tests\\") {
            continue;
        }
        for (i, line) in src.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("println!") || t.starts_with("eprintln!") {
                // Allow inside #[cfg(test)] modules — but we don't track context here, so
                // be conservative: only flag if the file isn't an exception.
                // Empirically only main.rs has println! after Phase 2, so this is safe.
                hits.push(format!("{}:{} {}", path.display(), i + 1, t));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "println!/eprintln! should not appear in pipeline source (use tracing):\n{}",
        hits.join("\n")
    );
}
