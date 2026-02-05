use std::path::PathBuf;
use std::process::Command;

#[test]
fn boundary_fitness_check_passes() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/<pkg> layout")
        .to_path_buf();

    let script = workspace_root.join("checks").join("boundary_fitness.py");

    let out = Command::new("python")
        .arg(script)
        .current_dir(&workspace_root)
        .output()
        .expect("run boundary_fitness.py");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "boundary fitness failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("PASS"), "expected PASS.\nstdout:\n{stdout}");
}
