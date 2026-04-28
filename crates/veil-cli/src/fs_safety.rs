use std::path::{Path, PathBuf};

use serde::Serialize;

pub(crate) fn ensure_dir_exists(path: &Path, kind: &str) -> Result<(), String> {
    let meta = std::fs::metadata(path)
        .map_err(|_| format!("{kind} path does not exist or is not accessible"))?;
    if !meta.is_dir() {
        return Err(format!("{kind} path must be a directory"));
    }
    Ok(())
}

pub(crate) fn ensure_file_exists(path: &Path, kind: &str) -> Result<(), String> {
    let meta = std::fs::metadata(path)
        .map_err(|_| format!("{kind} path does not exist or is not accessible"))?;
    if !meta.is_file() {
        return Err(format!("{kind} path must be a file"));
    }
    Ok(())
}

pub(crate) fn ensure_policy_json_exists(policy_dir: &Path) -> Result<(), String> {
    let path = policy_dir.join("policy.json");
    ensure_file_exists(&path, "policy.json")?;
    Ok(())
}

pub(crate) fn is_unsafe_reparse_point(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        let _ = meta;
        false
    }
}

pub(crate) fn ensure_existing_path_components_safe(path: &Path, kind: &str) -> Result<(), String> {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp.as_os_str());
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) {
                    return Err(format!("{kind} path points to an unsafe location"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(format!("{kind} path is not accessible"));
            }
        }
    }
    Ok(())
}

pub(crate) fn ensure_existing_file_safe(path: &Path, kind: &str) -> Result<(), String> {
    ensure_existing_path_components_safe(path, kind)?;
    let meta = std::fs::symlink_metadata(path).map_err(|_| format!("{kind} is not accessible"))?;
    if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) || !meta.is_file() {
        return Err(format!("{kind} path is unsafe"));
    }
    Ok(())
}

pub(crate) fn dir_total_file_bytes(root: &Path) -> Result<u64, ()> {
    ensure_existing_path_components_safe(root, "workdir").map_err(|_| ())?;
    let mut total = 0_u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|_| ())?;
        for entry in entries {
            let entry = entry.map_err(|_| ())?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).map_err(|_| ())?;
            if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) {
                return Err(());
            }
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if meta.is_file() {
                total = total.checked_add(meta.len()).ok_or(())?;
            }
        }
    }
    Ok(total)
}

pub(crate) fn sync_parent_dir(path: &Path) -> Result<(), ()> {
    let parent = path.parent().ok_or(())?;
    ensure_existing_path_components_safe(parent, "output").map_err(|_| ())?;
    #[cfg(unix)]
    {
        let dir = std::fs::File::open(parent).map_err(|_| ())?;
        dir.sync_all().map_err(|_| ())?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

pub(crate) fn ensure_output_fresh_or_resumable(
    output: &Path,
    workdir: &Path,
    quarantine_copy_enabled: bool,
) -> Result<(), String> {
    ensure_existing_path_components_safe(output, "output")?;
    ensure_existing_path_components_safe(workdir, "workdir")?;

    match std::fs::metadata(output) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err("output path must be a directory when it exists".to_string());
            }

            let mut entries =
                std::fs::read_dir(output).map_err(|_| "output path is not readable".to_string())?;
            if entries.next().is_none() {
                return Ok(());
            }

            let marker_path = workdir.join("in_progress.marker");
            let marker_meta = std::fs::metadata(&marker_path)
                .map_err(|_| "output directory must be empty or resumable".to_string())?;
            if !marker_meta.is_file() {
                return Err("output directory contains an invalid in-progress marker".to_string());
            }

            let ledger_path = output.join("evidence").join("ledger.sqlite3");
            let ledger_meta = std::fs::metadata(&ledger_path).map_err(|_| {
                "output directory must be empty or resumable (missing ledger)".to_string()
            })?;
            if !ledger_meta.is_file() {
                return Err("ledger.sqlite3 must be a file".to_string());
            }

            let raw_dir = output.join("quarantine").join("raw");
            let raw_present = raw_dir.exists();
            if raw_present != quarantine_copy_enabled {
                return Err("cannot resume with different --quarantine-copy setting".to_string());
            }

            let pack_manifest_path = output.join("pack_manifest.json");
            if let Ok(meta) = std::fs::symlink_metadata(&pack_manifest_path) {
                if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) {
                    return Err(
                        "output directory contains an unsafe pack manifest path".to_string()
                    );
                }
                if meta.is_file() {
                    return Err("output directory already contains a completed pack".to_string());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err("output path is not accessible".to_string());
        }
    }
    Ok(())
}

pub(crate) fn ensure_dir_exists_or_create(path: &Path, kind: &str) -> Result<(), String> {
    ensure_existing_path_components_safe(path, kind)?;
    match std::fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(format!("{kind} path must be a directory"));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .map_err(|_| format!("{kind} path could not be created"))?;
        }
        Err(_) => {
            return Err(format!("{kind} path is not accessible"));
        }
    }
    Ok(())
}

pub(crate) fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), ()> {
    ensure_existing_path_components_safe(path, "output").map_err(|_| ())?;
    let dir = path.parent().ok_or(())?;
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or(())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    if let Ok(meta) = std::fs::symlink_metadata(&tmp_path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        return Err(());
    }

    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    let mut tmp_file = std::fs::File::create(&tmp_path).map_err(|_| ())?;
    std::io::Write::write_all(&mut tmp_file, &bytes).map_err(|_| ())?;
    tmp_file.sync_all().map_err(|_| ())?;
    drop(tmp_file);
    ensure_existing_path_components_safe(path, "output").map_err(|_| ())?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(());
    }
    std::fs::rename(&tmp_path, path).map_err(|_| ())?;
    sync_parent_dir(path)?;
    Ok(())
}

pub(crate) fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    ensure_existing_path_components_safe(path, "output").map_err(|_| ())?;
    let dir = path.parent().ok_or(())?;
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or(())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    if let Ok(meta) = std::fs::symlink_metadata(&tmp_path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        return Err(());
    }

    let mut tmp_file = std::fs::File::create(&tmp_path).map_err(|_| ())?;
    std::io::Write::write_all(&mut tmp_file, bytes).map_err(|_| ())?;
    tmp_file.sync_all().map_err(|_| ())?;
    drop(tmp_file);
    ensure_existing_path_components_safe(path, "output").map_err(|_| ())?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(());
    }
    std::fs::rename(&tmp_path, path).map_err(|_| ())?;
    sync_parent_dir(path)?;
    Ok(())
}

pub(crate) fn write_bytes_sync(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    ensure_existing_path_components_safe(path, "output").map_err(|_| ())?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        return Err(());
    }
    let mut file = std::fs::File::create(path).map_err(|_| ())?;
    std::io::Write::write_all(&mut file, bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::path::PathBuf;

    #[cfg(unix)]
    fn test_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "veil_cli_fs_safety_test_{}_{}",
            std::process::id(),
            label.replace(['\\', '/', ':'], "_")
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[cfg(unix)]
    #[test]
    fn safe_path_check_rejects_symlink_component() {
        use super::ensure_existing_path_components_safe;
        use std::os::unix::fs::symlink;

        let dir = test_dir("symlink_component");
        let real = dir.join("real");
        let link = dir.join("link");
        std::fs::create_dir_all(&real).expect("create real dir");
        symlink(&real, &link).expect("create symlink");

        let candidate = link.join("child");
        let err = ensure_existing_path_components_safe(&candidate, "output")
            .expect_err("unsafe location");
        assert!(err.contains("unsafe location"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
