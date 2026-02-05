use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use blake3::Hasher;
use veil_domain::{Digest32, PolicyId};

#[derive(Debug)]
pub enum PolicyBundleIdError {
    NotADirectory,
    PathNotUtf8,
    PathTooLong,
    Io,
}

pub fn compute_policy_id(bundle_dir: &Path) -> Result<PolicyId, PolicyBundleIdError> {
    let meta = std::fs::metadata(bundle_dir).map_err(|_| PolicyBundleIdError::Io)?;
    if !meta.is_dir() {
        return Err(PolicyBundleIdError::NotADirectory);
    }

    let mut files = Vec::<BundleFile>::new();
    collect_files(bundle_dir, bundle_dir, &mut files)?;
    files.sort_by(|a, b| a.normalized_rel_path.cmp(&b.normalized_rel_path));

    let mut hasher = Hasher::new();
    for file in files {
        let path_bytes = file.normalized_rel_path.as_bytes();
        let path_len: u32 = path_bytes
            .len()
            .try_into()
            .map_err(|_| PolicyBundleIdError::PathTooLong)?;

        let bytes = std::fs::read(&file.abs_path).map_err(|_| PolicyBundleIdError::Io)?;
        let file_len: u64 = bytes.len() as u64;

        hasher.update(&path_len.to_le_bytes());
        hasher.update(path_bytes);
        hasher.update(&file_len.to_le_bytes());
        hasher.update(&bytes);
    }

    Ok(PolicyId::from_digest(Digest32::from_bytes(
        *hasher.finalize().as_bytes(),
    )))
}

#[derive(Debug)]
struct BundleFile {
    normalized_rel_path: String,
    abs_path: PathBuf,
}

fn collect_files(
    root: &Path,
    current: &Path,
    out: &mut Vec<BundleFile>,
) -> Result<(), PolicyBundleIdError> {
    for entry in std::fs::read_dir(current).map_err(|_| PolicyBundleIdError::Io)? {
        let entry = entry.map_err(|_| PolicyBundleIdError::Io)?;
        let path = entry.path();
        let meta = entry.metadata().map_err(|_| PolicyBundleIdError::Io)?;

        if meta.is_dir() {
            collect_files(root, &path, out)?;
            continue;
        }

        if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| PolicyBundleIdError::Io)?;
            let normalized_rel_path = normalize_rel_path(rel)?;
            out.push(BundleFile {
                normalized_rel_path,
                abs_path: path,
            });
        }
    }
    Ok(())
}

fn normalize_rel_path(rel: &Path) -> Result<String, PolicyBundleIdError> {
    let mut out = String::new();
    for (i, comp) in rel.components().enumerate() {
        let name = match comp {
            std::path::Component::Normal(os) => os,
            // Policy bundles are rooted under the given directory; any other component indicates an
            // unexpected path shape.
            _ => return Err(PolicyBundleIdError::Io),
        };

        let name = os_str_to_str(name)?;
        if i > 0 {
            out.push('/');
        }
        out.push_str(name);
    }
    Ok(out)
}

fn os_str_to_str(s: &OsStr) -> Result<&str, PolicyBundleIdError> {
    s.to_str().ok_or(PolicyBundleIdError::PathNotUtf8)
}
