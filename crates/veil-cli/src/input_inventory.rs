use std::io::Read;
use std::path::{Path, PathBuf};

use crate::fs_safety::is_unsafe_reparse_point;

#[derive(Debug, Clone)]
pub(crate) struct DiscoveredArtifact {
    pub(crate) sort_key: veil_domain::ArtifactSortKey,
    pub(crate) path: PathBuf,
    pub(crate) size_bytes: u64,
    pub(crate) artifact_type: String,
}

pub(crate) struct EnumeratedCorpus {
    pub(crate) artifacts: Vec<DiscoveredArtifact>,
    pub(crate) corpus_secret: [u8; 32],
}

pub(crate) fn enumerate_input_corpus(input_root: &Path) -> Result<EnumeratedCorpus, String> {
    let mut out = Vec::new();
    let mut corpus_hasher = blake3::Hasher::new();
    collect_input_files(input_root, input_root, &mut out, &mut corpus_hasher)?;
    out.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));
    Ok(EnumeratedCorpus {
        artifacts: out,
        corpus_secret: *corpus_hasher.finalize().as_bytes(),
    })
}

fn collect_input_files(
    root: &Path,
    current: &Path,
    out: &mut Vec<DiscoveredArtifact>,
    corpus_hasher: &mut blake3::Hasher,
) -> Result<(), String> {
    let read_dir = std::fs::read_dir(current)
        .map_err(|_| "input corpus directory is not readable (redacted)".to_string())?;

    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry
            .map_err(|_| "input corpus directory entry could not be read (redacted)".to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| "input corpus contains a non-UTF-8 path (redacted)".to_string())?
            .to_string();
        entries.push((name, entry));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (_, entry) in entries {
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|_| "input corpus entry type could not be read (redacted)".to_string())?;
        if meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta) {
            return Err("input corpus contains an unsafe path (symlink) (redacted)".to_string());
        }

        if meta.is_dir() {
            collect_input_files(root, &path, out, corpus_hasher)?;
            continue;
        }

        if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| "input corpus path normalization failed (redacted)".to_string())?;
            let normalized_rel_path = normalize_rel_path(rel)?;
            let source_locator_hash = veil_domain::hash_source_locator_hash(&normalized_rel_path);

            let size_bytes = meta.len();
            let path_bytes = normalized_rel_path.as_bytes();
            let path_len: u32 = path_bytes
                .len()
                .try_into()
                .map_err(|_| "input corpus path is too long (redacted)".to_string())?;
            corpus_hasher.update(&path_len.to_le_bytes());
            corpus_hasher.update(path_bytes);
            corpus_hasher.update(&size_bytes.to_le_bytes());

            let artifact_id = hash_file_artifact_id_and_update(&path, corpus_hasher)?;

            let artifact_type = classify_artifact_type(&path);
            out.push(DiscoveredArtifact {
                sort_key: veil_domain::ArtifactSortKey::new(artifact_id, source_locator_hash),
                path,
                size_bytes,
                artifact_type,
            });
        } else {
            return Err(
                "input corpus contains an unsupported filesystem entry (redacted)".to_string(),
            );
        }
    }

    Ok(())
}

fn normalize_rel_path(rel: &Path) -> Result<String, String> {
    let mut out = String::new();
    for (i, comp) in rel.components().enumerate() {
        let name = match comp {
            std::path::Component::Normal(os) => os,
            _ => {
                return Err(
                    "input corpus path is not a normalized relative path (redacted)".to_string(),
                );
            }
        };

        let name = name
            .to_str()
            .ok_or_else(|| "input corpus contains a non-UTF-8 path (redacted)".to_string())?;
        if i > 0 {
            out.push('/');
        }
        out.push_str(name);
    }
    Ok(out)
}

fn hash_file_artifact_id_and_update(
    path: &Path,
    corpus_hasher: &mut blake3::Hasher,
) -> Result<veil_domain::ArtifactId, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| "input artifact is not readable (redacted)".to_string())?;

    let mut hasher = blake3::Hasher::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| "input artifact could not be read (redacted)".to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        corpus_hasher.update(&buf[..n]);
    }

    Ok(veil_domain::ArtifactId::from_digest(
        veil_domain::Digest32::from_bytes(*hasher.finalize().as_bytes()),
    ))
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ReadArtifactError {
    Io,
    LimitExceeded,
    IdentityMismatch,
}

pub(crate) fn read_artifact_bytes_for_processing(
    path: &Path,
    expected_size_bytes: u64,
    expected_artifact_id: &veil_domain::ArtifactId,
    max_bytes_per_artifact: u64,
) -> Result<Vec<u8>, ReadArtifactError> {
    if max_bytes_per_artifact == 0 {
        return Err(ReadArtifactError::LimitExceeded);
    }

    let mut file = std::fs::File::open(path).map_err(|_| ReadArtifactError::Io)?;
    if let Ok(meta) = file.metadata()
        && meta.len() > max_bytes_per_artifact
    {
        return Err(ReadArtifactError::LimitExceeded);
    }

    let mut out = Vec::<u8>::new();
    let mut total = 0_u64;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|_| ReadArtifactError::Io)?;
        if n == 0 {
            break;
        }

        let n_u64 = u64::try_from(n).map_err(|_| ReadArtifactError::LimitExceeded)?;
        total = total
            .checked_add(n_u64)
            .ok_or(ReadArtifactError::LimitExceeded)?;
        if total > max_bytes_per_artifact {
            return Err(ReadArtifactError::LimitExceeded);
        }

        hasher.update(&buf[..n]);
        out.extend_from_slice(&buf[..n]);
    }

    let observed_artifact_id = veil_domain::ArtifactId::from_digest(
        veil_domain::Digest32::from_bytes(*hasher.finalize().as_bytes()),
    );
    if observed_artifact_id != *expected_artifact_id || total != expected_size_bytes {
        return Err(ReadArtifactError::IdentityMismatch);
    }

    Ok(out)
}

pub(crate) fn classify_artifact_type(path: &Path) -> String {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "txt" => "TEXT",
        "csv" => "CSV",
        "tsv" => "TSV",
        "json" => "JSON",
        "ndjson" => "NDJSON",
        "zip" => "ZIP",
        "tar" => "TAR",
        "eml" => "EML",
        "mbox" => "MBOX",
        "docx" => "DOCX",
        "pptx" => "PPTX",
        "xlsx" => "XLSX",
        _ => "FILE",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ReadArtifactError, read_artifact_bytes_for_processing};

    fn test_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "veil_cli_inventory_test_{}_{}",
            std::process::id(),
            label.replace(['\\', '/', ':'], "_")
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn read_artifact_detects_identity_mismatch() {
        let dir = test_dir("identity_mismatch");
        let file_path = dir.join("a.txt");
        std::fs::write(&file_path, b"hello").expect("write file");

        let expected = veil_domain::hash_artifact_id(b"hello");
        std::fs::write(&file_path, b"goodbye").expect("overwrite file");

        let read = read_artifact_bytes_for_processing(&file_path, 5, &expected, 1024)
            .expect_err("mismatch");
        assert!(matches!(read, ReadArtifactError::IdentityMismatch));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn read_artifact_enforces_max_bytes_per_artifact() {
        let dir = test_dir("artifact_limit");
        let file_path = dir.join("a.txt");
        std::fs::write(&file_path, b"0123456789ABCDEF").expect("write file");

        let expected = veil_domain::hash_artifact_id(b"0123456789ABCDEF");
        let read =
            read_artifact_bytes_for_processing(&file_path, 16, &expected, 8).expect_err("limit");
        assert!(matches!(read, ReadArtifactError::LimitExceeded));
        let _ = std::fs::remove_dir_all(dir);
    }
}
