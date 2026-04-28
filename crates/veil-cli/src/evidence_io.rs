use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fs_safety::{
    ensure_dir_exists_or_create, ensure_existing_path_components_safe, is_unsafe_reparse_point,
    sync_parent_dir, write_bytes_atomic,
};

pub(crate) const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROOF_KEY_DERIVATION_DOMAIN: &[u8] = b"veil.proof.key.v1";

#[derive(Debug, Clone)]
pub(crate) struct ArtifactRunResult {
    pub(crate) sort_key: veil_domain::ArtifactSortKey,
    pub(crate) size_bytes: u64,
    /// Wire-format `artifact_type` string. Either one of the `ArtifactType`
    /// canonical values (`"TEXT"`, `"ZIP"`, etc.) or `"FILE"` for files
    /// without a v1 extractor.
    pub(crate) artifact_type: String,
    pub(crate) state: veil_domain::ArtifactState,
    pub(crate) quarantine_reason_code: Option<String>,
    pub(crate) output_id: Option<String>,
    pub(crate) proof_tokens: Vec<String>,
}

pub(crate) fn create_pack_dirs(
    pack_root: &Path,
    quarantine_copy_enabled: bool,
) -> Result<(), String> {
    ensure_dir_exists_or_create(pack_root, "output")?;
    ensure_dir_exists_or_create(&pack_root.join("sanitized"), "sanitized")?;
    ensure_dir_exists_or_create(&pack_root.join("quarantine"), "quarantine")?;
    ensure_dir_exists_or_create(&pack_root.join("evidence"), "evidence")?;

    if quarantine_copy_enabled {
        ensure_dir_exists_or_create(&pack_root.join("quarantine").join("raw"), "quarantine/raw")?;
    }

    Ok(())
}

pub(crate) fn derive_proof_key(root_secret: &[u8], run_id: &veil_domain::RunId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROOF_KEY_DERIVATION_DOMAIN);
    hasher.update(run_id.as_digest().as_bytes());
    hasher.update(root_secret);
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Serialize)]
pub(crate) struct RunTotals {
    pub(crate) artifacts_discovered: u64,
    pub(crate) artifacts_verified: u64,
    pub(crate) artifacts_quarantined: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct RunManifestJsonV1 {
    pub(crate) tool_version: &'static str,
    pub(crate) run_id: String,
    pub(crate) policy_id: String,
    pub(crate) input_corpus_id: String,
    pub(crate) totals: RunTotals,
    pub(crate) quarantine_reason_counts: BTreeMap<String, u64>,
    pub(crate) tokenization_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tokenization_scope: Option<&'static str>,
    pub(crate) proof_scope: &'static str,
    pub(crate) proof_key_commitment: String,
    pub(crate) quarantine_copy_enabled: bool,
}

#[derive(Debug, Serialize)]
struct QuarantineIndexRecord<'a> {
    artifact_id: &'a str,
    source_locator_hash: &'a str,
    reason_code: &'a str,
}

pub(crate) fn write_quarantine_index(
    path: &Path,
    artifacts: &[ArtifactRunResult],
) -> Result<(), String> {
    ensure_existing_path_components_safe(path, "quarantine index")?;
    let dir = path
        .parent()
        .ok_or_else(|| "could not create quarantine index".to_string())?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "could not create quarantine index".to_string())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    if let Ok(meta) = std::fs::symlink_metadata(&tmp_path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        return Err("could not create quarantine index".to_string());
    }

    let file = std::fs::File::create(&tmp_path)
        .map_err(|_| "could not create quarantine index".to_string())?;
    let mut writer = std::io::BufWriter::new(file);

    for a in artifacts {
        if a.state != veil_domain::ArtifactState::Quarantined {
            continue;
        }
        let Some(reason_code) = a.quarantine_reason_code.as_deref() else {
            return Err("quarantined artifact missing reason_code".to_string());
        };

        let artifact_id = a.sort_key.artifact_id.to_string();
        let source_locator_hash = a.sort_key.source_locator_hash.to_string();
        let record = QuarantineIndexRecord {
            artifact_id: &artifact_id,
            source_locator_hash: &source_locator_hash,
            reason_code,
        };
        let line = serde_json::to_string(&record)
            .map_err(|_| "could not serialize quarantine index record".to_string())?;
        writer
            .write_all(line.as_bytes())
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|_| "could not write quarantine index".to_string())?;
    }

    writer
        .flush()
        .map_err(|_| "could not flush quarantine index".to_string())?;
    let file = writer
        .into_inner()
        .map_err(|_| "could not flush quarantine index".to_string())?;
    file.sync_all()
        .map_err(|_| "could not persist quarantine index".to_string())?;
    drop(file);
    ensure_existing_path_components_safe(path, "quarantine index")?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err("quarantine index path is unsafe".to_string());
    }
    std::fs::rename(&tmp_path, path)
        .map_err(|_| "could not persist quarantine index".to_string())?;
    sync_parent_dir(path).map_err(|_| "could not persist quarantine index".to_string())?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct ArtifactEvidenceRecord<'a> {
    artifact_id: &'a str,
    source_locator_hash: &'a str,
    size_bytes: u64,
    artifact_type: &'a str,
    state: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    quarantine_reason_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_tokens: Option<&'a [String]>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactEvidenceRecordOwned {
    pub(crate) artifact_id: String,
    pub(crate) source_locator_hash: String,
    pub(crate) size_bytes: u64,
    pub(crate) artifact_type: String,
    pub(crate) state: String,
    #[serde(default)]
    pub(crate) quarantine_reason_code: Option<String>,
    #[serde(default)]
    pub(crate) output_id: Option<String>,
    /// Wire-schema field: parsed for `deny_unknown_fields` compatibility,
    /// but the live source of truth is the ledger `proof_tokens` table.
    /// Keeping the field here means malformed NDJSON still fails closed
    /// during `verify`'s record parse pass.
    #[allow(dead_code)]
    #[serde(default)]
    pub(crate) proof_tokens: Vec<String>,
}

pub(crate) fn collect_proof_tokens(findings: &[veil_detect::Finding]) -> Vec<String> {
    let mut out = BTreeSet::<String>::new();
    for f in findings {
        if let Some(t) = &f.proof_token {
            out.insert(t.clone());
        }
    }
    out.into_iter().collect()
}

pub(crate) fn write_artifacts_evidence(
    path: &Path,
    artifacts: &[ArtifactRunResult],
) -> Result<(), String> {
    ensure_existing_path_components_safe(path, "artifacts evidence")?;
    let dir = path
        .parent()
        .ok_or_else(|| "could not create artifacts evidence".to_string())?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "could not create artifacts evidence".to_string())?;
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    if let Ok(meta) = std::fs::symlink_metadata(&tmp_path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        return Err("could not create artifacts evidence".to_string());
    }

    let file = std::fs::File::create(&tmp_path)
        .map_err(|_| "could not create artifacts evidence".to_string())?;
    let mut writer = std::io::BufWriter::new(file);

    for a in artifacts {
        let artifact_id = a.sort_key.artifact_id.to_string();
        let source_locator_hash = a.sort_key.source_locator_hash.to_string();
        let record = ArtifactEvidenceRecord {
            artifact_id: &artifact_id,
            source_locator_hash: &source_locator_hash,
            size_bytes: a.size_bytes,
            artifact_type: &a.artifact_type,
            state: a.state.as_str(),
            quarantine_reason_code: a.quarantine_reason_code.as_deref(),
            output_id: a.output_id.as_deref(),
            proof_tokens: if a.proof_tokens.is_empty() {
                None
            } else {
                Some(a.proof_tokens.as_slice())
            },
        };
        let line = serde_json::to_string(&record)
            .map_err(|_| "could not serialize artifacts evidence record".to_string())?;
        writer
            .write_all(line.as_bytes())
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|_| "could not write artifacts evidence".to_string())?;
    }

    writer
        .flush()
        .map_err(|_| "could not flush artifacts evidence".to_string())?;
    let file = writer
        .into_inner()
        .map_err(|_| "could not flush artifacts evidence".to_string())?;
    file.sync_all()
        .map_err(|_| "could not persist artifacts evidence".to_string())?;
    drop(file);
    ensure_existing_path_components_safe(path, "artifacts evidence")?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || is_unsafe_reparse_point(&meta))
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err("artifacts evidence path is unsafe".to_string());
    }
    std::fs::rename(&tmp_path, path)
        .map_err(|_| "could not persist artifacts evidence".to_string())?;
    sync_parent_dir(path).map_err(|_| "could not persist artifacts evidence".to_string())?;
    Ok(())
}

/// Sanitized output extension for a wire artifact_type string.
///
/// Mirrors [`veil_domain::ArtifactType::sanitized_extension`] for the
/// known v1 set; unrecognized values (notably the `"FILE"` placeholder
/// emitted for unsupported types) use `"bin"`.
pub(crate) fn sanitized_extension_for_wire(artifact_type_wire: &str) -> &'static str {
    match veil_domain::ArtifactType::parse(artifact_type_wire) {
        Ok(t) => t.sanitized_extension(),
        Err(_) => "bin",
    }
}

pub(crate) fn sanitized_output_path_v1(
    sanitized_dir: &Path,
    sort_key: &veil_domain::ArtifactSortKey,
    artifact_type_wire: &str,
) -> PathBuf {
    let ext = sanitized_extension_for_wire(artifact_type_wire);
    sanitized_dir.join(format!(
        "{}__{}.{}",
        sort_key.source_locator_hash, sort_key.artifact_id, ext
    ))
}

fn write_quarantine_raw(
    quarantine_raw_dir: &Path,
    sort_key: &veil_domain::ArtifactSortKey,
    artifact_type_wire: &str,
    bytes: &[u8],
) -> Result<(), ()> {
    let ext = sanitized_extension_for_wire(artifact_type_wire);
    let path = quarantine_raw_dir.join(format!(
        "{}__{}.{}",
        sort_key.source_locator_hash, sort_key.artifact_id, ext
    ));
    write_bytes_atomic(&path, bytes)
}

pub(crate) fn write_quarantine_raw_or_fail(
    quarantine_copy_enabled: bool,
    quarantine_raw_dir: &Path,
    sort_key: &veil_domain::ArtifactSortKey,
    artifact_type_wire: &str,
    bytes: &[u8],
) -> Result<(), ()> {
    if !quarantine_copy_enabled {
        return Ok(());
    }

    if write_quarantine_raw(quarantine_raw_dir, sort_key, artifact_type_wire, bytes).is_err() {
        tracing::error!(
            event = "quarantine_raw_write_failed",
            reason_code = "INTERNAL_ERROR",
            "could not persist quarantine raw copy"
        );
        return Err(());
    }
    Ok(())
}

pub(crate) fn coverage_hash_v1(coverage: veil_domain::CoverageMapV1) -> String {
    let s = format!(
        "coverage.v1|content_text={}|structured_fields={}|metadata={}|embedded_objects={}|attachments={}",
        coverage.content_text.as_str(),
        coverage.structured_fields.as_str(),
        coverage.metadata.as_str(),
        coverage.embedded_objects.as_str(),
        coverage.attachments.as_str()
    );
    blake3::hash(s.as_bytes()).to_hex().to_string()
}

pub(crate) fn validate_or_seed_resume_meta(
    ledger: &veil_evidence::Ledger,
    key: &str,
    expected: &str,
) -> bool {
    match ledger.get_meta(key) {
        Ok(Some(value)) => value == expected,
        Ok(None) => ledger.upsert_meta(key, expected).is_ok(),
        Err(_) => false,
    }
}
