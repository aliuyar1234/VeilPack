use std::path::Path;

use serde::Deserialize;

pub(crate) const DEFAULT_MAX_WORKDIR_BYTES: u64 = 1_073_741_824;
pub(crate) const DEFAULT_MAX_PROCESSING_MS_PER_ARTIFACT: u64 = 30_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFileV1 {
    schema_version: String,
    #[serde(default)]
    archive: ArchiveLimitsOverride,
    #[serde(default)]
    artifact: ArtifactLimitsOverride,
    #[serde(default)]
    disk: DiskLimitsOverride,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveLimitsOverride {
    max_nested_archive_depth: Option<u32>,
    max_entries_per_archive: Option<u32>,
    max_expansion_ratio: Option<u32>,
    max_expanded_bytes_per_archive: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactLimitsOverride {
    max_bytes_per_artifact: Option<u64>,
    max_processing_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskLimitsOverride {
    max_workdir_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RuntimeLimits {
    pub(crate) archive_limits: veil_domain::ArchiveLimits,
    pub(crate) max_workdir_bytes: u64,
    pub(crate) max_processing_ms_per_artifact: u64,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            archive_limits: veil_domain::ArchiveLimits::default(),
            max_workdir_bytes: DEFAULT_MAX_WORKDIR_BYTES,
            max_processing_ms_per_artifact: DEFAULT_MAX_PROCESSING_MS_PER_ARTIFACT,
        }
    }
}

pub(crate) fn load_runtime_limits_from_json(path: &Path) -> Result<RuntimeLimits, String> {
    let json =
        std::fs::read_to_string(path).map_err(|_| "limits-json could not be read".to_string())?;

    let parsed: LimitsFileV1 =
        serde_json::from_str(&json).map_err(|_| "limits-json is not valid JSON".to_string())?;

    if parsed.schema_version != "limits.v1" {
        return Err("limits-json schema_version must be 'limits.v1' (v1)".to_string());
    }

    let mut archive_limits = veil_domain::ArchiveLimits::default();
    let mut max_workdir_bytes = DEFAULT_MAX_WORKDIR_BYTES;
    let mut max_processing_ms_per_artifact = DEFAULT_MAX_PROCESSING_MS_PER_ARTIFACT;
    if let Some(v) = parsed.archive.max_nested_archive_depth {
        archive_limits.max_nested_archive_depth = v;
    }
    if let Some(v) = parsed.archive.max_entries_per_archive {
        archive_limits.max_entries_per_archive = v;
    }
    if let Some(v) = parsed.archive.max_expansion_ratio {
        if v == 0 {
            return Err("limits-json max_expansion_ratio must be >= 1".to_string());
        }
        archive_limits.max_expansion_ratio = v;
    }
    if let Some(v) = parsed.archive.max_expanded_bytes_per_archive {
        if v == 0 {
            return Err("limits-json max_expanded_bytes_per_archive must be >= 1".to_string());
        }
        archive_limits.max_expanded_bytes_per_archive = v;
    }
    if let Some(v) = parsed.artifact.max_bytes_per_artifact {
        if v == 0 {
            return Err("limits-json max_bytes_per_artifact must be >= 1".to_string());
        }
        archive_limits.max_bytes_per_artifact = v;
    }
    if let Some(v) = parsed.artifact.max_processing_ms {
        if v == 0 {
            return Err("limits-json max_processing_ms must be >= 1".to_string());
        }
        max_processing_ms_per_artifact = v;
    }
    if let Some(v) = parsed.disk.max_workdir_bytes {
        if v == 0 {
            return Err("limits-json max_workdir_bytes must be >= 1".to_string());
        }
        max_workdir_bytes = v;
    }

    Ok(RuntimeLimits {
        archive_limits,
        max_workdir_bytes,
        max_processing_ms_per_artifact,
    })
}
