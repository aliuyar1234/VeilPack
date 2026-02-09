use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug)]
struct ExtractWorkerArgs {
    artifact_type: String,
    artifact_path: PathBuf,
    archive_limits: veil_domain::ArchiveLimits,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
enum WorkerCanonicalArtifact {
    Text {
        text: String,
    },
    Csv {
        delimiter: u8,
        headers: Vec<String>,
        records: Vec<Vec<String>>,
    },
    Json {
        value: serde_json::Value,
    },
    Ndjson {
        values: Vec<serde_json::Value>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkerCoverageMap {
    content_text: String,
    structured_fields: String,
    metadata: String,
    embedded_objects: String,
    attachments: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
enum ExtractWorkerResponse {
    Extracted {
        extractor_id: String,
        canonical: WorkerCanonicalArtifact,
        coverage: WorkerCoverageMap,
    },
    Quarantined {
        extractor_id: Option<String>,
        reason_code: String,
    },
}

pub(super) fn cmd_extract_worker(args: &[String]) -> ExitCode {
    let parsed = match parse_extract_worker_args(args) {
        Ok(v) => v,
        Err(_) => return ExitCode::from(super::EXIT_FATAL),
    };

    if super::ensure_existing_file_safe(&parsed.artifact_path, "artifact").is_err() {
        return ExitCode::from(super::EXIT_FATAL);
    }

    let bytes = match std::fs::read(&parsed.artifact_path) {
        Ok(v) => v,
        Err(_) => return ExitCode::from(super::EXIT_FATAL),
    };
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > parsed.archive_limits.max_bytes_per_artifact
    {
        let response = ExtractWorkerResponse::Quarantined {
            extractor_id: None,
            reason_code: veil_domain::QuarantineReasonCode::LimitExceeded
                .as_str()
                .to_string(),
        };
        if serde_json::to_writer(std::io::stdout(), &response).is_err() {
            return ExitCode::from(super::EXIT_FATAL);
        }
        return ExitCode::from(super::EXIT_OK);
    }

    let artifact_id = veil_domain::hash_artifact_id(&bytes);
    let source_locator_hash =
        veil_domain::hash_source_locator_hash(&parsed.artifact_path.to_string_lossy());
    let ctx = veil_extract::ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let outcome = veil_extract::ExtractorRegistry::new(parsed.archive_limits).extract_by_type(
        &parsed.artifact_type,
        ctx,
        &bytes,
    );
    let response = extract_outcome_to_worker_response(outcome);
    if serde_json::to_writer(std::io::stdout(), &response).is_err() {
        return ExitCode::from(super::EXIT_FATAL);
    }
    ExitCode::from(super::EXIT_OK)
}

fn parse_extract_worker_args(args: &[String]) -> Result<ExtractWorkerArgs, String> {
    let mut artifact_type = None;
    let mut artifact_path = None;
    let mut max_nested_archive_depth = None;
    let mut max_entries_per_archive = None;
    let mut max_expansion_ratio = None;
    let mut max_expanded_bytes_per_archive = None;
    let mut max_bytes_per_artifact = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--artifact-type" => {
                i += 1;
                let raw: PathBuf = super::require_value(args, i, "--artifact-type")?;
                artifact_type = Some(
                    raw.to_str()
                        .ok_or_else(|| "invalid artifact-type (redacted)".to_string())?
                        .to_string(),
                );
            }
            "--artifact" => {
                i += 1;
                artifact_path = Some(super::require_value(args, i, "--artifact")?);
            }
            "--max-nested-archive-depth" => {
                i += 1;
                max_nested_archive_depth =
                    Some(parse_u32_cli_arg(args, i, "--max-nested-archive-depth")?);
            }
            "--max-entries-per-archive" => {
                i += 1;
                max_entries_per_archive =
                    Some(parse_u32_cli_arg(args, i, "--max-entries-per-archive")?);
            }
            "--max-expansion-ratio" => {
                i += 1;
                max_expansion_ratio = Some(parse_u32_cli_arg(args, i, "--max-expansion-ratio")?);
            }
            "--max-expanded-bytes-per-archive" => {
                i += 1;
                max_expanded_bytes_per_archive = Some(parse_u64_cli_arg(
                    args,
                    i,
                    "--max-expanded-bytes-per-archive",
                )?);
            }
            "--max-bytes-per-artifact" => {
                i += 1;
                max_bytes_per_artifact =
                    Some(parse_u64_cli_arg(args, i, "--max-bytes-per-artifact")?);
            }
            unknown if unknown.starts_with("--") => {
                let _ = unknown;
                return Err("unknown extract-worker flag (redacted)".to_string());
            }
            _ => return Err("unexpected extract-worker argument (redacted)".to_string()),
        }
        i += 1;
    }

    let archive_limits = veil_domain::ArchiveLimits {
        max_nested_archive_depth: max_nested_archive_depth
            .ok_or_else(|| "missing max_nested_archive_depth".to_string())?,
        max_entries_per_archive: max_entries_per_archive
            .ok_or_else(|| "missing max_entries_per_archive".to_string())?,
        max_expansion_ratio: max_expansion_ratio
            .ok_or_else(|| "missing max_expansion_ratio".to_string())?,
        max_expanded_bytes_per_archive: max_expanded_bytes_per_archive
            .ok_or_else(|| "missing max_expanded_bytes_per_archive".to_string())?,
        max_bytes_per_artifact: max_bytes_per_artifact
            .ok_or_else(|| "missing max_bytes_per_artifact".to_string())?,
    };

    if archive_limits.max_expansion_ratio == 0
        || archive_limits.max_expanded_bytes_per_archive == 0
        || archive_limits.max_bytes_per_artifact == 0
    {
        return Err("extract-worker limits must be >= 1 (redacted)".to_string());
    }

    Ok(ExtractWorkerArgs {
        artifact_type: artifact_type.ok_or_else(|| "missing artifact_type".to_string())?,
        artifact_path: artifact_path.ok_or_else(|| "missing artifact".to_string())?,
        archive_limits,
    })
}

fn parse_u32_cli_arg(args: &[String], i: usize, flag: &str) -> Result<u32, String> {
    let raw: PathBuf = super::require_value(args, i, flag)?;
    let raw = raw
        .to_str()
        .ok_or_else(|| format!("{flag} must be a positive integer"))?;
    let parsed = raw
        .parse::<u32>()
        .map_err(|_| format!("{flag} must be a positive integer"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be >= 1"));
    }
    Ok(parsed)
}

fn parse_u64_cli_arg(args: &[String], i: usize, flag: &str) -> Result<u64, String> {
    let raw: PathBuf = super::require_value(args, i, flag)?;
    let raw = raw
        .to_str()
        .ok_or_else(|| format!("{flag} must be a positive integer"))?;
    let parsed = raw
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be a positive integer"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be >= 1"));
    }
    Ok(parsed)
}

fn extract_outcome_to_worker_response(
    outcome: veil_extract::ExtractOutcome,
) -> ExtractWorkerResponse {
    match outcome {
        veil_extract::ExtractOutcome::Extracted {
            extractor_id,
            canonical,
            coverage,
        } => ExtractWorkerResponse::Extracted {
            extractor_id: extractor_id.to_string(),
            canonical: canonical_to_worker(canonical),
            coverage: coverage_to_worker(coverage),
        },
        veil_extract::ExtractOutcome::Quarantined {
            extractor_id,
            reason,
        } => ExtractWorkerResponse::Quarantined {
            extractor_id: extractor_id.map(str::to_string),
            reason_code: reason.as_str().to_string(),
        },
    }
}

fn extract_outcome_from_worker_response(
    response: ExtractWorkerResponse,
) -> Result<veil_extract::ExtractOutcome, String> {
    match response {
        ExtractWorkerResponse::Extracted {
            extractor_id,
            canonical,
            coverage,
        } => {
            let extractor_id = extractor_id_from_wire(&extractor_id)
                .ok_or_else(|| "worker returned unknown extractor_id (redacted)".to_string())?;
            let canonical = canonical_from_worker(canonical).ok_or_else(|| {
                "worker returned invalid canonical payload (redacted)".to_string()
            })?;
            let coverage = coverage_from_worker(coverage)
                .ok_or_else(|| "worker returned invalid coverage payload (redacted)".to_string())?;
            Ok(veil_extract::ExtractOutcome::Extracted {
                extractor_id,
                canonical,
                coverage,
            })
        }
        ExtractWorkerResponse::Quarantined {
            extractor_id,
            reason_code,
        } => {
            let reason = quarantine_reason_from_code(&reason_code)
                .ok_or_else(|| "worker returned invalid reason_code (redacted)".to_string())?;
            let extractor_id = match extractor_id {
                Some(v) => Some(extractor_id_from_wire(&v).ok_or_else(|| {
                    "worker returned unknown extractor_id (redacted)".to_string()
                })?),
                None => None,
            };
            Ok(veil_extract::ExtractOutcome::Quarantined {
                extractor_id,
                reason,
            })
        }
    }
}

fn canonical_to_worker(canonical: veil_extract::CanonicalArtifact) -> WorkerCanonicalArtifact {
    match canonical {
        veil_extract::CanonicalArtifact::Text(v) => WorkerCanonicalArtifact::Text {
            text: v.as_str().to_string(),
        },
        veil_extract::CanonicalArtifact::Csv(v) => WorkerCanonicalArtifact::Csv {
            delimiter: v.delimiter,
            headers: v.headers,
            records: v.records,
        },
        veil_extract::CanonicalArtifact::Json(v) => {
            WorkerCanonicalArtifact::Json { value: v.value }
        }
        veil_extract::CanonicalArtifact::Ndjson(v) => {
            WorkerCanonicalArtifact::Ndjson { values: v.values }
        }
    }
}

fn canonical_from_worker(
    canonical: WorkerCanonicalArtifact,
) -> Option<veil_extract::CanonicalArtifact> {
    Some(match canonical {
        WorkerCanonicalArtifact::Text { text } => {
            veil_extract::CanonicalArtifact::Text(veil_extract::CanonicalText::new(text))
        }
        WorkerCanonicalArtifact::Csv {
            delimiter,
            headers,
            records,
        } => veil_extract::CanonicalArtifact::Csv(veil_extract::CanonicalCsv {
            delimiter,
            headers,
            records,
        }),
        WorkerCanonicalArtifact::Json { value } => {
            veil_extract::CanonicalArtifact::Json(veil_extract::CanonicalJson { value })
        }
        WorkerCanonicalArtifact::Ndjson { values } => {
            veil_extract::CanonicalArtifact::Ndjson(veil_extract::CanonicalNdjson { values })
        }
    })
}

fn coverage_to_worker(coverage: veil_domain::CoverageMapV1) -> WorkerCoverageMap {
    WorkerCoverageMap {
        content_text: coverage.content_text.as_str().to_string(),
        structured_fields: coverage.structured_fields.as_str().to_string(),
        metadata: coverage.metadata.as_str().to_string(),
        embedded_objects: coverage.embedded_objects.as_str().to_string(),
        attachments: coverage.attachments.as_str().to_string(),
    }
}

fn coverage_from_worker(coverage: WorkerCoverageMap) -> Option<veil_domain::CoverageMapV1> {
    Some(veil_domain::CoverageMapV1 {
        content_text: coverage_status_from_wire(&coverage.content_text)?,
        structured_fields: coverage_status_from_wire(&coverage.structured_fields)?,
        metadata: coverage_status_from_wire(&coverage.metadata)?,
        embedded_objects: coverage_status_from_wire(&coverage.embedded_objects)?,
        attachments: coverage_status_from_wire(&coverage.attachments)?,
    })
}

fn coverage_status_from_wire(value: &str) -> Option<veil_domain::CoverageStatus> {
    Some(match value {
        "FULL" => veil_domain::CoverageStatus::Full,
        "NONE" => veil_domain::CoverageStatus::None,
        "UNKNOWN" => veil_domain::CoverageStatus::Unknown,
        _ => return None,
    })
}

fn quarantine_reason_from_code(value: &str) -> Option<veil_domain::QuarantineReasonCode> {
    Some(match value {
        "UNSUPPORTED_FORMAT" => veil_domain::QuarantineReasonCode::UnsupportedFormat,
        "ENCRYPTED" => veil_domain::QuarantineReasonCode::Encrypted,
        "PARSE_ERROR" => veil_domain::QuarantineReasonCode::ParseError,
        "LIMIT_EXCEEDED" => veil_domain::QuarantineReasonCode::LimitExceeded,
        "UNSAFE_PATH" => veil_domain::QuarantineReasonCode::UnsafePath,
        "UNKNOWN_COVERAGE" => veil_domain::QuarantineReasonCode::UnknownCoverage,
        "VERIFICATION_FAILED" => veil_domain::QuarantineReasonCode::VerificationFailed,
        "INTERNAL_ERROR" => veil_domain::QuarantineReasonCode::InternalError,
        _ => return None,
    })
}

fn extractor_id_from_wire(value: &str) -> Option<&'static str> {
    Some(match value {
        "extract.text.v1" => "extract.text.v1",
        "extract.csv.v1" => "extract.csv.v1",
        "extract.tsv.v1" => "extract.tsv.v1",
        "extract.json.v1" => "extract.json.v1",
        "extract.ndjson.v1" => "extract.ndjson.v1",
        "extract.zip.v1" => "extract.zip.v1",
        "extract.tar.v1" => "extract.tar.v1",
        "extract.eml.v1" => "extract.eml.v1",
        "extract.mbox.v1" => "extract.mbox.v1",
        "extract.ooxml.docx.v1" => "extract.ooxml.docx.v1",
        "extract.ooxml.pptx.v1" => "extract.ooxml.pptx.v1",
        "extract.ooxml.xlsx.v1" => "extract.ooxml.xlsx.v1",
        _ => return None,
    })
}

pub(super) fn is_risky_extractor_type(artifact_type: &str) -> bool {
    matches!(
        artifact_type,
        "ZIP" | "TAR" | "EML" | "MBOX" | "DOCX" | "PPTX" | "XLSX"
    )
}

pub(super) fn run_extract_in_worker(
    artifact_path: &Path,
    artifact_type: &str,
    archive_limits: veil_domain::ArchiveLimits,
    max_processing_ms: u64,
) -> Result<veil_extract::ExtractOutcome, String> {
    let exe = std::env::current_exe()
        .map_err(|_| "could not resolve extract worker executable (redacted)".to_string())?;
    let mut child = Command::new(exe)
        .arg("extract-worker")
        .arg("--artifact-type")
        .arg(artifact_type)
        .arg("--artifact")
        .arg(artifact_path)
        .arg("--max-nested-archive-depth")
        .arg(archive_limits.max_nested_archive_depth.to_string())
        .arg("--max-entries-per-archive")
        .arg(archive_limits.max_entries_per_archive.to_string())
        .arg("--max-expansion-ratio")
        .arg(archive_limits.max_expansion_ratio.to_string())
        .arg("--max-expanded-bytes-per-archive")
        .arg(archive_limits.max_expanded_bytes_per_archive.to_string())
        .arg("--max-bytes-per-artifact")
        .arg(archive_limits.max_bytes_per_artifact.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "could not start extract worker (redacted)".to_string())?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "extract worker did not expose stdout (redacted)".to_string())?;

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| "extract worker wait failed (redacted)".to_string())?
        {
            break status;
        }

        if started.elapsed() > Duration::from_millis(max_processing_ms) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("extract worker timed out (redacted)".to_string());
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    let mut out = Vec::<u8>::new();
    stdout
        .read_to_end(&mut out)
        .map_err(|_| "extract worker output could not be read (redacted)".to_string())?;
    if !status.success() {
        return Err("extract worker failed (redacted)".to_string());
    }

    let response: ExtractWorkerResponse = serde_json::from_slice(&out)
        .map_err(|_| "extract worker output is invalid (redacted)".to_string())?;
    extract_outcome_from_worker_response(response)
}
