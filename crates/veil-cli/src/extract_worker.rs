use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use crate::args::require_value;
use crate::extract_worker_protocol::{
    ExtractWorkerResponse, extract_outcome_from_worker_response,
    extract_outcome_to_worker_response, limit_exceeded_response,
};
use crate::fs_safety::ensure_existing_file_safe;

#[derive(Debug)]
struct ExtractWorkerArgs {
    artifact_type: String,
    artifact_path: PathBuf,
    archive_limits: veil_domain::ArchiveLimits,
}

pub(super) fn cmd_extract_worker(args: &[String]) -> ExitCode {
    let parsed = match parse_extract_worker_args(args) {
        Ok(v) => v,
        Err(_) => return ExitCode::from(super::EXIT_FATAL),
    };

    if ensure_existing_file_safe(&parsed.artifact_path, "artifact").is_err() {
        return ExitCode::from(super::EXIT_FATAL);
    }

    let bytes = match std::fs::read(&parsed.artifact_path) {
        Ok(v) => v,
        Err(_) => return ExitCode::from(super::EXIT_FATAL),
    };
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > parsed.archive_limits.max_bytes_per_artifact
    {
        return write_worker_response(&limit_exceeded_response());
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
    write_worker_response(&response)
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
                let raw: PathBuf = require_value(args, i, "--artifact-type")?;
                artifact_type = Some(
                    raw.to_str()
                        .ok_or_else(|| "invalid artifact-type (redacted)".to_string())?
                        .to_string(),
                );
            }
            "--artifact" => {
                i += 1;
                artifact_path = Some(require_value(args, i, "--artifact")?);
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
    let raw: PathBuf = require_value(args, i, flag)?;
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
    let raw: PathBuf = require_value(args, i, flag)?;
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

fn write_worker_response(response: &ExtractWorkerResponse) -> ExitCode {
    if serde_json::to_writer(std::io::stdout(), response).is_err() {
        ExitCode::from(super::EXIT_FATAL)
    } else {
        ExitCode::from(super::EXIT_OK)
    }
}
