use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::Duration;

use wait_timeout::ChildExt;

use crate::error::AppError;
use crate::extract_worker_protocol::{
    WorkerEnvelope, extract_outcome_from_worker_envelope, extract_outcome_to_worker_envelope,
    limit_exceeded_envelope, read_envelope, write_envelope,
};
use crate::fs_safety::ensure_existing_file_safe;

#[derive(Debug, clap::Args)]
pub(crate) struct ExtractWorkerArgs {
    #[arg(long = "artifact-type")]
    pub(crate) artifact_type: String,
    #[arg(long = "artifact")]
    pub(crate) artifact_path: std::path::PathBuf,
    #[arg(long = "max-nested-archive-depth")]
    pub(crate) max_nested_archive_depth: u32,
    #[arg(long = "max-entries-per-archive")]
    pub(crate) max_entries_per_archive: u32,
    #[arg(long = "max-expansion-ratio")]
    pub(crate) max_expansion_ratio: u32,
    #[arg(long = "max-expanded-bytes-per-archive")]
    pub(crate) max_expanded_bytes_per_archive: u64,
    #[arg(long = "max-bytes-per-artifact")]
    pub(crate) max_bytes_per_artifact: u64,
}

pub(super) fn cmd_extract_worker(parsed: ExtractWorkerArgs) -> ExitCode {
    if parsed.max_nested_archive_depth == 0
        || parsed.max_entries_per_archive == 0
        || parsed.max_expansion_ratio == 0
        || parsed.max_expanded_bytes_per_archive == 0
        || parsed.max_bytes_per_artifact == 0
    {
        return ExitCode::from(super::EXIT_FATAL);
    }

    let archive_limits = veil_domain::ArchiveLimits {
        max_nested_archive_depth: parsed.max_nested_archive_depth,
        max_entries_per_archive: parsed.max_entries_per_archive,
        max_expansion_ratio: parsed.max_expansion_ratio,
        max_expanded_bytes_per_archive: parsed.max_expanded_bytes_per_archive,
        max_bytes_per_artifact: parsed.max_bytes_per_artifact,
    };

    let artifact_type = match veil_domain::ArtifactType::parse(&parsed.artifact_type) {
        Ok(t) => t,
        Err(_) => return ExitCode::from(super::EXIT_FATAL),
    };

    if ensure_existing_file_safe(&parsed.artifact_path, "artifact").is_err() {
        return ExitCode::from(super::EXIT_FATAL);
    }

    let bytes = match std::fs::read(&parsed.artifact_path) {
        Ok(v) => v,
        Err(_) => return ExitCode::from(super::EXIT_FATAL),
    };
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > archive_limits.max_bytes_per_artifact {
        return write_worker_envelope(&limit_exceeded_envelope());
    }

    let artifact_id = veil_domain::hash_artifact_id(&bytes);
    let source_locator_hash =
        veil_domain::hash_source_locator_hash(&parsed.artifact_path.to_string_lossy());
    let ctx = veil_extract::ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let outcome =
        veil_extract::ExtractorRegistry::new(archive_limits).extract(artifact_type, ctx, &bytes);
    let envelope = extract_outcome_to_worker_envelope(outcome);
    write_worker_envelope(&envelope)
}

/// RAII guard for a spawned worker child. If the parent panics or returns
/// before `into_inner` is invoked, `Drop` kills the child and reaps it so
/// no orphan worker survives. The explicit `into_inner` consumes the guard
/// once the parent has finished reading the worker's envelope and observed
/// a clean exit code, transferring ownership of the `Child` so the parent
/// can call `wait_timeout` on it without the guard double-killing.
struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn as_mut(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("ChildGuard child taken before drop")
    }

    fn into_inner(mut self) -> Child {
        self.child.take().expect("ChildGuard child already taken")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(super) fn run_extract_in_worker(
    artifact_path: &Path,
    artifact_type: veil_domain::ArtifactType,
    archive_limits: veil_domain::ArchiveLimits,
    max_processing_ms: u64,
) -> Result<veil_extract::ExtractOutcome, AppError> {
    let exe = std::env::current_exe()
        .map_err(|_| AppError::Internal("worker_executable_resolution_failed".to_string()))?;
    let child = Command::new(exe)
        .arg("extract-worker")
        .arg("--artifact-type")
        .arg(artifact_type.as_str())
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
        .map_err(|_| AppError::Internal("worker_spawn_failed".to_string()))?;

    let mut guard = ChildGuard::new(child);

    // Wait for the worker bounded by max_processing_ms. wait_timeout reaps
    // the child once it exits, so the parent never busy-polls.
    let timeout = Duration::from_millis(max_processing_ms);
    let status = match guard
        .as_mut()
        .wait_timeout(timeout)
        .map_err(|_| AppError::Internal("worker_wait_failed".to_string()))?
    {
        Some(status) => status,
        None => {
            // ChildGuard::Drop will kill+reap on the way out.
            return Err(AppError::Internal("worker_timeout".to_string()));
        }
    };
    if !status.success() {
        return Err(AppError::Internal("worker_failed".to_string()));
    }

    // Worker exited cleanly: read stdout while still under the guard,
    // then explicitly wait. Clippy's `zombie_processes` lint requires
    // `wait()` on every code path that owns the Child, including the
    // early-return ones, so we do the read-and-decode while the guard
    // still holds the Child and only `into_inner` once we know we are
    // about to return successfully. (`wait_timeout` already reaped the
    // child; the explicit wait is redundant but lint-required.)
    let stdout_take = guard.as_mut().stdout.take();
    let read_result = match stdout_take {
        Some(mut stdout) => {
            read_envelope(&mut stdout).and_then(extract_outcome_from_worker_envelope)
        }
        None => Err(AppError::Internal("worker_no_stdout".to_string())),
    };
    let mut child = guard.into_inner();
    let _ = child.wait();
    read_result
}

fn write_worker_envelope(envelope: &WorkerEnvelope) -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    if write_envelope(&mut stdout, envelope).is_err() {
        return ExitCode::from(super::EXIT_FATAL);
    }
    use std::io::Write;
    if stdout.flush().is_err() {
        return ExitCode::from(super::EXIT_FATAL);
    }
    ExitCode::from(super::EXIT_OK)
}
