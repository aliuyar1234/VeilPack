//! Worker-pool harness for `--max-workers > 1`.
//!
//! Phase 4 turns the per-artifact pipeline into:
//! - a producer thread that iterates the sorted `run.artifacts` list,
//! - a pool of `max_workers` worker threads that run the pure pipeline
//!   (read bytes -> extract -> detect -> transform -> reverify),
//! - a single committer thread that applies side-effects (ledger writes,
//!   sanitized destination file, quarantine raw copy) in
//!   `ArtifactSortKey` order.
//!
//! Determinism contract: identical inputs and identical `--max-workers=N`
//! produce byte-identical output. The committer keeps a `BTreeMap` keyed
//! by sort key and drains in order so the output sequence does not
//! depend on which worker happened to finish first. `--max-workers=1`
//! still uses the pool but the pool degenerates into a one-thread
//! pipeline; that path is asserted byte-identical to the pre-pool serial
//! code in the integration tests.
//!
//! Backpressure: the producer->worker channel and worker->committer
//! channel are bounded at `4 * max_workers`. If workers fall behind the
//! producer blocks on `send`, capping memory usage. If the committer
//! falls behind the workers also block.
//!
//! Panic safety: each worker thread wraps its body in
//! `std::panic::catch_unwind`. A panic produces a
//! `WorkerOutcome::Panicked` result that the committer surfaces as a
//! fatal `worker_panic` event. Channel disconnect on drop guarantees
//! orderly shutdown if the committer aborts early.

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender, bounded};

use crate::artifact_processor::{
    ArtifactProcessStatus, ArtifactProcessor, WorkerOutcome, prepare_outcome_from_pure_pipeline,
};
use crate::error::AppError;
use crate::input_inventory::DiscoveredArtifact;
use crate::run_bootstrap::BootstrappedRun;

/// Producer payload: one artifact plus its index in the sort order.
/// Keeping the index avoids re-sorting on the committer side.
struct WorkItem {
    sort_index: usize,
    artifact: DiscoveredArtifact,
}

/// One unit of completed work flowing from a worker to the committer.
struct WorkerCompletion {
    sort_index: usize,
    artifact: DiscoveredArtifact,
    outcome: WorkerOutcome,
}

/// Run the full artifact-processing phase using the worker pool.
///
/// Returns once every artifact has either been committed (to ledger and
/// destination FS) or surfaced as a fatal error.
pub(crate) fn run_pool(run: &mut BootstrappedRun, max_workers: u32) -> Result<u64, AppError> {
    let extractors = veil_extract::ExtractorRegistry::new(run.context.archive_limits);
    let detector = veil_detect::DetectorEngineV1;
    let transformer = veil_transform::TransformerV1;

    // Shared, read-only context for workers. Wrapped in Arc so each
    // thread can hold a clone without re-cloning the underlying policy
    // or proof key.
    let shared = Arc::new(SharedWorkerContext {
        archive_limits: run.context.archive_limits,
        runtime_limits: run.context.runtime_limits,
        policy: run.context.policy.clone(),
        proof_key: *run.context.proof_key,
        isolate_risky_extractors: run.context.parsed.isolate_risky_extractors,
        extractors,
        detector,
        transformer,
    });

    let n_workers = max_workers.max(1) as usize;
    let bound = (4 * n_workers).max(4);
    let (work_tx, work_rx) = bounded::<WorkItem>(bound);
    let (done_tx, done_rx) = bounded::<WorkerCompletion>(bound);

    // Spawn worker threads.
    let mut worker_handles = Vec::with_capacity(n_workers);
    for worker_id in 0..n_workers {
        let work_rx = work_rx.clone();
        let done_tx = done_tx.clone();
        let shared = Arc::clone(&shared);
        let handle = thread::Builder::new()
            .name(format!("veil-worker-{worker_id}"))
            .spawn(move || worker_main(work_rx, done_tx, shared))
            .map_err(|_| AppError::Internal("worker_spawn_failed".to_string()))?;
        worker_handles.push(handle);
    }
    // Drop the original work sender clone; workers each hold their own.
    drop(work_rx);
    // The producer holds `work_tx`; once it finishes sending it is
    // dropped, which triggers worker shutdown via channel-disconnect.
    drop(done_tx);

    // Spawn producer thread.
    let artifacts_for_producer = run.artifacts.clone();
    let producer_handle = thread::Builder::new()
        .name("veil-producer".to_string())
        .spawn(move || {
            for (idx, artifact) in artifacts_for_producer.into_iter().enumerate() {
                let item = WorkItem {
                    sort_index: idx,
                    artifact,
                };
                if work_tx.send(item).is_err() {
                    // Committer or all workers gone; nothing more to do.
                    return;
                }
            }
        })
        .map_err(|_| AppError::Internal("producer_spawn_failed".to_string()))?;

    // Run committer on the current thread so it owns the &mut Ledger
    // and &mut workdir_bytes_observed without extra synchronization.
    let verified_count = committer_loop(run, done_rx)?;

    // Join producer and workers. Failures here are fatal because we
    // promised the run is finished by this function.
    if producer_handle.join().is_err() {
        return Err(AppError::Internal("producer_join_failed".to_string()));
    }
    for handle in worker_handles {
        if handle.join().is_err() {
            return Err(AppError::Internal("worker_join_failed".to_string()));
        }
    }

    Ok(verified_count)
}

/// Worker thread body. Reads `WorkItem`s, runs the pure pipeline, sends
/// `WorkerCompletion` to the committer. Panics inside the pure pipeline
/// are caught and surfaced as `WorkerOutcome::Panicked`.
fn worker_main(
    work_rx: Receiver<WorkItem>,
    done_tx: Sender<WorkerCompletion>,
    shared: Arc<SharedWorkerContext>,
) {
    while let Ok(item) = work_rx.recv() {
        let WorkItem {
            sort_index,
            artifact,
        } = item;
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            prepare_outcome_from_pure_pipeline(&shared, &artifact)
        }));
        let outcome = match result {
            Ok(o) => o,
            Err(_) => WorkerOutcome::Panicked,
        };
        let completion = WorkerCompletion {
            sort_index,
            artifact,
            outcome,
        };
        if done_tx.send(completion).is_err() {
            // Committer hung up; nothing more to do.
            return;
        }
    }
}

/// Committer loop: receives completions, applies them in `sort_index`
/// order using a `BTreeMap` to wait until each gap is filled. This is
/// what enforces determinism — outputs land in the same order regardless
/// of which worker finished first.
fn committer_loop(
    run: &mut BootstrappedRun,
    done_rx: Receiver<WorkerCompletion>,
) -> Result<u64, AppError> {
    let mut buffer: BTreeMap<usize, WorkerCompletion> = BTreeMap::new();
    let mut next_to_commit: usize = 0;
    let mut verified_count: u64 = 0;

    while let Ok(completion) = done_rx.recv() {
        buffer.insert(completion.sort_index, completion);
        // Drain any ready prefix.
        while let Some(completion) = buffer.remove(&next_to_commit) {
            let status = commit_completion(run, completion)?;
            verified_count = surface_after_first_verified(verified_count, &status)?;
            next_to_commit += 1;
        }
    }

    // After the channel disconnected, everything is in `buffer`. Drain.
    while let Some(completion) = buffer.remove(&next_to_commit) {
        let status = commit_completion(run, completion)?;
        verified_count = surface_after_first_verified(verified_count, &status)?;
        next_to_commit += 1;
    }

    Ok(verified_count)
}

/// Bump `verified_count` and surface the `after_first_verified` failpoint
/// if it is the first verified artifact. Factored out so the two drain
/// sites stay in sync.
fn surface_after_first_verified(
    verified_count: u64,
    status: &ArtifactProcessStatus,
) -> Result<u64, AppError> {
    if !matches!(status, ArtifactProcessStatus::Verified) {
        return Ok(verified_count);
    }
    let next = verified_count.saturating_add(1);
    if next == 1 && std::env::var("VEIL_FAILPOINT").as_deref() == Ok("after_first_verified") {
        tracing::error!(
            event = "failpoint_triggered",
            reason_code = "INTERNAL_ERROR",
            "failpoint triggered"
        );
        return Err(AppError::Internal("failpoint_triggered".to_string()));
    }
    Ok(next)
}

/// Apply one completion's side-effects through `ArtifactProcessor::commit`.
fn commit_completion(
    run: &mut BootstrappedRun,
    completion: WorkerCompletion,
) -> Result<ArtifactProcessStatus, AppError> {
    let WorkerCompletion {
        sort_index: _,
        artifact,
        outcome,
    } = completion;
    let mut processor = ArtifactProcessor {
        context: &run.context,
        paths: &run.paths,
        ledger: &mut run.ledger,
        proof_tokens_by_artifact: &mut run.proof_tokens_by_artifact,
        workdir_bytes_observed: &mut run.workdir_bytes_observed,
    };
    processor.commit(&artifact, outcome)
}

/// Read-only view of the context plumbed into the pure pipeline.
///
/// Cloned cheaply at pool startup. Workers hold an `Arc` so the
/// underlying `Policy` and proof key bytes are never copied per artifact.
pub(crate) struct SharedWorkerContext {
    pub(crate) archive_limits: veil_domain::ArchiveLimits,
    pub(crate) runtime_limits: crate::runtime_limits::RuntimeLimits,
    pub(crate) policy: veil_policy::Policy,
    pub(crate) proof_key: [u8; 32],
    pub(crate) isolate_risky_extractors: bool,
    pub(crate) extractors: veil_extract::ExtractorRegistry,
    pub(crate) detector: veil_detect::DetectorEngineV1,
    pub(crate) transformer: veil_transform::TransformerV1,
}
