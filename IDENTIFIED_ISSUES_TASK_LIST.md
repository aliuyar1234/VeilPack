# Identified Issues Task List

Date: 2026-03-09

This task list captures the issues identified during the full codebase analysis. It focuses on concrete defects, maintainability risks, and documentation or workflow gaps that should be tracked explicitly.

Current validation snapshot:

- `cargo fmt --all`: passed
- `cargo clippy --workspace -- -D warnings`: passed
- `cargo test --workspace`: passed
- `python checks/offline_enforcement.py`: passed
- `python checks/boundary_fitness.py`: passed
- `python checks/compatibility_matrix_check.py`: passed
- `python checks/package_release_smoke.py`: passed
- `python checks/ssot_validate.py all`: returns `SSOT_NOT_ENABLED ...` by design for this checkout

## Priority 0: Fix Broken Release Packaging

Issue:
- `scripts/package_release.py` calls `shutil.rmtree(dist)` but does not import `shutil`.
- The release workflow depends on this script, so packaging can fail before assets are created when `dist/` already exists.

Affected files:
- `scripts/package_release.py`
- `.github/workflows/release.yml`

Tasks:
- [x] Import `shutil` in `scripts/package_release.py`.
- [x] Add a packaging smoke test that covers both cases:
  - missing `dist/`
  - pre-existing `dist/`
- [x] Decide whether the script should always delete `dist/` or only clean matching release artifacts.
- [x] Add a CI check or local test command that exercises the packager outside the release workflow.

Acceptance criteria:
- `python scripts/package_release.py --tag v0.0.0` succeeds on a clean checkout.
- Re-running the same command with an existing `dist/` directory also succeeds.
- The packaging step in `.github/workflows/release.yml` is no longer a known single-point failure.

Status:
- [x] Completed

## Priority 1: Resolve SSOT and Spec Governance Drift

Issue:
- The repository contains SSOT/spec validation scaffolding, but the current checkout does not include the full expected root files and `spec/` tree.
- CI only runs those checks conditionally, which suggests the governance layer is partially dormant rather than actively maintained.
- `checks/CHECKS_INDEX.md` and related tooling describe files and processes that do not currently match the live repository shape.

Affected files:
- `checks/ssot_validate.py`
- `checks/CHECKS_INDEX.md`
- `.github/workflows/ci.yml`
- `README.md`

Tasks:
- [x] Decide whether the SSOT/spec governance layer is still an active project requirement.
- [x] If it is active, add the missing root docs and `spec/` content required by the validation tools.
- [x] If it is not active, remove or simplify the dormant validation paths and stale documentation.
- [x] Make the chosen direction explicit in `README.md` and contributor guidance.
- [x] Ensure CI reflects the real repo contract instead of a conditional legacy path.

Acceptance criteria:
- A contributor can tell from the docs whether SSOT/spec governance is required.
- CI contains either an always-valid SSOT path or no SSOT path at all.
- `checks/CHECKS_INDEX.md` matches the actual repository contents and supported workflows.

Status:
- [x] Completed

## Priority 2: Split the Extraction Monolith

Issue:
- `crates/veil-extract/src/lib.rs` is the largest and most security-sensitive file in the repo.
- It currently owns text, structured formats, archives, email, MBOX, OOXML extraction, path normalization, archive limit enforcement, and helper parsing logic in one module.
- This raises change risk even though the behavior is well-tested today.

Affected files:
- `crates/veil-extract/src/lib.rs`
- `crates/veil-extract/tests/extractors.rs`
- `crates/veil-extract/tests/fuzz_smoke.rs`
- `crates/veil-cli/tests/phase4_gates.rs`

Tasks:
- [x] Split `crates/veil-extract/src/lib.rs` into focused modules by concern.
- [x] Keep the public API stable through a small `lib.rs` facade.
- [x] Extract shared helpers for archive safety, path normalization, and bounded reads into dedicated internal modules.
- [x] Add targeted unit tests near newly extracted helpers, especially for:
  - archive path normalization
  - nested archive limits
  - MBOX separator parsing
  - OOXML text extraction
- [x] Re-run extractor, fuzz-smoke, and phase 4 regression coverage after each refactor step.

Acceptance criteria:
- No user-visible behavior changes.
- The extraction crate remains within boundary rules and is easier to reason about by module.
- Security-sensitive parser logic is broken into smaller reviewable units.

Status:
- [x] Completed

## Priority 3: Remove Semantic Duplication Between Detect and Transform

Issue:
- `veil-detect` and `veil-transform` both encode overlapping logic around selectors, JSON traversal, stable key behavior, and string-match span handling.
- The current tests catch major regressions, but the design still allows semantic drift over time.

Affected files:
- `crates/veil-detect/src/lib.rs`
- `crates/veil-transform/src/lib.rs`
- `crates/veil-cli/tests/phase2_gates.rs`
- `crates/veil-detect/tests/detect_v1.rs`

Tasks:
- [x] Inventory duplicated logic across `veil-detect` and `veil-transform`.
- [x] Decide where shared selector and traversal utilities should live without breaking layer direction.
- [x] Move shared logic into one canonical implementation.
- [x] Add cross-crate regression tests for:
  - JSON pointer selection
  - CSV header selection
  - stable JSON key behavior
  - residual verification after transformation
- [x] Document the canonical selector contract in code comments or docs.

Acceptance criteria:
- There is one source of truth for selector and structured-path semantics.
- Future selector changes require touching one implementation path, not two.
- Existing JSON pointer and stable-key regressions remain covered.

Status:
- [x] Completed

## Priority 4: Reduce Complexity in CLI Contract Hubs

Issue:
- `artifact_processor.rs`, `pack_verifier.rs`, and `run_bootstrap.rs` are well-factored compared with earlier states, but they remain major contract hubs with a lot of branching and failure handling.
- These files carry high review risk because small edits can affect resume semantics, output identity, verification behavior, or quarantine handling.

Affected files:
- `crates/veil-cli/src/artifact_processor.rs`
- `crates/veil-cli/src/pack_verifier.rs`
- `crates/veil-cli/src/run_bootstrap.rs`
- `crates/veil-cli/src/evidence_io.rs`

Tasks:
- [x] Extract smaller internal helpers from artifact commit and quarantine paths.
- [x] Extract explicit verification subcomponents for manifest loading, evidence reconciliation, and output identity checks.
- [x] Extract resume validation and bootstrap identity logic into narrower units.
- [x] Add focused tests around internal failure paths that are currently only covered through large integration tests.
- [x] Add module-level comments describing invariants for run bootstrap, verification, and artifact state transitions.

Acceptance criteria:
- The major CLI modules have clearer ownership boundaries.
- Contract-sensitive logic is easier to review in isolation.
- Existing integration coverage still passes without behavior drift.

Status:
- [x] Completed

## Priority 5: Clarify or Implement `--max-workers`

Issue:
- `--max-workers` is accepted and documented, but the baseline still executes deterministically in single-worker mode.
- The current behavior is honest in the README, but it is still a usability footgun because users may assume parallel execution exists.

Affected files:
- `README.md`
- `crates/veil-cli/src/run_command.rs`
- `crates/veil-cli/src/args.rs`
- `crates/veil-cli/tests/cli_smoke.rs`

Tasks:
- [x] Decide whether true parallel processing is part of the near-term roadmap.
- [x] If yes, create an implementation plan that preserves determinism and fail-closed behavior.
- [x] If no, reduce ambiguity by making the flag clearly advisory in help output, logs, and docs.
- [x] Consider emitting a structured warning when users pass values greater than `1`.
- [x] Add tests that lock in the chosen behavior and messaging.

Acceptance criteria:
- Users can tell exactly what `--max-workers` does today.
- The docs, CLI help, and runtime behavior all match.
- There is no implied promise of parallelism that the runtime does not fulfill.

Status:
- [x] Completed

## Priority 6: Expand Documentation and Example Coverage

Issue:
- The implementation and tests cover much more behavior than the public docs and examples currently show.
- The live example surface is mostly a single CSV walkthrough, while the code supports archives, email, MBOX, OOXML, quarantine behavior, verification integrity checks, resume flow, and limits JSON.

Affected files:
- `README.md`
- `examples/README.md`
- `examples/csv-redaction/README.md`
- `docs/compatibility-matrix.md`
- `docs/error-codes.md`

Tasks:
- [x] Add examples for at least one container format and one mail-style format.
- [x] Add operator-facing docs for:
  - quarantine behavior
  - `veil verify` integrity guarantees
  - resume workflow
  - limits JSON usage
  - common reason codes and troubleshooting
- [x] Link the broader examples and docs from `README.md`.
- [x] Decide whether the existing docs should stay intentionally minimal or grow into an operator guide.

Acceptance criteria:
- The documented behavior better matches the tested behavior.
- A new operator can understand more than the happy-path CSV demo.
- Verification and quarantine behavior are documented at the same level as run usage.

Status:
- [x] Completed

## Priority 7: Stabilize Extract Worker Protocol Expectations

Issue:
- The internal extract-worker path mirrors canonical artifact variants and reason codes manually.
- That is workable today, but it is another place where format evolution could drift from the in-process extraction contract.

Affected files:
- `crates/veil-cli/src/extract_worker.rs`
- `crates/veil-extract/src/lib.rs`

Tasks:
- [x] Review the current worker message schema and enumerate all mirrored types.
- [x] Decide whether the worker protocol should be formalized as explicit shared structs.
- [x] Add regression coverage for worker protocol round-trips when risky extractors are isolated.
- [x] Document how new extractor variants must update the worker protocol.

Acceptance criteria:
- The worker mode has an explicit compatibility story.
- Adding a new extractable artifact type cannot silently desynchronize worker behavior.

Status:
- [x] Completed

## Suggested Execution Order

1. Fix the release packager bug and add a smoke test.
2. Decide the SSOT/spec governance direction and clean up the support surface.
3. Clarify the `--max-workers` contract because it affects user expectations immediately.
4. Expand docs for verify, quarantine, resume, and limits behavior.
5. Refactor `veil-extract` into smaller internal modules.
6. Reduce duplication between detect and transform.
7. Continue shrinking the CLI contract hubs.
8. Stabilize the extract-worker protocol if worker isolation is expected to grow.

## Notes

- Most of the codebase is healthy right now. The backlog above mixes one confirmed defect with several structural and documentation tasks.
- The only issue reproduced as a current runtime failure during analysis was the missing `shutil` import in `scripts/package_release.py`.
- All other items are backlog-worthy because they increase future change risk, operator confusion, or maintenance cost.
