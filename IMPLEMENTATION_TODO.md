# Implementation TODO

Purpose: capture the identified security issues and refactor work in a repo-local checklist so implementation does not depend on chat context.

Status: completed on 2026-03-06.

## Guardrails

- [x] Do not start refactoring before adding regression tests for every confirmed issue.
- [x] Keep fail-closed behavior, exit codes, reason codes, determinism, and resume semantics stable unless a change is explicitly intended and documented.
- [x] Re-run the full existing validation suite after each logical milestone:
  - `cargo test --workspace`
  - `python checks/offline_enforcement.py`
  - `python checks/boundary_fitness.py`
  - `python checks/compatibility_matrix_check.py`

## Chosen Semantics

- [x] MBOX ambiguity fails closed.
  - Body lines beginning with `From ` are no longer silently treated as valid separators unless they match a valid mbox separator form.
  - Malformed or ambiguous separator cases quarantine with parse failure semantics.

- [x] JSON pointer selector behavior uses stable keys in v1.
  - Chosen option: keys must never be rewritten in v1.
  - Detection, transform, and residual verify now all observe the same JSON object paths.
  - The stale detector comment was updated to match the implemented contract.

- [x] `veil verify` is a full pack-integrity verifier.
  - Chosen option: full pack-integrity verification.
  - Chosen source of truth: both ledger and exported evidence are validated, with cross-checks.
  - Verified outputs must exist, match expected `output_id`, and still pass residual rescanning.

- [x] Residual verification quarantines on any remaining finding.
  - Chosen option: any residual finding should quarantine.
  - `LOW`, `MEDIUM`, and `HIGH` residual findings now all fail verification.

## Confirmed Issues To Fix

### 1. MBOX body lines starting with `From ` can be silently dropped

- [x] Replace or harden the hand-rolled MBOX splitting/parsing logic in `crates/veil-extract/src/lib.rs`.
- [x] Decide desired behavior for malformed/ambiguous mbox inputs.
- [x] Add tests for:
  - [x] body line beginning with `From ` containing sensitive data
  - [x] escaped `>From ` body line
  - [x] malformed separators
  - [x] multi-message mbox with safe deterministic ordering
- [x] No MBOX input can silently drop sensitive content and still produce `VERIFIED`.
- [x] Ambiguous/malformed cases fail closed.

### 2. JSON pointer selector bypass after key rewriting

- [x] Choose the intended contract for JSON field selectors.
  - [x] Option B: keys must never be rewritten in v1
- [x] Align detection, transformation, and verification semantics for selected JSON keys.
- [x] Remove or update stale comment in `crates/veil-detect/src/lib.rs` claiming keys are not rewritten in v1.
- [x] Add tests for:
  - [x] selected key rewritten but selected value remains sensitive
  - [x] selected key collision after rewrite
  - [x] duplicate-key suffixing behavior (`__dupN`) if that behavior remains supported
  - [x] selector behavior across `run` and `verify`
- [x] No selected JSON field can evade residual verification because its key changed during transformation.
- [x] JSON key mutation behavior is explicit, documented, and tested.

Note:
- Duplicate-key suffixing behavior was removed with the stable-key contract, so the bypass/collision coverage is now expressed through stable-key regression tests rather than continued `__dupN` support.

### 3. `veil verify` is not a full pack-integrity verifier

- [x] Define the exact contract of `veil verify`.
  - [x] Option A: full pack-integrity verification
- [x] Make `veil verify` validate immutable output identity.
- [x] Choose one source of truth.
  - [x] Option C: do both, with cross-checks
- [x] Update evidence schema/types.
- [x] Update run finalization to emit required identity metadata.
- [x] Update verify path to fail if:
  - [x] a verified file is missing
  - [x] a verified file's bytes do not match expected `output_id`
  - [x] evidence is tampered to downgrade/remove previously verified artifacts
  - [x] ledger/evidence are inconsistent
- [x] Keep existing residual rescanning in addition to integrity checks unless intentionally removed.
- [x] Add tests for:
  - [x] verified output removed + evidence edited to non-verified -> verify must fail
  - [x] verified output replaced with different detector-clean bytes -> verify must fail
  - [x] `artifacts.ndjson` tampered independently -> verify must fail
  - [x] ledger/evidence mismatch -> verify must fail
- [x] `veil verify` proves pack integrity at the documented contract level, not just residual cleanliness.

### 4. Residual verification only blocks `HIGH` severity

- [x] Confirm intended enforcement semantics.
  - [x] Option A: any residual finding should quarantine
- [x] Implement chosen rule in `crates/veil-verify/src/lib.rs`.
- [x] Add explicit tests for `LOW`, `MEDIUM`, and `HIGH` residual findings.
- [x] Update README/docs/error-contract language to reflect the stronger contract.
- [x] Residual severity handling is explicit, tested, and matches the documented security model.

## Regression Tests Added First

- [x] `phase4_gates` coverage for MBOX `From ` body-line ambiguity
- [x] `phase1_gates` coverage for detector-clean substitution tampering
- [x] `phase1_gates` / `phase2_gates` coverage for evidence downgrading/removal tampering
- [x] tests covering `LOW` and `MEDIUM` residual findings
- [x] tests covering JSON pointer selector + key rewrite bypass

## Refactor Plan

### Phase 1. Safe extraction from `main.rs`

- [x] Extract logging/event types into `crates/veil-cli/src/logging.rs`
- [x] Extract CLI arg parsing and validation into `crates/veil-cli/src/args.rs`
- [x] Extract path-safety and atomic-write helpers into `crates/veil-cli/src/fs_safety.rs`
- [x] Extract runtime limits loading into `crates/veil-cli/src/runtime_limits.rs`
- [x] Extract input enumeration into `crates/veil-cli/src/input_inventory.rs`
- [x] Extract pack/evidence contract structs and writers into `crates/veil-cli/src/evidence_io.rs`
- [x] Leave `main.rs` as command dispatch + help wiring only
- [x] Phase 1 acceptance met

### Phase 2. Introduce structured run orchestration

- [x] Add `RunContext` type
- [x] Add `RunPaths` type
- [x] Extract resume/bootstrap logic into `run_bootstrap.rs`
- [x] Extract finalization logic into `pack_finalize.rs`
- [x] Phase 2 acceptance met

### Phase 3. Extract an `ArtifactProcessor`

- [x] Create `artifact_processor.rs`
- [x] Move per-artifact workflow into explicit methods:
  - [x] `load_bytes`
  - [x] `extract`
  - [x] `handle_unknown_coverage`
  - [x] `detect`
  - [x] `transform`
  - [x] `reverify`
  - [x] `commit_verified_output`
  - [x] `quarantine`
- [x] Introduce one shared quarantine helper to centralize ledger state update, optional raw-copy persistence, and structured logging
- [x] Phase 3 acceptance met

### Phase 4. Refactor `verify_command.rs` into `PackVerifier`

- [x] Create `pack_verifier.rs`
- [x] Split verify flow into explicit phases:
  - [x] load/validate pack manifest
  - [x] load/validate evidence
  - [x] verify expected verified outputs
  - [x] verify no unexpected sanitized outputs exist
  - [x] apply residual rescanning
  - [x] apply hash/integrity validation
- [x] Phase 4 acceptance met

## Suggested Implementation Order

1. [x] Add regression tests for all confirmed issues
2. [x] Decide and document intended semantics for:
   - [x] `veil verify`
   - [x] residual severity enforcement
   - [x] JSON key rewriting under selectors
3. [x] Fix MBOX fail-open behavior
4. [x] Fix JSON selector/key rewrite bypass
5. [x] Fix verify integrity gap
6. [x] Fix residual severity semantics
7. [x] Perform Phase 1 refactor
8. [x] Perform Phase 2 refactor
9. [x] Perform Phase 3 refactor
10. [x] Perform Phase 4 refactor

## Final Validation Before Closing Work

- [x] `cargo fmt --all`
- [x] `cargo clippy --workspace -- -D warnings`
- [x] `cargo test --workspace`
- [x] `python checks/offline_enforcement.py`
- [x] `python checks/boundary_fitness.py`
- [x] `python checks/compatibility_matrix_check.py`
- [x] Re-run new targeted reproducer cases via the added automated regression suites

## Notes

- [x] Docs, tests, and implementation were updated together where the security contract changed.
- [x] The checklist is now a completion record rather than an open worklist.
