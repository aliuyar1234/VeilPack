# PROGRESS.md

## Task Status Table

Statuses: TODO / IN_PROGRESS / DONE / BLOCKED (BLOCKED only if blocking=YES question exists).

| Task ID | Phase | Status |
|---|---|---|
| T-0001 | PHASE_0_BOOTSTRAP | DONE |
| T-0002 | PHASE_0_BOOTSTRAP | DONE |
| T-0003 | PHASE_0_BOOTSTRAP | DONE |
| T-0004 | PHASE_0_BOOTSTRAP | IN_PROGRESS |
| T-0005 | PHASE_0_BOOTSTRAP | IN_PROGRESS |
| T-0006 | PHASE_0_BOOTSTRAP | DONE |
| T-0101 | PHASE_1_CORE_PIPELINE | TODO |
| T-0102 | PHASE_1_CORE_PIPELINE | TODO |
| T-0103 | PHASE_1_CORE_PIPELINE | TODO |
| T-0104 | PHASE_1_CORE_PIPELINE | TODO |
| T-0105 | PHASE_1_CORE_PIPELINE | TODO |
| T-0106 | PHASE_1_CORE_PIPELINE | TODO |
| T-0107 | PHASE_1_CORE_PIPELINE | TODO |
| T-0108 | PHASE_1_CORE_PIPELINE | TODO |
| T-0109 | PHASE_1_CORE_PIPELINE | TODO |
| T-0110 | PHASE_1_CORE_PIPELINE | TODO |
| T-0201 | PHASE_2_POLICY_BUNDLE | TODO |
| T-0202 | PHASE_2_POLICY_BUNDLE | TODO |
| T-0203 | PHASE_2_POLICY_BUNDLE | TODO |
| T-0204 | PHASE_2_POLICY_BUNDLE | TODO |
| T-0301 | PHASE_3_EVIDENCE_AND_AUDIT | TODO |
| T-0302 | PHASE_3_EVIDENCE_AND_AUDIT | TODO |
| T-0303 | PHASE_3_EVIDENCE_AND_AUDIT | TODO |
| T-0304 | PHASE_3_EVIDENCE_AND_AUDIT | TODO |
| T-0305 | PHASE_3_EVIDENCE_AND_AUDIT | TODO |
| T-0401 | PHASE_4_FORMATS_AND_LIMITS | TODO |
| T-0402 | PHASE_4_FORMATS_AND_LIMITS | TODO |
| T-0403 | PHASE_4_FORMATS_AND_LIMITS | TODO |
| T-0501 | PHASE_5_HARDENING | TODO |
| T-0502 | PHASE_5_HARDENING | TODO |
| T-0503 | PHASE_5_HARDENING | TODO |
| T-0504 | PHASE_5_HARDENING | TODO |
| T-0505 | PHASE_5_HARDENING | TODO |

## Evidence Recording Rules

- Evidence is recorded in this file under the relevant task/gate/check ID heading.
- Evidence must be specific: commands run, pass/fail outcome, and any relevant non-sensitive outputs.
- Evidence must not include plaintext sensitive values.


## Task Evidence

### T-0001
- status: DONE
- evidence:
  - `cargo build --workspace` PASS
  - Layer-aligned crates created under `crates/` per C-101.
  - Boundary check wired: `python checks/boundary_fitness.py` PASS (also executed via `cargo test`).

### T-0002
- status: DONE
- evidence:
  - `cargo fmt --all -- --check` PASS
  - `cargo clippy --workspace -- -D warnings` PASS
  - `cargo test --workspace` PASS
  - CI wired: `.github/workflows/ci.yml`

### T-0003
- status: DONE
- evidence:
  - `cargo run -p veil-cli -- --help` PASS
  - CLI smoke tests added: `cargo test -p veil-cli --test cli_smoke` PASS
  - Commands present (fail-closed stubs): `veil run`, `veil verify`, `veil policy lint` (exit codes per spec/04 for invalid args vs fail-closed stub).

### T-0004
- status: IN_PROGRESS
- evidence:
  - Determinism primitives started in `crates/veil-domain`:
    - hex-safe `Digest32` + ID newtypes with unit tests.
    - `ArtifactSortKey` helper for stable ordering.
  - Remaining to complete: BLAKE3 hashing helpers + tests (artifact_id/policy_id/run_id).

### T-0005
- status: IN_PROGRESS
- evidence:
  - CLI config parsing/validation implemented (strict baseline, tokenization/key invariants, quarantine-copy opt-in, output safety).
  - Default archive safety limits encoded: `crates/veil-domain/src/config.rs` (`ArchiveLimits::default`).

### T-0006
- status: DONE
- evidence:
  - README updated with implementation bootstrap pointers (build/test/run + boundary check).

### T-0101
- status: TODO
- evidence:

### T-0102
- status: TODO
- evidence:

### T-0103
- status: TODO
- evidence:

### T-0104
- status: TODO
- evidence:

### T-0105
- status: TODO
- evidence:

### T-0106
- status: TODO
- evidence:

### T-0107
- status: TODO
- evidence:

### T-0108
- status: TODO
- evidence:

### T-0109
- status: TODO
- evidence:

### T-0110
- status: TODO
- evidence:

### T-0201
- status: TODO
- evidence:

### T-0202
- status: TODO
- evidence:

### T-0203
- status: TODO
- evidence:

### T-0204
- status: TODO
- evidence:

### T-0301
- status: TODO
- evidence:

### T-0302
- status: TODO
- evidence:

### T-0303
- status: TODO
- evidence:

### T-0304
- status: TODO
- evidence:

### T-0305
- status: TODO
- evidence:

### T-0401
- status: TODO
- evidence:

### T-0402
- status: TODO
- evidence:

### T-0403
- status: TODO
- evidence:

### T-0501
- status: TODO
- evidence:

### T-0502
- status: TODO
- evidence:

### T-0503
- status: TODO
- evidence:

### T-0504
- status: TODO
- evidence:

### T-0505
- status: TODO
- evidence:


## Gate Status and Evidence

### G-SEC-OFFLINE-NO-NET
- status: TODO
- evidence:

### G-SEC-FAIL-CLOSED-TERMINAL
- status: TODO
- evidence:

### G-SEC-NO-PLAINTEXT-LEAKS
- status: TODO
- evidence:

### G-SEC-POLICY-ID-IMMUTABLE
- status: TODO
- evidence:

### G-SEC-COVERAGE-ENFORCED
- status: TODO
- evidence:

### G-SEC-VERIFY-RESIDUAL
- status: TODO
- evidence:

### G-SEC-KEY-HANDLING
- status: TODO
- evidence:

### G-SEC-QUARANTINE-NO-RAW-DEFAULT
- status: TODO
- evidence:

### G-REL-LEDGER-RESUME
- status: TODO
- evidence:

### G-REL-DETERMINISM
- status: TODO
- evidence:

### G-REL-ARCHIVE-LIMITS
- status: TODO
- evidence:

### G-REL-ATOMIC-COMMIT
- status: TODO
- evidence:

### G-PERF-NO-REGRESSION
- status: TODO
- evidence:

### G-OPS-RUNBOOK-COMPLETE
- status: TODO
- evidence:

### G-MAINT-BOUNDARY-FITNESS
- status: DONE
- evidence:
  - `python checks/boundary_fitness.py` PASS
  - `cargo test -p veil-cli --test boundary_fitness` PASS

### G-MAINT-NO-GLOBAL-STATE
- status: TODO
- evidence:

### G-COMP-PACK-COMPAT
- status: TODO
- evidence:

### G-COMP-CONTRACT-CONSISTENCY
- status: TODO
- evidence:


## Check Status and Evidence

### CHK-MANIFEST-VERIFY
- status: DONE
- evidence:
  - Regenerate: `python checks/generate_manifest.py`
  - Verify (CHK-MANIFEST-VERIFY): PASS

### CHK-FORBIDDEN-TERMS
- status: DONE
- evidence:
  - PASS (scope excludes build artifacts per D-0010)

### CHK-CORE-FILES
- status: TODO
- evidence:

### CHK-FINGERPRINT-MATRIX
- status: TODO
- evidence:

### CHK-SLOP-MAPPING
- status: TODO
- evidence:

### CHK-EVIDENCE-POINTER-FORMAT
- status: DONE
- evidence:
  - PASS

### CHK-REF-INTEGRITY
- status: DONE
- evidence:
  - PASS (evidence pointers resolve; referenced IDs exist)

### CHK-NO-ADHOC-FILES
- status: DONE
- evidence:
  - Manual review: repo contains expected SSOT spine + `crates/` implementation scaffold + `checks/` tooling + `.github/` CI.
  - Ephemeral outputs (e.g., `target/`) are excluded from the manifest generator and ignored via `.gitignore`.

### CHK-QAC-COVERAGE
- status: TODO
- evidence:

### CHK-BOUNDARY-FITNESS
- status: DONE
- evidence:
  - `python checks/boundary_fitness.py` PASS (automated)

### CHK-OFFLINE-ENFORCEMENT
- status: TODO
- evidence:

### CHK-NO-PLAINTEXT-LEAKS
- status: TODO
- evidence:

### CHK-NEGATIVE-PATHS
- status: TODO
- evidence:

### CHK-CONTRACT-CONSISTENCY
- status: TODO
- evidence:

### CHK-FAIL-CLOSED-INVARIANTS
- status: TODO
- evidence:


## SLOP_BLACKLIST Evidence

### SB-0001
- status: TODO
- evidence:

### SB-0002
- status: TODO
- evidence:

### SB-0003
- status: TODO
- evidence:

### SB-0004
- status: TODO
- evidence:

### SB-0005
- status: TODO
- evidence:

### SB-0006
- status: TODO
- evidence:

### SB-0007
- status: TODO
- evidence:

### SB-0008
- status: TODO
- evidence:

### SB-0009
- status: TODO
- evidence:

### SB-0010
- status: TODO
- evidence:

### SB-0011
- status: TODO
- evidence:

### SB-0012
- status: TODO
- evidence:


## Session History

- 2026-02-03: Initial SSOT pack generation.
- 2026-02-05: PHASE_0 bootstrap started (Rust workspace scaffold + fail-closed CLI stub + boundary fitness check + CI baseline).
