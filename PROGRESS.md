# PROGRESS.md

## Task Status Table

Statuses: TODO / IN_PROGRESS / DONE / BLOCKED (BLOCKED only if blocking=YES question exists).

| Task ID | Phase | Status |
|---|---|---|
| T-0001 | PHASE_0_BOOTSTRAP | DONE |
| T-0002 | PHASE_0_BOOTSTRAP | DONE |
| T-0003 | PHASE_0_BOOTSTRAP | DONE |
| T-0004 | PHASE_0_BOOTSTRAP | DONE |
| T-0005 | PHASE_0_BOOTSTRAP | DONE |
| T-0006 | PHASE_0_BOOTSTRAP | DONE |
| T-0101 | PHASE_1_CORE_PIPELINE | DONE |
| T-0102 | PHASE_1_CORE_PIPELINE | DONE |
| T-0103 | PHASE_1_CORE_PIPELINE | DONE |
| T-0104 | PHASE_1_CORE_PIPELINE | DONE |
| T-0105 | PHASE_1_CORE_PIPELINE | DONE |
| T-0106 | PHASE_1_CORE_PIPELINE | DONE |
| T-0107 | PHASE_1_CORE_PIPELINE | DONE |
| T-0108 | PHASE_1_CORE_PIPELINE | DONE |
| T-0109 | PHASE_1_CORE_PIPELINE | DONE |
| T-0110 | PHASE_1_CORE_PIPELINE | DONE |
| T-0201 | PHASE_2_POLICY_BUNDLE | DONE |
| T-0202 | PHASE_2_POLICY_BUNDLE | DONE |
| T-0203 | PHASE_2_POLICY_BUNDLE | DONE |
| T-0204 | PHASE_2_POLICY_BUNDLE | DONE |
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
- status: DONE
- evidence:
  - BLAKE3 hashing + determinism primitives implemented:
    - `crates/veil-domain/src/hashing.rs` (artifact_id/source_locator_hash/output_id, input_corpus_id, run_id)
    - `crates/veil-policy/src/bundle_id.rs` (policy_id hashing per D-0001 + D-0011)
  - `cargo test --workspace` PASS
  - Boundary check remains enforced: `python checks/boundary_fitness.py` PASS

### T-0005
- status: DONE
- evidence:
  - CLI config parsing/validation implemented (strict baseline, tokenization/key invariants, quarantine-copy opt-in, output safety).
  - Default archive safety limits encoded: `crates/veil-domain/src/config.rs` (`ArchiveLimits::default`).
  - `--limits-json` parsing implemented (schema `limits.v1`, deny unknown fields; see D-0012).
  - Limits-json tests: `cargo test -p veil-cli --test limits_json` PASS

### T-0006
- status: DONE
- evidence:
  - README updated with implementation bootstrap pointers (build/test/run + boundary check).

### T-0101
- status: DONE
- evidence:
  - Deterministic corpus enumeration implemented (sorted directory entries; stable `ArtifactSortKey` ordering).
  - Artifact identifiers computed per spec:
    - `artifact_id = BLAKE3(file bytes)`
    - `source_locator_hash = BLAKE3(normalized relative path)`
  - Plaintext paths are not emitted to evidence outputs (asserted by CLI smoke tests).
  - `cargo test --workspace` PASS

### T-0102
- status: DONE
- evidence:
  - Ledger schema v1 implemented as SQLite at `<pack_root>/evidence/ledger.sqlite3` (atomic transitions via transactions).
  - Resume semantics implemented:
    - output directory is accepted for resume only when an in-progress marker and ledger exist
    - refuses resume when the in-progress marker/run_id does not match (covers policy_id and corpus drift)
    - skips terminal artifacts (VERIFIED/QUARANTINED) on resume
  - Resume tests:
    - `cargo test -p veil-cli --test cli_smoke` PASS

### T-0103
- status: DONE
- evidence:
  - Extractor framework + registry implemented:
    - `crates/veil-extract` returns canonical artifacts + CoverageMap v1 or QUARANTINED.
    - `veil run` enforces `UNKNOWN` coverage → QUARANTINED (fail-closed).
  - Tests:
    - `cargo test -p veil-extract` PASS
    - `cargo test -p veil-cli --test phase1_gates` PASS

### T-0104
- status: DONE
- evidence:
  - Built-in extractors implemented: TEXT, CSV/TSV, JSON, NDJSON.
  - Canonicalization rules enforced:
    - JSON/NDJSON object keys sorted recursively.
    - CSV/TSV parsed with headers; canonical writer emits LF line endings.
  - Tests:
    - `cargo test -p veil-extract` PASS

### T-0105
- status: DONE
- evidence:
  - Detector engine v1 implemented (offline, deterministic):
    - regex detectors (bounded at policy load)
    - checksum: Luhn
    - field selectors: json_pointer and csv_header
  - Tests:
    - `cargo test -p veil-detect` PASS
    - `cargo test -p veil-cli --test phase1_gates` PASS

### T-0106
- status: DONE
- evidence:
  - Transform engine v1 implemented (deterministic):
    - REDACT: `{{<class_id>}}` marker replacement
    - MASK: keep last N chars
    - DROP: delete matched spans
  - Transforms applied before outputs are committed.
  - Tests:
    - `cargo test -p veil-cli --test phase1_gates` PASS

### T-0107
- status: DONE
- evidence:
  - Rewriters + atomic commit staging implemented:
    - stage writes under `<workdir>/staging/`
    - fsync staged file then rename into `sanitized/`
    - deterministic output mapping per D-0014
  - Atomicity regression test:
    - `cargo test -p veil-cli --test phase1_gates` PASS (failpoint ensures no partial files in `sanitized/`)

### T-0108
- status: DONE
- evidence:
  - Residual verification enforced in `veil run` (two-pass scan):
    - output is re-parsed and re-scanned with the same detector set
    - residual HIGH findings quarantine with reason `VERIFICATION_FAILED`
  - `veil verify` implemented and re-scans VERIFIED outputs.
  - Tests:
    - `cargo test -p veil-cli --test phase1_gates` PASS (residual quarantine + verify tamper regression)

### T-0109
- status: DONE
- evidence:
  - Exit code semantics enforced:
    - `2` when any artifacts are QUARANTINED
    - `0` only when no quarantines exist
  - Quarantine reason codes emitted as stable, non-sensitive codes (spec/03).
  - Reason codes exercised end-to-end (non-sensitive):
    - `UNSUPPORTED_FORMAT`, `PARSE_ERROR`, `UNKNOWN_COVERAGE`, `VERIFICATION_FAILED`, `INTERNAL_ERROR`
  - `cargo test --workspace` PASS

### T-0110
- status: DONE
- evidence:
  - `veil run` creates Veil Pack layout v1 and writes `pack_manifest.json` last.
  - Uses an in-progress marker in workdir and removes it on successful completion.
  - `cargo test --workspace` PASS

### T-0201
- status: DONE
- evidence:
  - Strict policy schema validation + compilation implemented in `crates/veil-policy` (`serde` deny_unknown_fields; bounded regex compilation; reject unsupported features).
  - `veil policy lint` implemented (validates policy bundle and prints policy_id).
  - `cargo test -p veil-cli --test phase2_gates` PASS (policy lint prints policy_id; rejects unknown fields)

### T-0202
- status: DONE
- evidence:
  - Canonical policy bundle hashing tests:
    - `cargo test -p veil-policy --test policy_bundle_id` PASS
  - policy_id immutability enforced:
    - `cargo test -p veil-cli --test cli_smoke` PASS (resume refuses on policy mismatch)
    - `cargo test -p veil-cli --test phase2_gates` PASS (verify refuses on policy mismatch; pack_manifest policy_id matches computed policy_id)

### T-0203
- status: DONE
- evidence:
  - Policy compiler produces deterministic detector set + per-class action plan and fails closed on invalid policy.
  - `cargo test -p veil-cli --test phase2_gates` PASS (policy lint path exercises policy compilation; invalid policies exit 3)

### T-0204
- status: DONE
- evidence:
  - Strict is the only supported baseline in v1; non-strict strictness fails closed:
    - `cargo test -p veil-cli --test phase2_gates` PASS (run refuses `--strictness permissive`)
  - Strict enforcement paths covered by Phase 1 gates (UNKNOWN coverage/residual/quarantine behavior):
    - `cargo test -p veil-cli --test phase1_gates` PASS

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
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (asserts every artifact ends VERIFIED or QUARANTINED)

### G-SEC-NO-PLAINTEXT-LEAKS
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (canary string absent from logs/evidence/quarantine index + sanitized)

### G-SEC-POLICY-ID-IMMUTABLE
- status: DONE
- evidence:
  - `cargo test -p veil-policy --test policy_bundle_id` PASS (canonical policy bundle hashing)
  - `cargo test -p veil-cli --test cli_smoke` PASS (resume refuses when policy_id mismatches ledger)
  - `cargo test -p veil-cli --test phase2_gates` PASS (verify refuses on policy_id mismatch; policy_id bound in pack_manifest)

### G-SEC-COVERAGE-ENFORCED
- status: TODO
- evidence:

### G-SEC-VERIFY-RESIDUAL
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (residual verification quarantines; `veil verify` catches tampered VERIFIED output)

### G-SEC-KEY-HANDLING
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase2_gates` PASS:
    - tokenization disabled by default
    - enabling tokenization without key fails to start
    - evidence includes `proof_key_commitment` only; secret key is never persisted

### G-SEC-QUARANTINE-NO-RAW-DEFAULT
- status: TODO
- evidence:

### G-REL-LEDGER-RESUME
- status: TODO
- evidence:

### G-REL-DETERMINISM
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (double-run snapshot equality; excludes `.veil_work/`)

### G-REL-ARCHIVE-LIMITS
- status: TODO
- evidence:

### G-REL-ATOMIC-COMMIT
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (failpoint abort after staging write; asserts `sanitized/` contains no partial files)

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
  - Regenerate: `python checks/generate_manifest.py` (post changes)
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
  - `python -c` (see `checks/CHECKS_INDEX.md` CHK-EVIDENCE-POINTER-FORMAT) PASS

### CHK-REF-INTEGRITY
- status: DONE
- evidence:
  - PASS (evidence pointers resolve; referenced IDs exist)
  - Evidence pointer resolution check (path exists + phrase present): PASS

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
  - `cargo test --workspace` PASS (includes boundary fitness test)

### CHK-OFFLINE-ENFORCEMENT
- status: TODO
- evidence:

### CHK-NO-PLAINTEXT-LEAKS
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (canary regression)

### CHK-NEGATIVE-PATHS
- status: TODO
- evidence:

### CHK-CONTRACT-CONSISTENCY
- status: TODO
- evidence:

### CHK-FAIL-CLOSED-INVARIANTS
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (terminal states only; no partial outputs on failpoint)


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
- 2026-02-05: PHASE_1 baseline started (pack layout v1 output + resumability ledger/resume + pack schema version decision).
- 2026-02-05: PHASE_1 core pipeline completed (extract/detect/transform/residual verify + atomic commit + determinism + canary tests).
- 2026-02-05: PHASE_2 policy bundle completed (policy lint + immutability + key-handling gate tests).
