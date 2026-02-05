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
| T-0301 | PHASE_3_EVIDENCE_AND_AUDIT | DONE |
| T-0302 | PHASE_3_EVIDENCE_AND_AUDIT | DONE |
| T-0303 | PHASE_3_EVIDENCE_AND_AUDIT | DONE |
| T-0304 | PHASE_3_EVIDENCE_AND_AUDIT | DONE |
| T-0305 | PHASE_3_EVIDENCE_AND_AUDIT | DONE |
| T-0401 | PHASE_4_FORMATS_AND_LIMITS | DONE |
| T-0402 | PHASE_4_FORMATS_AND_LIMITS | DONE |
| T-0403 | PHASE_4_FORMATS_AND_LIMITS | DONE |
| T-0501 | PHASE_5_HARDENING | DONE |
| T-0502 | PHASE_5_HARDENING | DONE |
| T-0503 | PHASE_5_HARDENING | DONE |
| T-0504 | PHASE_5_HARDENING | DONE |
| T-0505 | PHASE_5_HARDENING | DONE |

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
  - Runtime resource limits extended with `disk.max_workdir_bytes` (default 1 GiB) and fail-closed validation.
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
- status: DONE
- evidence:
  - Evidence bundle writer implemented:
    - `evidence/run_manifest.json`
    - `evidence/artifacts.ndjson`
  - Evidence safety regression tests:
    - `cargo test -p veil-cli --test phase1_gates` PASS (canary string absent from logs/evidence/quarantine index + sanitized)

### T-0302
- status: DONE
- evidence:
  - Quarantine index writer implemented: `quarantine/index.ndjson` (non-sensitive).
  - Default no-raw quarantine policy enforced:
    - `cargo test -p veil-cli --test cli_smoke` PASS (no `quarantine/raw/` by default)
  - Raw quarantine copying is explicit opt-in and contained:
    - `cargo test -p veil-cli --test phase3_gates` PASS (copies appear only under `quarantine/raw/` when enabled)

### T-0303
- status: DONE
- evidence:
  - Pack manifest writer implemented:
    - `pack_manifest.json` includes required identity + schema version fields and is written last (no timestamps).
  - `cargo test -p veil-cli --test phase1_gates` PASS (deterministic pack snapshot includes pack_manifest.json)
  - `cargo test -p veil-cli --test phase3_gates` PASS (pack_manifest includes schema versions; verify enforces them)

### T-0304
- status: DONE
- evidence:
  - `veil verify` rescans VERIFIED outputs and fails on residual HIGH findings:
    - `cargo test -p veil-cli --test phase1_gates` PASS (verify catches tampered VERIFIED output)
  - Verify refuses unsupported pack/ledger schema versions:
    - `cargo test -p veil-cli --test phase3_gates` PASS
  - Verify fail-closed hardening:
    - refuses unsafe `pack_manifest.json` / `artifacts.ndjson` paths before read
    - fails when `sanitized/` contains files not represented as VERIFIED in evidence
    - `cargo test -p veil-cli --test phase2_gates verify_fails_closed_on_unexpected_sanitized_output_file -- --exact` PASS

### T-0305
- status: DONE
- evidence:
  - Proof tokens emitted as digest-only evidence and never plaintext:
    - `cargo test -p veil-cli --test phase3_gates` PASS (proof_tokens are 12-hex digests; plaintext value absent from artifacts.ndjson)
  - Proof token binding decision logged:
    - evidence: DECISIONS.md :: ## D-0016 — Proof token emission binding (v1)

### T-0401
- status: DONE
- evidence:
  - Archive extractor (ZIP/TAR) enforces D-0006 limits and quarantines on violations/unsafe paths:
    - `cargo test -p veil-cli --test phase4_gates` PASS

### T-0402
- status: DONE
- evidence:
  - Email extractors (EML/MBOX) parse headers/body and quarantine on unsupported attachments:
    - `cargo test -p veil-cli --test phase4_gates` PASS

### T-0403
- status: DONE
- evidence:
  - OOXML bounded extractor (DOCX/PPTX/XLSX) quarantines on unknown embedded objects coverage:
    - `cargo test -p veil-cli --test phase4_gates` PASS

### T-0501
- status: DONE
- evidence:
  - Perf harness implemented + baseline captured:
    - `python checks/perf_harness.py --record-baseline` PASS (writes `checks/perf_baseline.json`)
    - `python checks/perf_harness.py` PASS (compares against baseline)

### T-0502
- status: DONE
- evidence:
  - Fuzz/property smoke for extractors and archive handling:
    - `cargo test -p veil-extract --test fuzz_smoke` PASS

### T-0503
- status: DONE
- evidence:
  - Determinism suite extended to include container formats:
    - `cargo test -p veil-cli --test phase5_gates` PASS (determinism corpus includes ZIP/TAR/EML/MBOX/DOCX)

### T-0504
- status: DONE
- evidence:
  - Key hardening:
    - `crates/veil-cli/src/main.rs` uses `zeroize` to zeroize derived proof keys and root secrets after use.
  - Temp hygiene and partial-output avoidance:
    - `cargo test -p veil-cli --test phase1_gates` PASS (atomic commit; no partial files in `sanitized/`)
  - Atomic persistence hardening:
    - atomic JSON/bytes writers sync temp files and parent directories
    - sanitized commit supports cross-filesystem-safe fallback atomic write path

### T-0505
- status: DONE
- evidence:
  - Release packaging + offline distribution notes added:
    - evidence: spec/12_RUNBOOK.md :: Offline distribution (release packaging)


## Gate Status and Evidence

### G-SEC-OFFLINE-NO-NET
- status: DONE
- evidence:
  - Static scan: `python checks/offline_enforcement.py` PASS
  - Runtime smoke: `cargo test -p veil-cli --test offline_enforcement` PASS
  - Runtime enforcement hardened: offline test now monitors live process socket activity while running under denied-proxy posture.

### G-SEC-FAIL-CLOSED-TERMINAL
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (asserts every artifact ends VERIFIED or QUARANTINED)
  - `cargo test --workspace` PASS (includes `read_artifact_detects_identity_mismatch` in `crates/veil-cli/src/main.rs`)
  - `cargo test -p veil-cli --test phase2_gates verify_fails_closed_on_unexpected_sanitized_output_file -- --exact` PASS (verify rejects untracked sanitized outputs)

### G-SEC-NO-PLAINTEXT-LEAKS
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (canary string absent from logs/evidence/quarantine index + sanitized)
  - `cargo test -p veil-cli --test phase1_gates logs_use_structured_json_schema_v1 -- --exact` PASS (stderr logs use JSON schema v1 fields)
  - `cargo test -p veil-cli --test cli_smoke usage_errors_redact_unexpected_argument_values -- --exact` PASS (usage errors do not echo unexpected argument content)

### G-SEC-POLICY-ID-IMMUTABLE
- status: DONE
- evidence:
  - `cargo test -p veil-policy --test policy_bundle_id` PASS (canonical policy bundle hashing)
  - `cargo test -p veil-cli --test cli_smoke` PASS (resume refuses when policy_id mismatches ledger)
  - `cargo test -p veil-cli --test phase2_gates` PASS (verify refuses on policy_id mismatch; policy_id bound in pack_manifest)

### G-SEC-COVERAGE-ENFORCED
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase4_gates` PASS (UNKNOWN coverage never results in VERIFIED; OOXML embedded binaries quarantine)

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
  - `cargo test -p veil-cli --test phase3_gates` PASS (proof_tokens are digest-only; no plaintext values)

### G-SEC-QUARANTINE-NO-RAW-DEFAULT
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test cli_smoke` PASS (no `quarantine/raw/` by default)
  - `cargo test -p veil-cli --test phase3_gates` PASS (opt-in raw copying only under `quarantine/raw/`)

### G-REL-LEDGER-RESUME
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase5_gates` PASS (crash simulation then resume completes)
  - `cargo test -p veil-cli --test cli_smoke` PASS (resume refuses policy mismatch; resume succeeds with marker+ledger)
  - `cargo test -p veil-cli --test cli_smoke run_resume_refuses_when_pack_manifest_already_exists -- --exact` PASS (resume refused when output already finalized)

### G-REL-DETERMINISM
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (double-run snapshot equality; excludes `.veil_work/`)

### G-REL-ARCHIVE-LIMITS
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase4_gates` PASS (archive limits + unsafe paths quarantine; no partial emission)
  - `cargo test -p veil-cli --test phase4_gates tar_max_entries_limit_quarantines_entire_archive -- --exact` PASS
  - `cargo test -p veil-cli --test phase4_gates tar_expanded_bytes_limit_quarantines_entire_archive -- --exact` PASS
  - `cargo test -p veil-cli --test phase4_gates tar_symlink_entry_quarantines_entire_archive -- --exact` PASS
  - `cargo test -p veil-cli --test limits_json` PASS (enforces `artifact.max_bytes_per_artifact` + `disk.max_workdir_bytes` bounds with `LIMIT_EXCEEDED` quarantine)

### G-REL-ATOMIC-COMMIT
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (failpoint abort after staging write; asserts `sanitized/` contains no partial files)
  - Manual review: output/workdir and output write paths are guarded by symlink/reparse safety checks before processing/writes.
  - `cargo test -p veil-cli --test cli_smoke run_rejects_workdir_symlink_path -- --exact` PASS
  - Manual review: atomic writers now fsync temp files and parent directories; sanitized writes use atomic fallback when direct rename fails.

### G-PERF-NO-REGRESSION
- status: DONE
- evidence:
  - `python checks/perf_harness.py` PASS (no regression vs `checks/perf_baseline.json`)
  - Post D-0018 hardening: `python checks/perf_harness.py` PASS (no regression vs baseline; tolerance 0.15)

### G-OPS-RUNBOOK-COMPLETE
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase5_gates` PASS (runbook quickstart end-to-end: run + verify)

### G-MAINT-BOUNDARY-FITNESS
- status: DONE
- evidence:
  - `python checks/boundary_fitness.py` PASS
  - `cargo test -p veil-cli --test boundary_fitness` PASS

### G-MAINT-NO-GLOBAL-STATE
- status: DONE
- evidence:
  - Manual review: policy/key/run context is passed explicitly; no hidden mutable singletons for critical flows.
  - `rg "static mut|lazy_static|once_cell::sync::Lazy" crates` PASS (no matches)

### G-COMP-PACK-COMPAT
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase3_gates` PASS (verify refuses unsupported pack_schema_version and ledger_schema_version)

### G-COMP-CONTRACT-CONSISTENCY
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test contract_consistency` PASS (CLI help flags + pack layout v1 assertions, including tokenization metadata and `ledger_schema_version`)


## Check Status and Evidence

### CHK-MANIFEST-VERIFY
- status: DONE
- evidence:
  - Regenerate: `python checks/generate_manifest.py`
  - Verify (CHK-MANIFEST-VERIFY): PASS
  - Regenerate: `python checks/generate_manifest.py` (post changes)
  - Verify (CHK-MANIFEST-VERIFY): PASS
  - Regenerate: `python checks/generate_manifest.py` (post PHASE_3 changes)
  - Verify (CHK-MANIFEST-VERIFY): PASS
  - Regenerate: `python checks/generate_manifest.py` (post doc alignment)
  - Verify (CHK-MANIFEST-VERIFY): PASS
  - Regenerate: `python checks/generate_manifest.py` (post PHASE_4 changes)
  - Verify (CHK-MANIFEST-VERIFY): PASS
  - Regenerate: `python checks/generate_manifest.py` (post PHASE_5 changes)
  - Verify (CHK-MANIFEST-VERIFY): PASS
  - Regenerate: `python checks/generate_manifest.py` (post D-0018 hardening changes)
  - Verify (CHK-MANIFEST-VERIFY): PASS
  - Regenerate: `python checks/generate_manifest.py` (post security audit log updates)
  - Verify (CHK-MANIFEST-VERIFY): PASS
  - Verify (CHK-MANIFEST-VERIFY): PASS (2026-02-05)
  - Regenerate: `python checks/generate_manifest.py` (post audit session updates)
  - Verify (CHK-MANIFEST-VERIFY): PASS (post audit session updates)
  - Verify (CHK-MANIFEST-VERIFY): PASS (session start; 2026-02-05)
  - Regenerate: `python checks/generate_manifest.py` (post codebase security audit log updates)
  - Verify (CHK-MANIFEST-VERIFY): PASS (post codebase security audit log updates)
  - Regenerate: `python checks/generate_manifest.py` (post D-0020 remediation hardening)
  - Verify (CHK-MANIFEST-VERIFY): PASS (post D-0020 remediation hardening)
  - Regenerate: `python checks/generate_manifest.py` (post D-0021 runtime hardening)
  - Verify (CHK-MANIFEST-VERIFY): PASS (post D-0021 runtime hardening)

### CHK-FORBIDDEN-TERMS
- status: DONE
- evidence:
  - PASS (scope excludes build artifacts per D-0010)

### CHK-CORE-FILES
- status: DONE
- evidence:
  - `python checks/ssot_validate.py core-files` PASS

### CHK-FINGERPRINT-MATRIX
- status: DONE
- evidence:
  - `python checks/ssot_validate.py fingerprint-matrix` PASS

### CHK-SLOP-MAPPING
- status: DONE
- evidence:
  - `python checks/ssot_validate.py slop-mapping` PASS

### CHK-EVIDENCE-POINTER-FORMAT
- status: DONE
- evidence:
  - PASS
  - `python -c` (see `checks/CHECKS_INDEX.md` CHK-EVIDENCE-POINTER-FORMAT) PASS
  - Post PHASE_3: PASS
  - Post doc alignment: PASS
  - Post PHASE_4: PASS
  - Post PHASE_5: PASS
  - Post D-0018 hardening docs update: PASS (`python -c` check from CHK-EVIDENCE-POINTER-FORMAT)
  - Post security audit log update: PASS (`python -c` check from CHK-EVIDENCE-POINTER-FORMAT)
  - PASS (`python -c` check from CHK-EVIDENCE-POINTER-FORMAT) (2026-02-05)
  - Post codebase security audit log update: PASS (`python -c` check from CHK-EVIDENCE-POINTER-FORMAT)
  - Post D-0020 remediation: PASS (`python -c` check from CHK-EVIDENCE-POINTER-FORMAT)
  - Post D-0021 runtime hardening: PASS (`python -c` check from CHK-EVIDENCE-POINTER-FORMAT)

### CHK-REF-INTEGRITY
- status: DONE
- evidence:
  - PASS (evidence pointers resolve; referenced IDs exist)
  - Evidence pointer resolution check (path exists + phrase present): PASS
  - Post PHASE_3: PASS
  - Post doc alignment: PASS
  - Post PHASE_4: PASS (`python -c` evidence pointer resolution check)
  - Post PHASE_5: PASS (`python -c` evidence pointer resolution check)
  - Post D-0018 hardening docs update: PASS (`python -c` evidence pointers + ID existence check)
  - Post security audit log update: PASS (`python -c` evidence pointers + ID existence check)
  - PASS (`python -c` evidence pointer resolution + ID existence check) (2026-02-05)
  - Post codebase security audit log update: PASS (manual review: evidence pointers resolve; referenced IDs exist)
  - Post D-0020 remediation: PASS (`python -c` evidence pointer resolution check)
  - Post D-0021 runtime hardening: PASS (`python -c` evidence pointer resolution check)

### CHK-NO-ADHOC-FILES
- status: DONE
- evidence:
  - Manual review: repo contains expected SSOT spine + `crates/` implementation scaffold + `checks/` tooling + `.github/` CI.
  - Ephemeral outputs (e.g., `target/`) are excluded from the manifest generator and ignored via `.gitignore`.
  - Post PHASE_4: PASS (`git ls-files --others --exclude-standard` is empty)
  - Post PHASE_5: PASS (`git ls-files --others --exclude-standard` is empty)
  - Post D-0018 hardening: PASS (`git ls-files --others --exclude-standard` is empty)
  - Post security audit log update: PASS (manual review of top-level tree)
  - Post security audit log update: PASS (`git ls-files --others --exclude-standard` is empty)
  - PASS (`git ls-files --others --exclude-standard` is empty) (2026-02-05)
  - Post codebase security audit log update: PASS (`git ls-files --others --exclude-standard` is empty)
  - Post D-0020 remediation: PASS (`git ls-files --others --exclude-standard` is empty)
  - Post D-0021 runtime hardening: PASS (top-level allowlist check; ephemeral build outputs excluded)

### CHK-QAC-COVERAGE
- status: DONE
- evidence:
  - `python checks/ssot_validate.py qac-coverage` PASS

### CHK-BOUNDARY-FITNESS
- status: DONE
- evidence:
  - `python checks/boundary_fitness.py` PASS (automated)
  - `cargo test --workspace` PASS (includes boundary fitness test)
  - Post D-0021 runtime hardening: `python checks/boundary_fitness.py` PASS

### CHK-OFFLINE-ENFORCEMENT
- status: DONE
- evidence:
  - `python checks/offline_enforcement.py` PASS
  - `cargo test -p veil-cli --test offline_enforcement` PASS
  - Static scan scope widened to `crates/**/*.rs` (includes `build.rs`) to reduce blind spots.
  - CI workflow includes both static and runtime offline enforcement commands.
  - Post D-0021 runtime hardening: `python checks/offline_enforcement.py` PASS

### CHK-NO-PLAINTEXT-LEAKS
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (canary regression)

### CHK-LOG-SCHEMA
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates logs_use_structured_json_schema_v1 -- --exact` PASS

### CHK-NEGATIVE-PATHS
- status: DONE
- evidence:
  - `cargo test -p veil-cli --tests` PASS
  - Post D-0021 runtime hardening: `cargo test -p veil-cli --tests` PASS

### CHK-CONTRACT-CONSISTENCY
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test contract_consistency` PASS
  - Post D-0021 runtime hardening: `cargo test -p veil-cli --test contract_consistency` PASS

### CHK-FAIL-CLOSED-INVARIANTS
- status: DONE
- evidence:
  - `cargo test -p veil-cli --test phase1_gates` PASS (terminal states only; no partial outputs on failpoint)


## SLOP_BLACKLIST Evidence

### SB-0001
- status: DONE
- evidence:
  - Safe defaults are explicit and tested:
    - `cargo test -p veil-cli --test phase2_gates` PASS (tokenization off by default; strict baseline only)
    - `cargo test -p veil-cli --test phase3_gates` PASS (quarantine raw copy is opt-in only)

### SB-0002
- status: DONE
- evidence:
  - Boundary enforcement prevents mega-modules:
    - `cargo test -p veil-cli --test boundary_fitness` PASS

### SB-0003
- status: DONE
- evidence:
  - Manual review: added format support uses shared helpers (limits/path normalization/record builders) rather than copy/paste forks.

### SB-0004
- status: DONE
- evidence:
  - Negative paths are covered by integration suites:
    - `cargo test -p veil-cli --tests` PASS (parse failures, unknown coverage, residual verify, archive limit violations)

### SB-0005
- status: DONE
- evidence:
  - Manual review: no unbounded retries; archive expansion is bounded by D-0006 limits.
  - Runtime smoke uses an explicit timeout guard:
    - `cargo test -p veil-cli --test offline_enforcement` PASS

### SB-0006
- status: DONE
- evidence:
  - Manual review: no hidden mutable singletons for policy/keys/run context.
  - `rg "static mut|lazy_static|once_cell::sync::Lazy" crates` PASS (no matches)

### SB-0007
- status: DONE
- evidence:
  - Manual review: glossary terms (VERIFIED/QUARANTINED/CoverageMap) remain consistent with spec/03.

### SB-0008
- status: DONE
- evidence:
  - Canary regression prevents plaintext leaks:
    - `cargo test -p veil-cli --test phase1_gates` PASS

### SB-0009
- status: DONE
- evidence:
  - Contract tests enforce spec/04 alignment:
    - `cargo test -p veil-cli --test contract_consistency` PASS

### SB-0010
- status: DONE
- evidence:
  - Fail-closed invariants are enforced:
    - `cargo test -p veil-cli --test phase1_gates` PASS (terminal states only; atomic commit; residual verify)

### SB-0011
- status: DONE
- evidence:
  - New harness scripts are documented and versioned under `checks/` and runbook:
    - evidence: checks/CHECKS_INDEX.md :: Checks Index
    - evidence: spec/12_RUNBOOK.md :: Phase 5 harnesses (optional operator checks)

### SB-0012
- status: DONE
- evidence:
  - Structural/output contract changes are logged as decisions:
    - evidence: DECISIONS.md :: ## D-0017 — Container format canonicalization to NDJSON (v1)
    - evidence: DECISIONS.md :: ## D-0018 — Hardening baseline: per-artifact memory bounds, identity revalidation, and unsafe output-path refusal
    - evidence: DECISIONS.md :: ## D-0020 - Remediation hardening pass: structured logs, resume metadata binding, and path/write safety tightening


## Session History

- 2026-02-03: Initial SSOT pack generation.
- 2026-02-05: PHASE_0 bootstrap started (Rust workspace scaffold + fail-closed CLI stub + boundary fitness check + CI baseline).
- 2026-02-05: PHASE_1 baseline started (pack layout v1 output + resumability ledger/resume + pack schema version decision).
- 2026-02-05: PHASE_1 core pipeline completed (extract/detect/transform/residual verify + atomic commit + determinism + canary tests).
- 2026-02-05: PHASE_2 policy bundle completed (policy lint + immutability + key-handling gate tests).
- 2026-02-05: PHASE_3 evidence and audit completed (proof tokens + pack compatibility tests).
- 2026-02-05: PHASE_4 formats and limits completed (ZIP/TAR/EML/MBOX/OOXML + limits + gates; decision D-0017).
- 2026-02-05: PHASE_5 hardening completed (perf harness + fuzz smoke + crash+resume + contract/offline checks + runbook updates).
- 2026-02-05: Security hardening follow-up completed (D-0018): per-artifact memory bounds, identity revalidation, unsafe output/workdir path refusal, stronger offline runtime monitoring, and pinned CI actions.
- 2026-02-05: Security audit completed (Audit Agent A); findings captured externally; no implementation changes.
- 2026-02-05: Implementation architecture audit completed (robustness/usability review; no code changes).
- 2026-02-05: Codebase security audit completed (crates/checks review; report-only, no code changes).
- 2026-02-05: D-0020 remediation hardening completed (structured JSON logs, resume metadata binding, unsafe path/write tightening, archive observed-byte limits, expanded tests, and CI gate coverage).
