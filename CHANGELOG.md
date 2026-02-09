# CHANGELOG.md

## SSOT Pack Changelog (no product code)

### Initial pack
- Created full SSOT spine and applicable specs for Veil offline fail-closed pipeline.
- Resolved Q-0001..Q-0008 into D-0001..D-0008 with conservative baselines.

### Patch v1.0.1
- Added explicit resolved question entries for Q-0001..Q-0008 to satisfy reference/ID integrity checks (no behavior change).
- Regenerated MANIFEST.sha256 and updated AUDIT_REPORT external audit section accordingly.

### Bootstrap (implementation started)
- Added Rust workspace scaffold with layer-aligned crates under `crates/`.
- Added fail-closed `veil` CLI stub and smoke tests.
- Added automated boundary fitness check (`checks/boundary_fitness.py`) and CI workflow.
- Added `.gitignore` to keep build artifacts out of the repo surface.

### Determinism + config primitives
- Added BLAKE3 hashing utilities (artifact_id/source_locator_hash/run_id) and policy bundle hashing (policy_id).
- Defined `--limits-json` schema `limits.v1`, implemented parsing, and added CLI tests.
- Updated decisions (D-0011, D-0012) and contracts (`spec/04`).

### Core pipeline baseline (PHASE_1 started)
- Implemented a minimal `veil run` that emits Veil Pack layout v1 (sanitized/quarantine/evidence + pack_manifest).
- Added SQLite ledger v1 (`ledger.sqlite3`) and safe resume support using an in-progress marker.
- Logged `pack_schema_version` literal `pack.v1` (D-0013) and updated `spec/04` accordingly.

### Core pipeline (PHASE_1 completed)
- Implemented end-to-end deterministic pipeline for core formats:
  - policy loading (strict v1 baseline support)
  - extraction + CoverageMap v1
  - detection (regex/Luhn + field selectors)
  - transforms (REDACT/MASK/DROP)
  - residual verification pass + `veil verify`
  - atomic staging + deterministic sanitized path mapping
- Added Phase 1 gate tests (fail-closed terminal, residual verify, no-plaintext canary, determinism, atomic commit).

### Policy bundle (PHASE_2 completed)
- Implemented `veil policy lint` (strict validation + prints policy_id).
- Enforced policy_id immutability across resume and verify with integration tests.
- Hardened key-handling evidence metadata: run manifest records proof key commitment and tokenization scope when enabled, without persisting the secret key.

### Evidence and audit (PHASE_3 completed)
- Added pack compatibility tests and enforcement (`veil verify` refuses unsupported pack/ledger schema versions).
- Implemented proof token emission (digest-only correlation tokens in `artifacts.ndjson`) with key commitment metadata in `run_manifest.json` (D-0016).
- Added quarantine raw-copy opt-in tests (`quarantine/raw/` created only when explicitly enabled).

### Formats and limits (PHASE_4 completed)
- Added container format extractors emitting NDJSON canonical representations:
  - ZIP/TAR with D-0006 safety limits, nested archive depth enforcement, and unsafe-path quarantine.
  - EML/MBOX with header/body handling; supported attachments scanned; unsupported attachments quarantine.
  - DOCX/PPTX/XLSX bounded OOXML extraction; embedded binaries/unknown parts force UNKNOWN coverage and quarantine.
- Added Phase 4 gate tests (`cargo test -p veil-cli --test phase4_gates`).
- Logged container canonicalization decision (D-0017) and updated specs/contracts accordingly.

### Hardening (PHASE_5 completed)
- Added crash+resume, determinism-with-containers, and runbook quickstart tests (`cargo test -p veil-cli --test phase5_gates`).
- Added contract consistency tests (`cargo test -p veil-cli --test contract_consistency`).
- Added offline enforcement checks: static scan (`checks/offline_enforcement.py`) + runtime smoke (`cargo test -p veil-cli --test offline_enforcement`).
- Added extractor fuzz/property smoke tests (`cargo test -p veil-extract --test fuzz_smoke`).
- Added perf harness + baseline capture (`checks/perf_harness.py`, `checks/perf_baseline.json`).
- Hardened key handling with in-memory zeroization (`zeroize` in `crates/veil-cli`).
- Updated runbook (`spec/12`) and checks index (`checks/CHECKS_INDEX.md`) with Phase 5 harness commands and SSOT validation automation (`checks/ssot_validate.py`).

### Security hardening follow-up (D-0018)
- Extended `limits.v1` with `artifact.max_bytes_per_artifact` and enforced bounded artifact reads in CLI and extractors.
- Added processing-time artifact identity revalidation (discovered hash/size vs processed bytes) with fail-closed quarantine on mismatch.
- Hardened output/workdir path safety checks to reject symlink/reparse traversal and unsafe write paths.
- Strengthened offline runtime enforcement test to monitor live process socket activity during execution under denied-proxy posture.
- Widened static offline scan scope to all Rust sources under `crates/**/*.rs` (including `build.rs`).
- Pinned GitHub Actions workflow references to immutable SHAs and set explicit least-privilege workflow permissions.
- Updated SSOT contracts/gates/specs (`spec/02`, `spec/04`, `spec/11`) and decision log (`DECISIONS.md` D-0018).

### Security audit session
- Recorded security audit session evidence updates (no product behavior changes).
- Logged codebase security audit findings for crates/checks (report-only; no product behavior changes).

### Implementation architecture audit (robustness/usability review)
- Recorded audit session updates and integrity check evidence (no product behavior changes).

### Remediation hardening pass (D-0020)
- Implemented structured JSON stderr logging (`level`, `event`, `run_id`, `policy_id`) for run/verify error and lifecycle events.
- Hardened resume metadata binding by storing/validating proof and tokenization meta keys in ledger and failing closed on invalid existing proof-token evidence.
- Tightened filesystem safety: input enumeration rejects symlink/reparse entries; verify rejects unsafe sanitized path types; evidence/atomic writers validate unsafe path states before persist.
- Enforced fail-closed behavior when quarantine raw-copy persistence fails under `--quarantine-copy=true`.
- Hardened ZIP/OOXML/TAR aggregate expanded-byte checks to use observed bytes read.
- Expanded tests for log schema, TAR limits/symlink safety, verify symlink output hardening, limits-json nested/zero validation, and resume invalid evidence behavior.
- Expanded CI gates with offline static/runtime enforcement, SSOT validation, and manifest verification.

### Runtime hardening pass (D-0021)
- Extended `limits.v1` with `disk.max_workdir_bytes` (default 1 GiB) and enforced fail-closed workdir disk bounds during `veil run`.
- Hardened `veil verify` to reject unsafe evidence/manifest paths and fail closed when `sanitized/` contains untracked files not represented as VERIFIED in `artifacts.ndjson`.
- Tightened resume safety: refuse resume when a completed `pack_manifest.json` already exists.
- Redacted usage parsing errors to avoid echoing unknown/unexpected argument values to stderr logs.
- Hardened atomic persistence with file+directory fsync and added a safe fallback path for cross-filesystem staging rename failures.
- Expanded tests for workdir bound enforcement, verify completeness/path safety, resume-finalized refusal, usage redaction, and contract assertions for tokenization + `ledger_schema_version`.

### Maintainability and strict container-parsing hardening pass (D-0022)
- Split `veil-cli` orchestration into dedicated command modules:
  - `crates/veil-cli/src/run_command.rs` (`veil run`)
  - `crates/veil-cli/src/verify_command.rs` (`veil verify`)
  - `crates/veil-cli/src/main.rs` retained as routing/shared utility layer.
- Removed duplicated detect/transform helper logic by exporting shared helpers from `crates/veil-detect` and consuming them from `crates/veil-transform`.
- Removed container extractor NDJSON content-sniff fallback in `crates/veil-extract`; container extensions now require strict container parse and quarantine mislabeled payloads with `PARSE_ERROR`.
- Preserved residual verification and `veil verify` behavior for container-origin sanitized outputs by re-parsing those outputs as NDJSON canonical artifacts during verification paths.
- Hardened perf gate stability by changing `checks/perf_harness.py` to sampled-median comparison (`--samples`, default `3`) with legacy baseline compatibility.
- Added Phase 4 regression test:
  - `zip_extension_with_ndjson_payload_quarantines_parse_error` in `crates/veil-cli/tests/phase4_gates.rs`.
