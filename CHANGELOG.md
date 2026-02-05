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
