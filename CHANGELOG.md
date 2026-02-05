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
- Hardened key-handling evidence: run manifest records `proof_key_commitment` (BLAKE3 of key) and tokenization scope when enabled, without persisting the secret key.

### Evidence and audit (PHASE_3 completed)
- Added pack compatibility tests and enforcement (`veil verify` refuses unsupported pack/ledger schema versions).
- Implemented proof token emission (digest-only correlation tokens in `artifacts.ndjson`) with key commitment metadata in `run_manifest.json` (D-0016).
- Added quarantine raw-copy opt-in tests (`quarantine/raw/` created only when explicitly enabled).
