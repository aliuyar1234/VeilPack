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
