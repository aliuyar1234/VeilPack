# spec/07_RELIABILITY_AND_OPERATIONS.md

## Reliability Model

### Resumability (crash-safe)
- Ledger is authoritative for resumability:
evidence: spec/05_DATASTORE_AND_MIGRATIONS.md :: Ledger Datastore
- Each artifact stage transition MUST be recorded atomically:
  - DISCOVERED → EXTRACTED → TRANSFORMED → VERIFIED/QUARANTINED
- Resume behavior:
  - on restart with same output pack root, Veil reads ledger and continues unfinished artifacts
  - resume MUST fail if policy_id mismatches (D-0001)

Gate:
evidence: spec/11_QUALITY_GATES.md :: G-REL-LEDGER-RESUME

### Atomic output commits
- Rewriters MUST write to staging, fsync, and atomically rename into final sanitized output path.
- On crash, partially written files MUST NOT appear in `sanitized/`.

Gate:
evidence: spec/11_QUALITY_GATES.md :: G-REL-ATOMIC-COMMIT

### Deterministic throughput and bounded resources
- Operators must be able to bound:
  - concurrency (workers)
  - temp/workdir disk usage
  - archive expansion and recursion depth
  - maximum per-artifact size
- `limits.v1` baseline knobs include `artifact.max_bytes_per_artifact` and `disk.max_workdir_bytes`.
- On bound violations, quarantine the artifact (or abort only if continuing would be unsafe).

Gate:
evidence: spec/11_QUALITY_GATES.md :: G-REL-ARCHIVE-LIMITS

### Error handling and idempotency
- `artifact_id` is content-based; reprocessing the same bytes must be idempotent.
- Non-fatal per-artifact errors MUST quarantine the artifact rather than abort the entire run.
- Fatal run-level errors (policy invalid, output layout invalid) MUST fail before processing.

---

## Operations (offline environments)

### Deployment envelopes
- Air-gapped batch servers (primary)
- Desktop/operator workstation mode (small corpora)
- CI pipeline steps for dataset release gates (offline runner)

### Safe defaults
- Deny-by-default for tokenization and quarantine raw copying.
- Refuse to start if output directory is non-empty or points to an unsafe location.
- Do not overwrite inputs.

### Upgrade/rollback principles
- Tool version MUST be recorded in pack_manifest.json.
- Verification (`veil verify`) MUST work across tool patch versions; if not, it must fail with a non-sensitive error.
- If a new tool version changes pack schema, it MUST bump `pack_schema_version` and document deprecations.

Compatibility gate:
evidence: spec/11_QUALITY_GATES.md :: G-COMP-PACK-COMPAT
