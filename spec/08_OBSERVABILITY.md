# spec/08_OBSERVABILITY.md

## Observability Signals

### Goals (offline, audit-grade)
- Provide enough diagnostics to operate and debug Veil offline.
- Never leak plaintext sensitive values.
- Support correlation across logs, evidence, and ledger via stable IDs.

### Primary signals
1) Structured logs (JSON lines to stderr by default)
2) Evidence bundle (run_manifest.json + artifacts.ndjson)
3) Quarantine index (index.ndjson)
4) Ledger (ledger.sqlite3)

Canonical evidence format:
evidence: DECISIONS.md :: D-0007

---

## Log Schema v1 (normative)
Log events MUST be structured JSON with at least:
- `level`: INFO/WARN/ERROR
- `event`: stable event name
- `run_id`
- `policy_id`
- optional `artifact_id`
- optional `source_locator_hash`
- optional `reason_code` (quarantine or error category)
- optional `counters` (non-sensitive integers)

Logs MUST NOT include:
- plaintext artifact paths
- plaintext sensitive values
- raw excerpts from inputs

---

## Log Redaction Rules (normative)
- Any string derived from input content MUST NOT be logged.
- Any identifier that may contain sensitive values MUST be replaced with:
  - `artifact_id`, `source_locator_hash`, `class_id`, `reason_code`, or a keyed digest token
- Debug logging MUST obey the same redaction rules (no privileged debug mode that leaks).

Gate:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-NO-PLAINTEXT-LEAKS

---

## Operator-facing summaries
- A run summary MUST be included in `evidence/run_manifest.json` and MAY be printed to stdout as non-sensitive totals:
  - total artifacts discovered
  - counts VERIFIED / QUARANTINED
  - quarantine reason counts
- If any artifacts are quarantined, the CLI MUST exit with code 2 (contract in spec/04).
