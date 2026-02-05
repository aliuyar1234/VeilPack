# spec/05_DATASTORE_AND_MIGRATIONS.md

## Ledger Datastore
Veil uses a local resumability ledger to:
- support crash-safe resume
- provide a non-sensitive processing trace for auditability
- enforce policy_id immutability across resume

Ledger location (v1):
- `<pack_root>/evidence/ledger.sqlite3`

Ledger invariants:
- MUST NOT store plaintext sensitive values.
- MUST NOT store plaintext paths; store `source_locator_hash` instead.
- MUST record `policy_id` and refuse resume on mismatch.
evidence: DECISIONS.md :: D-0001

## Schema v1 (SQLite)
### Table: meta
| Column | Type | Notes |
|---|---|---|
| key | TEXT PRIMARY KEY | includes schema_version, tool_version, policy_id, run_id |
| value | TEXT NOT NULL | values are non-sensitive identifiers |

Required meta keys:
- `schema_version` = "ledger.v1"
- `tool_version`
- `policy_id`
- `run_id`
- `input_corpus_id`

### Table: artifacts
| Column | Type | Invariants |
|---|---|---|
| artifact_id | TEXT PRIMARY KEY | BLAKE3 hex |
| source_locator_hash | TEXT NOT NULL | BLAKE3 hex |
| size_bytes | INTEGER NOT NULL | >= 0 |
| artifact_type | TEXT NOT NULL | enum-like string |
| state | TEXT NOT NULL | DISCOVERED/EXTRACTED/TRANSFORMED/VERIFIED/QUARANTINED |
| quarantine_reason_code | TEXT NULL | stable reason code only |
| extractor_id | TEXT NULL | non-sensitive identifier |
| coverage_hash | TEXT NULL | hash of CoverageMap |
| output_id | TEXT NULL | BLAKE3 of sanitized bytes; only when VERIFIED |

### Table: findings_summary
Stores counts only (no values).
| Column | Type | Notes |
|---|---|---|
| artifact_id | TEXT | FK artifacts |
| class_id | TEXT | policy class_id |
| severity | TEXT | HIGH/MEDIUM/LOW |
| action | TEXT | REDACT/MASK/DROP/TOKENIZE |
| count | INTEGER | >= 0 |

Indexes:
- artifacts(state)
- findings_summary(class_id)

## Migrations and compatibility
- Veil MUST refuse to operate with an unknown `schema_version`.
- Automatic schema migrations are not permitted in v1 (fail-closed baseline).
- Operator remediation:
  - start a new output directory for a fresh run, OR
  - upgrade Veil to a version that supports the schema_version (if provided)

Verification gate:
evidence: spec/11_QUALITY_GATES.md :: G-REL-LEDGER-RESUME
