# spec/04_INTERFACES_AND_CONTRACTS.md

## CLI Contract
Veil is a CLI-first batch tool. The CLI is a **public contract** and MUST be versioned and stable.

### Commands (v1)
1) `veil run`
- Purpose: process an input corpus into a Veil Pack.
- Required flags:
  - `--input <PATH>`: input corpus root (read-only)
  - `--output <PATH>`: output Veil Pack root (new run: must not exist or must be empty; resume: may be an in-progress Veil Pack for safe resume; path MUST NOT traverse symlink/reparse components)
  - `--policy <PATH>`: policy bundle directory
- Optional flags (selected):
  - `--workdir <PATH>`: work directory (default: `<output>/.veil_work/`; path MUST NOT traverse symlink/reparse components)
  - `--max-workers <N>`: worker bound (accepted in v1; baseline execution is deterministic single-worker, and values >1 are advisory for forward compatibility)
  - `--strictness strict`: strict is the only supported baseline in v1 (fail-closed)
  - `--enable-tokenization false|true` (default: false; see D-0004)
  - `--secret-key-file <PATH>` (required if tokenization is true)
  - `--quarantine-copy false|true` (default: false; see D-0005)
  - `--limits-json <PATH>`: optional JSON file overriding resource and archive limits

#### `--limits-json` schema v1
If `--limits-json` is provided, the file MUST be UTF-8 JSON and MUST conform to D-0012.

Minimal shape (conceptual):
```json
{
  "schema_version": "limits.v1",
  "archive": {
    "max_nested_archive_depth": 3,
    "max_entries_per_archive": 100000,
    "max_expansion_ratio": 25,
    "max_expanded_bytes_per_archive": 53687091200
  },
  "artifact": {
    "max_bytes_per_artifact": 268435456
  },
  "disk": {
    "max_workdir_bytes": 1073741824
  }
}
```

Rules:
- `schema_version` MUST equal `limits.v1`
- `artifact.max_bytes_per_artifact` MUST be >= 1 when present
- `disk.max_workdir_bytes` MUST be >= 1 when present
- Unknown fields MUST be rejected (fail closed)

Decision:
evidence: DECISIONS.md :: ## D-0012
evidence: DECISIONS.md :: ## D-0021 - Runtime hardening pass: verify completeness checks, usage redaction, and workdir disk bounds

2) `veil verify`
- Purpose: verify a Veil Pack output using a policy bundle.
- Required flags:
  - `--pack <PATH>`: Veil Pack root (path MUST NOT traverse symlink/reparse components)
  - `--policy <PATH>`: policy bundle directory
- Behavior:
  - re-scan VERIFIED outputs and fail if residual HIGH-severity findings exist
  - for container-origin artifact types (`ZIP`/`TAR`/`EML`/`MBOX`/`DOCX`/`PPTX`/`XLSX`), re-parse sanitized bytes using NDJSON canonical verification mapping while preserving original artifact type metadata in evidence
  - refuse unsafe sanitized output paths (symlink/reparse/non-file) during verification and count them as verification failures (fail-closed)
  - refuse unsafe `pack_manifest.json` / `evidence/artifacts.ndjson` paths (symlink/reparse/non-file) before reading
  - fail closed if `sanitized/` contains files that are not represented as VERIFIED in `evidence/artifacts.ndjson`

3) `veil policy lint`
- Purpose: validate policy bundle schema and compute `policy_id`.
- Required flags:
  - `--policy <PATH>`: policy bundle directory
- Output:
  - prints policy_id to stdout (no sensitive values)

### Exit codes (v1)
- 0: run completed and all artifacts VERIFIED
- 2: run completed with at least one QUARANTINED artifact (Veil Pack produced; check quarantine index)
- 1: fatal error (no Veil Pack guarantee; must not emit partial pack as “complete”)
- 3: invalid arguments or policy bundle invalid (no processing performed)

---

## Veil Pack Layout v1
The output directory of `veil run` is the Veil Pack root.

```
<pack_root>/
  sanitized/                      # VERIFIED outputs only
  quarantine/
    index.ndjson                  # non-sensitive quarantine index (always present)
    raw/                          # present only when quarantine-copy enabled
  evidence/
    run_manifest.json             # run + policy binding (no timestamps)
    artifacts.ndjson              # per-artifact evidence records (no plaintext)
    ledger.sqlite3                # resumability ledger (no plaintext)
  pack_manifest.json              # top-level pack identity and schema versions
```

### Pack invariants
- `pack_manifest.json` MUST include:
  - `pack_schema_version`
  - `tool_version`
  - `run_id`
  - `policy_id`
  - `input_corpus_id`
  - whether tokenization enabled and scope (but never the key)
  - whether quarantine raw copying enabled
  - `ledger_schema_version`
- `pack_schema_version` MUST equal `"pack.v1"` for layout v1.
- `sanitized/` MUST contain only VERIFIED artifacts.
- `quarantine/index.ndjson` MUST contain all QUARANTINED artifacts.
- Evidence MUST never contain plaintext sensitive values.
evidence: CONSTITUTION.md :: C-003 No plaintext sensitive values in logs/reports/evidence

Evidence proof tokens (non-sensitive correlation aids):
evidence: DECISIONS.md :: ## D-0016 — Proof token emission binding (v1)

### Sanitized output path mapping (v1 baseline)
To avoid plaintext path leakage in the pack, v1 baseline uses only digests for sanitized output names:
- `sanitized/<source_locator_hash>__<artifact_id>.<ext>`
- `<ext>` mapping (v1 baseline):
  - TEXT → `txt`
  - CSV → `csv`
  - TSV → `tsv`
  - JSON → `json`
  - NDJSON → `ndjson`

Decision:
evidence: DECISIONS.md :: ## D-0014

Decision:
evidence: DECISIONS.md :: ## D-0013

---

## Supported input formats (v1 baseline)
Veil classifies artifact types by file extension (lowercased) for v1 baseline.

Supported simple formats:
- TEXT: `.txt` → sanitized output ext `txt`
- CSV: `.csv` → sanitized output ext `csv`
- TSV: `.tsv` → sanitized output ext `tsv`
- JSON: `.json` → sanitized output ext `json`
- NDJSON: `.ndjson` → sanitized output ext `ndjson`

Supported container formats (canonicalized to NDJSON; sanitized output ext `ndjson`):
- ZIP: `.zip`
- TAR: `.tar`
- Email: `.eml`, `.mbox`
- Office Open XML: `.docx`, `.pptx`, `.xlsx`
- Container parsing is extension-contract strict:
  - bytes for these extensions MUST parse as the declared container format.
  - NDJSON/plaintext content-sniff fallback is not allowed for these container types.
  - parse failures quarantine with reason code `PARSE_ERROR`.
- Post-transform residual verification and `veil verify` re-parse container-origin sanitized bytes as NDJSON canonical form.

Email attachment baseline (fail-closed):
- ZIP/TAR attachments are supported (by mimetype or filename).
- `text/*` attachments are supported (decoded and scanned as attachment text).
- Any other attachment type MUST quarantine the entire email artifact as `UNSUPPORTED_FORMAT`.

Decision:
evidence: DECISIONS.md :: ## D-0017 — Container format canonicalization to NDJSON (v1)
evidence: DECISIONS.md :: ## D-0022 - Maintainability and strict container-parsing hardening pass

## Policy Bundle Schema v1
A policy bundle is a directory containing `policy.json` (required). `policy.json` is UTF-8 JSON.

### policy.json required top-level fields
| Field | Type | Description | Invariants |
|---|---|---|---|
| schema_version | string | policy schema version | MUST equal "policy.v1" |
| classes | array | sensitive classes | MUST be non-empty |
| defaults | object | default actions/severity | MUST exist |
| scopes | array | where policy applies | MUST exist (may be empty = apply everywhere) |

Strictness:
- Unknown fields MUST be rejected (fail closed).

### Class entry (conceptual)
| Field | Type | Description | Invariants |
|---|---|---|---|
| class_id | string | stable identifier (e.g., "PII.Email") | MUST be unique |
| severity | string | HIGH/MEDIUM/LOW | HIGH must be verifiable (D-0008) |
| detectors | array | detector definitions | MUST be non-empty |
| action | object | transform action | MUST be explicit |

### Detector definition (v1)
Supported detector kinds (offline, deterministic):
- `regex` (with bounded regex engine; catastrophic patterns rejected by lint)
- `checksum` (e.g., Luhn-like validators where applicable)
- `field_selector` (apply detectors only to selected structured fields)

Concrete shapes (v1 baseline):
- regex:
  - `{"kind":"regex","pattern":"...","case_insensitive":false,"dot_matches_new_line":false}`
- checksum:
  - `{"kind":"checksum","algorithm":"luhn"}`
- field_selector:
  - `{"kind":"field_selector","selector":"json_pointer"|"csv_header","fields":[...]}`

### Action definition (v1)
- `REDACT`: replace with class marker
- `MASK`: retain partials per configured rule
- `DROP`: remove value/field
- `TOKENIZE`: only permitted if tokenization enabled (D-0004)

Concrete shapes (v1 baseline):
- `{"kind":"REDACT"}`
- `{"kind":"MASK","keep_last":N}` where `N >= 1`
- `{"kind":"DROP"}`

V1 baseline support limits:
- `scopes` MUST be empty (`[]`) in v1 baseline.
- `TOKENIZE` is reserved but not supported in v1 baseline; policies using it MUST be rejected.

Decision:
evidence: DECISIONS.md :: ## D-0015

### Policy compatibility
- policy schema changes MUST be versioned.
- `veil policy lint` MUST refuse unknown schema_version values.

---

## Error model (stable)
- Errors MUST be categorized and non-sensitive.
- Quarantine reason codes MUST be stable:
evidence: spec/03_DOMAIN_MODEL.md :: QuarantineReason

---

## Deprecation policy (public contracts)
- CLI flags/subcommands:
  - no breaking removals within the same major version
  - deprecated flags MUST continue to work for at least one minor release cycle and MUST emit a non-sensitive warning
- Veil Pack layout:
  - any breaking layout or schema change requires `pack_schema_version` bump and a compatibility decision
- Policy schema:
  - any breaking schema change requires schema_version bump and migration guidance in runbook

Compatibility gates:
evidence: spec/11_QUALITY_GATES.md :: G-COMP-PACK-COMPAT

---

## Implementation mapping (non-normative)
- CLI (`veil`): `crates/veil-cli`
- Layer crates (C-101): see architecture mapping.
evidence: spec/02_ARCHITECTURE.md :: Workspace crate mapping (normative)
