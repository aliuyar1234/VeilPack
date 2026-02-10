# VeilPack

[![CI](https://github.com/aliuyar1234/VeilPack/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/aliuyar1234/VeilPack/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-stable-000000?logo=rust)
![Mode](https://img.shields.io/badge/mode-offline%20first-2ea44f)
![Safety](https://img.shields.io/badge/safety-fail--closed-critical)
![Determinism](https://img.shields.io/badge/output-deterministic-blue)

VeilPack is an offline, fail-closed privacy gate for enterprise data pipelines. It ingests mixed corpora, detects sensitive values using policy-defined detectors, rewrites outputs, and emits a verifiable pack that is safe to move downstream.

## Table of Contents
- [Why VeilPack](#why-veilpack)
- [Who It Is For](#who-it-is-for)
- [What You Get](#what-you-get)
- [High-Level Architecture](#high-level-architecture)
- [How Processing Works](#how-processing-works)
- [Supported Input Formats](#supported-input-formats)
- [CLI Overview](#cli-overview)
- [Operational Hardening](#operational-hardening)
- [Quickstart](#quickstart)
- [Worked Example (CSV)](#worked-example-csv)
- [Output Layout](#output-layout)
- [Exit Codes](#exit-codes)
- [Contracts and Compatibility](#contracts-and-compatibility)
- [Development and Quality Gates](#development-and-quality-gates)
- [Repository Structure](#repository-structure)
- [Project Notes](#project-notes)

## Why VeilPack
- Reduces data-sharing risk by defaulting to strict, deterministic sanitization.
- Enforces a fail-closed model: each artifact ends `VERIFIED` or `QUARANTINED`.
- Keeps runtime offline-first for air-gapped and regulated environments.
- Produces audit-friendly evidence without plaintext sensitive values.

## Who It Is For
- Security and privacy engineering teams that need enforceable data sanitization.
- Data platform teams that need repeatable, policy-driven preprocessing.
- ML and analytics teams that need safer corpora before training or sharing.
- Compliance-focused orgs that need deterministic outputs and verifiable controls.

## What You Get
- A Rust workspace with clear layer boundaries (`domain -> policy -> extract -> detect -> transform -> verify -> evidence -> cli`).
- A production-style CLI:
  - `veil run`
  - `veil verify`
  - `veil policy lint`
- Built-in checks for offline enforcement, boundary fitness, contract consistency, compatibility matrix validation, and performance regression gating.
- A deterministic Veil Pack output contract (`pack.v1` + `ledger` schema binding).

## High-Level Architecture
```mermaid
flowchart LR
  A[Input Corpus] --> I[Ingest and Fingerprint]
  I --> X[Extractor and Coverage]
  X --> D[Detector Engine]
  D --> T[Transform and Rewrite]
  T --> V[Residual Verification]
  V --> S[Sanitized Output]
  V --> Q[Quarantine Index]
  I --> L[(Ledger)]
  X --> L
  T --> L
  V --> L
  P[Policy Bundle] --> D
  V --> E[Evidence Builder]
  E --> M[Pack and Run Manifests]
```

### Layer-to-crate mapping
| Layer | Crate | Responsibility |
|---|---|---|
| Domain | `crates/veil-domain` | IDs, invariants, shared config/hashing primitives |
| Policy | `crates/veil-policy` | Policy schema parsing, validation, policy identity |
| Extract | `crates/veil-extract` | Format parsing, canonical representation, coverage |
| Detect | `crates/veil-detect` | Matching engine (regex/checksum/selectors) |
| Transform | `crates/veil-transform` | Deterministic redact/mask/drop rewrites |
| Verify | `crates/veil-verify` | Residual safety verification decisions |
| Evidence | `crates/veil-evidence` | Ledger and non-sensitive evidence persistence |
| CLI | `crates/veil-cli` | Orchestration, pack emission, command surface |

## How Processing Works
1. Discover artifacts and fingerprint content deterministically.
2. Extract to canonical representation with explicit coverage metadata.
3. Detect sensitive findings using compiled policy detectors.
4. Apply transforms (for example `REDACT`, `MASK`, `DROP`).
5. Re-scan transformed output (residual verification).
6. Emit `VERIFIED` outputs only when residual checks pass; otherwise quarantine.
7. Persist evidence and manifests with no plaintext sensitive values.

### Terminal state model
- `VERIFIED`: artifact passed strict coverage and residual verification.
- `QUARANTINED`: artifact is withheld with a non-sensitive reason code.

## Supported Input Formats
| Group | Types |
|---|---|
| Text and structured | `.txt`, `.csv`, `.tsv`, `.json`, `.ndjson` |
| Container and compound | `.zip`, `.tar`, `.eml`, `.mbox`, `.docx`, `.pptx`, `.xlsx` |

Notes:
- Container parsing is strict by extension contract.
- Mislabeled container payloads are quarantined (`PARSE_ERROR`).
- Container-origin sanitized outputs are canonical NDJSON.

## CLI Overview
```text
veil run --input <PATH> --output <PATH> --policy <PATH> [FLAGS]
veil verify --pack <PATH> --policy <PATH>
veil policy lint --policy <PATH>
```

Key `run` flags:
- `--workdir <PATH>`
- `--max-workers <N>` (accepted; v1 baseline executes deterministic single-worker)
- `--strictness strict`
- `--enable-tokenization true|false`
- `--secret-key-file <PATH>`
- `--quarantine-copy true|false`
- `--isolate-risky-extractors true|false`
- `--limits-json <PATH>`

## Operational Hardening
- Optional extractor process isolation for risky container/compound formats:
  - `--isolate-risky-extractors true`
- Per-artifact runtime bounding through limits JSON:
  - `artifact.max_processing_ms`
- Fail-closed crash/resume invariants for evidence + manifests:
  - explicit regression tests for post-evidence crash points
- Versioned compatibility controls:
  - `docs/compatibility-matrix.md`
  - enforced by `checks/compatibility_matrix_check.py`

## Quickstart
### Prerequisites
- Rust stable toolchain
- Python 3

### Build and test
```bash
cargo build --workspace
cargo test --workspace
```

### Create a minimal policy bundle
Create `policy/policy.json`:

```json
{
  "schema_version": "policy.v1",
  "classes": [
    {
      "class_id": "PII.Test",
      "severity": "HIGH",
      "detectors": [
        {
          "kind": "regex",
          "pattern": "SECRET"
        }
      ],
      "action": {
        "kind": "REDACT"
      }
    }
  ],
  "defaults": {},
  "scopes": []
}
```

### Run sanitization
```bash
cargo run -p veil-cli -- run \
  --input ./input \
  --output ./out \
  --policy ./policy
```

### Verify an emitted pack
```bash
cargo run -p veil-cli -- verify \
  --pack ./out \
  --policy ./policy
```

### Lint a policy bundle
```bash
cargo run -p veil-cli -- policy lint --policy ./policy
```

## Worked Example (CSV)
Use the committed end-to-end demo under `examples/csv-redaction`:

- walkthrough: `examples/csv-redaction/README.md`
- input corpus: `examples/csv-redaction/input/customers.csv`
- policy: `examples/csv-redaction/policy/policy.json`
- expected sanitized content: `examples/csv-redaction/expected/customers.sanitized.csv`

Run it:

```bash
cargo run -p veil-cli -- run \
  --input examples/csv-redaction/input \
  --output examples/csv-redaction/out \
  --policy examples/csv-redaction/policy
```

Then inspect:

```bash
cat examples/csv-redaction/out/sanitized/*.csv
```

This demo is also enforced by integration test:
`cargo test -p veil-cli --test examples_csv_demo`

## Output Layout
`veil run` writes:

```text
<pack_root>/
  sanitized/
  quarantine/
    index.ndjson
    raw/                     # present only when --quarantine-copy=true
  evidence/
    run_manifest.json
    artifacts.ndjson
    ledger.sqlite3
  pack_manifest.json
```

## Exit Codes
| Code | Meaning |
|---|---|
| `0` | Run completed and all artifacts are `VERIFIED` |
| `2` | Run completed with one or more `QUARANTINED` artifacts |
| `1` | Fatal error |
| `3` | Invalid arguments or invalid policy bundle |

## Contracts and Compatibility
- Output contract tests: `cargo test -p veil-cli --test contract_consistency --test contract_schema`
- Compatibility matrix (pack/ledger versions): `docs/compatibility-matrix.md`
- Error code catalog: `docs/error-codes.md`

## Development and Quality Gates
```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
python checks/offline_enforcement.py
python checks/boundary_fitness.py
python checks/compatibility_matrix_check.py
python checks/ssot_validate.py all
python checks/perf_harness.py --build --tolerance 0.20 --samples 3
```

## Repository Structure
```text
crates/
  veil-cli/
  veil-domain/
  veil-policy/
  veil-extract/
  veil-detect/
  veil-transform/
  veil-verify/
  veil-evidence/
checks/
docs/
.github/workflows/ci.yml
Cargo.toml
```

## Project Notes
- This repository is licensed under Apache License 2.0 (`LICENSE`).
- Internal SSOT/session documentation is intentionally kept local and out of the implementation repository history.
