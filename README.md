# VeilPack

[![CI](https://github.com/aliuyar1234/VeilPack/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/aliuyar1234/VeilPack/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-stable-000000?logo=rust)
![Mode](https://img.shields.io/badge/mode-offline%20first-2ea44f)
![Safety](https://img.shields.io/badge/safety-fail--closed-critical)
![Determinism](https://img.shields.io/badge/output-deterministic-blue)

VeilPack is an offline, fail-closed CLI for sanitizing corpora before they move into analytics, ML, or external sharing. It detects policy-defined sensitive values, rewrites supported artifacts, quarantines anything that cannot be handled safely, and emits a Veil Pack that can be verified later with the same policy bundle.

## Why it exists

- Keep sensitive source data out of downstream systems by default.
- Fail closed when parsing, extraction, verification, or integrity checks are not trustworthy.
- Produce deterministic outputs and non-sensitive evidence that are stable enough to test and re-verify.
- Stay usable in offline or tightly controlled environments.

## What you get today

- `veil run` to process a corpus into a Veil Pack.
- `veil verify` to re-check pack integrity, sanitized output identity, and residual policy cleanliness.
- `veil policy lint` to validate a policy bundle and compute its `policy_id`.
- Release artifacts for Linux, macOS, and Windows under [Releases](https://github.com/aliuyar1234/VeilPack/releases/latest).
- A workspace split by responsibility: `domain -> policy -> extract -> detect -> transform -> verify -> evidence -> cli`.

## Safety model

- Offline-first: the repo has both static and runtime offline enforcement checks.
- Fail-closed: unsupported formats, parse failures, unsafe archive paths, unknown coverage, residual matches, and evidence tampering do not pass as clean output.
- Deterministic: structured formats are canonicalized, sanitized filenames are hashed, and pack metadata is versioned.
- Re-verifiable: `veil verify` checks both content cleanliness and recorded output identity for previously verified artifacts.

## Install or build

### Option 1: download a release

Download the latest archive for your platform from [GitHub Releases](https://github.com/aliuyar1234/VeilPack/releases/latest) and verify the matching `.sha256` file.

### Option 2: build from source

Prerequisites:

- Rust stable
- Python 3

Build the CLI:

```bash
cargo build -p veil-cli --release
```

The binary will be:

- `target/release/veil` on Linux and macOS
- `target\release\veil.exe` on Windows

## Fastest demo

The repo includes a working CSV demo in [`examples/csv-redaction`](examples/csv-redaction).

Run it from the repository root:

```bash
cargo run -p veil-cli -- run \
  --input examples/csv-redaction/input \
  --output out \
  --policy examples/csv-redaction/policy
```

Then verify the emitted pack:

```bash
cargo run -p veil-cli -- verify \
  --pack out \
  --policy examples/csv-redaction/policy
```

Inspect the sanitized CSV:

```bash
cat out/sanitized/*.csv
```

PowerShell equivalent:

```powershell
Get-Content -Raw out/sanitized/*.csv
```

Expected content:

```csv
customer_id,name,email,notes
1,Alice,{{PII.Email}},priority_customer
2,Bob,{{PII.Email}},call_after_5pm
```

The same flow is covered by the integration test `cargo test -p veil-cli --test examples_csv_demo`.

## Policy bundles

Policy bundles are directories. The example bundle lives at [`examples/csv-redaction/policy`](examples/csv-redaction/policy) and contains a `policy.json` like this:

```json
{
  "schema_version": "policy.v1",
  "classes": [
    {
      "class_id": "PII.Email",
      "severity": "HIGH",
      "detectors": [
        {
          "kind": "field_selector",
          "selector": "csv_header",
          "fields": ["email"]
        },
        {
          "kind": "regex",
          "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
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

Validate a bundle and print its `policy_id`:

```bash
cargo run -p veil-cli -- policy lint --policy examples/csv-redaction/policy
```

## Supported input formats

| Group | Types |
|---|---|
| Text and structured | `.txt`, `.csv`, `.tsv`, `.json`, `.ndjson` |
| Container and compound | `.zip`, `.tar`, `.eml`, `.mbox`, `.docx`, `.pptx`, `.xlsx` |

Notes:

- Container parsing is strict by extension contract.
- Unsafe paths, malformed content, encrypted payloads, expansion-limit breaches, and unknown coverage fail closed.
- Sanitized output from container-style inputs is emitted as canonical NDJSON.

## Command reference

```text
veil run --input <PATH> --output <PATH> --policy <PATH> [FLAGS]
veil verify --pack <PATH> --policy <PATH>
veil policy lint --policy <PATH>
```

Important `run` flags:

- `--policy <PATH>` always points to a policy bundle directory, not directly to a `policy.json` file.
- `--output <PATH>` must be a new or empty directory, or an existing in-progress pack when resuming.
- `--workdir <PATH>` for an alternate work directory. The default is `<output>/.veil_work/`.
- `--limits-json <PATH>` to override safety limits.
- `--isolate-risky-extractors true|false` to run risky extractors in a worker process.
- `--quarantine-copy true|false` to retain raw quarantined bytes under `quarantine/raw/`.
- `--enable-tokenization true|false` with `--secret-key-file <PATH>` for opt-in tokenization.
- `--strictness strict` because strict is the only supported baseline in `policy.v1`.
- `--max-workers <N>` selects the number of concurrent extraction workers (default: `1`). Output is byte-identical regardless of `N` — artifacts commit in deterministic sort-key order via a bounded crossbeam-channel pool.

For operator-level diagnostics, set `RUST_LOG=debug` (or `RUST_LOG=trace`). All log lines are emitted as structured JSON on stderr with stable `event=` codes for downstream observability.

## What a Veil Pack contains

A typical run writes:

```text
<pack_root>/
  pack_manifest.json
  sanitized/
  quarantine/
    index.ndjson
    raw/                     # only when --quarantine-copy=true
  evidence/
    run_manifest.json
    artifacts.ndjson
    ledger.sqlite3
  .veil_work/                # default internal workdir unless overridden
```

Key details:

- `pack_manifest.json` records `pack_schema_version`, `ledger_schema_version`, `tool_version`, `run_id`, `policy_id`, and `input_corpus_id`.
- `sanitized/` filenames are content-addressed, not source filenames.
- `evidence/artifacts.ndjson` records per-artifact state and `output_id` for verified outputs.
- `quarantine/index.ndjson` stays non-sensitive and explains why an artifact did not pass.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Run completed and all artifacts are `VERIFIED` |
| `1` | Fatal error or failed verification |
| `2` | Run completed with one or more `QUARANTINED` artifacts |
| `3` | Invalid CLI usage or invalid policy input |

## Quality gates

Main CI runs the same gates you can run locally:

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
python checks/offline_enforcement.py
cargo test -p veil-cli --test offline_enforcement
python checks/boundary_fitness.py
python checks/compatibility_matrix_check.py
python checks/package_release_smoke.py
python checks/perf_harness.py --build --tolerance 0.20 --samples 3
```

Optional SSOT helper tooling still exists in `checks/ssot_validate.py` and `checks/generate_manifest.py`, but the current VeilPack checkout does not ship the SSOT/spec document pack those tools expect, so they are not part of the default CI contract.

## Repository map

- `crates/veil-cli`: CLI entrypoints, run orchestration, pack verification.
- `crates/veil-extract`: format extraction, archive handling, coverage decisions.
- `crates/veil-detect`: detector execution and selector handling.
- `crates/veil-transform`: deterministic redact, mask, drop, and related rewrites.
- `crates/veil-verify`: residual verification decisions.
- `crates/veil-evidence`: ledger persistence and evidence records.
- `crates/veil-domain`: shared IDs, hashing, invariants, and common types.
- `crates/veil-policy`: policy parsing, validation, and policy identity.
- `checks/`: repo-level enforcement scripts and perf harness.
- `docs/`: compatibility and operational contract docs.
- `examples/`: runnable demos.

## Docs and references

- [Examples](examples/README.md)
- [Operator guide](docs/operator-guide.md)
- [Compatibility matrix](docs/compatibility-matrix.md)
- [Error codes](docs/error-codes.md)
- [Checks index](checks/CHECKS_INDEX.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Apache-2.0 license](LICENSE)
