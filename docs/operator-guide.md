# Operator Guide

This guide covers the day-to-day operational behavior that sits behind the command reference.

## Running A Corpus

Baseline command:

```bash
veil run --input <PATH> --output <PATH> --policy <PATH>
```

Key operational points:
- `--output` must be a new or empty directory unless you are resuming an in-progress pack.
- `--policy` must point to a bundle directory containing `policy.json`.
- Exit code `0` means every artifact reached `VERIFIED`.
- Exit code `2` means the run completed, but one or more artifacts were quarantined.
- Exit code `1` means a fatal runtime or verification failure stopped the operation.

## Quarantine Behavior

Artifacts are quarantined instead of passing through when VeilPack cannot safely prove clean output. Common causes include:
- unsupported formats
- parse failures
- unsafe archive paths
- archive or processing limits
- unknown extraction coverage
- residual verification findings

Operational artifacts:
- `quarantine/index.ndjson` records one non-sensitive line per quarantined artifact.
- `quarantine/raw/` is only created when `--quarantine-copy true` is enabled.
- `evidence/artifacts.ndjson` and `evidence/ledger.sqlite3` still record quarantined outcomes for auditability.

## What `veil verify` Guarantees

`veil verify` is a pack-integrity verifier, not only a residual scanner.

It checks:
- `pack_manifest.json` schema compatibility
- policy identity match
- ledger and exported evidence consistency
- that every expected verified output still exists
- that verified output bytes still match the recorded `output_id`
- that no unexpected files were added under `sanitized/`
- that residual rescanning still finds no policy matches

If any of those checks fail, verification fails closed.

## Resume Workflow

If a run stops after creating the in-progress marker and ledger, rerun the same `veil run` command against the same output directory.

Resume rules:
- the output directory must still represent an in-progress pack
- the policy must match the original run
- completed pack manifests must not already exist
- quarantine-copy mode must match the original run
- malformed existing evidence causes resume to fail closed

The resume path is exercised by the regression coverage in `crates/veil-cli/tests/phase5_gates.rs`.

## Limits JSON

Use `--limits-json <PATH>` to tighten runtime safety limits without changing code.

Example:

```json
{
  "schema_version": "limits.v1",
  "archive": {
    "max_expansion_ratio": 25
  },
  "artifact": {
    "max_bytes_per_artifact": 1048576,
    "max_processing_ms": 5000
  },
  "disk": {
    "max_workdir_bytes": 1073741824
  }
}
```

Operational behavior:
- invalid schema versions or unknown fields are usage errors
- zero values for bounded limits are rejected
- tripped limits quarantine the affected artifact with `LIMIT_EXCEEDED`

Reference coverage lives in `crates/veil-cli/tests/limits_json.rs`.

## Worker Settings

`--max-workers <N>` is currently advisory only in the v1 baseline.

Current behavior:
- values greater than `1` are accepted
- the run still executes deterministically in single-worker mode
- VeilPack emits a `CONFIG_IGNORED` warning with event `max_workers_single_threaded_baseline`

`--isolate-risky-extractors true` is separate from `--max-workers` and controls whether risky extraction happens in a worker process.

## More Demos

Runnable examples live under `examples/`:
- `examples/csv-redaction`
- `examples/archive-redaction`
- `examples/email-redaction`
