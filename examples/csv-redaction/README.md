# CSV Redaction Demo

This demo shows a complete before/after CSV processing run with VeilPack.

## What it demonstrates
- Policy-driven detection and transformation on CSV data.
- Field-scoped matching (`csv_header` selector on the `email` column).
- Deterministic sanitized output (hashed filename, stable content).
- Fail-closed processing model (`run` exits non-zero when quarantines exist).

## Input
`input/customers.csv`

```csv
customer_id,name,email,notes
1,Alice,alice@example.com,priority_customer
2,Bob,bob.smith@acme.io,call_after_5pm
```

## Policy
`policy/policy.json`

The policy:
- selects only the `email` CSV header,
- detects email patterns via regex,
- applies `REDACT` with class marker `{{PII.Email}}`.

## Run the demo

From repository root:

```bash
cargo run -p veil-cli -- run \
  --input examples/csv-redaction/input \
  --output examples/csv-redaction/out \
  --policy examples/csv-redaction/policy
```

Expected exit code: `0` (all artifacts verified).

Inspect sanitized output:

```bash
ls examples/csv-redaction/out/sanitized
cat examples/csv-redaction/out/sanitized/*.csv
```

PowerShell equivalent:

```powershell
Get-ChildItem examples/csv-redaction/out/sanitized -File
Get-Content -Raw examples/csv-redaction/out/sanitized/*.csv
```

## Expected sanitized content
`expected/customers.sanitized.csv`

```csv
customer_id,name,email,notes
1,Alice,{{PII.Email}},priority_customer
2,Bob,{{PII.Email}},call_after_5pm
```

## Verification proof in tests
The integration test `crates/veil-cli/tests/examples_csv_demo.rs` executes this exact demo and asserts:
- exit code is `0`,
- exactly one sanitized CSV is emitted,
- sanitized content matches `expected/customers.sanitized.csv`,
- quarantine index is empty.
