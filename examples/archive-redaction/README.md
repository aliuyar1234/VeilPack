# Archive Redaction Demo

This demo shows container-style sanitization for a ZIP input.

## What it demonstrates
- Archive inputs are scanned entry-by-entry under fail-closed limits.
- Sanitized output for container inputs is emitted as canonical NDJSON.
- Sensitive text inside an archive entry is rewritten before verification.

## Input
- `input/sample.zip`
- `source/notes.txt`

`input/sample.zip` was built from `source/notes.txt`, whose raw content is:

```text
SECRET inside zip
```

## Policy
`policy/policy.json`

The policy:
- detects the literal token `SECRET`,
- applies `REDACT`,
- emits `{{PII.Secret}}` markers.

## Run the demo

From repository root:

```bash
cargo run -p veil-cli -- run \
  --input examples/archive-redaction/input \
  --output examples/archive-redaction/out \
  --policy examples/archive-redaction/policy
```

Expected exit code: `0` (all artifacts verified).

Inspect sanitized output:

```bash
ls examples/archive-redaction/out/sanitized
cat examples/archive-redaction/out/sanitized/*.ndjson
```

PowerShell equivalent:

```powershell
Get-ChildItem examples/archive-redaction/out/sanitized -File
Get-Content -Raw examples/archive-redaction/out/sanitized/*.ndjson
```

## Expected sanitized content
`expected/sample.sanitized.ndjson`

```json
{"archive_depth":1,"entry_path_hash":"a859c1198d69e635a868b337216913df319113c1315cdd69ff8eb460ee5f62de","text":"{{PII.Secret}} inside zip\n"}
```

## Verification proof in tests
The integration test `crates/veil-cli/tests/examples_additional_demos.rs` executes this demo and asserts:
- exit code is `0`,
- exactly one sanitized NDJSON file is emitted,
- sanitized content matches `expected/sample.sanitized.ndjson`,
- quarantine index is empty.
