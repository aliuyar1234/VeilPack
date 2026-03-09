# Email Redaction Demo

This demo shows sanitization of a simple RFC822-style `.eml` message.

## What it demonstrates
- Mail headers and body text are both scanned.
- Sanitized email output is emitted as canonical NDJSON.
- Verification succeeds only after residual scanning confirms the rewritten content is clean.

## Input
`input/sample.eml`

```eml
Subject: hello SECRET
From: alice@example.com
To: bob@example.com

Body SECRET
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
  --input examples/email-redaction/input \
  --output examples/email-redaction/out \
  --policy examples/email-redaction/policy
```

Expected exit code: `0` (all artifacts verified).

Inspect sanitized output:

```bash
ls examples/email-redaction/out/sanitized
cat examples/email-redaction/out/sanitized/*.ndjson
```

PowerShell equivalent:

```powershell
Get-ChildItem examples/email-redaction/out/sanitized -File
Get-Content -Raw examples/email-redaction/out/sanitized/*.ndjson
```

## Expected sanitized content
`expected/sample.sanitized.ndjson`

```json
{"header_index":0,"key":"Subject","value":"hello {{PII.Secret}}"}
{"header_index":1,"key":"From","value":"alice@example.com"}
{"header_index":2,"key":"To","value":"bob@example.com"}
{"body_index":0,"text":"Body {{PII.Secret}}\n"}
```

## Verification proof in tests
The integration test `crates/veil-cli/tests/examples_additional_demos.rs` executes this demo and asserts:
- exit code is `0`,
- exactly one sanitized NDJSON file is emitted,
- sanitized content matches `expected/sample.sanitized.ndjson`,
- quarantine index is empty.
