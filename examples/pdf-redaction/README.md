# PDF Redaction Demo

This demo shows end-to-end PDF processing for searchable (text-layer) PDFs.
PDF is disabled by default in `master`, so this demo passes an explicit `limits.json` opt-in.

## Run

```bash
cargo run -p veil-cli -- run \
  --input examples/pdf-redaction/input \
  --output examples/pdf-redaction/out \
  --policy examples/pdf-redaction/policy \
  --limits-json examples/pdf-redaction/limits.json
```

## Inspect

```bash
cat examples/pdf-redaction/out/sanitized/*.ndjson
```

Expected behavior:
- input `invoice.pdf` is processed as PDF
- sanitized output is canonical NDJSON
- `SECRET` is redacted to `{{PII.Secret}}`
