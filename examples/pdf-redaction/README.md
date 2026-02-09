# PDF Redaction Demo

This demo shows end-to-end PDF processing for searchable (text-layer) PDFs.

## Run

```bash
cargo run -p veil-cli -- run \
  --input examples/pdf-redaction/input \
  --output examples/pdf-redaction/out \
  --policy examples/pdf-redaction/policy
```

## Inspect

```bash
cat examples/pdf-redaction/out/sanitized/*.ndjson
```

Expected behavior:
- input `invoice.pdf` is processed as PDF
- sanitized output is canonical NDJSON
- `SECRET` is redacted to `{{PII.Secret}}`
