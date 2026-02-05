# spec/12_RUNBOOK.md

## Local Run Quickstart
This runbook assumes an offline environment.

### Build
- `cargo build --workspace`
- Release binary (recommended for real corpora):
  - `cargo build -p veil-cli --release`
  - Output: `target/release/veil` (or `target\\release\\veil.exe` on Windows)
- Pass condition: build succeeds without network.

### Test
- `cargo test --workspace`
- Pass condition: all tests pass.

### Run a minimal fixture corpus
1) Create a small fixture corpus directory (synthetic, non-sensitive) containing:
   - a text file with a canary marker
   - a JSON file with structured fields
2) Create a policy bundle directory with `policy.json` matching spec/04.
3) Run:
   - `veil run --input <fixture_corpus> --output <out_pack> --policy <policy_bundle>`
4) Expected:
   - `<out_pack>/pack_manifest.json` exists
   - `<out_pack>/sanitized/` contains VERIFIED outputs
   - `<out_pack>/quarantine/index.ndjson` exists (may be empty)
   - `<out_pack>/evidence/run_manifest.json` exists

### Verify the pack
- `veil verify --pack <out_pack> --policy <policy_bundle>`
- Pass condition:
  - exit code 0
  - no residual HIGH findings

---

## Offline distribution (release packaging)
- Build a release binary on a machine with the Rust toolchain:
  - `cargo build -p veil-cli --release`
- Copy the resulting `veil` binary to the offline environment.
- Veil runtime MUST NOT download anything; all inputs are local files and local policy bundles.

---

## Common failure modes (offline-safe diagnostics)

### Exit code 3 (invalid policy or arguments)
- Cause: policy.json schema invalid, missing required flags, or unknown schema_version.
- Remediation:
  - run `veil policy lint --policy <policy_bundle>` and fix reported issues.

### Exit code 2 (run completed with quarantines)
- Cause: unsupported formats, encrypted artifacts, unknown coverage, archive limit violations, verification failures.
- Remediation:
  - inspect `<out_pack>/quarantine/index.ndjson` (non-sensitive)
  - address specific reason codes by adding format support, adjusting inputs, or updating policy.

### Fatal errors (exit code 1)
- Cause: cannot create output pack safely, evidence writer failure, ledger corruption, or internal safety failure.
- Remediation:
  - ensure output directory is empty and writable
  - re-run with a fresh output directory
  - if ledger schema/version mismatch, start a new run (spec/05)

---

## Maintenance Playbook

### Policy updates
- Any policy bundle change yields a new policy_id (D-0001).
- Do not resume an in-progress run with a modified policy bundle.

### Key handling
- Tokenization is disabled by default (D-0004).
- If tokenization is enabled:
  - provide `--secret-key-file`
  - ensure key is stored and rotated according to operator security practices
  - key MUST NOT be embedded in the Veil Pack

### Cleaning workdir
- Workdir defaults to `<pack_root>/.veil_work/`.
- After a successful run, it is safe to remove workdir contents if resumability is no longer needed.

### Verifying before sharing
- Before sharing a Veil Pack, run:
  - `veil verify --pack <pack_root> --policy <policy_bundle>`
- Treat verify failure as a hard block on sharing.

### Upgrading Veil
- Verify pack_schema_version compatibility before relying on older packs.
- If pack schema changes, bump pack_schema_version and document in spec/04.

---

## Phase 5 harnesses (optional operator checks)

### Offline enforcement (no network)
- Static scan: `python checks/offline_enforcement.py`
- Runtime smoke: `cargo test -p veil-cli --test offline_enforcement`

### Contract consistency (spec/04)
- `cargo test -p veil-cli --test contract_consistency`

### Fuzz/property smoke (extractors)
- `cargo test -p veil-extract --test fuzz_smoke`

### Performance baseline (no regression gate)
- Record baseline: `python checks/perf_harness.py --record-baseline`
- Compare: `python checks/perf_harness.py`
