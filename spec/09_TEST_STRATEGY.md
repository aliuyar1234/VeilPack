# spec/09_TEST_STRATEGY.md

## Test Pyramid

### Unit tests
- Detector tests:
  - exact-match behavior
  - checksum validation behavior (where applicable)
  - catastrophic pattern rejection in policy lint
- CoverageMap tests:
  - supported formats produce no UNKNOWN coverage
  - unsupported formats produce quarantine

Reference:
evidence: DECISIONS.md :: D-0002

### Integration tests (end-to-end)
Must include a small fixture corpus that covers:
- VERIFIED happy path (text + structured)
- QUARANTINED unsupported format
- QUARANTINED encrypted artifact
- QUARANTINED archive limit exceeded
- QUARANTINED verification failed (intentional transform miss)

### Determinism tests
- Run the same corpus twice and assert identical:
  - sanitized output hashes
  - evidence bundle hashes (excluding any operator-only notes)
evidence: DECISIONS.md :: D-0003

### Security regression tests (no plaintext leaks)
- Canary secret tests:
  - inject known canary strings into inputs
  - assert canary strings do not appear in:
    - logs
    - evidence outputs
    - quarantine index
evidence: CONSTITUTION.md :: C-003 No plaintext sensitive values in logs/reports/evidence

### Property-based / fuzz tests (harden parsing)
- Fuzz extractors and archive handling to ensure:
  - no panics
  - no unbounded resource growth
  - quarantine on malformed inputs
- Archive traversal/path safety fuzzing.

---

## Test execution (normative)
- All tests must be runnable offline.
- Default command set:
  - `cargo test --workspace`
  - `cargo test --workspace --release` (selected integration/perf checks)

Gates:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-NO-PLAINTEXT-LEAKS
evidence: spec/11_QUALITY_GATES.md :: G-REL-DETERMINISM
