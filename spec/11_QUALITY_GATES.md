# spec/11_QUALITY_GATES.md

## Quality Gates Index
Quality gates are enforceable pass/fail requirements. A gate is PASS only if its verification procedure is executed and evidence is recorded.

Evidence location (default):
evidence: PROGRESS.md :: Evidence Recording Rules

No Evidence, No Accept / No Progress.

---

## Gate definitions

### G-SEC-OFFLINE-NO-NET
- Why: air-gapped compatibility; prevent exfiltration.
- Verify:
  - Static: dependency and code scan for network APIs.
  - Runtime: integration test that executes `veil run` against a fixture corpus in a network-denied environment and asserts no network attempts.
- Pass/fail:
  - PASS if both static and runtime checks pass.
- Evidence:
evidence: PROGRESS.md :: G-SEC-OFFLINE-NO-NET

Check IDs:
- CHK-OFFLINE-ENFORCEMENT

### G-SEC-FAIL-CLOSED-TERMINAL
- Why: prevent silent unsafe passes.
- Verify:
  - End-to-end test asserts: for a mixed corpus, every artifact ends VERIFIED or QUARANTINED; no other terminal states.
- Pass/fail:
  - PASS if the test confirms the invariant for all artifacts.
- Evidence:
evidence: PROGRESS.md :: G-SEC-FAIL-CLOSED-TERMINAL

### G-SEC-NO-PLAINTEXT-LEAKS
- Why: logs/evidence are commonly shared and must be safe.
- Verify:
  - Canary test injects known canary strings into inputs and asserts absence from:
    - logs
    - evidence outputs
    - quarantine index
- Pass/fail:
  - PASS if canary strings are absent.
- Evidence:
evidence: PROGRESS.md :: G-SEC-NO-PLAINTEXT-LEAKS

Check IDs:
- CHK-NO-PLAINTEXT-LEAKS

### G-SEC-POLICY-ID-IMMUTABLE
- Why: prevent policy drift across resume/verify.
- Verify:
  - Unit tests for canonical policy bundle hashing.
  - Integration test: resume refuses when policy_id mismatches ledger.
- Pass/fail:
  - PASS if mismatch is detected and execution is refused.
- Evidence:
evidence: PROGRESS.md :: G-SEC-POLICY-ID-IMMUTABLE

### G-SEC-COVERAGE-ENFORCED
- Why: prevent “verified but partially parsed”.
- Verify:
  - For each supported format, test that CoverageMap v1 has no UNKNOWN surfaces.
  - For unsupported/partial cases, test that UNKNOWN coverage leads to quarantine.
- Pass/fail:
  - PASS if UNKNOWN never results in VERIFIED.
- Evidence:
evidence: PROGRESS.md :: G-SEC-COVERAGE-ENFORCED

### G-SEC-QUARANTINE-NO-RAW-DEFAULT
- Why: avoid unintended duplication/retention of raw sensitive data.
- Verify:
  - Default run that produces quarantines must create `quarantine/index.ndjson` but must not create `quarantine/raw/`.
  - When quarantine raw copying is explicitly enabled, raw files may be created only under `quarantine/raw/` and the pack manifest must record that it was enabled.
- Pass/fail:
  - PASS if default produces no raw quarantine copies and opt-in behavior is correctly contained.
- Evidence:
evidence: PROGRESS.md :: G-SEC-QUARANTINE-NO-RAW-DEFAULT

### G-SEC-VERIFY-RESIDUAL
- Why: VERIFIED must be enforceable.
- Verify:
  - Integration test where transform misses a HIGH-severity match and residual verification quarantines.
  - `veil verify` reproduces the failure on the produced Veil Pack.
- Pass/fail:
  - PASS if residuals are detected and block VERIFIED.
- Evidence:
evidence: PROGRESS.md :: G-SEC-VERIFY-RESIDUAL

### G-SEC-KEY-HANDLING
- Why: tokenization and proof digests introduce linkage risk and secret handling.
- Verify:
  - Tokenization disabled by default.
  - Enabling tokenization without a key fails to start.
  - Evidence contains key commitment only; never the key.
- Pass/fail:
  - PASS if invariants hold and tests enforce them.
- Evidence:
evidence: PROGRESS.md :: G-SEC-KEY-HANDLING

---

### G-REL-LEDGER-RESUME
- Why: resumability is mandatory for large corpora.
- Verify:
  - Crash simulation test (kill mid-run) then resume; ensure no partial outputs and states reconcile.
  - Resume refuses on policy_id mismatch.
- Pass/fail:
  - PASS if resume completes correctly and invariants hold.
- Evidence:
evidence: PROGRESS.md :: G-REL-LEDGER-RESUME

### G-REL-DETERMINISM
- Why: reproducibility and auditability.
- Verify:
  - Determinism integration test: double-run same corpus; assert identical hashes for outputs and evidence.
- Pass/fail:
  - PASS if hashes match.
- Evidence:
evidence: PROGRESS.md :: G-REL-DETERMINISM

Related decision:
evidence: DECISIONS.md :: ## D-0014

### G-REL-ARCHIVE-LIMITS
- Why: prevent archive bombs and unsafe paths.
- Verify:
  - tests that trigger each archive limit and assert quarantine of the archive artifact.
  - tests that attempt path traversal and assert quarantine.
- Pass/fail:
  - PASS if all violations quarantine and no partial emission occurs.
- Evidence:
evidence: PROGRESS.md :: G-REL-ARCHIVE-LIMITS

### G-REL-ATOMIC-COMMIT
- Why: avoid partial sanitized outputs on crash.
- Verify:
  - integration test that forces failure mid-write and asserts `sanitized/` contains no partial files.
- Pass/fail:
  - PASS if atomicity invariant holds.
- Evidence:
evidence: PROGRESS.md :: G-REL-ATOMIC-COMMIT

Related decision:
evidence: DECISIONS.md :: ## D-0014

---

### G-PERF-NO-REGRESSION
- Why: scale must be maintainable without guessing absolute targets.
- Verify:
  - perf harness runs on a fixed fixture corpus and records baseline metrics.
  - subsequent runs compare against baseline and require a decision + mitigation if regressed.
- Pass/fail:
  - PASS if no regression OR regression is explicitly approved by decision with mitigation and evidence.
- Evidence:
evidence: PROGRESS.md :: G-PERF-NO-REGRESSION

---

### G-OPS-RUNBOOK-COMPLETE
- Why: operators must run/diagnose offline.
- Verify:
  - follow runbook “Local Run Quickstart” end-to-end on a fixture corpus.
- Pass/fail:
  - PASS if commands succeed and outputs match runbook expectations.
- Evidence:
evidence: PROGRESS.md :: G-OPS-RUNBOOK-COMPLETE

---

### G-MAINT-BOUNDARY-FITNESS
- Why: prevent architecture erosion and cross-layer coupling.
- Verify:
  - `python checks/boundary_fitness.py`
  - OR `cargo test -p veil-cli --test boundary_fitness`
- Pass/fail:
  - PASS if dependency direction rules are satisfied.
- Evidence:
evidence: PROGRESS.md :: G-MAINT-BOUNDARY-FITNESS

Check IDs:
- CHK-BOUNDARY-FITNESS

### G-MAINT-NO-GLOBAL-STATE
- Why: determinism and auditability.
- Verify:
  - manual review checklist confirms no hidden global state for policy/keys/run context.
- Pass/fail:
  - PASS if review evidence exists for all critical-flow changes.
- Evidence:
evidence: PROGRESS.md :: G-MAINT-NO-GLOBAL-STATE

---

### G-COMP-PACK-COMPAT
- Why: Veil Pack is a public artifact contract.
- Verify:
  - pack_manifest.json includes schema versions.
  - verify command refuses unsupported versions.
- Pass/fail:
  - PASS if compatibility behavior matches spec/04.
- Evidence:
evidence: PROGRESS.md :: G-COMP-PACK-COMPAT

### G-COMP-CONTRACT-CONSISTENCY
- Why: prevent contract drift.
- Verify:
  - contract tests assert CLI flags and Veil Pack layout match spec/04.
- Pass/fail:
  - PASS if tests match the spec and versioning rules are enforced.
- Evidence:
evidence: PROGRESS.md :: G-COMP-CONTRACT-CONSISTENCY

---

## SLOP Enforcement Mapping (SB-0001..SB-0012)
No Evidence, No Accept / No Progress.

| SB-ID | Enforcement type | Check IDs and/or checklist location | Required evidence |
|---|---|---|---|
| SB-0001 | checklist + tests | templates/PR_REVIEW_CHECKLIST.md :: SLOP_BLACKLIST Compliance | evidence: PROGRESS.md :: SB-0001 |
| SB-0002 | automated | CHK-BOUNDARY-FITNESS | evidence: PROGRESS.md :: SB-0002 |
| SB-0003 | checklist | templates/PR_REVIEW_CHECKLIST.md :: SLOP_BLACKLIST Compliance | evidence: PROGRESS.md :: SB-0003 |
| SB-0004 | tests | CHK-NEGATIVE-PATHS | evidence: PROGRESS.md :: SB-0004 |
| SB-0005 | checklist + tests | templates/PR_REVIEW_CHECKLIST.md :: SLOP_BLACKLIST Compliance | evidence: PROGRESS.md :: SB-0005 |
| SB-0006 | checklist | templates/PR_REVIEW_CHECKLIST.md :: SLOP_BLACKLIST Compliance | evidence: PROGRESS.md :: SB-0006 |
| SB-0007 | checklist | spec/03_DOMAIN_MODEL.md :: Glossary (normative) | evidence: PROGRESS.md :: SB-0007 |
| SB-0008 | tests | CHK-NO-PLAINTEXT-LEAKS | evidence: PROGRESS.md :: SB-0008 |
| SB-0009 | contract tests | CHK-CONTRACT-CONSISTENCY | evidence: PROGRESS.md :: SB-0009 |
| SB-0010 | tests | CHK-FAIL-CLOSED-INVARIANTS | evidence: PROGRESS.md :: SB-0010 |
| SB-0011 | checklist | spec/12_RUNBOOK.md :: Maintenance Playbook | evidence: PROGRESS.md :: SB-0011 |
| SB-0012 | checklist | templates/PR_REVIEW_CHECKLIST.md :: Decisions Updated | evidence: PROGRESS.md :: SB-0012 |
