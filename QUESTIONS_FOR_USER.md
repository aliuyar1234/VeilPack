# QUESTIONS_FOR_USER.md

## Open Questions
Questions are recorded for later confirmation. Non-blocking questions must not halt progress; proceed with conservative baselines and record decisions/assumptions.

### Resolved questions (historical; DO NOT REOPEN)
Each resolved question remains listed as a record for reference integrity. These are NON-BLOCKING and already encoded as decisions.

### Q-0001
- blocking: NO
- why needed: Define how policy bundles are identified and prevent policy drift across resume/verify.
- what it blocks: Nothing now; resolved and encoded as policy_id identity + mismatch refusal.
- safe default if non-blocking: Hash the entire policy bundle canonically; deny resume/verify on policy_id mismatch; refuse invalid policy before processing.
- where encoded (decision/assumption/spec path): evidence: DECISIONS.md :: D-0001 — Policy bundle identity and immutability (resolves Q-0001)
- what proceeds safely now: Implement canonical policy bundle hashing and bind all outputs/evidence/ledger to policy_id.
- risk if wrong: Policy drift undermines auditability and can cause unsafe outputs to be treated as approved.

### Q-0002
- blocking: NO
- why needed: Define extractor coverage semantics so VERIFIED never means partially parsed or ambiguously covered.
- what it blocks: Nothing now; resolved and encoded as CoverageMap v1 with UNKNOWN→QUARANTINE.
- safe default if non-blocking: Require CoverageMap v1; if any required surface is UNKNOWN, quarantine.
- where encoded (decision/assumption/spec path): evidence: DECISIONS.md :: D-0002 — Coverage contract semantics (resolves Q-0002)
- what proceeds safely now: Implement extractors that emit coverage; enforce VERIFIED requires no UNKNOWN surfaces.
- risk if wrong: “Verified but partially parsed” leads to false safety and leakage.

### Q-0003
- blocking: NO
- why needed: Define determinism scope so audits and re-runs produce identical artifacts and evidence.
- what it blocks: Nothing now; resolved and encoded as strict ordering + canonical serialization + deterministic run_id.
- safe default if non-blocking: Sort by artifact_id; canonicalize structured outputs; avoid timestamps in evidence; deterministic run_id.
- where encoded (decision/assumption/spec path): evidence: DECISIONS.md :: D-0003 — Determinism definition (resolves Q-0003)
- what proceeds safely now: Implement stable enumeration, canonical serialization, and determinism tests.
- risk if wrong: Drift breaks reproducibility, approvals, and verification parity across sessions.

### Q-0004
- blocking: NO
- why needed: Define deterministic tokenization scope to preserve utility without enabling unintended cross-dataset linkage.
- what it blocks: Nothing now; resolved and encoded as disabled-by-default + explicit enablement + per-run scope baseline.
- safe default if non-blocking: Tokenization off by default; require explicit enablement and key; default scope PER_RUN.
- where encoded (decision/assumption/spec path): evidence: DECISIONS.md :: D-0004 — Deterministic tokenization scope and key rules (resolves Q-0004)
- what proceeds safely now: Implement redact/mask/drop transforms; add tokenization only behind explicit config.
- risk if wrong: Unintended linkage and key-handling mistakes increase privacy risk.

### Q-0005
- blocking: NO
- why needed: Define how quarantine is handled without duplicating raw sensitive artifacts into outputs by default.
- what it blocks: Nothing now; resolved and encoded as index-only quarantine by default with explicit opt-in copying.
- safe default if non-blocking: Do not copy raw quarantined artifacts; produce non-sensitive quarantine index; raw copy only via explicit opt-in.
- where encoded (decision/assumption/spec path): evidence: DECISIONS.md :: D-0005 — Quarantine content handling (resolves Q-0005)
- what proceeds safely now: Implement quarantine index and strict output layout; keep raw copies disabled.
- risk if wrong: Unintended retention/duplication of raw sensitive data increases blast radius.

### Q-0006
- blocking: NO
- why needed: Define safe archive handling limits to prevent bombs, recursion abuse, and path traversal.
- what it blocks: Nothing now; resolved and encoded as strict safety limits with whole-archive quarantine on violation.
- safe default if non-blocking: Enforce expansion/recursion/size limits; quarantine the archive artifact on any violation.
- where encoded (decision/assumption/spec path): evidence: DECISIONS.md :: D-0006 — Archive extraction safety limits (resolves Q-0006)
- what proceeds safely now: Implement bounded archive traversal and negative-path tests.
- risk if wrong: Denial-of-service or unsafe extraction can cause data loss/leakage or system instability.

### Q-0007
- blocking: NO
- why needed: Define audit evidence that proves transformations occurred without ever storing plaintext sensitive values.
- what it blocks: Nothing now; resolved and encoded as digest-based proof tokens and non-sensitive evidence schemas.
- safe default if non-blocking: Evidence contains only non-sensitive IDs, counts, reason codes, and keyed digests; never plaintext.
- where encoded (decision/assumption/spec path): evidence: DECISIONS.md :: D-0007 — Evidence proof format without plaintext (resolves Q-0007)
- what proceeds safely now: Implement evidence bundle and canary tests; keep proofs non-linkable across runs by default.
- risk if wrong: Evidence/logs become an exfiltration vector.

### Q-0008
- blocking: NO
- why needed: Define post-transform verification so VERIFIED has enforceable meaning.
- what it blocks: Nothing now; resolved and encoded as mandatory residual verification before VERIFIED.
- safe default if non-blocking: Re-scan outputs with the same detectors; residual HIGH findings quarantine; `veil verify` blocks sharing.
- where encoded (decision/assumption/spec path): evidence: DECISIONS.md :: D-0008 — Residual verification strategy (resolves Q-0008)
- what proceeds safely now: Implement residual verification stage and verification command contract.
- risk if wrong: Sanitized outputs may retain sensitive values and still be treated as approved.

---

### Q-0009
- blocking: NO
- why needed: Decide whether and how to treat non-textual content (images, PDFs requiring OCR, binaries) within the “format-agnostic” promise.
- what it blocks: Does not block V1; influences roadmap priorities and quarantine rates.
- safe default if non-blocking: Quarantine non-textual or non-parseable content surfaces; do not attempt OCR in v1.
- where encoded (decision/assumption/spec path): spec/01_SCOPE.md :: Out of Scope (explicit non-goals / non-guarantees)
- what proceeds safely now: Implement core text + structured pipeline and strict coverage enforcement.
- risk if wrong: Higher quarantine rate; slower adoption in corpora dominated by scanned documents.

### Q-0010
- blocking: NO
- why needed: Determine how organizations supply custom identifier dictionaries (customer IDs, internal tokens) without leaking them into evidence/logs.
- what it blocks: Not blocking; affects policy bundle resource handling and hashing.
- safe default if non-blocking: Allow dictionary files inside policy bundle; treat them as sensitive inputs; never emit their contents; include in policy_id hashing (D-0001).
- where encoded (decision/assumption/spec path): DECISIONS.md :: D-0001
- what proceeds safely now: Implement policy bundle hashing and core detectors; add dictionaries later as data-only resources.
- risk if wrong: Policy bundle UX friction; customers may need encrypted dictionary packs.

### Q-0011
- blocking: NO
- why needed: Define policy authoring UX (hand-authored JSON vs tooling).
- what it blocks: Not blocking; affects adoption and support load.
- safe default if non-blocking: Provide strict JSON schema and a `veil policy lint` command; no GUI in v1.
- where encoded (decision/assumption/spec path): spec/04_INTERFACES_AND_CONTRACTS.md :: Policy Bundle Schema v1
- what proceeds safely now: Core engine and lint tooling.
- risk if wrong: Policy authoring becomes error-prone; requires additional tooling later.

### Q-0012
- blocking: NO
- why needed: Establish expected throughput/scale targets for specific ICP environments.
- what it blocks: Not blocking; gates avoid absolute targets by design.
- safe default if non-blocking: Use perf harness baseline and enforce non-regression (G-PERF-NO-REGRESSION).
- where encoded (decision/assumption/spec path): spec/11_QUALITY_GATES.md :: G-PERF-NO-REGRESSION
- what proceeds safely now: Implement perf harness and baseline capture.
- risk if wrong: Baseline chosen may not reflect real workloads; must be adjusted with a decision.

### Q-0013
- blocking: NO
- why needed: Define supported OS/filesystems and permission semantics (especially for quarantine-copy and atomic renames).
- what it blocks: Not blocking; may affect reliability guarantees on some platforms.
- safe default if non-blocking: Treat atomicity as required; if platform cannot guarantee safe atomic commit, fail the run before claiming completion.
- where encoded (decision/assumption/spec path): spec/07_RELIABILITY_AND_OPERATIONS.md :: Atomic output commits
- what proceeds safely now: Implement atomic staging + tests on at least one platform.
- risk if wrong: Deployment constraints appear late; packaging must be adjusted.

### Q-0014
- blocking: NO
- why needed: Decide if/when to support third-party plugins for extractors/detectors, and how to sandbox them offline.
- what it blocks: Not blocking for V1; impacts extensibility and governance.
- safe default if non-blocking: Ship built-in extractors/detectors only; defer plugin ABI until governance model is specified.
- where encoded (decision/assumption/spec path): ASSUMPTIONS.md :: A-0005
- what proceeds safely now: Build core pipeline and evidence model.
- risk if wrong: Some enterprises may require custom detectors early.

### Q-0015
- blocking: NO
- why needed: Determine secure deletion expectations for workdir/temp artifacts in regulated environments.
- what it blocks: Not blocking; affects operational hardening.
- safe default if non-blocking: Minimize temp usage; do not create plaintext temp copies; provide a cleanup command that deletes workdir contents; no “secure wipe” claims.
- where encoded (decision/assumption/spec path): spec/12_RUNBOOK.md :: Cleaning workdir
- what proceeds safely now: Implement temp hygiene and safe deletion best-effort without claims.
- risk if wrong: Customers may require platform-specific secure erase procedures.
