# CONSTITUTION.md

## Purpose
Prevent quality degradation, security regressions, and drift across sessions by enforcing **fail-closed**, **offline-first**, **audit-grade** engineering discipline.

All rules in this constitution are **non-negotiable** unless the Exception process is followed.

---

## Core invariants (MUST / MUST NOT)

### C-001 Offline-first enforcement
- MUST NOT perform network calls at runtime (including DNS).
- MUST NOT emit telemetry.
- Rationale: air-gapped compatibility and prevention of unintended data exfiltration.
- Detect:
  - build-time: dependency review and network API usage scan
  - runtime: integration test that denies network and asserts no network attempts
- Remediate:
  - remove offending dependency or isolate behind disabled-by-default feature flag
- Enforce:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-OFFLINE-NO-NET
evidence: checks/CHECKS_INDEX.md :: CHK-OFFLINE-ENFORCEMENT

### C-002 Fail-closed terminal states
- Every artifact MUST end in exactly one terminal state: VERIFIED or QUARANTINED.
- MUST NOT silently pass artifacts with partial parsing/coverage.
- Rationale: prevents false safety and uncontrolled leakage.
- Detect:
  - end-to-end tests with unsupported formats and induced parse failures
- Remediate:
  - route uncertain paths to quarantine with reason code
- Enforce:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-FAIL-CLOSED-TERMINAL
evidence: spec/03_DOMAIN_MODEL.md :: Artifact State Machine

### C-003 No plaintext sensitive values in logs/reports/evidence
- MUST NOT write raw sensitive values into:
  - logs
  - reports
  - evidence bundle
  - run manifest
  - quarantine reason strings
- Rationale: evidence and diagnostics must be safe to share with security/compliance reviewers.
- Detect:
  - canary-string tests that inject known markers into inputs and assert absence in outputs/logs/evidence
- Remediate:
  - replace any emission with class markers, hashed locators, or keyed digests (never plaintext)
- Enforce:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-NO-PLAINTEXT-LEAKS
evidence: spec/08_OBSERVABILITY.md :: Log Redaction Rules

### C-004 Deterministic, reproducible runs
- Given identical:
  - input bytes
  - policy bundle
  - tool version
  Veil MUST produce identical outputs and evidence (within the determinism definition).
- Rationale: auditability and stable approvals.
- Detect:
  - determinism integration test (double-run comparison)
- Remediate:
  - remove nondeterministic ordering; normalize volatile fields; pin formatting rules
- Enforce:
evidence: spec/11_QUALITY_GATES.md :: G-REL-DETERMINISM
evidence: DECISIONS.md :: D-0003

### C-005 Resource bounding and safe failure
- MUST provide configurable bounds for CPU, memory, disk/temp, archive expansion, and recursion depth.
- On bound violation MUST quarantine the artifact (or fail the run only when continuing would be unsafe).
- Rationale: prevents denial-of-service from malicious or accidental inputs.
- Detect:
  - archive-bomb and large-file tests
- Remediate:
  - implement streaming, backpressure, and strict limit checks
- Enforce:
evidence: spec/11_QUALITY_GATES.md :: G-REL-ARCHIVE-LIMITS
evidence: DECISIONS.md :: D-0006

### C-006 Canonical homes and anti-duplication
- MUST NOT duplicate normative rules across files.
- MUST reference the canonical home using evidence pointers.
- Rationale: drift prevention.
- Detect:
  - review checklist
- Remediate:
  - move/merge to canonical home and replace duplicates with evidence pointers
- Enforce:
evidence: templates/PR_REVIEW_CHECKLIST.md :: No Evidence, No Accept

---

## Boundary and coupling guardrails (MUST)

### C-101 Layering rules (dependency direction)
- The implementation MUST follow a strict layering that prevents cross-coupling:
  1) domain (pure types + invariants)
  2) policy (policy parsing + compilation)
  3) extract (format parsing → canonical representation + coverage map)
  4) detect (detector engine over canonical representation)
  5) transform (rewrite outputs + staging)
  6) verify (post-transform scan + gating)
  7) evidence (manifests + non-sensitive evidence)
  8) cli (argument parsing + orchestration)
- Lower layers MUST NOT depend on higher layers.
- Rationale: testability, maintainability, and drift resistance.
- Detect:
  - boundary fitness function check over crate/module dependency graph
- Remediate:
  - move shared types to lower layer; invert dependency via interfaces
- Enforce:
evidence: spec/11_QUALITY_GATES.md :: G-MAINT-BOUNDARY-FITNESS
evidence: checks/CHECKS_INDEX.md :: CHK-BOUNDARY-FITNESS

### C-102 No global implicit state for critical flows
- MUST avoid hidden global state for policy, keys, and run configuration.
- Rationale: determinism and auditability.
- Detect:
  - code review checklist + targeted lint rules
- Remediate:
  - pass explicit context objects through call graph
- Enforce:
evidence: spec/11_QUALITY_GATES.md :: G-MAINT-NO-GLOBAL-STATE

---

## SLOP_BLACKLIST

For each item, violating it requires the Exception process.

### SB-0001 Silent defaults in critical flows
- Detect: review for implicit permissive behavior.
- Remediate: enforce explicit configuration; fail closed.
- Enforce: evidence: spec/11_QUALITY_GATES.md :: SLOP Enforcement Mapping

### SB-0002 God objects / mega-modules
- Detect: modules exceeding agreed size/role boundaries; cross-layer imports.
- Remediate: split by layer; enforce boundaries.
- Enforce: evidence: spec/11_QUALITY_GATES.md :: SLOP Enforcement Mapping

### SB-0003 Copy-paste duplication instead of abstraction
- Detect: repeated logic across extractors/detectors/transforms.
- Remediate: factor shared utilities with clear ownership.
- Enforce: evidence: spec/11_QUALITY_GATES.md :: SLOP Enforcement Mapping

### SB-0004 Untested error paths
- Detect: missing negative-path tests for quarantine and verification failure.
- Remediate: add tests for failures and bounds.
- Enforce: evidence: spec/11_QUALITY_GATES.md :: SLOP Enforcement Mapping

### SB-0005 Unbounded retries / missing timeouts
- Detect: loops without bounds; I/O without timeouts.
- Remediate: bounded retries and explicit timeouts; quarantine on exhaustion where applicable.
- Enforce: evidence: spec/11_QUALITY_GATES.md :: SLOP Enforcement Mapping

### SB-0006 Hidden global state / implicit singletons
- Detect: static mutable state, hidden caches.
- Remediate: explicit context and dependency injection.
- Enforce: evidence: spec/11_QUALITY_GATES.md :: SLOP Enforcement Mapping

### SB-0007 Naming/semantics drift
- Detect: inconsistent term usage across specs and code.
- Remediate: update glossary + refactor to match.
- Enforce: evidence: spec/03_DOMAIN_MODEL.md :: Glossary (normative)

### SB-0008 Logging without correlation OR leaking sensitive data
- Detect: logs without run_id/artifact_id; any plaintext sensitive emission.
- Remediate: structured logs with correlation; strict redaction.
- Enforce: evidence: spec/08_OBSERVABILITY.md :: Log Schema v1

### SB-0009 Contract drift (implementation ≠ interfaces/spec)
- Detect: CLI/output/schema differs from spec/04.
- Remediate: update implementation or formally version/deprecate.
- Enforce: evidence: spec/11_QUALITY_GATES.md :: G-COMP-CONTRACT-CONSISTENCY

### SB-0010 Convenience over fail-closed
- Detect: best-effort behavior that emits outputs without verification.
- Remediate: quarantine or fail; never silently emit unsafe artifacts.
- Enforce: evidence: spec/11_QUALITY_GATES.md :: G-SEC-FAIL-CLOSED-TERMINAL

### SB-0011 One-off scripts without runbook/checks
- Detect: operational steps not documented or not gated.
- Remediate: add to runbook and checks.
- Enforce: evidence: spec/12_RUNBOOK.md :: Maintenance Playbook

### SB-0012 Structural changes without decision log
- Detect: changed boundaries/interfaces without a D-entry.
- Remediate: write decision + update specs/gates.
- Enforce: evidence: templates/PR_REVIEW_CHECKLIST.md :: Decisions Updated

---

## Exception process (REQUIRED)
Violating any SLOP_BLACKLIST rule requires ALL of:
(1) a DECISIONS.md entry with explicit justification,
(2) an explicit mitigation plan,
(3) a check or test plan that prevents uncontrolled spread,
(4) acceptance checklist evidence pointers to (1)-(3).
