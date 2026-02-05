# spec/00_PROJECT_FINGERPRINT.md

## Project Fingerprint
- Project name: Veil
- Product shape: offline batch CLI (primary) with a Rust library core (implementation target).
- Core function: process heterogeneous corpora to produce a **Veil Pack** (sanitized corpus + quarantine + non-sensitive evidence).
- Sensitivity tier: HIGH (handles raw customer data).
- Network posture: offline-first; air-gapped compatible; no telemetry.
- Primary storage surfaces:
  - input corpus (read-only)
  - output Veil Pack (sanitized + evidence)
  - resumability ledger (non-sensitive; inside Veil Pack)
- Public contracts:
  - CLI interface
  - Veil Pack layout + evidence schemas
  - Policy bundle schema

## Critical flows (must be fail-closed)
- Ingest and parse untrusted artifacts (archives, structured data).
- Detect + transform sensitive content.
- Emit outputs and evidence without plaintext sensitive values.
- Optional key handling (tokenization/proof digests) when explicitly enabled.
- Resume and verification semantics.

See the normative safety definition:
evidence: spec/03_DOMAIN_MODEL.md :: VERIFIED and QUARANTINED

## Spec Applicability Matrix
All spec documents are applicable because this project includes:
- a deployable CLI
- a public artifact format (Veil Pack)
- sensitive-data handling (critical flows)
- resumability ledger

| Spec | Path | Applicability | Justification |
|---:|---|---|---|
| 00 | spec/00_PROJECT_FINGERPRINT.md | APPLICABLE | required; defines applicability + QAC profile |
| 01 | spec/01_SCOPE.md | APPLICABLE | required; defines scope + constraints |
| 02 | spec/02_ARCHITECTURE.md | APPLICABLE | multi-component pipeline + boundaries |
| 03 | spec/03_DOMAIN_MODEL.md | APPLICABLE | defines states/invariants and key terms |
| 04 | spec/04_INTERFACES_AND_CONTRACTS.md | APPLICABLE | CLI + Veil Pack + policy bundle are public contracts |
| 05 | spec/05_DATASTORE_AND_MIGRATIONS.md | APPLICABLE | resumability ledger and schema versioning |
| 06 | spec/06_SECURITY_AND_THREAT_MODEL.md | APPLICABLE | sensitive-data critical flows + offline enforcement |
| 07 | spec/07_RELIABILITY_AND_OPERATIONS.md | APPLICABLE | batch reliability, resumability, safe failures |
| 08 | spec/08_OBSERVABILITY.md | APPLICABLE | audit-grade diagnostics without leakage |
| 09 | spec/09_TEST_STRATEGY.md | APPLICABLE | fail-closed and determinism require strong testing |
| 10 | spec/10_PHASES_AND_TASKS.md | APPLICABLE | required; implementation plan |
| 11 | spec/11_QUALITY_GATES.md | APPLICABLE | required; enforceable quality contract |
| 12 | spec/12_RUNBOOK.md | APPLICABLE | deployable CLI requires run/test/build instructions |

## Quality Attribute Profile
Each row defines enforceable quality via gates and checks.

| Attribute | Intent | Primary risks | Invariants (MUST / MUST NOT) | Verification mapping | Fail-closed default |
|---|---|---|---|---|---|
| Security | Prevent sensitive leakage; deny unsafe execution | plaintext leaks, partial parsing, unsafe archives, key mishandling | MUST be offline-first; MUST be fail-closed; MUST NOT emit plaintext sensitive values; MUST quarantine on unknown coverage | G-SEC-OFFLINE-NO-NET, G-SEC-FAIL-CLOSED-TERMINAL, G-SEC-NO-PLAINTEXT-LEAKS, G-SEC-COVERAGE-ENFORCED, G-SEC-KEY-HANDLING | Quarantine or refuse to start on uncertainty |
| Performance | Predictable throughput on large corpora | unbounded memory/disk, slow regex, inefficient parsing | MUST stream where feasible; MUST bound resources; MUST provide perf harness | G-PERF-NO-REGRESSION | Refuse configs exceeding bounds; quarantine artifacts exceeding limits |
| Reliability | Resume safely; deterministic outputs | partial outputs, non-idempotent stages, nondeterministic ordering | MUST have resumable ledger; MUST commit outputs atomically; MUST be deterministic per D-0003 | G-REL-LEDGER-RESUME, G-REL-DETERMINISM, G-REL-ARCHIVE-LIMITS | Fail run or quarantine artifact rather than emit partial |
| Operability | Operators can run, diagnose, and verify offline | unclear errors, missing runbook, poor evidence | MUST provide runbook; MUST emit evidence bundle; MUST provide verify command | G-OPS-RUNBOOK-COMPLETE, G-SEC-VERIFY-RESIDUAL | Verification failure blocks acceptance of outputs |
| Maintainability | Avoid architecture erosion | god modules, cross-layer imports, drift | MUST enforce layering rules; MUST log structural decisions | G-MAINT-BOUNDARY-FITNESS, G-COMP-CONTRACT-CONSISTENCY | Refuse merges without boundary gate evidence |
| Compatibility/Upgradability | Stable contracts with explicit versioning | breaking changes in pack layout/policy schema | MUST version policy and evidence schemas; MUST use deprecation policy | G-COMP-PACK-COMPAT, G-COMP-CONTRACT-CONSISTENCY | Refuse to read unsupported schema versions |

## Externally constrained unknowns
None were provided in the authoritative input. This SSOT MUST NOT claim adherence to external compliance regimes.
