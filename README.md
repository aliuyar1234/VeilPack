# Veil SSOT Pack (Codex-Ready)

This ZIP is the **Single Source of Truth (SSOT)** for implementing **Veil**: an offline, fail-closed privacy gate that converts raw customer-data corpora into **Veil Packs** (sanitized corpus + quarantine + non-sensitive evidence).

## Precedence Order (conflict resolution; verbatim)
1) AGENTS.md
2) CONSTITUTION.md
3) spec/* (numeric order; existing files only)
4) DECISIONS.md
5) ASSUMPTIONS.md
6) README.md
7) templates/*, checks/*, runbook content

## Where to find X (evidence pointers only)

### Scope
evidence: spec/01_SCOPE.md :: Scope Summary

### Architecture
evidence: spec/02_ARCHITECTURE.md :: Architecture Overview

### Domain model and definitions
evidence: spec/03_DOMAIN_MODEL.md :: Domain Entities

### Interfaces and contracts (CLI + Veil Pack)
evidence: spec/04_INTERFACES_AND_CONTRACTS.md :: CLI Contract

### Datastore and resumability ledger
evidence: spec/05_DATASTORE_AND_MIGRATIONS.md :: Ledger Datastore

### Security and threat model
evidence: spec/06_SECURITY_AND_THREAT_MODEL.md :: Threat Model

### Reliability and operations
evidence: spec/07_RELIABILITY_AND_OPERATIONS.md :: Reliability Model

### Observability
evidence: spec/08_OBSERVABILITY.md :: Observability Signals

### Test strategy
evidence: spec/09_TEST_STRATEGY.md :: Test Pyramid

### Phases and tasks
evidence: spec/10_PHASES_AND_TASKS.md :: Roadmap Summary Table

### Quality gates and checks
evidence: spec/11_QUALITY_GATES.md :: Quality Gates Index
evidence: checks/CHECKS_INDEX.md :: Checks Index

### Runbook (how to run/build/test)
evidence: spec/12_RUNBOOK.md :: Local Run Quickstart

### Decisions / assumptions / progress / questions
evidence: DECISIONS.md :: Decision Log
evidence: ASSUMPTIONS.md :: Assumptions Log
evidence: PROGRESS.md :: Task Status Table
evidence: QUESTIONS_FOR_USER.md :: Open Questions

### Self-audit
evidence: AUDIT_REPORT.md :: SSOT SCORECARD

## System Tour (15 minutes)

### What Veil is (execution model)
- **Offline batch CLI** that ingests a corpus (folders/archives/dumps) and emits a **Veil Pack**.
- **Fail-closed**: every artifact ends **VERIFIED** (safe derivative emitted) or **QUARANTINED** (withheld + reason code).
- **No plaintext sensitive values** in logs/reports/evidence, ever.

### Primary entrypoints (conceptual)
- `veil run`:
  - reads input corpus + policy bundle
  - processes artifacts deterministically via pipeline
  - emits Veil Pack (sanitized + quarantine index + evidence)
- `veil verify`:
  - rescans a Veil Pack output using the same policy
  - fails if residual sensitive matches are detected under configured detectors
- `veil policy lint`:
  - validates policy schema and computes policy identity (policy_id)

See the full contract:
evidence: spec/04_INTERFACES_AND_CONTRACTS.md :: CLI Contract

### Critical flows (fail-closed by design)
- Raw data ingestion and parsing
- Sensitive detection + transformation
- Output emission (sanitized corpus + evidence)
- Key handling (only when explicitly enabled)
- Logging and evidence generation

See security model:
evidence: spec/06_SECURITY_AND_THREAT_MODEL.md :: Critical Flows and Controls

### Minimal path to implement
- Implement PHASE_0_BOOTSTRAP then PHASE_1_CORE_PIPELINE, then PHASE_2_POLICY_BUNDLE and PHASE_3_EVIDENCE_AND_AUDIT.
evidence: spec/10_PHASES_AND_TASKS.md :: PHASE_0_BOOTSTRAP

## Change Map (if you change X, update Y)

1) **Change safety definition / VERIFIED criteria**
- Update: evidence: spec/03_DOMAIN_MODEL.md :: VERIFIED and QUARANTINED
- Update: evidence: spec/06_SECURITY_AND_THREAT_MODEL.md :: Safety Definition
- Update gates: evidence: spec/11_QUALITY_GATES.md :: G-SEC-VERIFY-RESIDUAL

2) **Add a new detector class**
- Update: evidence: spec/04_INTERFACES_AND_CONTRACTS.md :: Policy Bundle Schema v1
- Update tests: evidence: spec/09_TEST_STRATEGY.md :: Detector tests:

3) **Add a new extractor / format**
- Update: evidence: spec/02_ARCHITECTURE.md :: Extractor Contract and Coverage Map
- Update threat model: evidence: spec/06_SECURITY_AND_THREAT_MODEL.md :: Format Risk and Coverage
- Update tasks: evidence: spec/10_PHASES_AND_TASKS.md :: PHASE_4_FORMATS_AND_LIMITS

4) **Change archive safety limits**
- Update: evidence: DECISIONS.md :: D-0006
- Update gate: evidence: spec/11_QUALITY_GATES.md :: G-REL-ARCHIVE-LIMITS

5) **Change tokenization / proof digest rules**
- Update: evidence: DECISIONS.md :: D-0004
- Update: evidence: DECISIONS.md :: D-0007
- Update security gates: evidence: spec/11_QUALITY_GATES.md :: G-SEC-KEY-HANDLING

6) **Change Veil Pack layout or schema versions**
- Update: evidence: spec/04_INTERFACES_AND_CONTRACTS.md :: Veil Pack Layout v1
- Update compatibility gates: evidence: spec/11_QUALITY_GATES.md :: G-COMP-PACK-COMPAT

7) **Change logging**
- Update: evidence: spec/08_OBSERVABILITY.md :: Log Redaction Rules
- Update gate: evidence: spec/11_QUALITY_GATES.md :: G-SEC-NO-PLAINTEXT-LEAKS

8) **Change module boundaries**
- Update: evidence: spec/02_ARCHITECTURE.md :: Dependency Direction Rules
- Update gate: evidence: spec/11_QUALITY_GATES.md :: G-MAINT-BOUNDARY-FITNESS

9) **Change ledger schema**
- Update: evidence: spec/05_DATASTORE_AND_MIGRATIONS.md :: Schema v1
- Update gate: evidence: spec/11_QUALITY_GATES.md :: G-REL-LEDGER-RESUME

10) **Introduce any external I/O**
- Must remain disabled-by-default and fail-closed per autonomy policy.
- Update: evidence: spec/06_SECURITY_AND_THREAT_MODEL.md :: Offline-First Enforcement

## Drift detection (MANIFEST.sha256)
- Any change to any file in this pack requires regenerating MANIFEST.sha256.
- Verification procedure:
evidence: checks/CHECKS_INDEX.md :: CHK-MANIFEST-VERIFY

---

## Implementation bootstrap (PHASE_0)
This repository now contains an initial Rust workspace scaffold aligned to the C-101 layers.

- Workspace: `Cargo.toml` + `crates/*`
- CLI binary (stub): `crates/veil-cli` (run via Cargo; binary name is `veil`)
- Boundary check: `python checks/boundary_fitness.py`

Quickstart:
- `cargo build --workspace`
- `cargo test --workspace`
- `cargo run -p veil-cli -- --help`
