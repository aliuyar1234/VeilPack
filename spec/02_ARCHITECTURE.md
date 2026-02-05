# spec/02_ARCHITECTURE.md

## Architecture Overview
Veil is a deterministic, offline batch pipeline that transforms a corpus into a **Veil Pack** under an explicit policy bundle.

Exactly one architecture diagram follows.

```mermaid
flowchart LR
  subgraph IN[Input Corpus (read-only)]
    A[Artifacts: files/archives/exports]
  end

  subgraph VEIL[Veil Pipeline]
    I[Ingest + Fingerprint]
    L[(Resumability Ledger)]
    P[Policy Bundle Loader]
    X[Extractor (format handler) + CoverageMap]
    D[Detector Engine]
    T[Transformer/Rewriter]
    V[Residual Verification Pass]
    E[Evidence Builder]
  end

  subgraph OUT[Veil Pack (output)]
    S[Sanitized Corpus]
    Q[Quarantine Index (+ optional raw copies)]
    M[Run Manifest + Evidence Bundle]
  end

  A --> I --> X --> D --> T --> V --> E --> M
  P --> D
  I --> L
  X --> L
  T --> L
  V --> L
  T --> S
  V --> Q
```

## Component Boundary Table (normative)
| Component | Responsibilities | MUST NOT |
|---|---|---|
| Ingest + Fingerprint | enumerate corpus deterministically; compute artifact_id and source_locator_hash; schedule work | parse formats; emit outputs |
| Policy Bundle Loader | load and hash policy bundle; compile detectors; validate policy schema | mutate policy; proceed on invalid policy |
| Extractor | parse artifact to canonical representation; emit CoverageMap v1 | claim FULL coverage when UNKNOWN; emit plaintext secrets to logs/evidence |
| Detector Engine | run detectors over canonical representation; produce findings | read/write filesystem |
| Transformer/Rewriter | apply transforms; write outputs to staging; atomic commit | overwrite inputs; emit partial outputs on failure |
| Residual Verification | re-scan outputs; quarantine on residual; enforce VERIFIED definition | mark VERIFIED without verification |
| Evidence Builder | emit non-sensitive evidence and manifests; bind to policy_id and run_id | store plaintext sensitive values |
| Ledger | persist resumability state machine; record non-sensitive metadata | store plaintext sensitive values |

## Pipeline invariants (fail-closed)
- Every artifact MUST end VERIFIED or QUARANTINED.
- VERIFIED implies:
  - CoverageMap v1 has no UNKNOWN surfaces
  - post-transform verification pass succeeded
- If any stage cannot safely complete, artifact MUST be quarantined (or run aborts only if continuing would be unsafe).

Canonical state semantics:
evidence: spec/03_DOMAIN_MODEL.md :: Artifact State Machine

## Dependency Direction Rules (normative)
Implementation MUST follow the layering rules in:
evidence: CONSTITUTION.md :: C-101 Layering rules (dependency direction)

Boundary fitness enforcement:
evidence: spec/11_QUALITY_GATES.md :: G-MAINT-BOUNDARY-FITNESS

## Workspace crate mapping (normative)
The C-101 layers are implemented as a Rust workspace with one crate per layer:
- domain: `crates/veil-domain`
- policy: `crates/veil-policy`
- extract: `crates/veil-extract`
- detect: `crates/veil-detect`
- transform: `crates/veil-transform`
- verify: `crates/veil-verify`
- evidence: `crates/veil-evidence`
- cli: `crates/veil-cli` (binary name: `veil`)

Boundary check (automated):
- `python checks/boundary_fitness.py`

Decision:
evidence: DECISIONS.md :: ## D-0009

## Extractor Contract and Coverage Map (conceptual contract)
- Input: artifact bytes + artifact context (artifact_id, policy_id, limits)
- Output:
  - canonical representation (text segments and/or structured fields and/or metadata)
  - CoverageMap v1 (D-0002)
- If extractor cannot safely parse or cannot provide CoverageMap v1, it MUST return QUARANTINE with a reason code.

Coverage decision:
evidence: DECISIONS.md :: D-0002

## Determinism and ordering
- Deterministic ordering and canonical serialization rules are normative.
evidence: DECISIONS.md :: D-0003

## Feature Add/Remove Playbook (normative)
### Add a new artifact type (extractor)
1) Update extractor registry and CoverageMap behavior.
2) Add negative-path tests (parse failure → quarantine; unknown coverage → quarantine).
3) Update threat model for the new format.
4) Add/extend gates if the new format introduces new leakage surfaces.

Tasks:
evidence: spec/10_PHASES_AND_TASKS.md :: PHASE_4_FORMATS_AND_LIMITS
Gates:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-COVERAGE-ENFORCED

### Add a new detector class
1) Extend policy schema (class + severity + detectors).
2) Implement detector with deterministic behavior.
3) Add canary tests ensuring no plaintext leaks in evidence/logs.
4) Ensure residual verification catches misses.

Tasks:
evidence: spec/10_PHASES_AND_TASKS.md :: PHASE_2_POLICY_BUNDLE
Gates:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-VERIFY-RESIDUAL

### Remove or relax a safety rule
- MUST be logged as a decision with explicit risk analysis and verification impact.
evidence: templates/PR_REVIEW_CHECKLIST.md :: Decisions Updated
