# ASSUMPTIONS.md

## Assumptions Log
Assumptions are temporary and must be validated or promoted to decisions when needed.

---

## A-0001 — V1 optimizes for text and semi-structured corpora
- Assumption: Initial implementation prioritizes artifacts that can be deterministically processed offline with explicit coverage: text, CSV/TSV, JSON/NDJSON, and common message exports.
- Why: Matches the initial wedge while keeping the system buildable and verifiable.
- Risk if wrong: Excess quarantine reduces adoption; format support roadmap must accelerate.
- How to validate: Run pilot corpora and measure quarantine rates by reason code.
- Promote to decision when: format-support commitments become contractual.

---

## A-0002 — Operators treat Veil Pack as the approved sharing unit
- Assumption: Downstream workflows accept Veil Pack outputs as the “approved object” to share/process/train on.
- Why: Enables Veil to become a default gate rather than a one-off utility.
- Risk if wrong: Teams may bypass the gate; governance controls weaken.
- How to validate: Integrations and internal policy require Veil Pack for exports.
- Promote to decision when: governance workflow is formalized.

---

## A-0003 — No external compliance regime is asserted in this SSOT
- Assumption: The SSOT provides mechanisms (auditability, controls) without claiming adherence to any external framework.
- Why: External compliance obligations are externally constrained and must not be invented.
- Risk if wrong: Customers may require explicit mappings; those must be provided as inputs later.
- How to validate: Confirm customer compliance needs and map via policy profiles without claims.
- Promote to decision when: a specific externally constrained regime is provided.

---

## A-0004 — Cross-platform support is desirable but not required for correctness
- Assumption: The design avoids OS-specific behavior; verification focuses on deterministic output semantics.
- Why: Offline enterprises run mixed environments; portability is valuable.
- Risk if wrong: File permission semantics differ; quarantine-copy opt-in may be unsafe on some OSes.
- How to validate: run integration tests on at least one Unix-like OS and one Windows environment.
- Promote to decision when: official supported platform matrix is asserted.

---

## A-0005 — Extension mechanisms are phase-gated
- Assumption: V1 can ship with built-in extractors/detectors; plugin extension mechanisms can be added later without breaking contracts.
- Why: Keeps security posture conservative while establishing core pipeline and evidence model.
- Risk if wrong: Enterprises may demand custom detectors immediately.
- How to validate: collect early ICP requirements; measure demand for custom classes.
- Promote to decision when: plugin ABI and governance are formalized.
