# spec/01_SCOPE.md

## Scope Summary
Veil is an offline, air-gapped compatible privacy gate that processes customer-data corpora and emits a **Veil Pack**:
- sanitized corpus (safe derivative)
- quarantine index (and optional quarantine raw copies only via explicit opt-in)
- non-sensitive evidence bundle (audit-grade)

Veil is **fail-closed**: every artifact ends VERIFIED or QUARANTINED.

## In Scope
- Offline batch processing of large heterogeneous corpora from local storage.
- Deterministic pipeline:
  - ingest → extract → detect → transform → verify → emit evidence
- Policy-driven protection:
  - classes (PII/PHI/PCI and organization-specific identifiers)
  - detectors (pattern/structure-based; offline)
  - transforms (redact/mask/drop; optional deterministic tokenization only when enabled)
- Enterprise readiness:
  - audit-grade evidence without plaintext sensitive values
  - controlled outputs (Veil Pack as the approved sharing unit)
  - resumability with a non-sensitive ledger

## Out of Scope (explicit non-goals / non-guarantees)
- No claim of perfect detection of all sensitive information beyond configured detectors.
- No decryption of encrypted/password-protected artifacts (fail closed).
- No OCR for scanned images; no audio/video extraction (unless provided as text).
- No formal privacy guarantees for ML training (not a differential privacy system).
- No guarantee of eliminating re-identification risk from quasi-identifiers unless explicitly addressed via policy transforms.

## Non-negotiable constraints (normative)
- Offline-first: no network calls, no telemetry.
- Rust-first implementation target.
- Corpus/batch processing with resumability and stable throughput.
- Format-agnostic orientation via extractor contracts; unsupported formats quarantine.
- Fail-closed terminal states (VERIFIED or QUARANTINED only).
- No plaintext sensitive values in logs/reports/evidence artifacts.
- Auditability + governance + controlled outputs.

Canonical invariants:
evidence: CONSTITUTION.md :: Core invariants (MUST / MUST NOT)

## Success criteria (measurable; V1)
A run produces a Veil Pack where:
- Every discovered artifact is either VERIFIED or QUARANTINED.
- VERIFIED artifacts pass residual verification (no remaining High-severity matches under configured detectors).
- Evidence and logs contain no plaintext sensitive values (validated via canary tests).
- Outputs are deterministic per D-0003 for identical inputs/policy/tool version.

## Initial wedge (go-to-market wedge inside the universal vision)
- Prepare customer-interaction corpora (tickets/chats/emails/exports/logs) for:
  - external processing and vendor sharing
  - internal analytics in less-trusted environments
  - ML/GenAI preparation (training/eval/RAG corpora)

This wedge is implemented without changing the core pipeline; expansion is additive via new extractors/detectors.
