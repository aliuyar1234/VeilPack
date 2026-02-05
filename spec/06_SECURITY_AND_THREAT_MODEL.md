# spec/06_SECURITY_AND_THREAT_MODEL.md

## Threat Model

### Assets to protect
- Raw input artifacts (customer data).
- Sanitized outputs (must not contain prohibited sensitive values per policy).
- Evidence bundle (must be safe to share; no plaintext sensitive values).
- Optional secret keys (tokenization/proof digests).

### Actors and risk sources
- Benign operator error (misconfiguration, wrong policy).
- Malicious or malformed inputs (archive bombs, parser exploits, path traversal).
- Insider threats (attempting to exfiltrate via logs/evidence/quarantine copies).
- Supply-chain risk (dependencies introducing network calls or unsafe behavior).

### Attack surfaces
- Parsing and extraction (untrusted file formats, nested archives).
- Metadata surfaces (filenames, headers, document properties).
- Intermediate artifacts (temp directories, partial outputs).
- Logs and evidence outputs.
- Optional key handling (tokenization/digests).


## Format Risk and Coverage
- New formats and extractors expand the attack surface and leakage vectors.
- Rules:
  - Unsupported formats MUST quarantine (reason UNSUPPORTED_FORMAT).
  - Partial or unknown coverage MUST quarantine (D-0002).
  - Archives MUST enforce safety limits (D-0006) and quarantine on violations.
- Any format expansion MUST add:
  - negative-path tests for parse failure and unknown coverage
  - threat model update for format-specific leakage surfaces

### Format-specific notes (v1 baseline)
- ZIP/TAR:
  - enforce D-0006 limits (entry count, expansion ratio, expanded bytes, nested depth)
  - quarantine on unsafe paths (`..`, absolute), symlinks/links, or encryption/password requirements
- EML/MBOX:
  - headers are a metadata surface; must be scanned and transformed
  - attachments expand attack surface; unsupported attachment types quarantine (fail closed)
- DOCX/PPTX/XLSX (OOXML):
  - treat as zipped XML with high parser complexity risk
  - embedded binaries/unknown parts imply UNKNOWN coverage and must quarantine under strict baseline


---

## Leakage vectors (categories; must be covered)
1) Content (visible + hidden)
2) Metadata (paths, headers, properties)
3) Intermediate artifacts (temp/caches/partials)
4) Logs/reports/evidence (must remain non-sensitive)
5) Processed output re-identification (linkage via tokens, quasi-identifiers)

Canonical categories:
evidence: spec/03_DOMAIN_MODEL.md :: Veil Pack (conceptual)

---

## Safety Definition (normative summary)
- VERIFIED and QUARANTINED definitions are authoritative:
evidence: spec/03_DOMAIN_MODEL.md :: VERIFIED and QUARANTINED
- Key decisions:
  - policy identity: evidence: DECISIONS.md :: D-0001
  - coverage semantics: evidence: DECISIONS.md :: D-0002
  - determinism: evidence: DECISIONS.md :: D-0003
  - residual verification: evidence: DECISIONS.md :: D-0008

---

## Critical Flows and Controls

### Offline-First Enforcement
Controls:
- The runtime MUST not perform network calls.
- All optional external integrations MUST be disabled-by-default; enabling requires explicit config and must still preserve offline posture.
Gates:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-OFFLINE-NO-NET

### Fail-closed terminal outcomes
Controls:
- Every artifact ends VERIFIED or QUARANTINED only.
- Unknown coverage or parse failures quarantine.
Gates:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-FAIL-CLOSED-TERMINAL

### No plaintext sensitive values in logs/evidence
Controls:
- Logs and evidence must contain only:
  - class markers
  - hashes (artifact_id, source_locator_hash)
  - counts and non-sensitive codes
  - optional keyed proof digests (never plaintext)
Gates:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-NO-PLAINTEXT-LEAKS

### Coverage enforcement
Controls:
- Extractors must emit CoverageMap v1.
- UNKNOWN coverage quarantines.
Gates:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-COVERAGE-ENFORCED

### Residual verification enforcement
Controls:
- Post-transform re-scan is mandatory before VERIFIED.
- Verification failure quarantines.
Gates:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-VERIFY-RESIDUAL

### Archive safety
Controls:
- Enforce D-0006 limits; quarantine entire archive on violation; prevent path traversal.
Gates:
evidence: spec/11_QUALITY_GATES.md :: G-REL-ARCHIVE-LIMITS

### Key handling (only when enabled)
Controls:
- Tokenization disabled by default.
- Enabling tokenization requires explicit key; key never persisted; key commitment only.
Gates:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-KEY-HANDLING

---

## Security non-guarantees (explicit)
- Veil does not guarantee detection beyond configured detectors and supported formats.
- Veil does not decrypt encrypted/password-protected artifacts (quarantine).
- Veil does not provide formal privacy guarantees for ML training.
- Veil does not eliminate re-identification risk without explicit policy transforms.
