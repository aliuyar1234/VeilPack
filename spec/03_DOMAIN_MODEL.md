# spec/03_DOMAIN_MODEL.md

## Domain Entities
### Run
- Identifiers:
  - `run_id` (deterministic; see D-0003)
  - `policy_id`
  - `input_corpus_id`
- Output: exactly one Veil Pack per run.

### Artifact
- The unit of processing: a file, archive entry, or message part.
- Identifiers:
  - `artifact_id = BLAKE3(original_bytes)`
  - `source_locator_hash = BLAKE3(normalized_relative_path)`
- Artifact type:
  - classified by ingest and/or extractor (e.g., TEXT, CSV, JSON, ARCHIVE, EMAIL, OFFICE_OOXML)

### PolicyBundle
- A directory containing `policy.json` plus optional resources.
- Identity: `policy_id` (D-0001).

### Finding
- A detection result over an artifact’s canonical representation.
- Fields (conceptual):
  - `class_id`
  - `severity` (HIGH / MEDIUM / LOW)
  - `location` (canonical location descriptor; never raw values)
  - optional `proof_token` (digest; never plaintext)

### CoverageMap v1
- Describes which surfaces were inspected.
- Surfaces and statuses defined in D-0002.

### TransformAction
- Applied per finding class under policy:
  - REDACT (replace with marker)
  - MASK (partial reveal per policy)
  - DROP (remove field/value)
  - TOKENIZE (only when explicitly enabled; D-0004)

### QuarantineReason
- Stable reason codes (non-sensitive):
  - UNSUPPORTED_FORMAT
  - ENCRYPTED
  - PARSE_ERROR
  - LIMIT_EXCEEDED
  - UNSAFE_PATH
  - UNKNOWN_COVERAGE
  - VERIFICATION_FAILED
  - INTERNAL_ERROR

---

## Artifact State Machine (normative)
States:
- DISCOVERED
- EXTRACTED
- TRANSFORMED
- VERIFIED (terminal)
- QUARANTINED (terminal)

Transitions (fail-closed):
- DISCOVERED → EXTRACTED: only if extractor succeeds and emits CoverageMap v1
- EXTRACTED → TRANSFORMED: only if transform plan can be applied deterministically
- TRANSFORMED → VERIFIED: only if residual verification pass succeeds (D-0008)
- Any state → QUARANTINED: on any safety failure or uncertainty

Invariant:
- Every artifact MUST end in exactly one terminal state: VERIFIED or QUARANTINED.
- No other terminal outcomes exist.

---

## VERIFIED and QUARANTINED (normative definitions)

### VERIFIED
An artifact is VERIFIED if and only if ALL are true:
1) Extractor produced CoverageMap v1 with no UNKNOWN surfaces (D-0002).
2) Detectors executed under the configured policy bundle (policy_id bound).
3) Transforms were applied according to policy without emitting plaintext sensitive values.
4) Post-transform residual verification pass detected no remaining HIGH-severity matches (D-0008).
5) Evidence record contains no plaintext sensitive values (C-003).

### QUARANTINED
An artifact is QUARANTINED if ANY are true:
- Unsupported or unsafe format
- Encrypted/password-protected
- Parse error or canonicalization error
- Archive safety limit exceeded or unsafe archive path
- CoverageMap includes UNKNOWN for required surfaces
- Residual verification failed
- Any internal error that would otherwise risk unsafe emission

---

## Veil Pack (conceptual)
A Veil Pack is the standard output unit containing:
- sanitized corpus (VERIFIED artifacts only)
- quarantine index (all QUARANTINED artifacts; raw copies only if explicitly enabled)
- evidence bundle and pack manifest binding outputs to policy_id and run_id

Canonical layout:
evidence: spec/04_INTERFACES_AND_CONTRACTS.md :: Veil Pack Layout v1

---

## Glossary (normative)
Terms MUST be used consistently across code, docs, and evidence.

- Veil Pack: the output package (sanitized + quarantine + evidence).
- Policy bundle: directory with `policy.json` and resources; identity is policy_id.
- CoverageMap: extractor-declared coverage over artifact surfaces.
- VERIFIED: terminal state with verified-safe output.
- QUARANTINED: terminal state withheld due to safety inability.
- Artifact ID: BLAKE3 of original bytes.
- Source locator hash: BLAKE3 of normalized relative path; plaintext paths MUST NOT appear in evidence/logs.
