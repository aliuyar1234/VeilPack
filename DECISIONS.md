# DECISIONS.md

## Decision Log
Append-only. Do not renumber existing IDs.

---

## D-0001 — Policy bundle identity and immutability (resolves Q-0001)

### Decision statement
- A **policy bundle** is a directory with a single entrypoint file `policy.json` plus optional adjacent resources (e.g., dictionaries).
- The policy bundle identity is `policy_id = BLAKE3(canonical_bundle_bytes)`, where canonical bundle bytes are produced by:
  - enumerating all files under the policy bundle directory (recursive),
  - normalizing each relative path to forward-slash separators,
  - sorting paths lexicographically,
  - hashing `path_len || path_bytes || file_len || file_bytes` for each file in order.
- `policy_id` MUST be recorded in:
  - Veil Pack manifest
  - evidence run manifest
  - resumability ledger
- Resume MUST be denied if the ledger’s `policy_id` differs from the current policy bundle’s `policy_id`.

### Rationale
- Prevents “policy drift” where a run is resumed or verified under different rules.
- Hashing the entire bundle (not just `policy.json`) ensures auxiliary resources cannot change silently.

### Alternatives considered
- Hash only `policy.json`:
  - rejected: auxiliary resources could drift without changing `policy_id`.
- Allow resume under a changed policy:
  - rejected: would encode a guess into a critical flow.

### Implications (what it affects)
- Policy loader must implement canonical bundle hashing.
- All outputs must bind to `policy_id`.
- Any policy change requires a new run (or explicit operator restart with a new output directory).

### Affected files
- spec/04_INTERFACES_AND_CONTRACTS.md (policy bundle + policy_id contract)
- spec/05_DATASTORE_AND_MIGRATIONS.md (ledger meta policy_id)
- spec/11_QUALITY_GATES.md (immutability gate)

### Verification impact
- Must exist:
  - policy hashing unit tests with fixture bundles
  - resume refusal test on policy_id mismatch
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-POLICY-ID-IMMUTABLE

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (sensitive handling + audit evidence)
- unsafe/high-risk: YES (policy identity touches all downstream artifacts)
- conservative baseline available: YES
- safe to decide: YES (hash-based identity is reversible and verifiable)

### Conservative baseline
- YES (deny resume/verify on mismatch; refuse invalid policy)

### Fail-closed baseline behavior
- If policy bundle hashing fails or policy is unreadable, the run MUST fail before processing any artifact.
- If policy_id mismatch is detected during resume or verify, Veil MUST refuse to proceed.

---

## D-0002 — Coverage contract semantics (resolves Q-0002)

### Decision statement
- Every extractor MUST emit a **CoverageMap v1** for each artifact, describing coverage over these surfaces:
  - `content_text`
  - `structured_fields`
  - `metadata`
  - `embedded_objects`
  - `attachments`
- Each surface MUST have a coverage status:
  - `FULL` (inspected + transformed when findings exist)
  - `NONE` (no such surface exists for the artifact)
  - `UNKNOWN` (surface exists but extractor cannot declare safe coverage)
- VERIFIED requires:
  - `content_text` is FULL (or NONE if truly absent),
  - `structured_fields` is FULL (or NONE),
  - `metadata` is FULL (or NONE),
  - and NO surface is UNKNOWN.
- If any required surface is UNKNOWN, the artifact MUST be QUARANTINED.

### Rationale
- Prevents “verified but partially parsed” outcomes.
- Forces extractors to be explicit about what they did and did not cover.

### Alternatives considered
- Best-effort parsing with partial VERIFIED:
  - rejected: silently unsafe.
- Coverage without surface breakdown:
  - rejected: cannot reason about metadata/embedded leakage separately.

### Implications (what it affects)
- Extractor contract includes coverage map as mandatory output.
- Evidence bundle and ledger must record a coverage hash for each artifact.
- Unsupported substructures (e.g., embedded binaries) force quarantine unless extractor can safely mark them NONE.

### Affected files
- spec/02_ARCHITECTURE.md (extractor contract)
- spec/03_DOMAIN_MODEL.md (CoverageMap definition)
- spec/06_SECURITY_AND_THREAT_MODEL.md (coverage enforcement)
- spec/11_QUALITY_GATES.md (coverage gate)

### Verification impact
- Must exist:
  - extractor tests asserting correct coverage maps for supported formats
  - end-to-end tests that UNKNOWN coverage leads to quarantine
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-COVERAGE-ENFORCED

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (VERIFIED semantics)
- unsafe/high-risk: YES (directly defines safety boundaries)
- conservative baseline available: YES (UNKNOWN → quarantine)
- safe to decide: YES (strict coverage is reversible via policy later)

### Conservative baseline
- YES (UNKNOWN coverage quarantines)

### Fail-closed baseline behavior
- If an extractor cannot produce a CoverageMap v1, the artifact MUST be QUARANTINED.
- No “best effort” coverage is permitted in VERIFIED.

---

## D-0003 — Determinism definition (resolves Q-0003)

### Decision statement
A run is deterministic if identical inputs, policy bundle, and tool version produce identical:
- sanitized output bytes for VERIFIED artifacts
- evidence bundle content (excluding optional operator-only free-form notes)

Determinism requirements:
- Artifact enumeration order MUST be stable:
  - sort by `artifact_id` (BLAKE3 of original bytes); ties broken by `source_locator_hash`.
- Archive entry processing order MUST be stable:
  - sort entries by normalized entry path.
- Structured rewrites MUST use canonical serialization rules:
  - JSON/NDJSON: UTF-8, sorted object keys recursively, no insignificant whitespace.
  - CSV/TSV: canonical quoting rules, LF line endings, stable column ordering if headers exist; otherwise preserve input column order as parsed.
- Evidence MUST NOT include volatile timestamps.
- `run_id` MUST be deterministic: `run_id = BLAKE3(tool_version || policy_id || input_corpus_id)` where `input_corpus_id` is the BLAKE3 hash of the sorted list of artifact_ids.

### Rationale
- Enables auditability, stable approvals, and reproducible verification across sessions.
- Prevents drift caused by filesystem ordering or nondeterministic serialization.

### Alternatives considered
- Random run_id:
  - rejected: breaks deterministic evidence outputs unless excluded everywhere.
- Preserve original formatting for structured outputs:
  - rejected: increases complexity and nondeterminism; canonicalization is safer.

### Implications (what it affects)
- Ingest stage must compute artifact_id and enforce stable ordering.
- Rewriters must implement canonical serialization.
- Evidence generator must avoid embedding wall-clock time.

### Affected files
- spec/04_INTERFACES_AND_CONTRACTS.md (manifest fields)
- spec/08_OBSERVABILITY.md (no timestamps)
- spec/11_QUALITY_GATES.md (determinism gate)

### Verification impact
- Must exist:
  - determinism integration test: run the same corpus twice and assert identical output hashes
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-REL-DETERMINISM

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (public outputs + evidence)
- unsafe/high-risk: YES (output stability is a contract)
- conservative baseline available: YES (canonicalization + strict ordering)
- safe to decide: YES (rules are explicit and testable)

### Conservative baseline
- YES (canonical ordering + canonical serialization)

### Fail-closed baseline behavior
- If canonical serialization fails for a structured format, the artifact MUST be QUARANTINED.
- If deterministic ordering cannot be established (e.g., missing artifact_id), the run MUST fail before emitting outputs.

---

## D-0004 — Deterministic tokenization scope and key rules (resolves Q-0004)

### Decision statement
- Deterministic tokenization is **disabled by default**.
- If enabled, Veil MUST require an explicit tokenization scope:
  - default scope: `PER_RUN` (tokens stable within one run only)
- Tokenization and keyed proof digests share a single **secret key input**, but use domain separation labels:
  - `veil.token.v1`
  - `veil.proof.v1`
- If tokenization is enabled and no secret key is provided, Veil MUST refuse to start (fail closed).
- Veil MUST NOT persist the secret key in the Veil Pack.

### Rationale
- Prevents unintended cross-dataset linkage and correlation risk.
- Keeps baseline behavior safe and simple (redact/mask/drop) unless explicitly enabled.

### Alternatives considered
- Enable tokenization by default:
  - rejected: creates hidden linkage risk.
- Persist key in the pack for convenience:
  - rejected: increases secret leakage blast radius.

### Implications (what it affects)
- CLI/config must include explicit enablement for tokenization and key provision.
- Evidence must record:
  - whether tokenization was enabled
  - the tokenization scope
  - key commitment (hash) but never the key

### Affected files
- spec/04_INTERFACES_AND_CONTRACTS.md (CLI flags and manifest fields)
- spec/06_SECURITY_AND_THREAT_MODEL.md (key controls)
- spec/11_QUALITY_GATES.md (key handling gate)

### Verification impact
- Must exist:
  - tests that confirm tokenization cannot run without explicit enablement and key
  - tests ensuring keys are absent from evidence and logs
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-KEY-HANDLING

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (data transformation semantics)
- unsafe/high-risk: YES (linkage risk)
- conservative baseline available: YES (disable by default + explicit enablement)
- safe to decide: YES (reversible by config/policy)

### Conservative baseline
- YES (tokenization disabled unless explicitly enabled)

### Fail-closed baseline behavior
- If tokenization is requested without a key, Veil MUST fail to start.
- If key handling invariants are violated, Veil MUST fail before emitting outputs.

---

## D-0005 — Quarantine content handling (resolves Q-0005)

### Decision statement
- Default quarantine behavior MUST NOT copy raw quarantined artifacts into the output Veil Pack.
- The Veil Pack MUST include a **quarantine index** describing quarantined artifacts using only non-sensitive identifiers:
  - `artifact_id`
  - `source_locator_hash`
  - `reason_code`
- Optional raw quarantine copying is allowed ONLY when explicitly enabled via configuration.
  - If enabled, Veil MUST copy into a dedicated `quarantine/raw/` directory and MUST record that raw copying was enabled in the pack manifest.

### Rationale
- Avoids unintended duplication/retention of raw sensitive data.
- Still provides actionable remediation via reason codes and stable IDs.

### Alternatives considered
- Always copy quarantined raw data:
  - rejected: creates new retention surface by default.
- Never allow raw quarantine copies:
  - rejected: some operators may need them for controlled remediation workflows.

### Implications (what it affects)
- Output layout includes quarantine index always; raw quarantine directory only when enabled.
- Evidence must disclose whether raw quarantine copying was enabled.

### Affected files
- spec/04_INTERFACES_AND_CONTRACTS.md (pack layout + quarantine)
- spec/08_OBSERVABILITY.md (non-sensitive summaries)
- spec/11_QUALITY_GATES.md (quarantine default gate)

### Verification impact
- Must exist:
  - tests ensuring default run produces no raw quarantined copies
  - tests ensuring enabling raw quarantine copying creates files only under the quarantine directory
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-QUARANTINE-NO-RAW-DEFAULT

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (sensitive data retention)
- unsafe/high-risk: YES (blast radius if wrong)
- conservative baseline available: YES (no copy by default)
- safe to decide: YES (explicit opt-in is reversible)

### Conservative baseline
- YES (no raw quarantine copies by default)

### Fail-closed baseline behavior
- If raw quarantine copying is enabled but the quarantine destination cannot be created safely, Veil MUST fail before processing.

---

## D-0006 — Archive extraction safety limits (resolves Q-0006)

### Decision statement
Veil MUST enforce strict archive safety limits with conservative defaults (configurable):
- maximum nested archive depth: 3
- maximum total entries per archive: 100000
- maximum expansion ratio (expanded_bytes / compressed_bytes): 25
- maximum expanded bytes per archive: 50 GiB
- disallow:
  - absolute paths
  - path traversal segments (`..`)
  - symlinks and hardlinks
If any limit is exceeded or a forbidden condition is detected, the archive artifact MUST be QUARANTINED with reason code `LIMIT_EXCEEDED` or `UNSAFE_PATH`.

### Rationale
- Prevents archive bombs, path traversal, and denial-of-service conditions.
- Conservative defaults favor safety; operators can loosen via explicit config if needed.

### Alternatives considered
- Extract as much as possible and quarantine only offending entries:
  - rejected: partial emission creates complex safety edge cases.
- No archive support:
  - rejected: archives are common in enterprise corpora.

### Implications (what it affects)
- Archive extractor must track bytes and depth and enforce limits before emitting any sanitized outputs from the archive.
- Quarantine reasons must be stable and evidence-safe.

### Affected files
- spec/03_DOMAIN_MODEL.md (reason codes)
- spec/06_SECURITY_AND_THREAT_MODEL.md (archive controls)
- spec/11_QUALITY_GATES.md (archive limits gate)

### Verification impact
- Must exist:
  - archive bomb test fixtures that trigger each limit and assert quarantine
  - path traversal fixtures asserting quarantine
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-REL-ARCHIVE-LIMITS

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (input parsing safety)
- unsafe/high-risk: YES (availability and safety)
- conservative baseline available: YES (strict defaults)
- safe to decide: YES (configurable and verifiable)

### Conservative baseline
- YES (strict defaults; quarantine entire archive on violation)

### Fail-closed baseline behavior
- On any limit violation, quarantine the entire archive artifact; do not emit partial sanitized children.

---

## D-0007 — Evidence proof format without plaintext (resolves Q-0007)

### Decision statement
- Evidence MUST be safe by construction:
  - never store plaintext sensitive values
  - never store file paths; store `source_locator_hash` instead
- Evidence formats:
  - `evidence/run_manifest.json` (single JSON object)
  - `evidence/artifacts.ndjson` (one record per artifact)
  - `quarantine/index.ndjson` (one record per quarantined artifact)
- Evidence MAY include **proof tokens** for correlation within a run:
  - `proof_token = TRUNC12(HMAC(key, value, domain="veil.proof.v1"))`
- A per-run proof key MUST be generated in memory if no key is provided.
  - The key MUST NOT be persisted.
  - Evidence MUST include only a key commitment `proof_key_commitment = BLAKE3(key)` and a scope marker.

### Rationale
- Enables audit correlation (same value redacted across multiple artifacts) without disclosure.
- Keeps baseline safe even if evidence is shared broadly.

### Alternatives considered
- Store redacted plaintext snippets for debugging:
  - rejected: even partial snippets can leak.
- Store stable digests without a key:
  - rejected: creates cross-run linkage risk; keyed digests are safer.

### Implications (what it affects)
- Evidence builder must implement keyed digest emission with domain separation.
- Policy and config must clearly indicate when proof tokens are emitted.

### Affected files
- spec/04_INTERFACES_AND_CONTRACTS.md (evidence layout)
- spec/08_OBSERVABILITY.md (log/evidence rules)
- spec/11_QUALITY_GATES.md (no-plaintext gate)

### Verification impact
- Must exist:
  - tests that inject canary secrets and assert they never appear in evidence/logs
  - tests that evidence records contain only digests and class markers
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-NO-PLAINTEXT-LEAKS

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (evidence safety)
- unsafe/high-risk: YES (evidence is commonly shared)
- conservative baseline available: YES (digests only; no plaintext)
- safe to decide: YES (format and tests enforce)

### Conservative baseline
- YES (digests only; no plaintext)

### Fail-closed baseline behavior
- If evidence writer cannot guarantee non-plaintext emission (e.g., serialization error), the run MUST fail before finalizing the Veil Pack.

---

## D-0008 — Residual verification strategy (resolves Q-0008)

### Decision statement
- VERIFIED requires a post-transform verification pass:
  1) scan input artifact → findings
  2) transform/rewrite output artifact
  3) re-scan the output artifact with the same detector set
- If any High-severity finding remains after transform, the artifact MUST be QUARANTINED with reason `VERIFICATION_FAILED`.
- `veil verify` MUST:
  - load policy bundle
  - re-scan all VERIFIED outputs in a Veil Pack
  - fail the verification command if any residual findings are detected

### Rationale
- “Trust but verify” is mandatory to avoid false safety.
- Ensures VERIFIED has enforceable meaning.

### Alternatives considered
- Single-pass detection without re-scan:
  - rejected: transforms can miss; VERIFIED would be unenforceable.
- Verify only a sample:
  - rejected: creates silent leakage risk.

### Implications (what it affects)
- Pipeline requires a second-pass scan stage.
- Veil Pack must include sufficient metadata to link outputs to policy_id and detector versions.

### Affected files
- spec/03_DOMAIN_MODEL.md (VERIFIED definition)
- spec/04_INTERFACES_AND_CONTRACTS.md (verify command contract)
- spec/11_QUALITY_GATES.md (residual verification gate)

### Verification impact
- Must exist:
  - integration tests where transforms intentionally miss a case and verification catches it
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-VERIFY-RESIDUAL

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (VERIFIED correctness)
- unsafe/high-risk: YES (data safety)
- conservative baseline available: YES (fail closed on residual)
- safe to decide: YES (fully testable)

### Conservative baseline
- YES (verify and quarantine on residuals)

### Fail-closed baseline behavior
- If output cannot be re-parsed for verification, the artifact MUST be QUARANTINED.

---

## D-0009 — Layer-aligned Rust workspace and boundary fitness enforcement

### Decision statement
- The Veil implementation is organized as a single Rust workspace with one crate per C-101 layer:
  - `veil-domain`
  - `veil-policy`
  - `veil-extract`
  - `veil-detect`
  - `veil-transform`
  - `veil-verify`
  - `veil-evidence`
  - `veil-cli` (binary name: `veil`)
- Dependency direction is enforced by an automated boundary fitness check:
  - `python checks/boundary_fitness.py`
  - and a `cargo test` integration test that runs the script.

### Rationale
- Makes the layering rules concrete and enforceable from day one.
- Prevents cross-layer coupling drift that would weaken testability and safety review.

### Alternatives considered
- Single crate with modules:
  - rejected: boundaries are easier to violate and harder to test automatically.
- Layering via conventions only:
  - rejected: does not fail fast on architecture erosion.

### Implications (what it affects)
- All new functionality must land in the correct layer crate, with dependencies only downward.
- Boundary fitness failures block progress until resolved.

### Affected files
- Cargo.toml (workspace members)
- crates/* (layer crates)
- checks/boundary_fitness.py (automated check)
- checks/CHECKS_INDEX.md (CHK-BOUNDARY-FITNESS procedure)
- spec/02_ARCHITECTURE.md (layer mapping)
- spec/11_QUALITY_GATES.md (boundary gate verification procedure)

### Verification impact
- Must exist:
  - automated boundary fitness check and a test that executes it
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-MAINT-BOUNDARY-FITNESS
evidence: checks/CHECKS_INDEX.md :: CHK-BOUNDARY-FITNESS

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (architecture boundaries constrain critical flows)
- unsafe/high-risk: YES (boundary drift increases safety and maintenance risk)
- conservative baseline available: YES (enforce strict layering early)
- safe to decide: YES (fully testable and reversible only via explicit refactor decision)

### Conservative baseline
- YES (one crate per layer + automated boundary gate)

### Fail-closed baseline behavior
- On any boundary check failure, merges and progress claims MUST be blocked until fixed.

---

## D-0010 — MANIFEST.sha256 scope and exclusions

### Decision statement
- `MANIFEST.sha256` is regenerated from the repository filesystem and covers all canonical source files needed to build, test, and review Veil offline.
- `MANIFEST.sha256` MUST exclude ephemeral build and cache outputs to remain deterministic, including at minimum:
  - `target/`
  - `.git/`
  - `__pycache__/`
  - `MANIFEST.sha256` itself
- The canonical regeneration procedure is:
  - `python checks/generate_manifest.py`

### Rationale
- Prevents drift while keeping the manifest stable across machines and builds.
- Avoids accidental inclusion of volatile artifacts that would make integrity checks noisy or unusable.

### Alternatives considered
- Include build outputs:
  - rejected: non-deterministic and changes on every build.
- Keep the manifest limited to documentation only:
  - rejected: does not meet the "regenerate after any change" requirement once product code exists.

### Implications (what it affects)
- Contributors must run the manifest generator after any change and re-verify.
- The manifest becomes the integrity backbone for both the SSOT spine and the implementation scaffold.

### Affected files
- MANIFEST.sha256 (generated)
- checks/generate_manifest.py (generator)
- checks/CHECKS_INDEX.md (regeneration procedure)

### Verification impact
- Must exist:
  - deterministic manifest generator
  - manifest verification check
- Gates/checks:
evidence: checks/CHECKS_INDEX.md :: CHK-MANIFEST-VERIFY

### DSC classification summary
- externally constrained: NO
- critical flow impacted: NO
- unsafe/high-risk: NO
- conservative baseline available: YES (exclude volatile outputs)
- safe to decide: YES (fully testable)

### Conservative baseline
- YES (exclude build artifacts and verify via CHK-MANIFEST-VERIFY)

### Fail-closed baseline behavior
- If the manifest cannot be regenerated or does not verify, the session MUST be treated as BLOCKED for acceptance.

---

## D-0011 — Canonical length encoding for policy bundle hashing (extends D-0001)

### Decision statement
For D-0001 canonical policy bundle hashing:
- `path_len` is encoded as a 4-byte unsigned little-endian integer (`u32`, bytes of UTF-8 path).
- `file_len` is encoded as an 8-byte unsigned little-endian integer (`u64`, bytes of file content).
- `path_bytes` are the normalized relative path bytes:
  - UTF-8
  - forward-slash (`/`) separators
  - no leading `./`

### Rationale
- Removes ambiguity in D-0001 so independent implementations produce identical `policy_id`.
- Keeps the canonical byte stream compact and unambiguous.

### Alternatives considered
- Text encoding lengths (ASCII decimal):
  - rejected: slower and ambiguous without separators.
- Big-endian:
  - rejected: no benefit; little-endian is conventional in Rust and stable.

### Implications (what it affects)
- Any policy bundle hashing implementation must follow this encoding exactly.

### Affected files
- crates/veil-policy/src/bundle_id.rs
- DECISIONS.md (this decision clarifies D-0001)

### Verification impact
- Must exist:
  - unit/integration tests for policy bundle hashing determinism
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-POLICY-ID-IMMUTABLE

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (policy identity is bound to all outputs)
- unsafe/high-risk: YES (drift undermines auditability and resume/verify safety)
- conservative baseline available: YES (strict, explicit encoding)
- safe to decide: YES (fully testable)

### Conservative baseline
- YES (explicit binary length encoding; strict UTF-8 paths)

### Fail-closed baseline behavior
- If any path cannot be normalized to UTF-8, policy hashing MUST fail and the run MUST refuse to start.

---

## D-0012 — `--limits-json` schema v1 (archive limits overrides)

### Decision statement
The `--limits-json` file is a UTF-8 JSON object with:
- required: `schema_version` (string) which MUST equal `limits.v1`
- optional: `archive` object with optional numeric overrides:
  - `max_nested_archive_depth` (u32)
  - `max_entries_per_archive` (u32)
  - `max_expansion_ratio` (u32, MUST be >= 1)
  - `max_expanded_bytes_per_archive` (u64, MUST be >= 1)

Unknown fields at any level MUST be rejected (fail closed).

### Rationale
- Provides a strict, versioned, offline configuration surface for safety limits.
- Deny-unknown-fields prevents silent misconfiguration in critical flows.

### Alternatives considered
- Unversioned ad-hoc JSON:
  - rejected: invites drift and ambiguity.
- Allow unknown fields:
  - rejected: makes typos silently unsafe.

### Implications (what it affects)
- `veil run` must refuse to start if the file is not valid UTF-8 JSON, has an unknown schema_version, or contains unknown keys.

### Affected files
- crates/veil-cli/src/main.rs
- spec/04_INTERFACES_AND_CONTRACTS.md (CLI contract)

### Verification impact
- Must exist:
  - CLI tests for schema_version and unknown fields rejection
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-REL-ARCHIVE-LIMITS

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (resource limits + archive safety)
- unsafe/high-risk: YES (misconfiguration can weaken bounds)
- conservative baseline available: YES (strict schema + deny unknown)
- safe to decide: YES (fully testable)

### Conservative baseline
- YES (schema_version required; unknown keys rejected)

### Fail-closed baseline behavior
- If limits parsing or validation fails, the run MUST exit with invalid-arguments semantics (spec/04).
