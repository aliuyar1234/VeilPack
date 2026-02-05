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
- Evidence MAY include **proof tokens** for correlation within a run (digest-only; never plaintext).
- Concrete proof token derivation + key binding:
evidence: DECISIONS.md :: ## D-0016 — Proof token emission binding (v1)
- The proof key MUST NOT be persisted.
- Evidence MUST include only a key commitment `proof_key_commitment = BLAKE3(proof_key)` and a scope marker `proof_scope`.

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

## D-0012 — `--limits-json` schema v1 (archive + artifact limits overrides)

### Decision statement
The `--limits-json` file is a UTF-8 JSON object with:
- required: `schema_version` (string) which MUST equal `limits.v1`
- optional: `archive` object with optional numeric overrides:
  - `max_nested_archive_depth` (u32)
  - `max_entries_per_archive` (u32)
  - `max_expansion_ratio` (u32, MUST be >= 1)
  - `max_expanded_bytes_per_archive` (u64, MUST be >= 1)
- optional: `artifact` object with optional numeric overrides:
  - `max_bytes_per_artifact` (u64, MUST be >= 1)

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
- Limits parsing now covers both archive-level and per-artifact bounds.

### Affected files
- crates/veil-cli/src/main.rs
- spec/04_INTERFACES_AND_CONTRACTS.md (CLI contract)

### Verification impact
- Must exist:
  - CLI tests for schema_version and unknown fields rejection
  - CLI test for `max_bytes_per_artifact` over-limit quarantine behavior
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

---

## D-0013 — Veil Pack schema version literal `pack.v1`

### Decision statement
- Veil Pack layout v1 is identified by `pack_schema_version = "pack.v1"` in `pack_manifest.json`.
- Tools MUST refuse to operate on Veil Packs with an unknown `pack_schema_version` (fail closed).

### Rationale
- Makes the Veil Pack a versioned public contract independent of tool version.
- Enables compatibility gating and safe evolution of layout and evidence schemas.

### Alternatives considered
- No schema version:
  - rejected: ambiguous upgrades and compatibility behavior.
- Use tool version as pack version:
  - rejected: tool version may change without a schema change; packs should remain readable across patch releases.

### Implications (what it affects)
- `veil run` writes `pack_schema_version: "pack.v1"` for v1 packs.
- `veil verify` MUST check `pack_schema_version` and fail closed on unknown values.

### Affected files
- spec/04_INTERFACES_AND_CONTRACTS.md (Veil Pack Layout v1)
- crates/veil-cli/src/main.rs

### Verification impact
- Must exist:
  - contract tests asserting `pack_manifest.json` contains `pack_schema_version` and required fields
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-COMP-PACK-COMPAT
evidence: spec/11_QUALITY_GATES.md :: G-COMP-CONTRACT-CONSISTENCY

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (public artifact contract + downstream sharing)
- unsafe/high-risk: YES (schema drift can cause unsafe reads/writes)
- conservative baseline available: YES (explicit v1 literal + refuse unknown)
- safe to decide: YES (fully testable)

### Conservative baseline
- YES (`pack.v1` + refuse unknown pack_schema_version)

### Fail-closed baseline behavior
- If `pack_schema_version` is missing or unknown, Veil MUST refuse to verify the pack.

---

## D-0014 — Sanitized output path mapping + atomic commit staging (v1 baseline)

### Decision statement
- Sanitized outputs MUST be written under `<pack_root>/sanitized/` using **hash-derived, collision-safe** file names:
  - `sanitized/<source_locator_hash>__<artifact_id>.<ext>`
  - where:
    - `artifact_id = BLAKE3(original bytes)` (spec/10 T-0101)
    - `source_locator_hash = BLAKE3(normalized relative path)` (spec/10 T-0101)
    - `<ext>` is derived from the artifact type:
      - TEXT → `txt`
      - CSV → `csv`
      - TSV → `tsv`
      - JSON → `json`
      - NDJSON → `ndjson`
- Plaintext input paths MUST NOT be used in sanitized output path mapping for v1 baseline.
- Outputs MUST be committed atomically:
  - write to `<workdir>/staging/` first
  - `fsync` the staged file
  - `rename` into `sanitized/` as the final step for that artifact

### Rationale
- Prevents accidental disclosure of sensitive or identifying metadata embedded in file names/paths.
- Guarantees crash safety: partial writes never appear in `sanitized/`.
- Keeps mapping deterministic and audit-friendly by using stable IDs already present in evidence/ledger.

### Alternatives considered
- Preserve original relative paths under `sanitized/`:
  - rejected for v1 baseline: paths can contain sensitive identifiers and are often shared alongside packs.
- Name outputs by `artifact_id` only:
  - rejected: identical bytes in different source locations would collide.

### Implications (what it affects)
- `veil run` uses only digests to name sanitized outputs; operators correlate using `artifacts.ndjson` (artifact_id + source_locator_hash).
- Output mapping becomes part of the v1 pack compatibility surface.

### Affected files
- spec/02_ARCHITECTURE.md (pipeline emission and staging)
- spec/04_INTERFACES_AND_CONTRACTS.md (sanitized output mapping)
- spec/11_QUALITY_GATES.md (atomic commit + determinism evidence)
- crates/veil-cli/src/main.rs

### Verification impact
- Must exist:
  - deterministic output mapping tests
  - atomic commit tests ensuring no partial files appear in `sanitized/` on failure
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-REL-DETERMINISM
evidence: spec/11_QUALITY_GATES.md :: G-REL-ATOMIC-COMMIT

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (output emission + metadata leakage)
- unsafe/high-risk: YES (pack is a sharing unit)
- conservative baseline available: YES (hash-derived naming)
- safe to decide: YES (fully testable and reversible in future versions)

### Conservative baseline
- YES (hash-derived names + atomic rename)

### Fail-closed baseline behavior
- If staging or atomic rename cannot be performed, the artifact MUST be QUARANTINED (or the run MUST fail if safety cannot be preserved).

---

## D-0015 — Policy JSON schema v1 concrete shape (v1 baseline support)

### Decision statement
- `policy.json` MUST be strict JSON (UTF-8) with unknown fields rejected.
- V1 baseline implements the following concrete shapes:
  - Detectors are objects tagged by `kind`:
    - `{"kind":"regex","pattern":"...","case_insensitive":false,"dot_matches_new_line":false}`
    - `{"kind":"checksum","algorithm":"luhn"}`
    - `{"kind":"field_selector","selector":"json_pointer"|"csv_header","fields":["/ptr"|"header", ...]}`
  - Actions are objects tagged by `kind`:
    - `{"kind":"REDACT"}`
    - `{"kind":"MASK","keep_last":N}` with `N >= 1`
    - `{"kind":"DROP"}`
- V1 baseline support limits:
  - `scopes` MUST exist and MUST be empty (`[]`) in v1 baseline.
  - `TOKENIZE` is reserved but NOT supported in v1 baseline; policies using it MUST be rejected (fail closed).
- Regex compilation MUST be bounded (size/dfa limits) and invalid patterns MUST be rejected.

### Rationale
- Makes the policy contract explicit and machine-checkable.
- Keeps baseline safe and small: scopes and tokenization introduce additional critical-flow complexity and key-handling requirements.

### Alternatives considered
- Lenient/implicit policy parsing (unknown fields ignored, missing defaults inferred):
  - rejected: silent drift and unsafe misconfiguration.
- Accept non-empty scopes but ignore them:
  - rejected: would violate operator intent and could transform outside intended scope.
- Allow TOKENIZE without implementing key handling:
  - rejected: would create false security assumptions.

### Implications (what it affects)
- `veil run` MUST refuse to start on invalid policy bundles (exit code 3).
- Field selectors apply only where meaningful; unsupported combinations are treated conservatively.

### Affected files
- spec/04_INTERFACES_AND_CONTRACTS.md (Policy Bundle Schema v1)
- crates/veil-policy/src/lib.rs
- crates/veil-cli/src/main.rs

### Verification impact
- Must exist:
  - integration coverage: invalid policy causes exit code 3; valid policy drives the pipeline
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-COMP-CONTRACT-CONSISTENCY

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (policy binding drives transformation + verification)
- unsafe/high-risk: YES (misparsed policy can leak data)
- conservative baseline available: YES (strict schema + reject unsupported features)
- safe to decide: YES (explicit contract + tests)

### Conservative baseline
- YES (strict schema; no scopes; no tokenization)

### Fail-closed baseline behavior
- If policy parsing/compilation fails, Veil MUST refuse to run (exit code 3) and MUST NOT process any artifact.

---

## D-0016 — Proof token emission binding (v1)

### Decision statement
- Veil MAY emit per-match **proof tokens** to support within-run correlation without plaintext.
- Proof tokens are emitted as `proof_tokens` in `evidence/artifacts.ndjson` records (array of digest strings).
- Proof token derivation (conceptual):
  - `proof_token = TRUNC12(PRF(proof_key, domain="veil.proof.v1" || value_bytes))`
- Proof key handling:
  - If a `--secret-key-file` is provided (tokenization enabled), Veil MUST derive a per-run proof key from that secret key and `run_id` using domain separation `veil.proof.key.v1`.
  - Otherwise Veil MUST derive a per-run proof key from a corpus-derived secret (hash of input paths+bytes) and `run_id` using the same domain separation.
- Evidence MUST include, in `evidence/run_manifest.json`:
  - `proof_scope` (v1: `PER_RUN`)
  - `proof_key_commitment = BLAKE3(proof_key)` (never the key)

### Rationale
- Enables audit correlation (same value redacted across multiple artifacts) without disclosure.
- Preserves determinism (D-0003): proof keys and proof tokens are deterministic functions of run inputs/config.
- Avoids requiring operators to manage an external secret key when tokenization is disabled.

### Alternatives considered
- Random per-run proof key without persistence:
  - rejected: breaks determinism (D-0003).
- Unkeyed digests:
  - rejected: enables trivial dictionary attacks over common formats.
- Persist proof key in the pack:
  - rejected: violates key handling invariant (D-0004).

### Implications (what it affects)
- `evidence/run_manifest.json` includes proof metadata fields (`proof_scope`, `proof_key_commitment`).
- `evidence/artifacts.ndjson` records MAY include `proof_tokens` for artifacts with findings.
- `veil verify` ignores proof tokens and does not require any key.

### Affected files
- spec/04_INTERFACES_AND_CONTRACTS.md (evidence and manifest notes)
- spec/11_QUALITY_GATES.md (key handling gate coverage)
- crates/veil-cli/src/main.rs
- crates/veil-detect/src/lib.rs

### Verification impact
- Must exist:
  - tests that prove `proof_tokens` are digest strings (no plaintext) and are emitted when matches occur
  - determinism test still passes with proof fields present
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-NO-PLAINTEXT-LEAKS
evidence: spec/11_QUALITY_GATES.md :: G-REL-DETERMINISM

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (evidence + key handling)
- unsafe/high-risk: MEDIUM (linkage via proof tokens is scoped per-run; no plaintext)
- conservative baseline available: YES (keyed digests; per-run scope)
- safe to decide: YES (fully testable; proof tokens are optional evidence metadata)

### Conservative baseline
- YES (PER_RUN scope; keyed digests; no plaintext)

### Fail-closed baseline behavior
- If proof token computation fails, Veil MUST continue without emitting proof tokens rather than emitting plaintext.

---

## D-0017 — Container format canonicalization to NDJSON (v1)

### Decision statement
- Veil v1 baseline supports these additional container artifact types:
  - ZIP (`.zip`)
  - TAR (`.tar`)
  - Email: EML (`.eml`), MBOX (`.mbox`)
  - Office Open XML: DOCX (`.docx`), PPTX (`.pptx`), XLSX (`.xlsx`)
- These container formats MUST be canonicalized to NDJSON for scanning and transformation:
  - sanitized output ext is `ndjson` per D-0014
  - each line is a JSON object; ordering is deterministic
- Internal locators inside container formats MUST NOT be emitted as plaintext in the canonical output.
  - Archive entry paths → `entry_path_hash` (+ optional `container_path_hash` for nested containers)
  - Email attachment locators → `attachment_locator_hash` (+ optional `filename_hash`)
  - OOXML part paths → `part_path_hash`
- Archive safety limits (D-0006) apply to ZIP/TAR and to nested archives encountered inside other containers.
- Email attachment baseline (fail-closed):
  - supported: ZIP/TAR attachments and `text/*` attachments
  - all other attachment types MUST quarantine the email artifact as `UNSUPPORTED_FORMAT`
- OOXML embedded objects baseline (fail-closed):
  - if an OOXML package contains non-XML parts (other than `.rels`), the extractor MUST mark `embedded_objects` coverage as UNKNOWN (D-0002), which results in quarantine under strict baseline.

### Rationale
- Container formats carry many subdocuments and metadata surfaces; NDJSON provides a uniform canonical stream for detectors/transforms.
- Hashing internal locators prevents accidental leakage of identifiers embedded in filenames/paths/attachment names.
- Strict baselines for attachments and embedded objects prevent verified-but-partially-parsed outcomes.

### Alternatives considered
- Preserve internal filenames/paths in the canonical output:
  - rejected: high risk of metadata leakage into sanitized outputs.
- Best-effort decode of arbitrary binary attachments:
  - rejected: unsafe; encourages false confidence; should quarantine unless explicitly supported.
- Fully parse OOXML embedded objects:
  - rejected for v1 baseline: expands attack surface; requires additional parsers and coverage semantics.

### Implications (what it affects)
- Supported file types and their sanitized output ext mapping become part of the v1 contract surface.
- Phase 4 gates must include negative-path tests for:
  - archive limits and unsafe paths
  - unsupported email attachments
  - OOXML unknown embedded parts

### Affected files
- spec/02_ARCHITECTURE.md (supported format handlers)
- spec/04_INTERFACES_AND_CONTRACTS.md (supported input formats)
- spec/06_SECURITY_AND_THREAT_MODEL.md (format-specific notes)
- spec/11_QUALITY_GATES.md (gate verification pointers)
- crates/veil-extract/src/lib.rs
- crates/veil-cli/src/main.rs

### Verification impact
- Must exist:
  - integration tests covering archive limits and unsafe paths
  - integration tests covering email attachments (supported vs unsupported)
  - integration tests covering OOXML embedded binaries → UNKNOWN coverage → quarantine
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-REL-ARCHIVE-LIMITS
evidence: spec/11_QUALITY_GATES.md :: G-SEC-COVERAGE-ENFORCED

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (format parsing + output contract)
- unsafe/high-risk: YES (untrusted containers + new leakage surfaces)
- conservative baseline available: YES (hash internal locators; quarantine unsupported/unknown)
- safe to decide: YES (testable via deterministic fixtures)

### Conservative baseline
- YES (fail-closed on unsupported attachments, unsafe archive paths, unknown embedded objects)

### Fail-closed baseline behavior
- On any container parse error, limit violation, unsafe path, or unsupported substructure, the artifact MUST be QUARANTINED.

---

## D-0018 — Hardening baseline: per-artifact memory bounds, identity revalidation, and unsafe output-path refusal

### Decision statement
- Extend `limits.v1` with an optional artifact section:
  - `artifact.max_bytes_per_artifact` (u64, must be >= 1 when present).
- Introduce a default per-artifact in-memory bound:
  - `max_bytes_per_artifact = 268435456` (256 MiB) when not overridden.
- Runtime MUST enforce per-artifact bounds fail-closed:
  - top-level artifact reads in CLI are bounded.
  - extractor reads for OOXML parts, ZIP/TAR entries, and email attachment payloads are bounded.
  - bound violations MUST quarantine with `LIMIT_EXCEEDED`.
- Runtime MUST revalidate discovered artifact identity at processing time:
  - processed bytes and size must match discovered `artifact_id` and discovered size.
  - mismatches quarantine with `INTERNAL_ERROR` (fail-closed baseline without introducing a new reason code in v1).
- CLI MUST refuse unsafe output/workdir locations:
  - reject symlink/reparse components in output/workdir path traversal.
  - refuse writes when output targets resolve through unsafe components.
- Offline runtime gate baseline is hardened:
  - runtime offline test monitors the process for socket activity while `veil run` executes under denied-network posture.
- CI supply-chain baseline is hardened:
  - pin GitHub Actions to immutable commit SHAs and use least-privilege workflow permissions.

### Rationale
- Enforces the SSOT requirement for maximum per-artifact resource bounds (C-005, spec/07).
- Closes identity TOCTOU gap between discovery hashing and processing reads.
- Reduces write-what-where exposure from symlink/reparse path indirection in output/workdir.
- Makes offline runtime verification materially stronger than completion-time smoke checks.
- Improves CI supply-chain integrity without changing product runtime behavior.

### Alternatives considered
- Keep archive-only limits and rely on OS memory pressure behavior:
  - rejected: does not satisfy explicit max per-artifact bound requirement.
- Abort entire run on artifact identity mismatch:
  - rejected for v1 baseline: spec/07 favors per-artifact quarantine for non-fatal artifact-level failures.
- Preserve workflow tags (e.g., `@v4`, `@stable`) in CI:
  - rejected: mutable references weaken supply-chain guarantees.

### Implications (what it affects)
- `--limits-json` contract now includes an artifact-bound field.
- Large single artifacts/entries now fail-closed via quarantine rather than unbounded memory growth.
- Output/workdir path validation is stricter and may reject previously accepted unsafe path indirection.
- Offline gate evidence quality improves by observing runtime socket activity directly.

### Affected files
- spec/02_ARCHITECTURE.md
- spec/04_INTERFACES_AND_CONTRACTS.md
- spec/11_QUALITY_GATES.md
- crates/veil-domain/src/config.rs
- crates/veil-cli/src/main.rs
- crates/veil-cli/tests/limits_json.rs
- crates/veil-cli/tests/offline_enforcement.rs
- crates/veil-cli/tests/cli_smoke.rs
- crates/veil-extract/src/lib.rs
- checks/offline_enforcement.py
- .github/workflows/ci.yml

### Verification impact
- Must exist:
  - tests for per-artifact bound enforcement (`limits_json`).
  - tests for identity mismatch detection.
  - tests for unsafe output/workdir path refusal.
  - offline runtime test with socket-activity monitoring.
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-REL-ARCHIVE-LIMITS
evidence: spec/11_QUALITY_GATES.md :: G-SEC-FAIL-CLOSED-TERMINAL
evidence: spec/11_QUALITY_GATES.md :: G-REL-ATOMIC-COMMIT
evidence: spec/11_QUALITY_GATES.md :: G-SEC-OFFLINE-NO-NET

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (artifact IO, output emission, offline enforcement)
- unsafe/high-risk: YES (memory exhaustion, integrity drift, path indirection)
- conservative baseline available: YES (strict bounds + quarantine/refusal)
- safe to decide: YES (fully testable with local fixtures)

### Conservative baseline
- YES (bounded reads, identity revalidation quarantine, unsafe path refusal, pinned CI actions)

### Fail-closed baseline behavior
- On over-limit artifacts/entries: QUARANTINE (`LIMIT_EXCEEDED`).
- On discovered/processed identity mismatch: QUARANTINE (`INTERNAL_ERROR`).
- On unsafe output/workdir path traversal: refuse to start (usage error) or quarantine on write-path safety failure.

---

## D-0019 — Security audit session log (no behavior change)

### Decision statement
- Record that a security audit of the current codebase was performed and no product behavior changes were made in this session.

### Rationale
- Provides an audit trail for review activity without implying implementation changes.

### Implications (what it affects)
- None.

### Verification impact
- None.

### DSC classification summary
- externally constrained: NO
- critical flow impacted: NO
- unsafe/high-risk: NO
- conservative baseline available: N/A
- safe to decide: YES

---

## D-0020 - Remediation hardening pass: structured logs, resume metadata binding, and path/write safety tightening

### Decision statement
- Enforce structured JSON stderr logging in `veil-cli` runtime paths:
  - log records include `level`, `event`, `run_id`, and `policy_id`.
  - runtime counters are emitted for `run_started`, `run_completed`, `verify_started`, and `verify_completed`.
- Tighten resume metadata consistency:
  - ledger meta now stores and validates `proof_scope`, `proof_key_commitment`, `tokenization_enabled`, and `tokenization_scope`.
  - resume fails usage validation on mismatches; missing keys are seeded for compatibility.
  - resume now fails closed when existing `artifacts.ndjson` proof-token records are unreadable/invalid.
- Tighten filesystem safety:
  - input enumeration rejects symlink/reparse entries via `symlink_metadata`.
  - verify rejects unsafe sanitized output paths (symlink/reparse/non-file) and counts them as verification failures.
  - quarantine index and artifacts evidence writers now validate path component safety before persist.
  - atomic writers additionally reject unsafe temp/target symlink reparse paths before rename.
  - quarantine raw copy failures are now fail-closed (`EXIT_FATAL`) when `--quarantine-copy=true`.
- Harden archive accounting against forged size metadata:
  - ZIP/OOXML/TAR aggregate expanded-byte checks now use observed bytes read, not only header size metadata.
- Clarify `--max-workers` semantics in v1:
  - accepted as advisory input (`>=1`) with explicit warning when `>1`.
  - v1 baseline remains deterministic single-worker.

### Rationale
- Closes SSOT/implementation drift in observability schema requirements (spec/08).
- Prevents silent evidence degradation on resume and strengthens proof-binding continuity.
- Reduces write-redirection exposure from symlink/reparse races in evidence/output paths.
- Improves fail-closed behavior in verification and quarantine-copy persistence.
- Reduces archive-limit bypass risk from untrusted header values.

### Alternatives considered
- Keep plain stderr text logs and rely only on evidence files:
  - rejected: violates structured log contract and weakens operational correlation.
- Continue best-effort resume when proof-token evidence is unreadable:
  - rejected: can silently drop proof-token continuity.
- Introduce multi-threaded processing immediately for `--max-workers`:
  - rejected for this pass due determinism/ledger coupling risk; baseline remains single-worker with explicit advisory semantics.

### Implications (what it affects)
- Runtime stderr format is now structured JSON events.
- Resume contracts include proof/tokenization metadata consistency checks.
- Verification is stricter for unsafe sanitized output path types.
- Evidence writing and atomic persistence paths apply stricter safety checks.
- Archive-limit behavior relies on observed expanded bytes and remains fail-closed.

### Affected files
- spec/02_ARCHITECTURE.md
- spec/04_INTERFACES_AND_CONTRACTS.md
- spec/11_QUALITY_GATES.md
- checks/CHECKS_INDEX.md
- .github/workflows/ci.yml
- crates/veil-cli/src/main.rs
- crates/veil-evidence/src/ledger.rs
- crates/veil-extract/src/lib.rs
- crates/veil-cli/tests/cli_smoke.rs
- crates/veil-cli/tests/limits_json.rs
- crates/veil-cli/tests/phase1_gates.rs
- crates/veil-cli/tests/phase2_gates.rs
- crates/veil-cli/tests/phase4_gates.rs
- crates/veil-cli/tests/phase5_gates.rs

### Verification impact
- Must exist:
  - log-schema integration test for stderr JSON required fields.
  - resume invalid-evidence fail-closed test.
  - unsafe verify path test (symlink sanitized output).
  - TAR limits/symlink tests and nested limits-json unknown/zero-value tests.
  - CI runs offline static/runtime checks, SSOT validation, and manifest verification.
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-SEC-NO-PLAINTEXT-LEAKS
evidence: spec/11_QUALITY_GATES.md :: G-REL-ARCHIVE-LIMITS
evidence: spec/11_QUALITY_GATES.md :: G-REL-ATOMIC-COMMIT
evidence: checks/CHECKS_INDEX.md :: CHK-LOG-SCHEMA
evidence: checks/CHECKS_INDEX.md :: CHK-MANIFEST-VERIFY

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (run/verify/evidence/resume contracts)
- unsafe/high-risk: YES (path safety, evidence integrity, archive limits)
- conservative baseline available: YES (fail closed on ambiguity/failure)
- safe to decide: YES (testable with deterministic integration suites)

### Conservative baseline
- YES (structured logs + strict path safety + fail-closed resume/evidence behavior)

### Fail-closed baseline behavior
- On unsafe output/evidence path state, unreadable prior proof evidence, or raw-copy persist failure with opt-in enabled: abort with `EXIT_FATAL`.
- On unsafe verified output path at `verify` time: count as verification failure and return `EXIT_QUARANTINED` if any failures exist.

---

## D-0021 - Runtime hardening pass: verify completeness checks, usage redaction, and workdir disk bounds

### Decision statement
- Extend `limits.v1` with optional disk bounds:
  - `disk.max_workdir_bytes` (u64, must be `>= 1` when present).
  - default when omitted: `1073741824` (1 GiB).
- `veil run` MUST enforce workdir usage bound fail-closed:
  - preflight measure workdir usage; if already above bound, fail run (`EXIT_FATAL`).
  - before staging sanitized bytes, if projected usage exceeds bound, quarantine artifact with `LIMIT_EXCEEDED`.
- `veil verify` MUST enforce output/evidence consistency fail-closed:
  - refuse unsafe `pack_manifest.json` and `evidence/artifacts.ndjson` paths (symlink/reparse/non-file).
  - enforce `sanitized/` contains only files represented as VERIFIED in `artifacts.ndjson`.
- Resume safety tightening:
  - if `pack_manifest.json` already exists, output is treated as completed and resume is refused.
- Usage/log redaction tightening:
  - unknown flags and unexpected positional arguments are reported as redacted usage errors (no user-provided plaintext echoed).
- Atomic persistence tightening:
  - atomic writers sync temporary file contents before rename and sync parent directory after rename.
  - sanitized commit path adds a cross-filesystem-safe fallback (`rename` failure -> atomic write in destination directory).

### Rationale
- Addresses remaining fail-closed and security gaps in verification completeness, resume semantics, and usage-message leakage.
- Adds explicit temp/workdir disk bounding to satisfy resource-bound requirements in critical flows.
- Improves durability guarantees for evidence/manifests and avoids all-artifact quarantine on cross-filesystem workdir/output layouts.

### Alternatives considered
- Keep verify as evidence-only enumeration without filesystem cross-check:
  - rejected: allows untracked sanitized outputs to evade verification.
- Keep argument-specific usage messages:
  - rejected: can leak operator-provided sensitive values into stderr logs.
- Abort immediately on cross-filesystem rename:
  - rejected: causes unnecessary INTERNAL_ERROR quarantines despite safe atomic write fallback availability.

### Implications (what it affects)
- CLI/public limits schema now includes a disk-bound knob (`limits.v1` extension).
- Verification is stricter and will fail/quarantine packs with unexpected sanitized files or unsafe evidence path topology.
- Resume behavior is stricter for already-finalized outputs.

### Affected files
- spec/02_ARCHITECTURE.md
- spec/04_INTERFACES_AND_CONTRACTS.md
- spec/11_QUALITY_GATES.md
- spec/07_RELIABILITY_AND_OPERATIONS.md
- crates/veil-cli/src/main.rs
- crates/veil-cli/tests/cli_smoke.rs
- crates/veil-cli/tests/contract_consistency.rs
- crates/veil-cli/tests/limits_json.rs
- crates/veil-cli/tests/phase2_gates.rs
- crates/veil-cli/tests/phase3_gates.rs

### Verification impact
- Must exist:
  - limits-json tests for `disk.max_workdir_bytes` validation and fail-closed enforcement.
  - verify tests for unexpected sanitized files and unsafe evidence/manifest paths.
  - resume test refusing marker+ledger when `pack_manifest.json` already exists.
  - usage redaction test for unexpected arguments.
- Gates/checks:
evidence: spec/11_QUALITY_GATES.md :: G-REL-ARCHIVE-LIMITS
evidence: spec/11_QUALITY_GATES.md :: G-COMP-CONTRACT-CONSISTENCY
evidence: spec/11_QUALITY_GATES.md :: G-SEC-NO-PLAINTEXT-LEAKS
evidence: spec/11_QUALITY_GATES.md :: G-REL-ATOMIC-COMMIT

### DSC classification summary
- externally constrained: NO
- critical flow impacted: YES (verify/run/output emission/resume)
- unsafe/high-risk: YES (verification bypass, path safety, resource exhaustion, logging leaks)
- conservative baseline available: YES (strict refusal/quarantine and redacted diagnostics)
- safe to decide: YES (fully testable with local integration suites)

### Conservative baseline
- YES (fail closed on unsafe paths, inconsistent outputs, and workdir bound violations)

### Fail-closed baseline behavior
- Unsafe verify-evidence paths or malformed verified-output topology: verification fails closed.
- Workdir bound violations: per-artifact quarantine (`LIMIT_EXCEEDED`) or run abort if preflight state is already unsafe.
