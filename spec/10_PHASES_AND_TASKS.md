# spec/10_PHASES_AND_TASKS.md

## Roadmap Summary Table

| Phase | Deliverable | Exit gates |
|---|---|---|
| PHASE_0_BOOTSTRAP | Make the repository buildable and runnable with fail-closed CLI scaffolding and enforced module boundaries. | G-MAINT-BOUNDARY-FITNESS, G-SEC-OFFLINE-NO-NET, G-SEC-FAIL-CLOSED-TERMINAL |
| PHASE_1_CORE_PIPELINE | Implement the end-to-end deterministic pipeline for V1 core formats and enforce VERIFIED/QUARANTINED semantics. | G-SEC-FAIL-CLOSED-TERMINAL, G-SEC-VERIFY-RESIDUAL, G-SEC-NO-PLAINTEXT-LEAKS, G-REL-DETERMINISM, G-REL-ATOMIC-COMMIT |
| PHASE_2_POLICY_BUNDLE | Implement strict policy bundle schema, hashing, and compilation into detectors/actions. | G-SEC-POLICY-ID-IMMUTABLE, G-SEC-KEY-HANDLING |
| PHASE_3_EVIDENCE_AND_AUDIT | Emit audit-grade evidence and implement independent verification over Veil Packs. | G-SEC-NO-PLAINTEXT-LEAKS, G-SEC-VERIFY-RESIDUAL, G-COMP-PACK-COMPAT |
| PHASE_4_FORMATS_AND_LIMITS | Expand V1 format coverage while preserving fail-closed coverage contracts and safety limits. | G-REL-ARCHIVE-LIMITS, G-SEC-COVERAGE-ENFORCED |
| PHASE_5_HARDENING | Harden reliability/security and establish performance non-regression discipline for large corpora. | G-PERF-NO-REGRESSION, G-REL-DETERMINISM, G-OPS-RUNBOOK-COMPLETE |
| DONE | All gates pass; Veil Pack production + verification complete | ALL |

## PHASE_0_BOOTSTRAP

**Phase goal**
- Make the repository buildable and runnable with fail-closed CLI scaffolding and enforced module boundaries.

**Entry criteria**
- SSOT pack applied to repo root.
- No code exists yet or code may be partial.

**Exit criteria**
- Workspace builds/tests offline.
- CLI skeleton exists with fail-closed behavior.
- Tooling/CI wired.
- Determinism primitives implemented.

**Exit gates**

- G-MAINT-BOUNDARY-FITNESS (see spec/11)
- G-SEC-OFFLINE-NO-NET (see spec/11)
- G-SEC-FAIL-CLOSED-TERMINAL (see spec/11)

### Tasks

### T-0001 — Repo scaffold + module boundaries (Rust workspace).

**Acceptance criteria**
- `cargo build --workspace` succeeds offline.
- Workspace defines crates/modules that map to the layering rules in CONSTITUTION C-101.
- Boundary fitness check is wired (may be manual initially) and documented in spec/11.

**Required evidence**
evidence: PROGRESS.md :: T-0001

Implementation Notes:
- Create a Cargo workspace with crates aligned to layers (names are suggestions; keep mapping explicit):
  - domain, policy, extract, detect, transform, verify, evidence, cli
- Ensure lower layers have zero dependency on higher layers.
- Add minimal public interfaces between layers (traits / structs) without leaking filesystem concerns into core layers.

### T-0002 — Tooling baseline (format, lint, tests) + CI/acceptance gate wiring.

**Acceptance criteria**
- `cargo fmt --all -- --check` passes.
- `cargo clippy --workspace -- -D warnings` passes.
- `cargo test --workspace` passes.
- CI config runs the above commands in an offline-friendly way.
- Quality gates in spec/11 are mapped to runnable checks (manual or automated).

**Required evidence**
evidence: PROGRESS.md :: T-0002

Implementation Notes:
- Add standard Rust toolchain files if needed (pin to a stable toolchain).
- Add a minimal CI pipeline that runs fmt/clippy/test.
- Do not add network-dependent steps.

### T-0003 — Minimal runnable CLI path (fail-closed stubs).

**Acceptance criteria**
- `veil --help` runs.
- `veil run` validates args and refuses unsafe configs (fail-closed) without processing.
- `veil verify` and `veil policy lint` exist and fail closed with clear non-sensitive errors.
- A smoke test invokes the CLI and asserts exit codes and non-sensitive stderr output.

**Required evidence**
evidence: PROGRESS.md :: T-0003

Implementation Notes:
- Use a single binary entrypoint.
- Implement strict argument validation per spec/04.
- Do not emit any input-derived strings in logs.

### T-0004 — Determinism primitives (hashing + stable ordering) + tests.

**Acceptance criteria**
- BLAKE3 hashing utility exists for artifact_id/policy_id and is unit-tested.
- Stable sorting utility exists for artifact ordering and is unit-tested.
- Determinism definition from D-0003 is encoded as a testable module contract.

**Required evidence**
evidence: PROGRESS.md :: T-0004

Implementation Notes:
- Provide canonical byte hashing helpers and ensure UTF-8 handling is explicit.
- Ensure no wall-clock timestamps are required for run_id or evidence.

### T-0005 — Configuration model + safe defaults (offline enforcement, limits, disabled-by-default risky features).

**Acceptance criteria**
- Default configuration is fail-closed and offline-first.
- Tokenization is disabled unless explicitly enabled and key provided (D-0004).
- Quarantine raw copying is disabled unless explicitly enabled (D-0005).
- Resource limits exist with conservative defaults (D-0006).

**Required evidence**
evidence: PROGRESS.md :: T-0005

Implementation Notes:
- Implement config parsing from flags and optional JSON file.
- Validate config before touching inputs.

### T-0006 — Documentation navigability + reference integrity for project repo docs.

**Acceptance criteria**
- The project repo contains a minimal README that points to the SSOT pack and runbook usage.
- A maintainer can locate scope/architecture/contracts/security/test plan quickly (links or pointers).
- Local run instructions exist in repo (may reference spec/12 content).

**Required evidence**
evidence: PROGRESS.md :: T-0006

Implementation Notes:
- Keep repo docs brief; the SSOT pack is canonical.
- Ensure no contradictions: specs are authoritative.


---

## PHASE_1_CORE_PIPELINE

**Phase goal**
- Implement the end-to-end deterministic pipeline for V1 core formats and enforce VERIFIED/QUARANTINED semantics.

**Entry criteria**
- PHASE_0 complete.
- CLI scaffolding and hashing utilities exist.

**Exit criteria**
- `veil run` produces Veil Pack layout v1.
- Artifacts end VERIFIED or QUARANTINED.
- Residual verification enforced.
- Quarantine reason codes stable.
- No plaintext leaks in logs/evidence (canary tests).

**Exit gates**

- G-SEC-FAIL-CLOSED-TERMINAL (see spec/11)
- G-SEC-VERIFY-RESIDUAL (see spec/11)
- G-SEC-NO-PLAINTEXT-LEAKS (see spec/11)
- G-REL-DETERMINISM (see spec/11)
- G-REL-ATOMIC-COMMIT (see spec/11)

### Tasks

### T-0101 — Corpus enumeration and ingest (deterministic).

**Acceptance criteria**
- Given the same input bytes and directory structure, enumeration order is deterministic.
- Each artifact has:
  - artifact_id = BLAKE3(original bytes)
  - source_locator_hash = BLAKE3(normalized relative path)
- Plaintext paths are not written to evidence/logs.

**Required evidence**
evidence: PROGRESS.md :: T-0101

Implementation Notes:
- Walk filesystem deterministically (sort directory entries).
- Normalize relative paths with forward slashes before hashing.

### T-0102 — Resumability ledger v1 (SQLite) + state transitions.

**Acceptance criteria**
- Ledger schema v1 created at `<pack_root>/evidence/ledger.sqlite3`.
- Artifact transitions recorded atomically.
- Resume continues incomplete artifacts and never reprocesses VERIFIED artifacts unless forced.
- Resume refuses on policy_id mismatch (D-0001).

**Required evidence**
evidence: PROGRESS.md :: T-0102

Implementation Notes:
- Use transactions for state updates.
- Store only non-sensitive identifiers (no plaintext values).

### T-0103 — Extractor framework + CoverageMap v1 contract enforcement.

**Acceptance criteria**
- Extractors return canonical representation + CoverageMap v1 or quarantine.
- UNKNOWN coverage for required surfaces causes quarantine (D-0002).
- Extractor failures never emit partial sanitized outputs.

**Required evidence**
evidence: PROGRESS.md :: T-0103

Implementation Notes:
- Implement a registry keyed by detected artifact type.
- Ensure extractors are pure w.r.t. filesystem writes (they read bytes, emit structures).

### T-0104 — Built-in extractors: TEXT, CSV/TSV, JSON, NDJSON.

**Acceptance criteria**
- Supported formats produce CoverageMap v1 with no UNKNOWN surfaces.
- Unsupported encodings or parse failures quarantine with reason code.
- Structured rewrites follow canonical rules (D-0003).

**Required evidence**
evidence: PROGRESS.md :: T-0104

Implementation Notes:
- V1 baseline supports UTF-8 text; quarantine otherwise.
- JSON/NDJSON output is canonical (sorted keys, no insignificant whitespace).

### T-0105 — Detector engine v1 (offline, deterministic).

**Acceptance criteria**
- Detector engine runs over canonical representation.
- Supports:
  - regex detectors (bounded; catastrophic patterns rejected at policy lint)
  - checksum validators where configured
  - field selectors for structured inputs
- Produces finding summaries without plaintext values.

**Required evidence**
evidence: PROGRESS.md :: T-0105

Implementation Notes:
- Separate detector compilation from execution.
- Ensure regex engine choice supports safe limits (time/space bounded).

### T-0106 — Transform engine v1 (REDACT/MASK/DROP).

**Acceptance criteria**
- Actions are applied deterministically.
- No plaintext sensitive values are written to logs/evidence.
- Transforms are applied before outputs are committed.

**Required evidence**
evidence: PROGRESS.md :: T-0106

Implementation Notes:
- Implement class markers (e.g., `{{PII.Email}}`) as deterministic replacements.
- Define masking rules in policy (e.g., keep last N chars) but do not log raw.

### T-0107 — Rewriter implementations + atomic commit staging.

**Acceptance criteria**
- Sanitized outputs are written to staging then atomically moved into `sanitized/`.
- No partial files appear in final output on crash.
- Output path mapping is deterministic and collision-safe.

**Required evidence**
evidence: PROGRESS.md :: T-0107

Implementation Notes:
- If two artifacts map to same output path, disambiguate deterministically using a suffix derived from artifact_id.
- Use fsync/rename where supported; if atomicity cannot be guaranteed, fail the run before claiming completion.

### T-0108 — Residual verification pass (two-pass scan).

**Acceptance criteria**
- Post-transform re-scan is performed for every candidate VERIFIED artifact.
- Any residual HIGH-severity match causes quarantine with reason VERIFICATION_FAILED.
- If output cannot be re-parsed for verification, quarantine (D-0008).

**Required evidence**
evidence: PROGRESS.md :: T-0108

Implementation Notes:
- Verification uses the same detector set compiled from the policy bundle.
- Verification operates on the emitted output bytes.

### T-0109 — Quarantine reason codes + exit code semantics.

**Acceptance criteria**
- Quarantine reason codes are stable and match spec/03.
- `veil run` exit codes match spec/04.
- Quarantine index is emitted even when quarantines occur.

**Required evidence**
evidence: PROGRESS.md :: T-0109

Implementation Notes:
- Treat per-artifact errors as quarantines; only run-level validation errors are fatal.

### T-0110 — Veil Pack directory creation + invariants enforcement.

**Acceptance criteria**
- `veil run` creates Veil Pack layout v1 exactly (spec/04).
- pack_manifest.json is written last and only if the pack is internally consistent.
- If the run ends fatally, pack_manifest.json MUST NOT claim completion.

**Required evidence**
evidence: PROGRESS.md :: T-0110

Implementation Notes:
- Use a staging marker file in workdir to indicate in-progress runs; delete on completion.


---

## PHASE_2_POLICY_BUNDLE

**Phase goal**
- Implement strict policy bundle schema, hashing, and compilation into detectors/actions.

**Entry criteria**
- PHASE_1 baseline pipeline exists.
- Detector engine and transform engine exist.

**Exit criteria**
- `veil policy lint` validates policy bundle and prints policy_id.
- policy_id immutability enforced across run/resume/verify.
- Strictness baseline enforced.

**Exit gates**

- G-SEC-POLICY-ID-IMMUTABLE (see spec/11)
- G-SEC-KEY-HANDLING (see spec/11)

### Tasks

### T-0201 — Policy schema v1 (policy.json) and strict linting.

**Acceptance criteria**
- policy.json schema matches spec/04 and is strictly validated.
- Unknown fields cause lint failure.
- Lint rejects unsafe regex patterns and invalid severity/action combinations.

**Required evidence**
evidence: PROGRESS.md :: T-0201

Implementation Notes:
- Keep schema minimal and explicit; prefer explicit allowlists over implicit defaults.

### T-0202 — Policy bundle hashing and immutability enforcement.

**Acceptance criteria**
- policy_id computed per D-0001.
- policy_id recorded in evidence and ledger.
- Resume and verify refuse on mismatch.

**Required evidence**
evidence: PROGRESS.md :: T-0202

Implementation Notes:
- Hash canonical bundle bytes including all files under policy bundle.

### T-0203 — Policy compiler to detector set + transform plan.

**Acceptance criteria**
- Compiles policy into an internal detector set and per-class transform actions.
- Compilation is deterministic.
- Compilation failures prevent any processing.

**Required evidence**
evidence: PROGRESS.md :: T-0203

Implementation Notes:
- Apply domain separation for any keyed digests/tokenization configuration.

### T-0204 — Strictness mode (strict baseline).

**Acceptance criteria**
- strict is the default and only supported baseline in v1.
- strict enforces:
  - UNKNOWN coverage → quarantine
  - residual HIGH findings → quarantine
  - archive limit violations → quarantine
- Any attempt to enable permissive modes fails closed.

**Required evidence**
evidence: PROGRESS.md :: T-0204

Implementation Notes:
- Future permissive profiles require a decision + explicit gates; do not implement in v1.


---

## PHASE_3_EVIDENCE_AND_AUDIT

**Phase goal**
- Emit audit-grade evidence and implement independent verification over Veil Packs.

**Entry criteria**
- PHASE_2 policy bundle implemented.
- Core pipeline produces sanitized outputs.

**Exit criteria**
- Evidence bundle formats implemented with no plaintext.
- pack_manifest.json written last and deterministic.
- `veil verify` rescans and fails on residuals.

**Exit gates**

- G-SEC-NO-PLAINTEXT-LEAKS (see spec/11)
- G-SEC-VERIFY-RESIDUAL (see spec/11)
- G-COMP-PACK-COMPAT (see spec/11)

### Tasks

### T-0301 — Evidence bundle writer (run_manifest.json, artifacts.ndjson).

**Acceptance criteria**
- Evidence formats match D-0007 and spec/04.
- Evidence contains no plaintext sensitive values.
- Evidence records bind to run_id, policy_id, tool_version.

**Required evidence**
evidence: PROGRESS.md :: T-0301

Implementation Notes:
- Store only hashes/IDs, class_ids, counts, reason codes.
- Avoid timestamps in evidence (D-0003).

### T-0302 — Quarantine index writer (index.ndjson) + default no-raw policy.

**Acceptance criteria**
- quarantine/index.ndjson always present and non-sensitive.
- raw quarantined copies are absent by default (D-0005).
- If raw copying is enabled, files appear only under quarantine/raw/.

**Required evidence**
evidence: PROGRESS.md :: T-0302

Implementation Notes:
- Ensure index includes artifact_id, source_locator_hash, reason_code.

### T-0303 — Pack manifest writer (pack_manifest.json) + schema versioning.

**Acceptance criteria**
- pack_manifest.json includes required fields from spec/04.
- pack_manifest.json is written last after successful run finalization.
- schema version fields are explicit and validated by verify.

**Required evidence**
evidence: PROGRESS.md :: T-0303

Implementation Notes:
- Keep manifest deterministic (no timestamps).

### T-0304 — `veil verify` implementation (pack verification).

**Acceptance criteria**
- `veil verify` loads policy bundle, checks policy_id match, and rescans sanitized outputs.
- Verification fails (non-zero) on any residual HIGH findings.
- Verification output is non-sensitive and references artifact_id only.

**Required evidence**
evidence: PROGRESS.md :: T-0304

Implementation Notes:
- Verify command must not rely on ledger state; it must trust only pack_manifest + evidence + sanitized outputs.

### T-0305 — Proof token emission (optional, non-sensitive) per D-0007.

**Acceptance criteria**
- Proof tokens are digests only; never plaintext.
- If a stable secret key is not provided, a per-run in-memory key is used and not persisted.
- Evidence includes key commitment only.

**Required evidence**
evidence: PROGRESS.md :: T-0305

Implementation Notes:
- Use domain separation label `veil.proof.v1`.


---

## PHASE_4_FORMATS_AND_LIMITS

**Phase goal**
- Expand V1 format coverage while preserving fail-closed coverage contracts and safety limits.

**Entry criteria**
- PHASE_3 complete.
- Evidence and verification stable.

**Exit criteria**
- Archive limits enforced.
- Email extractors implemented.
- Office Open XML bounded extractor implemented with strict coverage semantics.

**Exit gates**

- G-REL-ARCHIVE-LIMITS (see spec/11)
- G-SEC-COVERAGE-ENFORCED (see spec/11)

### Tasks

### T-0401 — Archive extractor (ZIP/TAR) with safety limits and path defenses.

**Acceptance criteria**
- Enforces D-0006 limits.
- Quarantines entire archive on any violation (no partial emission).
- Prevents absolute paths and path traversal; quarantines on detection.

**Required evidence**
evidence: PROGRESS.md :: T-0401

Implementation Notes:
- Process entries deterministically by normalized path.
- Treat nested archives as depth+1; enforce maximum depth.

### T-0402 — Email extractors (EML/MBOX) with header/body handling.

**Acceptance criteria**
- Parses headers and body into canonical representation.
- Treats headers as metadata surfaces for coverage.
- Attachments are treated as separate artifacts; unsupported attachments quarantine.

**Required evidence**
evidence: PROGRESS.md :: T-0402

Implementation Notes:
- Ensure headers are scanned as metadata (paths hashed; no plaintext email addresses in evidence).

### T-0403 — Office Open XML bounded extractor (DOCX/PPTX/XLSX) with explicit coverage.

**Acceptance criteria**
- Extracts visible text and known metadata fields into canonical representation.
- If embedded binaries or unknown parts exist, extractor MUST mark coverage UNKNOWN and quarantine (strict baseline).
- No plaintext is emitted in evidence/logs.

**Required evidence**
evidence: PROGRESS.md :: T-0403

Implementation Notes:
- Treat these formats as zipped XML; process deterministically by part path ordering.


---

## PHASE_5_HARDENING

**Phase goal**
- Harden reliability/security and establish performance non-regression discipline for large corpora.

**Entry criteria**
- PHASE_4 complete.
- Core contracts stable.

**Exit criteria**
- Perf harness baseline captured.
- Fuzzing harness operational.
- Determinism suite stable.
- Release packaging documented and usable offline.

**Exit gates**

- G-PERF-NO-REGRESSION (see spec/11)
- G-REL-DETERMINISM (see spec/11)
- G-OPS-RUNBOOK-COMPLETE (see spec/11)

### Tasks

### T-0501 — Performance harness + baseline capture (no regression gate).

**Acceptance criteria**
- Provides a repeatable perf harness that measures throughput and resource usage on a fixed fixture corpus.
- Captures a baseline and enforces “no regression without a decision and evidence.”

**Required evidence**
evidence: PROGRESS.md :: T-0501

Implementation Notes:
- Do not set absolute performance targets; compare against recorded baseline.

### T-0502 — Fuzzing harness for extractors and archives.

**Acceptance criteria**
- Fuzz tests run offline and do not require network.
- No panics; malformed inputs quarantine or fail safely.
- Archive fuzzing covers limit enforcement and path traversal cases.

**Required evidence**
evidence: PROGRESS.md :: T-0502

Implementation Notes:
- Keep fuzz corpus non-sensitive; synthetic fixtures only.

### T-0503 — End-to-end determinism and reproducibility suite.

**Acceptance criteria**
- Double-run determinism test is stable across runs on same tool version.
- Evidence and sanitized outputs hash-identical under D-0003 conditions.

**Required evidence**
evidence: PROGRESS.md :: T-0503

Implementation Notes:
- Ensure fixture corpus includes structured formats and archives.

### T-0504 — Security hardening: key zeroization + temp hygiene.

**Acceptance criteria**
- Secret keys are zeroized in memory after use where feasible.
- Temp/work directories do not leak plaintext.
- Failures do not leave partial outputs in sanitized/.

**Required evidence**
evidence: PROGRESS.md :: T-0504

Implementation Notes:
- Treat temp files as sensitive by default; store only non-sensitive intermediates when possible.

### T-0505 — Release packaging and offline distribution notes.

**Acceptance criteria**
- Build produces a distributable binary artifact.
- Runbook includes offline installation guidance.
- Versioning and schema compatibility are documented.

**Required evidence**
evidence: PROGRESS.md :: T-0505

Implementation Notes:
- Prefer a single static binary where feasible; avoid runtime download steps.


---

## DONE

**Phase goal**
- All phases complete; all quality gates pass; Veil produces and verifies Veil Packs according to the safety definition.

**Entry criteria**
- All tasks DONE.

**Exit criteria**
- All gates in spec/11 are PASS with evidence recorded in PROGRESS.
- No blocking questions remain for core functionality.

**Exit gates**
- All gates in spec/11 must be PASS.
