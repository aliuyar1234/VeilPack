# checks/CHECKS_INDEX.md

## Checks Index
Each check defines: purpose, type, how to run, pass/fail, and where to record evidence.

Default evidence recording location:
- evidence: PROGRESS.md :: Evidence Recording Rules

---

## CHK-MANIFEST-VERIFY
- Purpose: ensure SSOT pack integrity; detect drift.
- Type: automated
- How to regenerate:
  - `python checks/generate_manifest.py`
- How to run:
  - `python -c "import hashlib, pathlib; p=pathlib.Path('.'); mf=p/'MANIFEST.sha256'; lines=mf.read_text().splitlines(); ok=True; 
for line in lines:
  h, rel = line.split('  ', 1)
  data=(p/rel).read_bytes()
  hh=hashlib.sha256(data).hexdigest()
  if hh!=h:
    ok=False
    print('MISMATCH', rel)
print('PASS' if ok else 'FAIL'); raise SystemExit(0 if ok else 1)"`
- Pass/fail:
  - PASS if command exits 0 and prints PASS.
- Evidence:
  - evidence: PROGRESS.md :: CHK-MANIFEST-VERIFY

---

## CHK-FORBIDDEN-TERMS
- Purpose: prevent thin docs and placeholder drift.
- Type: automated
- Scope: text source files in the repo (md/rs/py/toml/yml/yaml/gitignore), excluding ephemeral build/cache outputs (per D-0010) and checks/CHECKS_INDEX.md.
- Forbidden placeholder tokens (literal list; canonical home):
  - TBD
  - T.B.D.
  - PLACEHOLDER
  - LOREM
  - IPSUM
  - FIXME
  - XXX
  - INSERT HERE
  - FILL THIS IN
- How to run:
  - `python -c "import pathlib, sys; root=pathlib.Path('.'); bad=['TBD','T.B.D.','PLACEHOLDER','LOREM','IPSUM','FIXME','XXX','INSERT HERE','FILL THIS IN']; ex_dirs={'.git','target','__pycache__','.pytest_cache','.mypy_cache','.ruff_cache'}; ex_files={'checks/CHECKS_INDEX.md'}; ex_ext={'.md','.rs','.py','.toml','.yml','.yaml'}; ok=True
for p in root.rglob('*'):
  if not p.is_file(): continue
  if p.as_posix() in ex_files: continue
  if any(part in ex_dirs for part in p.parts): continue
  if p.suffix.lower() not in ex_ext and p.name != '.gitignore': continue
  s=p.read_text(errors='ignore')
  for b in bad:
    if b in s:
      ok=False
      print('FORBIDDEN', b, 'IN', p.as_posix())
print('PASS' if ok else 'FAIL'); sys.exit(0 if ok else 1)"`
- Pass/fail:
  - PASS if no forbidden token appears.
- Evidence:
  - evidence: PROGRESS.md :: CHK-FORBIDDEN-TERMS

---

## CHK-CORE-FILES
- Purpose: verify required core files exist.
- Type: manual
- How to run:
  - Confirm all non-omittable core files are present per required ZIP structure.
  - Optional automation: `python checks/ssot_validate.py core-files`
- Pass/fail:
  - PASS if all required files exist.
- Evidence:
  - evidence: PROGRESS.md :: CHK-CORE-FILES

---

## CHK-FINGERPRINT-MATRIX
- Purpose: verify Spec Applicability Matrix matches filesystem.
- Type: manual (automate later)
- How to run:
  - Compare spec/00 matrix to actual files under spec/.
  - Ensure all APPLICABLE spec files exist and no NON-APPLICABLE files exist.
  - Optional automation: `python checks/ssot_validate.py fingerprint-matrix`
- Pass/fail:
  - PASS if matrix and filesystem match exactly.
- Evidence:
  - evidence: PROGRESS.md :: CHK-FINGERPRINT-MATRIX

---

## CHK-SLOP-MAPPING
- Purpose: ensure SB-0001..SB-0012 are present and mapped to enforcement in spec/11.
- Type: manual
- How to run:
  - Confirm spec/11 contains the SLOP Enforcement Mapping table with SB-0001..SB-0012.
  - Optional automation: `python checks/ssot_validate.py slop-mapping`
- Pass/fail:
  - PASS if all SB IDs appear exactly once in the mapping table.
- Evidence:
  - evidence: PROGRESS.md :: CHK-SLOP-MAPPING

---

## CHK-EVIDENCE-POINTER-FORMAT
- Purpose: ensure evidence pointers use the required syntax exactly.
- Type: automated
- How to run:
  - `python -c "import pathlib, re, sys; root=pathlib.Path('.'); pat=re.compile(r'evidence: ([^ ]+) :: ([^|\n\r]+)'); 
ok=True
for p in root.rglob('*.md'):
  txt=p.read_text(errors='ignore')
  for m in pat.finditer(txt):
    path=m.group(1)
    phrase=m.group(2).strip()
    if not path or not phrase:
      ok=False
      print('BAD_EVIDENCE_POINTER', p.as_posix(), m.group(0))
print('PASS' if ok else 'FAIL'); sys.exit(0 if ok else 1)"`
- Pass/fail:
  - PASS if all evidence pointers match the required format.
- Evidence:
  evidence: PROGRESS.md :: CHK-EVIDENCE-POINTER-FORMAT

---

## CHK-REF-INTEGRITY

- Purpose: prevent broken internal references (paths and IDs).
- Type: manual (automate later)
- How to run:
  1) For every evidence pointer (format described in CHK-EVIDENCE-POINTER-FORMAT):
     - confirm the referenced path exists
     - confirm the phrase appears somewhere in the referenced file
  2) Confirm all referenced IDs exist:
     - Decisions: D-####
     - Assumptions: A-####
     - Questions: Q-####
     - Tasks: T-####
     - Slop rules: SB-####
     - Checks: CHK-...
- Pass/fail:
  - PASS if all evidence pointers resolve and all IDs exist.
- Evidence:
  - evidence: PROGRESS.md :: CHK-REF-INTEGRITY

---

## CHK-NO-ADHOC-FILES
- Purpose: ensure the pack contains only the canonical file tree.
- Type: manual
- How to run:
  - Confirm the repo contains only the expected source tree (SSOT spine + implementation scaffold), excluding ephemeral outputs per D-0010.
  - Expected top-level items include:
    - `Cargo.toml`, `MANIFEST.sha256`, `.gitignore`
    - `crates/`, `checks/`, `spec/`, `templates/`, `.github/`
    - SSOT core markdown files (README/AGENTS/CONSTITUTION/DECISIONS/ASSUMPTIONS/PROGRESS/QUESTIONS/AUDIT_REPORT/CHANGELOG)
  - Confirm ephemeral outputs are excluded from the manifest generator and not treated as canonical (e.g., `target/`).
- Pass/fail:
  - PASS if no extra files/folders exist and no required file is missing.
- Evidence:
  - evidence: PROGRESS.md :: CHK-NO-ADHOC-FILES

---

## CHK-QAC-COVERAGE
- Purpose: ensure Quality Attribute Profile rows map to at least one gate and gates exist.
- Type: manual
- How to run:
  - Confirm spec/00 quality profile lists gate IDs.
  - Confirm spec/11 defines those gate IDs.
  - Optional automation: `python checks/ssot_validate.py qac-coverage`
- Pass/fail:
  - PASS if every quality attribute maps to at least one defined gate.
- Evidence:
  - evidence: PROGRESS.md :: CHK-QAC-COVERAGE

---

## CHK-BOUNDARY-FITNESS
- Purpose: enforce dependency direction rules and prevent architecture erosion.
- Type: automated (implemented in repo)
- How to run:
  - `python checks/boundary_fitness.py`
- Pass/fail:
  - PASS if dependency graph matches C-101 layering rules.
- Evidence:
  - evidence: PROGRESS.md :: CHK-BOUNDARY-FITNESS

---

## CHK-OFFLINE-ENFORCEMENT
- Purpose: enforce no network usage in runtime code paths.
- Type: automated (implemented in repo)
- How to run:
  - Static scan: `python checks/offline_enforcement.py`
  - Runtime offline monitor: `cargo test -p veil-cli --test offline_enforcement`
- Pass/fail:
  - PASS if static scan has no hits and runtime test observes no socket activity from `veil run`.
- Evidence:
  - evidence: PROGRESS.md :: CHK-OFFLINE-ENFORCEMENT

---

## CHK-NO-PLAINTEXT-LEAKS
- Purpose: ensure canary secrets never appear in logs/evidence/quarantine index.
- Type: automated (implemented in repo)
- How to run:
  - Run the canary regression test suite.
- Pass/fail:
  - PASS if canaries are absent from all outputs.
- Evidence:
  - evidence: PROGRESS.md :: CHK-NO-PLAINTEXT-LEAKS

---

## CHK-LOG-SCHEMA
- Purpose: ensure stderr logs follow Observability Log Schema v1.
- Type: automated (implemented in repo)
- How to run:
  - `cargo test -p veil-cli --test phase1_gates logs_use_structured_json_schema_v1 -- --exact`
- Pass/fail:
  - PASS if every emitted stderr log line is JSON and includes `level`, `event`, `run_id`, `policy_id`.
- Evidence:
  - evidence: PROGRESS.md :: CHK-LOG-SCHEMA

---

## CHK-NEGATIVE-PATHS
- Purpose: ensure quarantine behavior covers error paths (parse failures, unknown coverage, verification failure).
- Type: automated (implemented in repo)
- How to run:
  - `cargo test -p veil-cli --tests`
- Pass/fail:
  - PASS if all negative cases quarantine or fail safely as specified.
- Evidence:
  - evidence: PROGRESS.md :: CHK-NEGATIVE-PATHS

---

## CHK-CONTRACT-CONSISTENCY
- Purpose: prevent drift between implementation and spec/04 contracts.
- Type: automated (implemented in repo)
- How to run:
  - `cargo test -p veil-cli --test contract_consistency`
- Pass/fail:
  - PASS if tests match spec/04 exactly.
- Evidence:
  - evidence: PROGRESS.md :: CHK-CONTRACT-CONSISTENCY

---

## CHK-FAIL-CLOSED-INVARIANTS
- Purpose: enforce the fail-closed invariants across critical flows.
- Type: automated (implemented in repo)
- How to run:
  - Run invariant tests that assert:
    - all artifacts are VERIFIED or QUARANTINED
    - unknown coverage never yields VERIFIED
    - residual verification is enforced
- Pass/fail:
  - PASS if invariants hold.
- Evidence:
  - evidence: PROGRESS.md :: CHK-FAIL-CLOSED-INVARIANTS
