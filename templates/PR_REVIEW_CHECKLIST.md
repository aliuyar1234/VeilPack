# templates/PR_REVIEW_CHECKLIST.md

## No Evidence, No Accept
- [ ] Evidence for this change is recorded in PROGRESS with evidence pointers.

## Decisions Updated
- [ ] Any structural/interface/schema changes have a corresponding D-entry in DECISIONS.md.
- [ ] Verification impact has been updated in spec/11 gates and/or checks index.

## Questions classification
- [ ] New uncertainties were processed via DSC.
- [ ] Questions are classified blocking YES/NO.
- [ ] Non-blocking questions proceeded with conservative baselines and were logged.

## SLOP_BLACKLIST Compliance
For each SB item, include an evidence pointer (usually to PROGRESS).

- [ ] SB-0001 Silent defaults in critical flows — evidence:
- [ ] SB-0002 God objects / mega-modules — evidence:
- [ ] SB-0003 Copy-paste duplication instead of abstraction — evidence:
- [ ] SB-0004 Untested error paths — evidence:
- [ ] SB-0005 Unbounded retries / missing timeouts — evidence:
- [ ] SB-0006 Hidden global state / implicit singletons — evidence:
- [ ] SB-0007 Naming/semantics drift — evidence:
- [ ] SB-0008 Logging without correlation OR leaking sensitive data — evidence:
- [ ] SB-0009 Contract drift (implementation ≠ interfaces/spec) — evidence:
- [ ] SB-0010 Convenience over fail-closed — evidence:
- [ ] SB-0011 One-off scripts without runbook/checks — evidence:
- [ ] SB-0012 Structural changes without decision log — evidence:

## Required checks before acceptance
- [ ] CHK-FORBIDDEN-TERMS PASS
- [ ] CHK-REF-INTEGRITY PASS
- [ ] CHK-EVIDENCE-POINTER-FORMAT PASS
- [ ] CHK-QAC-COVERAGE PASS
- [ ] CHK-BOUNDARY-FITNESS PASS (when code exists)
- [ ] CHK-MANIFEST-VERIFY PASS

## Security and safety gates (when applicable)
- [ ] G-SEC-OFFLINE-NO-NET evidence recorded
- [ ] G-SEC-NO-PLAINTEXT-LEAKS evidence recorded
- [ ] G-SEC-FAIL-CLOSED-TERMINAL evidence recorded
- [ ] G-SEC-VERIFY-RESIDUAL evidence recorded
