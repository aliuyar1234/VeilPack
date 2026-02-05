# AGENTS.md (Highest Precedence)

This file is the **highest precedence** authority for how to use and evolve this SSOT pack.

## Mandatory session read-order (onboarding guidance)
README → AGENTS → CONSTITUTION → spec/* (existing files only; numeric order) → DECISIONS → ASSUMPTIONS → PROGRESS → QUESTIONS (if present) → AUDIT_REPORT.

## Precedence Order (conflict resolution; verbatim)
1) AGENTS.md
2) CONSTITUTION.md
3) spec/* (numeric order; existing files only)
4) DECISIONS.md
5) ASSUMPTIONS.md
6) README.md
7) templates/*, checks/*, runbook content

## Read-order vs precedence clarification (verbatim)
- Read-order is onboarding guidance.
- Precedence order is conflict resolution.
- If they conflict, precedence wins.

## Session protocol (mandatory)
- Follow:
evidence: templates/SESSION_PROTOCOL.md :: SESSION_START
evidence: templates/SESSION_PROTOCOL.md :: SESSION_END
- Update after each session:
  - DECISIONS.md (new decisions, conflict resolutions)
  - ASSUMPTIONS.md (new/retired assumptions)
  - PROGRESS.md (task statuses + evidence entries)
  - CHANGELOG.md (SSOT pack changes)
- Regenerate MANIFEST.sha256 after any change. If not regenerated, acceptance is blocked.
evidence: checks/CHECKS_INDEX.md :: CHK-MANIFEST-VERIFY

## DSC + autonomy policy enforcement (mandatory)
- Any ambiguity or missing datum that affects behavior MUST be processed via DSC and recorded:
  - Decisions → DECISIONS.md
  - Assumptions → ASSUMPTIONS.md
  - Questions → QUESTIONS_FOR_USER.md
- Blocking questions are allowed ONLY when truly blocking; otherwise proceed with conservative baselines.
evidence: templates/SESSION_PROTOCOL.md :: QUESTION_ENTRY_FORMAT

## No silent refactors (mandatory)
- Any structural change (module boundaries, interfaces, schemas, output layout) requires:
  1) A DECISIONS.md entry (why + implications + verification impact)
  2) Corresponding updates to spec/02, spec/04, spec/11
  3) MANIFEST regeneration
- Enforcement:
evidence: spec/11_QUALITY_GATES.md :: G-MAINT-BOUNDARY-FITNESS

## New session ramp-up checklist (copy/paste)
1) Verify MANIFEST integrity:
evidence: checks/CHECKS_INDEX.md :: CHK-MANIFEST-VERIFY
2) Read in order:
evidence: README.md :: Where to find X (evidence pointers only)
3) Identify critical-flow edits planned this session (yes/no per change).
evidence: spec/06_SECURITY_AND_THREAT_MODEL.md :: Critical Flows and Controls
4) Apply DSC to each uncertainty and record:
evidence: DECISIONS.md :: Decision Log
evidence: ASSUMPTIONS.md :: Assumptions Log
evidence: QUESTIONS_FOR_USER.md :: Open Questions
5) Execute the minimal checks before claiming progress:
evidence: checks/CHECKS_INDEX.md :: Checks Index
6) Update PROGRESS with status changes and evidence entries:
evidence: PROGRESS.md :: Task Status Table
7) Regenerate MANIFEST and re-verify:
evidence: checks/CHECKS_INDEX.md :: CHK-MANIFEST-VERIFY
