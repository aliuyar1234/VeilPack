# templates/SESSION_PROTOCOL.md

## SESSION_START
1) Verify SSOT integrity:
   - run CHK-MANIFEST-VERIFY
   - if failing: declare the session BLOCKED until MANIFEST is regenerated correctly
2) Read required files in order:
   - README.md
   - AGENTS.md
   - CONSTITUTION.md
   - spec/* (numeric order; existing files only)
   - DECISIONS.md
   - ASSUMPTIONS.md
   - PROGRESS.md
   - QUESTIONS_FOR_USER.md (if present)
   - AUDIT_REPORT.md
3) Declare planned changes:
   - list each planned change
   - mark whether it impacts a critical flow (YES/NO)
4) Run DSC on any uncertainty:
   - classify as decision/assumption/question
   - classify questions as blocking YES/NO
   - proceed with conservative baselines for non-blocking questions
5) Plan evidence:
   - for each task you intend to complete, identify:
     - acceptance criteria
     - gates/checks to run
     - where evidence will be recorded in PROGRESS

## SESSION_END
1) Update logs:
   - DECISIONS.md: append new decisions; include verification impact
   - ASSUMPTIONS.md: add/retire assumptions
   - PROGRESS.md: update task statuses and add evidence entries
   - CHANGELOG.md: record SSOT pack changes (no dates)
2) Run required checks:
   - CHK-REF-INTEGRITY
   - CHK-EVIDENCE-POINTER-FORMAT
   - CHK-NO-ADHOC-FILES
3) Regenerate MANIFEST.sha256 and verify:
   - run CHK-MANIFEST-VERIFY
4) Record any new questions:
   - append to QUESTIONS_FOR_USER.md using QUESTION_ENTRY_FORMAT
   - ensure blocking classification is explicit

## QUESTION_ENTRY_FORMAT
- Q-ID:
- blocking: YES/NO
- why needed:
- what it blocks:
- safe default if non-blocking:
- where encoded (decision/assumption/spec path):
- what proceeds safely now:
- risk if wrong:
