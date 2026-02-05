import argparse
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


def fail(msg: str) -> None:
    print(msg)
    raise SystemExit(1)


def check_core_files() -> None:
    required_paths = [
        "README.md",
        "AGENTS.md",
        "CONSTITUTION.md",
        "DECISIONS.md",
        "ASSUMPTIONS.md",
        "PROGRESS.md",
        "QUESTIONS_FOR_USER.md",
        "AUDIT_REPORT.md",
        "CHANGELOG.md",
        "MANIFEST.sha256",
        "Cargo.toml",
        "Cargo.lock",
        ".gitignore",
        "crates",
        "checks",
        "spec",
        "templates",
        ".github",
    ]

    missing = []
    for rel in required_paths:
        p = ROOT / rel
        if not p.exists():
            missing.append(rel)
    if missing:
        fail("MISSING_CORE_FILES " + ", ".join(missing))
    print("PASS")


def check_fingerprint_matrix() -> None:
    fp = ROOT / "spec" / "00_PROJECT_FINGERPRINT.md"
    txt = fp.read_text(encoding="utf-8", errors="ignore")

    row_pat = re.compile(r"^\|\s*(\d{2})\s*\|\s*([^|]+?)\s*\|\s*(APPLICABLE|NON-APPLICABLE)\s*\|")
    applicable = []
    non_applicable = []
    for line in txt.splitlines():
        m = row_pat.match(line)
        if not m:
            continue
        _, path, app = m.group(1), m.group(2).strip(), m.group(3)
        if app == "APPLICABLE":
            applicable.append(path)
        else:
            non_applicable.append(path)

    if not applicable:
        fail("NO_MATRIX_ROWS_FOUND")

    missing = [p for p in applicable if not (ROOT / p).exists()]
    present_non = [p for p in non_applicable if (ROOT / p).exists()]
    if missing:
        fail("MISSING_APPLICABLE_SPEC_FILES " + ", ".join(missing))
    if present_non:
        fail("PRESENT_NON_APPLICABLE_SPEC_FILES " + ", ".join(present_non))

    spec_dir = ROOT / "spec"
    spec_files = sorted([p.name for p in spec_dir.glob("*.md") if p.is_file()])
    matrix_files = sorted([pathlib.Path(p).name for p in applicable])
    extra = sorted(set(spec_files) - set(matrix_files))
    if extra:
        fail("EXTRA_SPEC_FILES " + ", ".join(extra))

    print("PASS")


def check_slop_mapping() -> None:
    spec11 = ROOT / "spec" / "11_QUALITY_GATES.md"
    txt = spec11.read_text(encoding="utf-8", errors="ignore")

    table_start = txt.find("| SB-ID |")
    if table_start == -1:
        fail("MISSING_SLOP_MAPPING_TABLE")

    table_lines = []
    for line in txt[table_start:].splitlines():
        if not line.startswith("|"):
            break
        table_lines.append(line)

    row_pat = re.compile(r"^\|\s*(SB-\d{4})\s*\|")
    rows = []
    for line in table_lines:
        m = row_pat.match(line)
        if m:
            rows.append(m.group(1))

    missing = []
    dup = []
    for i in range(1, 13):
        sb = f"SB-{i:04d}"
        c = rows.count(sb)
        if c == 0:
            missing.append(sb)
        elif c != 1:
            dup.append(f"{sb}={c}")

    if missing:
        fail("MISSING_SB_IDS " + ", ".join(missing))
    if dup:
        fail("DUPLICATE_SB_IDS " + ", ".join(dup))

    print("PASS")


def check_qac_coverage() -> None:
    spec0 = ROOT / "spec" / "00_PROJECT_FINGERPRINT.md"
    spec11 = ROOT / "spec" / "11_QUALITY_GATES.md"

    txt0 = spec0.read_text(encoding="utf-8", errors="ignore")
    required_gates = sorted(set(re.findall(r"\bG-[A-Z0-9-]+\b", txt0)))
    if not required_gates:
        fail("NO_GATES_FOUND_IN_QAC")

    txt11 = spec11.read_text(encoding="utf-8", errors="ignore")
    defined_gates = set(re.findall(r"^###\s+(G-[A-Z0-9-]+)\b", txt11, flags=re.MULTILINE))

    missing = [g for g in required_gates if g not in defined_gates]
    if missing:
        fail("MISSING_GATE_DEFINITIONS " + ", ".join(missing))

    print("PASS")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "check",
        choices=["core-files", "fingerprint-matrix", "slop-mapping", "qac-coverage", "all"],
    )
    args = ap.parse_args()

    if args.check in ("core-files", "all"):
        check_core_files()
    if args.check in ("fingerprint-matrix", "all"):
        check_fingerprint_matrix()
    if args.check in ("slop-mapping", "all"):
        check_slop_mapping()
    if args.check in ("qac-coverage", "all"):
        check_qac_coverage()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
