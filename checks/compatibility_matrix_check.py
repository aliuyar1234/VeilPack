import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "docs" / "compatibility-matrix.md"
MAIN_RS = ROOT / "crates" / "veil-cli" / "src" / "main.rs"
LEDGER_RS = ROOT / "crates" / "veil-evidence" / "src" / "ledger.rs"
MATRIX_TEST = ROOT / "crates" / "veil-cli" / "tests" / "compatibility_matrix.rs"


def read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def extract_constant(text: str, name: str) -> str:
    m = re.search(rf'{re.escape(name)}\s*:\s*&str\s*=\s*"([^"]+)"', text)
    if not m:
        raise RuntimeError(f"could not extract {name}")
    return m.group(1)


def main() -> int:
    errors: list[str] = []

    if not MATRIX_PATH.exists():
        errors.append(f"missing matrix file: {MATRIX_PATH.relative_to(ROOT).as_posix()}")
    if not MATRIX_TEST.exists():
        errors.append(f"missing matrix test: {MATRIX_TEST.relative_to(ROOT).as_posix()}")

    if errors:
        print("FAIL")
        for err in errors:
            print(err)
        return 1

    pack_schema = extract_constant(read_text(MAIN_RS), "PACK_SCHEMA_VERSION")
    ledger_schema = extract_constant(read_text(LEDGER_RS), "LEDGER_SCHEMA_VERSION")
    matrix = read_text(MATRIX_PATH)

    expected_supported_row = f"| `{pack_schema}` | `{ledger_schema}` | yes |"
    if expected_supported_row not in matrix:
        errors.append(
            f"matrix missing supported current row: {expected_supported_row}"
        )

    if re.search(r"\|\s*`[^`]+`\s*\|\s*`[^`]+`\s*\|\s*no\s*\|", matrix) is None:
        errors.append("matrix must include at least one unsupported (no) row")

    if "compatibility_matrix.rs" not in matrix:
        errors.append("matrix must reference compatibility_matrix.rs regression test")

    if errors:
        print("FAIL")
        for err in errors:
            print(err)
        return 1

    print("PASS")
    print("CURRENT_PACK_SCHEMA", pack_schema)
    print("CURRENT_LEDGER_SCHEMA", ledger_schema)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
