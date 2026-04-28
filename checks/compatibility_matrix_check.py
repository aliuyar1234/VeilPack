import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "docs" / "compatibility-matrix.md"
SCHEMA_RS = ROOT / "crates" / "veil-evidence" / "src" / "schema.rs"
MATRIX_TEST = ROOT / "crates" / "veil-cli" / "tests" / "compatibility_matrix.rs"


def read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def extract_current_schema(text: str, type_name: str) -> str:
    """Resolve `<type_name>::CURRENT` -> wire-format string by chaining the enum
    constant declaration (`pub const CURRENT: Self = Self::Vn;`) inside the
    `impl <type_name>` block to the matching `as_str` arm (`Self::Vn => "..."`).
    """
    impl_match = re.search(
        rf"impl\s+{re.escape(type_name)}\s*{{(.*?)\n}}",
        text,
        flags=re.DOTALL,
    )
    if not impl_match:
        raise RuntimeError(f"could not find impl block for {type_name}")
    body = impl_match.group(1)

    variant_match = re.search(
        r"pub\s+const\s+CURRENT\s*:\s*Self\s*=\s*Self::(\w+)\s*;",
        body,
    )
    if not variant_match:
        raise RuntimeError(f"could not extract CURRENT variant from {type_name}")
    variant = variant_match.group(1)

    arm_match = re.search(
        rf'Self::{re.escape(variant)}\s*=>\s*"([^"]+)"',
        body,
    )
    if not arm_match:
        raise RuntimeError(
            f"could not extract wire string for {type_name}::{variant}"
        )
    return arm_match.group(1)


def main() -> int:
    errors: list[str] = []

    if not MATRIX_PATH.exists():
        errors.append(f"missing matrix file: {MATRIX_PATH.relative_to(ROOT).as_posix()}")
    if not MATRIX_TEST.exists():
        errors.append(f"missing matrix test: {MATRIX_TEST.relative_to(ROOT).as_posix()}")
    if not SCHEMA_RS.exists():
        errors.append(f"missing schema file: {SCHEMA_RS.relative_to(ROOT).as_posix()}")

    if errors:
        print("FAIL")
        for err in errors:
            print(err)
        return 1

    schema_text = read_text(SCHEMA_RS)
    pack_schema = extract_current_schema(schema_text, "PackSchemaVersion")
    ledger_schema = extract_current_schema(schema_text, "LedgerSchemaVersion")
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
