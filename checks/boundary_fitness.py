import json
import pathlib
import subprocess
import sys


LAYER_ORDER = [
    "veil-domain",
    "veil-policy",
    "veil-extract",
    "veil-detect",
    "veil-transform",
    "veil-verify",
    "veil-evidence",
    "veil-cli",
]

LAYER_INDEX = {name: i for i, name in enumerate(LAYER_ORDER)}
MAX_RUST_SOURCE_LOC = 2200


def main() -> int:
    meta = cargo_metadata()

    workspace_member_ids = set(meta["workspace_members"])
    packages = [p for p in meta["packages"] if p["id"] in workspace_member_ids]

    by_name = {p["name"]: p for p in packages}

    unknown = sorted([name for name in by_name.keys() if name not in LAYER_INDEX])
    if unknown:
        print("FAIL")
        for name in unknown:
            print("UNKNOWN_WORKSPACE_PACKAGE", name)
        return 1

    violations: list[tuple[str, str]] = []
    for pkg in packages:
        pkg_name = pkg["name"]
        pkg_layer = LAYER_INDEX[pkg_name]

        deps = pkg.get("dependencies", [])
        for dep in deps:
            dep_name = dep.get("name")
            if dep_name not in by_name:
                continue

            dep_layer = LAYER_INDEX[dep_name]
            if dep_layer > pkg_layer:
                violations.append((pkg_name, dep_name))

    if violations:
        print("FAIL")
        for pkg_name, dep_name in sorted(violations):
            print("VIOLATION", pkg_name, "DEPENDS_ON_HIGHER_LAYER", dep_name)
        return 1

    loc_violations = rust_source_size_violations()
    if loc_violations:
        print("FAIL")
        for rel, lines in loc_violations:
            print("GOD_MODULE", rel, "LINES", lines, "MAX", MAX_RUST_SOURCE_LOC)
        return 1

    print("PASS")
    return 0


def cargo_metadata() -> dict:
    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(proc.stdout)


def rust_source_size_violations() -> list[tuple[str, int]]:
    root = pathlib.Path(__file__).resolve().parents[1]
    violations: list[tuple[str, int]] = []
    for path in sorted((root / "crates").glob("*/src/**/*.rs")):
        try:
            line_count = len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
        except OSError:
            continue
        if line_count > MAX_RUST_SOURCE_LOC:
            violations.append((path.relative_to(root).as_posix(), line_count))
    return violations


if __name__ == "__main__":
    raise SystemExit(main())
