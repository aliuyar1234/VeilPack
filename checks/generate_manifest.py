import hashlib
import pathlib


EXCLUDED_DIRS = {
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "target",
}

EXCLUDED_FILES = {
    "MANIFEST.sha256",
}


def main() -> None:
    root = pathlib.Path(".")
    paths = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue

        rel = p.relative_to(root)

        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue

        if rel.as_posix() in EXCLUDED_FILES:
            continue

        paths.append(rel)

    paths.sort(key=lambda p: p.as_posix())

    lines = []
    for rel in paths:
        data = (root / rel).read_bytes()
        h = hashlib.sha256(data).hexdigest()
        lines.append(f"{h}  {rel.as_posix()}")

    (root / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

