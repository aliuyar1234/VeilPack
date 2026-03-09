#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import pathlib
import shutil
import subprocess
import zipfile


def workspace_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def rust_host_triple() -> str:
    output = subprocess.check_output(["rustc", "-vV"], text=True)
    for line in output.splitlines():
        if line.startswith("host: "):
            return line.split("host: ", 1)[1].strip()
    raise RuntimeError("could not determine rust host triple")


def file_sha256(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def prepare_dist_dir(root: pathlib.Path) -> pathlib.Path:
    dist = root / "dist"
    # Clear the whole release staging directory so uploads never pick up stale assets.
    if dist.exists():
        shutil.rmtree(dist)
    dist.mkdir(parents=True, exist_ok=True)
    return dist


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True, help="Release tag, e.g. v1.0.0")
    args = parser.parse_args()

    root = workspace_root()
    dist = prepare_dist_dir(root)

    host = rust_host_triple()
    exe_name = "veil.exe" if (root / "target" / "release" / "veil.exe").exists() else "veil"
    binary_path = root / "target" / "release" / exe_name
    if not binary_path.exists():
        raise FileNotFoundError(f"missing built binary: {binary_path}")

    asset_stem = f"veil-{args.tag}-{host}"
    archive_path = dist / f"{asset_stem}.zip"
    checksum_path = dist / f"{asset_stem}.sha256"

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(binary_path, arcname=exe_name)
        archive.write(root / "README.md", arcname="README.md")
        archive.write(root / "LICENSE", arcname="LICENSE")

    checksum = file_sha256(archive_path)
    checksum_path.write_text(f"{checksum}  {archive_path.name}\n", encoding="utf-8")
    print(f"created {archive_path}")
    print(f"created {checksum_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
