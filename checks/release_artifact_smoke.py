#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def release_assets(dist: pathlib.Path, tag: str | None) -> tuple[pathlib.Path, pathlib.Path]:
    zip_pattern = "veil-*.zip" if tag is None else f"veil-{tag}-*.zip"
    sha_pattern = "veil-*.sha256" if tag is None else f"veil-{tag}-*.sha256"

    archives = sorted(dist.glob(zip_pattern))
    checksums = sorted(dist.glob(sha_pattern))
    if len(archives) != 1:
        raise SystemExit(f"expected exactly one archive in {dist}, found {len(archives)}")
    if len(checksums) != 1:
        raise SystemExit(f"expected exactly one checksum in {dist}, found {len(checksums)}")
    return archives[0], checksums[0]


def file_sha256(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def parse_checksum_file(path: pathlib.Path) -> tuple[str, str]:
    line = path.read_text(encoding="utf-8").strip()
    checksum, file_name = line.split(maxsplit=1)
    return checksum, file_name.strip()


def binary_name_for_platform() -> str:
    return "veil.exe" if os.name == "nt" else "veil"


def chmod_executable(path: pathlib.Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def smoke_archive(archive_path: pathlib.Path) -> None:
    expected_binary = binary_name_for_platform()
    with tempfile.TemporaryDirectory(prefix="veil_release_smoke_") as td:
        extract_root = pathlib.Path(td)
        with zipfile.ZipFile(archive_path) as archive:
            names = sorted(archive.namelist())
            expected_names = sorted(["LICENSE", "README.md", expected_binary])
            if names != expected_names:
                raise SystemExit(
                    f"archive contents mismatch for {archive_path.name}: expected {expected_names}, found {names}"
                )
            archive.extractall(extract_root)

        binary_path = extract_root / expected_binary
        if os.name != "nt":
            chmod_executable(binary_path)

        proc = subprocess.run(
            [str(binary_path), "--help"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if proc.returncode != 0:
            raise SystemExit(
                f"smoke command failed for {binary_path.name} with code {proc.returncode}:\n{proc.stdout}"
            )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", type=pathlib.Path, default=ROOT / "dist")
    ap.add_argument("--tag", type=str, default=None)
    args = ap.parse_args()

    archive_path, checksum_path = release_assets(args.dist, args.tag)
    expected_checksum, recorded_name = parse_checksum_file(checksum_path)
    if recorded_name != archive_path.name:
        raise SystemExit(
            f"checksum file {checksum_path.name} points to {recorded_name}, expected {archive_path.name}"
        )

    actual_checksum = file_sha256(archive_path)
    if actual_checksum != expected_checksum:
        raise SystemExit(
            f"checksum mismatch for {archive_path.name}: expected {expected_checksum}, got {actual_checksum}"
        )

    smoke_archive(archive_path)
    print(f"PASS {archive_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
