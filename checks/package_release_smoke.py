import importlib.util
import pathlib
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "package_release.py"


def load_module():
    spec = importlib.util.spec_from_file_location("package_release", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def write_fixture_repo(root: pathlib.Path, exe_name: str = "veil") -> None:
    (root / "target" / "release").mkdir(parents=True, exist_ok=True)
    (root / "target" / "release" / exe_name).write_bytes(b"fake-binary")
    (root / "README.md").write_text("readme\n", encoding="utf-8")
    (root / "LICENSE").write_text("license\n", encoding="utf-8")


class PackageReleaseSmokeTests(unittest.TestCase):
    def run_packager(self, repo_root: pathlib.Path) -> int:
        module = load_module()
        with (
            mock.patch.object(module, "workspace_root", return_value=repo_root),
            mock.patch.object(module, "rust_host_triple", return_value="x86_64-unknown-linux-gnu"),
            mock.patch.object(
                sys,
                "argv",
                ["package_release.py", "--tag", "v0.0.0"],
            ),
        ):
            return module.main()

    def test_packager_creates_assets_when_dist_is_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="veil_packager_") as td:
            repo_root = pathlib.Path(td)
            write_fixture_repo(repo_root)

            rc = self.run_packager(repo_root)

            self.assertEqual(rc, 0)
            archive = repo_root / "dist" / "veil-v0.0.0-x86_64-unknown-linux-gnu.zip"
            checksum = repo_root / "dist" / "veil-v0.0.0-x86_64-unknown-linux-gnu.sha256"
            self.assertTrue(archive.is_file())
            self.assertTrue(checksum.is_file())

            with zipfile.ZipFile(archive) as zf:
                self.assertEqual(
                    sorted(zf.namelist()),
                    ["LICENSE", "README.md", "veil"],
                )

    def test_packager_replaces_preexisting_dist_contents(self) -> None:
        with tempfile.TemporaryDirectory(prefix="veil_packager_") as td:
            repo_root = pathlib.Path(td)
            write_fixture_repo(repo_root)
            dist = repo_root / "dist"
            dist.mkdir(parents=True, exist_ok=True)
            (dist / "stale.txt").write_text("old\n", encoding="utf-8")

            rc = self.run_packager(repo_root)

            self.assertEqual(rc, 0)
            self.assertFalse((dist / "stale.txt").exists())
            self.assertTrue(
                (dist / "veil-v0.0.0-x86_64-unknown-linux-gnu.zip").is_file()
            )
            self.assertTrue(
                (dist / "veil-v0.0.0-x86_64-unknown-linux-gnu.sha256").is_file()
            )


if __name__ == "__main__":
    unittest.main()
