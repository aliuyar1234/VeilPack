import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time


SCHEMA_VERSION = "perf.v1"
DEFAULT_BASELINE_PATH = pathlib.Path("checks") / "perf_baseline.json"


def repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def default_veil_bin_path(root: pathlib.Path) -> pathlib.Path:
    exe = "veil.exe" if os.name == "nt" else "veil"
    return root / "target" / "release" / exe


def detect_tool_version(root: pathlib.Path) -> str:
    cargo_toml = root / "crates" / "veil-cli" / "Cargo.toml"
    txt = cargo_toml.read_text(encoding="utf-8", errors="ignore")

    in_package = False
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_package = line == "[package]"
            continue
        if not in_package:
            continue
        if line.startswith("version"):
            m = re.match(r'version\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    return ""


def build_release(root: pathlib.Path) -> None:
    subprocess.run(
        ["cargo", "build", "-p", "veil-cli", "--release"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def write_policy(dir_path: pathlib.Path, pattern: str) -> None:
    policy = {
        "schema_version": "policy.v1",
        "classes": [
            {
                "class_id": "PII.Perf",
                "severity": "HIGH",
                "detectors": [{"kind": "regex", "pattern": pattern}],
                "action": {"kind": "REDACT"},
            }
        ],
        "defaults": {},
        "scopes": [],
    }
    (dir_path / "policy.json").write_text(json.dumps(policy, separators=(",", ":")), encoding="utf-8")


def write_fixture_corpus(dir_path: pathlib.Path) -> int:
    dir_path.mkdir(parents=True, exist_ok=True)

    # Deterministic synthetic corpus (non-sensitive).
    token = "SECRET"
    blob = (token + "\n") * 128  # ~768 bytes
    total = 0

    for i in range(400):
        p = dir_path / f"t{i:04d}.txt"
        data = (blob + f"file={i}\n").encode("utf-8")
        p.write_bytes(data)
        total += len(data)

    for i in range(200):
        p = dir_path / f"j{i:04d}.json"
        obj = {"a": i, "b": token, "c": [token, i, {"k": token}]}
        data = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        p.write_bytes(data)
        total += len(data)

    return total


def run_once(veil_bin: pathlib.Path, input_dir: pathlib.Path, output_dir: pathlib.Path, policy_dir: pathlib.Path) -> dict:
    start = time.perf_counter()
    proc = subprocess.run(
        [
            str(veil_bin),
            "run",
            "--input",
            str(input_dir),
            "--output",
            str(output_dir),
            "--policy",
            str(policy_dir),
            "--max-workers",
            "1",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    elapsed_s = time.perf_counter() - start
    if proc.returncode != 0:
        raise RuntimeError(f"veil run failed with code {proc.returncode}:\n{proc.stdout}")

    corpus_bytes = sum(p.stat().st_size for p in input_dir.glob("*") if p.is_file())
    throughput = 0.0 if elapsed_s <= 0 else (corpus_bytes / elapsed_s)

    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": "",
        "profile": "release",
        "corpus": {"files": len([p for p in input_dir.glob('*') if p.is_file()]), "bytes": corpus_bytes},
        "elapsed_ms": int(round(elapsed_s * 1000.0)),
        "throughput_bytes_per_sec": throughput,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--veil-bin", type=pathlib.Path, default=None, help="Path to built veil binary (release)")
    ap.add_argument("--build", action="store_true", help="Build release binary before running")
    ap.add_argument("--baseline", type=pathlib.Path, default=DEFAULT_BASELINE_PATH, help="Baseline JSON path")
    ap.add_argument("--record-baseline", action="store_true", help="Record baseline (overwrite requires --decision-id)")
    ap.add_argument("--decision-id", type=str, default=None, help="Required to overwrite an existing baseline")
    ap.add_argument("--tolerance", type=float, default=0.15, help="Allowed regression ratio (e.g., 0.15 == 15%)")
    args = ap.parse_args()

    root = repo_root()
    baseline_path = (root / args.baseline).resolve()

    if args.build:
        build_release(root)

    veil_bin = args.veil_bin
    if veil_bin is None:
        veil_bin = default_veil_bin_path(root)
    veil_bin = (root / veil_bin) if not veil_bin.is_absolute() else veil_bin

    if not veil_bin.exists():
        raise SystemExit(f"veil binary not found: {veil_bin} (use --build or --veil-bin)")

    with tempfile.TemporaryDirectory(prefix="veil_perf_") as td:
        td = pathlib.Path(td)
        input_dir = td / "input"
        policy_dir = td / "policy"
        output_dir = td / "output"
        policy_dir.mkdir(parents=True, exist_ok=True)
        write_policy(policy_dir, "SECRET")
        write_fixture_corpus(input_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        metrics = run_once(veil_bin, input_dir, output_dir, policy_dir)
        metrics["tool_version"] = detect_tool_version(root)

    if args.record_baseline:
        if baseline_path.exists() and not args.decision_id:
            raise SystemExit(
                "refusing to overwrite existing baseline without --decision-id (log a decision with mitigation)"
            )
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
        print(f"WROTE_BASELINE {baseline_path}")
        print(json.dumps(metrics, indent=2, sort_keys=True))
        return 0

    if not baseline_path.exists():
        raise SystemExit(f"baseline missing: {baseline_path} (run with --record-baseline)")

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    base_tp = float(baseline.get("throughput_bytes_per_sec", 0.0))
    cur_tp = float(metrics.get("throughput_bytes_per_sec", 0.0))

    floor = base_tp * (1.0 - float(args.tolerance))
    ok = cur_tp >= floor

    print(f"BASELINE_THROUGHPUT {base_tp:.2f}")
    print(f"CURRENT_THROUGHPUT {cur_tp:.2f}")
    print(f"TOLERANCE {args.tolerance:.2f}")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
