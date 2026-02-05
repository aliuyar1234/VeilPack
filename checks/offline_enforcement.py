import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


DENY_RUST_PATTERNS = [
    r"\bstd::net::",
    r"\btokio::net::",
    r"\basync_std::net::",
    r"\breqwest::",
    r"\bhyper::",
    r"\bureq::",
    r"\bcurl::",
    r"\bsocket2::",
    r"\bTcpStream\b",
    r"\bUdpSocket\b",
    r"\bIpAddr\b",
    r"\bSocketAddr\b",
]

# Dependency names in Cargo.lock that are commonly associated with networking.
DENY_CRATES = {
    "reqwest",
    "hyper",
    "ureq",
    "curl",
    "socket2",
    "tokio",
    "async-std",
    "smol",
}


def iter_rust_sources():
    for p in (ROOT / "crates").rglob("src/**/*.rs"):
        if p.is_file():
            yield p


def scan_sources() -> list[str]:
    hits = []
    pats = [re.compile(p) for p in DENY_RUST_PATTERNS]
    for p in iter_rust_sources():
        txt = p.read_text(errors="ignore")
        for pat in pats:
            if pat.search(txt):
                hits.append(f"SRC {p.as_posix()} matched {pat.pattern}")
    return hits


def scan_lockfile() -> list[str]:
    lock = ROOT / "Cargo.lock"
    if not lock.exists():
        return [f"MISSING {lock.as_posix()}"]
    txt = lock.read_text(errors="ignore")
    hits = []
    for name in sorted(DENY_CRATES):
        if re.search(rf'name = "{re.escape(name)}"', txt):
            hits.append(f"LOCK Cargo.lock includes crate {name}")
    return hits


def main() -> int:
    hits = []
    hits.extend(scan_lockfile())
    hits.extend(scan_sources())

    if hits:
        for h in hits:
            print(h)
        print("FAIL")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

