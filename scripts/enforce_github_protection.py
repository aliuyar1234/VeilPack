#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
RELEASE_TAG_RULESET_NAME = "Protect release tags"


def run(cmd: list[str], stdin: str | None = None) -> str:
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")
    return proc.stdout


def gh_api(path: str, method: str = "GET", payload: dict | None = None) -> dict | list | None:
    cmd = ["gh", "api", path]
    if method != "GET":
        cmd.extend(["-X", method])
    if payload is not None:
        cmd.extend(["--input", "-"])
        stdout = run(cmd, stdin=json.dumps(payload))
    else:
        stdout = run(cmd)
    stdout = stdout.strip()
    if not stdout:
        return None
    return json.loads(stdout)


def detect_repo() -> str:
    remote = run(["git", "remote", "get-url", "origin"]).strip()
    patterns = [
        r"^https://github\.com/([^/]+/[^/.]+)(?:\.git)?$",
        r"^git@github\.com:([^/]+/[^/.]+)(?:\.git)?$",
    ]
    for pattern in patterns:
        match = re.match(pattern, remote)
        if match:
            return match.group(1)
    raise RuntimeError(f"could not determine GitHub repository from remote: {remote}")


def default_branch(repo: str) -> str:
    data = json.loads(
        run(
            [
                "gh",
                "repo",
                "view",
                repo,
                "--json",
                "defaultBranchRef",
            ]
        )
    )
    return data["defaultBranchRef"]["name"]


def branch_protection_payload(current: dict, required_check: str) -> dict:
    status_checks = current.get("required_status_checks") or {}
    reviews = current.get("required_pull_request_reviews")

    return {
        "required_status_checks": {
            "strict": bool(status_checks.get("strict", True)),
            "contexts": [required_check],
        },
        "enforce_admins": bool((current.get("enforce_admins") or {}).get("enabled", False)),
        "required_pull_request_reviews": (
            {
                "dismiss_stale_reviews": bool(reviews.get("dismiss_stale_reviews", False)),
                "require_code_owner_reviews": bool(
                    reviews.get("require_code_owner_reviews", False)
                ),
                "require_last_push_approval": bool(
                    reviews.get("require_last_push_approval", False)
                ),
                "required_approving_review_count": int(
                    reviews.get("required_approving_review_count", 0)
                ),
            }
            if reviews is not None
            else None
        ),
        "restrictions": current.get("restrictions"),
        "required_linear_history": bool(
            (current.get("required_linear_history") or {}).get("enabled", False)
        ),
        "allow_force_pushes": bool(
            (current.get("allow_force_pushes") or {}).get("enabled", False)
        ),
        "allow_deletions": bool((current.get("allow_deletions") or {}).get("enabled", False)),
        "block_creations": bool((current.get("block_creations") or {}).get("enabled", False)),
        "required_conversation_resolution": bool(
            (current.get("required_conversation_resolution") or {}).get("enabled", False)
        ),
        "lock_branch": bool((current.get("lock_branch") or {}).get("enabled", False)),
        "allow_fork_syncing": bool(
            (current.get("allow_fork_syncing") or {}).get("enabled", False)
        ),
    }


def tag_ruleset_payload(repo: str, tag_pattern: str) -> dict:
    return {
        "name": RELEASE_TAG_RULESET_NAME,
        "target": "tag",
        "source_type": "Repository",
        "source": repo,
        "enforcement": "active",
        "conditions": {
            "ref_name": {
                "include": [tag_pattern],
                "exclude": [],
            }
        },
        "rules": [
            {"type": "update"},
            {"type": "deletion"},
        ],
        "bypass_actors": [],
    }


def find_release_tag_ruleset(repo: str) -> dict | None:
    rulesets = gh_api(f"repos/{repo}/rulesets")
    assert isinstance(rulesets, list)
    for ruleset in rulesets:
        if ruleset.get("name") == RELEASE_TAG_RULESET_NAME:
            return ruleset
    return None


def apply(repo: str, branch: str, required_check: str, tag_pattern: str) -> None:
    current = gh_api(f"repos/{repo}/branches/{branch}/protection")
    assert isinstance(current, dict)
    branch_payload = branch_protection_payload(current, required_check)
    gh_api(
        f"repos/{repo}/branches/{branch}/protection",
        method="PUT",
        payload=branch_payload,
    )

    ruleset_payload = tag_ruleset_payload(repo, tag_pattern)
    existing_ruleset = find_release_tag_ruleset(repo)
    if existing_ruleset is None:
        gh_api(f"repos/{repo}/rulesets", method="POST", payload=ruleset_payload)
    else:
        gh_api(
            f"repos/{repo}/rulesets/{existing_ruleset['id']}",
            method="PUT",
            payload=ruleset_payload,
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=None, help="owner/name; defaults to origin remote")
    ap.add_argument("--branch", default=None, help="branch to protect; defaults to repo default")
    ap.add_argument("--required-check", default="ci-required")
    ap.add_argument("--tag-pattern", default="refs/tags/v*")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    repo = args.repo or detect_repo()
    branch = args.branch or default_branch(repo)

    current = gh_api(f"repos/{repo}/branches/{branch}/protection")
    assert isinstance(current, dict)
    branch_payload = branch_protection_payload(current, args.required_check)
    ruleset_payload = tag_ruleset_payload(repo, args.tag_pattern)

    if args.dry_run:
        print("BRANCH_PROTECTION")
        print(json.dumps(branch_payload, indent=2, sort_keys=True))
        print("TAG_RULESET")
        print(json.dumps(ruleset_payload, indent=2, sort_keys=True))
        return 0

    apply(repo, branch, args.required_check, args.tag_pattern)
    print(f"APPLIED repo={repo} branch={branch} required_check={args.required_check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
