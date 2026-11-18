#!/usr/bin/env python3
"""Publish a strictly scoped four-core-job commit status (ADR 0070, #101).

Only the separate status-writing CI job invokes main(). Unit tests operate
offline. The workflow retains read-only permissions everywhere else.
This GitHub-reported status is NOT independent build/release attestation.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

CORE_JOBS = ("backend", "frontend", "docker-smoke", "terraform")
KNOWN_RESULTS = frozenset(("success", "failure", "cancelled", "skipped"))
STATUS_CONTEXT = "temporalmark/ci-4-core-jobs"


def parse_needs(raw: str) -> object:
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def build_verdict(needs: object) -> tuple[str, str]:
    """A malformed/incomplete/unexpected dependency set can NEVER be green."""
    exact_keys = (
        isinstance(needs, dict) and
        set(needs.keys()) == set(CORE_JOBS)
    )
    sanitized: list[str] = []
    all_success = exact_keys
    for name in CORE_JOBS:
        entry = needs.get(name) if isinstance(needs, dict) else None
        value = entry.get("result") if isinstance(entry, dict) else None
        valid = isinstance(value, str) and value in KNOWN_RESULTS
        normalized = value if valid else "unknown"
        sanitized.append(f"{name}={normalized}")
        if normalized != "success":
            all_success = False
    state = "success" if all_success else "failure"
    # No raw job outputs, arbitrary values, runner variables or secrets.
    description = " ".join(sanitized)
    if len(description) > 140:
        raise AssertionError("Fixed four-job description unexpectedly exceeds limit")
    return state, description


def validate_target(repository: str, sha: str, run_id: str,
                    attempt: str, ref: str, event: str) -> str:
    """Reject ambiguous commit identity or off-main publishing."""
    if not isinstance(repository, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*",
            repository):
        raise ValueError("Invalid repository")
    if any(piece in (".", "..") for piece in repository.split("/")):
        raise ValueError("Invalid repository")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Invalid full commit SHA")
    for value in (run_id, attempt):
        if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value):
            raise ValueError("Invalid workflow identity")
    if ref != "refs/heads/main" or event not in ("push", "workflow_dispatch"):
        raise ValueError("Commit status must be published from main only")
    return f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{attempt}"


def make_payload(needs: object, target_url: str) -> dict[str, str]:
    state, description = build_verdict(needs)
    return {
        "state": state,
        "context": STATUS_CONTEXT,
        "description": description,
        "target_url": target_url,
    }


def publish_status(repository: str, sha: str,
                   token: str, payload: dict[str, str]) -> None:
    if not token or not isinstance(token, str):
        raise ValueError("Missing workflow status-writer token")
    url = f"https://api.github.com/repos/{repository}/statuses/{sha}"
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "TemporalMark-CI-verdict",
            "X-GitHub-Api-Version": "2022-11-28",
        })
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 201:
            raise RuntimeError("GitHub refused CI status publication")


def main() -> int:
    try:
        env = os.environ
        repository = env.get("GITHUB_REPOSITORY", "")
        sha = env.get("GITHUB_SHA", "")
        target_url = validate_target(
            repository, sha,
            env.get("GITHUB_RUN_ID", ""),
            env.get("GITHUB_RUN_ATTEMPT", ""),
            env.get("GITHUB_REF", ""),
            env.get("GITHUB_EVENT_NAME", ""))
        payload = make_payload(parse_needs(env.get("CORE_JOB_NEEDS", "")), target_url)
        publish_status(repository, sha, env.get("GH_TOKEN", ""), payload)
        print(f"CI four-core-job verdict posted for SHA {sha}: {payload['state']}")
        summary_path = env.get("GITHUB_STEP_SUMMARY", "")
        if summary_path:
            with Path(summary_path).open("a", encoding="utf-8") as summary:
                summary.write(
                    f"### Four-core-job CI verdict: {payload['state']}\n\n"
                    f"Commit: `{sha}`  \n"
                    f"Core job results: `{payload['description']}`  \n"
                    f"Workflow attempt: {target_url}\n\n"
                    "GitHub-reported job results only; not a signed production attestation.\n")
        return 0
    except (ValueError, OSError, RuntimeError, urllib.error.URLError) as error:
        # Avoid printing raw external HTTP messages or the bearer token.
        print(f"CI status publication failed ({type(error).__name__}); "
              "this commit has no verified success verdict.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
