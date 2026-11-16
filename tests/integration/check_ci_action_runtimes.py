#!/usr/bin/env python3
"""Offline source allowlist for upstream-verified native Node 24 actions (ADR 0050).

An action's runtime was verified independently from its exact upstream
action.yml and official Git tag. Do not infer runtime from the SHA or comment.
"""
from __future__ import annotations

import sys
from pathlib import Path

import check_ci_action_pins as sha_policy

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

# Upstream official git tag dereferences + exact-SHA action.yml runs.using=node24,
# independently reviewed 2026-11-16. The map is a release policy, not a network query.
NATIVE_NODE24 = {
    "actions/checkout": "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",  # v5
    "actions/setup-node": "a0853c24544627f65ddf259abe73b1d18a591444",  # v5
    "actions/setup-dotnet": "26b0ec14cb23fa6904739307f278c14f94c95bf1",  # v5
    "actions/upload-artifact": "b7c566a772e6b6bfb58ed0dc250532a479d7789f",  # v6
    "hashicorp/setup-terraform": "dfe3c3f87815947d99a8997f908cb6525fc44e9e",  # v4
}
KNOWN_NODE20 = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "actions/setup-dotnet": "67a3573c9a986a3f9c594539f4ab511d57bb3ce9",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "hashicorp/setup-terraform": "b9cd54a3c349d3f38e8881555d616ced269862dd",
}


def check_text(source: str, name: str) -> tuple[list[str], set[str]]:
    errors: list[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(source.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        use = sha_policy.USES.match(line)
        if use is None:
            continue
        ref = sha_policy.parse_value(use.group(1))
        if sha_policy.LOCAL.fullmatch(ref):
            # The pre-existing full SHA source guard separately checks safe
            # local-action paths; this guard reviews only external runtimes.
            continue
        if not sha_policy.PIN.fullmatch(ref):
            errors.append(f"{name}:{line_number}: invalid or mutable action runtime reference: {ref!r}")
            continue
        action, sha = ref.rsplit("@", 1)
        if action in KNOWN_NODE20 and KNOWN_NODE20[action] == sha:
            errors.append(f"{name}:{line_number}: deprecated native node20 action {action}@{sha}")
        elif action in NATIVE_NODE24 and NATIVE_NODE24[action] == sha:
            seen.add(action)
        else:
            errors.append(f"{name}:{line_number}: unreviewed action SHA or external action: {ref!r}")
    return errors, seen


def check_directory(directory: Path) -> list[str]:
    paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    if not paths:
        return [f"{directory}: no workflow files found"]
    errors: list[str] = []
    observed: set[str] = set()
    for path in paths:
        failures, seen = check_text(path.read_text(encoding="utf-8"), str(path))
        errors.extend(failures)
        observed.update(seen)
    for action in sorted(NATIVE_NODE24.keys() - observed):
        errors.append(f"{directory}: required reviewed node24 action missing: {action}")
    return errors


if __name__ == "__main__":
    problems = check_directory(WORKFLOWS)
    if problems:
        print("Native Node 24 GitHub Actions source policy FAILED:", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        sys.exit(1)
    print("All external GitHub Actions: upstream-reviewed exact native node24 SHA allowlist")
