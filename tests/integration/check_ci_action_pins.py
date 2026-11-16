#!/usr/bin/env python3
"""Narrow, dependency-free source policy: commit-pin external GitHub Actions."""
from __future__ import annotations
import re
import sys
from pathlib import Path

USES = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*(.*?)\s*$")
PIN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}\Z")
LOCAL = re.compile(r"\./\.github/actions/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\Z")
WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"

def parse_value(raw: str) -> str:
    raw = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
    if raw.startswith(("'", '"')):
        if len(raw) < 2 or raw[-1] != raw[0]:
            return ""
        raw = raw[1:-1]
    return raw

def check_text(source: str, name: str) -> tuple[list[str], int]:
    errors = []
    count = 0
    for number, line in enumerate(source.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        match = USES.match(line)
        if match is None:
            continue
        count += 1
        ref = parse_value(match.group(1))
        if PIN.fullmatch(ref) or LOCAL.fullmatch(ref):
            continue
        errors.append(f"{name}:{number}: floating or invalid uses reference: {ref!r}")
    return errors, count

def check_directory(directory: Path) -> list[str]:
    paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    if not paths:
        return [f"{directory}: no workflow files found"]
    errors = []
    count = 0
    for path in paths:
        found, refs = check_text(path.read_text(encoding="utf-8"), str(path))
        errors.extend(found)
        count += refs
    if not count:
        errors.append(f"{directory}: no uses references discovered")
    return errors

if __name__ == "__main__":
    errors = check_directory(WORKFLOWS)
    if errors:
        print("GitHub Action immutable SHA policy FAILED", file=sys.stderr)
        for error in errors:
            print("  " + error, file=sys.stderr)
        sys.exit(1)
    print("GitHub Action references: all external uses pinned to full commit SHA")
