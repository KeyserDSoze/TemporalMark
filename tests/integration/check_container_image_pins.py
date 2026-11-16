#!/usr/bin/env python3
"""Narrow source guard for CI/dev Dockerfile and Compose images, ADR 0045."""
from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")
COMPONENT = re.compile(r"[a-z0-9][a-z0-9_.-]*(?::[0-9]+)?\Z")
FROM = re.compile(r"^\s*FROM\s+(.+?)\s*$", re.IGNORECASE)
IMAGE = re.compile(r"^\s*image\s*:\s*(.*?)\s*$")
STAGE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]*\Z")

def pinned_image(ref: str) -> bool:
    if ref.count("@") != 1 or any(c in ref for c in "$ {}'\"<>\\"):
        return False
    name_tag, digest = ref.split("@")
    if SHA.fullmatch(digest) is None or ":" not in name_tag:
        return False
    name, tag = name_tag.rsplit(":", 1)
    if TAG.fullmatch(tag) is None or tag.lower() in {"latest", "main", "stable", "edge"}:
        return False
    parts = name.split("/")
    return bool(parts) and all(COMPONENT.fullmatch(p) is not None and p not in {".", ".."} for p in parts)

def check_dockerfile(source: str, label: str) -> tuple[list[str], int]:
    errors = []
    stages: set[str] = set()
    count = 0
    for line_no, line in enumerate(source.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        match = FROM.match(line)
        if match is None:
            continue
        count += 1
        tokens = match.group(1).split()
        if len(tokens) == 1:
            ref, alias = tokens[0], None
        elif len(tokens) == 3 and tokens[1].lower() == "as" and STAGE.fullmatch(tokens[2]):
            ref, alias = tokens[0], tokens[2].lower()
        else:
            errors.append(f"{label}:{line_no}: dynamic or malformed FROM")
            continue
        if ref.lower() not in stages and not pinned_image(ref):
            errors.append(f"{label}:{line_no}: unpinned FROM image {ref}")
        if alias is not None:
            stages.add(alias)
    return errors, count

def check_compose(source: str, label: str) -> tuple[list[str], int]:
    errors = []
    count = 0
    for line_no, line in enumerate(source.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        match = IMAGE.match(line)
        if match is None:
            continue
        count += 1
        ref = re.split(r"\s+#", match.group(1), maxsplit=1)[0].strip()
        if len(ref) >= 2 and ref[0] in ("'", '"') and ref[-1] == ref[0]:
            ref = ref[1:-1]
        if not pinned_image(ref):
            errors.append(f"{label}:{line_no}: unpinned Compose image {ref}")
    return errors, count

def check_repository(root: Path) -> list[str]:
    errors = []
    required = (Path("src/backend/applications/TemporalMark.Api/Dockerfile"), Path("src/frontend/Dockerfile"))
    if any(not (root / p).is_file() for p in required):
        errors.append("Required application Dockerfile missing")
    sources = sorted(root.glob("src/**/Dockerfile*"))
    if not sources:
        errors.append("No Dockerfiles found")
    found = 0
    for path in sources:
        more, count = check_dockerfile(path.read_text(encoding="utf-8"), str(path.relative_to(root)))
        errors.extend(more)
        found += count
    if found < 4:
        errors.append("Expected at least four Dockerfile FROM declarations")
    comps = sorted([*(root / "docker").glob("compose*.yml"), *(root / "docker").glob("compose*.yaml")])
    if not comps or not (root / "docker/compose.yml").is_file():
        errors.append("Required Compose source missing")
    found = 0
    for path in comps:
        more, count = check_compose(path.read_text(encoding="utf-8"), str(path.relative_to(root)))
        errors.extend(more)
        found += count
    if found < 4:
        errors.append("Expected at least four Compose image references")
    return errors

if __name__ == "__main__":
    errors = check_repository(ROOT)
    if errors:
        print("Docker OCI digest source policy FAILED:", file=sys.stderr)
        for error in errors:
            print("  " + error, file=sys.stderr)
        sys.exit(1)
    print("Docker OCI digest source policy PASSED: all Dockerfile/Compose sources pinned")
