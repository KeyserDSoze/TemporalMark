#!/usr/bin/env python3
"""Fail-closed NuGet packages.lock.json and CI/Docker restore policy. ADR 0048.

Only package inventory metadata is read; no feed queries, secrets or binaries.
The authoritative dependency-graph check is still real dotnet --locked-mode.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.+-]+)?\Z")
KINDS = {"Direct", "Transitive", "CentralTransitive", "Project"}


def project_paths(root: Path) -> list[Path]:
    projects = sorted({
        *(p.relative_to(root) for p in (root / "src/backend").rglob("*.csproj")),
        *(p.relative_to(root) for p in (root / "tests/backend").rglob("*.csproj"))
    }, key=str)
    return projects


def project_references(csproj: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    tree = ET.parse(csproj)
    for ref in tree.iter():
        if ref.tag.split("}")[-1] != "PackageReference":
            continue
        name = ref.get("Include", "")
        version = ref.get("Version", "")
        if not version:
            for element in ref:
                if element.tag.split("}")[-1] == "Version":
                    version = (element.text or "").strip()
                    break
        if not name or not SEMVER.fullmatch(version) or name.lower() in result:
            raise ValueError("Invalid, floating or repeated direct PackageReference")
        result[name.lower()] = version
    return result


def canonical_sha512(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(decoded) == 64 and base64.b64encode(decoded).decode("ascii") == value


def check_project(root: Path, path: Path) -> list[str]:
    errors: list[str] = []
    full = root / path
    lock_path = full.parent / "packages.lock.json"
    if not full.is_file() or not lock_path.is_file():
        return [f"{path}: checked-in packages.lock.json required beside .csproj"]
    try:
        direct = project_references(full)
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, ET.ParseError) as error:
        return [f"{path}: invalid csproj or lock JSON: {error}"]
    if not isinstance(lock, dict) or lock.get("version") not in (1, 2, 3):
        return [f"{path}: unsupported NuGet lockfile schema version"]
    targets = lock.get("dependencies")
    if not isinstance(targets, dict):
        return [f"{path}: missing NuGet target dependency mapping"]
    if not targets and direct:
        errors.append(f"{path}: direct package declarations but no target locks")
    for target, entries in targets.items():
        if not isinstance(target, str) or not target.startswith("net10.0") or not isinstance(entries, dict):
            errors.append(f"{path}: unexpected target framework in lock")
            continue
        actual_direct: dict[str, str] = {}
        for package, info in entries.items():
            if not isinstance(package, str) or not package or not isinstance(info, dict):
                errors.append(f"{path}: malformed NuGet lock package entry")
                continue
            kind = info.get("type")
            if kind not in KINDS:
                errors.append(f"{path}: unknown NuGet dependency kind {kind!r} at {package}")
                continue
            if kind == "Project":
                continue
            version = info.get("resolved")
            if not isinstance(version, str) or not SEMVER.fullmatch(version):
                errors.append(f"{path}: unresolved/nonfixed NuGet version at {package}")
            if not canonical_sha512(info.get("contentHash")):
                errors.append(f"{path}: invalid/missing canonical SHA512 at {package}")
            if kind == "Direct":
                actual_direct[package.lower()] = version
        for name, version in direct.items():
            if actual_direct.get(name) != version:
                errors.append(f"{path}: direct PackageReference drift for {name}: expected {version}")
        for name in actual_direct:
            if name not in direct:
                errors.append(f"{path}: unexpected direct lock package {name}")
    return errors


def check_workflow(workflow: str, dockerfile: str) -> list[str]:
    errors: list[str] = []
    if "\n  backend:\n" not in workflow or "\n  frontend:\n" not in workflow:
        return ["Missing backend/frontend workflow scope"]
    backend = workflow.split("\n  backend:\n", 1)[1].split("\n  frontend:\n", 1)[0]
    restore = 'dotnet restore "$project" --locked-mode'
    source = "find src/backend tests/backend -type f -name '*.csproj'"
    at = backend.find(restore)
    if at < 0 or source not in backend or at >= backend.find("      - name: Domain tests"):
        errors.append("All nine .NET projects must be restored in locked mode BEFORE backend tests")
    if backend.count(restore) != 1:
        errors.append("Exactly one all-project locked restore loop required")
    if "test \"$(printf '%s" not in backend or " -eq 9" not in backend:
        errors.append("Backend locked restore must assert exactly nine projects")
    for line in backend.splitlines():
        if "run: dotnet test " in line or "run: dotnet publish " in line:
            if "--no-restore" not in line and "-p:RestoreLockedMode=true" not in line:
                errors.append("Backend build/test must not implicitly use an unlocked restore")
        if "dotnet run --project " in line and "--no-restore" not in line:
            errors.append("Backend dotnet run must not use an implicit unlocked restore")
    if "--force-evaluate" in backend or "RestoreForceEvaluate" in backend:
        errors.append("Force-evaluate contradicts locked-mode restore")
    if "-p:RestoreLockedMode=true" not in dockerfile:
        errors.append("API Dockerfile must fail closed on unlocked NuGet publication")
    return errors


def check_repository(root: Path) -> list[str]:
    errors: list[str] = []
    projects = project_paths(root)
    if len(projects) != 9:
        errors.append(f"Expected nine .NET csproj projects; found {len(projects)}")
    locks = {p.relative_to(root) for base in ("src/backend", "tests/backend")
             for p in (root / base).rglob("packages.lock.json")}
    expected = {p.parent / "packages.lock.json" for p in projects}
    if locks != expected:
        errors.append(f"NuGet lockfile discovery mismatch: expected {len(expected)}, found {len(locks)}")
    for project in projects:
        errors.extend(check_project(root, project))
    workflow = root / ".github/workflows/ci.yml"
    docker = root / "src/backend/applications/TemporalMark.Api/Dockerfile"
    if not workflow.is_file() or not docker.is_file():
        errors.append("Required CI workflow or API Dockerfile absent")
    else:
        errors.extend(check_workflow(workflow.read_text(encoding="utf-8"), docker.read_text(encoding="utf-8")))
    return errors


if __name__ == "__main__":
    problems = check_repository(ROOT)
    if problems:
        print("NuGet locked restore source policy FAILED:", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        sys.exit(1)
    print("NuGet lockfiles verified: all nine project trees and locked CI/Docker restores")
