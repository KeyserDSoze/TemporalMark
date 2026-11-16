#!/usr/bin/env python3
"""CI source policy for BOTH npm v10 lockfiles; no npm dependencies required.

This checks committed metadata and registry integrity; npm ci is the actual
resolution/installation authority and will reject lock/manifest drift.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECTS = (Path("src/frontend"), Path("tests/frontend"))
VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?\Z")
INTEGRITY = re.compile(r"(?:sha512|sha384|sha256|sha1)-[A-Za-z0-9+/]+={0,2}\Z")


def verify_project(root: Path, directory: Path) -> list[str]:
    errors: list[str] = []
    package_path = root / directory / "package.json"
    lock_path = root / directory / "package-lock.json"
    if not package_path.is_file() or not lock_path.is_file():
        return [f"{directory}: both package.json and committed package-lock.json required"]
    try:
        package = json.loads(package_path.read_text(encoding="utf-8"))
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as error:
        return [f"{directory}: invalid manifest/lockfile JSON: {error}"]
    if lock.get("lockfileVersion") != 3:
        errors.append(f"{directory}: npm v10 lockfileVersion 3 required")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or len(packages) < 2:
        return errors + [f"{directory}: lockfile must contain resolved package tree"]
    root_entry = packages.get("")
    if not isinstance(root_entry, dict):
        return errors + [f"{directory}: missing root entry in lockfile"]
    for key in ("name", "version"):
        if root_entry.get(key) != package.get(key) or lock.get(key) != package.get(key):
            errors.append(f"{directory}: manifest and lockfile root {key} mismatch")
    for kind in ("dependencies", "devDependencies", "optionalDependencies"):
        if root_entry.get(kind, {}) != package.get(kind, {}):
            errors.append(f"{directory}: {kind} differs between manifest and lockfile")
    for location, value in packages.items():
        if not location:
            continue
        if not isinstance(value, dict):
            errors.append(f"{directory}: malformed package entry {location}")
            continue
        if value.get("link"):
            errors.append(f"{directory}: symlink package entry not permitted: {location}")
            continue
        if not VERSION.fullmatch(str(value.get("version", ""))):
            errors.append(f"{directory}: non-fixed package version at {location}")
        url = value.get("resolved", "")
        if not isinstance(url, str) or not url.startswith("https://registry.npmjs.org/"):
            errors.append(f"{directory}: registry tarball URL missing or not HTTPS at {location}")
        if not INTEGRITY.fullmatch(str(value.get("integrity", ""))):
            errors.append(f"{directory}: registry integrity missing/invalid at {location}")
    return errors


def verify_repository(root: Path) -> list[str]:
    errors: list[str] = []
    for directory in PROJECTS:
        errors.extend(verify_project(root, directory))
    workflow = root / ".github/workflows/ci.yml"
    dockerfile = root / "src/frontend/Dockerfile"
    if not workflow.is_file() or not dockerfile.is_file():
        return errors + ["Required CI or Dockerfile source missing"]
    ci = workflow.read_text(encoding="utf-8")
    docker = dockerfile.read_text(encoding="utf-8")
    if re.search(r"\bnpm\s+install\b", ci + "\n" + docker):
        errors.append("CI and web Dockerfile must use npm ci, not npm install")
    if ci.count("npm ci --no-audit --no-fund") < 3:
        errors.append("Both browser projects must use npm ci in frontend and Docker smoke jobs")
    if "npm ci --no-audit --no-fund" not in docker:
        errors.append("Docker web build must use npm ci")
    if "package-lock.json" not in docker.split("RUN npm ci", 1)[0]:
        errors.append("Docker build must COPY package-lock before npm ci")
    return errors


if __name__ == "__main__":
    failures = verify_repository(ROOT)
    if failures:
        print("npm dependency integrity policy FAILED:", file=sys.stderr)
        for failure in failures:
            print("  " + failure, file=sys.stderr)
        sys.exit(1)
    print("npm dependency integrity policy passed for both manifests and clean installs")
