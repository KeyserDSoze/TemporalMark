#!/usr/bin/env python3
"""Deterministic CycloneDX 1.5 *npm lockfile inventory*, not an installed-binary SBOM.

No registry I/O, package imports, wall clock, authentication, or tokens.
The actual npm ci installation and container/runtime attestations are separate.
ADR 0046 / issue #77.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

from check_npm_lockfiles import verify_project

ROOT = Path(__file__).resolve().parents[2]
PROJECTS = {
    Path("src/frontend"): "pwa-lockfile.cdx.json",
    Path("tests/frontend"): "playwright-lockfile.cdx.json",
}
VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.+-]+)?\Z")
SRI = re.compile(r"(sha512|sha384|sha256|sha1)-([A-Za-z0-9+/]+={0,2})\Z")
ALG = {"sha512": ("SHA-512", 64), "sha384": ("SHA-384", 48),
       "sha256": ("SHA-256", 32), "sha1": ("SHA-1", 20)}


class InventoryError(ValueError):
    """Unusable or inconsistent source inventory; fail closed."""


def lock_name(location: str) -> str:
    if not location.startswith("node_modules/"):
        raise InventoryError(f"Unsupported npm package location: {location!r}")
    path = location.rsplit("node_modules/", 1)[-1]
    parts = path.split("/")
    if len(parts) == 1 and parts[0] and not parts[0].startswith("@"):
        return parts[0]
    if len(parts) == 2 and parts[0].startswith("@") and len(parts[0]) > 1 and parts[1]:
        return parts[0] + "/" + parts[1]
    raise InventoryError(f"Malformed npm package location: {location!r}")


def sri_hash(integrity: object) -> dict[str, str]:
    if not isinstance(integrity, str) or not (match := SRI.fullmatch(integrity)):
        raise InventoryError("Missing or noncanonical single npm SRI integrity hash")
    algorithm, b64 = match.groups()
    try:
        decoded = base64.b64decode(b64, validate=True)
    except (ValueError, binascii.Error) as error:
        raise InventoryError("Invalid base64 npm registry integrity") from error
    algorithm_name, expected_size = ALG[algorithm]
    if len(decoded) != expected_size or base64.b64encode(decoded).decode("ascii") != b64:
        raise InventoryError("Noncanonical or truncated npm registry integrity")
    return {"alg": algorithm_name, "content": decoded.hex()}


def package_component(location: str, entry: dict) -> dict:
    if not isinstance(entry, dict) or entry.get("link"):
        raise InventoryError(f"Unsupported npm linked package at {location!r}")
    name = lock_name(location)
    version = entry.get("version")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise InventoryError(f"Unpinned npm package at {location!r}")
    resolved = entry.get("resolved")
    if not isinstance(resolved, str) or not resolved.startswith("https://registry.npmjs.org/"):
        raise InventoryError(f"Non-registry source at {location!r}")
    purl_name = quote(name, safe="/")
    purl_version = quote(version, safe=".-_")
    return {
        "type": "library",
        "bom-ref": "npm-lock:" + location,
        "name": name,
        "version": version,
        "purl": f"pkg:npm/{purl_name}@{purl_version}",
        "hashes": [sri_hash(entry.get("integrity"))],
        "properties": [
            {"name": "temporalmark:npm:dev", "value": str(entry.get("dev") is True).lower()},
            {"name": "temporalmark:npm:optional", "value": str(entry.get("optional") is True).lower()},
        ],
    }


def make_inventory(lock_bytes: bytes, source: str) -> dict:
    try:
        lock = json.loads(lock_bytes)
    except (UnicodeError, ValueError) as error:
        raise InventoryError("Invalid npm package-lock JSON") from error
    if not isinstance(lock, dict) or lock.get("lockfileVersion") != 3:
        raise InventoryError("Required npm v10 lockfileVersion 3")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or len(packages) < 2:
        raise InventoryError("Missing npm resolved dependency tree")
    root = packages.get("")
    if not isinstance(root, dict) or not isinstance(root.get("name"), str) or not isinstance(root.get("version"), str):
        raise InventoryError("Missing npm root package identity")
    if root["name"] != lock.get("name") or root["version"] != lock.get("version"):
        raise InventoryError("Root package and lockfile identity mismatch")
    components = [package_component(location, packages[location])
                  for location in sorted(packages) if location]
    refs = [component["bom-ref"] for component in components]
    if len(set(refs)) != len(refs):
        raise InventoryError("Duplicate npm lock path component reference")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "npm-lock:root",
                "name": root["name"],
                "version": root["version"],
                "hashes": [{
                    "alg": "SHA-256",
                    "content": hashlib.sha256(lock_bytes).hexdigest(),
                }],
                "properties": [
                    {"name": "temporalmark:inventory", "value": "npm-lockfile-only"},
                    {"name": "temporalmark:sourceLockfile", "value": source},
                ],
            },
        },
        "components": components,
    }


def validate_inventory(bom: object, lock_bytes: bytes, source: str) -> None:
    """Compare all path-scoped component claims with original SRI-bearing lock bytes.

    Exact canonical comparison rejects extra or missing components, duplicate
    refs, modified hashes or purl, altered root/scope, and unknown claims.
    """
    if not isinstance(bom, dict):
        raise InventoryError("CycloneDX inventory must be a JSON object")
    expected = make_inventory(lock_bytes, source)
    components = bom.get("components")
    if not isinstance(components, list):
        raise InventoryError("Missing components array")
    refs = [x.get("bom-ref") if isinstance(x, dict) else None for x in components]
    if len(set(refs)) != len(refs) or None in refs:
        raise InventoryError("Duplicate or missing npm component references")
    if bom != expected:
        raise InventoryError("CycloneDX inventory differs from the exact source lockfile")


def process(root: Path, output: Path, operation: str) -> list[tuple[str, int]]:
    from check_npm_lockfiles import verify_project
    if operation not in {"generate", "verify"}:
        raise InventoryError("Unknown operation")
    results = []
    expected_files = {v for v in PROJECTS.values()}
    if operation == "verify":
        if not output.is_dir() or {p.name for p in output.glob("*.json")} != expected_files:
            raise InventoryError("Expected exactly two npm lockfile CycloneDX JSON files")
    else:
        output.mkdir(parents=True, exist_ok=True)
    for project, filename in PROJECTS.items():
        errors = verify_project(root, project)
        if errors:
            raise InventoryError("; ".join(errors))
        lock_bytes = (root / project / "package-lock.json").read_bytes()
        source = str(project / "package-lock.json")
        path = output / filename
        if operation == "generate":
            inventory = make_inventory(lock_bytes, source)
            path.write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        else:
            try:
                inventory = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise InventoryError(f"Unparseable inventory {filename}") from error
        validate_inventory(inventory, lock_bytes, source)
        results.append((filename, len(inventory["components"])))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="CI-only npm lockfile CycloneDX 1.5 inventory")
    parser.add_argument("operation", choices=("generate", "verify"))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        rows = process(ROOT, args.output_dir, args.operation)
    except (InventoryError, OSError, ValueError) as error:
        print(f"npm SBOM inventory {args.operation} FAILED: {error}", file=sys.stderr)
        return 1
    for filename, count in rows:
        print(f"npm SBOM {args.operation} PASSED: {filename}, {count} lockfile dependency entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
