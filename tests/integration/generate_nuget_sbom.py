#!/usr/bin/env python3
"""CI-only CycloneDX 1.5 NuGet *restore* inventory; not a locked or installed SBOM.

Reads authentic SDK project.assets.json. No NuGet feed requests, credentials,
build artifacts, security verdicts, timestamps, signed provenance or secrets.
ADR 0047 / #78.
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

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_NAME = "nuget-restored.cdx.json"
LIBRARY = re.compile(r"([A-Za-z0-9_.-]+)/(\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.+-]+)?)\Z")


class RestoreInventoryError(ValueError):
    """Missing, malformed, or unsupported NuGet restore evidence."""


def project_list(root: Path) -> list[Path]:
    projects = sorted({
        *(p.relative_to(root) for p in (root / "src/backend").rglob("*.csproj")),
        *(p.relative_to(root) for p in (root / "tests/backend").rglob("*.csproj")),
    }, key=str)
    if len(projects) != 9:
        raise RestoreInventoryError(
            f"Expected exactly 9 .NET projects, found {len(projects)}; review inventory scope"
        )
    return projects


def hash512(integrity: object) -> str:
    if not isinstance(integrity, str) or not integrity:
        raise RestoreInventoryError("NuGet package sha512 metadata required")
    value = integrity.removeprefix("sha512-")
    try:
        digest = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as e:
        raise RestoreInventoryError("Invalid NuGet SHA-512 base64") from e
    if len(digest) != 64 or base64.b64encode(digest).decode("ascii") != value:
        raise RestoreInventoryError("Truncated or noncanonical NuGet SHA-512")
    return digest.hex()


def parse_assets(contents: bytes, project: Path) -> tuple[list[dict], dict]:
    try:
        assets = json.loads(contents)
    except (UnicodeError, ValueError) as e:
        raise RestoreInventoryError(f"Invalid NuGet assets for {project}") from e
    if not isinstance(assets, dict) or assets.get("version") != 3:
        raise RestoreInventoryError(f"Expected NuGet assets v3 for {project}")
    if not isinstance(assets.get("targets"), dict) or not assets["targets"]:
        raise RestoreInventoryError(f"Missing restored target frameworks in {project}")
    libraries = assets.get("libraries")
    if not isinstance(libraries, dict):
        raise RestoreInventoryError(f"Missing NuGet libraries map in {project}")
    components = []
    for identity in sorted(libraries):
        library = libraries[identity]
        if not isinstance(library, dict):
            raise RestoreInventoryError(f"Malformed NuGet library {identity} in {project}")
        kind = library.get("type")
        if kind == "project":
            continue
        if kind != "package":
            raise RestoreInventoryError(f"Unsupported NuGet library kind {kind!r} for {identity}")
        match = LIBRARY.fullmatch(identity)
        if match is None:
            raise RestoreInventoryError(f"Malformed NuGet package identity {identity!r}")
        name, version = match.groups()
        if any(c in name for c in "/\\"):
            raise RestoreInventoryError(f"Invalid NuGet package name {name!r}")
        component = {
            "type": "library",
            "bom-ref": "nuget-assets:" + str(project) + ":" + identity,
            "name": name,
            "version": version,
            "purl": f"pkg:nuget/{quote(name, safe='.-_')}@{quote(version, safe='.-_')}",
            "hashes": [{"alg": "SHA-512", "content": hash512(library.get("sha512"))}],
            "properties": [
                {"name": "temporalmark:nuget:sourceProject", "value": str(project)},
                {"name": "temporalmark:nuget:identity", "value": identity},
            ],
        }
        components.append(component)
    return components, {"sha256": hashlib.sha256(contents).hexdigest(), "packages": len(components)}


def make_inventory(root: Path, projects: list[Path] | None = None) -> dict:
    selected = project_list(root) if projects is None else projects
    if not selected:
        raise RestoreInventoryError("NuGet project inventory cannot be empty")
    if len(set(selected)) != len(selected):
        raise RestoreInventoryError("Duplicate NuGet project source")
    components = []
    metadata = [
        {"name": "temporalmark:inventory", "value": "nuget-restored-graph-only"},
        {"name": "temporalmark:projectCount", "value": str(len(selected))},
    ]
    for project in sorted(selected, key=str):
        if project.is_absolute() or ".." in project.parts or project.suffix != ".csproj":
            raise RestoreInventoryError("Unsafe project source path")
        csproj = root / project
        assets = csproj.parent / "obj/project.assets.json"
        if not csproj.is_file() or not assets.is_file():
            raise RestoreInventoryError(f"Missing project or restore assets for {project}")
        project_hash = hashlib.sha256(csproj.read_bytes()).hexdigest()
        from_assets, info = parse_assets(assets.read_bytes(), project)
        components.extend(from_assets)
        metadata.extend([
            {"name": "temporalmark:csproj-sha256:" + str(project), "value": project_hash},
            {"name": "temporalmark:assets-sha256:" + str(project), "value": info["sha256"]},
        ])
    if not components:
        raise RestoreInventoryError("No resolved NuGet packages in selected restore snapshots")
    refs = [entry["bom-ref"] for entry in components]
    if len(set(refs)) != len(refs):
        raise RestoreInventoryError("Duplicate NuGet component reference")
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "TemporalMark .NET restored NuGet inventory",
                          "properties": metadata},
        },
        "components": sorted(components, key=lambda x: x["bom-ref"]),
    }


def verify_inventory(inventory: object, root: Path, projects: list[Path] | None = None) -> None:
    if not isinstance(inventory, dict):
        raise RestoreInventoryError("NuGet inventory must be JSON object")
    components = inventory.get("components")
    if not isinstance(components, list):
        raise RestoreInventoryError("Missing NuGet components")
    refs = [c.get("bom-ref") if isinstance(c, dict) else None for c in components]
    if None in refs or len(set(refs)) != len(refs):
        raise RestoreInventoryError("Duplicate or missing component refs")
    if inventory != make_inventory(root, projects):
        raise RestoreInventoryError("NuGet inventory differs from original restored project assets")


def process(root: Path, output: Path, operation: str) -> int:
    if operation not in {"generate", "verify"}:
        raise RestoreInventoryError("Unsupported inventory operation")
    if operation == "generate":
        output.mkdir(parents=True, exist_ok=True)
        inventory = make_inventory(root)
        path = output / OUTPUT_NAME
        path.write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    else:
        if not output.is_dir() or {p.name for p in output.glob("*.json")} != {OUTPUT_NAME}:
            raise RestoreInventoryError("Expected exactly one NuGet CycloneDX JSON inventory")
        try:
            inventory = json.loads((output / OUTPUT_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise RestoreInventoryError("Invalid NuGet SBOM artifact JSON") from e
    verify_inventory(inventory, root)
    return len(inventory["components"])


def main() -> int:
    cli = argparse.ArgumentParser(description="CI-only NuGet restored dependency inventory")
    cli.add_argument("operation", choices=["generate", "verify"])
    cli.add_argument("--output-dir", type=Path, required=True)
    args = cli.parse_args()
    try:
        count = process(ROOT, args.output_dir, args.operation)
    except (RestoreInventoryError, OSError, ValueError) as e:
        print(f"NuGet CycloneDX inventory {args.operation} FAILED: {e}", file=sys.stderr)
        return 1
    print(f"NuGet CycloneDX inventory {args.operation} PASSED: 9 projects, {count} restored package occurrences")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
