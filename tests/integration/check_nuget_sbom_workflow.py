#!/usr/bin/env python3
"""Narrow CI source gate for all-project restored NuGet inventory, ADR 0047."""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATE = "python3 tests/integration/generate_nuget_sbom.py generate"
VERIFY = "python3 tests/integration/generate_nuget_sbom.py verify"
from check_ci_action_runtimes import NATIVE_NODE24
UPLOAD = "actions/upload-artifact@" + NATIVE_NODE24["actions/upload-artifact"]


def check_workflow(source: str) -> list[str]:
    if "\n  backend:\n" not in source or "\n  frontend:\n" not in source:
        return ["Expected backend and frontend CI jobs"]
    backend = source.split("\n  backend:\n", 1)[1].split("\n  frontend:\n", 1)[0]
    errors = []
    restore = backend.find('dotnet restore "$project"')
    discovery = backend.find("find src/backend tests/backend -type f -name '*.csproj'")
    generate = backend.find(GENERATE)
    verify = backend.find(VERIFY)
    upload = backend.find(UPLOAD)
    if discovery < 0 or restore < 0 or restore <= discovery:
        errors.append("Backend must enumerate and restore all .NET projects")
    if generate < 0 or restore < 0 or generate <= restore:
        errors.append("Backend must generate NuGet inventory after restore")
    if verify < 0 or generate < 0 or verify <= generate:
        errors.append("Backend must verify restored NuGet inventory")
    if upload < 0 or backend.count(UPLOAD) != 1 or verify < 0 or upload <= verify:
        errors.append("Backend must SHA-pin upload after semantic NuGet verification")
    if "name: nuget-restored-cyclonedx" not in backend:
        errors.append("Missing scoped NuGet SBOM artifact name")
    if "temporalmark-nuget-sbom/*.json" not in backend:
        errors.append("NuGet SBOM artifact must contain only generated JSON")
    if "if-no-files-found: error" not in backend:
        errors.append("Empty NuGet SBOM artifact must fail")
    if "retention-days: 7" not in backend:
        errors.append("NuGet SBOM retention must be 7 days")
    if "id-token: write" in backend or "contents: write" in backend:
        errors.append("No elevated CI token permissions")
    return errors


def check_repository(root: Path) -> list[str]:
    path = root / ".github/workflows/ci.yml"
    return check_workflow(path.read_text(encoding="utf-8")) if path.is_file() else ["Missing CI workflow"]


if __name__ == "__main__":
    findings = check_repository(ROOT)
    if findings:
        print("NuGet CycloneDX backend policy FAILED:", file=sys.stderr)
        for finding in findings:
            print("  " + finding, file=sys.stderr)
        sys.exit(1)
    print("NuGet CycloneDX backend source policy PASSED")
