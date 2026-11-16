#!/usr/bin/env python3
"""Narrow CI source policy for two independently validated npm SBOM artifacts.

Not a YAML parser. Live generator/semantic verifier are separate controls.
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
from check_ci_action_runtimes import NATIVE_NODE24
PINNED_UPLOAD = "actions/upload-artifact@" + NATIVE_NODE24["actions/upload-artifact"]
OUTPUT = "temporalmark-npm-sbom"
GENERATE = "python3 tests/integration/generate_npm_sbom.py generate"
VERIFY = "python3 tests/integration/generate_npm_sbom.py verify"


def check_workflow(text: str) -> list[str]:
    if "\n  frontend:\n" not in text or "\n  docker-smoke:\n" not in text:
        return ["Expected frontend and docker-smoke jobs missing"]
    frontend = text.split("\n  frontend:\n", 1)[1].split("\n  docker-smoke:\n", 1)[0]
    errors = []
    position = frontend.find(GENERATE)
    if position < 0:
        errors.append("Frontend must generate npm lockfile CycloneDX SBOMs")
    elif frontend[:position].count("npm ci --no-audit --no-fund") < 2:
        errors.append("Generate both SBOMs only after both npm ci installs")
    verified = frontend.find(VERIFY)
    if verified < 0 or position < 0 or verified <= position:
        errors.append("Frontend must verify both SBOMs after generation")
    upload_at = frontend.find(PINNED_UPLOAD)
    if frontend.count(PINNED_UPLOAD) != 1:
        errors.append("Frontend needs one SHA-pinned upload-artifact step")
    elif verified < 0 or upload_at <= verified:
        errors.append("Frontend must upload only after semantic verification")
    if "if-no-files-found: error" not in frontend:
        errors.append("Empty SBOM artifacts must fail the frontend job")
    if "name: npm-lockfile-cyclonedx" not in frontend:
        errors.append("Expected short-lived npm-only SBOM artifact missing")
    if "retention-days: 7" not in frontend:
        errors.append("SBOM artifact retention must be limited to seven days")
    if "temporalmark-npm-sbom/*.json" not in frontend:
        errors.append("SBOM artifact must include only generated JSON inventories")
    if "npm-lockfile-cyclonedx" in frontend and (
        "id-token: write" in frontend or "contents: write" in frontend
    ):
        errors.append("SBOM export must not expand workflow token permissions")
    return errors


def check_repository(root: Path) -> list[str]:
    workflow = root / ".github/workflows/ci.yml"
    if not workflow.is_file():
        return ["CI workflow not present"]
    return check_workflow(workflow.read_text(encoding="utf-8"))


if __name__ == "__main__":
    failures = check_repository(ROOT)
    if failures:
        print("npm SBOM pipeline source policy FAILED:", file=sys.stderr)
        for failure in failures:
            print("  " + failure, file=sys.stderr)
        sys.exit(1)
    print("npm SBOM pipeline source policy passed: generation, verification and limited upload")
