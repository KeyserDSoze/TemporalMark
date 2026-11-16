"""Unit tests for SBOM CI source policy (offline, stdlib only)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_sbom_workflow as policy


def workflow(pinned=True, validate=True, two_installs=True, retention=7):
    setup = "          npm ci --no-audit --no-fund\n"
    return (
        "name: CI\njobs:\n  frontend:\n    steps:\n"
        + setup
        + (setup if two_installs else "")
        + "      - name: Generate npm lockfile SBOMs\n"
        + "        run: python3 tests/integration/generate_npm_sbom.py generate --output-dir \"$RUNNER_TEMP/temporalmark-npm-sbom\"\n"
        + ("      - name: Verify npm lockfile SBOMs\n        run: python3 tests/integration/generate_npm_sbom.py verify --output-dir \"$RUNNER_TEMP/temporalmark-npm-sbom\"\n" if validate else "")
        + "      - uses: actions/upload-artifact@"
        + ("ea165f8d65b6e75b540449e92b4886f43607fa02" if pinned else "v4")
        + "\n        with:\n          name: npm-lockfile-cyclonedx\n"
        + "          path: $" + "{{ runner.temp }}/temporalmark-npm-sbom/*.json\n"
        + f"          retention-days: {retention}\n"
        + "  docker-smoke:\n    steps:\n      - run: true\n"
    )


class SbomSourcePolicyTests(unittest.TestCase):
    def test_valid_after_both_clean_installs(self):
        self.assertEqual([], policy.check_workflow(workflow()))

    def test_missing_generator_and_validation_denied(self):
        text = workflow().replace(policy.GENERATE, "echo no-export")
        failures = policy.check_workflow(text)
        self.assertIn("generate", " ".join(failures).lower())
        self.assertTrue(policy.check_workflow(workflow(validate=False)))

    def test_unpinned_upload_or_long_retention_denied(self):
        self.assertTrue(policy.check_workflow(workflow(pinned=False)))
        self.assertTrue(policy.check_workflow(workflow(retention=90)))

    def test_missing_second_install_or_broad_token_denied(self):
        self.assertTrue(policy.check_workflow(workflow(two_installs=False)))
        self.assertTrue(policy.check_workflow(workflow().replace(
            "  docker-smoke:\n", "    permissions:\n      id-token: write\n  docker-smoke:\n"
        )))

    def test_missing_job_denied(self):
        self.assertTrue(policy.check_workflow("name: CI\njobs: {}"))


if __name__ == "__main__":
    unittest.main()
