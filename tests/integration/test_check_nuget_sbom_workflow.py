"""Offline source policy regressions for nine-project restored NuGet inventory."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_nuget_sbom_workflow as policy


def workflow(restore=True, verify=True, pinned=True, retention=7, json_only=True):
    return (
        "name: CI\njobs:\n  backend:\n    steps:\n"
        + ('      - name: Restore every .NET project\n'
           '        run: |\n'
           "          projects=\"$(find src/backend tests/backend -type f -name '*.csproj' | sort)\"\n"
           '          while IFS= read -r project; do\n'
           '            dotnet restore "$project"\n'
           '          done <<< "$projects"\n'
           if restore else "")
        + '      - name: Generate NuGet SBOM\n'
        + '        run: python3 tests/integration/generate_nuget_sbom.py generate --output-dir "$RUNNER_TEMP/temporalmark-nuget-sbom"\n'
        + ('      - name: Verify NuGet SBOM\n'
           '        run: python3 tests/integration/generate_nuget_sbom.py verify --output-dir "$RUNNER_TEMP/temporalmark-nuget-sbom"\n'
           if verify else "")
        + "      - uses: actions/upload-artifact@"
        + ("ea165f8d65b6e75b540449e92b4886f43607fa02" if pinned else "v4")
        + "\n        with:\n          name: nuget-restored-cyclonedx\n"
        + ("          path: $" + "{{ runner.temp }}/temporalmark-nuget-sbom/*.json\n" if json_only else
           "          path: obj/project.assets.json\n")
        + "          if-no-files-found: error\n"
        + f"          retention-days: {retention}\n"
        + "  frontend:\n    steps:\n      - run: true\n"
    )


class NugetWorkflowSourcePolicyTests(unittest.TestCase):
    def test_expected_scope_and_order(self):
        self.assertEqual([], policy.check_workflow(workflow()))

    def test_restore_or_verifier_absent_denied(self):
        self.assertTrue(policy.check_workflow(workflow(restore=False)))
        self.assertTrue(policy.check_workflow(workflow(verify=False)))

    def test_unpinned_upload_broad_retention_and_raw_assets_denied(self):
        self.assertTrue(policy.check_workflow(workflow(pinned=False)))
        self.assertTrue(policy.check_workflow(workflow(retention=30)))
        self.assertTrue(policy.check_workflow(workflow(json_only=False)))

    def test_verification_after_upload_denied(self):
        source = workflow()
        fragment = ('      - name: Verify NuGet SBOM\n'
                    '        run: python3 tests/integration/generate_nuget_sbom.py verify --output-dir "$RUNNER_TEMP/temporalmark-nuget-sbom"\n')
        altered = source.replace(fragment, "").replace("  frontend:\n", fragment + "  frontend:\n")
        self.assertTrue(policy.check_workflow(altered))

    def test_missing_job_and_new_permissions_denied(self):
        self.assertTrue(policy.check_workflow("jobs: {}\n"))
        self.assertTrue(policy.check_workflow(workflow().replace(
            "  frontend:\n", "    permissions:\n      id-token: write\n  frontend:\n")))


if __name__ == "__main__":
    unittest.main()
