"""Offline TDD fixtures for native Node24 action source allowlist (ADR 0050)."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_ci_action_runtimes as policy


class NativeRuntimeTests(unittest.TestCase):
    def test_verified_native_node24_pins(self):
        source = "\n".join(f"  - uses: {name}@{sha}" for name, sha in policy.NATIVE_NODE24.items())
        errors, seen = policy.check_text(source, "ci.yml")
        self.assertEqual([], errors)
        self.assertEqual(set(policy.NATIVE_NODE24), seen)
        self.assertEqual(5, len(seen))

    def test_every_known_deprecated_node20_sha_fails(self):
        for name, sha in policy.KNOWN_NODE20.items():
            with self.subTest(action=name):
                errors, seen = policy.check_text(f"      - uses: {name}@{sha} # old", "ci.yml")
                self.assertEqual(set(), seen)
                self.assertEqual(1, len(errors))
                self.assertIn("deprecated native node20", errors[0])

    def test_unreviewed_shas_floating_refs_and_extra_actions_denied(self):
        cases = [
            "actions/checkout@" + "0" * 40,
            "random/private-action@" + "0" * 40,
            "actions/upload-artifact@v5",  # tag is mutable; v5 also node20
            "actions/checkout@" + "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c0",
            "docker://alpine:latest",
            "actions/setup-dotnet@${{ secrets.SHA }}",
        ]
        for ref in cases:
            with self.subTest(ref=ref):
                errors, _ = policy.check_text(f"    - uses: {ref}", "ci.yml")
                self.assertEqual(1, len(errors))

    def test_comments_safe_local_and_quoted_known_sha(self):
        sha = policy.NATIVE_NODE24["actions/checkout"]
        source = (f"# - uses: actions/checkout@v4\n"
                  f" - uses: './.github/actions/internal'\n"
                  f' - uses: "actions/checkout@{sha}" # v5\n')
        errors, seen = policy.check_text(source, "ci.yml")
        self.assertEqual([], errors)
        self.assertEqual({"actions/checkout"}, seen)

    def test_all_workflow_files_and_missing_families(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertTrue(policy.check_directory(root))
            (root / "main.yml").write_text(
                "\n".join(f"- uses: {name}@{sha}" for name, sha in policy.NATIVE_NODE24.items())
            )
            (root / "other.yaml").write_text("# ignored old uses: actions/checkout@v4\n")
            self.assertEqual([], policy.check_directory(root))
            (root / "other.yaml").write_text("- uses: actions/checkout@" + policy.KNOWN_NODE20["actions/checkout"])
            self.assertIn("deprecated native node20", " ".join(policy.check_directory(root)))
            (root / "other.yaml").unlink()
            (root / "main.yml").write_text(
                "- uses: actions/checkout@" + policy.NATIVE_NODE24["actions/checkout"]
            )
            self.assertIn("required reviewed node24 action missing", " ".join(policy.check_directory(root)))


if __name__ == "__main__":
    unittest.main()
