"""Offline regression tests for workflow-action source pinning policy."""
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_ci_action_pins as pins
SHA = "0123456789abcdef" * 2 + "01234567"

class PolicyTests(unittest.TestCase):
    def check(self, ref):
        errors, count = pins.check_text("jobs:\n  smoke:\n    steps:\n      - uses: " + ref + "\n", "workflow.yml")
        self.assertEqual(1, count)
        return errors

    def test_literal_sha_and_safe_local(self):
        self.assertEqual([], self.check("actions/checkout@" + SHA))
        self.assertEqual([], self.check("'actions/setup-node@" + SHA + "'"))
        self.assertEqual([], self.check("hashicorp/setup-terraform@" + SHA + " # v3"))
        self.assertEqual([], self.check("./.github/actions/my-action"))

    def test_mutable_dynamic_short_or_invalid_denied(self):
        dynamic = "actions/checkout@" + "$" + "{{ inputs.ref }}"
        for value in ["actions/checkout@v4", "actions/checkout@main",
                      "actions/checkout@deadbeef", "actions/checkout@" + SHA.upper(),
                      dynamic, "docker://alpine:latest",
                      "../actions/checkout", "./.github/actions/../../evil", "", '"actions/checkout@v4"']:
            with self.subTest(ref=value):
                self.assertEqual(1, len(self.check(value)))

    def test_comments_and_multiple_workflows(self):
        src = "# - uses: actions/checkout@v4\n- uses: actions/checkout@" + SHA + "\n- uses: actions/setup-node@v4\n"
        errors, count = pins.check_text(src, "sample.yml")
        self.assertEqual(2, count)
        self.assertEqual(1, len(errors))
        self.assertIn("sample.yml:3", errors[0])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertTrue(pins.check_directory(root))
            (root / "a.yml").write_text("- uses: actions/checkout@" + SHA + "\n")
            (root / "b.yaml").write_text("- uses: actions/setup-node@v4\n")
            self.assertEqual(1, len(pins.check_directory(root)))
            (root / "b.yaml").write_text("- uses: actions/setup-node@" + SHA + "\n")
            self.assertEqual([], pins.check_directory(root))

if __name__ == "__main__":
    unittest.main()
