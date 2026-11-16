"""Test-first npm lockfile policy; fixtures are synthetic and never committed locks."""
import json
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_npm_lockfiles as guard

class LockPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.project = self.root / "src/frontend"
        self.project.mkdir(parents=True)
        self.manifest = {
            "name": "test-web",
            "version": "0.1.0",
            "dependencies": {"react": "19.2.0"},
            "devDependencies": {"typescript": "5.9.3"}
        }
        self.lock = {
            "name": "test-web",
            "version": "0.1.0",
            "lockfileVersion": 3,
            "packages": {
                "": json.loads(json.dumps(self.manifest)),
                "node_modules/react": {
                    "version": "19.2.0",
                    "resolved": "https://registry.npmjs.org/react/-/react-19.2.0.tgz",
                    "integrity": "sha512-ZXhhbXBsZQ=="
                },
            }
        }
        self.save()

    def save(self):
        (self.project / "package.json").write_text(json.dumps(self.manifest))
        (self.project / "package-lock.json").write_text(json.dumps(self.lock))

    def check(self):
        return guard.verify_project(self.root, Path("src/frontend"))

    def test_complete_snapshot(self):
        self.assertEqual([], self.check())

    def test_missing_or_unparseable_lock(self):
        (self.project / "package-lock.json").unlink()
        self.assertTrue(self.check())
        (self.project / "package-lock.json").write_text("NOT JSON")
        self.assertTrue(self.check())

    def test_manifest_drift_rejected(self):
        self.manifest["dependencies"]["react"] = "19.2.1"
        self.save()
        self.assertIn("dependencies", " ".join(self.check()))

    def test_missing_integrity_or_insecure_url_rejected(self):
        self.lock["packages"]["node_modules/react"].pop("integrity")
        self.lock["packages"]["node_modules/react"]["resolved"] = "http://example.org"
        self.save()
        self.assertIn("integrity", " ".join(self.check()))
        self.assertIn("HTTPS", " ".join(self.check()))

    def test_floating_version_and_missing_transitive_tree_denied(self):
        self.lock["packages"]["node_modules/react"]["version"] = "^19.2"
        self.save()
        self.assertIn("non-fixed", " ".join(self.check()))
        self.lock["packages"] = {"": self.manifest}
        self.save()
        self.assertIn("resolved package tree", " ".join(self.check()))

if __name__ == "__main__":
    unittest.main()
