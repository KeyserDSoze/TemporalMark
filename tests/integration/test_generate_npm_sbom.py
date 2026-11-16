"""Positive and adversarial tests of deterministic npm-lockfile-only CycloneDX."""
import base64
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_npm_sbom as sbom


def sample():
    digest = base64.b64encode(bytes(range(64))).decode("ascii")
    return {
        "name": "test-sbom", "version": "1.2.3", "lockfileVersion": 3,
        "packages": {
            "": {"name": "test-sbom", "version": "1.2.3",
                 "dependencies": {"@scope/widget": "2.0.0"}},
            "node_modules/@scope/widget": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/@scope/widget/-/widget-2.0.0.tgz",
                "integrity": "sha512-" + digest,
            },
            "node_modules/@scope/widget/node_modules/react": {
                "version": "19.2.0",
                "resolved": "https://registry.npmjs.org/react/-/react-19.2.0.tgz",
                "integrity": "sha512-" + digest,
                "dev": True,
                "optional": True,
            },
            "node_modules/react": {
                "version": "19.2.0",
                "resolved": "https://registry.npmjs.org/react/-/react-19.2.0.tgz",
                "integrity": "sha512-" + digest,
            },
        },
    }


def source_bytes(lock=None):
    return (json.dumps(lock or sample(), sort_keys=True) + "\n").encode()


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.data = source_bytes()
        self.source = "src/frontend/package-lock.json"
        self.bom = sbom.make_inventory(self.data, self.source)

    def test_valid_deterministic_complete_inventory(self):
        self.assertEqual("CycloneDX", self.bom["bomFormat"])
        self.assertEqual("1.5", self.bom["specVersion"])
        self.assertEqual(3, len(self.bom["components"]))
        self.assertEqual(self.bom, sbom.make_inventory(self.data, self.source))
        sbom.validate_inventory(self.bom, self.data, self.source)

    def test_scoped_purl_and_nested_duplicate_paths(self):
        components = self.bom["components"]
        scoped = [x for x in components if x["name"] == "@scope/widget"][0]
        self.assertEqual("pkg:npm/%40scope/widget@2.0.0", scoped["purl"])
        duplicates = [x for x in components if x["name"] == "react"]
        self.assertEqual(2, len(duplicates))
        self.assertEqual(2, len({x["bom-ref"] for x in duplicates}))

    def test_removed_or_injected_packages_denied(self):
        missing = copy.deepcopy(self.bom)
        missing["components"].pop()
        with self.assertRaises(sbom.InventoryError):
            sbom.validate_inventory(missing, self.data, self.source)
        extra = copy.deepcopy(self.bom)
        extra["components"].append(copy.deepcopy(extra["components"][0]))
        extra["components"][-1]["bom-ref"] = "npm-lock:fake"
        with self.assertRaises(sbom.InventoryError):
            sbom.validate_inventory(extra, self.data, self.source)

    def test_tampered_hash_version_or_duplicate_ref_denied(self):
        for field, value in (("version", "99.9.9"), ("purl", "pkg:npm/fake@1.0.0"),
                             ("hashes", [{"alg": "SHA-512", "content": "a"*128}])):
            changed = copy.deepcopy(self.bom)
            changed["components"][0][field] = value
            with self.subTest(field=field), self.assertRaises(sbom.InventoryError):
                sbom.validate_inventory(changed, self.data, self.source)
        duplicate = copy.deepcopy(self.bom)
        duplicate["components"][1]["bom-ref"] = duplicate["components"][0]["bom-ref"]
        with self.assertRaises(sbom.InventoryError):
            sbom.validate_inventory(duplicate, self.data, self.source)

    def test_altered_lock_bytes_source_and_root_denied(self):
        changed = copy.deepcopy(sample())
        changed["packages"]["node_modules/react"]["version"] = "19.2.1"
        with self.assertRaises(sbom.InventoryError):
            sbom.validate_inventory(self.bom, source_bytes(changed), self.source)
        with self.assertRaises(sbom.InventoryError):
            sbom.validate_inventory(self.bom, self.data, "tests/frontend/package-lock.json")
        changed_bom = copy.deepcopy(self.bom)
        changed_bom["metadata"]["component"]["properties"][0]["value"] = "certified"
        with self.assertRaises(sbom.InventoryError):
            sbom.validate_inventory(changed_bom, self.data, self.source)

    def test_reject_short_or_malformed_sri_and_unknown_paths(self):
        for integrity in ("sha512-AAAA", "sha512-%%%garbage", "", "sha256-AQ=="):
            lock = sample()
            lock["packages"]["node_modules/react"]["integrity"] = integrity
            with self.subTest(integrity=integrity), self.assertRaises(sbom.InventoryError):
                sbom.make_inventory(source_bytes(lock), self.source)
        lock = sample()
        lock["packages"]["../evil"] = lock["packages"]["node_modules/react"]
        with self.assertRaises(sbom.InventoryError):
            sbom.make_inventory(source_bytes(lock), self.source)

    def test_output_directory_roundtrip_and_corruption_denied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            for project in sbom.PROJECTS:
                directory = root / project
                directory.mkdir(parents=True)
                data = sample()
                (directory / "package.json").write_text(
                    json.dumps({"name": "test-sbom", "version": "1.2.3",
                                "dependencies": {"@scope/widget": "2.0.0"}}))
                (directory / "package-lock.json").write_bytes(source_bytes(data))
            output = Path(temp) / "out"
            result = sbom.process(root, output, "generate")
            self.assertEqual(2, len(result))
            self.assertEqual(2, len(sbom.process(root, output, "verify")))
            path = output / sbom.PROJECTS[Path("src/frontend")]
            path.write_text("{}")
            with self.assertRaises(sbom.InventoryError):
                sbom.process(root, output, "verify")


if __name__ == "__main__":
    unittest.main()
