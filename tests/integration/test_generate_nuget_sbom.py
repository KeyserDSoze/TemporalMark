"""Positive/adversarial restoration metadata inventory tests, offline Python stdlib."""
import base64
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_nuget_sbom as sbom

INTEGRITY = base64.b64encode(bytes(range(64))).decode("ascii")


def assets(name="Fido2", version="4.3.3", *, integrity=INTEGRITY):
    return {
        "version": 3,
        "targets": {"net10.0": {f"{name}/{version}": {"type": "package"}}},
        "libraries": {
            f"{name}/{version}": {
                "sha512": integrity, "type": "package", "path": f"{name.lower()}/{version}"
            },
            "TemporalMark.Domain/1.0.0": {
                "type": "project", "path": "../TemporalMark.Domain"
            },
        },
        "project": {"frameworks": {"net10.0": {}}},
    }


class NugetInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.projects = [Path("src/backend/Foo/Foo.csproj"), Path("tests/backend/Bar/Bar.csproj")]
        for project in self.projects:
            project_path = self.root / project
            project_path.parent.mkdir(parents=True)
            project_path.write_text('<Project Sdk="Microsoft.NET.Sdk" />')
            (project_path.parent / "obj").mkdir()
            (project_path.parent / "obj/project.assets.json").write_text(json.dumps(assets()))
        self.inventory = sbom.make_inventory(self.root, self.projects)

    def test_canonical_sha512_and_real_component_attributes(self):
        component = self.inventory["components"][0]
        self.assertEqual("pkg:nuget/Fido2@4.3.3", component["purl"])
        self.assertEqual(bytes(range(64)).hex(), component["hashes"][0]["content"])
        self.assertEqual("1.5", self.inventory["specVersion"])
        self.assertEqual(2, len(self.inventory["components"]))
        sbom.verify_inventory(self.inventory, self.root, self.projects)

    def test_same_version_across_projects_has_distinct_references(self):
        refs = [p["bom-ref"] for p in self.inventory["components"]]
        self.assertEqual(2, len(set(refs)))
        self.assertTrue(all(p["purl"] == "pkg:nuget/Fido2@4.3.3" for p in self.inventory["components"]))

    def test_absent_or_broken_assets_fails_closed(self):
        path = self.root / self.projects[0] / "../obj/project.assets.json"
        actual = (self.root / self.projects[0]).parent / "obj/project.assets.json"
        actual.unlink()
        with self.assertRaises(sbom.RestoreInventoryError):
            sbom.make_inventory(self.root, self.projects)
        actual.write_text("{}")
        with self.assertRaises(sbom.RestoreInventoryError):
            sbom.make_inventory(self.root, self.projects)

    def test_missing_bad_digest_or_fake_package_type(self):
        path = (self.root / self.projects[0]).parent / "obj/project.assets.json"
        for integrity in ("", "sha512-AAAA", "%%%notbase64"):
            with self.subTest(integrity=integrity):
                path.write_text(json.dumps(assets(integrity=integrity)))
                with self.assertRaises(sbom.RestoreInventoryError):
                    sbom.make_inventory(self.root, self.projects)
        invalid = assets()
        invalid["libraries"]["Fido2/4.3.3"]["type"] = "unverified-binary"
        path.write_text(json.dumps(invalid))
        with self.assertRaises(sbom.RestoreInventoryError):
            sbom.make_inventory(self.root, self.projects)

    def test_missing_extra_duplicate_or_altered_source_denied(self):
        for mutate in ("pop", "extra", "purl", "version", "sha512", "duplicate", "root"):
            with self.subTest(mutate=mutate):
                entry = copy.deepcopy(self.inventory)
                if mutate == "pop":
                    entry["components"].pop()
                elif mutate == "extra":
                    component = copy.deepcopy(entry["components"][0])
                    component["bom-ref"] += ":fake"
                    entry["components"].append(component)
                elif mutate == "purl":
                    entry["components"][0]["purl"] = "pkg:nuget/Malicious@1.0.0"
                elif mutate == "version":
                    entry["components"][0]["version"] = "999.0.0"
                elif mutate == "sha512":
                    entry["components"][0]["hashes"][0]["content"] = "00"*64
                elif mutate == "duplicate":
                    entry["components"][1]["bom-ref"] = entry["components"][0]["bom-ref"]
                else:
                    entry["metadata"]["component"]["name"] = "certified-and-approved"
                with self.assertRaises(sbom.RestoreInventoryError):
                    sbom.verify_inventory(entry, self.root, self.projects)
        changed = (self.root / self.projects[0])
        changed.write_text('<Project Sdk="Microsoft.NET.Sdk.Web" />')
        with self.assertRaises(sbom.RestoreInventoryError):
            sbom.verify_inventory(self.inventory, self.root, self.projects)

    def test_roundtrip_and_tamper_file_fails(self):
        # Full nine project fake tree to exercise real repository discovery.
        for i in range(7):
            project = self.root / f"src/backend/Added{i}/Added{i}.csproj"
            project.parent.mkdir(parents=True)
            project.write_text("<Project />")
            (project.parent / "obj").mkdir()
            (project.parent / "obj/project.assets.json").write_text(json.dumps(assets()))
        output = Path(self.temp.name) / "out"
        self.assertEqual(9, len(sbom.project_list(self.root)))
        count = sbom.process(self.root, output, "generate")
        self.assertEqual(9, count)
        self.assertEqual(9, sbom.process(self.root, output, "verify"))
        path = output / sbom.OUTPUT_NAME
        path.write_text('{"bomFormat":"CycloneDX"}')
        with self.assertRaises(sbom.RestoreInventoryError):
            sbom.process(self.root, output, "verify")

    def test_extra_projects_rejected_by_scope(self):
        with self.assertRaises(sbom.RestoreInventoryError):
            sbom.project_list(self.root)
        with self.assertRaises(sbom.RestoreInventoryError):
            sbom.make_inventory(self.root, [self.projects[0], self.projects[0]])
        with self.assertRaises(sbom.RestoreInventoryError):
            sbom.make_inventory(self.root, [Path("../outside.csproj")])


if __name__ == "__main__":
    unittest.main()
