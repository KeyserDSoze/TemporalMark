"""Offline RED/GREEN fixtures for NuGet lockfiles and fail-closed CI sources."""
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_nuget_lockfiles as policy

HASH = base64.b64encode(bytes(range(64))).decode("ascii")
PROJECT = Path("src/backend/Api/Api.csproj")


class LockPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        base = self.root / PROJECT
        base.parent.mkdir(parents=True)
        base.write_text('<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Npgsql" Version="10.0.0" /></ItemGroup></Project>')
        self.lock = {
            "version": 1,
            "dependencies": {"net10.0": {
                "Npgsql": {"type": "Direct", "requested": "[10.0.0, )",
                           "resolved": "10.0.0", "contentHash": HASH},
                "System.Memory": {"type": "Transitive", "resolved": "4.5.5",
                                  "contentHash": HASH},
                "Local.Project": {"type": "Project", "resolved": "1.0.0"},
            }}
        }
        self.save()

    def save(self):
        (self.root / PROJECT.parent / "packages.lock.json").write_text(json.dumps(self.lock))

    def errors(self):
        return policy.check_project(self.root, PROJECT)

    def test_committed_graph_sha512_and_direct_reference(self):
        self.assertEqual([], self.errors())
        self.assertTrue(policy.canonical_sha512(HASH))

    def test_absent_lock_and_short_or_bad_hash_denied(self):
        path = self.root / PROJECT.parent / "packages.lock.json"
        path.unlink()
        self.assertTrue(self.errors())
        for value in ("AAAA", "", "not-base64*"):
            self.lock["dependencies"]["net10.0"]["Npgsql"]["contentHash"] = value
            self.save()
            with self.subTest(value=value):
                self.assertIn("SHA512", " ".join(self.errors()))

    def test_direct_manifest_or_package_version_drift_denied(self):
        self.lock["dependencies"]["net10.0"]["Npgsql"]["resolved"] = "10.1.0"
        self.save()
        self.assertIn("PackageReference drift", " ".join(self.errors()))
        self.lock["dependencies"]["net10.0"]["Npgsql"]["resolved"] = "10.0.0"
        self.save()
        path = self.root / PROJECT
        path.write_text(path.read_text().replace('Version="10.0.0"', 'Version="10.0.1"'))
        self.assertIn("PackageReference drift", " ".join(self.errors()))

    def test_unknown_kind_bad_target_or_unexpected_direct_denied(self):
        entry = self.lock["dependencies"]["net10.0"]["System.Memory"]
        entry["type"] = "Suspicious"
        self.save()
        self.assertIn("unknown", " ".join(self.errors()))
        entry["type"] = "Direct"
        self.save()
        self.assertIn("unexpected direct", " ".join(self.errors()))
        self.lock["dependencies"] = {"net9.0": self.lock["dependencies"].pop("net10.0")}
        self.save()
        self.assertIn("target framework", " ".join(self.errors()))

    def test_nuget_four_part_transitive_version_is_valid(self):
        self.lock["dependencies"]["net10.0"]["libsodium"] = {
            "type": "Transitive", "resolved": "1.0.20.1", "contentHash": HASH
        }
        self.save()
        self.assertEqual([], self.errors())

    def test_source_workflow_explicit_locked_mode(self):
        snippet = (
            "jobs:\n  backend:\n    steps:\n"
            "      - name: Restore all .NET projects in locked mode\n"
            "        run: |\n"
            "          projects=\"$(find src/backend tests/backend -type f -name '*.csproj' | sort)\"\n"
            "          test \"$(printf '%s\\n' \"$projects\" | wc -l)\" -eq 9\n"
            "          while IFS= read -r project; do\n"
            "            dotnet restore \"$project\" --locked-mode\n"
            "          done <<< \"$projects\"\n"
            "      - name: Domain tests\n"
            "        run: dotnet test tests/backend/TemporalMark.Domain.Tests/TemporalMark.Domain.Tests.csproj --configuration Release --no-restore\n"
            "  frontend:\n    steps:\n"
        )
        docker = "RUN dotnet publish app.csproj -p:RestoreLockedMode=true\n"
        self.assertEqual([], policy.check_workflow(snippet, docker))
        self.assertTrue(policy.check_workflow(snippet.replace("--locked-mode", ""), docker))
        self.assertTrue(policy.check_workflow(snippet.replace("--no-restore", ""), docker))
        self.assertTrue(policy.check_workflow(snippet, "RUN dotnet publish app.csproj\n"))


if __name__ == "__main__":
    unittest.main()
