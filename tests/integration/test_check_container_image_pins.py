"""Offline TDD for OCI digest pinning policy."""
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_container_image_pins as guard

PIN = "@sha256:" + "a" * 64

class ImagePolicyTests(unittest.TestCase):
    def test_real_registry_sources(self):
        for ref in ("postgres:17.6-alpine", "quay.io/keycloak/keycloak:26.4.0",
                    "node:22-alpine", "nginx:1.27-alpine",
                    "mcr.microsoft.com/dotnet/sdk:10.0",
                    "mcr.microsoft.com/dotnet/aspnet:10.0"):
            with self.subTest(ref=ref):
                self.assertTrue(guard.pinned_image(ref + PIN))

    def test_dynamic_short_or_unsafe_sources_denied(self):
        for ref in ("postgres:17.6-alpine", "node:22-alpine@sha256:abc",
                    "node:22-alpine@sha256:" + "A"*64,
                    "nginx:latest" + PIN, "postgres:" + "$" + "{TAG}" + PIN,
                    "postgres:17.6@sha256:" + "$" + "{DIGEST}",
                    "docker://postgres:17.6" + PIN, "../postgres:17.6" + PIN,
                    "postgres:stable" + PIN, ""):
            with self.subTest(ref=ref):
                self.assertFalse(guard.pinned_image(ref))

    def test_multistage_alias_and_unsafe_base(self):
        source = "FROM node:22-alpine" + PIN + " AS build\nRUN true\nFROM build AS copy\nFROM nginx:1.27-alpine" + PIN + "\n"
        errors, count = guard.check_dockerfile(source, "Dockerfile")
        self.assertEqual(3, count)
        self.assertEqual([], errors)
        errors, count = guard.check_dockerfile("FROM future AS build\nFROM postgres:17.6-alpine\nFROM " + "$" + "{BASE}\n", "Dockerfile")
        self.assertEqual(3, count)
        self.assertEqual(3, len(errors))

    def test_compose_yaml_literals_and_comments(self):
        source = "# image: postgres:latest\n    image: 'postgres:17.6-alpine" + PIN + "' # pinned\n    image: quay.io/keycloak/keycloak:26.4.0\n"
        errors, count = guard.check_compose(source, "docker/compose.yml")
        self.assertEqual(2, count)
        self.assertEqual(1, len(errors))
        self.assertIn("docker/compose.yml:3:", errors[0])

    def test_discover_all_and_reject_new_unpinned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertTrue(guard.check_repository(root))
            web = root / "src/frontend/Dockerfile"
            api = root / "src/backend/applications/TemporalMark.Api/Dockerfile"
            compose = root / "docker/compose.yml"
            for p in (web, api, compose):
                p.parent.mkdir(parents=True, exist_ok=True)
            web.write_text("FROM node:22-alpine" + PIN + " AS build\nFROM nginx:1.27-alpine" + PIN + "\n")
            api.write_text("FROM mcr.microsoft.com/dotnet/sdk:10.0" + PIN + " AS build\nFROM mcr.microsoft.com/dotnet/aspnet:10.0" + PIN + "\n")
            compose.write_text("services:\n" + ("    image: postgres:17.6-alpine" + PIN + "\n")*3 + "    image: quay.io/keycloak/keycloak:26.4.0" + PIN + "\n")
            self.assertEqual([], guard.check_repository(root))
            compose.write_text(compose.read_text().replace(PIN, "", 1))
            self.assertIn("unpinned", " ".join(guard.check_repository(root)))

if __name__ == "__main__":
    unittest.main()
