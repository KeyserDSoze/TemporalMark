"""#167 / ADR 0125 RED-first: real API smoke export wrapper must use strict offline v1.

These isolated tests mock only the HTTP reply to the existing two-tenant
integration script. The live docker-smoke still runs the real compiled .NET
exporter, signed Keycloak and PostgreSQL; no network or credentials here.
"""
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_verify_period_export import (
    DER, ORG, OfflinePeriodExportTests, build_zip, record,
)

spec = importlib.util.spec_from_file_location(
    "temporalmark_ci_api_isolation", HERE / "api-tenant-isolation.py")
assert spec is not None and spec.loader is not None
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class RealApiOfflineExportBridgeTests(unittest.TestCase):
    def test_valid_v1_http_export_is_still_readable_without_network(self):
        raw = build_zip()
        with patch.object(smoke, "api", return_value=(
                200, {"Cache-Control": "no-store, private"}, raw)):
            manifest, receipts = smoke.export("synthetic-unused-token")
        self.assertEqual(ORG, manifest["organizationId"])
        self.assertEqual(1, manifest["count"])
        self.assertEqual({record()["responseFile"]: DER}, receipts)

    def test_stock_zipfile_readable_hidden_gap_is_denied_by_api_export_bridge(self):
        base = build_zip()
        changed = OfflinePeriodExportTests._insert_opaque_gap_after_member(
            base, record()["responseFile"])
        with zipfile.ZipFile(io.BytesIO(changed), "r") as archive:
            self.assertEqual(DER, archive.read(record()["responseFile"]))
            self.assertEqual(1, __import__("json").loads(
                archive.read("manifest.json"))["count"])
        with patch.object(smoke, "api", return_value=(
                200, {"Cache-Control": "no-store, private"}, changed)):
            with self.assertRaisesRegex(AssertionError, "(?i)offline v1") as caught:
                smoke.export("synthetic-unused-token")
        self.assertNotIn(ORG, str(caught.exception))
        self.assertNotIn("PRIVATE-UNREFERENCED", str(caught.exception))
        self.assertNotIn("synthetic-unused-token", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
