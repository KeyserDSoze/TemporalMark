"""#169 / ADR 0127: avoid false positives in the real CI-only audit SQL probe.

Use a deliberately simulated psql stdout format. Real Docker CI still seeds
PostgreSQL and checks signed Keycloak A=409/B=404 plus zero prepared audits.
Neither this test nor its mocks uses live JWT, HTTP, Docker or credentials.
"""
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location(
    "temporalmark_api_oversized_ci", HERE / "api-tenant-isolation.py")
assert spec is not None and spec.loader is not None
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class OversizedReceiptAuditProbeTests(unittest.TestCase):
    def _run_fixture(self, audit_count):
        seen = []

        def run_psql(command, *, input, **kwargs):
            self.assertTrue(command[:2] == ["docker", "compose"])
            self.assertEqual(kwargs["check"], False)
            self.assertTrue(kwargs["capture_output"])
            if "INSERT INTO public.timestamp_registry" in input:
                seen.append("insert")
                return subprocess.CompletedProcess(command, 0, "", "")
            if "SELECT count(*) FROM public.tenant_audit_events" in input:
                seen.append("audit")
                # Real psql without -t/-A produces a *display table*
                # rather than just '0', even if there are no matching rows.
                rows = (f"{audit_count}\n" if
                        "-t" in command and "-A" in command else
                        f" count \n-------\n     {audit_count}\n(1 row)\n")
                return subprocess.CompletedProcess(command, 0, rows, "")
            raise AssertionError("Unexpected CI-only SQL operation")

        def fake_api(path, *, token):
            self.assertTrue(path.endswith("/receipt"))
            if token == "synthetic-tenant-a":
                return 409, {"Cache-Control": "no-store, private"}, b'{"title":"Pilot receipt unavailable"}'
            if token == "synthetic-tenant-b":
                return 404, {}, b""
            raise AssertionError("Unexpected synthetic principal")

        with (patch.object(smoke, "api", side_effect=fake_api),
              patch.object(smoke.subprocess, "run", side_effect=run_psql),
              patch("sys.stdout", new_callable=io.StringIO) as log):
            if audit_count:
                with self.assertRaisesRegex(
                    AssertionError, "incorrectly prepared a download audit"
                ):
                    smoke.assert_oversized_legacy_receipt_is_not_downloaded(
                        "synthetic-tenant-a", "synthetic-tenant-b")
            else:
                smoke.assert_oversized_legacy_receipt_is_not_downloaded(
                    "synthetic-tenant-a", "synthetic-tenant-b")
            text = log.getvalue()
        self.assertEqual(["insert", "audit"], seen)
        self.assertNotIn("synthetic-tenant-a", text)
        self.assertNotIn("synthetic-tenant-b", text)

    def test_zero_actual_audit_count_is_accepted_without_table_format_false_alarm(self):
        self._run_fixture(0)

    def test_nonzero_actual_audit_count_remains_strictly_rejected(self):
        self._run_fixture(1)


if __name__ == "__main__":
    unittest.main()
