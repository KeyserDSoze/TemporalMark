#!/usr/bin/env python3
"""Source-only Nginx access-log privacy policy (#117): no customer selectors.

This is a syntactic guard. The separate Docker HTTP smoke proves the actual
Nginx container's output; neither proves Azure-managed edge/error logs.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
FORMAT_FILE = ROOT / "docker" / "nginx-privacy-logs.conf"
SERVER_FILE = ROOT / "docker" / "nginx.conf.template"
DOCKERFILE = ROOT / "src" / "frontend" / "Dockerfile"


class NginxAccessPrivacyPolicyTests(unittest.TestCase):
    def test_http_context_log_format_is_bounded_to_method_status_duration(self):
        self.assertTrue(FORMAT_FILE.is_file(), "Missing http-context Nginx privacy log format")
        source = FORMAT_FILE.read_text(encoding="utf-8")
        # Exact allowlist: no path, query, request body, client IP, referrer,
        # cookies, bearer, user-agent, sub, bytes sent or response contents.
        self.assertRegex(source, r"(?m)^log_format temporalmark_minimal\s+")
        statements = re.findall(r"(?m)^log_format\s+[^;]+;", source)
        self.assertEqual(1, len(statements), "Exactly one log_format allowed")
        self.assertEqual(
            "log_format temporalmark_minimal 'tm_access status=$status method=$request_method duration=$request_time';",
            statements[0],
        )
        self.assertNotRegex(source, r"(?m)^\s*(?:access_log|error_log)\s+")

    def test_actual_server_explicitly_selects_privacy_format_without_overrides(self):
        source = SERVER_FILE.read_text(encoding="utf-8")
        self.assertIn("access_log /dev/stdout temporalmark_minimal;", source)
        self.assertEqual(1, len(re.findall(r"(?m)^\s*access_log\s+", source)))
        self.assertNotRegex(source, r"(?m)^\s*log_format\s+")
        # $uri is legitimately used by try_files for SPA routing: this
        # policy only constrains access_log, not non-logging proxy directives.
        self.assertNotRegex(source, r"(?m)^\s*access_log\s+[^;]*(?:\$|combined|off)")

    def test_docker_image_installs_http_context_format_into_conf_d(self):
        source = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn(
            "COPY docker/nginx-privacy-logs.conf /etc/nginx/conf.d/00-temporalmark-log-format.conf",
            source,
        )
        self.assertIn(
            "COPY docker/nginx.conf.template /etc/nginx/templates/default.conf.template",
            source,
        )


if __name__ == "__main__":
    unittest.main()
