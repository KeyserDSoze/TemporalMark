#!/usr/bin/env python3
"""#145 / ADR0110: source contract for pre-location Nginx 414 no-store.

Actual pinned Docker 414 HTTP response and stdout/stderr canaries are a
separate MANDATORY test. Source checks cannot prove request-line parser
behavior or managed Azure ingress.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Early414CachePrivacySourcePolicy(unittest.TestCase):
    def test_http_scope_map_is_414_only_with_empty_default(self):
        config = (ROOT / "docker/nginx-privacy-logs.conf").read_text()
        maps = re.findall(r"(?ms)^map\s+\$status\s+\$tm_early_414_cache_control\s*\{(.*?)^\}", config)
        self.assertEqual(1, len(maps), "Require one 414-only HTTP-scope cache map")
        lines = [line.strip() for line in maps[0].splitlines()
                 if line.strip() and not line.strip().startswith("#")]
        self.assertEqual(['default "";', '414 "no-store";'], lines)
        self.assertEqual(config.count("map $status "), 1)
        self.assertNotRegex(config, r"(?m)^\s*(?:access_log|error_log)\s+")
        # A broad HTTP-scope crit would suppress unrelated incident diagnostics.
        self.assertNotIn("error_log /dev/stderr crit;", config)

    def test_server_conditional_header_preserves_standard_api_and_spa(self):
        server = (ROOT / "docker/nginx.conf.template").read_text()
        self.assertEqual(
            server.count(
                "add_header Cache-Control $tm_early_414_cache_control always;"),
            1)
        self.assertEqual(server.count(
            "add_header X-Content-Type-Options nosniff always;"), 1)
        self.assertEqual(server.count(
            "add_header Referrer-Policy strict-origin-when-cross-origin always;"), 1)
        self.assertNotIn('error_page 414 = @', server)
        self.assertIn("location ~* ^/api/v1/stamps/search$ {", server)
        self.assertIn("client_max_body_size 4k;", server)
        self.assertIn("limit_req zone=tm_search_peer burst=12 nodelay;", server)
        self.assertIn("proxy_intercept_errors off;", server)
        self.assertIn("location @tm_search_edge_denied {", server)
        self.assertIn('add_header Cache-Control "no-store" always;', server)

    def test_414_real_docker_gate_and_other_privacy_jobs_remain_mandatory(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("test_nginx_early_414_privacy.py", ci)
        self.assertIn("nginx-early-414-privacy.py", ci)
        self.assertIn('TEMPORALMARK_CI_NGINX_EARLY_414: "1"', ci)
        for step in ("nginx-access-privacy.py", "imprint-search-body-budget.py",
                     "imprint-search-nginx-edge-limit.py", "api-tenant-isolation.py"):
            self.assertIn(step, ci)


if __name__ == "__main__":
    unittest.main()
