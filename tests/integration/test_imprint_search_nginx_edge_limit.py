#!/usr/bin/env python3
"""#143 / ADR0108: source policy; actual pinned Nginx Docker 429/logs must
also run in docker-smoke. Cannot attest real Azure managed ingress.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NginxSearchEdgeBurstPolicy(unittest.TestCase):
    def test_zone_is_http_scope_and_never_uses_client_forwarded_headers(self):
        source = (ROOT / "docker/nginx-privacy-logs.conf").read_text()
        zones = re.findall(r"(?m)^limit_req_zone\s+[^;]+;", source)
        self.assertEqual(
            ["limit_req_zone $binary_remote_addr zone=tm_search_peer:1m rate=2r/s;"],
            zones,
        )
        self.assertNotIn("$http_x_forwarded_for", source)
        self.assertNotIn("$http_authorization", source)
        self.assertNotIn("$request_body", source)
        self.assertNotIn("$request_uri", source)

    def test_exact_search_only_and_upstream_429_not_intercepted(self):
        conf = (ROOT / "docker/nginx.conf.template").read_text()
        exact = re.search(
            r"(?ms)^\s*location = /api/v1/stamps/search \{(.*?)^\s*\}",
            conf,
        )
        self.assertIsNotNone(exact)
        block = exact.group(1)
        for required in (
            "client_max_body_size 4k;",
            "error_log /dev/stderr crit;",
            "limit_req zone=tm_search_peer burst=12 nodelay;",
            "limit_req_status 429;",
            "error_page 429 = @tm_search_edge_denied;",
            "proxy_intercept_errors off;",
            "proxy_set_header Host $host;",
            "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        ):
            self.assertIn(required, block)
        self.assertIn("proxy_pass $" + "{API_UPSTREAM};", block)
        self.assertEqual(conf.count("limit_req zone="), 1)
        self.assertEqual(conf.count("access_log /dev/stdout temporalmark_minimal;"), 1)
        self.assertIn("location /api/ {", conf)
        self.assertIn("location /healthz {", conf)
        self.assertNotIn("limit_req_dry_run", conf)
        self.assertNotIn("proxy_intercept_errors on;", conf)

    def test_generic_429_error_path_has_strict_privacy_headers(self):
        conf = (ROOT / "docker/nginx.conf.template").read_text()
        loc = re.search(
            r"(?ms)^\s*location @tm_search_edge_denied \{(.*?)^\s*\}",
            conf,
        )
        self.assertIsNotNone(loc)
        for item in (
            "internal;",
            "error_log /dev/stderr crit;",
            'add_header Cache-Control "no-store" always;',
            'add_header Retry-After "1" always;',
            "return 429;",
        ):
            self.assertIn(item, loc.group(1))
        self.assertNotRegex(conf, r"(?m)^\s*access_log\s+.*(?:\$request|\$uri|\$http_)")

    def test_both_python_source_and_real_docker_ci_are_mandatory(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("test_imprint_search_nginx_edge_limit.py", ci)
        self.assertIn("imprint-search-nginx-edge-limit.py", ci)
        self.assertIn('TEMPORALMARK_CI_NGINX_EDGE_LIMIT: "1"', ci)
        self.assertIn("api-tenant-isolation.py", ci)
        self.assertIn("imprint-search-body-budget.py", ci)


if __name__ == "__main__":
    unittest.main()
