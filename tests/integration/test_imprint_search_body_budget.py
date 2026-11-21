#!/usr/bin/env python3
"""ADR 0102 / #136 RED-first source policy for *two* independent preauth
imprint-search JSON body budgets: Kestrel direct API and pinned Nginx frontend.

The real Docker + signed Keycloak integration tests are mandatory as well.
Source-only checks cannot prove Kestrel reads chunked bodies or Nginx logs.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
API = ROOT / "src/backend/applications/TemporalMark.Api/Program.cs"
NGINX = ROOT / "docker/nginx.conf.template"
CI = ROOT / ".github/workflows/ci.yml"
SIGNED = ROOT / "tests/integration/api-tenant-isolation.py"
LIMIT = 4096


class SearchBodyBudgetPolicyTests(unittest.TestCase):
    def test_api_imposes_4096_byte_budget_before_authentication_or_model_binding(self):
        source = API.read_text()
        self.assertIn("const long ImprintSearchBodyLimitBytes = 4096;", source)
        self.assertIn("IHttpMaxRequestBodySizeFeature", source)
        self.assertIn("MaxRequestBodySize = ImprintSearchBodyLimitBytes", source)
        self.assertIn("IsReadOnly", source)
        self.assertIn("context.Request.ContentLength > ImprintSearchBodyLimitBytes", source)
        self.assertIn("StringComparison.OrdinalIgnoreCase", source)
        self.assertIn("StatusCodes.Status413PayloadTooLarge", source)
        self.assertIn('context.Response.Headers.CacheControl = "no-store";', source)
        self.assertLess(source.index("IHttpMaxRequestBodySizeFeature"),
                        source.index("app.UseAuthentication();"))
        # Don't trust declared Content-Length alone: enforce the actual
        # Kestrel body read for chunked/unknown-length requests.
        self.assertIn("Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute", source)

    def test_nginx_exact_search_route_and_confidential_error_channel(self):
        source = NGINX.read_text()
        exact = re.search(
            r"(?ms)^\s*location\s+=\s+/api/v1/stamps/search\s*\{(?P<body>.*?)^\s*\}",
            source,
        )
        self.assertIsNotNone(exact, "Missing exact search POST Nginx location")
        body = exact.group("body")
        self.assertRegex(body, r"(?m)^\s*client_max_body_size\s+4k;\s*$")
        self.assertIn("proxy_pass ${API_UPSTREAM};", body)
        self.assertIn("proxy_set_header Host $host;", body)
        self.assertIn("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;", body)
        # A 413 in Nginx normally logs the request line incl. hostile query
        # at error severity; for this *one* sensitive location only suppress
        # less-than-critical error events (at the cost of route diagnostics).
        self.assertIn("error_log /dev/stderr crit;", body)
        self.assertEqual(source.count("access_log /dev/stdout temporalmark_minimal;"), 1)
        self.assertEqual(len(re.findall(r"(?m)^\s*access_log\s+", source)), 1)
        self.assertNotRegex(source, r"(?m)^\s*client_max_body_size\s+0;")

    def test_limit_is_scoped_and_does_not_replace_existing_security_boundaries(self):
        app = API.read_text()
        nginx = NGINX.read_text()
        self.assertIn('api.MapPost("/stamps/search"', app)
        self.assertIn('app.UseAuthorization();', app)
        self.assertIn('api.MapPost("/stamps/issue"', app)
        self.assertIn("ImprintSearchRateGateService searchRateGate", app)
        self.assertIn("PrepareImprintSearchAsync(", app)
        self.assertIn("location /api/ {", nginx)
        self.assertIn("location /healthz {", nginx)
        self.assertIn("location / { try_files $uri $uri/ /index.html; }", nginx)

    def test_source_contract_is_mandatory_in_full_ci(self):
        workflow = CI.read_text()
        self.assertIn("test_imprint_search_body_budget.py", workflow)
        self.assertIn("imprint-search-body-budget.py", workflow)
        self.assertIn("TEMPORALMARK_CI_SEARCH_BODY_BUDGET=1", workflow)
        self.assertIn("api-tenant-isolation.py", workflow)
        signed = SIGNED.read_text()
        self.assertIn("assert_search_body_budget_with_signed_chunked_jwt(", signed)
        self.assertIn('"Transfer-Encoding", "chunked"', signed)
        self.assertIn("HTTPConnection", signed)
        # All integration tests must use fixed, disposable loopback fixtures.
        self.assertIn('API = "http://127.0.0.1:8080"', signed)


if __name__ == "__main__":
    unittest.main()
