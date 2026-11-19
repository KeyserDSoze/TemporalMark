#!/usr/bin/env python3
"""TDD source guard: require code-owned .NET 10 API request log minimization.

This does not inspect arbitrary privileged agents or production ingress;
the separate Docker HTTP probe tests normal API-container log output.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROGRAM = ROOT / "src/backend/applications/TemporalMark.Api/Program.cs"


class ApiDiagnosticPrivacyPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PROGRAM.read_text(encoding="utf-8")

    def test_request_start_and_endpoint_info_diagnostics_are_suppressed_by_code(self):
        for category in (
            "Microsoft.AspNetCore.Hosting.Diagnostics",
            "Microsoft.AspNetCore.Routing.EndpointMiddleware",
            "Microsoft.AspNetCore.Routing.Matching.DfaMatcher",
        ):
            with self.subTest(category=category):
                self.assertIn(
                    f'builder.Logging.AddFilter("{category}", LogLevel.Warning);',
                    self.source,
                )
        self.assertLess(self.source.index('builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics"'),
                        self.source.index("var app = builder.Build();"))

    def test_http_body_and_header_logging_is_explicitly_off_even_if_middleware_added_later(self):
        self.assertIn("using Microsoft.AspNetCore.HttpLogging;", self.source)
        self.assertIn("builder.Services.AddHttpLogging(", self.source)
        self.assertIn("options.LoggingFields = HttpLoggingFields.None;", self.source)
        self.assertIn(
            'builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware", LogLevel.None);',
            self.source,
        )
        self.assertIn(
            'builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging.W3CLogger", LogLevel.None);',
            self.source,
        )
        # Explicitly reject future activating request/body/response logging.
        self.assertNotIn("app.UseHttpLogging(", self.source)
        self.assertNotIn("app.UseW3CLogging(", self.source)
        self.assertNotIn("HttpLoggingFields.All", self.source)
        self.assertNotIn("HttpLoggingFields.RequestBody", self.source)
        self.assertNotIn("HttpLoggingFields.ResponseBody", self.source)


if __name__ == "__main__":
    unittest.main()
