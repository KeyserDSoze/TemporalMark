#!/usr/bin/env python3
"""RED-first source policy for enumerated, exact CI-only MFA loopback callbacks."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "tests/frontend/mfa.spec.ts"
REALM = ROOT / "docker/keycloak/temporalmark-mfa-ci-realm.json"
CI = ROOT / ".github/workflows/ci.yml"
WRAPPER = ROOT / "tests/integration/run-mfa-with-blocked-primary-callback.py"
PORTS = (45678, 46678, 47678)


class DisposableMfaCallbackFallbackPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = SPEC.read_text(encoding="utf-8")
        cls.ci = CI.read_text(encoding="utf-8")
        cls.realm = json.loads(REALM.read_text(encoding="utf-8"))

    def test_exact_callback_registration_never_uses_wildcards(self):
        clients = [x for x in self.realm["clients"]
                   if x["clientId"] == "temporalmark-mfa-pkce-ci"]
        self.assertEqual(1, len(clients))
        self.assertEqual(
            [f"http://127.0.0.1:{port}/oidc-mfa-callback" for port in PORTS],
            clients[0]["redirectUris"],
        )
        self.assertFalse(clients[0]["directAccessGrantsEnabled"])
        self.assertTrue(clients[0]["standardFlowEnabled"])
        self.assertEqual("S256", clients[0]["attributes"]["pkce.code.challenge.method"])

    def test_code_binds_explicit_ports_and_only_recovers_address_in_use(self):
        self.assertIn("const callbackPorts = [45678, 46678, 47678] as const;", self.spec)
        self.assertIn("for (const port of callbackPorts)", self.spec)
        self.assertIn('server.listen(port, "127.0.0.1")', self.spec)
        self.assertIn('code !== "EADDRINUSE"', self.spec)
        self.assertIn("throw new Error(", self.spec)
        self.assertIn("redirect = `http://127.0.0.1:${port}/oidc-mfa-callback`;", self.spec)
        self.assertIn("redirect_uri: redirect", self.spec)
        self.assertIn("redirect_uri: redirect, code: authorization.code", self.spec)
        self.assertNotRegex(self.spec, r"listen\(0,")
        self.assertNotIn("0.0.0.0", self.spec)

    def test_ci_intentionally_occupies_primary_loopback_callback(self):
        self.assertTrue(WRAPPER.is_file())
        wrapper = WRAPPER.read_text(encoding="utf-8")
        self.assertIn('socket_holder.bind(("127.0.0.1", 45678))', wrapper)
        self.assertIn("socket_holder.listen(1)", wrapper)
        self.assertIn("mfa.config.ts", wrapper)
        self.assertIn("finally:", wrapper)
        self.assertIn("socket_holder.close()", wrapper)
        self.assertIn("run-mfa-with-blocked-primary-callback.py", self.ci)
        # Workflow must NOT launch the original test directly.
        self.assertNotIn("(cd tests/frontend && npx playwright test --config mfa.config.ts)", self.ci)


if __name__ == "__main__":
    unittest.main()
