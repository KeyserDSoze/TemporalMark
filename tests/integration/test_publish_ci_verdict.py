"""RED-first #101: exact-main, four-core-job GitHub commit-status verdict."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_ci_verdict as verdict


def needs(**results):
    return {name: {"result": result} for name, result in results.items()}


GOOD = needs(backend="success", frontend="success",
             **{"docker-smoke": "success"}, terraform="success")


class CommitVerdictTests(unittest.TestCase):
    def test_exact_four_success_only_yields_success(self):
        state, description = verdict.build_verdict(GOOD)
        self.assertEqual("success", state)
        for name in ("backend", "frontend", "docker-smoke", "terraform"):
            self.assertIn(name + "=success", description)
        self.assertLessEqual(len(description), 140)

    def test_any_failure_cancelled_or_skipped_denies(self):
        for name in GOOD:
            for result in ("failure", "cancelled", "skipped", None, "", "SUCCESS"):
                with self.subTest(name=name, result=result):
                    altered = dict(GOOD)
                    altered[name] = {"result": result}
                    state, description = verdict.build_verdict(altered)
                    self.assertEqual("failure", state)
                    self.assertLessEqual(len(description), 140)

    def test_missing_unexpected_job_and_malformed_needs_fail_closed(self):
        for bad in (
            {}, None, [], "success", "{}", {"other": {"result": "success"}},
            {k: v for k, v in GOOD.items() if k != "docker-smoke"},
            {**GOOD, "extra": {"result": "success"}},
            {**GOOD, "backend": "success"},
            {**GOOD, "backend": {"conclusion": "success"}},
        ):
            with self.subTest(bad=bad):
                self.assertEqual("failure", verdict.build_verdict(bad)[0])

    def test_unknown_job_text_is_never_leaked_into_description(self):
        malicious = {**GOOD, "backend": {"result": "secret=abc raw error content"}}
        state, description = verdict.build_verdict(malicious)
        self.assertEqual("failure", state)
        self.assertNotIn("secret", description)
        self.assertNotIn("abc", description)

    def test_status_target_exact_sha_run_attempt_and_context(self):
        sha = "0123456789abcdef" * 2 + "01234567"
        target = verdict.validate_target(
            "KeyserDSoze/TemporalMark", sha, "44010513402", "2",
            "refs/heads/main", "push")
        self.assertEqual(
            "https://github.com/KeyserDSoze/TemporalMark/actions/runs/44010513402/attempts/2",
            target)
        payload = verdict.make_payload(GOOD, target)
        self.assertEqual("success", payload["state"])
        self.assertEqual("temporalmark/ci-4-core-jobs", payload["context"])
        self.assertEqual(target, payload["target_url"])
        self.assertEqual({"state", "description", "context", "target_url"}, set(payload))
        self.assertLessEqual(len(payload["description"]), 140)

    def test_invalid_environment_values_are_rejected_before_network(self):
        sha = "0123456789abcdef" * 2 + "01234567"
        base = ["KeyserDSoze/TemporalMark", sha, "5", "1", "refs/heads/main", "push"]
        cases = {
            0: ["", "https://evil.example/x", "../Bad", "a/b/c"],
            1: ["a" * 39, "A" * 40, "xyz" * 14, "a" * 41],
            2: ["", "0", "-1", "01", "1/../other"],
            3: ["", "0", "01", "1.2"],
            4: ["refs/heads/other", "refs/pull/1/merge", ""],
            5: ["pull_request", "workflow_run", ""],
        }
        for position, invalid in cases.items():
            for value in invalid:
                bad = base.copy()
                bad[position] = value
                with self.subTest(position=position, value=value):
                    with self.assertRaises(ValueError):
                        verdict.validate_target(*bad)

    def test_malformed_json_does_not_silently_become_success(self):
        for raw in ("", "null", "[]", "not-json",
                    '{"backend":{"result":"success"}}'):
            with self.subTest(raw=raw):
                parsed = verdict.parse_needs(raw)
                self.assertEqual("failure", verdict.build_verdict(parsed)[0])
        self.assertEqual("success", verdict.build_verdict(
            verdict.parse_needs(json.dumps(GOOD)))[0])

    def test_publish_uses_only_scoped_github_status_api_and_sanitized_payload(self):
        sha = "0123456789abcdef" * 2 + "01234567"
        repo = "KeyserDSoze/TemporalMark"
        target = verdict.validate_target(repo, sha, "42", "1", "refs/heads/main", "push")
        payload = verdict.make_payload(GOOD, target)
        captured = {}

        class Created:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        def fake_request(request, timeout):
            captured["url"] = request.full_url
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["authorization"] = request.get_header("Authorization")
            captured["timeout"] = timeout
            return Created()

        with patch.object(verdict.urllib.request, "urlopen", side_effect=fake_request):
            verdict.publish_status(repo, sha, "test-private-token", payload)

        self.assertEqual(
            f"https://api.github.com/repos/{repo}/statuses/{sha}", captured["url"])
        self.assertEqual(payload, captured["body"])
        self.assertEqual("Bearer test-private-token", captured["authorization"])
        self.assertNotIn("test-private-token", json.dumps(captured["body"]))
        self.assertEqual(20, captured["timeout"])

    def test_missing_token_and_unexpected_success_http_status_fail(self):
        with patch.object(verdict.urllib.request, "urlopen") as mock:
            with self.assertRaises(ValueError):
                verdict.publish_status("KeyserDSoze/TemporalMark", "a" * 40,
                                       "", verdict.make_payload(GOOD, "https://example.invalid/"))
            mock.assert_not_called()

        class WrongResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        with patch.object(verdict.urllib.request, "urlopen", return_value=WrongResponse()):
            with self.assertRaises(RuntimeError):
                verdict.publish_status("KeyserDSoze/TemporalMark", "a" * 40,
                                       "only-for-test", verdict.make_payload(GOOD, "https://example.invalid/"))

    def test_workflow_job_is_main_only_after_all_four_and_only_statuses_write(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", text)
        self.assertIn("  ci-verdict:\n", text)
        job = text.split("\n  ci-verdict:\n", 1)[1]
        self.assertIn("needs: [backend, frontend, docker-smoke, terraform]", job)
        self.assertIn("always()", job)
        self.assertIn("github.ref == 'refs/heads/main'", job)
        self.assertIn("permissions:\n      contents: read\n      statuses: write", job)
        self.assertNotIn("issues: write", job)
        self.assertNotIn("id-token: write", job)
        self.assertIn("toJSON(needs)", job)
        self.assertIn("python3 tests/integration/publish_ci_verdict.py", job)
        self.assertIn("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", job)
        self.assertIn("persist-credentials: false", job)
        self.assertIn("timeout-minutes: 5", job)
        self.assertIn("test_publish_ci_verdict.py", text)


if __name__ == "__main__":
    unittest.main()
