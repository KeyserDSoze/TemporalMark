#!/usr/bin/env python3
"""CI-ONLY: normal ASP.NET Core API container logs must not echo HTTP canaries.

Disposables only: loopback host and synthetic values; no real tokens/imprints.
Tests the running Npgsql/Keycloak-backed .NET API image; NOT external Azure
ingress, exceptional stack traces or privileged telemetry agents.
"""
import json
import os
import subprocess
import urllib.error
import urllib.request

COMPOSE = ["docker", "compose", "-f", "docker/compose.yml"]
API = "http://127.0.0.1:8080"
SENTINELS = [
    "API_CI_PRIVATE_PATH_20261119",
    "API_CI_PRIVATE_QUERY_20261119",
    "API_CI_PRIVATE_REFERER_20261119",
    "API_CI_PRIVATE_AGENT_20261119",
    "API_CI_FAKE_BEARER_20261119",
    "D" * 64,
]


def probe(path, method="GET", body=None):
    headers = {
        "User-Agent": SENTINELS[3],
        "Referer": "http://localhost/" + SENTINELS[2],
        "Authorization": "Bearer " + SENTINELS[4],
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(API + path, headers=headers, method=method, data=body)
    try:
        with urllib.request.urlopen(request, timeout=25) as result:
            return result.status
    except urllib.error.HTTPError as error:
        return error.code


def main():
    if os.environ.get("TEMPORALMARK_CI_API_LOG_PRIVACY") != "1":
        raise AssertionError("Explicit disposable API CI fixture gate required")

    # Genuine 404 may be handled before auth middleware; request path/query
    # are intentionally hostile synthetic inputs and must not be recorded.
    status = probe("/" + SENTINELS[0] + "?imprint=" + SENTINELS[1])
    if status != 404:
        raise AssertionError("Unexpected API response to anonymous unrecognized path")

    # Authentication must remain fail-closed; logging policy cannot change
    # authorized role or request-body processing semantics.
    status = probe("/api/v1/me?" + "canary=" + SENTINELS[1])
    if status != 401:
        raise AssertionError("Authentication gate was changed by API logging policy")

    payload = json.dumps({
        "digestSha256Hex": SENTINELS[5],
        "fromUtc": "2026-11-01T00:00:00Z",
        "toUtcExclusive": "2026-11-02T00:00:00Z",
        "offset": 0,
        "limit": 50,
    }).encode("utf-8")
    status = probe("/api/v1/stamps/search?canary=" + SENTINELS[1],
                   method="POST", body=payload)
    if status != 401:
        raise AssertionError("Unauthenticated document lookup was not denied")

    result = subprocess.run(
        COMPOSE + ["logs", "--no-color", "api"],
        capture_output=True, text=True, check=False, timeout=45,
    )
    if result.returncode != 0:
        raise AssertionError("Could not inspect real API container logs")
    # Do not print raw logs, tokens, URLs or original request payload even on
    # failure. Check both stdout and stderr (and Compose log prefixes).
    if any(canary in result.stdout or canary in result.stderr for canary in SENTINELS):
        raise AssertionError("Real ASP.NET Core API container output leaked synthetic request data")

    print("PASS: real .NET API 404/401 normal request diagnostics excluded synthetic "
          "URL/query/referrer/agent/fake-bearer/JSON-imprint canaries")


if __name__ == "__main__":
    main()
