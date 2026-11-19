#!/usr/bin/env python3
"""CI ONLY: test the actual pinned Nginx web-container access-log bytes.

Uses fake, synthetic strings on fixed loopback targets. Never send live
imprints, JWTs or operator-selected URLs to this test. Raw logs are not printed.
"""
import json
import os
import subprocess
import urllib.error
import urllib.request

WEB = "http://127.0.0.1:3000"
COMPOSE = ["docker", "compose", "-f", "docker/compose.yml"]
SENTINELS = [
    "CI_PRIVATE_PATH_20261119",
    "CI_PRIVATE_QUERY_20261119",
    "CI_PRIVATE_REFERER_20261119",
    "CI_PRIVATE_AGENT_20261119",
    "CI_FAKE_AUTH_BEARER_20261119",
    "C" * 64,
]


def request(path, method="GET", body=None):
    headers = {
        "User-Agent": SENTINELS[3],
        "Referer": "http://localhost/" + SENTINELS[2],
        "Authorization": "Bearer " + SENTINELS[4],
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(WEB + path, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            return response.status
    except urllib.error.HTTPError as error:
        # Keep error payload (which might contain a canary) out of output.
        return error.code


def main():
    if os.environ.get("TEMPORALMARK_CI_NGINX_ACCESS_PRIVACY") != "1":
        raise AssertionError("Explicit disposable Nginx CI fixture gate required")

    root = "/" + SENTINELS[0] + "?" + "documentSha256=" + SENTINELS[1]
    if request(root) != 200:
        raise AssertionError("The real Nginx SPA probe did not return HTTP 200")

    search = "/api/v1/stamps/search?" + "queryCanary=" + SENTINELS[1]
    # This is deliberately not a valid JWT: the real API must return HTTP 401
    # while Nginx sees a synthetic JSON body, query, referrer and fake bearer.
    payload = json.dumps({
        "digestSha256Hex": SENTINELS[5],
        "fromUtc": "2026-11-01T00:00:00Z",
        "toUtcExclusive": "2026-11-02T00:00:00Z",
        "offset": 0, "limit": 50,
    }).encode("utf-8")
    if request(search, "POST", payload) != 401:
        raise AssertionError("Real Nginx did not forward the unauthorized API probe")

    proc = subprocess.run(
        COMPOSE + ["logs", "--no-color", "web"],
        check=False, capture_output=True, text=True, timeout=35,
    )
    if proc.returncode:
        raise AssertionError("Cannot verify actual Nginx access logs")
    access_lines = [line for line in proc.stdout.splitlines()
                    if "tm_access status=" in line]
    if not any("status=200 method=GET duration=" in line for line in access_lines):
        raise AssertionError("Missing privacy-formatted successful Nginx access event")
    if not any("status=401 method=POST duration=" in line for line in access_lines):
        raise AssertionError("Missing privacy-formatted unauthorized Nginx access event")

    # Each access log line must include only predeclared primitive fields
    # after the Docker Compose container prefix. Never print raw lines.
    for line in access_lines:
        content = line.split("tm_access ", 1)[-1]
        fields = content.split()
        if len(fields) != 3 or not fields[0].startswith("status=") or \
           not fields[1].startswith("method=") or not fields[2].startswith("duration="):
            raise AssertionError("Nginx emitted an access field outside its privacy allowlist")
        if not fields[0][7:].isdigit():
            raise AssertionError("Nginx emitted non-numeric HTTP status")
        if fields[1][7:] not in ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"):
            raise AssertionError("Nginx emitted unexpected HTTP method metadata")
        try:
            float(fields[2][9:])
        except ValueError:
            raise AssertionError("Nginx emitted invalid duration metadata") from None
        if any(sentinel in line for sentinel in SENTINELS):
            raise AssertionError("Nginx access log exposed synthetic sensitive request content")

    print("PASS: real shared Nginx image logs status/method/duration only; "
          "synthetic URL/query/body/referrer/agent/fake bearer withheld from access log")


if __name__ == "__main__":
    main()
