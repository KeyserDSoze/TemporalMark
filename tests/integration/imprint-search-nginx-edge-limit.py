#!/usr/bin/env python3
"""#143 / ADR 0108: live synthetic, local-only Nginx pre-auth burst test.
Never use with real bearers, imprints, tenants, or external URLs.
"""
import concurrent.futures
import json
import os
import subprocess
import urllib.error
import urllib.request

API = "http://127.0.0.1:8080"
WEB = "http://127.0.0.1:3000"
PATH = "/api/v1/stamps/search"
COMPOSE = ["docker", "compose", "-f", "docker/compose.yml"]
CANARIES = ("CI_EDGE_QUERY_SECRET_143", "CI_EDGE_FAKE_JWT_143",
            "CI_EDGE_AGENT_PRIVATE_143", "CI_EDGE_REFERRER_PRIVATE_143",
            "D" * 64)
BODY = json.dumps({
    "digestSha256Hex": CANARIES[4],
    "fromUtc": "2026-11-01T00:00:00Z",
    "toUtcExclusive": "2026-11-02T00:00:00Z",
    "offset": 0, "limit": 50
}, separators=(",", ":")).encode("ascii")


def fetch(base, path, method="GET", body=None, forged_ip=None, auth=True):
    headers = {
        "User-Agent": CANARIES[2],
        "Referer": "http://localhost/" + CANARIES[3]
    }
    if auth:
        headers["Authorization"] = "Bearer " + CANARIES[1]
    if forged_ip is not None:
        # Documentation-only test IP addresses. Nginx must key off the real
        # TCP peer, never the untrusted X-Forwarded-For request header.
        headers["X-Forwarded-For"] = f"198.51.100.{forged_ip % 250 + 1}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=body,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, dict(response.headers), response.read(4096)
    except urllib.error.HTTPError as ex:
        return ex.code, dict(ex.headers), ex.read(4096)


def assert_code(label, response, code):
    if response[0] != code:
        raise AssertionError(f"{label}: expected {code}; got {response[0]}, body withheld")


def validate_429(response):
    _, headers, body = response
    h = {k.lower(): v for k, v in headers.items()}
    if h.get("retry-after") != "1":
        raise AssertionError("Local 429 must advertise fixed Retry-After: 1")
    if "no-store" not in h.get("cache-control", "").lower():
        raise AssertionError("Local 429 must be non-cacheable")
    if any(c.encode() in body for c in CANARIES):
        raise AssertionError("Edge 429 echoed a synthetic private request canary")
    if any(word in body.lower() for word in
           (b"tenantid", b"organizationid", b"matches", b"hasmore",
            b"digestsha256hex")):
        raise AssertionError("Edge 429 exposed match/tenant metadata")


def actual_nginx_logs():
    p = subprocess.run(COMPOSE + ["logs", "--no-color", "web"],
                       text=True, capture_output=True, timeout=40)
    if p.returncode:
        raise AssertionError("Unable to inspect disposable Nginx logs")
    return p.stdout + p.stderr


def main():
    if os.environ.get("TEMPORALMARK_CI_NGINX_EDGE_LIMIT") != "1":
        raise AssertionError("Explicit local disposable CI fixture required")
    if len(BODY) > 4096:
        raise AssertionError("Synthetic JSON exceeds existing body limit")
    path = PATH + "?query=" + CANARIES[0]
    assert_code("direct Kestrel fake JWT", fetch(API, path, "POST", BODY), 401)
    assert_code("Nginx normal fake JWT", fetch(WEB, path, "POST", BODY, 0), 401)

    # Distinct forged XFF values are sent through ONE real peer. A bounded
    # 2req/s + burst 12 gate must deny some of 48 concurrent requests.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(fetch, WEB, path, "POST", BODY, i + 1)
                   for i in range(48)]
        results = [future.result(timeout=30) for future in futures]

    if any(result[0] not in (401, 429) for result in results):
        raise AssertionError("Unexpected anonymous Nginx burst response")
    blocked = [result for result in results if result[0] == 429]
    if not blocked:
        raise AssertionError("Missing Nginx pre-auth local-peer burst 429")
    if not any(result[0] == 401 for result in results):
        raise AssertionError("Missing normal Keycloak/JWT 401 during burst")
    for result in blocked:
        validate_429(result)

    # Exact web proxy route only; direct Kestrel and unrelated paths unaffected.
    assert_code("direct API bypasses web-only limit", fetch(API, path, "POST", BODY), 401)
    assert_code("other API POST", fetch(WEB, "/api/v1/stamps/issue", "POST", BODY), 401)
    assert_code("web health", fetch(WEB, "/healthz", auth=False), 200)
    assert_code("web SPA", fetch(WEB, "/", auth=False), 200)

    logs = actual_nginx_logs()
    if any(canary in logs for canary in CANARIES):
        raise AssertionError("Nginx logs leaked synthetic URL/body/bearer canary")
    access = [line.split("tm_access ", 1)[-1].split()
              for line in logs.splitlines() if "tm_access " in line]
    if not any(len(fields) == 3 and fields[0] == "status=429" and
               fields[1] == "method=POST" for fields in access):
        raise AssertionError("Missing minimal anonymous 429 access event")
    for fields in access:
        if len(fields) != 3 or not fields[0].startswith("status=") or \
                not fields[1].startswith("method=") or \
                not fields[2].startswith("duration="):
            raise AssertionError("Unexpected Nginx access field beyond privacy allowlist")

    print("PASS: shared real Nginx throttles anonymous POST search by real peer "
          "to 429, fixed Retry-After/no-store; forged XFF, canary response/log "
          "leaks and unrelated-route regression denied")


if __name__ == "__main__":
    main()
